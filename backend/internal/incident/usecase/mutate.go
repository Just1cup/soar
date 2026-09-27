package usecase

import (
	"context"
	"time"

	"github.com/titas/soar/backend/internal/audit"
	"github.com/titas/soar/backend/internal/auth"
	"github.com/titas/soar/backend/internal/core/clock"
	"github.com/titas/soar/backend/internal/core/errs"
	"github.com/titas/soar/backend/internal/core/id"
	"github.com/titas/soar/backend/internal/incident"
	"github.com/titas/soar/backend/internal/platform/outbox"
	"github.com/titas/soar/backend/internal/platform/telemetry"
	"github.com/titas/soar/backend/internal/rbac"
)

// TxManager is the port for "run these writes as one".
type TxManager interface {
	InTx(ctx context.Context, fn func(context.Context) error) error
}

// Outbox is the port for domain events. Declared here, where it is consumed.
type Outbox interface {
	Enqueue(ctx context.Context, tenant id.TenantID, events []outbox.Event) error
}

// Deps is what every mutating incident use case needs. Bundling them is not
// a service locator: each field is an explicit port, and the set is small
// because the shape of a mutation is always the same.
type Deps struct {
	Tx     TxManager
	Repo   incident.Repository
	Audit  audit.Writer
	Outbox Outbox
	Perms  rbac.Checker
	Clock  clock.Clock
}

// mutation is the one shape every state change follows (docs/soar/06 §9):
//
//	autorizar -> abrir transação -> travar a linha -> checar versão ->
//	aplicar a regra de domínio -> gravar -> auditar -> enfileirar evento
//
// Nenhuma chamada externa acontece aqui dentro. O SIEM é avisado depois, por
// um consumidor do evento — uma transação aberta esperando um HTTP de 15
// segundos é o jeito mais rápido de esgotar o pool.
func (d Deps) mutation(
	ctx context.Context,
	permission string,
	incidentID id.IncidentID,
	expectedVersion int,
	apply func(*incident.Incident, auth.Actor, time.Time) error,
	describe func(*incident.Incident, auth.Actor) audit.Fact,
) (*incident.Incident, error) {
	actor, err := d.Perms.Require(ctx, permission)
	if err != nil {
		return nil, err
	}

	var out *incident.Incident
	err = d.Tx.InTx(ctx, func(ctx context.Context) error {
		inc, err := d.Repo.FindForUpdate(ctx, actor.TenantID, incidentID)
		if err != nil {
			if errs := asNotFound(err); errs != nil {
				return errs
			}
			return err
		}
		// Optimistic locking: quem leu a versão 41 e tenta escrever sobre a 42
		// recebe 409 em vez de sobrescrever silenciosamente o trabalho alheio.
		//
		// A versão é OBRIGATÓRIA aqui, e não só no handler. Um controle que a
		// camada de transporte pode pular não é controle: o motor de regras e
		// os nós de playbook chamam este caso de uso direto, e precisam ler
		// antes de escrever exatamente como um humano precisa.
		if expectedVersion < 1 {
			return errs.Coded(errs.ErrPreconditionFailed, "EXPECTED_VERSION_REQUIRED",
				"mutação exige a versão lida do incidente")
		}
		if inc.Version != expectedVersion {
			return errs2Conflict(inc.Version, expectedVersion)
		}

		before := snapshot(inc)
		now := d.Clock.Now()
		if err := apply(inc, actor, now); err != nil {
			return err
		}
		if err := d.Repo.Save(ctx, inc); err != nil {
			return err
		}

		fact := describe(inc, actor)
		fact.TenantID = actor.TenantID
		fact.OccurredAt = now
		fact.Before = before
		fact.After = snapshot(inc)
		fact.RequestID = telemetry.RequestID(ctx)
		fact.TraceID = telemetry.TraceID(ctx)
		fact.IncidentID = &incidentID
		fact.Result = audit.Succeeded
		fact.Actor = audit.Actor{
			Kind: audit.ActorKind(actor.Kind), ID: actor.ID, Label: actor.Label,
		}
		if err := d.Audit.Record(ctx, fact); err != nil {
			return err
		}

		events := make([]outbox.Event, 0, 2)
		for _, e := range inc.PendingEvents() {
			aggregate := e.AggregateID.UUID
			events = append(events, outbox.Event{
				Topic: e.Topic, AggregateID: &aggregate,
				ActorKind: actor.Kind, ActorID: actor.ID,
				Payload: e.Payload, TraceID: telemetry.TraceID(ctx),
			})
		}
		if err := d.Outbox.Enqueue(ctx, actor.TenantID, events); err != nil {
			return err
		}
		out = inc
		return nil
	})
	return out, err
}

// snapshot is what lands in before_state / after_state. Only the fields a
// reader of the trail would ask about — a full row dump is noise that hides
// the change.
func snapshot(i *incident.Incident) map[string]any {
	s := map[string]any{
		"status": string(i.Status), "severity": string(i.Severity),
		"priority": i.Priority, "version": i.Version,
	}
	if i.OwnerID != nil {
		s["owner_id"] = i.OwnerID.String()
	}
	if i.Resolution != "" {
		s["resolution"] = string(i.Resolution)
	}
	return s
}

func asNotFound(err error) error {
	if errsIs(err, errs.ErrNotFound) {
		return errs.Coded(errs.ErrNotFound, "INCIDENT_NOT_FOUND", "incidente não encontrado")
	}
	return nil
}

func errs2Conflict(actual, expected int) error {
	return errs.Coded(errs.ErrVersionConflict, "VERSION_CONFLICT",
		"o incidente está na versão %d e você enviou %d; recarregue e revise", actual, expected)
}
