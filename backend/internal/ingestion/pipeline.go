package ingestion

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/titas/soar/backend/internal/audit"
	"github.com/titas/soar/backend/internal/core/clock"
	"github.com/titas/soar/backend/internal/core/id"
	"github.com/titas/soar/backend/internal/incident"
	"github.com/titas/soar/backend/internal/platform/outbox"
)

// errDuplicate rolls back the transaction when the alert turns out to have
// been ingested already. It never reaches the caller of Process.
var errDuplicate = errors.New("alerta já ingerido")

type TxManager interface {
	InTx(ctx context.Context, fn func(context.Context) error) error
}

type Outbox interface {
	Enqueue(ctx context.Context, tenant id.TenantID, events []outbox.Event) error
}

// AlertRepository persists the canonical alert and its link to an incident.
type AlertRepository interface {
	// Insert returns false when the alert was already ingested. Duplicate is
	// not an error: at-least-once delivery is assumed everywhere in this
	// product, and the unique constraint is what makes consumers idempotent.
	Insert(ctx context.Context, tenant id.TenantID, source id.SourceID, a *Alert,
		incidentID *id.IncidentID, suppressedBy *id.RuleID, reason string) (bool, error)
}

type RuleRepository interface {
	ActivePreprocess(ctx context.Context, tenant id.TenantID) ([]Rule, error)
	RecordRun(ctx context.Context, tenant id.TenantID, ruleID id.RuleID,
		incidentID *id.IncidentID, matched, dryRun bool, outcome string) error
}

// Pipeline turns accepted raw events into incidents.
//
//	mapear -> fingerprint -> pre-process -> criar OU incrementar
//
// The last step is the one that matters: a rule firing fifty thousand times
// moves a counter on one incident. The identity does not change.
type Pipeline struct {
	Tx        TxManager
	Raw       RawRepository
	Alerts    AlertRepository
	Incidents incident.Repository
	Rules     RuleRepository
	Audit     audit.Writer
	Outbox    Outbox
	Clock     clock.Clock
	// Sources maps a source kind to the compiled connector that can map it.
	Sources map[string]Source
	// DedupeWindow is the fallback when the incident type does not set one.
	DedupeWindow time.Duration
}

type ProcessStats struct {
	Mapped, Suppressed, Duplicates, Quarantined int
	IncidentsCreated, IncidentsUpdated          int
}

// Process drains accepted raw events into alerts and incidents.
func (p *Pipeline) Process(ctx context.Context, tenant id.TenantID,
	source SourceConfig, limit int) (ProcessStats, error) {

	var stats ProcessStats
	pending, err := p.Raw.Pending(ctx, tenant, limit)
	if err != nil {
		return stats, err
	}
	if len(pending) == 0 {
		return stats, nil
	}
	rules, err := p.Rules.ActivePreprocess(ctx, tenant)
	if err != nil {
		return stats, err
	}
	connector, ok := p.Sources[source.Kind]
	if !ok {
		return stats, fmt.Errorf("nenhum conector compilado para %q", source.Kind)
	}

	for _, raw := range pending {
		alert, err := connector.Map(RawEvent{Payload: raw.Payload, Mode: raw.Mode})
		if err != nil {
			// Payload irreconhecível vai para quarentena, NUNCA é descartado:
			// "perdemos" não pode ser uma dedução, tem de ser uma linha.
			if qErr := p.Raw.Quarantine(ctx, raw.ID, err.Error()); qErr != nil {
				return stats, qErr
			}
			stats.Quarantined++
			continue
		}
		alert.Fingerprint = Fingerprint(alert.RuleName, alert.Host, alert.EntityKind, alert.Entity)

		outcome := Evaluate(alert, rules, p.Clock.Now())
		if outcome.Severity != "" {
			alert.Severity = outcome.Severity
		}

		created, updated, duplicate, err := p.apply(ctx, tenant, source, raw, alert, outcome)
		if err != nil {
			return stats, err
		}
		switch {
		case duplicate:
			stats.Duplicates++
		case outcome.Drop:
			stats.Suppressed++
		case created:
			stats.IncidentsCreated++
		case updated:
			stats.IncidentsUpdated++
		}
		stats.Mapped++
	}
	return stats, nil
}

func (p *Pipeline) apply(ctx context.Context, tenant id.TenantID, source SourceConfig,
	raw PendingRaw, alert *Alert, outcome Outcome) (created, updated, duplicate bool, err error) {

	err = p.Tx.InTx(ctx, func(ctx context.Context) error {
		now := p.Clock.Now()

		// Suprimido: o alerta é gravado com a regra que o suprimiu e segue
		// consultável. `drop` nunca apaga.
		if outcome.Drop {
			inserted, err := p.Alerts.Insert(ctx, tenant, source.ID, alert, nil,
				outcome.DroppedBy, outcome.Reason)
			if err != nil {
				return err
			}
			if !inserted {
				duplicate = true
				return p.Raw.MarkDuplicate(ctx, raw.ID)
			}
			if outcome.DroppedBy != nil {
				if err := p.Rules.RecordRun(ctx, tenant, *outcome.DroppedBy, nil, true, false,
					"suppressed"); err != nil {
					return err
				}
			}
			return p.Raw.MarkMapped(ctx, raw.ID)
		}

		existing, err := p.Incidents.FindOpenByFingerprint(ctx, tenant, alert.Fingerprint)
		if err != nil {
			return err
		}

		var target *incident.Incident
		switch {
		case existing != nil && p.withinWindow(existing, alert, now):
			// O caso que define a funcionalidade: mover o contador, não criar
			// identidade nova.
			existing.AbsorbAlert(alert.EventTime, now)
			if err := p.Incidents.Save(ctx, existing); err != nil {
				return err
			}
			target, updated = existing, true
		default:
			inc, err := p.newIncident(ctx, tenant, source, alert, outcome, now)
			if err != nil {
				return err
			}
			target, created = inc, true
		}

		inserted, err := p.Alerts.Insert(ctx, tenant, source.ID, alert, &target.ID, nil, "")
		if err != nil {
			return err
		}
		if !inserted {
			// Já tínhamos este alerta. Desfaz a transação inteira — inclusive
			// a contagem que acabamos de somar — devolvendo uma sentinela que
			// o chamador reconhece. Contar duas vezes o mesmo alerta é
			// exatamente o que a entrega at-least-once produziria sem isto.
			return errDuplicate
		}
		if err := p.recordFacts(ctx, tenant, target, alert, created, now); err != nil {
			return err
		}
		return p.Raw.MarkMapped(ctx, raw.ID)
	})
	if errors.Is(err, errDuplicate) {
		// A transação foi desfeita de propósito; marcar a duplicata é uma
		// escrita separada, fora dela.
		return false, false, true, p.Raw.MarkDuplicate(ctx, raw.ID)
	}
	return created, updated, duplicate, err
}

// withinWindow decides whether a new alert joins the open incident or starts
// a new one. Outside the window the same fingerprint is a RECURRENCE, and a
// recurrence deserves its own case rather than silently reviving an old one.
func (p *Pipeline) withinWindow(inc *incident.Incident, alert *Alert, now time.Time) bool {
	if inc.DedupeUntil == nil {
		return true
	}
	return now.Before(*inc.DedupeUntil)
}

func (p *Pipeline) newIncident(ctx context.Context, tenant id.TenantID, source SourceConfig,
	alert *Alert, outcome Outcome, now time.Time) (*incident.Incident, error) {

	typeSlug := outcome.IncidentType
	if typeSlug == "" {
		typeSlug = source.DefaultIncidentType
	}
	if typeSlug == "" {
		typeSlug = "generic"
	}
	key, err := p.Incidents.NextKey(ctx, tenant, now.Year())
	if err != nil {
		return nil, err
	}
	until := now.Add(p.DedupeWindow)
	sourceID := source.ID
	inc := &incident.Incident{
		TenantID: tenant, Key: key, TypeSlug: typeSlug,
		Title:       alert.Title,
		Status:      incident.StatusNew,
		Severity:    incident.Severity(alert.Severity),
		Priority:    priorityFor(alert.Severity),
		SourceID:    &sourceID,
		SourceRule:  alert.RuleName,
		Fingerprint: alert.Fingerprint, DedupeUntil: &until,
		AlertCount: 1, FirstSeen: alert.EventTime, LastSeen: alert.EventTime,
		Tags: outcome.Tags,
	}
	if err := inc.Validate(); err != nil {
		return nil, err
	}
	if err := p.Incidents.Create(ctx, inc); err != nil {
		return nil, err
	}
	return inc, nil
}

func (p *Pipeline) recordFacts(ctx context.Context, tenant id.TenantID,
	inc *incident.Incident, alert *Alert, created bool, now time.Time) error {

	actor := audit.Actor{Kind: audit.ActorSystem, ID: "system:ingestion", Label: "ingestão"}
	title := fmt.Sprintf("Alerta agrupado (%d no total)", inc.AlertCount)
	topic, eventType := "incident.updated", "alert.grouped"
	if created {
		title = "Incidente criado a partir de " + alert.RuleName
		topic, eventType = "incident.created", "incident.created"
	}
	if err := p.Audit.Record(ctx, audit.Fact{
		// Ingestão é fato de timeline, não decisão: ninguém mandou, e nada
		// mudou de estado por vontade de alguém.
		Classification: audit.TimelineOnly,
		TenantID:       tenant, OccurredAt: now, Actor: actor,
		IncidentID: &inc.ID, EventType: eventType, Title: title,
		Detail:  alert.Title,
		Payload: map[string]any{"fingerprint": hex.EncodeToString(alert.Fingerprint)},
	}); err != nil {
		return err
	}
	if !created {
		return nil // um evento por alerta agrupado inundaria o barramento
	}
	aggregate := inc.ID.UUID
	return p.Outbox.Enqueue(ctx, tenant, []outbox.Event{{
		Topic: topic, AggregateID: &aggregate,
		ActorKind: "system", ActorID: "system:ingestion",
		Payload: map[string]any{
			"incident_id": inc.ID.String(), "key": inc.Key,
			"severity": string(inc.Severity), "rule": alert.RuleName,
		},
	}})
}

func priorityFor(severity string) int {
	switch severity {
	case "critical":
		return 1
	case "high":
		return 2
	case "medium":
		return 3
	case "low":
		return 4
	default:
		return 5
	}
}
