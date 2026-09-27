package response

import (
	"context"
	"fmt"
	"time"

	"github.com/titas/soar/backend/internal/audit"
	"github.com/titas/soar/backend/internal/core/clock"
	"github.com/titas/soar/backend/internal/core/errs"
	"github.com/titas/soar/backend/internal/core/id"
	"github.com/titas/soar/backend/internal/platform/telemetry"
	"github.com/titas/soar/backend/internal/rbac"
)

// Approver decides pending approvals.
//
// It is a separate use case from the executor on purpose: approving and
// executing are different acts, held by different permissions, and in an
// environment with more than one analyst they would be different people.
type Approver struct {
	Tx        TxManager
	Approvals ApprovalRepository
	Audit     audit.Writer
	Perms     rbac.Checker
	Clock     clock.Clock
	// SelfApprovalForbidden separa quem pede de quem aprova. Fica DESLIGADO
	// no perfil `edge`, onde há um operador só e a regra apenas impediria
	// qualquer ação de acontecer — e a razão fica aqui, registrada, em vez de
	// virar uma omissão que ninguém lembra de revisar quando surgir o segundo
	// analista.
	SelfApprovalForbidden bool
}

type DecideCommand struct {
	ApprovalID      id.ApprovalID
	Approve         bool
	Note            string
	ExpectedVersion int
}

func (a *Approver) Decide(ctx context.Context, cmd DecideCommand) (*Approval, error) {
	actor, err := a.Perms.Require(ctx, rbac.ApprovalDecide)
	if err != nil {
		return nil, err
	}
	if actor.UserID == nil {
		// Uma aprovação é ato humano. Um motor que aprova o próprio pedido
		// transforma o controle em decoração.
		return nil, errs.Coded(errs.ErrForbidden, "HUMAN_APPROVAL_REQUIRED",
			"apenas um usuário pode decidir uma aprovação")
	}
	if cmd.ExpectedVersion < 1 {
		return nil, errs.Coded(errs.ErrPreconditionFailed, "EXPECTED_VERSION_REQUIRED",
			"decisão exige a versão lida da aprovação")
	}
	if !cmd.Approve && cmd.Note == "" {
		// Recusar sem dizer por quê deixa o próximo analista repetindo o
		// mesmo pedido.
		return nil, errs.Coded(errs.ErrValidation, "REASON_REQUIRED",
			"recusar exige um motivo")
	}

	status := "rejected"
	if cmd.Approve {
		status = "approved"
	}

	var decided *Approval
	err = a.Tx.InTx(ctx, func(ctx context.Context) error {
		before, err := a.Approvals.Get(ctx, actor.TenantID, cmd.ApprovalID)
		if err != nil {
			return err
		}
		if before == nil {
			return errs.Coded(errs.ErrNotFound, "APPROVAL_NOT_FOUND", "aprovação não encontrada")
		}
		// Quem pede não decide o próprio pedido — quando há mais de um
		// usuário. Com um operador só, a regra é desligada explicitamente,
		// e a razão fica registrada em vez de esquecida.
		if a.SelfApprovalForbidden && before.RequestedBy == actor.ID {
			return errs.Coded(errs.ErrForbidden, "SELF_APPROVAL_FORBIDDEN",
				"quem pediu a ação não pode aprová-la")
		}

		now := a.Clock.Now()
		decided, err = a.Approvals.Decide(ctx, actor.TenantID, cmd.ApprovalID,
			cmd.ExpectedVersion, status, *actor.UserID, cmd.Note, now)
		if err != nil {
			return err
		}
		return a.Audit.Record(ctx, audit.Fact{
			Classification: classificationFor(decided.IncidentID),
			TenantID:       actor.TenantID,
			OccurredAt:     now,
			Actor:          audit.Actor{Kind: audit.ActorKind(actor.Kind), ID: actor.ID, Label: actor.Label},
			Action:         "approval.decide",
			ResourceType:   "approval",
			ResourceID:     decided.ID.String(),
			IncidentID:     decided.IncidentID,
			Result:         audit.Succeeded,
			Reason:         cmd.Note,
			Before:         map[string]any{"status": before.Status},
			After:          map[string]any{"status": status, "action": decided.Action},
			EventType:      "approval.decided",
			Title:          decisionTitle(cmd.Approve, decided),
			Detail:         cmd.Note,
			RequestID:      telemetry.RequestID(ctx),
			TraceID:        telemetry.TraceID(ctx),
		})
	})
	return decided, err
}

func (a *Approver) ListPending(ctx context.Context, limit int) ([]*Approval, error) {
	actor, err := a.Perms.Require(ctx, rbac.IncidentRead)
	if err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	return a.Approvals.ListPending(ctx, actor.TenantID, limit)
}

func decisionTitle(approved bool, a *Approval) string {
	verb := "recusada"
	if approved {
		verb = "aprovada"
	}
	return fmt.Sprintf("Ação %s %s: %s", a.Action, verb, a.Plan.Summary)
}

var _ = time.Time{}
