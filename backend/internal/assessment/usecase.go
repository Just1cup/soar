package assessment

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/titas/soar/backend/internal/audit"
	"github.com/titas/soar/backend/internal/core/clock"
	"github.com/titas/soar/backend/internal/core/errs"
	"github.com/titas/soar/backend/internal/core/id"
	"github.com/titas/soar/backend/internal/platform/outbox"
	"github.com/titas/soar/backend/internal/platform/telemetry"
	"github.com/titas/soar/backend/internal/rbac"
)

type TxManager interface {
	InTx(ctx context.Context, fn func(context.Context) error) error
}

type Outbox interface {
	Enqueue(ctx context.Context, tenant id.TenantID, events []outbox.Event) error
}

type Repository interface {
	Save(ctx context.Context, a *Assessment) error
	ByIncident(ctx context.Context, tenant id.TenantID, incidentID id.IncidentID) ([]*Assessment, error)
	Get(ctx context.Context, tenant id.TenantID, assessmentID id.AssessmentID) (*Assessment, error)
	MarkPromoted(ctx context.Context, tenant id.TenantID, assessmentID id.AssessmentID, by id.UserID, at time.Time) error
	HasAssessment(ctx context.Context, tenant id.TenantID, incidentID id.IncidentID) (bool, error)
}

type Service struct {
	Tx        TxManager
	Repo      Repository
	Generator *Generator
	Context   *ContextBuilder
	Audit     audit.Writer
	Outbox    Outbox
	Perms     rbac.Checker
	Clock     clock.Clock
	Log       *slog.Logger
}

// Evidence builds the deterministic case facts without invoking the model.
// It is deliberately available even when automatic assessment is disabled or
// still queued: collecting telemetry and weighing it are different jobs.
func (s *Service) Evidence(ctx context.Context, incidentID id.IncidentID) (*ReferenceBundle, error) {
	actor, err := s.Perms.Require(ctx, rbac.IncidentRead)
	if err != nil {
		return nil, err
	}
	if s.Context == nil {
		return nil, errs.Coded(errs.ErrUnavailable, "CASE_EVIDENCE_DISABLED",
			"coleta de evidências do caso está indisponível")
	}
	bundle, err := s.Context.BuildReference(ctx, actor.TenantID, incidentID)
	if err != nil {
		return nil, fmt.Errorf("construir evidências do caso: %w", err)
	}
	return bundle, nil
}

// Analyse generates an assessment and attaches it to the incident.
//
// It runs under the system:assessment actor, which by construction holds
// neither incident.close nor assessment.promote: the model cannot close
// anything, and cannot adopt its own conclusion. That is enforced by RBAC,
// not by this function being careful.
func (s *Service) Analyse(ctx context.Context, tenant id.TenantID, incidentID id.IncidentID) (*Assessment, error) {
	if s.Generator == nil {
		return nil, errs.Coded(errs.ErrUnavailable, "ASSESSMENT_DISABLED",
			"geração automática de avaliações está desabilitada")
	}
	// At-least-once delivery means this can be called twice for one incident.
	// Regenerating would burn thirty seconds of GPU to produce a duplicate.
	already, err := s.Repo.HasAssessment(ctx, tenant, incidentID)
	if err != nil {
		return nil, err
	}
	if already {
		return nil, nil
	}

	// FORA de transação: a inferência leva dezenas de segundos, e uma
	// transação aberta esperando a GPU esgota o pool.
	a, err := s.Generator.Generate(ctx, tenant, incidentID)
	if err != nil {
		return nil, err
	}

	err = s.Tx.InTx(ctx, func(ctx context.Context) error {
		if err := s.Repo.Save(ctx, a); err != nil {
			return err
		}
		detail := fmt.Sprintf("%s · confiança %s · Admiralty %s",
			VerdictLabel[a.Verdict], a.Confidence, a.Admiralty())
		if a.Disagreed() {
			// A discordância entre os dois passes é mostrada, não escondida.
			detail += " · os dois passes discordaram"
		}
		if err := s.Audit.Record(ctx, audit.Fact{
			Classification: audit.TimelineOnly,
			TenantID:       tenant, OccurredAt: a.GeneratedAt,
			Actor:      audit.Actor{Kind: audit.ActorSystem, ID: "system:assessment", Label: "analista local"},
			IncidentID: &incidentID,
			EventType:  "assessment.created",
			Title:      "Avaliação automática: " + a.Title,
			Detail:     detail,
			Payload: map[string]any{
				"assessment_id": a.ID.String(), "verdict": string(a.Verdict),
				"model": a.Model, "latency_ms": a.LatencyMS,
			},
			RequestID: telemetry.RequestID(ctx),
		}); err != nil {
			return err
		}
		aggregate := incidentID.UUID
		return s.Outbox.Enqueue(ctx, tenant, []outbox.Event{{
			Topic: "assessment.created", AggregateID: &aggregate,
			ActorKind: "system", ActorID: "system:assessment",
			Payload: map[string]any{
				"incident_id": incidentID.String(), "assessment_id": a.ID.String(),
				"verdict": string(a.Verdict), "confidence": string(a.Confidence),
			},
		}})
	})
	return a, err
}

func (s *Service) List(ctx context.Context, incidentID id.IncidentID) ([]*Assessment, error) {
	actor, err := s.Perms.Require(ctx, rbac.IncidentRead)
	if err != nil {
		return nil, err
	}
	return s.Repo.ByIncident(ctx, actor.TenantID, incidentID)
}

// Promote is a HUMAN act: "I agree with this analysis."
//
// It deliberately does NOT close the incident. Agreeing with an analysis and
// deciding to close a case are different decisions, held by different
// permissions — and collapsing them would let one click do both, which is
// exactly how an automated verdict becomes an automated closure.
func (s *Service) Promote(ctx context.Context, incidentID id.IncidentID,
	assessmentID id.AssessmentID, note string) (*Assessment, error) {

	actor, err := s.Perms.Require(ctx, rbac.AssessmentPromote)
	if err != nil {
		return nil, err
	}
	if actor.UserID == nil {
		return nil, errs.Coded(errs.ErrForbidden, "HUMAN_REQUIRED",
			"promover uma avaliação é ato humano")
	}
	note = strings.TrimSpace(note)
	if note == "" {
		return nil, errs.Coded(errs.ErrValidation, "PROMOTION_NOTE_REQUIRED",
			"informe por que esta avaliação será promovida")
	}
	if len(note) > 4000 {
		return nil, errs.Coded(errs.ErrValidation, "PROMOTION_NOTE_TOO_LONG",
			"a justificativa excede 4000 caracteres")
	}

	var promoted *Assessment
	err = s.Tx.InTx(ctx, func(ctx context.Context) error {
		a, err := s.Repo.Get(ctx, actor.TenantID, assessmentID)
		if err != nil {
			return err
		}
		if a == nil {
			return errs.Coded(errs.ErrNotFound, "ASSESSMENT_NOT_FOUND", "avaliação não encontrada")
		}
		if a.IncidentID != incidentID {
			return errs.Coded(errs.ErrNotFound, "ASSESSMENT_NOT_FOUND", "avaliação não encontrada")
		}
		now := s.Clock.Now()
		if err := s.Repo.MarkPromoted(ctx, actor.TenantID, assessmentID, *actor.UserID, now); err != nil {
			return err
		}
		a.PromotedAt, a.PromotedBy = &now, actor.UserID
		promoted = a

		return s.Audit.Record(ctx, audit.Fact{
			// Both: é decisão de alguém sobre um incidente.
			Classification: audit.Both,
			TenantID:       actor.TenantID, OccurredAt: now,
			Actor:        audit.Actor{Kind: audit.ActorKind(actor.Kind), ID: actor.ID, Label: actor.Label},
			Action:       "assessment.promote",
			ResourceType: "assessment",
			ResourceID:   assessmentID.String(),
			IncidentID:   &a.IncidentID,
			Result:       audit.Succeeded,
			Reason:       note,
			After:        map[string]any{"verdict": string(a.Verdict), "confidence": string(a.Confidence)},
			EventType:    "assessment.promoted",
			Title:        "Avaliação adotada: " + VerdictLabel[a.Verdict],
			Detail:       note,
			RequestID:    telemetry.RequestID(ctx),
			TraceID:      telemetry.TraceID(ctx),
		})
	})
	return promoted, err
}

// HandleIncidentCreated adapts the durable outbox event to the use case. The
// payload is produced by our ingestion pipeline, but it is still validated at
// the boundary so a malformed event cannot become a zero UUID query.
func (s *Service) HandleIncidentCreated(ctx context.Context, event outbox.Delivered) error {
	raw, ok := event.Payload["incident_id"].(string)
	if !ok || raw == "" {
		return fmt.Errorf("incident.created %s sem incident_id", event.EventID)
	}
	incidentID, err := id.ParseIncident(raw)
	if err != nil {
		return fmt.Errorf("incident.created %s: %w", event.EventID, err)
	}
	tenant := id.TenantID{UUID: event.TenantID}
	created, err := s.Analyse(ctx, tenant, incidentID)
	if err != nil {
		return err
	}
	if created != nil && s.Log != nil {
		s.Log.Info("avaliação local criada", "assessment_id", created.ID,
			"incident_id", incidentID, "verdict", created.Verdict,
			"latency_ms", created.LatencyMS)
	}
	return nil
}
