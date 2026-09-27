package response

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/titas/soar/backend/internal/audit"
	"github.com/titas/soar/backend/internal/auth"
	"github.com/titas/soar/backend/internal/core/clock"
	"github.com/titas/soar/backend/internal/core/errs"
	"github.com/titas/soar/backend/internal/core/id"
	"github.com/titas/soar/backend/internal/integration"
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

type Executor struct {
	Tx        TxManager
	Registry  *integration.Registry
	Assets    AssetRepository
	Approvals ApprovalRepository
	Runs      RunRepository
	Audit     audit.Writer
	Outbox    Outbox
	Perms     rbac.Checker
	Creds     integration.CredentialProvider
	Clock     clock.Clock
	// ApprovalTTL bounds how long a confirmed plan stays confirmable. A plan
	// approved yesterday describes yesterday's world.
	ApprovalTTL time.Duration
}

type PreviewRequest struct {
	Qualified  string // "elastic-siem.close_alerts"
	IncidentID *id.IncidentID
	Input      map[string]any
}

type Preview struct {
	Plan        integration.Plan
	Autonomy    integration.Autonomy
	Fingerprint []byte
	ApprovalID  *id.ApprovalID
	// ApprovalVersion is the optimistic-lock token the UI must send when it
	// decides the approval inline. Keeping it beside the id makes the plan ->
	// decide flow atomic from the operator's point of view without weakening
	// the concurrency check used by the approval queue.
	ApprovalVersion *int
	ExpiresAt       *time.Time
	Reversible      string
	Idempotent      bool
}

// Preview renders the change and, when the action needs a human, persists the
// approval that the execution will be checked against.
func (e *Executor) Preview(ctx context.Context, req PreviewRequest) (*Preview, error) {
	manifest, action, adapter, err := e.Registry.Lookup(req.Qualified)
	if err != nil {
		return nil, errs.Coded(errs.ErrValidation, "UNKNOWN_ACTION", "%v", err)
	}
	actor, err := e.Perms.Require(ctx, action.Permission)
	if err != nil {
		return nil, err
	}
	if !action.Implemented || adapter == nil {
		return nil, errs.Coded(errs.ErrNotImplemented, "ACTION_NOT_IMPLEMENTED",
			"%s", unavailableReason(action))
	}
	if err := validateInput(action, req.Input); err != nil {
		return nil, err
	}

	ref, asset, err := e.resolveAsset(ctx, actor.TenantID, manifest.ID)
	if err != nil {
		return nil, err
	}
	call := integration.ActionCall{
		Integration: manifest.ID, Action: action.ID,
		Asset: *asset, Input: req.Input,
	}

	// Fora de transação: planejar lê o sistema de terceiros.
	planCtx, cancel := context.WithTimeout(ctx, timeoutOf(action))
	defer cancel()
	plan, err := adapter.Plan(planCtx, call)
	if err != nil {
		return nil, errs.Coded(errs.ErrUnavailable, "PLAN_FAILED", "não foi possível planejar: %v", err)
	}
	if plan.Reversible == "" {
		plan.Reversible = action.Reversible
	}
	fingerprint := plan.Fingerprint(manifest.ID, action.ID)

	out := &Preview{
		Plan: *plan, Autonomy: action.Autonomy, Fingerprint: fingerprint,
		Reversible: plan.Reversible, Idempotent: action.Idempotent,
	}
	if action.Autonomy != integration.ApprovalRequired || !plan.Ready {
		return out, nil
	}

	now := e.Clock.Now()
	expires := now.Add(e.ApprovalTTL)
	approval := &Approval{
		ID: id.NewApproval(), TenantID: actor.TenantID, IncidentID: req.IncidentID,
		AssetID: ref.ID, Action: action.ID, Permission: action.Permission,
		Plan: *plan, Fingerprint: fingerprint, Affected: plan.Affected,
		Status: "requested", RequestedBy: actor.ID, RequestedAt: now, ExpiresAt: expires,
		Version: 1,
	}
	err = e.Tx.InTx(ctx, func(ctx context.Context) error {
		if err := e.Approvals.Create(ctx, approval); err != nil {
			return err
		}
		return e.Audit.Record(ctx, e.fact(actor, audit.Fact{
			Classification: classificationFor(req.IncidentID),
			Action:         "approval.request",
			ResourceType:   "approval",
			ResourceID:     approval.ID.String(),
			IncidentID:     req.IncidentID,
			Result:         audit.Succeeded,
			Reason:         plan.Summary,
			After:          map[string]any{"affected": plan.Affected, "action": req.Qualified},
			EventType:      "approval.requested",
			Title:          "Aprovação pedida: " + plan.Summary,
			Detail:         plan.Reversible,
		}, now, ctx))
	})
	if err != nil {
		return nil, err
	}
	out.ApprovalID, out.ApprovalVersion, out.ExpiresAt = &approval.ID, &approval.Version, &expires
	return out, nil
}

type ExecuteRequest struct {
	Qualified      string
	IncidentID     *id.IncidentID
	Input          map[string]any
	ApprovalID     *id.ApprovalID
	IdempotencyKey string
}

// Execute performs the action, and refuses in every case where it cannot
// prove that what is about to happen is what was confirmed.
func (e *Executor) Execute(ctx context.Context, req ExecuteRequest) (*Run, error) {
	manifest, action, adapter, err := e.Registry.Lookup(req.Qualified)
	if err != nil {
		return nil, errs.Coded(errs.ErrValidation, "UNKNOWN_ACTION", "%v", err)
	}
	actor, err := e.Perms.Require(ctx, action.Permission)
	if err != nil {
		return nil, err
	}
	if !action.Implemented || adapter == nil {
		return nil, errs.Coded(errs.ErrNotImplemented, "ACTION_NOT_IMPLEMENTED",
			"%s", unavailableReason(action))
	}
	if req.IdempotencyKey == "" {
		return nil, errs.Coded(errs.ErrValidation, "IDEMPOTENCY_KEY_REQUIRED",
			"toda execução de ação externa exige Idempotency-Key")
	}
	// Repetir a chave devolve o resultado gravado. Sem isto, um timeout do
	// cliente vira uma segunda execução em produção.
	if prev, err := e.Runs.ByIdempotencyKey(ctx, actor.TenantID, req.IdempotencyKey); err != nil {
		return nil, err
	} else if prev != nil {
		return prev, nil
	}
	if err := validateInput(action, req.Input); err != nil {
		return nil, err
	}

	ref, asset, err := e.resolveAsset(ctx, actor.TenantID, manifest.ID)
	if err != nil {
		return nil, err
	}

	var approval *Approval
	if action.Autonomy == integration.ApprovalRequired {
		approval, err = e.checkApproval(ctx, actor, action, req)
		if err != nil {
			return nil, err
		}
	}

	call := integration.ActionCall{
		Integration: manifest.ID, Action: action.ID, Asset: *asset, Input: req.Input,
	}

	// Replanejar e comparar o fingerprint: é o que impede confirmar um plano
	// que dizia "42 alertas" e executar contra os 4.000 que chegaram no meio.
	if action.Plan {
		planCtx, cancel := context.WithTimeout(ctx, timeoutOf(action))
		fresh, planErr := adapter.Plan(planCtx, call)
		cancel()
		if planErr != nil {
			return nil, errs.Coded(errs.ErrUnavailable, "REPLAN_FAILED",
				"não foi possível revalidar o plano: %v", planErr)
		}
		if !fresh.Ready {
			return nil, errs.Coded(errs.ErrConflict, "PLAN_NOT_APPLICABLE",
				"o plano deixou de ser aplicável: %s", fresh.Summary)
		}
		current := fresh.Fingerprint(manifest.ID, action.ID)
		if approval != nil && subtle.ConstantTimeCompare(current, approval.Fingerprint) != 1 {
			// O mundo mudou desde a aprovação. A aprovação morre; não se
			// executa "quase o que foi confirmado".
			_ = e.Approvals.Supersede(ctx, actor.TenantID, approval.ID)
			return nil, errs.Coded(errs.ErrConflict, "PLAN_SUPERSEDED",
				"a situação mudou desde a pré-visualização; revise o plano e aprove de novo")
		}
		// A requisição executada é literalmente a que foi planejada.
		call.Input["__request"] = fresh.Request
	}

	now := e.Clock.Now()
	run := &Run{
		ID: id.NewActionRun(), TenantID: actor.TenantID, IncidentID: req.IncidentID,
		AssetID: ref.ID, Integration: manifest.ID, Action: action.ID,
		IdempotencyKey: req.IdempotencyKey, Autonomy: action.Autonomy,
		Status: "running", Input: redactInput(req.Input),
		ActorKind: actor.Kind, ActorID: actor.ID, RequestedAt: now, StartedAt: &now,
	}
	if approval != nil {
		run.ApprovalID, run.Fingerprint = &approval.ID, approval.Fingerprint
	}

	// TRANSAÇÃO 1: a intenção. Grava a execução como `running` e consome a
	// aprovação, para que ela não sirva duas vezes.
	if err := e.Tx.InTx(ctx, func(ctx context.Context) error {
		if err := e.Runs.Start(ctx, run); err != nil {
			return err
		}
		if approval != nil {
			if err := e.Approvals.Consume(ctx, actor.TenantID, approval.ID); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}

	// FORA DE TRANSAÇÃO: a chamada externa.
	execCtx, cancel := context.WithTimeout(ctx, timeoutOf(action))
	result, execErr := adapter.Execute(execCtx, call)
	cancel()

	finished := e.Clock.Now()
	latency := int(finished.Sub(now).Milliseconds())
	run.FinishedAt, run.LatencyMS = &finished, &latency
	if execErr != nil {
		run.Status, run.Error = "failed", execErr.Error()
	} else {
		run.Status, run.Output, run.Affected = "succeeded", result.Output, result.Affected
	}

	// TRANSAÇÃO 2: o resultado, a auditoria e o evento.
	if err := e.Tx.InTx(ctx, func(ctx context.Context) error {
		if err := e.Runs.Finish(ctx, run); err != nil {
			return err
		}
		outcome, result := audit.Succeeded, "executada"
		if execErr != nil {
			outcome, result = audit.Failed, "falhou"
		}
		if err := e.Audit.Record(ctx, e.fact(actor, audit.Fact{
			Classification: classificationFor(req.IncidentID),
			Action:         "response.execute",
			ResourceType:   "action_run",
			ResourceID:     run.ID.String(),
			IncidentID:     req.IncidentID,
			Result:         outcome,
			Reason:         run.Error,
			After: map[string]any{
				"action": req.Qualified, "affected": run.Affected, "autonomy": string(action.Autonomy),
			},
			EventType: "action.executed",
			Title:     fmt.Sprintf("Ação %s %s", req.Qualified, result),
			Detail:    summaryOf(run),
		}, finished, ctx)); err != nil {
			return err
		}
		topic := "action.executed"
		if execErr != nil {
			topic = "action.failed"
		}
		var aggregate *uuid.UUID
		if req.IncidentID != nil {
			aggregate = &req.IncidentID.UUID
		}
		return e.Outbox.Enqueue(ctx, actor.TenantID, []outbox.Event{{
			Topic: topic, AggregateID: aggregate,
			ActorKind: actor.Kind, ActorID: actor.ID,
			Payload: map[string]any{
				"action": req.Qualified, "run_id": run.ID.String(),
				"affected": run.Affected, "status": run.Status,
			},
			TraceID: telemetry.TraceID(ctx),
		}})
	}); err != nil {
		return nil, err
	}

	if execErr != nil {
		return run, errs.Coded(errs.ErrUnavailable, "ACTION_FAILED",
			"a ação falhou: %v", execErr)
	}
	return run, nil
}

func (e *Executor) checkApproval(ctx context.Context, actor auth.Actor,
	action integration.Action, req ExecuteRequest) (*Approval, error) {

	if req.ApprovalID == nil {
		return nil, errs.Coded(errs.ErrApprovalRequired, "APPROVAL_REQUIRED",
			"%s exige aprovação: planeje, aprove e então execute", req.Qualified)
	}
	approval, err := e.Approvals.Get(ctx, actor.TenantID, *req.ApprovalID)
	if err != nil {
		return nil, err
	}
	switch {
	case approval == nil:
		return nil, errs.Coded(errs.ErrNotFound, "APPROVAL_NOT_FOUND", "aprovação não encontrada")
	case approval.Action != action.ID:
		// Uma aprovação de "fechar alertas" não autoriza "criar exceção".
		return nil, errs.Coded(errs.ErrForbidden, "APPROVAL_MISMATCH",
			"a aprovação é para %q, não para %q", approval.Action, action.ID)
	case approval.Status == "consumed":
		return nil, errs.Coded(errs.ErrConflict, "APPROVAL_ALREADY_USED",
			"esta aprovação já foi usada")
	case !approval.Approved(e.Clock.Now()):
		return nil, errs.Coded(errs.ErrApprovalRequired, "APPROVAL_NOT_GRANTED",
			"aprovação em estado %q", approval.Status)
	}
	return approval, nil
}

// resolveAsset devolve os dois: a referência tipada, que o registro de
// execução e a aprovação precisam, e o Asset resolvido que o adapter recebe.
func (e *Executor) resolveAsset(ctx context.Context, tenant id.TenantID, slug string) (*AssetRef, *integration.Asset, error) {
	ref, err := e.Assets.ByIntegration(ctx, tenant, slug)
	if err != nil {
		return nil, nil, err
	}
	if ref == nil || !ref.Enabled {
		return nil, nil, errs.Coded(errs.ErrUnavailable, "INTEGRATION_NOT_CONFIGURED",
			"integração %q não está configurada neste ambiente", slug)
	}
	if ref.Circuit == "open" {
		return nil, nil, errs.Coded(errs.ErrUnavailable, "CIRCUIT_OPEN",
			"o circuito de %q está aberto após falhas repetidas", slug)
	}
	secret, err := e.Creds.Resolve(ref.CredRef)
	if err != nil {
		var missing integration.ErrNoCredential
		if errors.As(err, &missing) {
			return nil, nil, errs.Coded(errs.ErrUnavailable, "CREDENTIAL_MISSING",
				"credencial de %q não está configurada (%s)", slug, ref.CredRef)
		}
		return nil, nil, err
	}
	return ref, &integration.Asset{
		ID: ref.ID.String(), Name: ref.Name, Endpoint: ref.Endpoint,
		Credential: secret, Config: ref.Config,
	}, nil
}

func (e *Executor) fact(actor auth.Actor, f audit.Fact, at time.Time, ctx context.Context) audit.Fact {
	f.TenantID, f.OccurredAt = actor.TenantID, at
	f.Actor = audit.Actor{Kind: audit.ActorKind(actor.Kind), ID: actor.ID, Label: actor.Label}
	f.RequestID, f.TraceID = telemetry.RequestID(ctx), telemetry.TraceID(ctx)
	return f
}

func classificationFor(incidentID *id.IncidentID) audit.Classification {
	if incidentID != nil {
		return audit.Both
	}
	return audit.AuditOnly
}

func timeoutOf(a integration.Action) time.Duration {
	if a.Timeout > 0 {
		return a.Timeout
	}
	return 60 * time.Second
}

func unavailableReason(a integration.Action) string {
	if a.Unavailable != "" {
		return a.Unavailable
	}
	return "esta ação não tem implementação neste deploy"
}

func summaryOf(r *Run) string {
	if r.Error != "" {
		return r.Error
	}
	if r.Affected != nil {
		return fmt.Sprintf("%d objeto(s) afetado(s)", *r.Affected)
	}
	return ""
}

// redactInput keeps secrets out of the persisted record. The same list is
// applied at the logging edge, on purpose: two independent places, because
// one of them will be forgotten some day.
func redactInput(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		switch k {
		case "password", "token", "api_key", "secret", "credential", "__request":
			continue
		default:
			out[k] = v
		}
	}
	return out
}

func validateInput(a integration.Action, in map[string]any) error {
	for name, spec := range a.Input {
		if !spec.Required {
			continue
		}
		v, ok := in[name]
		if !ok || v == nil || v == "" {
			return errs.Coded(errs.ErrValidation, "MISSING_INPUT",
				"campo obrigatório ausente: %s", name)
		}
	}
	return nil
}
