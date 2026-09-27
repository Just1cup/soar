package response

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/titas/soar/backend/internal/audit"
	"github.com/titas/soar/backend/internal/auth"
	"github.com/titas/soar/backend/internal/core/clock"
	"github.com/titas/soar/backend/internal/core/errs"
	"github.com/titas/soar/backend/internal/core/id"
	"github.com/titas/soar/backend/internal/integration"
	"github.com/titas/soar/backend/internal/platform/outbox"
	"github.com/titas/soar/backend/internal/rbac"
)

// --- dublês ---------------------------------------------------------------

type fakeTx struct{}

func (fakeTx) InTx(ctx context.Context, fn func(context.Context) error) error { return fn(ctx) }

type fakeAudit struct{ facts []audit.Fact }

func (f *fakeAudit) Record(_ context.Context, fact audit.Fact) error {
	f.facts = append(f.facts, fact)
	return nil
}

type fakeOutbox struct{ events []outbox.Event }

func (f *fakeOutbox) Enqueue(_ context.Context, _ id.TenantID, e []outbox.Event) error {
	f.events = append(f.events, e...)
	return nil
}

type fakeAssets struct{ ref *AssetRef }

func (f *fakeAssets) ByIntegration(context.Context, id.TenantID, string) (*AssetRef, error) {
	return f.ref, nil
}
func (f *fakeAssets) SetCircuit(context.Context, id.AssetID, string, *time.Time) error { return nil }
func (f *fakeAssets) SetHealth(context.Context, id.AssetID, string, string, time.Time) error {
	return nil
}

type fakeApprovals struct {
	stored     map[string]*Approval
	consumed   []string
	superseded []string
}

func newApprovals() *fakeApprovals {
	return &fakeApprovals{stored: map[string]*Approval{}}
}
func (f *fakeApprovals) Create(_ context.Context, a *Approval) error {
	f.stored[a.ID.String()] = a
	return nil
}
func (f *fakeApprovals) Get(_ context.Context, _ id.TenantID, a id.ApprovalID) (*Approval, error) {
	return f.stored[a.String()], nil
}
func (f *fakeApprovals) ListPending(context.Context, id.TenantID, int) ([]*Approval, error) {
	return nil, nil
}
func (f *fakeApprovals) Decide(context.Context, id.TenantID, id.ApprovalID, int, string, id.UserID, string, time.Time) (*Approval, error) {
	return nil, nil
}
func (f *fakeApprovals) Supersede(_ context.Context, _ id.TenantID, a id.ApprovalID) error {
	f.superseded = append(f.superseded, a.String())
	if s := f.stored[a.String()]; s != nil {
		s.Status = "superseded"
	}
	return nil
}
func (f *fakeApprovals) Consume(_ context.Context, _ id.TenantID, a id.ApprovalID) error {
	f.consumed = append(f.consumed, a.String())
	if s := f.stored[a.String()]; s != nil {
		s.Status = "consumed"
	}
	return nil
}

type fakeRuns struct{ started, finished []*Run }

func (f *fakeRuns) Start(_ context.Context, r *Run) error {
	f.started = append(f.started, r)
	return nil
}
func (f *fakeRuns) Finish(_ context.Context, r *Run) error {
	f.finished = append(f.finished, r)
	return nil
}
func (f *fakeRuns) ByIdempotencyKey(_ context.Context, _ id.TenantID, key string) (*Run, error) {
	for _, r := range f.finished {
		if r.IdempotencyKey == key {
			return r, nil
		}
	}
	return nil, nil
}
func (f *fakeRuns) ListByIncident(context.Context, id.TenantID, id.IncidentID, int) ([]*Run, error) {
	return nil, nil
}

// fakeAdapter deixa o teste mover o mundo entre o plano e a execução.
type fakeAdapter struct {
	affected  int
	executed  int
	failWith  error
	lastInput map[string]any
}

func (f *fakeAdapter) Slug() string { return "fake" }
func (f *fakeAdapter) Plan(_ context.Context, _ integration.ActionCall) (*integration.Plan, error) {
	n := f.affected
	return &integration.Plan{
		Summary: "plano", Affected: &n, Ready: n > 0,
		Request: map[string]any{"method": "POST", "url": "http://x", "body": map[string]any{"n": n}},
	}, nil
}
func (f *fakeAdapter) Execute(_ context.Context, c integration.ActionCall) (*integration.Result, error) {
	f.executed++
	f.lastInput = c.Input
	if f.failWith != nil {
		return nil, f.failWith
	}
	n := f.affected
	return &integration.Result{Affected: &n, Output: map[string]any{"updated": n}}, nil
}
func (f *fakeAdapter) Health(context.Context, integration.Asset) error { return nil }

// --- montagem -------------------------------------------------------------

var tenant = id.TenantID{UUID: uuid.MustParse("00000000-0000-7000-8000-000000000001")}

func manifest() integration.Manifest {
	return integration.Manifest{
		ID: "fake", Name: "Fake",
		Actions: []integration.Action{{
			ID: "close", Autonomy: integration.ApprovalRequired,
			Permission: rbac.ResponseCloseAlerts, Idempotent: true, Plan: true,
			Reversible: "desfazer", Implemented: true,
			Input: map[string]integration.FieldSpec{"rule_name": {Type: "string", Required: true}},
		}, {
			ID: "enrich", Autonomy: integration.AutoExec,
			Permission: rbac.IncidentRead, Idempotent: true, Implemented: true,
		}, {
			ID: "isolate", Autonomy: integration.ApprovalRequired,
			Permission: rbac.ResponseCloseAlerts, Plan: true, Reversible: "console",
			Implemented: false, Unavailable: "sem adapter neste deploy",
		}},
	}
}

type harness struct {
	exec      *Executor
	adapter   *fakeAdapter
	approvals *fakeApprovals
	runs      *fakeRuns
	trail     *fakeAudit
	bus       *fakeOutbox
	clock     *clock.Fixed
}

func newHarness(t *testing.T, perms ...string) *harness {
	t.Helper()
	reg := integration.NewRegistry()
	reg.Install(manifest())
	adapter := &fakeAdapter{affected: 42}
	reg.Bind(adapter)

	h := &harness{
		adapter: adapter, approvals: newApprovals(), runs: &fakeRuns{},
		trail: &fakeAudit{}, bus: &fakeOutbox{},
		clock: &clock.Fixed{T: time.Date(2026, 9, 21, 3, 0, 0, 0, time.UTC)},
	}
	h.exec = &Executor{
		Tx: fakeTx{}, Registry: reg,
		Assets: &fakeAssets{ref: &AssetRef{
			ID: id.AssetID{UUID: uuid.New()}, Integration: "fake", Name: "default",
			Endpoint: "http://kibana", CredRef: "none://", Enabled: true, Circuit: "closed",
		}},
		Approvals: h.approvals, Runs: h.runs, Audit: h.trail, Outbox: h.bus,
		Perms: rbac.Checker{}, Creds: integration.NewChainProvider(),
		Clock: h.clock, ApprovalTTL: 30 * time.Minute,
	}
	return h
}

func ctxWith(perms ...string) context.Context {
	p := map[string]bool{}
	for _, x := range perms {
		p[x] = true
	}
	return auth.WithActor(context.Background(), auth.Actor{
		Kind: "user", ID: "u1", Label: "analista", TenantID: tenant, Perms: p,
	})
}

// --- os invariantes -------------------------------------------------------

func TestApprovalRequiredActionRefusesWithoutApproval(t *testing.T) {
	h := newHarness(t)
	_, err := h.exec.Execute(ctxWith(rbac.ResponseCloseAlerts), ExecuteRequest{
		Qualified: "fake.close", IdempotencyKey: "k1",
		Input: map[string]any{"rule_name": "R"},
	})
	if !errors.Is(err, errs.ErrApprovalRequired) {
		t.Fatalf("esperava ErrApprovalRequired, veio %v", err)
	}
	if h.adapter.executed != 0 {
		t.Fatal("a ação executou sem aprovação")
	}
}

// O invariante central: confirmar um plano que dizia 42 e executar contra
// 4.000 é exatamente o que o fingerprint existe para impedir.
func TestWorldChangingBetweenPlanAndExecuteSupersedesApproval(t *testing.T) {
	ctx := ctxWith(rbac.ResponseCloseAlerts, rbac.ApprovalDecide)
	h := newHarness(t)

	preview, err := h.exec.Preview(ctx, PreviewRequest{
		Qualified: "fake.close", Input: map[string]any{"rule_name": "R"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if preview.ApprovalVersion == nil || *preview.ApprovalVersion != 1 {
		t.Fatalf("versão inicial da aprovação = %v; a decisão inline precisa do token 1", preview.ApprovalVersion)
	}
	approval := h.approvals.stored[preview.ApprovalID.String()]
	approval.Status = "approved"

	// O mundo se move: 42 -> 4000.
	h.adapter.affected = 4000

	_, err = h.exec.Execute(ctx, ExecuteRequest{
		Qualified: "fake.close", ApprovalID: preview.ApprovalID, IdempotencyKey: "k2",
		Input: map[string]any{"rule_name": "R"},
	})
	if !errors.Is(err, errs.ErrConflict) {
		t.Fatalf("esperava conflito, veio %v", err)
	}
	if errs.CodeOf(err) != "PLAN_SUPERSEDED" {
		t.Fatalf("code = %q", errs.CodeOf(err))
	}
	if h.adapter.executed != 0 {
		t.Fatal("executou contra um mundo diferente do confirmado")
	}
	if len(h.approvals.superseded) != 1 {
		t.Fatal("a aprovação obsoleta deveria ter sido invalidada")
	}
}

func TestApprovedPlanExecutesAndIsConsumedOnce(t *testing.T) {
	ctx := ctxWith(rbac.ResponseCloseAlerts)
	h := newHarness(t)

	preview, _ := h.exec.Preview(ctx, PreviewRequest{
		Qualified: "fake.close", Input: map[string]any{"rule_name": "R"},
	})
	h.approvals.stored[preview.ApprovalID.String()].Status = "approved"

	run, err := h.exec.Execute(ctx, ExecuteRequest{
		Qualified: "fake.close", ApprovalID: preview.ApprovalID, IdempotencyKey: "k3",
		Input: map[string]any{"rule_name": "R"},
	})
	if err != nil {
		t.Fatalf("execução legítima falhou: %v", err)
	}
	if run.Status != "succeeded" || run.Affected == nil || *run.Affected != 42 {
		t.Fatalf("resultado inesperado: %+v", run)
	}
	if len(h.approvals.consumed) != 1 {
		t.Fatal("a aprovação deveria ter sido consumida")
	}
	// A requisição executada é literalmente a planejada.
	if _, ok := h.adapter.lastInput["__request"]; !ok {
		t.Fatal("executou sem a requisição do plano revalidado")
	}

	// Usar a mesma aprovação de novo é recusado.
	_, err = h.exec.Execute(ctx, ExecuteRequest{
		Qualified: "fake.close", ApprovalID: preview.ApprovalID, IdempotencyKey: "k4",
		Input: map[string]any{"rule_name": "R"},
	})
	if errs.CodeOf(err) != "APPROVAL_ALREADY_USED" {
		t.Fatalf("aprovação reusada deveria falhar, veio %v", err)
	}
}

func TestIdempotencyKeyReturnsRecordedRun(t *testing.T) {
	ctx := ctxWith(rbac.ResponseCloseAlerts)
	h := newHarness(t)
	preview, _ := h.exec.Preview(ctx, PreviewRequest{
		Qualified: "fake.close", Input: map[string]any{"rule_name": "R"},
	})
	h.approvals.stored[preview.ApprovalID.String()].Status = "approved"

	first, err := h.exec.Execute(ctx, ExecuteRequest{
		Qualified: "fake.close", ApprovalID: preview.ApprovalID, IdempotencyKey: "mesma",
		Input: map[string]any{"rule_name": "R"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// O cliente perdeu a resposta por timeout e repete.
	second, err := h.exec.Execute(ctx, ExecuteRequest{
		Qualified: "fake.close", ApprovalID: preview.ApprovalID, IdempotencyKey: "mesma",
		Input: map[string]any{"rule_name": "R"},
	})
	if err != nil {
		t.Fatalf("repetição deveria devolver o registro: %v", err)
	}
	if h.adapter.executed != 1 {
		t.Fatalf("executou %d vezes; deveria ser 1", h.adapter.executed)
	}
	if first.ID != second.ID {
		t.Fatal("a repetição devolveu uma execução diferente")
	}
}

func TestExecuteWithoutIdempotencyKeyIsRefused(t *testing.T) {
	h := newHarness(t)
	_, err := h.exec.Execute(ctxWith(rbac.IncidentRead), ExecuteRequest{Qualified: "fake.enrich"})
	if errs.CodeOf(err) != "IDEMPOTENCY_KEY_REQUIRED" {
		t.Fatalf("veio %v", err)
	}
}

func TestRbacIsCheckedBeforeAnythingElse(t *testing.T) {
	h := newHarness(t)
	// Sem a permissão, nem o plano acontece — não se vaza a contagem de um
	// escopo para quem não pode agir sobre ele.
	_, err := h.exec.Preview(ctxWith(rbac.IncidentRead), PreviewRequest{
		Qualified: "fake.close", Input: map[string]any{"rule_name": "R"},
	})
	if !errors.Is(err, errs.ErrForbidden) {
		t.Fatalf("esperava ErrForbidden, veio %v", err)
	}
}

func TestUnimplementedActionAnswersNotImplementedWithReason(t *testing.T) {
	h := newHarness(t)
	_, err := h.exec.Preview(ctxWith(rbac.ResponseCloseAlerts), PreviewRequest{
		Qualified: "fake.isolate", Input: map[string]any{"host": "h"},
	})
	if !errors.Is(err, errs.ErrNotImplemented) {
		t.Fatalf("esperava ErrNotImplemented, veio %v", err)
	}
	if got := err.Error(); got != "sem adapter neste deploy" {
		t.Fatalf("a razão deveria chegar ao operador, veio %q", got)
	}
}

func TestMissingRequiredInputIsRefused(t *testing.T) {
	h := newHarness(t)
	_, err := h.exec.Preview(ctxWith(rbac.ResponseCloseAlerts), PreviewRequest{
		Qualified: "fake.close", Input: map[string]any{},
	})
	if errs.CodeOf(err) != "MISSING_INPUT" {
		t.Fatalf("veio %v", err)
	}
}

func TestFailedExecutionIsRecordedAndAudited(t *testing.T) {
	ctx := ctxWith(rbac.ResponseCloseAlerts)
	h := newHarness(t)
	preview, _ := h.exec.Preview(ctx, PreviewRequest{
		Qualified: "fake.close", Input: map[string]any{"rule_name": "R"},
	})
	h.approvals.stored[preview.ApprovalID.String()].Status = "approved"
	h.adapter.failWith = errors.New("kibana fora do ar")

	run, err := h.exec.Execute(ctx, ExecuteRequest{
		Qualified: "fake.close", ApprovalID: preview.ApprovalID, IdempotencyKey: "k5",
		Input: map[string]any{"rule_name": "R"},
	})
	if err == nil {
		t.Fatal("esperava erro")
	}
	if run == nil || run.Status != "failed" {
		t.Fatalf("a falha precisa ficar registrada: %+v", run)
	}
	// Falhar também é um fato auditável: "tentamos e não conseguiu" é
	// diferente de "ninguém tentou".
	var sawFailure bool
	for _, f := range h.trail.facts {
		if f.Action == "response.execute" && f.Result == audit.Failed {
			sawFailure = true
		}
	}
	if !sawFailure {
		t.Fatal("a falha não foi auditada")
	}
	if len(h.bus.events) == 0 || h.bus.events[len(h.bus.events)-1].Topic != "action.failed" {
		t.Fatal("o evento action.failed não foi publicado")
	}
}
