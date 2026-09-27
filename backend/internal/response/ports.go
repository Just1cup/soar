// Package response executes actions against other systems.
//
// Everything here follows one shape, and the shape is the whole point:
//
//	autorizar -> planejar -> aprovar -> revalidar o plano -> executar -> auditar
//
// The external call NEVER happens inside a database transaction. Two short
// transactions bracket it instead: one records the intent, one records the
// outcome. A transaction held open waiting fifteen seconds on a vendor is the
// fastest way to exhaust the pool (docs/soar/07 §6.9).
package response

import (
	"context"
	"time"

	"github.com/titas/soar/backend/internal/core/id"
	"github.com/titas/soar/backend/internal/integration"
)

type AssetRef struct {
	ID          id.AssetID
	Integration string
	Name        string
	Endpoint    string
	CredRef     string
	Config      map[string]any
	Enabled     bool
	Circuit     string
}

type Approval struct {
	ID          id.ApprovalID
	TenantID    id.TenantID
	IncidentID  *id.IncidentID
	AssetID     id.AssetID
	Action      string
	Permission  string
	Plan        integration.Plan
	Fingerprint []byte
	Affected    *int
	Status      string
	RequestedBy string
	RequestedAt time.Time
	ExpiresAt   time.Time
	DecidedBy   *id.UserID
	DecidedAt   *time.Time
	Note        string
	Version     int
}

func (a Approval) Approved(now time.Time) bool {
	return a.Status == "approved" && now.Before(a.ExpiresAt)
}

type Run struct {
	ID             id.ActionRunID
	TenantID       id.TenantID
	IncidentID     *id.IncidentID
	AssetID        id.AssetID
	Integration    string
	Action         string
	ApprovalID     *id.ApprovalID
	IdempotencyKey string
	Fingerprint    []byte
	Autonomy       integration.Autonomy
	Status         string
	Input          map[string]any
	Output         map[string]any
	Error          string
	Affected       *int
	ActorKind      string
	ActorID        string
	RequestedAt    time.Time
	StartedAt      *time.Time
	FinishedAt     *time.Time
	LatencyMS      *int
}

type AssetRepository interface {
	ByIntegration(ctx context.Context, tenant id.TenantID, slug string) (*AssetRef, error)
	SetCircuit(ctx context.Context, assetID id.AssetID, state string, until *time.Time) error
	SetHealth(ctx context.Context, assetID id.AssetID, status, detail string, at time.Time) error
}

type ApprovalRepository interface {
	Create(ctx context.Context, a *Approval) error
	Get(ctx context.Context, tenant id.TenantID, approvalID id.ApprovalID) (*Approval, error)
	ListPending(ctx context.Context, tenant id.TenantID, limit int) ([]*Approval, error)
	// Decide applies the decision under optimistic locking, so two analysts
	// deciding the same approval do not both win.
	Decide(ctx context.Context, tenant id.TenantID, approvalID id.ApprovalID,
		expectedVersion int, status string, by id.UserID, note string, at time.Time) (*Approval, error)
	// Supersede marks an approval whose plan no longer matches the world.
	Supersede(ctx context.Context, tenant id.TenantID, approvalID id.ApprovalID) error
	Consume(ctx context.Context, tenant id.TenantID, approvalID id.ApprovalID) error
}

type RunRepository interface {
	Start(ctx context.Context, r *Run) error
	Finish(ctx context.Context, r *Run) error
	ByIdempotencyKey(ctx context.Context, tenant id.TenantID, key string) (*Run, error)
	ListByIncident(ctx context.Context, tenant id.TenantID, incidentID id.IncidentID, limit int) ([]*Run, error)
}

// PlanView is integration.Plan seen from the transport layer, so the HTTP
// package does not import the integration package just to name a struct.
type PlanView = struct {
	Summary    string         `json:"summary"`
	Details    []string       `json:"details"`
	Affected   *int           `json:"affected"`
	Reversible string         `json:"reversible"`
	Warnings   []string       `json:"warnings"`
	Request    map[string]any `json:"request"`
	Ready      bool           `json:"ready"`
}
