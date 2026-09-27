package incident

import (
	"context"
	"time"

	"github.com/titas/soar/backend/internal/core/id"
	"github.com/titas/soar/backend/internal/core/pagination"
)

// Filter is the server-side query. There is no free-form predicate here on
// purpose: every filter is a named field with an index behind it, and nothing
// the client sends is ever interpolated into SQL.
type Filter struct {
	Status   *Status
	OpenOnly bool
	Severity *Severity
	OwnerID  *id.UserID
	Limit    int
	After    *pagination.Key
}

type Page struct {
	Items      []*Incident
	NextCursor *pagination.Key
}

// Repository is declared here, where it is consumed, and implemented in
// internal/incident/postgres. That direction is what keeps the domain free of
// pgx — infrastructure depends on the domain, never the reverse.
type Repository interface {
	List(ctx context.Context, tenant id.TenantID, f Filter) (Page, error)
	FindByID(ctx context.Context, tenant id.TenantID, incidentID id.IncidentID) (*Incident, error)
	// FindForUpdate takes a row lock; used by every mutating use case.
	FindForUpdate(ctx context.Context, tenant id.TenantID, incidentID id.IncidentID) (*Incident, error)
	Save(ctx context.Context, inc *Incident) error

	// FindOpenByFingerprint is the deduplication lookup, run once per
	// incoming alert. The partial unique index guarantees at most one row,
	// so a broken rule firing fifty thousand times finds the same incident
	// fifty thousand times and moves a counter.
	FindOpenByFingerprint(ctx context.Context, tenant id.TenantID, fingerprint []byte) (*Incident, error)
	Create(ctx context.Context, inc *Incident) error
	NextKey(ctx context.Context, tenant id.TenantID, year int) (string, error)
}

// Outbox receives domain events inside the caller's transaction. The interface
// is here rather than in a shared package so the domain states what it needs
// instead of importing what exists.
type Outbox interface {
	Enqueue(ctx context.Context, tenant id.TenantID, events []Event) error
}

// AuditWriter is a mandatory dependency of every mutating use case. A platform
// that changes production and cannot say who asked is not auditable.
type AuditWriter interface {
	Append(ctx context.Context, entry AuditEntry) error
}

type AuditEntry struct {
	TenantID   id.TenantID
	OccurredAt time.Time
	ActorKind  string
	ActorID    string
	Action     string
	Resource   string
	IncidentID *id.IncidentID
	Result     string
	Reason     string
	Before     map[string]any
	After      map[string]any
	RequestID  string
	TraceID    string
}
