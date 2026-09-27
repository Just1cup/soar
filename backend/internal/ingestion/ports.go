// Package ingestion turns what a SIEM saw into incidents this platform can
// work on.
//
// The design rule is docs/soar/08 §2: durability is a property of the
// INGESTION MODE, not of the platform. A pull connector owns a durable cursor
// and the source keeps the data; a push sender often keeps nothing and does
// not retry. Both go through one pipeline, because two ingestion paths is the
// same mistake as two sources of truth.
package ingestion

import (
	"context"
	"time"

	"github.com/titas/soar/backend/internal/core/id"
)

// RawEvent is one event exactly as the source produced it. The raw payload is
// ALWAYS kept: every mapper is wrong about some field, and without the raw
// event the fix is retroactive only on paper.
type RawEvent struct {
	ExternalID string
	Payload    map[string]any
	EventTime  time.Time
	Mode       string
}

type Receipt struct {
	ID         string
	Received   int
	Accepted   int
	Duplicates int
}

type Backlog struct {
	Pending   int64
	OldestAge time.Duration
}

// IntakeSink is the port that decides where a batch lands durably.
//
// Accept MUST NOT return nil before the batch survives this process dying.
// Three implementations exist behind it, chosen by deployment profile:
// PostgreSQL (edge), NATS JetStream (standard), Kafka (scale). Nothing above
// this line knows which is in use.
type IntakeSink interface {
	Accept(ctx context.Context, tenant id.TenantID, source id.SourceID, batch []RawEvent) (Receipt, error)
	Watermark(ctx context.Context, tenant id.TenantID) (Backlog, error)
}

// Cursor is the XSOAR lastRun model, adopted literally because it solves a
// failure they documented: items sharing a timestamp across fetch cycles are
// lost with `>` and duplicated with `>=`.
//
// The query is inclusive on LastFetchTime and SeenIDs filters what already
// arrived; the timestamp only advances when pagination ends.
type Cursor struct {
	LastFetchTime time.Time `json:"last_fetch_time"`
	SeenIDs       []string  `json:"seen_ids"`
	NextToken     string    `json:"next_token"`
}

type FetchResult struct {
	Events  []RawEvent
	Next    Cursor
	HasMore bool
}

// Source is a pull connector.
type Source interface {
	Kind() string
	Fetch(ctx context.Context, cfg map[string]any, cursor Cursor, maxFetch int) (FetchResult, error)
	// Map turns one raw event into the canonical alert. Declarative mappers
	// come later (F-23); a compiled source maps what it knows.
	Map(raw RawEvent) (*Alert, error)
}

// Alert is the canonical model, deliberately small. Everything vendor
// specific stays in the raw payload: a canonical model that tries to cover
// every field of every SIEM is one that describes none of them.
type Alert struct {
	ExternalID  string
	Title       string
	RuleID      string
	RuleName    string
	Severity    string
	Host        string
	Entity      string
	EntityKind  string
	EventTime   time.Time
	Normalized  map[string]any
	SourceRef   map[string]any
	Fingerprint []byte
}

type SourceConfig struct {
	ID                  id.SourceID
	TenantID            id.TenantID
	Slug                string
	Name                string
	Kind                string
	Mode                string
	Config              map[string]any
	DefaultIncidentType string
	Enabled             bool
}

type SourceRepository interface {
	ListEnabled(ctx context.Context, tenant id.TenantID) ([]SourceConfig, error)
	BySlug(ctx context.Context, tenant id.TenantID, slug string) (*SourceConfig, error)
	Cursor(ctx context.Context, sourceID id.SourceID) (Cursor, error)
	// AdvanceCursor is only called AFTER a durable accept. That is what makes
	// pull at-least-once instead of best effort: if the sink fails the cursor
	// does not move, the next cycle repeats, and the duplicate dies in the
	// dedupe.
	AdvanceCursor(ctx context.Context, sourceID id.SourceID, cursor Cursor, at time.Time) error
	Upsert(ctx context.Context, s *SourceConfig) error
}

// PendingRaw is an accepted event waiting to become an alert.
type PendingRaw struct {
	ID       string
	SourceID id.SourceID
	TenantID id.TenantID
	Payload  map[string]any
	Mode     string
	Ingested time.Time
}

type RawRepository interface {
	Pending(ctx context.Context, tenant id.TenantID, limit int) ([]PendingRaw, error)
	MarkMapped(ctx context.Context, rawID string) error
	Quarantine(ctx context.Context, rawID, reason string) error
	MarkDuplicate(ctx context.Context, rawID string) error
}

// RunRecorder makes "the connector stopped bringing alerts at 03:12" a query
// instead of a suspicion. It is the most common and most silent failure of
// any SOAR in production.
type RunRecorder interface {
	Begin(ctx context.Context, tenant id.TenantID, source id.SourceID, before Cursor) (string, error)
	End(ctx context.Context, runID string, stats RunStats) error
}

type RunStats struct {
	Fetched, Accepted, Duplicates, Quarantined int
	IncidentsCreated, IncidentsUpdated         int
	After                                      Cursor
	Status                                     string
	Err                                        string
	Duration                                   time.Duration
}
