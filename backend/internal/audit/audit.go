// Package audit owns the trail and its projection, the War Room.
//
// There is exactly one writer. Every mutating use case calls Record; nothing
// else may write to audit.audit_events or audit.timeline_events. That is what
// makes the two tables consistent with each other — the objection "the same
// fact in two places will diverge" only holds when there are two writers.
package audit

import (
	"context"
	"time"

	"github.com/titas/soar/backend/internal/core/id"
)

// Classification decides which tables a fact lands in.
//
// They overlap but are not the same thing. "VirusTotal enrichment finished" is
// timeline-worthy and not audit-worthy: no decision, no state change. "Role
// analyst_l2 was granted response.create_exception" is audit-worthy and has no
// incident to appear on.
type Classification int

const (
	// TimelineOnly: contexto para o analista, sem decisão nem mudança de estado.
	TimelineOnly Classification = iota
	// AuditOnly: decisão sobre um recurso que não é um incidente.
	AuditOnly
	// Both: alguém decidiu algo sobre um incidente. O caso comum.
	Both
)

type ActorKind string

const (
	ActorUser        ActorKind = "user"
	ActorAutomation  ActorKind = "automation"
	ActorWorkflow    ActorKind = "workflow"
	ActorIntegration ActorKind = "integration"
	ActorSystem      ActorKind = "system"
)

type Actor struct {
	Kind  ActorKind
	ID    string // uuid do usuário, ou "system:automation"
	Label string // nome exibível, só para a timeline
}

type Result string

const (
	Succeeded Result = "succeeded"
	Failed    Result = "failed"
	Denied    Result = "denied"
)

// Fact is one thing that happened. It is recorded once, in the caller's
// transaction, and fans out to the right tables.
type Fact struct {
	Classification Classification

	TenantID   id.TenantID
	OccurredAt time.Time
	Actor      Actor

	// Auditoria
	Action       string // incident.close, rbac.grant, response.execute
	ResourceType string
	ResourceID   string
	Result       Result
	Reason       string
	Before       map[string]any
	After        map[string]any

	// Timeline
	IncidentID *id.IncidentID
	EventType  string // incident.closed, enrichment.completed
	Title      string // uma linha, renderizável
	Detail     string
	Payload    map[string]any

	// Correlação
	RequestID   string
	TraceID     string
	ExecutionID *string
	SourceIP    string
}

// Writer is the port. Implemented in internal/audit/postgres; the import lint
// keeps that package out of every other domain.
type Writer interface {
	Record(ctx context.Context, f Fact) error
}

// Reader serves the War Room and the auditor's view.
type Reader interface {
	Timeline(ctx context.Context, tenant id.TenantID, incidentID id.IncidentID, limit int) ([]TimelineEntry, error)
}

type TimelineEntry struct {
	ID         string
	OccurredAt time.Time
	EventType  string
	ActorKind  string
	ActorID    string
	ActorLabel string
	Title      string
	Detail     string
	Payload    map[string]any
}
