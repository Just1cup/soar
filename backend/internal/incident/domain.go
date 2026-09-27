// Package incident owns the lifecycle of an incident: what it is, which
// transitions are legal, and what must be true before it can be closed.
//
// Nothing in this file knows about HTTP, SQL or Elasticsearch. That is not
// ceremony — it is what lets the rules below be tested without a database, and
// it is verified in CI by an import lint, not by good intentions.
package incident

import (
	"fmt"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/titas/soar/backend/internal/core/errs"
	"github.com/titas/soar/backend/internal/core/id"
)

// MaxReasonLength bounds free text that ends up in the audit trail and in the
// timeline. O limite existe no domínio, e não só no schema da API, porque a
// trilha é append-only: um motivo de 10 MB gravado por engano não pode ser
// apagado depois.
const MaxReasonLength = 4000

type Status string

const (
	StatusNew           Status = "new"
	StatusTriage        Status = "triage"
	StatusInvestigating Status = "investigating"
	StatusPendingAction Status = "pending_action"
	StatusResolved      Status = "resolved"
	StatusClosed        Status = "closed"
)

// transitions is the whole state machine. Anything not listed is illegal,
// which is the point: a status field with no transition table is a text field.
//
// closed is terminal. Reopening is a separate, permissioned operation that
// creates a new audit entry rather than erasing the close — see Reopen.
var transitions = map[Status][]Status{
	StatusNew:           {StatusTriage, StatusInvestigating, StatusClosed},
	StatusTriage:        {StatusInvestigating, StatusResolved, StatusClosed},
	StatusInvestigating: {StatusPendingAction, StatusResolved, StatusClosed},
	StatusPendingAction: {StatusInvestigating, StatusResolved},
	StatusResolved:      {StatusClosed, StatusInvestigating},
	StatusClosed:        {},
}

func (s Status) Valid() bool { _, ok := transitions[s]; return ok }

// Open reports whether the incident still demands attention. The queue, the
// dedupe index and the SLA clock all depend on this single definition.
func (s Status) Open() bool { return s != StatusClosed }

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

func (s Severity) Valid() bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
		return true
	}
	return false
}

// Resolution is the vocabulary carried over from the Python assessment schema,
// and benign_true_positive is the one that matters. The detection fired
// correctly and the behaviour was authorised: calling that a false positive
// teaches people to distrust the rule instead of tuning it.
type Resolution string

const (
	ResolutionTruePositive       Resolution = "true_positive"
	ResolutionBenignTruePositive Resolution = "benign_true_positive"
	ResolutionFalsePositive      Resolution = "false_positive"
	ResolutionInconclusive       Resolution = "inconclusive"
)

func (r Resolution) Valid() bool {
	switch r {
	case ResolutionTruePositive, ResolutionBenignTruePositive,
		ResolutionFalsePositive, ResolutionInconclusive:
		return true
	}
	return false
}

// Incident is the aggregate root. OpenMandatoryTasks is carried on the
// aggregate rather than fetched inside Close, so the invariant stays testable
// without a repository.
type Incident struct {
	ID       id.IncidentID
	TenantID id.TenantID
	Key      string
	TypeSlug string

	Title       string
	Description string
	Status      Status
	Severity    Severity
	Priority    int

	OwnerID    *id.UserID
	OwnerName  string
	AssignedAt *time.Time

	SourceID    *id.SourceID
	SourceRule  string
	Fingerprint []byte
	DedupeUntil *time.Time

	AlertCount int
	FirstSeen  time.Time
	LastSeen   time.Time

	Resolution   Resolution
	ClosedReason string
	ClosedAt     *time.Time
	ClosedBy     *id.UserID
	FirstAckAt   *time.Time

	AttackTactics    []string
	AttackTechniques []string
	Tags             []string

	OpenMandatoryTasks int

	Version   int
	CreatedAt time.Time
	UpdatedAt time.Time

	events []Event
}

// Event is a domain event, collected on the aggregate and drained by the use
// case into the same transaction as the state change (the outbox pattern).
type Event struct {
	Topic       string
	AggregateID id.IncidentID
	OccurredAt  time.Time
	Payload     map[string]any
}

func (i *Incident) record(topic string, at time.Time, payload map[string]any) {
	i.events = append(i.events, Event{
		Topic: topic, AggregateID: i.ID, OccurredAt: at, Payload: payload,
	})
}

// PendingEvents drains the events. Draining rather than reading stops the same
// event being enqueued twice if a use case is retried.
func (i *Incident) PendingEvents() []Event {
	out := i.events
	i.events = nil
	return out
}

func (i *Incident) CanTransitionTo(next Status) bool {
	return slices.Contains(transitions[i.Status], next)
}

// Acknowledge stamps the first human attention, which is the numerator of MTTA.
// It is idempotent: the first ack is the one that counts.
func (i *Incident) Acknowledge(by id.UserID, now time.Time) {
	if i.FirstAckAt == nil {
		t := now
		i.FirstAckAt = &t
		i.record("incident.acknowledged", now, map[string]any{"by": by.String()})
	}
}

func (i *Incident) Assign(to id.UserID, now time.Time) error {
	if !i.Status.Open() {
		return errs.Coded(errs.ErrInvalidStateTransition, "INCIDENT_CLOSED",
			"não é possível atribuir um incidente fechado")
	}
	i.OwnerID = &to
	t := now
	i.AssignedAt = &t
	i.UpdatedAt = now
	i.record("incident.assigned", now, map[string]any{"owner_id": to.String()})
	return nil
}

// Close is the invariant that matters most, and the reason the aggregate
// carries OpenMandatoryTasks: an incident cannot be closed while a step someone
// marked as required is still undone.
func (i *Incident) Close(res Resolution, reason string, by *id.UserID, now time.Time) error {
	if !i.CanTransitionTo(StatusClosed) {
		return errs.Coded(errs.ErrInvalidStateTransition, "INVALID_TRANSITION",
			"transição ilegal: %s -> closed", i.Status)
	}
	if !res.Valid() {
		return errs.Coded(errs.ErrValidation, "INVALID_RESOLUTION",
			"resolução inválida: %q", res)
	}
	if err := validateReason(reason, "fechamento"); err != nil {
		return err
	}
	if i.OpenMandatoryTasks > 0 {
		return errs.Coded(errs.ErrPreconditionFailed, "MANDATORY_TASKS_OPEN",
			"%d tarefa(s) obrigatória(s) em aberto", i.OpenMandatoryTasks)
	}
	prev := i.Status
	t := now
	i.Status, i.Resolution, i.ClosedReason, i.ClosedAt, i.ClosedBy = StatusClosed, res, reason, &t, by
	i.UpdatedAt = now
	payload := map[string]any{"from": string(prev), "resolution": string(res), "reason": reason}
	if by != nil {
		payload["by"] = by.String()
	}
	i.record("incident.closed", now, payload)
	return nil
}

// Reopen is deliberately not a transition out of closed in the table above.
// It is a distinct, separately permissioned operation, and it leaves the
// previous close in the audit trail rather than overwriting it.
func (i *Incident) Reopen(reason string, by *id.UserID, now time.Time) error {
	if i.Status != StatusClosed {
		return errs.Coded(errs.ErrInvalidStateTransition, "NOT_CLOSED",
			"apenas um incidente fechado pode ser reaberto (está em %s)", i.Status)
	}
	if err := validateReason(reason, "reabertura"); err != nil {
		return err
	}
	i.Status = StatusInvestigating
	i.Resolution, i.ClosedReason, i.ClosedAt, i.ClosedBy = "", "", nil, nil
	i.UpdatedAt = now
	payload := map[string]any{"reason": reason}
	if by != nil {
		payload["by"] = by.String()
	}
	i.record("incident.reopened", now, payload)
	return nil
}

// AbsorbAlert folds another alert of the same fingerprint into this incident.
// This is the whole point of deduplication: a broken rule that fires 50 000
// times produces one incident whose alert_count is 50 000, not 50 000
// incidents. The counter moves; the identity does not.
func (i *Incident) AbsorbAlert(eventTime time.Time, now time.Time) {
	i.AlertCount++
	if eventTime.After(i.LastSeen) {
		i.LastSeen = eventTime
	}
	if eventTime.Before(i.FirstSeen) {
		i.FirstSeen = eventTime
	}
	i.UpdatedAt = now
}

func (i *Incident) Validate() error {
	switch {
	case !i.Status.Valid():
		return fmt.Errorf("%w: status desconhecido %q", errs.ErrValidation, i.Status)
	case !i.Severity.Valid():
		return fmt.Errorf("%w: severidade desconhecida %q", errs.ErrValidation, i.Severity)
	case i.Priority < 1 || i.Priority > 5:
		return fmt.Errorf("%w: prioridade fora de 1..5: %d", errs.ErrValidation, i.Priority)
	case i.Title == "":
		return fmt.Errorf("%w: título obrigatório", errs.ErrValidation)
	case len(i.Fingerprint) == 0:
		return fmt.Errorf("%w: fingerprint obrigatório", errs.ErrValidation)
	}
	return nil
}

func validateReason(reason, kind string) error {
	if reason == "" {
		return errs.Coded(errs.ErrValidation, "REASON_REQUIRED",
			"motivo de %s é obrigatório", kind)
	}
	// Conta runes, não bytes: cortar em 4000 bytes partiria um caractere
	// multibyte ao meio e gravaria lixo na trilha.
	if n := utf8.RuneCountInString(reason); n > MaxReasonLength {
		return errs.Coded(errs.ErrValidation, "REASON_TOO_LONG",
			"motivo tem %d caracteres; o máximo é %d", n, MaxReasonLength)
	}
	return nil
}
