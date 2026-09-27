// Package outbox turns a state change and its event into one commit.
//
// The failure it removes is specific: UPDATE succeeds, COMMIT succeeds, then
// publishing to the broker fails — and now the database says one thing while
// every consumer believes another. Writing the event as a row in the same
// transaction makes that impossible.
//
// The dispatcher then moves rows to the bus. It wakes on a short adaptive
// poll rather than LISTEN/NOTIFY, because LISTEN is *never* supported behind
// PgBouncer in transaction pooling — verified in their compatibility matrix —
// and the day a pooler appears, a NOTIFY-based dispatcher stops silently
// (docs/soar/07 §1, AD-04R.2).
package outbox

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/titas/soar/backend/internal/core/id"
	pg "github.com/titas/soar/backend/internal/platform/postgres"
)

type Event struct {
	Topic       string
	AggregateID *uuid.UUID
	ActorKind   string
	ActorID     string
	Payload     map[string]any
	TraceID     string
}

type Store struct{ tx *pg.TxManager }

func New(tx *pg.TxManager) *Store { return &Store{tx: tx} }

// Enqueue must be called inside the use case's transaction. Outside one it
// still works, and then it is just a durable queue insert — but the guarantee
// it exists for is gone.
func (s *Store) Enqueue(ctx context.Context, tenant id.TenantID, events []Event) error {
	if len(events) == 0 {
		return nil
	}
	db := s.tx.DB(ctx)
	for _, e := range events {
		payload, err := json.Marshal(e.Payload)
		if err != nil {
			return fmt.Errorf("serializar evento %s: %w", e.Topic, err)
		}
		if _, err := db.Exec(ctx, `
			INSERT INTO platform.outbox_events
			  (tenant_id, topic, aggregate_id, actor_kind, actor_id, payload, trace_id)
			VALUES ($1,$2,$3,$4,$5,$6,NULLIF($7,''))`,
			tenant.UUID, e.Topic, e.AggregateID, e.ActorKind, e.ActorID, string(payload), e.TraceID,
		); err != nil {
			return fmt.Errorf("enfileirar %s: %w", e.Topic, err)
		}
	}
	return nil
}

// Delivered is one event handed to the bus.
type Delivered struct {
	ID        int64
	EventID   uuid.UUID
	TenantID  uuid.UUID
	Topic     string
	Payload   map[string]any
	ActorKind string
	ActorID   string
	TraceID   string
	CreatedAt time.Time
}

// Claim leases pending events without holding a database transaction while a
// publisher talks to a broker or runs an in-process handler. A crashed worker's
// lease expires and another dispatcher retries it.
func (s *Store) Claim(ctx context.Context, worker string, limit int, lease time.Duration) ([]Delivered, error) {
	rows, err := s.tx.DB(ctx).Query(ctx, `
		WITH picked AS (
			SELECT id FROM platform.outbox_events
			 WHERE published_at IS NULL
			   AND next_attempt_at <= now()
			   AND (locked_at IS NULL OR locked_at < now() - $3::interval)
			 ORDER BY id
			 FOR UPDATE SKIP LOCKED
			 LIMIT $2
		)
		UPDATE platform.outbox_events o
		   SET locked_at = now(), locked_by = $1, attempts = attempts + 1
		  FROM picked
		 WHERE o.id = picked.id
		RETURNING o.id, o.event_id, o.tenant_id, o.topic, o.payload,
		          o.actor_kind, o.actor_id, COALESCE(o.trace_id,''), o.created_at`,
		worker, limit, intervalLiteral(lease))
	if err != nil {
		return nil, fmt.Errorf("reivindicar outbox: %w", err)
	}
	defer rows.Close()
	var out []Delivered
	for rows.Next() {
		var e Delivered
		var raw []byte
		if err := rows.Scan(&e.ID, &e.EventID, &e.TenantID, &e.Topic, &raw,
			&e.ActorKind, &e.ActorID, &e.TraceID, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("ler outbox: %w", err)
		}
		if err := json.Unmarshal(raw, &e.Payload); err != nil {
			return nil, fmt.Errorf("decodificar outbox %d: %w", e.ID, err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func intervalLiteral(d time.Duration) string {
	seconds := int64(d / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	return fmt.Sprintf("%d seconds", seconds)
}

func (s *Store) MarkPublished(ctx context.Context, worker string, eventID int64) error {
	tag, err := s.tx.DB(ctx).Exec(ctx, `
		UPDATE platform.outbox_events
		   SET published_at = now(), locked_at = NULL, locked_by = NULL, last_error = NULL
		 WHERE id = $1 AND locked_by = $2 AND published_at IS NULL`, eventID, worker)
	if err != nil {
		return fmt.Errorf("marcar outbox publicada: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("lease da outbox %d não pertence mais a %s", eventID, worker)
	}
	return nil
}

func (s *Store) Retry(ctx context.Context, worker string, eventID int64, cause error, delay time.Duration) error {
	_, err := s.tx.DB(ctx).Exec(ctx, `
		UPDATE platform.outbox_events
		   SET locked_at = NULL, locked_by = NULL, last_error = $3,
		       next_attempt_at = now() + $4::interval
		 WHERE id = $1 AND locked_by = $2 AND published_at IS NULL`,
		eventID, worker, cause.Error(), intervalLiteral(delay))
	if err != nil {
		return fmt.Errorf("reagendar outbox: %w", err)
	}
	return nil
}

// Handler consumes an event. It must be idempotent: delivery is at-least-once
// everywhere in this product, and chasing exactly-once through six different
// vendors is chasing something that does not exist.
type Handler func(context.Context, Delivered) error

type Publisher interface {
	Publish(context.Context, Delivered) error
}

// TopicPublisher is the in-process edge bus. Every event still crosses the
// default publisher (normally structured logging), and selected topics are
// then delivered to their domain consumer. A handler error is returned to the
// dispatcher, which keeps the event pending and retries it.
type TopicPublisher struct {
	Default  Publisher
	Handlers map[string]Handler
}

func (p TopicPublisher) Publish(ctx context.Context, e Delivered) error {
	if p.Default != nil {
		if err := p.Default.Publish(ctx, e); err != nil {
			return err
		}
	}
	if handler := p.Handlers[e.Topic]; handler != nil {
		return handler(ctx, e)
	}
	return nil
}

// LoggingPublisher is the edge-profile event bus. It provides a real delivery
// boundary and structured observability without requiring a broker. Standard
// and scale profiles replace it with NATS/Kafka adapters.
type LoggingPublisher struct{ Log *slog.Logger }

func (p LoggingPublisher) Publish(_ context.Context, e Delivered) error {
	p.Log.Info("domain event", "event_id", e.EventID, "topic", e.Topic,
		"tenant_id", e.TenantID, "actor_kind", e.ActorKind, "actor_id", e.ActorID,
		"trace_id", e.TraceID)
	return nil
}
