package outbox

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

type fakeQueue struct {
	mu      sync.Mutex
	events  []Delivered
	acked   []int64
	retried []int64
}

func (q *fakeQueue) Claim(context.Context, string, int, time.Duration) ([]Delivered, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := q.events
	q.events = nil
	return out, nil
}
func (q *fakeQueue) MarkPublished(_ context.Context, _ string, id int64) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.acked = append(q.acked, id)
	return nil
}
func (q *fakeQueue) Retry(_ context.Context, _ string, id int64, _ error, _ time.Duration) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.retried = append(q.retried, id)
	return nil
}

type fakePublisher struct{ failID int64 }

func (p fakePublisher) Publish(_ context.Context, e Delivered) error {
	if e.ID == p.failID {
		return errors.New("broker indisponível")
	}
	return nil
}

func TestTopicPublisherRoutesOnlyMatchingEvent(t *testing.T) {
	var handled []string
	p := TopicPublisher{
		Default: fakePublisher{},
		Handlers: map[string]Handler{
			"incident.created": func(_ context.Context, e Delivered) error {
				handled = append(handled, e.Topic)
				return nil
			},
		},
	}
	if err := p.Publish(context.Background(), Delivered{ID: 1, Topic: "incident.updated"}); err != nil {
		t.Fatal(err)
	}
	if err := p.Publish(context.Background(), Delivered{ID: 1, Topic: "incident.created"}); err != nil {
		t.Fatal(err)
	}
	if len(handled) != 1 || handled[0] != "incident.created" {
		t.Fatalf("handled=%v", handled)
	}
}

func TestDispatcherAcknowledgesSuccessAndRetriesFailure(t *testing.T) {
	q := &fakeQueue{events: []Delivered{{ID: 1, EventID: uuid.New()}, {ID: 2, EventID: uuid.New()}}}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	d := Dispatcher{
		Queue: q, Publisher: fakePublisher{failID: 2}, WorkerID: "test",
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		MinPoll: time.Millisecond, MaxPoll: 5 * time.Millisecond,
	}
	if err := d.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if len(q.acked) != 1 || q.acked[0] != 1 {
		t.Fatalf("acks=%v", q.acked)
	}
	if len(q.retried) != 1 || q.retried[0] != 2 {
		t.Fatalf("retries=%v", q.retried)
	}
}
