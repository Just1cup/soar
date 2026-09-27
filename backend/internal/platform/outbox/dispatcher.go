package outbox

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

type Queue interface {
	Claim(context.Context, string, int, time.Duration) ([]Delivered, error)
	MarkPublished(context.Context, string, int64) error
	Retry(context.Context, string, int64, error, time.Duration) error
}

type Dispatcher struct {
	Queue     Queue
	Publisher Publisher
	WorkerID  string
	Log       *slog.Logger
	BatchSize int
	Lease     time.Duration
	MinPoll   time.Duration
	MaxPoll   time.Duration
}

func (d Dispatcher) Run(ctx context.Context) error {
	if d.Queue == nil || d.Publisher == nil || d.WorkerID == "" {
		return fmt.Errorf("dispatcher incompleto")
	}
	if d.BatchSize == 0 {
		d.BatchSize = 50
	}
	if d.Lease == 0 {
		d.Lease = 2 * time.Minute
	}
	if d.MinPoll == 0 {
		d.MinPoll = 250 * time.Millisecond
	}
	if d.MaxPoll == 0 {
		d.MaxPoll = 5 * time.Second
	}
	delay := d.MinPoll
	for {
		events, err := d.Queue.Claim(ctx, d.WorkerID, d.BatchSize, d.Lease)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			d.Log.Error("outbox claim falhou", "error", err)
			delay = minDuration(delay*2, d.MaxPoll)
		} else if len(events) == 0 {
			delay = minDuration(delay*2, d.MaxPoll)
		} else {
			delay = d.MinPoll
			for _, event := range events {
				if err := d.Publisher.Publish(ctx, event); err != nil {
					retryDelay := retryBackoff(event.ID)
					d.Log.Error("outbox publish falhou", "event_id", event.EventID,
						"topic", event.Topic, "retry_in", retryDelay, "error", err)
					if retryErr := d.Queue.Retry(ctx, d.WorkerID, event.ID, err, retryDelay); retryErr != nil {
						d.Log.Error("outbox retry falhou", "event_id", event.EventID, "error", retryErr)
					}
					continue
				}
				if err := d.Queue.MarkPublished(ctx, d.WorkerID, event.ID); err != nil {
					d.Log.Error("outbox ack falhou", "event_id", event.EventID, "error", err)
				}
			}
		}

		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func retryBackoff(id int64) time.Duration {
	// Deterministic bounded jitter avoids a synchronized retry wave without a
	// process-global random source in the hot path.
	return 5*time.Second + time.Duration(id%7)*time.Second
}
