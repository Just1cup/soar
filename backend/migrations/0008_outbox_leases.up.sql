ALTER TABLE platform.outbox_events
    ADD COLUMN locked_at TIMESTAMPTZ,
    ADD COLUMN locked_by TEXT,
    ADD COLUMN next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now();

DROP INDEX platform.outbox_pending;
CREATE INDEX outbox_pending ON platform.outbox_events (next_attempt_at, id)
    WHERE published_at IS NULL;
