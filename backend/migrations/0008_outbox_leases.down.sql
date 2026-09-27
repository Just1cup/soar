DROP INDEX IF EXISTS platform.outbox_pending;
ALTER TABLE platform.outbox_events
    DROP COLUMN IF EXISTS next_attempt_at,
    DROP COLUMN IF EXISTS locked_by,
    DROP COLUMN IF EXISTS locked_at;
CREATE INDEX outbox_pending ON platform.outbox_events (id) WHERE published_at IS NULL;
