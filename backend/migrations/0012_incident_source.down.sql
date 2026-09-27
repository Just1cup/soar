DROP INDEX IF EXISTS incident.incidents_by_source;
ALTER TABLE incident.incidents DROP COLUMN IF EXISTS source_id;
