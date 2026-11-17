BEGIN;

DROP INDEX IF EXISTS idx_api_runtime_events_trace_id;
ALTER TABLE api_runtime_events DROP COLUMN IF EXISTS trace_id;

COMMIT;
