BEGIN;

DROP INDEX IF EXISTS idx_api_runtime_events_app_device_time;
ALTER TABLE api_runtime_events DROP COLUMN IF EXISTS application_id;

COMMIT;
