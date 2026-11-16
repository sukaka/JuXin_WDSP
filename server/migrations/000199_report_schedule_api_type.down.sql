BEGIN;

ALTER TABLE report_schedules
    DROP COLUMN IF EXISTS api_report_type;

COMMIT;
