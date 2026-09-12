-- 000131 down：移除 api_runtime_events.final_decision 列。
BEGIN;

ALTER TABLE api_runtime_events
    DROP COLUMN IF EXISTS final_decision;

COMMIT;
