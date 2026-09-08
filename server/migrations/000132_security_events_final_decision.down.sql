-- 000132 down：移除 security_events.final_decision 列。
BEGIN;

ALTER TABLE security_events
    DROP COLUMN IF EXISTS final_decision;

COMMIT;
