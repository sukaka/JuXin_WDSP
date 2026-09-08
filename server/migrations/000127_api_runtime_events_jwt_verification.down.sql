-- 000127 回滚：移除 api_runtime_events.jwt_verification 列。
BEGIN;

ALTER TABLE api_runtime_events
    DROP COLUMN IF EXISTS jwt_verification;

COMMIT;
