-- 000029 回滚：移除 api_runtime_events 身份列与部分索引。
BEGIN;

DROP INDEX IF EXISTS idx_api_runtime_events_identity;
ALTER TABLE api_runtime_events
    DROP COLUMN IF EXISTS identity_fingerprint,
    DROP COLUMN IF EXISTS auth_type;

COMMIT;
