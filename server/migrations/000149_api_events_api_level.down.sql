-- 000149 回滚：移除 api_runtime_events.api_level（含词表 CHECK 约束）与
-- api_runtime_findings 的 device_fingerprint/object_identifiers 冗余列。
BEGIN;

ALTER TABLE api_runtime_events
    DROP CONSTRAINT IF EXISTS chk_api_runtime_events_api_level,
    DROP COLUMN IF EXISTS api_level;

ALTER TABLE api_runtime_findings
    DROP COLUMN IF EXISTS device_fingerprint,
    DROP COLUMN IF EXISTS object_identifiers;

COMMIT;
