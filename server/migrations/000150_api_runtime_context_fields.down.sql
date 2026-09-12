-- 000150 回滚：移除 api_runtime_events.device_fingerprint 与 object_identifiers 列。
BEGIN;

ALTER TABLE api_runtime_events
    DROP COLUMN IF EXISTS device_fingerprint,
    DROP COLUMN IF EXISTS object_identifiers;

COMMIT;
