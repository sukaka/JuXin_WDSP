-- 000035 回滚：移除 api_runtime_events 六个审计列。
BEGIN;

ALTER TABLE api_runtime_events
    DROP COLUMN IF EXISTS client_ip,
    DROP COLUMN IF EXISTS method,
    DROP COLUMN IF EXISTS raw_path,
    DROP COLUMN IF EXISTS latency_ms,
    DROP COLUMN IF EXISTS model_version,
    DROP COLUMN IF EXISTS policy_version;

COMMIT;
