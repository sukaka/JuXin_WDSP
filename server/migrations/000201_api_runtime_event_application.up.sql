-- 000201 API 运行时事件应用归属（共享设备群控观察只读聚合）。
-- application_id 可空：旧版事件及未识别应用的请求保持 NULL，不从同名端点猜测回填。
BEGIN;

ALTER TABLE api_runtime_events
    ADD COLUMN IF NOT EXISTS application_id UUID;

CREATE INDEX IF NOT EXISTS idx_api_runtime_events_app_device_time
    ON api_runtime_events (application_id, device_fingerprint, occurred_at DESC)
    WHERE application_id IS NOT NULL AND device_fingerprint IS NOT NULL;

COMMENT ON COLUMN api_runtime_events.application_id IS
    '网关已识别的应用 UUID；可空，历史事件不回填。用于按应用隔离共享设备观察聚合。';

COMMIT;
