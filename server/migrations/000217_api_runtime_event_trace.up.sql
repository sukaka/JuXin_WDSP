-- 000217 API 运行时事件 W3C Trace 关联键。
-- 历史事件与缺失/非法 trace_id 保持 NULL，不回填、不生成替代关联键。
BEGIN;

ALTER TABLE api_runtime_events
    ADD COLUMN IF NOT EXISTS trace_id VARCHAR(32)
    CONSTRAINT chk_api_runtime_events_trace_id
    CHECK (trace_id IS NULL OR (trace_id ~ '^[0-9a-f]{32}$' AND trace_id <> '00000000000000000000000000000000'));

CREATE INDEX IF NOT EXISTS idx_api_runtime_events_trace_id
    ON api_runtime_events (trace_id)
    WHERE trace_id IS NOT NULL;

COMMENT ON COLUMN api_runtime_events.trace_id IS
    'W3C trace_id：32 位小写 hex 且非全零；可空，历史事件不回填。仅用于同链路事件关联。';

COMMIT;
