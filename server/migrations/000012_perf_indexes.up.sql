-- 阶段6 性能索引：千万级事件下态势页关键查询
-- （disposition_status, severity）复合索引覆盖「未处置高危事件」计数与最近列表

BEGIN;

CREATE INDEX IF NOT EXISTS idx_security_events_disposition_severity
    ON security_events (disposition_status, severity, occurred_at DESC);

CREATE INDEX IF NOT EXISTS idx_ac_events_disposition_time
    ON access_control_events (event_type, occurred_at DESC);

-- uri_security_summaries 增加 WAF 阻断计数（TOP URI 排行用）
ALTER TABLE uri_security_summaries ADD COLUMN IF NOT EXISTS waf_blocks BIGINT NOT NULL DEFAULT 0;

COMMIT;
