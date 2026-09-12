-- 规则版本效果统计复用 security_event_matches + security_events 原始事实表。
-- 聚合任务按 event_occurred_at 时间窗口筛选；该索引覆盖时间/规则版本维度。
CREATE INDEX IF NOT EXISTS idx_security_event_matches_effect_stats
    ON security_event_matches (event_occurred_at DESC, rule_id, rule_version, event_id);

CREATE INDEX IF NOT EXISTS idx_security_events_effect_stats_disposition
    ON security_events (occurred_at DESC, disposition_status, action, id);
