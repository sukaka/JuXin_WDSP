-- 规则版本按日效果统计：由现有 aggregations 小时任务重算写入。
-- 该表是派生数据，不进入网关实时请求路径，可按日期窗口安全重算。
CREATE TABLE IF NOT EXISTS rule_statistics_daily (
    id                         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_key                   VARCHAR(255) NOT NULL,
    rule_id                    INTEGER NOT NULL,
    rule_name                  VARCHAR(512) NOT NULL DEFAULT '',
    rule_source                VARCHAR(32) NOT NULL DEFAULT '',
    rule_version               VARCHAR(32) NOT NULL DEFAULT '',
    stat_date                  DATE NOT NULL,
    observed_count             BIGINT NOT NULL DEFAULT 0,
    blocked_count              BIGINT NOT NULL DEFAULT 0,
    confirmed_attack_count     BIGINT NOT NULL DEFAULT 0,
    confirmed_false_positive_count BIGINT NOT NULL DEFAULT 0,
    unresolved_count           BIGINT NOT NULL DEFAULT 0,
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT rule_statistics_daily_unique UNIQUE (rule_key, rule_version, stat_date)
);

CREATE INDEX IF NOT EXISTS idx_rule_statistics_daily_date
    ON rule_statistics_daily (stat_date DESC, rule_id, rule_version);
