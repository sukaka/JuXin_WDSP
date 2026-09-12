-- 000142 告警维护窗口（阶段6 §11.5）：计划性维护期间抑制告警评估。
--
-- 语义：
--   1. 窗口命中（enabled 且当前时刻落在窗口内、scope 匹配告警类型/组件）时，
--      评估引擎跳过告警新建与合并（不产生/不更新 system_alerts 行）；
--   2. 抑制事实可观测：每次被抑制 suppressed_count+1 并刷新 last_suppressed_at，
--      同时写 slog 日志，不静默吞掉；
--   3. recurrence=ONCE 为一次性窗口 [starts_at, ends_at]；DAILY 在
--      [starts_at, ends_at] 日期跨度内每日按 UTC 日内时段
--      [daily_start_minute, daily_end_minute) 生效（end<=start 表示跨零点）；
--   4. scope=ALL 抑制全部告警；CUSTOM 时 alert_types/components 非空维度按
--      命中过滤（空数组维度视为通配）。

BEGIN;

CREATE TABLE IF NOT EXISTS system_alert_maintenance_windows (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                VARCHAR(100) NOT NULL,
    description         VARCHAR(500) NOT NULL DEFAULT '',
    scope               VARCHAR(10)  NOT NULL DEFAULT 'ALL',   -- ALL / CUSTOM
    alert_types         TEXT[]       NOT NULL DEFAULT '{}',    -- scope=CUSTOM 时按告警类型过滤
    components          TEXT[]       NOT NULL DEFAULT '{}',    -- scope=CUSTOM 时按组件过滤
    recurrence          VARCHAR(10)  NOT NULL DEFAULT 'ONCE',  -- ONCE / DAILY
    starts_at           TIMESTAMPTZ  NOT NULL,                 -- 窗口生效起点（含）
    ends_at             TIMESTAMPTZ  NOT NULL,                 -- 窗口生效终点（含）
    daily_start_minute  INTEGER,                               -- DAILY：UTC 日内开始分钟 [0,1439]
    daily_end_minute    INTEGER,                               -- DAILY：UTC 日内结束分钟 [0,1439]，<= start 表示跨零点
    enabled             BOOLEAN      NOT NULL DEFAULT TRUE,
    suppressed_count    BIGINT       NOT NULL DEFAULT 0,       -- 窗口内被抑制的告警评估次数
    last_suppressed_at  TIMESTAMPTZ,                           -- 最近一次抑制时刻
    created_by          UUID,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CHECK (ends_at > starts_at),
    CHECK (scope IN ('ALL','CUSTOM')),
    CHECK (recurrence IN ('ONCE','DAILY')),
    CHECK (daily_start_minute IS NULL OR daily_start_minute BETWEEN 0 AND 1439),
    CHECK (daily_end_minute IS NULL OR daily_end_minute BETWEEN 0 AND 1439)
);
CREATE INDEX IF NOT EXISTS idx_alert_maint_windows_enabled ON system_alert_maintenance_windows (enabled, starts_at);

COMMENT ON TABLE system_alert_maintenance_windows IS
    '告警维护窗口（阶段6 §11.5）：窗口内匹配的告警评估被抑制，抑制计入 suppressed_count 可观测';

COMMIT;
