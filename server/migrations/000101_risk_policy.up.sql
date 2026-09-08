-- 000101 风险策略（WDSP AI 自动化渗透防护增强 阶段3，服务端）。
--   security_risk_policy：身份风险处置全局策略，单行（scope='GLOBAL' UNIQUE）；
--   经发布通道下发网关 jiuzhang_guard risk_policy 段（跨分片契约已冻结，
--   见 server/internal/gatewayconfig/guard.go GuardRiskPolicy）：
--   信号窗口内身份风险分达 rate_limit_threshold 限速（rate_limit_rps）、
--   达 block_threshold 阻断；mode=OBSERVE 仅观测（事件 action_taken=would_block/
--   would_rate_limit），PROTECT 实际处置（blocked/rate_limited）；
--   enabled=false 时网关风险处置零行为；scores 为信号类型→分值覆盖（键格式
--   应用层校验兜底），risk_levels 为风险等级阈值（medium/high/critical）。
--   version 乐观锁（管理面全量更新，随发布下发，事件回报 policy_version 溯源）。
-- 同时扩展 access_control_events.details（JSONB）：风险处置事件（RISK_POLICY_BLOCK /
--   RISK_POLICY_RATE_LIMIT）的 identity_key/score/risk_level/threshold/signals/mode/
--   policy_version/action_taken/reason 证据载荷落点——表无专用列，经 details 落库；
--   分区表 ALTER 由 PG 自动传播各分区（常量默认值，元数据级变更）。
BEGIN;

CREATE TABLE IF NOT EXISTS security_risk_policy (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scope                  VARCHAR(32)  NOT NULL DEFAULT 'GLOBAL' UNIQUE,
    enabled                BOOLEAN      NOT NULL DEFAULT true,
    mode                   VARCHAR(16)  NOT NULL DEFAULT 'OBSERVE'
                           CHECK (mode IN ('OBSERVE', 'PROTECT')),
    version                INT          NOT NULL DEFAULT 1,
    block_threshold        INT          NOT NULL DEFAULT 80
                           CHECK (block_threshold BETWEEN 1 AND 100),
    rate_limit_threshold   INT          NOT NULL DEFAULT 40
                           CHECK (rate_limit_threshold BETWEEN 1 AND 100),
    rate_limit_rps         INT          NOT NULL DEFAULT 10
                           CHECK (rate_limit_rps > 0),
    signal_window_seconds  INT          NOT NULL DEFAULT 86400
                           CHECK (signal_window_seconds > 0),
    scores                 JSONB        NOT NULL DEFAULT '{}'::jsonb,
    risk_levels            JSONB        NOT NULL DEFAULT '{"medium":20,"high":40,"critical":70}'::jsonb,
    updated_by             VARCHAR(255) DEFAULT '',
    created_at             TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- 单行种子（GLOBAL 全局策略，默认值即网关内置基线）
INSERT INTO security_risk_policy (scope) VALUES ('GLOBAL')
ON CONFLICT (scope) DO NOTHING;

-- 风险处置事件证据载荷列（非风险事件恒为 '{}'）
ALTER TABLE access_control_events ADD COLUMN IF NOT EXISTS details JSONB NOT NULL DEFAULT '{}'::jsonb;

COMMIT;
