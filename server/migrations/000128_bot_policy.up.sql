-- 000128 应用级 Bot 策略（WDSP P1-02 B0/B1，服务端管理面；任务书 docs/tasks/wdsp-p1/P1-02_BOT_CHALLENGE.md）。
--   bot_policies：按应用的 Bot 策略当前草稿（每应用一行，application_id UNIQUE）；
--     mode 默认 OFF（不改变既有流量）；selectors/signal_rules/challenge/route_reservation
--     为 JSONB（字段契约由应用层 botpolicy.ValidateStructure 校验，B0 冻结口径：
--     selectors 仅 GET + path_exact/path_prefix 二选一、禁止正则与全站通配、禁止落入
--     保留命名空间 /_wdsp/bot/v1/；signal_rules 三组信号（request_behavior/access_sequence/
--     client_claim，声明组为可伪造弱信号）、提出挑战需 ≥2 个独立信号组且至少 1 个行为组、
--     同源计数派生指标（同 group+metric+params）不重复计权；challenge 仅 type=JS，
--     nonce_ttl 30~300s 默认 90、clearance_ttl 60~3600s 默认 900、difficulty 10~18bit
--     默认 14、max_attempts 1~5 默认 3；route_reservation 状态机
--     ENABLED/RESERVED_TOMBSTONE/RELEASED，namespace 恒为 /_wdsp/bot/v1/）。
--     version 乐观锁（PUT 携带 expected_version，冲突 409）。
--   bot_policy_versions：不可变策略版本记录（每次草稿保存追加一行，
--     UNIQUE(application_id, version)；reason 非空进操作审计同步留存），
--     供版本溯源与回滚对照（回退生成新版本，不改历史）；已发布/已生效版本以
--     access_control_versions 快照（GuardConfig bot_policy 段）为准。
-- 本阶段（B1）只落地策略与配置链：挑战生成/verify 端点/Eval 处置属 B2/B3，
-- 网关请求链不变。Valkey 键前缀 jiuzhang:guard:bot 冻结保留（B2 启用，本阶段不写运行时逻辑）。
BEGIN;

CREATE TABLE IF NOT EXISTS bot_policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id  UUID         NOT NULL UNIQUE REFERENCES applications(id) ON DELETE CASCADE,
    mode            VARCHAR(16)  NOT NULL DEFAULT 'OFF'
                    CHECK (mode IN ('OFF', 'OBSERVE', 'PROTECT')),
    version         INT          NOT NULL DEFAULT 1,
    selectors       JSONB        NOT NULL DEFAULT '[]'::jsonb,
    signal_rules    JSONB        NOT NULL DEFAULT
                    '{"min_independent_groups":2,"require_behavior_group":true,"rules":[]}'::jsonb,
    challenge       JSONB        NOT NULL DEFAULT
                    '{"type":"JS","nonce_ttl_seconds":90,"clearance_ttl_seconds":900,"difficulty":14,"max_attempts":3}'::jsonb,
    route_reservation JSONB      NOT NULL DEFAULT
                    '{"state":"RELEASED","namespace":"/_wdsp/bot/v1/"}'::jsonb,
    updated_by      VARCHAR(255) DEFAULT '',
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS bot_policy_versions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id  UUID         NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    version         INT          NOT NULL,
    mode            VARCHAR(16)  NOT NULL
                    CHECK (mode IN ('OFF', 'OBSERVE', 'PROTECT')),
    selectors       JSONB        NOT NULL DEFAULT '[]'::jsonb,
    signal_rules    JSONB        NOT NULL,
    challenge       JSONB        NOT NULL,
    route_reservation JSONB      NOT NULL,
    reason          TEXT         NOT NULL,
    created_by      VARCHAR(255) DEFAULT '',
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (application_id, version)
);

COMMIT;
