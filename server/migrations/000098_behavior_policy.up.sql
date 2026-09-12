-- 000098 行为策略（WDSP AI 自动化渗透防护增强 阶段1，服务端）。
--   security_behavior_policy：侦察/枚举行为检测全局策略，单行（scope='GLOBAL' UNIQUE）；
--   经发布通道下发网关 jiuzhang_guard identity_behavior 段（跨分片契约已冻结，
--   见 server/internal/gatewayconfig/guard.go GuardIdentityBehavior）：
--   阈值/比率/敏感路径/各信号分值/白名单，enabled=false 时网关行为检测零行为；
--   version 乐观锁（管理面全量更新，随发布作为 policy_version 字符串下发）。
--   scores 键限定 7 种信号：URI_ENUMERATION/NOT_FOUND_ENUMERATION/SENSITIVE_PATH_PROBE/
--   METHOD_ENUMERATION/PARAMETER_MUTATION/AUTH_FAIL_PROBE/LOW_SLOW_RECON（应用层校验兜底）。
BEGIN;

CREATE TABLE IF NOT EXISTS security_behavior_policy (
    id                           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scope                        VARCHAR(32)   NOT NULL DEFAULT 'GLOBAL' UNIQUE,
    enabled                      BOOLEAN       NOT NULL DEFAULT true,
    mode                         VARCHAR(16)   NOT NULL DEFAULT 'OBSERVE',
    version                      INT           NOT NULL DEFAULT 1,
    uri_enum_unique_threshold    INT           NOT NULL DEFAULT 50,
    uri_enum_new_ratio_threshold NUMERIC(4,3)  NOT NULL DEFAULT 0.8,
    not_found_ratio_threshold    NUMERIC(4,3)  NOT NULL DEFAULT 0.7,
    not_found_min_requests       INT           NOT NULL DEFAULT 30,
    method_enum_threshold        INT           NOT NULL DEFAULT 4,
    param_mutation_threshold     INT           NOT NULL DEFAULT 30,
    auth_fail_threshold          INT           NOT NULL DEFAULT 10,
    low_slow_sensitive_min_hits  INT           NOT NULL DEFAULT 10,
    sensitive_paths              JSONB         NOT NULL DEFAULT '["/.git","/.env","/swagger","/openapi.json","/v3/api-docs","/actuator","/metrics","/debug","/admin","/graphql","/server-status","/config"]'::jsonb,
    scores                       JSONB         NOT NULL DEFAULT '{"URI_ENUMERATION":15,"NOT_FOUND_ENUMERATION":10,"SENSITIVE_PATH_PROBE":15,"METHOD_ENUMERATION":10,"PARAMETER_MUTATION":20,"AUTH_FAIL_PROBE":15,"LOW_SLOW_RECON":15}'::jsonb,
    whitelist_ips                JSONB         NOT NULL DEFAULT '[]'::jsonb,
    whitelist_uas                JSONB         NOT NULL DEFAULT '[]'::jsonb,
    updated_by                   VARCHAR(255)  DEFAULT '',
    created_at                   TIMESTAMPTZ   NOT NULL DEFAULT now(),
    updated_at                   TIMESTAMPTZ   NOT NULL DEFAULT now()
);

-- 单行种子（GLOBAL 全局策略，默认值即网关内置基线）
INSERT INTO security_behavior_policy (scope) VALUES ('GLOBAL')
ON CONFLICT (scope) DO NOTHING;

COMMIT;
