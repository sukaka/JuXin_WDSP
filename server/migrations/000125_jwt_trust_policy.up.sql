-- 000125 业务 JWT 信任链策略（WDSP P0-03，服务端管理面；任务书 docs/tasks/wdsp-p0/P0-03_JWT_TRUST_CHAIN.md）。
--   jwt_trust_policies：按应用的 JWT 信任策略当前草稿（每应用一行，application_id UNIQUE）；
--     mode 默认 OFF（不改变既有流量），selectors/issuers 为 JSONB（字段契约由应用层
--     jwttrust.Validate 校验：方法大写去重、path_exact/path_prefix 二选一、issuer 精确值唯一、
--     algorithms ⊆ {RS256,ES256}、clock_skew_seconds 0~120、静态 JWKS 仅公钥）。
--     version 乐观锁（PUT 携带 expected_version，冲突 409）。
--   jwt_trust_policy_versions：不可变策略版本记录（每次草稿保存追加一行，
--     UNIQUE(application_id, version)；reason 非空进操作审计同步留存），
--     供版本溯源与回滚对照；已发布/已生效版本以 access_control_versions 快照为准。
--   system_settings 种子 jwt_trust:remote_jwks_allowlist：REMOTE_JWKS 企业内网 IdP
--     显式允许清单（逗号分隔主机名/CIDR；默认空=仅公网 HTTPS，云元数据/链路本地恒拒绝）。
BEGIN;

CREATE TABLE IF NOT EXISTS jwt_trust_policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id  UUID         NOT NULL UNIQUE REFERENCES applications(id) ON DELETE CASCADE,
    mode            VARCHAR(16)  NOT NULL DEFAULT 'OFF'
                    CHECK (mode IN ('OFF', 'OBSERVE', 'PROTECT')),
    version         INT          NOT NULL DEFAULT 1,
    selectors       JSONB        NOT NULL DEFAULT '[]'::jsonb,
    issuers         JSONB        NOT NULL DEFAULT '[]'::jsonb,
    updated_by      VARCHAR(255) DEFAULT '',
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS jwt_trust_policy_versions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id  UUID         NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    version         INT          NOT NULL,
    mode            VARCHAR(16)  NOT NULL
                    CHECK (mode IN ('OFF', 'OBSERVE', 'PROTECT')),
    selectors       JSONB        NOT NULL DEFAULT '[]'::jsonb,
    issuers         JSONB        NOT NULL DEFAULT '[]'::jsonb,
    reason          TEXT         NOT NULL,
    created_by      VARCHAR(255) DEFAULT '',
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (application_id, version)
);

-- REMOTE_JWKS 内网 IdP 允许清单（空=仅公网 HTTPS；SSRF 校验规则见 jwttrust/outboundhttp）
INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, is_sensitive, description) VALUES
('jwt_trust', 'remote_jwks_allowlist', '""', 'string', FALSE,
 'JWT信任策略 REMOTE_JWKS 企业内网 IdP 允许清单：逗号/空白分隔的主机名或 CIDR；默认空=仅允许公网 HTTPS 地址，云元数据与链路本地地址恒拒绝')
ON CONFLICT (setting_group, setting_key) DO NOTHING;

COMMIT;
