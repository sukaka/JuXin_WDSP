-- URL 白名单规则表：与 ip_access_rules 同级，支持全局/应用级、精确/前缀/正则匹配、
-- 可选 HTTP 方法限定、永久/临时有效期及安全事件溯源。
-- 网关放行语义与 IP 白名单一致：跳过 IP 黑名单、L7、自动封禁、身份风险策略与 CC，
-- 不绕过人工临时封禁、Bot 挑战、API 动态防护与 WAF（安全底线）。

BEGIN;

CREATE TABLE IF NOT EXISTS url_whitelist_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(200) NOT NULL,
    scope_type      VARCHAR(15)  NOT NULL,                    -- GLOBAL / APPLICATION
    application_id  UUID REFERENCES applications(id),
    match_type      VARCHAR(15)  NOT NULL DEFAULT 'EXACT',    -- EXACT / PREFIX / REGEX
    uri_pattern     VARCHAR(512) NOT NULL,
    methods         TEXT[]       NOT NULL DEFAULT '{}',       -- 空数组表示全部 HTTP 方法
    priority        INTEGER      NOT NULL DEFAULT 100,
    status          VARCHAR(15)  NOT NULL DEFAULT 'ACTIVE',   -- DRAFT/ACTIVE/DISABLED/EXPIRED/DELETED
    validity_type   VARCHAR(15)  NOT NULL DEFAULT 'PERMANENT', -- PERMANENT / TEMPORARY
    effective_from  TIMESTAMPTZ,
    effective_until TIMESTAMPTZ,
    reason          VARCHAR(500) NOT NULL DEFAULT '',
    source_type     VARCHAR(20)  NOT NULL DEFAULT 'MANUAL',   -- MANUAL / SECURITY_EVENT
    source_event_id UUID,
    hit_count       BIGINT       NOT NULL DEFAULT 0,
    last_hit_at     TIMESTAMPTZ,
    created_by      UUID,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_by      UUID,
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    deleted_at      TIMESTAMPTZ,
    version         INTEGER      NOT NULL DEFAULT 1,
    CONSTRAINT chk_url_whitelist_app_scope CHECK (
        (scope_type = 'APPLICATION' AND application_id IS NOT NULL) OR
        (scope_type = 'GLOBAL' AND application_id IS NULL)
    ),
    CONSTRAINT chk_url_whitelist_match_type CHECK (
        match_type IN ('EXACT', 'PREFIX', 'REGEX')
    )
);

CREATE INDEX IF NOT EXISTS idx_url_whitelist_scope
    ON url_whitelist_rules (scope_type, status) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_url_whitelist_app
    ON url_whitelist_rules (application_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_url_whitelist_until
    ON url_whitelist_rules (effective_until) WHERE status = 'ACTIVE' AND effective_until IS NOT NULL;

COMMIT;
