-- 000247 MCP 工具定义钉扎 / OAuth 2.1 扩展与 A2A 协议安全治理 / AgBOM（Phase 9C-1）：
--   a) mcp_catalog_tools 扩展：description（完整描述）、pinned_definition_hash（Rug Pull 钉扎摘要）、pin_enforcement（OFF|OBSERVE|PROTECT）
--   b) mcp_catalog_bindings 扩展：response_guard_mode（OFF|OBSERVE|SANITIZE|PROTECT）、require_session_binding、oauth_resource_metadata_url
--   c) api_a2a_policies：按应用的 A2A 协议安全策略当前草稿（application_id UNIQUE + version 乐观锁）
--   d) api_a2a_policy_versions：不可变 A2A 策略版本历史（UNIQUE(application_id, version)，留存审计）
--   e) api_a2a_agents：Agent 物料清单（AgBOM）——支持网关自动发现观测与管理员审批/封禁
--   f) api_a2a_events：A2A 安全事件（委派越权、深度超限、递归循环熔断、致命三要素拦截）
--   g) permissions / role_permissions：种子化 api_a2a.read 与 api_a2a.manage（遵循 000232 三权边界）
BEGIN;

-- a) MCP 目录工具行扩展：定义钉扎与执行模式
ALTER TABLE mcp_catalog_tools
    ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS pinned_definition_hash VARCHAR(128) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS pin_enforcement VARCHAR(16) NOT NULL DEFAULT 'OBSERVE';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_mcp_catalog_tools_pin_enforcement'
    ) THEN
        ALTER TABLE mcp_catalog_tools
            ADD CONSTRAINT chk_mcp_catalog_tools_pin_enforcement
            CHECK (pin_enforcement IN ('OFF', 'OBSERVE', 'PROTECT'));
    END IF;
END $$;

-- b) MCP 目录绑定扩展：响应间接入侵防护、Streamable HTTP 会话绑定与 OAuth 2.1 元数据地址
ALTER TABLE mcp_catalog_bindings
    ADD COLUMN IF NOT EXISTS response_guard_mode VARCHAR(16) NOT NULL DEFAULT 'OBSERVE',
    ADD COLUMN IF NOT EXISTS require_session_binding BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS oauth_resource_metadata_url TEXT NOT NULL DEFAULT '';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_mcp_catalog_bindings_response_guard_mode'
    ) THEN
        ALTER TABLE mcp_catalog_bindings
            ADD CONSTRAINT chk_mcp_catalog_bindings_response_guard_mode
            CHECK (response_guard_mode IN ('OFF', 'OBSERVE', 'SANITIZE', 'PROTECT'));
    END IF;
END $$;

-- c) 应用级 A2A 协议安全策略（当前草稿）
CREATE TABLE IF NOT EXISTS api_a2a_policies (
    id                         UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id             UUID         NOT NULL UNIQUE REFERENCES applications(id) ON DELETE CASCADE,
    mode                       VARCHAR(16)  NOT NULL DEFAULT 'OFF'
                               CHECK (mode IN ('OFF', 'OBSERVE', 'PROTECT')),
    version                    INT          NOT NULL DEFAULT 1,
    card_discovery_enabled     BOOLEAN      NOT NULL DEFAULT TRUE,
    a2a_path_prefixes          JSONB        NOT NULL DEFAULT '["/a2a","/.well-known/agent.json","/.well-known/agent-card.json"]'::jsonb,
    allowed_caller_agents      JSONB        NOT NULL DEFAULT '[]'::jsonb,
    max_delegation_depth       INT          NOT NULL DEFAULT 3
                               CHECK (max_delegation_depth >= 1 AND max_delegation_depth <= 10),
    enforce_scope_attenuation  BOOLEAN      NOT NULL DEFAULT TRUE,
    loop_window_seconds        INT          NOT NULL DEFAULT 60
                               CHECK (loop_window_seconds >= 5 AND loop_window_seconds <= 3600),
    max_calls_per_task_window  INT          NOT NULL DEFAULT 20
                               CHECK (max_calls_per_task_window >= 1 AND max_calls_per_task_window <= 10000),
    lethal_trifecta_enabled    BOOLEAN      NOT NULL DEFAULT TRUE,
    confidential_read_patterns JSONB        NOT NULL DEFAULT '["/api/v1/secrets","/api/v1/customers","read_secret","query_pii"]'::jsonb,
    external_egress_patterns   JSONB        NOT NULL DEFAULT '["send_email","webhook","http_post","upload_external"]'::jsonb,
    updated_by                 VARCHAR(128) NOT NULL DEFAULT '',
    created_at                 TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at                 TIMESTAMPTZ  NOT NULL DEFAULT now()
);

COMMENT ON TABLE api_a2a_policies IS
    '应用级 A2A 协议安全策略草稿（Agent Card 发现、RFC 8693 委派链与权限衰减、递归循环熔断与致命三要素阻断）';

-- d) 应用级 A2A 协议安全策略不可变版本历史
CREATE TABLE IF NOT EXISTS api_a2a_policy_versions (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id  UUID         NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    version         INT          NOT NULL,
    mode            VARCHAR(16)  NOT NULL
                    CHECK (mode IN ('OFF', 'OBSERVE', 'PROTECT')),
    policy_snapshot JSONB        NOT NULL DEFAULT '{}'::jsonb,
    reason          TEXT         NOT NULL,
    created_by      VARCHAR(128) NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (application_id, version)
);

COMMENT ON TABLE api_a2a_policy_versions IS
    '应用级 A2A 协议安全策略不可变版本历史（每次草稿保存追加一行，供版本溯源与审计对照）';

-- e) Agent 物料清单（AgBOM）
CREATE TABLE IF NOT EXISTS api_a2a_agents (
    id             UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID         NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    agent_name     VARCHAR(256) NOT NULL,
    agent_url      TEXT         NOT NULL DEFAULT '',
    agent_version  VARCHAR(64)  NOT NULL DEFAULT '',
    status         VARCHAR(16)  NOT NULL DEFAULT 'DISCOVERED'
                   CHECK (status IN ('DISCOVERED', 'APPROVED', 'BLOCKED')),
    description    TEXT         NOT NULL DEFAULT '',
    skills         JSONB        NOT NULL DEFAULT '[]'::jsonb,
    allowed_skills JSONB        NOT NULL DEFAULT '[]'::jsonb,
    auth_schemes   JSONB        NOT NULL DEFAULT '[]'::jsonb,
    first_seen_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_seen_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    observed_count BIGINT       NOT NULL DEFAULT 0,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (application_id, agent_name, agent_url)
);

CREATE INDEX IF NOT EXISTS idx_api_a2a_agents_app_status
    ON api_a2a_agents (application_id, status);

CREATE INDEX IF NOT EXISTS idx_api_a2a_agents_last_seen
    ON api_a2a_agents (last_seen_at DESC);

COMMENT ON TABLE api_a2a_agents IS
    'A2A Agent 物料清单（AgBOM）：自动发现的 Agent Card 与管理员登记/审批/封禁台账';

-- f) A2A 安全事件（委派/循环/致命三要素）
CREATE TABLE IF NOT EXISTS api_a2a_events (
    id               UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id   UUID         NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    request_id       VARCHAR(128) NOT NULL DEFAULT '',
    occurred_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    event_type       VARCHAR(64)  NOT NULL,
    method           VARCHAR(128) NOT NULL DEFAULT '',
    agent_name       VARCHAR(256) NOT NULL DEFAULT '',
    delegation_depth INT          NOT NULL DEFAULT 0,
    rule_id          VARCHAR(128) NOT NULL DEFAULT '',
    action_taken     VARCHAR(32)  NOT NULL DEFAULT '',
    reason           TEXT         NOT NULL DEFAULT '',
    client_ip        VARCHAR(64)  NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_api_a2a_events_app_occurred
    ON api_a2a_events (application_id, occurred_at DESC);

CREATE INDEX IF NOT EXISTS idx_api_a2a_events_type_rule_occurred
    ON api_a2a_events (event_type, rule_id, occurred_at DESC);

COMMENT ON TABLE api_a2a_events IS
    'A2A 协议安全事件明细（委派深度/权限膨胀、递归循环熔断与致命三要素拦截记录）';

-- g) 权限种子（遵循 000232 三权边界：业务防护策略归安全管理员 SECURITY_ADMIN，审计管理员 AUDIT_ADMIN 只读）
INSERT INTO permissions (code, name, module, description) VALUES
('api_a2a.read', '查看A2A安全与AgBOM', 'api', '查看应用 A2A 安全策略、Agent 物料清单（AgBOM）及 A2A 安全事件'),
('api_a2a.manage', '管理A2A安全与AgBOM', 'api', '管理应用 A2A 安全策略及 Agent 物料清单（登记、审批、封禁与删除）')
ON CONFLICT (code) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN' AND p.code IN ('api_a2a.read', 'api_a2a.manage')
ON CONFLICT (role_id, permission_id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'AUDIT_ADMIN' AND p.code IN ('api_a2a.read')
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
