BEGIN;

CREATE TABLE IF NOT EXISTS api_llm_security_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID NOT NULL REFERENCES applications(id),
    name VARCHAR(128) NOT NULL,
    mode VARCHAR(8) NOT NULL DEFAULT 'OBSERVE',
    prompt_injection_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    pii_detection_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    blocked_topics JSONB NOT NULL DEFAULT '[]'::jsonb,
    max_prompt_bytes INTEGER NOT NULL DEFAULT 0,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    version BIGINT NOT NULL DEFAULT 1,
    created_by UUID,
    updated_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_llm_security_policy_mode CHECK (mode IN ('OBSERVE','PROTECT')),
    CONSTRAINT chk_llm_security_policy_topics CHECK (jsonb_typeof(blocked_topics) = 'array'),
    CONSTRAINT chk_llm_security_policy_prompt_bytes CHECK (max_prompt_bytes = 0 OR max_prompt_bytes BETWEEN 512 AND 4194304)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_api_llm_security_policies_application ON api_llm_security_policies(application_id);
CREATE INDEX IF NOT EXISTS idx_api_llm_security_policies_enabled ON api_llm_security_policies(application_id) WHERE enabled;

CREATE TABLE IF NOT EXISTS api_llm_security_policy_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id UUID NOT NULL REFERENCES api_llm_security_policies(id) ON DELETE CASCADE,
    version BIGINT NOT NULL,
    policy_snapshot JSONB NOT NULL,
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_api_llm_security_policy_version UNIQUE(policy_id, version)
);

INSERT INTO permissions (code, name, module, description) VALUES
('api_llm_security.read', '查看AI安全策略', 'api', '查看大模型输入保护策略、版本与命中证据'),
('api_llm_security.manage', '管理AI安全策略', 'api', '创建、修改、停用大模型输入保护策略')
ON CONFLICT (code) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id,p.id FROM roles r,permissions p
WHERE r.code='SECURITY_ADMIN' AND p.code IN ('api_llm_security.read','api_llm_security.manage')
ON CONFLICT (role_id,permission_id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id,p.id FROM roles r,permissions p
WHERE r.code='AUDIT_ADMIN' AND p.code='api_llm_security.read'
ON CONFLICT (role_id,permission_id) DO NOTHING;

COMMIT;
