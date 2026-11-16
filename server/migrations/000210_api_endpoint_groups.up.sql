-- 000210 业务功能分组与接口组成员：后续按接口组限速的真实数据源。
BEGIN;

CREATE TABLE IF NOT EXISTS api_endpoint_groups (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID         NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    code           VARCHAR(64)  NOT NULL,
    name           VARCHAR(128) NOT NULL,
    description    VARCHAR(512) NOT NULL DEFAULT '',
    enabled        BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT ck_api_endpoint_groups_code
        CHECK (code ~ '^[A-Z][A-Z0-9_]*$'),
    CONSTRAINT ck_api_endpoint_groups_name
        CHECK (char_length(btrim(name)) > 0),
    CONSTRAINT uq_api_endpoint_groups_application_code
        UNIQUE (application_id, code)
);
CREATE INDEX IF NOT EXISTS idx_api_endpoint_groups_application
    ON api_endpoint_groups (application_id, enabled);

CREATE TABLE IF NOT EXISTS api_endpoint_group_members (
    group_id    UUID        NOT NULL REFERENCES api_endpoint_groups(id) ON DELETE CASCADE,
    endpoint_id UUID        NOT NULL REFERENCES api_endpoints(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, endpoint_id)
);
CREATE INDEX IF NOT EXISTS idx_api_endpoint_group_members_endpoint
    ON api_endpoint_group_members (endpoint_id, group_id);

INSERT INTO permissions (code, name, module, description) VALUES
('api_endpoint_group.read',   '查看接口分组', 'api', '查看业务功能分组及其接口成员'),
('api_endpoint_group.manage', '管理接口分组', 'api', '创建、编辑、删除业务功能分组并维护接口成员')
ON CONFLICT (code) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN'
  AND p.code IN ('api_endpoint_group.read', 'api_endpoint_group.manage')
ON CONFLICT (role_id, permission_id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'AUDIT_ADMIN' AND p.code = 'api_endpoint_group.read'
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
