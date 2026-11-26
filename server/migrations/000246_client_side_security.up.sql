-- 000246 客户端供应链安全防护（Magecart 防护 / PCI DSS 4.0 6.4.3 & 11.6.1，Phase 9B）：
--   a) client_side_policies：按应用的客户端供应链安全策略当前草稿（application_id UNIQUE + version 乐观锁）
--   b) client_side_policy_versions：不可变策略版本记录（UNIQUE(application_id, version)，留存审计）
--   c) client_script_inventory：支付/业务页面脚本资产清单与授权台账（PCI DSS 4.0 6.4.3）
--   d) client_side_violations：脚本篡改、未授权脚本、CSP 违规与敏感页探针告警记录（PCI DSS 4.0 11.6.1）
--   e) permissions / role_permissions：种子化 client_side.read 与 client_side.manage（遵循 000232 三权边界）
BEGIN;

-- a) 应用级客户端供应链安全策略（当前草稿）
CREATE TABLE IF NOT EXISTS client_side_policies (
    id                         UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id             UUID         NOT NULL UNIQUE REFERENCES applications(id) ON DELETE CASCADE,
    mode                       VARCHAR(16)  NOT NULL DEFAULT 'OFF'
                               CHECK (mode IN ('OFF', 'OBSERVE', 'PROTECT')),
    version                    INT          NOT NULL DEFAULT 1,
    csp_mode                   VARCHAR(16)  NOT NULL DEFAULT 'OFF'
                               CHECK (csp_mode IN ('OFF', 'REPORT_ONLY', 'ENFORCE')),
    sensitive_paths            JSONB        NOT NULL DEFAULT '[]'::jsonb,
    probe_enabled              BOOLEAN      NOT NULL DEFAULT FALSE,
    strip_unauthorized_scripts BOOLEAN      NOT NULL DEFAULT FALSE,
    allowed_script_origins     JSONB        NOT NULL DEFAULT '[]'::jsonb,
    allowed_connect_origins    JSONB        NOT NULL DEFAULT '[]'::jsonb,
    allowed_form_origins       JSONB        NOT NULL DEFAULT '[]'::jsonb,
    custom_csp_directives      TEXT         NOT NULL DEFAULT '',
    updated_by                 VARCHAR(255) NOT NULL DEFAULT '',
    created_at                 TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at                 TIMESTAMPTZ  NOT NULL DEFAULT now()
);

COMMENT ON TABLE client_side_policies IS
    '应用级客户端供应链安全策略草稿（CSP 策略、敏感表单探针、外链脚本 SRI 校验与未授权脚本剥离）';

-- b) 应用级客户端供应链安全策略不可变版本历史
CREATE TABLE IF NOT EXISTS client_side_policy_versions (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id  UUID         NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    version         INT          NOT NULL,
    mode            VARCHAR(16)  NOT NULL
                    CHECK (mode IN ('OFF', 'OBSERVE', 'PROTECT')),
    csp_mode        VARCHAR(16)  NOT NULL
                    CHECK (csp_mode IN ('OFF', 'REPORT_ONLY', 'ENFORCE')),
    policy_snapshot JSONB        NOT NULL DEFAULT '{}'::jsonb,
    reason          TEXT         NOT NULL,
    created_by      VARCHAR(255) NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (application_id, version)
);

COMMENT ON TABLE client_side_policy_versions IS
    '应用级客户端供应链安全策略不可变版本历史（每次草稿保存追加一行，供版本溯源与 PCI DSS 审计对照）';

-- c) 客户端脚本资产与授权台账（PCI DSS 4.0 6.4.3）
CREATE TABLE IF NOT EXISTS client_script_inventory (
    id               UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id   UUID         NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    script_url       TEXT         NOT NULL,
    script_origin    TEXT         NOT NULL DEFAULT '',
    script_type      VARCHAR(16)  NOT NULL
                     CHECK (script_type IN ('EXTERNAL', 'INLINE_HASH')),
    sri_hash         TEXT         NOT NULL DEFAULT '',
    observed_sri     TEXT         NOT NULL DEFAULT '',
    status           VARCHAR(16)  NOT NULL DEFAULT 'DISCOVERED'
                     CHECK (status IN ('DISCOVERED', 'AUTHORIZED', 'BLOCKED')),
    justification    TEXT         NOT NULL DEFAULT '',
    approved_by      VARCHAR(128) NOT NULL DEFAULT '',
    approved_at      TIMESTAMPTZ,
    sample_page_path TEXT         NOT NULL DEFAULT '',
    first_seen_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_seen_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    observed_count   BIGINT       NOT NULL DEFAULT 0,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (application_id, script_url, script_type)
);

CREATE INDEX IF NOT EXISTS idx_client_script_inventory_app_status
    ON client_script_inventory (application_id, status);

CREATE INDEX IF NOT EXISTS idx_client_script_inventory_last_seen
    ON client_script_inventory (last_seen_at DESC);

COMMENT ON TABLE client_script_inventory IS
    '客户端脚本资产与授权清单（支持自动发现观测、预授权/封禁审批、SRI 完整性固定与 PCI DSS 4.0 6.4.3 业务必要性说明）';

-- d) 客户端供应链篡改与 CSP 违规告警（PCI DSS 4.0 11.6.1）
CREATE TABLE IF NOT EXISTS client_side_violations (
    id                 UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id     UUID         NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    request_id         VARCHAR(128) NOT NULL DEFAULT '',
    occurred_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
    violation_type     VARCHAR(32)  NOT NULL
                       CHECK (violation_type IN ('UNAUTHORIZED_SCRIPT', 'SCRIPT_TAMPERED', 'CSP_VIOLATION', 'PROBE_ALERT')),
    script_url         TEXT         NOT NULL DEFAULT '',
    script_origin      TEXT         NOT NULL DEFAULT '',
    expected_sri       TEXT         NOT NULL DEFAULT '',
    observed_sri       TEXT         NOT NULL DEFAULT '',
    page_path          TEXT         NOT NULL DEFAULT '',
    violated_directive TEXT         NOT NULL DEFAULT '',
    blocked_uri        TEXT         NOT NULL DEFAULT '',
    action_taken       VARCHAR(32)  NOT NULL DEFAULT '',
    reason             TEXT         NOT NULL DEFAULT '',
    client_ip          VARCHAR(64)  NOT NULL DEFAULT '',
    status             VARCHAR(16)  NOT NULL DEFAULT 'OPEN'
                       CHECK (status IN ('OPEN', 'ACKNOWLEDGED', 'RESOLVED', 'FALSE_POSITIVE')),
    note               TEXT         NOT NULL DEFAULT '',
    handled_by         VARCHAR(128) NOT NULL DEFAULT '',
    handled_at         TIMESTAMPTZ,
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_client_side_violations_app_occurred
    ON client_side_violations (application_id, occurred_at DESC);

CREATE INDEX IF NOT EXISTS idx_client_side_violations_status_type
    ON client_side_violations (status, violation_type, occurred_at DESC);

COMMENT ON TABLE client_side_violations IS
    '客户端供应链安全违规与篡改检测告警（PCI DSS 4.0 11.6.1 变更/篡改检测与处置记录）';

-- e) 权限种子（遵循 000232 三权边界：业务防护策略归安全管理员 SECURITY_ADMIN，审计管理员 AUDIT_ADMIN 只读）
INSERT INTO permissions (code, name, module, description) VALUES
('client_side.read', '查看客户端供应链安全', 'security', '查看应用客户端供应链安全策略、脚本资产清单、篡改与 CSP 违规告警及合规证据导出'),
('client_side.manage', '管理客户端供应链安全', 'security', '管理应用客户端供应链安全策略、审批/封禁脚本资产及处置篡改与 CSP 违规告警')
ON CONFLICT (code) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN' AND p.code IN ('client_side.read', 'client_side.manage')
ON CONFLICT (role_id, permission_id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'AUDIT_ADMIN' AND p.code IN ('client_side.read')
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
