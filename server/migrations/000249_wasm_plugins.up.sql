-- 000249 Wasm 检测插件热插拔沙箱（Phase 9D-1）：
--   a) wasm_plugins：全局/应用级 Wasm 自定义检测插件当前版本（version 乐观锁，同作用域名称唯一）
--   b) wasm_plugin_versions：不可变插件版本历史（含二进制与配置快照，支持审计溯源与一键回滚）
--   c) permissions / role_permissions：种子化 wasm_plugins.read 与 wasm_plugins.manage（遵循 000232 三权边界）
BEGIN;

-- a) Wasm 自定义检测插件（当前版本）
CREATE TABLE IF NOT EXISTS wasm_plugins (
    id             UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID         NULL REFERENCES applications(id) ON DELETE CASCADE,
    name           VARCHAR(128) NOT NULL,
    description    TEXT         NOT NULL DEFAULT '',
    version        INT          NOT NULL DEFAULT 1,
    abi_version    VARCHAR(32)  NOT NULL DEFAULT 'wdsp_v1'
                   CHECK (abi_version IN ('wdsp_v1')),
    mode           VARCHAR(16)  NOT NULL DEFAULT 'OFF'
                   CHECK (mode IN ('OFF', 'OBSERVE', 'PROTECT')),
    sha256         VARCHAR(64)  NOT NULL,
    wasm_size      INT          NOT NULL
                   CHECK (wasm_size > 0 AND wasm_size <= 4194304),
    wasm_binary    BYTEA        NOT NULL,
    priority       INT          NOT NULL DEFAULT 100
                   CHECK (priority >= 0 AND priority <= 10000),
    timeout_ms     INT          NOT NULL DEFAULT 2
                   CHECK (timeout_ms >= 1 AND timeout_ms <= 50),
    max_memory_kb  INT          NOT NULL DEFAULT 4096
                   CHECK (max_memory_kb >= 256 AND max_memory_kb <= 16384),
    max_body_bytes INT          NOT NULL DEFAULT 65536
                   CHECK (max_body_bytes >= 0 AND max_body_bytes <= 65536),
    fail_policy    VARCHAR(16)  NOT NULL DEFAULT 'FAIL_OPEN'
                   CHECK (fail_policy IN ('FAIL_OPEN', 'FAIL_CLOSED')),
    path_prefixes  JSONB        NOT NULL DEFAULT '[]'::jsonb,
    updated_by     VARCHAR(128) NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ  NOT NULL DEFAULT now()
);

COMMENT ON TABLE wasm_plugins IS
    '全局与应用级 Wasm 自定义检测插件（wazero 零权限沙箱，按作用域唯一命名，带乐观锁版本号）';

CREATE UNIQUE INDEX IF NOT EXISTS uq_wasm_plugins_scope_name
    ON wasm_plugins (COALESCE(application_id, '00000000-0000-0000-0000-000000000000'::uuid), name);

CREATE INDEX IF NOT EXISTS idx_wasm_plugins_scope_priority
    ON wasm_plugins (application_id, priority ASC, name ASC);

-- b) Wasm 插件不可变版本历史（供版本溯源与一键回滚）
CREATE TABLE IF NOT EXISTS wasm_plugin_versions (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    plugin_id       UUID         NOT NULL REFERENCES wasm_plugins(id) ON DELETE CASCADE,
    version         INT          NOT NULL,
    abi_version     VARCHAR(32)  NOT NULL
                    CHECK (abi_version IN ('wdsp_v1')),
    mode            VARCHAR(16)  NOT NULL
                    CHECK (mode IN ('OFF', 'OBSERVE', 'PROTECT')),
    sha256          VARCHAR(64)  NOT NULL,
    wasm_size       INT          NOT NULL
                    CHECK (wasm_size > 0 AND wasm_size <= 4194304),
    wasm_binary     BYTEA        NOT NULL,
    config_snapshot JSONB        NOT NULL DEFAULT '{}'::jsonb,
    reason          TEXT         NOT NULL DEFAULT '',
    created_by      VARCHAR(128) NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (plugin_id, version)
);

COMMENT ON TABLE wasm_plugin_versions IS
    'Wasm 检测插件不可变版本历史（每次创建、更新或回滚追加新版本，永不覆盖或删除既有版本）';

CREATE INDEX IF NOT EXISTS idx_wasm_plugin_versions_plugin_version
    ON wasm_plugin_versions (plugin_id, version DESC);

-- c) 权限种子（遵循 000232 三权边界：业务防护策略归安全管理员 SECURITY_ADMIN，审计管理员 AUDIT_ADMIN 只读）
INSERT INTO permissions (code, name, module, description) VALUES
('wasm_plugins.read', '查看 Wasm 检测插件', 'wasm_plugins', '查看全局与应用级 Wasm 检测插件清单、沙箱护栏参数与不可变版本历史'),
('wasm_plugins.manage', '管理 Wasm 检测插件', 'wasm_plugins', '上传、更新、回滚与删除全局及应用级 Wasm 检测插件')
ON CONFLICT (code) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN' AND p.code IN ('wasm_plugins.read', 'wasm_plugins.manage')
ON CONFLICT (role_id, permission_id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'AUDIT_ADMIN' AND p.code IN ('wasm_plugins.read')
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
