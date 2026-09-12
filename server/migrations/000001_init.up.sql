-- 九章WEB应用智能防护系统V2.0 阶段2 初始迁移
-- 创建身份认证、RBAC、会话、日志、审计、系统设置相关表

BEGIN;

-- ---------- 用户 ----------
CREATE TABLE IF NOT EXISTS users (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username                VARCHAR(64)  NOT NULL,
    display_name            VARCHAR(128) NOT NULL DEFAULT '',
    password_hash           VARCHAR(255) NOT NULL,
    status                  VARCHAR(32)  NOT NULL DEFAULT 'ACTIVE',
    must_change_password    BOOLEAN      NOT NULL DEFAULT FALSE,
    password_changed_at     TIMESTAMPTZ,
    password_expires_at     TIMESTAMPTZ,
    failed_login_count      INTEGER      NOT NULL DEFAULT 0,
    locked_until            TIMESTAMPTZ,
    last_login_at           TIMESTAMPTZ,
    last_login_ip           INET,
    created_by              UUID,
    created_at              TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ  NOT NULL DEFAULT now(),
    deleted_at              TIMESTAMPTZ,
    version                 INTEGER      NOT NULL DEFAULT 1
);
-- 用户名不区分大小写唯一（含逻辑删除后不可重用，保留历史完整性）
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_lower ON users (lower(username));

-- ---------- 角色 ----------
CREATE TABLE IF NOT EXISTS roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code        VARCHAR(64)  NOT NULL UNIQUE,
    name        VARCHAR(128) NOT NULL,
    description TEXT         NOT NULL DEFAULT '',
    is_builtin  BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- ---------- 权限 ----------
CREATE TABLE IF NOT EXISTS permissions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code        VARCHAR(128) NOT NULL UNIQUE,
    name        VARCHAR(128) NOT NULL,
    module      VARCHAR(64)  NOT NULL,
    description TEXT         NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- ---------- 用户-角色 ----------
CREATE TABLE IF NOT EXISTS user_roles (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id    UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, role_id)
);
CREATE INDEX IF NOT EXISTS idx_user_roles_user ON user_roles (user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role ON user_roles (role_id);

-- ---------- 角色-权限 ----------
CREATE TABLE IF NOT EXISTS role_permissions (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_id       UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (role_id, permission_id)
);
CREATE INDEX IF NOT EXISTS idx_role_permissions_role ON role_permissions (role_id);

-- ---------- 密码历史 ----------
CREATE TABLE IF NOT EXISTS password_histories (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    password_hash VARCHAR(255) NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_password_histories_user ON password_histories (user_id, created_at DESC);

-- ---------- 登录会话摘要（不保存原始 Session ID） ----------
CREATE TABLE IF NOT EXISTS login_sessions (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id            UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_hash       VARCHAR(128) NOT NULL UNIQUE,
    source_ip          INET,
    user_agent_summary VARCHAR(512) NOT NULL DEFAULT '',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at         TIMESTAMPTZ NOT NULL,
    revoked_at         TIMESTAMPTZ,
    revoke_reason      VARCHAR(64)
);
CREATE INDEX IF NOT EXISTS idx_login_sessions_user ON login_sessions (user_id, created_at DESC);

-- ---------- 登录日志 ----------
CREATE TABLE IF NOT EXISTS login_logs (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    occurred_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    username           VARCHAR(64) NOT NULL,
    user_id            UUID,
    source_ip          INET,
    connection_ip      INET,
    user_agent_summary VARCHAR(512) NOT NULL DEFAULT '',
    event_type         VARCHAR(64) NOT NULL,
    result             VARCHAR(32) NOT NULL,
    failure_code       VARCHAR(64) NOT NULL DEFAULT '',
    request_id         VARCHAR(64) NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_login_logs_time ON login_logs (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_login_logs_username ON login_logs (username, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_login_logs_request ON login_logs (request_id);

-- ---------- 操作审计（仅新增和查询，禁止 UPDATE/DELETE） ----------
CREATE TABLE IF NOT EXISTS operation_audits (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    occurred_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    user_id            UUID,
    username           VARCHAR(64) NOT NULL DEFAULT '',
    source_ip          INET,
    connection_ip      INET,
    user_agent_summary VARCHAR(512) NOT NULL DEFAULT '',
    module             VARCHAR(64) NOT NULL,
    action             VARCHAR(64) NOT NULL,
    object_type        VARCHAR(64) NOT NULL DEFAULT '',
    object_id          VARCHAR(64) NOT NULL DEFAULT '',
    object_name        VARCHAR(255) NOT NULL DEFAULT '',
    before_summary     TEXT NOT NULL DEFAULT '',
    after_summary      TEXT NOT NULL DEFAULT '',
    result             VARCHAR(32) NOT NULL,
    failure_reason     TEXT NOT NULL DEFAULT '',
    risk_level         VARCHAR(16) NOT NULL DEFAULT 'LOW',
    request_id         VARCHAR(64) NOT NULL DEFAULT '',
    previous_hash      VARCHAR(128) NOT NULL DEFAULT '',
    record_hash        VARCHAR(128) NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_operation_audits_time ON operation_audits (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_operation_audits_user ON operation_audits (username, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_operation_audits_module ON operation_audits (module, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_operation_audits_request ON operation_audits (request_id);

-- 审计表防篡改：禁止 UPDATE/DELETE（规则限制应用层误操作）
CREATE OR REPLACE RULE operation_audits_no_update AS ON UPDATE TO operation_audits
    DO INSTEAD NOTHING;
CREATE OR REPLACE RULE operation_audits_no_delete AS ON DELETE TO operation_audits
    DO INSTEAD NOTHING;

-- ---------- 系统设置 ----------
CREATE TABLE IF NOT EXISTS system_settings (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    setting_group VARCHAR(64)  NOT NULL,
    setting_key   VARCHAR(128) NOT NULL,
    setting_value JSONB        NOT NULL,
    value_type    VARCHAR(32)  NOT NULL DEFAULT 'string',
    is_sensitive  BOOLEAN      NOT NULL DEFAULT FALSE,
    description   TEXT         NOT NULL DEFAULT '',
    updated_by    UUID,
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    version       INTEGER      NOT NULL DEFAULT 1,
    UNIQUE (setting_group, setting_key)
);

COMMIT;
