-- 000156 已吊销凭据清单（阶段8 §35 凭据异常「已吊销凭据使用」数据源）。
--   1. api_revoked_credentials：指纹级吊销清单，不存凭据明文。凭据身份沿用项目
--      统一口径（dynamic_security/detectors CredentialKey / apiruntime identity_fingerprint）：
--      credential_type ∈ auth/key/sess（与网关身份指纹前缀一致），fingerprint 为加盐
--      HMAC-SHA256 截断 16 字节的 32 位 hex（CHECK 约束强制）。唯一键为
--      (credential_type, fingerprint)：同一原始凭据值在不同头部来源下盐后指纹相同，
--      需允许按来源上下文分别登记吊销。effective_from/effective_until 为生效窗口
--      （NULL = 永久吊销），发布通道仅下发当前生效行。
--   2. 权限点 api_credential.read / api_credential.manage，授权口径与 000155 一致。
BEGIN;

CREATE TABLE IF NOT EXISTS api_revoked_credentials (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    credential_type VARCHAR(8)  NOT NULL,           -- 凭据来源上下文：auth（Authorization）/key（X-API-Key）/sess（Cookie）
    fingerprint     VARCHAR(32) NOT NULL,           -- 加盐 HMAC-SHA256 指纹（32 位 hex，不含前缀，不存明文）
    reason          TEXT        NOT NULL,           -- 吊销原因（必填）
    revoked_by      TEXT,                           -- 吊销人（操作者用户名，服务端取自登录主体）
    effective_from  TIMESTAMPTZ NOT NULL DEFAULT now(), -- 生效时间
    effective_until TIMESTAMPTZ,                    -- 到期时间（NULL = 永久吊销）
    created_by      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT ck_api_revoked_credentials_type
        CHECK (credential_type IN ('auth', 'key', 'sess')),
    CONSTRAINT ck_api_revoked_credentials_fingerprint
        CHECK (fingerprint ~ '^[0-9a-f]{32}$'),
    CONSTRAINT ck_api_revoked_credentials_window
        CHECK (effective_until IS NULL OR effective_until > effective_from),
    CONSTRAINT uq_api_revoked_credentials UNIQUE (credential_type, fingerprint)
);
-- 发布通道按生效窗口过滤，到期/未生效行不下发
CREATE INDEX IF NOT EXISTS idx_api_revoked_credentials_window
    ON api_revoked_credentials (effective_from, effective_until);

-- 已吊销凭据管理权限点（查看/管理）
INSERT INTO permissions (code, name, module, description) VALUES
('api_credential.read',   '查看已吊销凭据', 'api', '查看已吊销凭据清单（指纹级，无凭据明文）'),
('api_credential.manage', '管理已吊销凭据', 'api', '维护已吊销凭据清单（登记吊销/调整窗口/移除）')
ON CONFLICT (code) DO NOTHING;

-- 安全管理员：全部 2 个权限点（与 000155 口径一致，AUDIT_ADMIN/SYSTEM_ADMIN 不授权）
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN' AND p.code IN ('api_credential.read', 'api_credential.manage')
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
