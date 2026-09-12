-- 000078 产品侧离线授权（licenses 表 + license.* 权限点）。
--
-- 授权文件（.lic）由授权中心离线 Ed25519 签发，产品侧验签导入：
-- 生效授权 = 唯一 status='ACTIVE' 行（部分唯一索引保证单行）；
-- 导入新授权时同事务将旧生效候选行（ACTIVE/FINGERPRINT_MISMATCH）置 SUPERSEDED。
-- payload/signature 为验签通过的签发产物原文留存；raw_file 为 .lic 原文
-- （应用层 AES-256-GCM 加密后落库，未装配加密服务时为 NULL，不出现明文）。
BEGIN;

CREATE TABLE IF NOT EXISTS licenses (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    license_id          TEXT         NOT NULL UNIQUE,            -- 授权编号（签发侧 license_id）
    license_type        VARCHAR(16)  NOT NULL DEFAULT 'FORMAL',  -- FORMAL / TRIAL
    product             VARCHAR(16)  NOT NULL,                   -- waf / wdsp / api
    customer            TEXT         NOT NULL DEFAULT '',        -- 客户名称
    payload             JSONB        NOT NULL,                   -- 签名 payload（验签后原文留存）
    signature           TEXT         NOT NULL,                   -- Ed25519 签名（hex）
    raw_file            BYTEA,                                   -- .lic 原文密文（encSvc 加密）；NULL = 未装配加密服务
    status              VARCHAR(24)  NOT NULL DEFAULT 'ACTIVE',  -- ACTIVE/EXPIRED/FINGERPRINT_MISMATCH/SUPERSEDED/INVALID
    imported_by         UUID,                                    -- 导入操作人（users.id；NULL = 系统）
    imported_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at          DATE,                                    -- 到期日（含当天 23:59:59 UTC）；NULL = 永久授权
    perpetual           BOOLEAN      NOT NULL DEFAULT FALSE,     -- 是否永久授权
    machine_fingerprint TEXT         NOT NULL DEFAULT '',        -- 绑定机器指纹（sha256:...）；'' = 未绑定
    quotas              JSONB        NOT NULL DEFAULT '{}',      -- {max_applications,max_api_endpoints,max_qps}，0 = 不限制
    features            JSONB        NOT NULL DEFAULT '[]',      -- 授权能力点（展示用）
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT chk_licenses_status CHECK (status IN ('ACTIVE','EXPIRED','FINGERPRINT_MISMATCH','SUPERSEDED','INVALID')),
    CONSTRAINT chk_licenses_product CHECK (product IN ('waf','wdsp','api')),
    CONSTRAINT chk_licenses_type CHECK (license_type IN ('FORMAL','TRIAL'))
);

-- 生效授权单行约束：ACTIVE 至多一行（EXPIRED/FINGERPRINT_MISMATCH 等不受限）
CREATE UNIQUE INDEX IF NOT EXISTS idx_licenses_single_active
    ON licenses ((status)) WHERE status = 'ACTIVE';

CREATE INDEX IF NOT EXISTS idx_licenses_imported_at
    ON licenses (imported_at DESC);

COMMENT ON TABLE licenses IS '产品侧离线授权（.lic 导入）；生效授权 = 唯一 ACTIVE 行，周期复核翻转 EXPIRED/FINGERPRINT_MISMATCH';

-- 权限点（系统管理域口径：SYSTEM_ADMIN 全量、AUDIT_ADMIN 只读、SECURITY_ADMIN 不授权）
INSERT INTO permissions (code, name, module, description) VALUES
('license.read',   '查看授权', 'license', '查看授权状态与导入历史'),
('license.manage', '管理授权', 'license', '导入离线授权文件（.lic）')
ON CONFLICT (code) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SYSTEM_ADMIN' AND p.code IN ('license.read','license.manage')
ON CONFLICT (role_id, permission_id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'AUDIT_ADMIN' AND p.code IN ('license.read')
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
