-- 双因子认证（TOTP，RFC 6238）：users 表扩展。
-- 密钥经应用层 AES-256-GCM 加密后存储（密文 base64），数据库不落明文；
-- 恢复码只存 SHA-256 哈希（jsonb 字符串数组）。
BEGIN;

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS totp_secret_encrypted         TEXT,        -- 已启用密钥（加密）
    ADD COLUMN IF NOT EXISTS totp_pending_secret_encrypted TEXT,        -- 待启用密钥（加密，enable 验证通过后转正）
    ADD COLUMN IF NOT EXISTS totp_enabled                  BOOLEAN      NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS totp_enabled_at               TIMESTAMPTZ, -- 开启时间
    ADD COLUMN IF NOT EXISTS totp_recovery_codes           JSONB        NOT NULL DEFAULT '[]'::jsonb; -- 恢复码哈希数组

COMMIT;
