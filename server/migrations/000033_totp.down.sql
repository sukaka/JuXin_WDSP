-- 双因子认证（TOTP）回滚：移除 users 表 TOTP 字段
BEGIN;

ALTER TABLE users
    DROP COLUMN IF EXISTS totp_recovery_codes,
    DROP COLUMN IF EXISTS totp_enabled_at,
    DROP COLUMN IF EXISTS totp_enabled,
    DROP COLUMN IF EXISTS totp_pending_secret_encrypted,
    DROP COLUMN IF EXISTS totp_secret_encrypted;

COMMIT;
