-- 回滚 000240：移除 app_tls_configs 表、application_certificates 槽位列及 certificates 国密双证扩展列
BEGIN;

DROP TABLE IF EXISTS app_tls_configs;

DROP INDEX IF EXISTS idx_app_certs_active_slot;
ALTER TABLE application_certificates
    DROP CONSTRAINT IF EXISTS chk_app_certs_slot,
    DROP COLUMN IF EXISTS cert_slot;

DROP INDEX IF EXISTS idx_certificates_protocol_type;
ALTER TABLE certificates
    DROP CONSTRAINT IF EXISTS chk_certificates_protocol_type,
    DROP COLUMN IF EXISTS enc_fingerprint_sha256,
    DROP COLUMN IF EXISTS enc_not_after,
    DROP COLUMN IF EXISTS enc_not_before,
    DROP COLUMN IF EXISTS enc_serial_number,
    DROP COLUMN IF EXISTS enc_issuer,
    DROP COLUMN IF EXISTS enc_subject,
    DROP COLUMN IF EXISTS enc_common_name,
    DROP COLUMN IF EXISTS encrypted_enc_private_key_reference,
    DROP COLUMN IF EXISTS enc_certificate_reference,
    DROP COLUMN IF EXISTS protocol_type;

COMMIT;
