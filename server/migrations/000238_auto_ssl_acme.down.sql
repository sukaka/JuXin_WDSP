BEGIN;

DROP TABLE IF EXISTS acme_cert_orders;

DROP INDEX IF EXISTS idx_applications_auto_ssl;
ALTER TABLE applications
    DROP COLUMN IF EXISTS auto_ssl_last_attempt_at,
    DROP COLUMN IF EXISTS auto_ssl_next_retry_at,
    DROP COLUMN IF EXISTS auto_ssl_fail_count,
    DROP COLUMN IF EXISTS auto_ssl_last_error,
    DROP COLUMN IF EXISTS auto_ssl_last_status,
    DROP COLUMN IF EXISTS auto_ssl_renew_before_days,
    DROP COLUMN IF EXISTS auto_ssl_challenge_type,
    DROP COLUMN IF EXISTS auto_ssl_enabled;

DROP INDEX IF EXISTS idx_certificates_managed_auto_renew;
ALTER TABLE certificates
    DROP COLUMN IF EXISTS last_renewed_at,
    DROP COLUMN IF EXISTS superseded_by,
    DROP COLUMN IF EXISTS replaces_certificate_id,
    DROP COLUMN IF EXISTS renew_before_days,
    DROP COLUMN IF EXISTS auto_renew,
    DROP COLUMN IF EXISTS acme_account_id,
    DROP COLUMN IF EXISTS acme_directory_url,
    DROP COLUMN IF EXISTS acme_provider,
    DROP COLUMN IF EXISTS managed_by;

DROP TABLE IF EXISTS acme_accounts;
DROP TABLE IF EXISTS acme_config;

COMMIT;
