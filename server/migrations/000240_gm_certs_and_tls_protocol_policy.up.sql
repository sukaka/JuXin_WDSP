-- 000240 国密双证书（SM2/TLCP）、应用双槽位证书绑定与站点 TLS/HTTP 协议降级配置：
--   a) certificates：新增 protocol_type（INTERNATIONAL/SM_TLCP）及国密加密证书与密文私钥列
--   b) application_certificates：新增 cert_slot 槽位列及活动单槽唯一索引（允许同站点同时绑定国际证书+国密双证书，与 ACME 自动续约互不干扰）
--   c) app_tls_configs：每应用一对一的协议自识别、TLS 版本、HTTP 降级、回源 SSL 加载与加密会话分析配置
BEGIN;

-- a) 证书表扩展国密双证书支持（既有记录默认 INTERNATIONAL，完全兼容）
ALTER TABLE certificates
    ADD COLUMN IF NOT EXISTS protocol_type                     VARCHAR(32)  NOT NULL DEFAULT 'INTERNATIONAL',
    ADD COLUMN IF NOT EXISTS enc_certificate_reference         TEXT         NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS encrypted_enc_private_key_reference TEXT       NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS enc_common_name                   VARCHAR(255) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS enc_subject                       VARCHAR(512) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS enc_issuer                        VARCHAR(512) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS enc_serial_number                 VARCHAR(128) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS enc_not_before                    TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS enc_not_after                     TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS enc_fingerprint_sha256            VARCHAR(128) NOT NULL DEFAULT '';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'certificates'::regclass AND conname = 'chk_certificates_protocol_type'
    ) THEN
        ALTER TABLE certificates
            ADD CONSTRAINT chk_certificates_protocol_type
            CHECK (protocol_type IN ('INTERNATIONAL', 'SM_TLCP'));
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_certificates_protocol_type
    ON certificates (protocol_type)
    WHERE deleted_at IS NULL;

COMMENT ON COLUMN certificates.protocol_type IS
    '证书协议类型：INTERNATIONAL（国际通用 RSA/ECDSA/Ed25519 单证）或 SM_TLCP（国密 SM2 签名+加密双证）';
COMMENT ON COLUMN certificates.enc_certificate_reference IS
    '国密加密证书 PEM（SM_TLCP 专用；签名证书存于 certificate_reference）';
COMMENT ON COLUMN certificates.encrypted_enc_private_key_reference IS
    '国密加密私钥密文（AES-256-GCM 加密落库，绝不对外回显）';

-- b) 应用-证书绑定表增加协议槽位（同一应用可同时保有 1 个国际活动绑定 + 1 个国密活动绑定）
ALTER TABLE application_certificates
    ADD COLUMN IF NOT EXISTS cert_slot VARCHAR(32) NOT NULL DEFAULT 'INTERNATIONAL';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'application_certificates'::regclass AND conname = 'chk_app_certs_slot'
    ) THEN
        ALTER TABLE application_certificates
            ADD CONSTRAINT chk_app_certs_slot
            CHECK (cert_slot IN ('INTERNATIONAL', 'SM_TLCP'));
    END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS idx_app_certs_active_slot
    ON application_certificates (application_id, cert_slot)
    WHERE is_active = TRUE;

COMMENT ON COLUMN application_certificates.cert_slot IS
    '证书绑定槽位：INTERNATIONAL 或 SM_TLCP；同一应用每个槽位最多 1 条 is_active=TRUE 记录';

-- c) 站点级 TLS/HTTP 协议与加密会话分析配置（与 app_header_configs 同构的一对一配置表 + version 乐观锁）
CREATE TABLE IF NOT EXISTS app_tls_configs (
    application_id               UUID        PRIMARY KEY REFERENCES applications(id) ON DELETE CASCADE,
    tls_protocol_mode            VARCHAR(32) NOT NULL DEFAULT 'AUTO_DETECT'
                                             CHECK (tls_protocol_mode IN ('AUTO_DETECT', 'INTERNATIONAL_ONLY', 'GM_ONLY')),
    allowed_tls_versions         JSONB       NOT NULL DEFAULT '["TLS1.2","TLS1.3"]'::jsonb,
    legacy_ssl_analysis_versions JSONB       NOT NULL DEFAULT '["SSLv2","SSLv2_v3","SSLv3"]'::jsonb,
    http_versions                JSONB       NOT NULL DEFAULT '["HTTP/1.0","HTTP/1.1","HTTP/2"]'::jsonb,
    upstream_http_version        VARCHAR(16) NOT NULL DEFAULT 'AUTO'
                                             CHECK (upstream_http_version IN ('AUTO', 'HTTP/1.0', 'HTTP/1.1', 'HTTP/2')),
    upstream_tls_min_version     VARCHAR(16) NOT NULL DEFAULT 'TLS1.2'
                                             CHECK (upstream_tls_min_version IN ('TLS1.0', 'TLS1.1', 'TLS1.2', 'TLS1.3')),
    session_analysis_enabled     BOOLEAN     NOT NULL DEFAULT TRUE,
    updated_by                   UUID,
    created_at                   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                   TIMESTAMPTZ NOT NULL DEFAULT now(),
    version                      INTEGER     NOT NULL DEFAULT 1
);

COMMENT ON TABLE app_tls_configs IS
    '应用级 TLS/国密协议自识别、TLS/HTTP 协议降级、回源 SSL 加载与加密会话分析策略配置';

COMMIT;
