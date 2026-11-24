-- 000238 自动申请 SSL 证书与到期自动续约（Auto-SSL / ACME v2）：
--   a) acme_config：全局 ACME 配置单行表（CA 提供商、目录 URL、SSRF 允许列表、邮箱、EAB 加密凭据、续约天数、自动发布开关）
--   b) acme_accounts：按 (directory_url, email) 唯一持久化的 ACME 账户及加密私钥
--   c) certificates：新增 ACME 托管元数据与不可变续签替换链列（managed_by / auto_renew / replaces_certificate_id / superseded_by 等）
--   d) applications：新增站点级自动 SSL 开关、验证方式、续约提前天数覆写及运行态退避状态列
--   e) acme_cert_orders：ACME 首次签发/到期续约/域名同步/手工触发订单台账
BEGIN;

-- a) 全局 ACME 配置（单行，由 certificates.update 权限管理，符合三权分立）
CREATE TABLE IF NOT EXISTS acme_config (
    id                         SMALLINT    PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    enabled                    BOOLEAN     NOT NULL DEFAULT FALSE,
    provider                   VARCHAR(32) NOT NULL DEFAULT 'LETSENCRYPT',
    directory_url              TEXT        NOT NULL DEFAULT '',
    custom_directory_allowlist TEXT        NOT NULL DEFAULT '',
    email                      VARCHAR(255) NOT NULL DEFAULT '',
    tos_agreed                 BOOLEAN     NOT NULL DEFAULT FALSE,
    eab_kid                    VARCHAR(255) NOT NULL DEFAULT '',
    encrypted_eab_hmac_key     TEXT        NOT NULL DEFAULT '',
    key_type                   VARCHAR(16) NOT NULL DEFAULT 'EC256',
    renew_before_days          INTEGER     NOT NULL DEFAULT 30 CHECK (renew_before_days BETWEEN 7 AND 60),
    auto_publish               BOOLEAN     NOT NULL DEFAULT TRUE,
    updated_by                 UUID,
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    version                    INTEGER     NOT NULL DEFAULT 1
);

INSERT INTO acme_config (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

COMMENT ON TABLE acme_config IS
    '全局 ACME 自动 SSL 证书配置（单行表）；敏感 EAB HMAC 密钥经 AES-256-GCM 加密落库，永不回显明文';

-- b) ACME 账户台账（私钥加密存储）
CREATE TABLE IF NOT EXISTS acme_accounts (
    id                    UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    provider              VARCHAR(32)  NOT NULL,
    directory_url         TEXT         NOT NULL,
    email                 VARCHAR(255) NOT NULL,
    account_uri           TEXT         NOT NULL DEFAULT '',
    encrypted_private_key TEXT         NOT NULL,
    eab_kid               VARCHAR(255) NOT NULL DEFAULT '',
    status                VARCHAR(32)  NOT NULL DEFAULT 'ACTIVE',
    created_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (directory_url, email)
);

COMMENT ON TABLE acme_accounts IS
    'ACME v2 已注册账户（私钥经 AES-256-GCM 加密存储）';

-- c) certificates 表扩展 ACME 托管与不可变续签链字段
ALTER TABLE certificates
    ADD COLUMN IF NOT EXISTS managed_by              VARCHAR(32) NOT NULL DEFAULT 'MANUAL',
    ADD COLUMN IF NOT EXISTS acme_provider           VARCHAR(32) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS acme_directory_url      TEXT        NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS acme_account_id         UUID        REFERENCES acme_accounts(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS auto_renew              BOOLEAN     NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS renew_before_days       INTEGER     NOT NULL DEFAULT 30,
    ADD COLUMN IF NOT EXISTS replaces_certificate_id UUID        REFERENCES certificates(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS superseded_by           UUID        REFERENCES certificates(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS last_renewed_at         TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_certificates_managed_auto_renew
    ON certificates (managed_by, auto_renew, not_after)
    WHERE deleted_at IS NULL;

COMMENT ON COLUMN certificates.managed_by IS
    '证书管理方式：MANUAL（手动上传）或 ACME（自动申请/续约）';
COMMENT ON COLUMN certificates.superseded_by IS
    '续签替换后的新证书 ID；旧证书标记 status=REPLACED 但保留密文私钥以支持历史版本回滚';

-- d) applications 表扩展站点级自动 SSL 配置与重试退避状态
ALTER TABLE applications
    ADD COLUMN IF NOT EXISTS auto_ssl_enabled           BOOLEAN     NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS auto_ssl_challenge_type    VARCHAR(16) NOT NULL DEFAULT 'HTTP01',
    ADD COLUMN IF NOT EXISTS auto_ssl_renew_before_days INTEGER     CHECK (auto_ssl_renew_before_days IS NULL OR (auto_ssl_renew_before_days BETWEEN 7 AND 60)),
    ADD COLUMN IF NOT EXISTS auto_ssl_last_status       VARCHAR(32) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS auto_ssl_last_error        TEXT        NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS auto_ssl_fail_count        INTEGER     NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS auto_ssl_next_retry_at     TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS auto_ssl_last_attempt_at   TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_applications_auto_ssl
    ON applications (auto_ssl_enabled, status)
    WHERE deleted_at IS NULL;

COMMENT ON COLUMN applications.auto_ssl_enabled IS
    '站点级自动 SSL 开关：开启后无证书自动申请、到期前自动续约';

-- e) ACME 证书申请与续约订单记录
CREATE TABLE IF NOT EXISTS acme_cert_orders (
    id                      UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id          UUID         NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    trigger_type            VARCHAR(32)  NOT NULL,
    provider                VARCHAR(32)  NOT NULL,
    directory_url           TEXT         NOT NULL,
    challenge_type          VARCHAR(16)  NOT NULL DEFAULT 'HTTP01',
    domains                 JSONB        NOT NULL DEFAULT '[]',
    status                  VARCHAR(32)  NOT NULL DEFAULT 'PENDING',
    certificate_id          UUID         REFERENCES certificates(id) ON DELETE SET NULL,
    previous_certificate_id UUID         REFERENCES certificates(id) ON DELETE SET NULL,
    publish_task_id         UUID,
    error_code              VARCHAR(64)  NOT NULL DEFAULT '',
    error_message           TEXT         NOT NULL DEFAULT '',
    requested_by            UUID,
    request_id              VARCHAR(128) NOT NULL DEFAULT '',
    started_at              TIMESTAMPTZ,
    finished_at             TIMESTAMPTZ,
    created_at              TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_acme_orders_app_created
    ON acme_cert_orders (application_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_acme_orders_status
    ON acme_cert_orders (status);
CREATE INDEX IF NOT EXISTS idx_acme_orders_created
    ON acme_cert_orders (created_at DESC);

COMMENT ON TABLE acme_cert_orders IS
    'ACME 自动申请与到期续约任务订单台账（AUTO_INIT / AUTO_RENEW / AUTO_DOMAIN_SYNC / MANUAL_ISSUE / MANUAL_RENEW）';

COMMIT;
