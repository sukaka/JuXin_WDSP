-- 阶段3 初始迁移：Web应用、域名、源站、证书、配置版本、发布任务
-- 在阶段2基础上新增应用接入与配置发布相关表

BEGIN;

-- ---------- Web应用 ----------
CREATE TABLE IF NOT EXISTS applications (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code               VARCHAR(64)  NOT NULL,
    name               VARCHAR(128) NOT NULL,
    description        TEXT         NOT NULL DEFAULT '',
    business_owner     VARCHAR(128) NOT NULL DEFAULT '',
    technical_owner    VARCHAR(128) NOT NULL DEFAULT '',
    status             VARCHAR(32)  NOT NULL DEFAULT 'DRAFT',
    protection_mode    VARCHAR(32)  NOT NULL DEFAULT 'OBSERVE',
    deployment_status  VARCHAR(32)  NOT NULL DEFAULT 'NOT_PUBLISHED',
    health_status      VARCHAR(32)  NOT NULL DEFAULT 'UNKNOWN',
    current_version_id UUID,
    last_publish_at    TIMESTAMPTZ,
    last_publish_result VARCHAR(32) NOT NULL DEFAULT '',
    created_by         UUID,
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_by         UUID,
    updated_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
    deleted_at         TIMESTAMPTZ,
    version            INTEGER      NOT NULL DEFAULT 1
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_applications_code ON applications (code) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_applications_status ON applications (status);

-- ---------- 应用域名 ----------
CREATE TABLE IF NOT EXISTS application_domains (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id        UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    hostname              VARCHAR(255) NOT NULL,
    normalized_hostname   VARCHAR(255) NOT NULL,
    domain_type           VARCHAR(32)  NOT NULL DEFAULT 'EXACT',
    is_primary            BOOLEAN      NOT NULL DEFAULT FALSE,
    http_enabled          BOOLEAN      NOT NULL DEFAULT TRUE,
    https_enabled         BOOLEAN      NOT NULL DEFAULT FALSE,
    http_port             INTEGER,
    https_port            INTEGER,
    redirect_http_to_https BOOLEAN     NOT NULL DEFAULT FALSE,
    status                VARCHAR(32)  NOT NULL DEFAULT 'ACTIVE',
    created_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_app_domains_app ON application_domains (application_id);
CREATE INDEX IF NOT EXISTS idx_app_domains_host ON application_domains (normalized_hostname);

-- ---------- 源站 ----------
CREATE TABLE IF NOT EXISTS upstreams (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id              UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    name                        VARCHAR(128) NOT NULL,
    scheme                      VARCHAR(16)  NOT NULL DEFAULT 'http',
    host                        VARCHAR(255) NOT NULL,
    normalized_host             VARCHAR(255) NOT NULL,
    port                        INTEGER      NOT NULL,
    weight                      INTEGER      NOT NULL DEFAULT 10,
    priority                    INTEGER      NOT NULL DEFAULT 0,
    status                      VARCHAR(32)  NOT NULL DEFAULT 'ACTIVE',
    health_check_enabled        BOOLEAN      NOT NULL DEFAULT TRUE,
    health_check_path           VARCHAR(255) NOT NULL DEFAULT '/health',
    health_check_method         VARCHAR(16)  NOT NULL DEFAULT 'GET',
    health_check_interval_seconds INTEGER    NOT NULL DEFAULT 30,
    health_check_timeout_seconds  INTEGER    NOT NULL DEFAULT 5,
    expected_status_codes       VARCHAR(64)  NOT NULL DEFAULT '200',
    connect_timeout_ms          INTEGER      NOT NULL DEFAULT 3000,
    response_header_timeout_ms  INTEGER      NOT NULL DEFAULT 10000,
    tls_server_name             VARCHAR(255) NOT NULL DEFAULT '',
    tls_verify                  BOOLEAN      NOT NULL DEFAULT TRUE,
    max_retries                 INTEGER      NOT NULL DEFAULT 1,
    created_by                  UUID,
    created_at                  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_by                  UUID,
    updated_at                  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    deleted_at                  TIMESTAMPTZ,
    version                     INTEGER      NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_upstreams_app ON upstreams (application_id);

-- ---------- 源站健康记录 ----------
CREATE TABLE IF NOT EXISTS upstream_health_records (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    upstream_id          UUID NOT NULL REFERENCES upstreams(id) ON DELETE CASCADE,
    checked_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    status               VARCHAR(32) NOT NULL,
    response_status      INTEGER,
    response_time_ms     INTEGER,
    error_code           VARCHAR(64) NOT NULL DEFAULT '',
    error_message        VARCHAR(512) NOT NULL DEFAULT '',
    consecutive_successes INTEGER     NOT NULL DEFAULT 0,
    consecutive_failures INTEGER      NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_upstream_health_upstream ON upstream_health_records (upstream_id, checked_at DESC);

-- ---------- HTTPS证书 ----------
CREATE TABLE IF NOT EXISTS certificates (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                        VARCHAR(128) NOT NULL,
    certificate_type            VARCHAR(32)  NOT NULL DEFAULT 'SERVER',
    common_name                 VARCHAR(255) NOT NULL DEFAULT '',
    subject                     VARCHAR(512) NOT NULL DEFAULT '',
    issuer                      VARCHAR(512) NOT NULL DEFAULT '',
    serial_number               VARCHAR(128) NOT NULL DEFAULT '',
    not_before                  TIMESTAMPTZ,
    not_after                   TIMESTAMPTZ,
    fingerprint_sha256          VARCHAR(128) NOT NULL DEFAULT '',
    public_key_algorithm        VARCHAR(64)  NOT NULL DEFAULT '',
    public_key_bits             INTEGER      NOT NULL DEFAULT 0,
    signature_algorithm         VARCHAR(64)  NOT NULL DEFAULT '',
    san_domains                 JSONB        NOT NULL DEFAULT '[]',
    status                      VARCHAR(32)  NOT NULL DEFAULT 'VALID',
    certificate_reference       TEXT         NOT NULL,
    encrypted_private_key_reference TEXT     NOT NULL,
    chain_reference             TEXT         NOT NULL DEFAULT '',
    created_by                  UUID,
    created_at                  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_by                  UUID,
    updated_at                  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    deleted_at                  TIMESTAMPTZ,
    version                     INTEGER      NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_certificates_not_after ON certificates (not_after);
CREATE INDEX IF NOT EXISTS idx_certificates_fingerprint ON certificates (fingerprint_sha256);

-- ---------- 应用-证书绑定 ----------
CREATE TABLE IF NOT EXISTS application_certificates (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    certificate_id UUID NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
    is_active      BOOLEAN NOT NULL DEFAULT TRUE,
    created_by     UUID,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (application_id, certificate_id)
);
CREATE INDEX IF NOT EXISTS idx_app_certs_app ON application_certificates (application_id);
CREATE INDEX IF NOT EXISTS idx_app_certs_cert ON application_certificates (certificate_id);

-- ---------- 网关配置版本 ----------
CREATE TABLE IF NOT EXISTS gateway_config_versions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version_number      VARCHAR(64)  NOT NULL UNIQUE,
    configuration_json  TEXT         NOT NULL,
    configuration_hash  VARCHAR(128) NOT NULL,
    business_snapshot   JSONB        NOT NULL DEFAULT '{}',
    change_summary      TEXT         NOT NULL DEFAULT '',
    previous_version_id UUID,
    publish_task_id     UUID,
    publish_result      VARCHAR(32)  NOT NULL DEFAULT '',
    validation_result   VARCHAR(32)  NOT NULL DEFAULT '',
    is_current          BOOLEAN      NOT NULL DEFAULT FALSE,
    created_by          UUID,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    published_by        UUID,
    published_at        TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_config_versions_current ON gateway_config_versions (is_current);
CREATE INDEX IF NOT EXISTS idx_config_versions_created ON gateway_config_versions (created_at DESC);

-- ---------- 配置发布任务 ----------
CREATE TABLE IF NOT EXISTS gateway_publish_tasks (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    task_type           VARCHAR(32)  NOT NULL DEFAULT 'PUBLISH',
    status              VARCHAR(32)  NOT NULL DEFAULT 'PENDING',
    requested_by        UUID,
    requested_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
    started_at          TIMESTAMPTZ,
    finished_at         TIMESTAMPTZ,
    target_version_id   UUID,
    previous_version_id UUID,
    current_step        VARCHAR(64)  NOT NULL DEFAULT '',
    progress            INTEGER      NOT NULL DEFAULT 0,
    result_summary      TEXT         NOT NULL DEFAULT '',
    failure_code        VARCHAR(64)  NOT NULL DEFAULT '',
    failure_message     TEXT         NOT NULL DEFAULT '',
    idempotency_key     VARCHAR(128) NOT NULL DEFAULT '',
    request_id          VARCHAR(64)  NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_publish_tasks_status ON gateway_publish_tasks (status);
CREATE INDEX IF NOT EXISTS idx_publish_tasks_requested ON gateway_publish_tasks (requested_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_publish_tasks_idempotency ON gateway_publish_tasks (idempotency_key) WHERE idempotency_key <> '';

-- ---------- 发布校验结果 ----------
CREATE TABLE IF NOT EXISTS gateway_validation_results (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    publish_task_id UUID NOT NULL REFERENCES gateway_publish_tasks(id) ON DELETE CASCADE,
    validation_type VARCHAR(64) NOT NULL,
    validation_step VARCHAR(64) NOT NULL,
    result          VARCHAR(32) NOT NULL,
    error_code      VARCHAR(64) NOT NULL DEFAULT '',
    message         TEXT        NOT NULL DEFAULT '',
    details_summary TEXT        NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_validation_results_task ON gateway_validation_results (publish_task_id);

COMMIT;
