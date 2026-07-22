-- 阶段6 初始迁移：指标聚合、报告、告警、监控、备份恢复、升级、交付检查

BEGIN;

-- ---------- 指标聚合 ----------
CREATE TABLE IF NOT EXISTS metric_minute_aggregates (
    bucket_start  TIMESTAMPTZ  NOT NULL,
    metric        VARCHAR(64)  NOT NULL,
    labels        JSONB        NOT NULL DEFAULT '{}',
    value         DOUBLE PRECISION NOT NULL DEFAULT 0,
    extra         JSONB        NOT NULL DEFAULT '{}',
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    PRIMARY KEY (bucket_start, metric, labels)
);
CREATE INDEX IF NOT EXISTS idx_mma_metric_time ON metric_minute_aggregates (metric, bucket_start DESC);

CREATE TABLE IF NOT EXISTS metric_hour_aggregates (
    bucket_start  TIMESTAMPTZ  NOT NULL,
    metric        VARCHAR(64)  NOT NULL,
    labels        JSONB        NOT NULL DEFAULT '{}',
    value         DOUBLE PRECISION NOT NULL DEFAULT 0,
    extra         JSONB        NOT NULL DEFAULT '{}',
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    PRIMARY KEY (bucket_start, metric, labels)
);
CREATE INDEX IF NOT EXISTS idx_mha_metric_time ON metric_hour_aggregates (metric, bucket_start DESC);

CREATE TABLE IF NOT EXISTS metric_daily_aggregates (
    bucket_start  DATE         NOT NULL,
    metric        VARCHAR(64)  NOT NULL,
    labels        JSONB        NOT NULL DEFAULT '{}',
    value         DOUBLE PRECISION NOT NULL DEFAULT 0,
    extra         JSONB        NOT NULL DEFAULT '{}',
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    PRIMARY KEY (bucket_start, metric, labels)
);
CREATE INDEX IF NOT EXISTS idx_mda_metric_time ON metric_daily_aggregates (metric, bucket_start DESC);

CREATE TABLE IF NOT EXISTS application_security_summaries (
    bucket_start      TIMESTAMPTZ NOT NULL,
    application_id    UUID        NOT NULL,
    requests_total    BIGINT      NOT NULL DEFAULT 0,
    waf_events        BIGINT      NOT NULL DEFAULT 0,
    waf_blocks        BIGINT      NOT NULL DEFAULT 0,
    waf_observes      BIGINT      NOT NULL DEFAULT 0,
    cc_exceeded       BIGINT      NOT NULL DEFAULT 0,
    cc_rejected       BIGINT      NOT NULL DEFAULT 0,
    ip_deny_hits      BIGINT      NOT NULL DEFAULT 0,
    ip_allow_hits     BIGINT      NOT NULL DEFAULT 0,
    high_severity     BIGINT      NOT NULL DEFAULT 0,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (bucket_start, application_id)
);

CREATE TABLE IF NOT EXISTS rule_hit_summaries (
    bucket_start  TIMESTAMPTZ NOT NULL,
    rule_id       INTEGER     NOT NULL,
    attack_type   VARCHAR(40) NOT NULL DEFAULT '',
    hits          BIGINT      NOT NULL DEFAULT 0,
    false_positives BIGINT    NOT NULL DEFAULT 0,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (bucket_start, rule_id, attack_type)
);

CREATE TABLE IF NOT EXISTS source_ip_summaries (
    bucket_start  TIMESTAMPTZ NOT NULL,
    client_ip     INET        NOT NULL,
    waf_events    BIGINT      NOT NULL DEFAULT 0,
    cc_events     BIGINT      NOT NULL DEFAULT 0,
    deny_hits     BIGINT      NOT NULL DEFAULT 0,
    last_seen_at  TIMESTAMPTZ,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (bucket_start, client_ip)
);

CREATE TABLE IF NOT EXISTS uri_security_summaries (
    bucket_start     TIMESTAMPTZ NOT NULL,
    application_code VARCHAR(64) NOT NULL DEFAULT '',
    uri_path         VARCHAR(255) NOT NULL DEFAULT '',
    waf_events       BIGINT      NOT NULL DEFAULT 0,
    cc_events        BIGINT      NOT NULL DEFAULT 0,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (bucket_start, application_code, uri_path)
);

CREATE TABLE IF NOT EXISTS system_health_snapshots (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    taken_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    component    VARCHAR(40) NOT NULL,
    status       VARCHAR(20) NOT NULL,           -- UP / DOWN / DEGRADED / UNKNOWN
    latency_ms   INTEGER,
    metrics      JSONB       NOT NULL DEFAULT '{}',
    message      VARCHAR(500) NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_health_snap_comp_time ON system_health_snapshots (component, taken_at DESC);

CREATE TABLE IF NOT EXISTS aggregation_jobs (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_type     VARCHAR(20)  NOT NULL,          -- MINUTE / HOUR / DAILY
    window_start TIMESTAMPTZ  NOT NULL,
    window_end   TIMESTAMPTZ  NOT NULL,
    status       VARCHAR(20)  NOT NULL DEFAULT 'SUCCESS', -- SUCCESS / FAILED
    retry_count  INTEGER      NOT NULL DEFAULT 0,
    error        VARCHAR(500) NOT NULL DEFAULT '',
    rows_written INTEGER      NOT NULL DEFAULT 0,
    started_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    finished_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_agg_jobs_type_time ON aggregation_jobs (job_type, window_start DESC);

-- ---------- 报告 ----------
CREATE TABLE IF NOT EXISTS report_templates (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name         VARCHAR(100) NOT NULL,
    is_builtin   BOOLEAN      NOT NULL DEFAULT FALSE,
    company_name VARCHAR(200) NOT NULL DEFAULT '',
    product_name VARCHAR(200) NOT NULL DEFAULT '九章WEB应用智能防护系统',
    logo_text    VARCHAR(50)  NOT NULL DEFAULT '九章',
    header_text  VARCHAR(200) NOT NULL DEFAULT '',
    footer_text  VARCHAR(200) NOT NULL DEFAULT '',
    report_no_format VARCHAR(50) NOT NULL DEFAULT 'JZ-{YYYYMM}-{SEQ}',
    prepared_by  VARCHAR(100) NOT NULL DEFAULT '',
    reviewed_by  VARCHAR(100) NOT NULL DEFAULT '',
    description  VARCHAR(500) NOT NULL DEFAULT '',
    sections     JSONB        NOT NULL DEFAULT '{}',  -- 章节显示开关
    created_by   UUID,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_by   UUID,
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    deleted_at   TIMESTAMPTZ,
    version      INTEGER      NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS report_jobs (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_type      VARCHAR(10)  NOT NULL,      -- DAILY / WEEKLY / MONTHLY / CUSTOM / INCIDENT
    time_range_start TIMESTAMPTZ  NOT NULL,
    time_range_end   TIMESTAMPTZ  NOT NULL,
    application_ids  JSONB,
    template_id      UUID REFERENCES report_templates(id),
    status           VARCHAR(12)  NOT NULL DEFAULT 'PENDING', -- PENDING/COLLECTING/AGGREGATING/RENDERING/SUCCESS/FAILED/CANCELLED
    progress         INTEGER      NOT NULL DEFAULT 0,
    requested_by     UUID,
    requested_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    started_at       TIMESTAMPTZ,
    finished_at      TIMESTAMPTZ,
    file_reference   VARCHAR(255) NOT NULL DEFAULT '',
    file_hash        VARCHAR(64)  NOT NULL DEFAULT '',
    file_format      VARCHAR(10)  NOT NULL DEFAULT 'html',   -- html / pdf
    file_size        BIGINT       NOT NULL DEFAULT 0,
    report_no        VARCHAR(50)  NOT NULL DEFAULT '',
    failure_code     VARCHAR(50)  NOT NULL DEFAULT '',
    failure_message  VARCHAR(500) NOT NULL DEFAULT '',
    request_id       VARCHAR(64)  NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_report_jobs_status ON report_jobs (status, requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_report_jobs_type ON report_jobs (report_type, requested_at DESC);

CREATE TABLE IF NOT EXISTS report_archives (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_job_id UUID REFERENCES report_jobs(id),
    archived_by UUID,
    archived_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    note        VARCHAR(500) NOT NULL DEFAULT ''
);

-- ---------- 系统告警 ----------
CREATE TABLE IF NOT EXISTS system_alerts (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_type   VARCHAR(50)  NOT NULL,
    severity     VARCHAR(10)  NOT NULL,          -- CRITICAL / HIGH / MEDIUM / LOW / INFO
    component    VARCHAR(40)  NOT NULL DEFAULT '',
    title        VARCHAR(200) NOT NULL,
    message      VARCHAR(1000) NOT NULL DEFAULT '',
    status       VARCHAR(15)  NOT NULL DEFAULT 'OPEN', -- OPEN / ACKNOWLEDGED / RESOLVED / IGNORED
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ  NOT NULL DEFAULT now(),
    occurrence_count INTEGER  NOT NULL DEFAULT 1,
    acknowledged_by UUID,
    acknowledged_at TIMESTAMPTZ,
    resolved_by  UUID,
    resolved_at  TIMESTAMPTZ,
    resolve_type VARCHAR(20),                    -- AUTO / MANUAL / RECOVERED
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_system_alerts_status ON system_alerts (status, severity, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_system_alerts_dedup ON system_alerts (alert_type, component, status);

CREATE TABLE IF NOT EXISTS system_alert_notes (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id   UUID NOT NULL REFERENCES system_alerts(id),
    note       VARCHAR(1000) NOT NULL,
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_alert_notes_alert ON system_alert_notes (alert_id);

-- ---------- 备份与恢复 ----------
CREATE TABLE IF NOT EXISTS backup_jobs (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    backup_type  VARCHAR(20)  NOT NULL,          -- FULL / CONFIG_ONLY / DATABASE_ONLY / CERTIFICATE_ONLY
    status       VARCHAR(12)  NOT NULL DEFAULT 'PENDING', -- PENDING/RUNNING/VERIFYING/SUCCESS/FAILED/CANCELLED
    include_logs BOOLEAN      NOT NULL DEFAULT FALSE,
    file_reference VARCHAR(255) NOT NULL DEFAULT '',
    file_size    BIGINT       NOT NULL DEFAULT 0,
    file_hash    VARCHAR(64)  NOT NULL DEFAULT '',
    manifest     JSONB        NOT NULL DEFAULT '{}',
    requested_by UUID,
    requested_at TIMESTAMPTZ  NOT NULL DEFAULT now(),
    started_at   TIMESTAMPTZ,
    finished_at  TIMESTAMPTZ,
    verified     BOOLEAN      NOT NULL DEFAULT FALSE,
    verified_at  TIMESTAMPTZ,
    failure_code VARCHAR(50)  NOT NULL DEFAULT '',
    failure_message VARCHAR(500) NOT NULL DEFAULT '',
    request_id   VARCHAR(64)  NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS backup_files (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    backup_job_id UUID REFERENCES backup_jobs(id),
    file_path   VARCHAR(255) NOT NULL,
    file_size   BIGINT       NOT NULL DEFAULT 0,
    file_hash   VARCHAR(64)  NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS restore_jobs (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    backup_job_id  UUID REFERENCES backup_jobs(id),
    restore_scope  VARCHAR(20) NOT NULL,         -- FULL / CONFIG / DATABASE / CERTIFICATE / CONFIG_VERSION
    status         VARCHAR(20) NOT NULL DEFAULT 'PENDING', -- PENDING/VALIDATING/ISOLATED_RESTORE/VERIFYING/AWAITING_CONFIRM/RESTORING/SUCCESS/FAILED/CANCELLED
    preview        JSONB       NOT NULL DEFAULT '{}',
    confirmed_by   UUID,
    confirmed_at   TIMESTAMPTZ,
    requested_by   UUID,
    requested_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    started_at     TIMESTAMPTZ,
    finished_at    TIMESTAMPTZ,
    failure_code   VARCHAR(50)  NOT NULL DEFAULT '',
    failure_message VARCHAR(500) NOT NULL DEFAULT '',
    request_id     VARCHAR(64)  NOT NULL DEFAULT ''
);

-- ---------- 升级 ----------
CREATE TABLE IF NOT EXISTS upgrade_packages (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    file_name    VARCHAR(255) NOT NULL,
    version_from VARCHAR(50)  NOT NULL DEFAULT '',
    version_to   VARCHAR(50)  NOT NULL DEFAULT '',
    file_hash    VARCHAR(64)  NOT NULL,
    file_size    BIGINT       NOT NULL DEFAULT 0,
    manifest     JSONB        NOT NULL DEFAULT '{}',
    status       VARCHAR(15)  NOT NULL DEFAULT 'REGISTERED', -- REGISTERED / VERIFIED / REJECTED
    uploaded_by  UUID,
    uploaded_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS upgrade_jobs (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    package_id     UUID REFERENCES upgrade_packages(id),
    status         VARCHAR(15) NOT NULL DEFAULT 'PENDING', -- PENDING/PRECHECK/BACKUP/APPLYING/MIGRATING/VERIFYING/SUCCESS/FAILED/ROLLING_BACK/ROLLED_BACK
    precheck       JSONB       NOT NULL DEFAULT '{}',
    backup_job_id  UUID,
    requested_by   UUID,
    requested_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    started_at     TIMESTAMPTZ,
    finished_at    TIMESTAMPTZ,
    failure_code   VARCHAR(50)  NOT NULL DEFAULT '',
    failure_message VARCHAR(500) NOT NULL DEFAULT '',
    request_id     VARCHAR(64)  NOT NULL DEFAULT ''
);

-- ---------- 交付检查 ----------
CREATE TABLE IF NOT EXISTS delivery_checks (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    overall_result VARCHAR(10) NOT NULL DEFAULT 'PENDING', -- PASS / WARNING / FAIL
    total        INTEGER NOT NULL DEFAULT 0,
    pass_count   INTEGER NOT NULL DEFAULT 0,
    warning_count INTEGER NOT NULL DEFAULT 0,
    fail_count   INTEGER NOT NULL DEFAULT 0,
    requested_by UUID,
    started_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at  TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS delivery_check_results (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    check_id    UUID NOT NULL REFERENCES delivery_checks(id) ON DELETE CASCADE,
    item_key    VARCHAR(64) NOT NULL,
    item_name   VARCHAR(200) NOT NULL,
    category    VARCHAR(40) NOT NULL DEFAULT '',
    result      VARCHAR(10) NOT NULL,           -- PASS / WARNING / FAIL / NOT_APPLICABLE
    critical    BOOLEAN     NOT NULL DEFAULT FALSE,
    message     VARCHAR(500) NOT NULL DEFAULT '',
    details     JSONB       NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_delivery_results_check ON delivery_check_results (check_id);

COMMIT;
