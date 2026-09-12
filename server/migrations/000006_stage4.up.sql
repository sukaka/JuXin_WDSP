-- 阶段4 初始迁移：防护策略、规则、例外、安全事件、策略版本
-- 在阶段3基础上新增 WAF 策略与安全事件中心相关表

BEGIN;

-- ---------- 防护策略 ----------
CREATE TABLE IF NOT EXISTS protection_policies (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code                        VARCHAR(64)  NOT NULL,
    name                        VARCHAR(128) NOT NULL,
    description                 TEXT         NOT NULL DEFAULT '',
    is_builtin                  BOOLEAN      NOT NULL DEFAULT FALSE,
    status                      VARCHAR(32)  NOT NULL DEFAULT 'ACTIVE',
    protection_mode             VARCHAR(32)  NOT NULL DEFAULT 'OBSERVE',
    paranoia_level              INTEGER      NOT NULL DEFAULT 1,
    inbound_anomaly_threshold   INTEGER      NOT NULL DEFAULT 5,
    outbound_anomaly_threshold  INTEGER      NOT NULL DEFAULT 4,
    request_body_access         BOOLEAN      NOT NULL DEFAULT TRUE,
    response_body_access        BOOLEAN      NOT NULL DEFAULT FALSE,
    request_body_limit          BIGINT       NOT NULL DEFAULT 13107200,
    request_body_no_files_limit BIGINT       NOT NULL DEFAULT 131072,
    response_body_limit         BIGINT       NOT NULL DEFAULT 524288,
    upload_file_limit           BIGINT       NOT NULL DEFAULT 13107200,
    json_parser_enabled         BOOLEAN      NOT NULL DEFAULT TRUE,
    xml_parser_enabled          BOOLEAN      NOT NULL DEFAULT TRUE,
    multipart_parser_enabled    BOOLEAN      NOT NULL DEFAULT TRUE,
    audit_log_enabled           BOOLEAN      NOT NULL DEFAULT TRUE,
    audit_log_relevant_status   VARCHAR(64)  NOT NULL DEFAULT '^(?:(5|4)(0|1)[0-9])$',
    audit_log_parts             VARCHAR(32)  NOT NULL DEFAULT 'ABIJDEFHZ',
    blocking_status_code        INTEGER      NOT NULL DEFAULT 403,
    blocking_page_id            VARCHAR(64)  NOT NULL DEFAULT 'default',
    created_by                  UUID,
    created_at                  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_by                  UUID,
    updated_at                  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    deleted_at                  TIMESTAMPTZ,
    version                     INTEGER      NOT NULL DEFAULT 1
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_protection_policies_code ON protection_policies (code) WHERE deleted_at IS NULL;

-- ---------- 应用-策略绑定 ----------
CREATE TABLE IF NOT EXISTS application_policies (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    policy_id      UUID NOT NULL REFERENCES protection_policies(id) ON DELETE CASCADE,
    is_active      BOOLEAN NOT NULL DEFAULT TRUE,
    created_by     UUID,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (application_id, policy_id)
);
CREATE INDEX IF NOT EXISTS idx_app_policies_app ON application_policies (application_id);
CREATE INDEX IF NOT EXISTS idx_app_policies_policy ON application_policies (policy_id);

-- ---------- WAF 规则元数据（CRS 同步） ----------
CREATE TABLE IF NOT EXISTS waf_rules (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id       INTEGER      NOT NULL,
    rule_source   VARCHAR(32)  NOT NULL DEFAULT 'OWASP_CRS',
    file_name     VARCHAR(255) NOT NULL DEFAULT '',
    name          VARCHAR(512) NOT NULL DEFAULT '',
    message       TEXT         NOT NULL DEFAULT '',
    severity      VARCHAR(32)  NOT NULL DEFAULT 'NOTICE',
    phase         INTEGER      NOT NULL DEFAULT 2,
    tags          JSONB        NOT NULL DEFAULT '[]',
    attack_type   VARCHAR(64)  NOT NULL DEFAULT 'OTHER',
    default_state VARCHAR(32)  NOT NULL DEFAULT 'ENABLED',
    crs_version   VARCHAR(32)  NOT NULL DEFAULT '',
    content_hash  VARCHAR(128) NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (rule_id, rule_source, crs_version)
);
CREATE INDEX IF NOT EXISTS idx_waf_rules_rule_id ON waf_rules (rule_id);
CREATE INDEX IF NOT EXISTS idx_waf_rules_attack_type ON waf_rules (attack_type);
CREATE INDEX IF NOT EXISTS idx_waf_rules_severity ON waf_rules (severity);

-- ---------- 规则覆盖 ----------
CREATE TABLE IF NOT EXISTS rule_overrides (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id        INTEGER      NOT NULL,
    scope_type     VARCHAR(32)  NOT NULL DEFAULT 'POLICY',  -- GLOBAL / POLICY / APPLICATION
    scope_id       UUID,                                    -- policy_id 或 application_id
    action         VARCHAR(32)  NOT NULL DEFAULT 'DISABLE', -- ENABLE / DISABLE / SEVERITY_OVERRIDE / ACTION_OVERRIDE
    severity_override VARCHAR(32) NOT NULL DEFAULT '',
    effective_from TIMESTAMPTZ,
    effective_until TIMESTAMPTZ,
    reason         TEXT         NOT NULL DEFAULT '',
    created_by     UUID,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_by     UUID,
    updated_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    version        INTEGER      NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_rule_overrides_rule ON rule_overrides (rule_id);
CREATE INDEX IF NOT EXISTS idx_rule_overrides_scope ON rule_overrides (scope_type, scope_id);

-- ---------- 自定义规则 ----------
CREATE TABLE IF NOT EXISTS custom_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id         INTEGER      NOT NULL UNIQUE,
    name            VARCHAR(128) NOT NULL,
    description     TEXT         NOT NULL DEFAULT '',
    attack_type     VARCHAR(64)  NOT NULL DEFAULT 'OTHER',
    severity        VARCHAR(32)  NOT NULL DEFAULT 'WARNING',
    phase           INTEGER      NOT NULL DEFAULT 2,
    operator        VARCHAR(64)  NOT NULL DEFAULT 'rx',
    operator_value  TEXT         NOT NULL DEFAULT '',
    target_variables JSONB       NOT NULL DEFAULT '[]',
    action          VARCHAR(32)  NOT NULL DEFAULT 'LOG',
    tags            JSONB        NOT NULL DEFAULT '[]',
    status          VARCHAR(32)  NOT NULL DEFAULT 'ENABLED',
    scope_type      VARCHAR(32)  NOT NULL DEFAULT 'GLOBAL',
    scope_ids       JSONB        NOT NULL DEFAULT '[]',
    effective_from  TIMESTAMPTZ,
    effective_until TIMESTAMPTZ,
    generated_rule  TEXT         NOT NULL DEFAULT '',
    created_by      UUID,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_by      UUID,
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    version         INTEGER      NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_custom_rules_rule_id ON custom_rules (rule_id);
CREATE INDEX IF NOT EXISTS idx_custom_rules_status ON custom_rules (status);

-- ---------- 例外策略 ----------
CREATE TABLE IF NOT EXISTS exception_policies (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name             VARCHAR(128) NOT NULL,
    description      TEXT         NOT NULL DEFAULT '',
    scope_type       VARCHAR(32)  NOT NULL DEFAULT 'APPLICATION',
    application_id   UUID,
    policy_id        UUID,
    domain           VARCHAR(255) NOT NULL DEFAULT '',
    uri_exact        VARCHAR(512) NOT NULL DEFAULT '',
    uri_prefix       VARCHAR(512) NOT NULL DEFAULT '',
    uri_regex        TEXT         NOT NULL DEFAULT '',
    methods          JSONB        NOT NULL DEFAULT '[]',
    source_ips       JSONB        NOT NULL DEFAULT '[]',
    param_names      JSONB        NOT NULL DEFAULT '[]',
    cookie_names     JSONB        NOT NULL DEFAULT '[]',
    header_names     JSONB        NOT NULL DEFAULT '[]',
    rule_ids         JSONB        NOT NULL DEFAULT '[]',
    rule_tags        JSONB        NOT NULL DEFAULT '[]',
    attack_types     JSONB        NOT NULL DEFAULT '[]',
    content_types    JSONB        NOT NULL DEFAULT '[]',
    exception_action VARCHAR(32)  NOT NULL DEFAULT 'REMOVE_RULE',
    action_target    VARCHAR(255) NOT NULL DEFAULT '',
    is_temporary     BOOLEAN      NOT NULL DEFAULT FALSE,
    effective_from   TIMESTAMPTZ,
    effective_until  TIMESTAMPTZ,
    status           VARCHAR(32)  NOT NULL DEFAULT 'ENABLED',
    risk_acknowledged BOOLEAN     NOT NULL DEFAULT FALSE,
    reason           TEXT         NOT NULL DEFAULT '',
    created_by       UUID,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_by       UUID,
    updated_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    deleted_at       TIMESTAMPTZ,
    version          INTEGER      NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_exception_policies_app ON exception_policies (application_id);
CREATE INDEX IF NOT EXISTS idx_exception_policies_status ON exception_policies (status);

-- ---------- 安全事件（按月分区） ----------
CREATE TABLE IF NOT EXISTS security_events (
    id                        UUID NOT NULL DEFAULT gen_random_uuid(),
    request_id                VARCHAR(64)  NOT NULL,
    occurred_at               TIMESTAMPTZ  NOT NULL,
    application_id            UUID,
    application_name_snapshot VARCHAR(128) NOT NULL DEFAULT '',
    domain                    VARCHAR(255) NOT NULL DEFAULT '',
    gateway_node_id           VARCHAR(64)  NOT NULL DEFAULT '',
    client_ip                 INET,
    connection_ip             INET,
    client_port               INTEGER,
    request_method            VARCHAR(16)  NOT NULL DEFAULT '',
    request_uri               TEXT         NOT NULL DEFAULT '',
    request_path              TEXT         NOT NULL DEFAULT '',
    query_summary             TEXT         NOT NULL DEFAULT '',
    http_version              VARCHAR(16)  NOT NULL DEFAULT '',
    content_type              VARCHAR(255) NOT NULL DEFAULT '',
    user_agent_summary        VARCHAR(512) NOT NULL DEFAULT '',
    referer_summary           VARCHAR(512) NOT NULL DEFAULT '',
    event_source              VARCHAR(32)  NOT NULL DEFAULT 'coraza',
    attack_type               VARCHAR(64)  NOT NULL DEFAULT 'OTHER',
    severity                  VARCHAR(32)  NOT NULL DEFAULT 'INFO',
    anomaly_score             INTEGER      NOT NULL DEFAULT 0,
    action                    VARCHAR(32)  NOT NULL DEFAULT 'OBSERVE',
    response_status           INTEGER,
    rule_match_count          INTEGER      NOT NULL DEFAULT 0,
    disposition_status        VARCHAR(32)  NOT NULL DEFAULT 'UNPROCESSED',
    disposition_user_id       UUID,
    disposition_at            TIMESTAMPTZ,
    disposition_result        VARCHAR(64)  NOT NULL DEFAULT '',
    raw_log_reference         TEXT         NOT NULL DEFAULT '',
    created_at                TIMESTAMPTZ  NOT NULL DEFAULT now(),
    PRIMARY KEY (id, occurred_at)
) PARTITION BY RANGE (occurred_at);

CREATE INDEX IF NOT EXISTS idx_security_events_time ON security_events (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_app ON security_events (application_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_client_ip ON security_events (client_ip);
CREATE INDEX IF NOT EXISTS idx_security_events_attack_type ON security_events (attack_type);
CREATE INDEX IF NOT EXISTS idx_security_events_severity ON security_events (severity);
CREATE INDEX IF NOT EXISTS idx_security_events_action ON security_events (action);
CREATE INDEX IF NOT EXISTS idx_security_events_disposition ON security_events (disposition_status);
CREATE INDEX IF NOT EXISTS idx_security_events_request_id ON security_events (request_id);

-- 初始分区（当前月 + 下月）
CREATE TABLE IF NOT EXISTS security_events_default PARTITION OF security_events DEFAULT;

-- ---------- 事件规则匹配 ----------
CREATE TABLE IF NOT EXISTS security_event_matches (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id            UUID         NOT NULL,
    event_occurred_at   TIMESTAMPTZ  NOT NULL,
    rule_id             INTEGER      NOT NULL,
    rule_name           VARCHAR(512) NOT NULL DEFAULT '',
    rule_source         VARCHAR(32)  NOT NULL DEFAULT 'OWASP_CRS',
    rule_version        VARCHAR(32)  NOT NULL DEFAULT '',
    severity            VARCHAR(32)  NOT NULL DEFAULT 'NOTICE',
    message             TEXT         NOT NULL DEFAULT '',
    matched_variable    VARCHAR(255) NOT NULL DEFAULT '',
    matched_data_masked TEXT         NOT NULL DEFAULT '',
    tags                JSONB        NOT NULL DEFAULT '[]',
    phase               INTEGER      NOT NULL DEFAULT 2,
    anomaly_score       INTEGER      NOT NULL DEFAULT 0,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_event_matches_event ON security_event_matches (event_id);
CREATE INDEX IF NOT EXISTS idx_event_matches_rule ON security_event_matches (rule_id);

-- ---------- 事件备注 ----------
CREATE TABLE IF NOT EXISTS security_event_notes (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id   UUID NOT NULL,
    user_id    UUID,
    username   VARCHAR(64) NOT NULL DEFAULT '',
    note       TEXT        NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_event_notes_event ON security_event_notes (event_id);

-- ---------- 事件处置记录 ----------
CREATE TABLE IF NOT EXISTS security_event_actions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id        UUID NOT NULL,
    action_type     VARCHAR(64) NOT NULL,
    operator_id     UUID,
    operator_name   VARCHAR(64) NOT NULL DEFAULT '',
    detail          TEXT        NOT NULL DEFAULT '',
    related_ref_id  VARCHAR(64) NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_event_actions_event ON security_event_actions (event_id);

-- ---------- 策略版本 ----------
CREATE TABLE IF NOT EXISTS policy_versions (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version_number    VARCHAR(64)  NOT NULL UNIQUE,
    policy_id         UUID         NOT NULL REFERENCES protection_policies(id) ON DELETE CASCADE,
    configuration_snapshot JSONB   NOT NULL DEFAULT '{}',
    configuration_hash VARCHAR(128) NOT NULL DEFAULT '',
    change_summary    TEXT         NOT NULL DEFAULT '',
    previous_version_id UUID,
    publish_task_id   UUID,
    publish_result    VARCHAR(32)  NOT NULL DEFAULT '',
    is_current        BOOLEAN      NOT NULL DEFAULT FALSE,
    created_by        UUID,
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
    published_by      UUID,
    published_at      TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_policy_versions_policy ON policy_versions (policy_id, is_current);

-- ---------- 事件采集检查点 ----------
CREATE TABLE IF NOT EXISTS event_collector_checkpoints (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    collector_id  VARCHAR(64)  NOT NULL UNIQUE,
    file_path     TEXT         NOT NULL DEFAULT '',
    file_offset   BIGINT       NOT NULL DEFAULT 0,
    file_inode    BIGINT       NOT NULL DEFAULT 0,
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- ---------- 事件解析失败队列 ----------
CREATE TABLE IF NOT EXISTS event_parse_failures (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    collector_id VARCHAR(64) NOT NULL DEFAULT '',
    raw_line     TEXT        NOT NULL DEFAULT '',
    error_reason TEXT        NOT NULL DEFAULT '',
    occurred_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    retry_count  INTEGER     NOT NULL DEFAULT 0,
    resolved     BOOLEAN     NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_parse_failures_resolved ON event_parse_failures (resolved, occurred_at DESC);

COMMIT;
