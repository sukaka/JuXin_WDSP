-- 阶段5 初始迁移：可信代理、保护地址、IP访问控制、CC策略、临时封禁、访问控制事件、版本
-- 在阶段4基础上新增访问控制与CC防护相关表

BEGIN;

-- ---------- 可信代理 ----------
CREATE TABLE IF NOT EXISTS trusted_proxies (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name               VARCHAR(100) NOT NULL,
    cidr               VARCHAR(64)  NOT NULL,              -- 单IP或CIDR（规范形式）
    ip_version         VARCHAR(10)  NOT NULL,              -- IPV4 / IPV6
    header_type        VARCHAR(20)  NOT NULL,              -- X_FORWARDED_FOR / X_REAL_IP / FORWARDED / CUSTOM
    custom_header_name VARCHAR(64),
    priority           INTEGER      NOT NULL DEFAULT 100,  -- 数值小者优先
    status             VARCHAR(20)  NOT NULL DEFAULT 'ENABLED', -- ENABLED / DISABLED
    scope              VARCHAR(20)  NOT NULL DEFAULT 'GLOBAL',  -- GLOBAL / NODE
    node_name          VARCHAR(100),                          -- scope=NODE 时限定网关节点
    description        VARCHAR(500) NOT NULL DEFAULT '',
    created_by         UUID,
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_by         UUID,
    updated_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
    deleted_at         TIMESTAMPTZ,
    version            INTEGER      NOT NULL DEFAULT 1
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_trusted_proxies_cidr
    ON trusted_proxies (cidr, COALESCE(node_name, '')) WHERE deleted_at IS NULL;

-- ---------- 保护地址 ----------
CREATE TABLE IF NOT EXISTS protected_addresses (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name         VARCHAR(100) NOT NULL,
    address      VARCHAR(64),                            -- 单IP（与 cidr 二选一）
    cidr         VARCHAR(64),                            -- CIDR
    address_type VARCHAR(20)  NOT NULL,                  -- GATEWAY/MANAGEMENT/UPSTREAM/DATABASE/CACHE/TRUSTED_PROXY/LOOPBACK/LINK_LOCAL/CUSTOM
    source_type  VARCHAR(20)  NOT NULL DEFAULT 'SYSTEM', -- SYSTEM / MANUAL
    description  VARCHAR(500) NOT NULL DEFAULT '',
    status       VARCHAR(20)  NOT NULL DEFAULT 'ENABLED',
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_protected_addresses_addr
    ON protected_addresses (COALESCE(address, ''), COALESCE(cidr, ''));

-- ---------- IP访问控制规则 ----------
CREATE TABLE IF NOT EXISTS ip_access_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(200) NOT NULL,
    rule_type       VARCHAR(10)  NOT NULL,               -- ALLOW / DENY
    scope_type      VARCHAR(15)  NOT NULL,               -- GLOBAL / APPLICATION
    application_id  UUID REFERENCES applications(id),
    address         VARCHAR(64)  NOT NULL,               -- 规范单IP或CIDR（统一存一列）
    ip_version      VARCHAR(10)  NOT NULL,               -- IPV4 / IPV6
    priority        INTEGER      NOT NULL DEFAULT 100,
    status          VARCHAR(15)  NOT NULL DEFAULT 'ACTIVE', -- DRAFT/ACTIVE/DISABLED/EXPIRED/DELETED
    validity_type   VARCHAR(15)  NOT NULL DEFAULT 'PERMANENT', -- PERMANENT / TEMPORARY
    effective_from  TIMESTAMPTZ,
    effective_until TIMESTAMPTZ,
    reason          VARCHAR(500) NOT NULL DEFAULT '',
    source_type     VARCHAR(20)  NOT NULL DEFAULT 'MANUAL', -- MANUAL/SECURITY_EVENT/IMPORT/AUTO_BLOCK/SYSTEM
    source_event_id UUID,
    hit_count       BIGINT       NOT NULL DEFAULT 0,
    last_hit_at     TIMESTAMPTZ,
    created_by      UUID,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_by      UUID,
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    deleted_at      TIMESTAMPTZ,
    version         INTEGER      NOT NULL DEFAULT 1,
    CONSTRAINT chk_ip_access_rules_app_scope CHECK (
        (scope_type = 'APPLICATION' AND application_id IS NOT NULL) OR
        (scope_type = 'GLOBAL' AND application_id IS NULL)
    )
);
CREATE INDEX IF NOT EXISTS idx_ip_access_rules_scope ON ip_access_rules (scope_type, rule_type, status) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_ip_access_rules_address ON ip_access_rules (address) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_ip_access_rules_app ON ip_access_rules (application_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_ip_access_rules_until ON ip_access_rules (effective_until) WHERE status = 'ACTIVE' AND effective_until IS NOT NULL;

-- ---------- CC防护策略 ----------
CREATE TABLE IF NOT EXISTS rate_limit_policies (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                   VARCHAR(200) NOT NULL,
    description            VARCHAR(500) NOT NULL DEFAULT '',
    scope_type             VARCHAR(15)  NOT NULL,           -- GLOBAL / APPLICATION / URI
    application_id         UUID REFERENCES applications(id),
    uri_match_type         VARCHAR(10)  NOT NULL DEFAULT 'ALL', -- ALL / EXACT / PREFIX / REGEX
    uri_pattern            VARCHAR(256) NOT NULL DEFAULT '',
    dimension              VARCHAR(30)  NOT NULL,           -- CLIENT_IP / APPLICATION / CLIENT_IP_AND_URI / CLIENT_IP_AND_APPLICATION
    algorithm              VARCHAR(20)  NOT NULL DEFAULT 'TOKEN_BUCKET', -- TOKEN_BUCKET / SLIDING_WINDOW
    requests_limit         INTEGER      NOT NULL,
    window_seconds         INTEGER      NOT NULL,
    burst_capacity         INTEGER      NOT NULL DEFAULT 0,
    action                 VARCHAR(15)  NOT NULL,           -- LOG / OBSERVE / REJECT / TEMP_BLOCK
    block_duration_seconds INTEGER      NOT NULL DEFAULT 0,
    status                 VARCHAR(15)  NOT NULL DEFAULT 'ACTIVE', -- ACTIVE / DISABLED
    observe_only           BOOLEAN      NOT NULL DEFAULT FALSE,
    priority               INTEGER      NOT NULL DEFAULT 100,
    effective_from         TIMESTAMPTZ,
    effective_until        TIMESTAMPTZ,
    created_by             UUID,
    created_at             TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_by             UUID,
    updated_at             TIMESTAMPTZ  NOT NULL DEFAULT now(),
    deleted_at             TIMESTAMPTZ,
    version                INTEGER      NOT NULL DEFAULT 1,
    CONSTRAINT chk_rate_limit_positive CHECK (requests_limit > 0 AND window_seconds > 0),
    CONSTRAINT chk_rate_limit_app_scope CHECK (
        (scope_type IN ('APPLICATION', 'URI') AND application_id IS NOT NULL) OR
        (scope_type = 'GLOBAL' AND application_id IS NULL)
    )
);
CREATE INDEX IF NOT EXISTS idx_rate_limit_policies_scope ON rate_limit_policies (scope_type, status) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_rate_limit_policies_app ON rate_limit_policies (application_id) WHERE deleted_at IS NULL;

-- ---------- 临时封禁 ----------
CREATE TABLE IF NOT EXISTS temporary_blocks (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_ip          INET         NOT NULL,
    application_id     UUID REFERENCES applications(id),  -- NULL = 全局
    trigger_type       VARCHAR(20)  NOT NULL,             -- CC_AUTO / MANUAL
    trigger_policy_id  UUID,
    trigger_event_ids  JSONB,
    block_started_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    block_expires_at   TIMESTAMPTZ  NOT NULL,
    status             VARCHAR(20)  NOT NULL DEFAULT 'ACTIVE', -- ACTIVE / EXPIRED / MANUALLY_RELEASED / CANCELLED
    hit_count          BIGINT       NOT NULL DEFAULT 0,
    release_type       VARCHAR(20),                         -- AUTO_EXPIRE / MANUAL / CONVERTED
    released_by        UUID,
    released_at        TIMESTAMPTZ,
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_temporary_blocks_ip ON temporary_blocks (client_ip) WHERE status = 'ACTIVE';
CREATE INDEX IF NOT EXISTS idx_temporary_blocks_expires ON temporary_blocks (block_expires_at) WHERE status = 'ACTIVE';

-- ---------- 访问控制事件（按月分区） ----------
CREATE TABLE IF NOT EXISTS access_control_events (
    id               UUID         NOT NULL DEFAULT gen_random_uuid(),
    request_id       VARCHAR(64)  NOT NULL DEFAULT '',
    occurred_at      TIMESTAMPTZ  NOT NULL,
    application_id   UUID,
    application_code VARCHAR(64)  NOT NULL DEFAULT '',
    client_ip        INET         NOT NULL,
    connection_ip    INET,
    domain           VARCHAR(255) NOT NULL DEFAULT '',
    request_method   VARCHAR(10)  NOT NULL DEFAULT '',
    request_path     VARCHAR(512) NOT NULL DEFAULT '',
    event_type       VARCHAR(40)  NOT NULL,
    action           VARCHAR(20)  NOT NULL DEFAULT '',
    policy_id        VARCHAR(64)  NOT NULL DEFAULT '',
    access_rule_id   VARCHAR(64)  NOT NULL DEFAULT '',
    current_count    BIGINT,
    limit_value      BIGINT,
    window_seconds   INTEGER,
    block_expires_at TIMESTAMPTZ,
    response_status  INTEGER,
    gateway_node_id  VARCHAR(100) NOT NULL DEFAULT '',
    message          VARCHAR(512) NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    PRIMARY KEY (id, occurred_at)
) PARTITION BY RANGE (occurred_at);

CREATE TABLE IF NOT EXISTS access_control_events_default PARTITION OF access_control_events DEFAULT;
-- 初始月份分区（2026-07 / 2026-08）
CREATE TABLE IF NOT EXISTS access_control_events_2026_07 PARTITION OF access_control_events
    FOR VALUES FROM ('2026-07-01 00:00:00+00') TO ('2026-08-01 00:00:00+00');
CREATE TABLE IF NOT EXISTS access_control_events_2026_08 PARTITION OF access_control_events
    FOR VALUES FROM ('2026-08-01 00:00:00+00') TO ('2026-09-01 00:00:00+00');

CREATE INDEX IF NOT EXISTS idx_ac_events_time ON access_control_events (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_ac_events_app ON access_control_events (application_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_ac_events_ip ON access_control_events (client_ip, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_ac_events_type ON access_control_events (event_type, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_ac_events_policy ON access_control_events (policy_id) WHERE policy_id <> '';
CREATE INDEX IF NOT EXISTS idx_ac_events_request ON access_control_events (request_id) WHERE request_id <> '';

-- ---------- 访问控制配置版本 ----------
CREATE TABLE IF NOT EXISTS access_control_versions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version_no          INTEGER      NOT NULL,
    config              JSONB        NOT NULL,          -- guard 配置快照（全局+按应用）
    config_hash         VARCHAR(64)  NOT NULL,
    change_summary      VARCHAR(1000) NOT NULL DEFAULT '',
    previous_version_id UUID,
    publish_task_id     UUID,
    publish_result      VARCHAR(20)  NOT NULL DEFAULT 'PENDING', -- PENDING / SUCCESS / FAILED
    created_by          UUID,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_ac_versions_no ON access_control_versions (version_no);

-- ---------- CC运行汇总 ----------
CREATE TABLE IF NOT EXISTS rate_limit_runtime_summaries (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id         UUID         NOT NULL,
    window_start      TIMESTAMPTZ  NOT NULL,
    total_requests    BIGINT       NOT NULL DEFAULT 0,
    rejected_requests BIGINT       NOT NULL DEFAULT 0,
    blocked_ips       INTEGER      NOT NULL DEFAULT 0,
    recorded_at       TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_rl_summaries_policy ON rate_limit_runtime_summaries (policy_id, window_start DESC);

COMMIT;
