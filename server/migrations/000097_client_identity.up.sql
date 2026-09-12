-- 000097 client_identity 体系（WDSP AI 自动化渗透防护增强 阶段1，服务端）。
-- 数据源：网关 identity-events.log（identity_observation / behavior_snapshot / recon_signal
-- 三种 JSONL 记录，采集器见 server/internal/identityevents，网关侧契约已冻结）。
--   client_identity         身份主表（identity_key 唯一，风险分由 recon_signal 重算）；
--   identity_ip_history     身份 × IP 历史（request_count 累计）；
--   identity_credential     身份 × 凭据指纹（只存哈希不落明文凭据）；
--   behavior_statistics     身份 × 窗口（1m/5m/30m/24h）行为计数（窗口对齐，采集侧覆盖写）；
--   identity_behavior_events 侦察信号事件（risk_score_delta 24h 滚动求和驱动风险分级）。
BEGIN;

-- ---------- 身份主表 ----------
CREATE TABLE IF NOT EXISTS client_identity (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_key        VARCHAR(128) NOT NULL UNIQUE,
    identity_type       VARCHAR(32)  NOT NULL DEFAULT 'UNKNOWN',
    first_seen_at       TIMESTAMPTZ,
    last_seen_at        TIMESTAMPTZ,
    primary_ip          VARCHAR(64),
    asn                 VARCHAR(64)  NOT NULL DEFAULT '',
    tls_fingerprint     VARCHAR(255) NOT NULL DEFAULT '',
    browser_fingerprint VARCHAR(255) NOT NULL DEFAULT '',
    account_id          VARCHAR(255) NOT NULL DEFAULT '',
    jwt_subject         VARCHAR(255) NOT NULL DEFAULT '',
    api_key_hash        VARCHAR(255) NOT NULL DEFAULT '',
    oauth_client_id     VARCHAR(255) NOT NULL DEFAULT '',
    device_type         VARCHAR(64)  NOT NULL DEFAULT '',
    risk_score          INT          NOT NULL DEFAULT 0,
    risk_level          VARCHAR(32)  NOT NULL DEFAULT 'LOW',
    status              VARCHAR(32)  NOT NULL DEFAULT 'NORMAL',
    request_count       BIGINT       NOT NULL DEFAULT 0,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_client_identity_risk_level ON client_identity (risk_level);
CREATE INDEX IF NOT EXISTS idx_client_identity_last_seen ON client_identity (last_seen_at DESC);

-- ---------- 身份 × IP 历史 ----------
CREATE TABLE IF NOT EXISTS identity_ip_history (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id   UUID         NOT NULL REFERENCES client_identity(id) ON DELETE CASCADE,
    ip            VARCHAR(64)  NOT NULL,
    first_seen_at TIMESTAMPTZ,
    last_seen_at  TIMESTAMPTZ,
    request_count BIGINT       NOT NULL DEFAULT 0,
    UNIQUE (identity_id, ip)
);

-- ---------- 身份 × 凭据指纹 ----------
CREATE TABLE IF NOT EXISTS identity_credential (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id     UUID         NOT NULL REFERENCES client_identity(id) ON DELETE CASCADE,
    credential_type VARCHAR(32)  NOT NULL,
    credential_hash VARCHAR(255) NOT NULL,
    first_seen_at   TIMESTAMPTZ,
    last_seen_at    TIMESTAMPTZ,
    UNIQUE (identity_id, credential_type, credential_hash)
);

-- ---------- 行为窗口统计 ----------
CREATE TABLE IF NOT EXISTS behavior_statistics (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id              UUID         NOT NULL REFERENCES client_identity(id) ON DELETE CASCADE,
    window_type              VARCHAR(16)  NOT NULL,
    window_start             TIMESTAMPTZ  NOT NULL,
    request_count             BIGINT NOT NULL DEFAULT 0,
    unique_uri_count          BIGINT NOT NULL DEFAULT 0,
    new_uri_count             BIGINT NOT NULL DEFAULT 0,
    status_401_count          BIGINT NOT NULL DEFAULT 0,
    status_403_count          BIGINT NOT NULL DEFAULT 0,
    status_404_count          BIGINT NOT NULL DEFAULT 0,
    status_405_count          BIGINT NOT NULL DEFAULT 0,
    status_500_count          BIGINT NOT NULL DEFAULT 0,
    auth_fail_count           BIGINT NOT NULL DEFAULT 0,
    parameter_mutation_count  BIGINT NOT NULL DEFAULT 0,
    sensitive_path_hits       BIGINT NOT NULL DEFAULT 0,
    created_at               TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (identity_id, window_type, window_start)
);

-- ---------- 侦察信号事件 ----------
CREATE TABLE IF NOT EXISTS identity_behavior_events (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id      UUID         REFERENCES client_identity(id) ON DELETE SET NULL,
    identity_key     VARCHAR(128) NOT NULL,
    occurred_at      TIMESTAMPTZ  NOT NULL,
    event_kind       VARCHAR(32)  NOT NULL DEFAULT 'RECON_SIGNAL',
    rule_code        VARCHAR(64)  NOT NULL,
    rule_version     VARCHAR(32)  NOT NULL,
    signal           VARCHAR(64)  NOT NULL,
    risk_score_delta INT          NOT NULL DEFAULT 0,
    mode             VARCHAR(16)  NOT NULL DEFAULT 'OBSERVE',
    reason           TEXT         DEFAULT '',
    metadata         JSONB        NOT NULL DEFAULT '{}'::jsonb,
    request_id       VARCHAR(128) DEFAULT '',
    client_ip        VARCHAR(64)  DEFAULT '',
    method           VARCHAR(16)  DEFAULT '',
    path             TEXT         DEFAULT '',
    app_id           VARCHAR(64)  DEFAULT '',
    domain           VARCHAR(255) DEFAULT '',
    gateway_node     VARCHAR(128) DEFAULT '',
    created_at       TIMESTAMPTZ  DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_identity_behavior_events_identity ON identity_behavior_events (identity_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_identity_behavior_events_occurred ON identity_behavior_events (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_identity_behavior_events_signal ON identity_behavior_events (signal);

COMMIT;
