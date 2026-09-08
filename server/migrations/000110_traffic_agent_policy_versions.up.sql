-- 000110 WDSP 流量采集 Agent Phase 2：策略版本化与健康评分输入。
--
--   1) agent_policy_versions：策略历史版本快照（设计 §68.13/§68.14：策略必须版本化、
--      支持回滚）。策略创建与每次 PUT/回滚在同一事务快照一行（policy_id,version 唯一）；
--      随策略删除级联（策略删除已被「仍被绑定 RESTRICT」拦截，历史快照不阻碍解绑后删除）。
--      回填：本迁移为既有 agent_policies 按当前版本补一行快照（此前无历史，如实只补当前版）。
--   2) agents.last_clock_offset_ms：最近一次心跳的时钟偏移（毫秒，signed；
--      = 服务端收包时间 − Agent 上报 timestamp，正值表示 Agent 时钟偏慢），
--      健康评分 clock_drift 档输入（设计 §23：>5s 告警阈值）。
BEGIN;

-- 兼容修复：部分既有环境曾将 000108/000109 都用于权限种子，导致
-- 000108_traffic_agents 被迁移器按版本号误判为已执行。这里幂等补齐 Phase 1
-- 基础表，保证旧库可继续升级；全新数据库已由 000108 创建，IF NOT EXISTS
-- 会使以下语句成为无操作。
CREATE TABLE IF NOT EXISTS agent_enrollment_tokens (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    label            VARCHAR(128) NOT NULL DEFAULT '',
    token_hash       CHAR(64) NOT NULL UNIQUE,
    expires_at       TIMESTAMPTZ NOT NULL,
    used_at          TIMESTAMPTZ,
    used_by_agent_id UUID,
    revoked_at       TIMESTAMPTZ,
    created_by       VARCHAR(255) NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_agent_enrollment_tokens_created
    ON agent_enrollment_tokens (created_at DESC);

CREATE TABLE IF NOT EXISTS agents (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id               UUID NOT NULL UNIQUE,
    hostname               VARCHAR(255) NOT NULL DEFAULT '',
    ip                     VARCHAR(64) NOT NULL DEFAULT '',
    os                     VARCHAR(255) NOT NULL DEFAULT '',
    kernel                 VARCHAR(255) NOT NULL DEFAULT '',
    arch                   VARCHAR(64) NOT NULL DEFAULT '',
    version                VARCHAR(64) NOT NULL DEFAULT '',
    credential_hash        CHAR(64) NOT NULL UNIQUE,
    disabled               BOOLEAN NOT NULL DEFAULT false,
    enrollment_token_id    UUID REFERENCES agent_enrollment_tokens(id) ON DELETE RESTRICT,
    last_seen              TIMESTAMPTZ,
    last_status            VARCHAR(16) NOT NULL DEFAULT ''
                           CHECK (last_status IN ('', 'ONLINE', 'DEGRADED', 'ERROR')),
    last_metrics           JSONB NOT NULL DEFAULT '{}'::jsonb,
    config_version         BIGINT NOT NULL DEFAULT 0,
    applied_config_version BIGINT NOT NULL DEFAULT 0,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_agents_hostname ON agents (hostname);

CREATE TABLE IF NOT EXISTS agent_interfaces (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id   UUID NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    name       VARCHAR(128) NOT NULL,
    mac        VARCHAR(32) NOT NULL DEFAULT '',
    ipv4       VARCHAR(64) NOT NULL DEFAULT '',
    ipv6       VARCHAR(128) NOT NULL DEFAULT '',
    mtu        INT NOT NULL DEFAULT 0,
    speed_mbps INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (agent_id, name)
);

CREATE TABLE IF NOT EXISTS agent_policies (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name       VARCHAR(128) NOT NULL UNIQUE,
    config     JSONB NOT NULL,
    version    INT NOT NULL DEFAULT 1,
    created_by VARCHAR(255) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS agent_policy_bindings (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id   UUID NOT NULL UNIQUE REFERENCES agents(agent_id) ON DELETE CASCADE,
    policy_id  UUID NOT NULL REFERENCES agent_policies(id) ON DELETE RESTRICT,
    bound_by   VARCHAR(255) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_agent_policy_bindings_policy
    ON agent_policy_bindings (policy_id);

CREATE TABLE IF NOT EXISTS agent_flow_events (
    id             BIGSERIAL PRIMARY KEY,
    agent_id       UUID NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    ts             TIMESTAMPTZ NOT NULL,
    event_type     VARCHAR(16) NOT NULL CHECK (event_type IN ('request', 'flow_end')),
    flow_id        VARCHAR(255) NOT NULL DEFAULT '',
    src_ip         VARCHAR(64) NOT NULL DEFAULT '',
    src_port       INT NOT NULL DEFAULT 0,
    dst_ip         VARCHAR(64) NOT NULL DEFAULT '',
    dst_port       INT NOT NULL DEFAULT 0,
    protocol       VARCHAR(16) NOT NULL DEFAULT 'tcp',
    direction      VARCHAR(16) NOT NULL DEFAULT '',
    bytes_in       BIGINT NOT NULL DEFAULT 0,
    bytes_out      BIGINT NOT NULL DEFAULT 0,
    packets_in     BIGINT NOT NULL DEFAULT 0,
    packets_out    BIGINT NOT NULL DEFAULT 0,
    tls_visibility VARCHAR(16) NOT NULL DEFAULT ''
                   CHECK (tls_visibility IN ('', 'PLAINTEXT', 'ENCRYPTED', 'UNKNOWN')),
    http_method    VARCHAR(16) NOT NULL DEFAULT '',
    http_host      VARCHAR(255) NOT NULL DEFAULT '',
    http_uri       TEXT NOT NULL DEFAULT '',
    http_status    INT NOT NULL DEFAULT 0,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_agent_flow_events_agent_ts
    ON agent_flow_events (agent_id, ts DESC);

-- ---------- agent_policy_versions ----------
CREATE TABLE IF NOT EXISTS agent_policy_versions (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id  UUID         NOT NULL REFERENCES agent_policies(id) ON DELETE CASCADE,
    version    INT          NOT NULL,
    config     JSONB        NOT NULL,           -- 该版本策略全量快照（契约 §3.3 policy JSON）
    created_by VARCHAR(255) NOT NULL DEFAULT '', -- 产生该版本的操作人（创建/修改/回滚）
    created_at TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (policy_id, version)
);
CREATE INDEX IF NOT EXISTS idx_agent_policy_versions_policy
    ON agent_policy_versions (policy_id, version DESC);

-- 既有策略回填当前版本快照（历史版本无留存，如实只补当前版）
INSERT INTO agent_policy_versions (policy_id, version, config, created_by)
SELECT id, version, config, created_by FROM agent_policies
ON CONFLICT (policy_id, version) DO NOTHING;

-- ---------- agents.last_clock_offset_ms ----------
ALTER TABLE agents ADD COLUMN IF NOT EXISTS last_clock_offset_ms BIGINT;

COMMIT;
