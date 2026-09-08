-- 000108 WDSP 分布式流量采集 Agent（Phase 1，契约 docs/agents/WDSP_AGENT_PHASE1_CONTRACT.md §7）。
-- 说明：契约文字称「迁移 000106/000107」，但 000106 已被 000106_attack_session_automation
-- 占用，故本批实际编号 000108（表）/000109（权限种子；000107 被并行任务 000107_ha_groups_unicast_peers 占用），仅编号顺延，无语义偏离。
--
--   1) agent_enrollment_tokens：一次性注册令牌（明文 wdt_<64hex> 只存 SHA-256 hex 摘要；
--      使用即作废（used_at/used_by_agent_id），可撤销（revoked_at），有过期时间；
--      消费在注册事务内原子完成（used_at IS NULL AND revoked_at IS NULL AND expires_at > now()）；
--   2) agents：Agent 登记（对外标识 agent_id 为服务端签发 UUID；credential_hash 只存
--      wda_ 明文的 SHA-256 hex 摘要，UNIQUE 供 Bearer 反查；status 不落库——DISABLED
--      看 disabled、OFFLINE 看 last_seen 超时（契约 §5 查询时派生），last_status 仅为
--      最近心跳自报状态（ONLINE/DEGRADED/ERROR）；last_metrics 为心跳 metrics 快照 +
--      RAW 通道累计计数 raw_frames_received/raw_bytes_received；config_version 在策略
--      更新/绑定/解绑时 +1，applied_config_version 由 config/ack（APPLIED）回填；
--      enrollment_token_id 溯源注册所用令牌（令牌删除暂不支持，留 RESTRICT 防线）；
--   3) agent_interfaces：注册上报网卡清单（重注册整批替换；随 Agent 删除级联）；
--   4) agent_policies：采集策略（config 为契约 §3.3 policy JSON，应用层枚举校验兜底；
--      version 每次修改 +1，随绑定下发，config 不落明文之外的任何派生物）；
--   5) agent_policy_bindings：每 Agent 同时仅一条生效绑定（agent_id UNIQUE，重复绑定即
--      换绑；策略删除被绑定 RESTRICT 拦截，须先解绑）；
--   6) agent_flow_events：FLOW 通道流量事件（request/flow_end；ts 为 Agent 上报事件时间，
--      (agent_id, ts DESC) 索引支撑管理端按时间倒序分页；随 Agent 删除级联清理——
--      契约 §4 删除语义为吊销 credential/删除绑定与网卡，事件属 Agent 生命周期数据，
--      操作审计（audits 表）不受影响如实保留）。
BEGIN;

-- ---------- agent_enrollment_tokens ----------
CREATE TABLE IF NOT EXISTS agent_enrollment_tokens (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    label        VARCHAR(128) NOT NULL DEFAULT '',
    token_hash   CHAR(64)     NOT NULL UNIQUE,  -- SHA-256 hex（明文 wdt_<64hex> 仅签发时返回一次）
    expires_at   TIMESTAMPTZ  NOT NULL,
    used_at      TIMESTAMPTZ,
    used_by_agent_id UUID,
    revoked_at   TIMESTAMPTZ,
    created_by   VARCHAR(255) NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_agent_enrollment_tokens_created
    ON agent_enrollment_tokens (created_at DESC);

-- ---------- agents ----------
CREATE TABLE IF NOT EXISTS agents (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id                UUID         NOT NULL UNIQUE,   -- 契约对外标识（路径/上报均用此值）
    hostname                VARCHAR(255) NOT NULL DEFAULT '',
    ip                      VARCHAR(64)  NOT NULL DEFAULT '',
    os                      VARCHAR(255) NOT NULL DEFAULT '',
    kernel                  VARCHAR(255) NOT NULL DEFAULT '',
    arch                    VARCHAR(64)  NOT NULL DEFAULT '',
    version                 VARCHAR(64)  NOT NULL DEFAULT '',
    credential_hash         CHAR(64)     NOT NULL UNIQUE,   -- wda_ 明文 SHA-256 hex
    disabled                BOOLEAN      NOT NULL DEFAULT false,
    enrollment_token_id     UUID         REFERENCES agent_enrollment_tokens(id) ON DELETE RESTRICT,
    last_seen               TIMESTAMPTZ,                    -- 最近心跳/指标上报时间（状态派生输入）
    last_status             VARCHAR(16)  NOT NULL DEFAULT ''
                            CHECK (last_status IN ('', 'ONLINE', 'DEGRADED', 'ERROR')),
    last_metrics            JSONB        NOT NULL DEFAULT '{}'::jsonb,
    config_version          BIGINT       NOT NULL DEFAULT 0,
    applied_config_version  BIGINT       NOT NULL DEFAULT 0,
    created_at              TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_agents_hostname ON agents (hostname);

-- ---------- agent_interfaces ----------
CREATE TABLE IF NOT EXISTS agent_interfaces (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id   UUID         NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    name       VARCHAR(128) NOT NULL,
    mac        VARCHAR(32)  NOT NULL DEFAULT '',
    ipv4       VARCHAR(64)  NOT NULL DEFAULT '',
    ipv6       VARCHAR(128) NOT NULL DEFAULT '',
    mtu        INT          NOT NULL DEFAULT 0,
    speed_mbps INT          NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (agent_id, name)
);

-- ---------- agent_policies ----------
CREATE TABLE IF NOT EXISTS agent_policies (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name       VARCHAR(128) NOT NULL UNIQUE,
    config     JSONB        NOT NULL,           -- 契约 §3.3 policy JSON（capture/output/limits/sampling/buffer）
    version    INT          NOT NULL DEFAULT 1, -- 每次修改 +1（审计/溯源用；下发版本为 agents.config_version）
    created_by VARCHAR(255) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- ---------- agent_policy_bindings ----------
CREATE TABLE IF NOT EXISTS agent_policy_bindings (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id   UUID         NOT NULL UNIQUE REFERENCES agents(agent_id) ON DELETE CASCADE,
    policy_id  UUID         NOT NULL REFERENCES agent_policies(id) ON DELETE RESTRICT,
    bound_by   VARCHAR(255) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_agent_policy_bindings_policy ON agent_policy_bindings (policy_id);

-- ---------- agent_flow_events ----------
CREATE TABLE IF NOT EXISTS agent_flow_events (
    id             BIGSERIAL PRIMARY KEY,
    agent_id       UUID         NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    ts             TIMESTAMPTZ  NOT NULL,          -- Agent 上报事件时间（Unix 秒转换）
    event_type     VARCHAR(16)  NOT NULL
                   CHECK (event_type IN ('request', 'flow_end')),
    flow_id        VARCHAR(255) NOT NULL DEFAULT '',
    src_ip         VARCHAR(64)  NOT NULL DEFAULT '',
    src_port       INT          NOT NULL DEFAULT 0,
    dst_ip         VARCHAR(64)  NOT NULL DEFAULT '',
    dst_port       INT          NOT NULL DEFAULT 0,
    protocol       VARCHAR(16)  NOT NULL DEFAULT 'tcp',
    direction      VARCHAR(16)  NOT NULL DEFAULT '',
    bytes_in       BIGINT       NOT NULL DEFAULT 0,
    bytes_out      BIGINT       NOT NULL DEFAULT 0,
    packets_in     BIGINT       NOT NULL DEFAULT 0,
    packets_out    BIGINT       NOT NULL DEFAULT 0,
    tls_visibility VARCHAR(16)  NOT NULL DEFAULT ''
                   CHECK (tls_visibility IN ('', 'PLAINTEXT', 'ENCRYPTED', 'UNKNOWN')),
    http_method    VARCHAR(16)  NOT NULL DEFAULT '',
    http_host      VARCHAR(255) NOT NULL DEFAULT '',
    http_uri       TEXT         NOT NULL DEFAULT '',
    http_status    INT          NOT NULL DEFAULT 0,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_agent_flow_events_agent_ts
    ON agent_flow_events (agent_id, ts DESC);

COMMIT;
