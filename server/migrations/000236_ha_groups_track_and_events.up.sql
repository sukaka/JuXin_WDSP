-- 000236 主备高可用增强：
--   a) ha_groups 新增 track_interfaces（Keepalived track_interface 关联接口列表）
--   b) 新建 ha_events（持久化漂移、联动、脑裂、回切与同步历史事件）
--   c) api_gateway_nodes 新增节点协同代理地址、加密密钥、上报版本及 HA/网络状态快照列
--   d) ha_group_members 增加 node_id 唯一索引，保证单个节点同时仅归属一个主备组
BEGIN;

-- a) ha_groups.track_interfaces
ALTER TABLE ha_groups
    ADD COLUMN IF NOT EXISTS track_interfaces JSONB NOT NULL DEFAULT '[]';

COMMENT ON COLUMN ha_groups.track_interfaces IS
    'Keepalived track_interface 监控的关联接口列表（如透明网桥成员口），JSON 字符串数组，默认 []';

-- b) ha_events 持久化事件表
CREATE TABLE IF NOT EXISTS ha_events (
    id          BIGSERIAL PRIMARY KEY,
    group_id    UUID        REFERENCES ha_groups(id) ON DELETE SET NULL,
    group_name  TEXT        NOT NULL DEFAULT '',
    node_name   TEXT        NOT NULL DEFAULT '',
    event_type  VARCHAR(48) NOT NULL,
    detail      JSONB       NOT NULL DEFAULT '{}',
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ha_events_group_occurred
    ON ha_events (group_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_ha_events_node_occurred
    ON ha_events (node_name, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_ha_events_occurred
    ON ha_events (occurred_at DESC);

COMMENT ON TABLE ha_events IS
    '主备高可用持久化历史事件（FAILBACK / SYNC_FAILED / SPLIT_BRAIN / VIP_TRANSITION / LINK_PAIR_CHANGE 等）';

-- c) api_gateway_nodes 节点协同代理与遥测状态快照列
ALTER TABLE api_gateway_nodes
    ADD COLUMN IF NOT EXISTS sync_agent_addr        TEXT        NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS sync_secret_ciphertext TEXT        NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS reported_version       TEXT        NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS ha_vip_status          JSONB,
    ADD COLUMN IF NOT EXISTS ha_vip_status_at       TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS network_status         JSONB,
    ADD COLUMN IF NOT EXISTS network_status_at      TIMESTAMPTZ;

COMMENT ON COLUMN api_gateway_nodes.sync_agent_addr IS
    '节点 hasyncd 协同代理地址（内网 http(s)://host:port）；空串 = 未配置';
COMMENT ON COLUMN api_gateway_nodes.sync_secret_ciphertext IS
    '节点 hasyncd HMAC 共享密钥密文（encSvc 加密，永不回显明文）；空串 = 未配置';
COMMENT ON COLUMN api_gateway_nodes.reported_version IS
    '节点协同代理上报的当前系统版本；空串 = 未知';
COMMENT ON COLUMN api_gateway_nodes.ha_vip_status IS
    '节点最新汇聚的 ha-vip-status.json 状态快照';
COMMENT ON COLUMN api_gateway_nodes.ha_vip_status_at IS
    '节点最新 ha_vip_status 采集/刷新时间';
COMMENT ON COLUMN api_gateway_nodes.network_status IS
    '节点最新汇聚的 network-status.json 状态快照';
COMMENT ON COLUMN api_gateway_nodes.network_status_at IS
    '节点最新 network_status 采集/刷新时间';

-- d) 单节点互斥约束：同一网关节点同时仅允许归属一个 HA 主备组
CREATE UNIQUE INDEX IF NOT EXISTS uq_ha_group_members_node_id
    ON ha_group_members (node_id);

COMMIT;
