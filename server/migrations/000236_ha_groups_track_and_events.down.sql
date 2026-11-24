-- 000236 回滚：移除单节点互斥索引、api_gateway_nodes 协同列、ha_events 表及 ha_groups.track_interfaces 列。
BEGIN;

DROP INDEX IF EXISTS uq_ha_group_members_node_id;

ALTER TABLE api_gateway_nodes
    DROP COLUMN IF EXISTS network_status_at,
    DROP COLUMN IF EXISTS network_status,
    DROP COLUMN IF EXISTS ha_vip_status_at,
    DROP COLUMN IF EXISTS ha_vip_status,
    DROP COLUMN IF EXISTS reported_version,
    DROP COLUMN IF EXISTS sync_secret_ciphertext,
    DROP COLUMN IF EXISTS sync_agent_addr;

DROP INDEX IF EXISTS idx_ha_events_occurred;
DROP INDEX IF EXISTS idx_ha_events_node_occurred;
DROP INDEX IF EXISTS idx_ha_events_group_occurred;
DROP TABLE IF EXISTS ha_events;

ALTER TABLE ha_groups
    DROP COLUMN IF EXISTS track_interfaces;

COMMIT;
