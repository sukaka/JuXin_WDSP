-- 000069 回滚：drop 节点版本视图表 + 移除 api_runtime_events.gateway_node 补列。
BEGIN;

DROP TABLE IF EXISTS api_gateway_nodes;
DROP INDEX IF EXISTS idx_api_runtime_events_node;
ALTER TABLE api_runtime_events DROP COLUMN IF EXISTS gateway_node;

COMMIT;
