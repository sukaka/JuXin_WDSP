-- 回滚 000065：删除节点网络期望配置表。
BEGIN;

DROP TABLE IF EXISTS node_network_configs;

COMMIT;
