-- 回滚 000047：删除节点网口清单表。
BEGIN;

DROP TABLE IF EXISTS gateway_node_interfaces;

COMMIT;
