-- 000177 回滚：移除实例与步骤事件两表。
BEGIN;

DROP TABLE IF EXISTS api_strong_flow_step_events;
DROP TABLE IF EXISTS api_strong_flow_instances;

COMMIT;
