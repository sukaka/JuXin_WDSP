-- 000176 回滚：移除强流程定义两表（无实例表依赖——实例表 000177 属 FLOW-02，
-- 回滚顺序要求 177 先回滚）。
BEGIN;

DROP TABLE IF EXISTS api_strong_flow_steps;
DROP TABLE IF EXISTS api_strong_flow_definitions;

COMMIT;
