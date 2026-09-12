-- 000108 回滚：删除流量采集 Agent 6 张表（按外键依赖逆序）
BEGIN;

DROP TABLE IF EXISTS agent_flow_events;
DROP TABLE IF EXISTS agent_policy_bindings;
DROP TABLE IF EXISTS agent_policies;
DROP TABLE IF EXISTS agent_interfaces;
DROP TABLE IF EXISTS agents;
DROP TABLE IF EXISTS agent_enrollment_tokens;

COMMIT;
