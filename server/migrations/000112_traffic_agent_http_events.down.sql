-- 000112 回滚：删除 Agent HTTP 事件表（索引随表级联删除）
BEGIN;

DROP TABLE IF EXISTS agent_http_events;

COMMIT;
