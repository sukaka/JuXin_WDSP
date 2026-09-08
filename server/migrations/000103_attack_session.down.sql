-- 000103 down：删除攻击活动会话两表（事件关联表先删，解除外键依赖）。
BEGIN;

DROP TABLE IF EXISTS attack_session_event;
DROP TABLE IF EXISTS attack_session;

COMMIT;
