-- 000097 回滚：删除 client_identity 体系全部表（按外键依赖逆序）
BEGIN;

DROP TABLE IF EXISTS identity_behavior_events;
DROP TABLE IF EXISTS behavior_statistics;
DROP TABLE IF EXISTS identity_credential;
DROP TABLE IF EXISTS identity_ip_history;
DROP TABLE IF EXISTS client_identity;

COMMIT;
