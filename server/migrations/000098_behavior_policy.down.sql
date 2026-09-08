-- 000098 回滚：删除 security_behavior_policy 表
BEGIN;

DROP TABLE IF EXISTS security_behavior_policy;

COMMIT;
