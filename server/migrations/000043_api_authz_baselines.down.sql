-- 000043 回滚：删除授权基线两张表（索引随表删除）。
BEGIN;

DROP TABLE IF EXISTS api_object_ownership;
DROP TABLE IF EXISTS api_role_baselines;

COMMIT;
