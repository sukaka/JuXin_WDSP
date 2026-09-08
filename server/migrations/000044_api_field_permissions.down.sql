-- 000044 回滚：删除字段权限表（唯一索引随表删除）。
BEGIN;

DROP TABLE IF EXISTS api_field_permissions;

COMMIT;
