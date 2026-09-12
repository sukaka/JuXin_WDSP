-- 000090 回滚：删除 apm.sql.read 权限种子
BEGIN;

DELETE FROM role_permissions WHERE permission_id IN (
  SELECT id FROM permissions WHERE code IN ('apm.sql.read')
);
DELETE FROM permissions WHERE code IN ('apm.sql.read');

COMMIT;
