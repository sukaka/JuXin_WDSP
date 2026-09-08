-- 000084 回滚：删除 reports.delete_all 权限点及其角色关联
BEGIN;

DELETE FROM role_permissions WHERE permission_id IN (
  SELECT id FROM permissions WHERE code IN ('reports.delete_all')
);
DELETE FROM permissions WHERE code IN ('reports.delete_all');

COMMIT;
