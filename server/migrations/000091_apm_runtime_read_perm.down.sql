-- 000091 回滚：删除 apm.runtime.read 权限种子
BEGIN;

DELETE FROM role_permissions WHERE permission_id IN (
  SELECT id FROM permissions WHERE code IN ('apm.runtime.read')
);
DELETE FROM permissions WHERE code IN ('apm.runtime.read');

COMMIT;
