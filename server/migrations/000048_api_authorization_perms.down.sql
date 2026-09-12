-- 000048 回滚：删除 api_authorization.* 权限点及其角色关联
BEGIN;

DELETE FROM role_permissions WHERE permission_id IN (
  SELECT id FROM permissions WHERE code IN ('api_authorization.read','api_authorization.manage')
);
DELETE FROM permissions WHERE code IN ('api_authorization.read','api_authorization.manage');

COMMIT;
