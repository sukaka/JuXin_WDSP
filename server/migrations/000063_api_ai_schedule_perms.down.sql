-- 000063 回滚：删除 api_ai.* 权限点及其角色关联
BEGIN;

DELETE FROM role_permissions WHERE permission_id IN (
  SELECT id FROM permissions WHERE code IN ('api_ai.read','api_ai.execute')
);
DELETE FROM permissions WHERE code IN ('api_ai.read','api_ai.execute');

COMMIT;
