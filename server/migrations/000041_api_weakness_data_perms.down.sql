-- 000041 回滚：删除 api_weakness.*/api_data.* 权限点及其角色关联
BEGIN;

DELETE FROM role_permissions WHERE permission_id IN (
  SELECT id FROM permissions WHERE code IN (
    'api_weakness.read','api_weakness.handle','api_data.read','api_data.manage'
  )
);
DELETE FROM permissions WHERE code IN (
  'api_weakness.read','api_weakness.handle','api_data.read','api_data.manage'
);

COMMIT;
