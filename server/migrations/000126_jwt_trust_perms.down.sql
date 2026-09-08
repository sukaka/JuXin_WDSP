-- 000126 回滚：删除 JWT 信任链 2 个权限点及其角色关联
BEGIN;

DELETE FROM role_permissions WHERE permission_id IN (
  SELECT id FROM permissions WHERE code IN ('jwt_trust.read', 'jwt_trust.manage')
);
DELETE FROM permissions WHERE code IN ('jwt_trust.read', 'jwt_trust.manage');

COMMIT;
