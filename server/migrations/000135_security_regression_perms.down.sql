-- 000135 回滚：删除安全回归 3 个权限点及其角色关联
BEGIN;

DELETE FROM role_permissions WHERE permission_id IN (
  SELECT id FROM permissions WHERE code IN (
    'security_regression.read', 'security_regression.import', 'security_regression.policy')
);
DELETE FROM permissions WHERE code IN (
  'security_regression.read', 'security_regression.import', 'security_regression.policy');

COMMIT;
