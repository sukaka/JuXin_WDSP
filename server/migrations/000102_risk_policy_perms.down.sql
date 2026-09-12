-- 000102 回滚：删除风险策略 2 个权限点及其角色关联
BEGIN;

DELETE FROM role_permissions WHERE permission_id IN (
  SELECT id FROM permissions WHERE code IN ('risk_policy.read', 'risk_policy.edit')
);
DELETE FROM permissions WHERE code IN ('risk_policy.read', 'risk_policy.edit');

COMMIT;
