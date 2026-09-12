-- 000099 回滚：删除 client_identity 体系与行为策略 3 个权限点及其角色关联
BEGIN;

DELETE FROM role_permissions WHERE permission_id IN (
  SELECT id FROM permissions WHERE code IN (
    'security_identities.read','behavior_policy.read','behavior_policy.edit'
  )
);
DELETE FROM permissions WHERE code IN (
  'security_identities.read','behavior_policy.read','behavior_policy.edit'
);

COMMIT;
