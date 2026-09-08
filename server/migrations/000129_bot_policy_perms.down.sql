-- 000129 回滚：删除 Bot 策略 2 个权限点及其角色关联
BEGIN;

DELETE FROM role_permissions WHERE permission_id IN (
  SELECT id FROM permissions WHERE code IN ('bot_policy.read', 'bot_policy.edit')
);
DELETE FROM permissions WHERE code IN ('bot_policy.read', 'bot_policy.edit');

COMMIT;
