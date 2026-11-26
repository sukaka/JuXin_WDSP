-- 回滚 000246：移除 client_side 权限种子及客户端供应链安全四张表
BEGIN;

DELETE FROM role_permissions
WHERE permission_id IN (SELECT id FROM permissions WHERE code IN ('client_side.read', 'client_side.manage'));

DELETE FROM permissions WHERE code IN ('client_side.read', 'client_side.manage');

DROP TABLE IF EXISTS client_side_violations;
DROP TABLE IF EXISTS client_script_inventory;
DROP TABLE IF EXISTS client_side_policy_versions;
DROP TABLE IF EXISTS client_side_policies;

COMMIT;
