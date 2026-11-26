-- 回滚 000248：移除 semantic_guard 权限种子及本地语义防火墙策略两张表
BEGIN;

DELETE FROM role_permissions
WHERE permission_id IN (SELECT id FROM permissions WHERE code IN ('semantic_guard.read', 'semantic_guard.manage'));

DELETE FROM permissions WHERE code IN ('semantic_guard.read', 'semantic_guard.manage');

DROP TABLE IF EXISTS semantic_guard_policy_versions;
DROP TABLE IF EXISTS semantic_guard_policies;

COMMIT;
