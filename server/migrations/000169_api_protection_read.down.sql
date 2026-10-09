-- 000169 回滚：移除统一执行覆盖查询权限点与角色映射。
BEGIN;

DELETE FROM role_permissions WHERE permission_id IN (
  SELECT id FROM permissions WHERE code IN ('api_protection.read')
);
DELETE FROM permissions WHERE code IN ('api_protection.read');

COMMIT;
