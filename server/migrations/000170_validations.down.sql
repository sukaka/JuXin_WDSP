-- 000170 回滚：移除模拟报告表与 api_protection.validate 权限种子。
BEGIN;

DELETE FROM role_permissions WHERE permission_id IN (
  SELECT id FROM permissions WHERE code IN ('api_protection.validate')
);
DELETE FROM permissions WHERE code IN ('api_protection.validate');

DROP TABLE IF EXISTS validation_reports;

COMMIT;
