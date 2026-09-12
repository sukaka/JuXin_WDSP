-- 000078 回滚：删除 license.* 权限点及角色关联、licenses 表
BEGIN;

DELETE FROM role_permissions WHERE permission_id IN (
  SELECT id FROM permissions WHERE code IN ('license.read','license.manage')
);
DELETE FROM permissions WHERE code IN ('license.read','license.manage');

DROP TABLE IF EXISTS licenses;

COMMIT;
