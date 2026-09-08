-- 系统控制权限种子回滚

BEGIN;

DELETE FROM role_permissions WHERE permission_id IN (
  SELECT id FROM permissions WHERE code IN (
    'system.reboot','system.shutdown','system.factory_reset'
  )
);
DELETE FROM permissions WHERE code IN (
  'system.reboot','system.shutdown','system.factory_reset'
);

COMMIT;
