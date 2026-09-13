-- 网络诊断工具权限种子回滚

BEGIN;

DELETE FROM role_permissions WHERE permission_id IN (
  SELECT id FROM permissions WHERE code IN (
    'network_tools.execute','network_tools.download'
  )
);
DELETE FROM permissions WHERE code IN (
  'network_tools.execute','network_tools.download'
);

COMMIT;
