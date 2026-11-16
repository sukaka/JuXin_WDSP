-- 容器运维权限种子回滚

BEGIN;

DELETE FROM role_permissions WHERE permission_id IN (
  SELECT id FROM permissions WHERE code IN (
    'containers.read','containers.logs','containers.control','containers.update'
  )
);
DELETE FROM permissions WHERE code IN (
  'containers.read','containers.logs','containers.control','containers.update'
);

COMMIT;
