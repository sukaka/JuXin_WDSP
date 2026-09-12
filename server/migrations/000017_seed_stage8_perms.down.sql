BEGIN;
DELETE FROM role_permissions WHERE permission_id IN (
  SELECT id FROM permissions WHERE code LIKE 'api_%'
);
DELETE FROM permissions WHERE code LIKE 'api_%';
COMMIT;
