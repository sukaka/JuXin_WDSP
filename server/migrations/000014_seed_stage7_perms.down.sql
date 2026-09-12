-- 阶段7 权限种子回滚

BEGIN;

DELETE FROM role_permissions WHERE permission_id IN (
  SELECT id FROM permissions WHERE code LIKE 'ai.%'
);
DELETE FROM permissions WHERE code LIKE 'ai.%';

COMMIT;
