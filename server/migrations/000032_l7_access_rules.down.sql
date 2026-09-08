-- L7 访问控制规则回滚：权限点种子 + 表 + 索引
BEGIN;

DELETE FROM role_permissions WHERE permission_id IN (
  SELECT id FROM permissions WHERE code IN (
    'l7rules.read','l7rules.create','l7rules.update','l7rules.delete','l7rules.publish'
  )
);
DELETE FROM permissions WHERE code IN (
  'l7rules.read','l7rules.create','l7rules.update','l7rules.delete','l7rules.publish'
);

DROP INDEX IF EXISTS idx_ac_events_access_rule;
DROP TABLE IF EXISTS l7_access_rules;

COMMIT;
