-- 阶段5 权限种子回滚

BEGIN;

DELETE FROM role_permissions WHERE permission_id IN (
  SELECT id FROM permissions WHERE code IN (
    'trusted_proxies.read','trusted_proxies.manage',
    'protected_addresses.read','protected_addresses.manage',
    'access_rules.read','access_rules.manage','access_rules.publish','access_rules.import',
    'rate_limits.read','rate_limits.manage','rate_limits.publish',
    'temporary_blocks.read','temporary_blocks.manage',
    'access_control_events.read','access_control_events.export',
    'access_control_versions.read','access_control_versions.rollback'
  )
);
DELETE FROM permissions WHERE code IN (
  'trusted_proxies.read','trusted_proxies.manage',
  'protected_addresses.read','protected_addresses.manage',
  'access_rules.read','access_rules.manage','access_rules.publish','access_rules.import',
  'rate_limits.read','rate_limits.manage','rate_limits.publish',
  'temporary_blocks.read','temporary_blocks.manage',
  'access_control_events.read','access_control_events.export',
  'access_control_versions.read','access_control_versions.rollback'
);

COMMIT;
