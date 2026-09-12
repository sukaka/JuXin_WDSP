-- 回滚 000005_seed_stage3_perms

BEGIN;

DELETE FROM role_permissions WHERE permission_id IN (
  SELECT id FROM permissions WHERE code IN (
    'applications.read','applications.create','applications.update','applications.disable','applications.delete','applications.publish','applications.rollback',
    'domains.read','domains.create','domains.update','domains.delete',
    'upstreams.read','upstreams.create','upstreams.update','upstreams.delete','upstreams.test',
    'certificates.read','certificates.create','certificates.update','certificates.delete','certificates.bind',
    'gateway_configs.preview','gateway_configs.validate','gateway_configs.publish','gateway_configs.rollback',
    'publish_tasks.read','config_versions.read','gateway_status.read','gateway_runtime.read',
    'certificates.read_metadata','applications.read_audit','upstreams.read_audit','gateway_changes.read'
  )
);
DELETE FROM permissions WHERE code IN (
  'applications.read','applications.create','applications.update','applications.disable','applications.delete','applications.publish','applications.rollback',
  'domains.read','domains.create','domains.update','domains.delete',
  'upstreams.read','upstreams.create','upstreams.update','upstreams.delete','upstreams.test',
  'certificates.read','certificates.create','certificates.update','certificates.delete','certificates.bind',
  'gateway_configs.preview','gateway_configs.validate','gateway_configs.publish','gateway_configs.rollback',
  'publish_tasks.read','config_versions.read','gateway_status.read','gateway_runtime.read',
  'certificates.read_metadata','applications.read_audit','upstreams.read_audit','gateway_changes.read'
);

COMMIT;
