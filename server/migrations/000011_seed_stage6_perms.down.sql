-- 阶段6 权限种子回滚

BEGIN;

DELETE FROM role_permissions WHERE permission_id IN (
  SELECT id FROM permissions WHERE code IN (
    'dashboard.security.read','dashboard.runtime.read','dashboard.audit.read',
    'analytics.security.read','analytics.disposition.read',
    'reports.read','reports.create','reports.download','reports.delete_own',
    'reports.read_audit','reports.download_audit','report_templates.manage',
    'system_health.read','system_alerts.read','system_alerts.read_security','system_alerts.read_audit',
    'system_alerts.acknowledge','system_alerts.acknowledge_security',
    'backups.read','backups.create','backups.verify','backups.restore','backups.delete',
    'backup_records.read','restore_records.read',
    'upgrades.read','upgrades.precheck','upgrades.execute','upgrades.rollback','upgrade_records.read',
    'delivery_checks.read','delivery_checks.run'
  )
);
DELETE FROM permissions WHERE code IN (
  'dashboard.security.read','dashboard.runtime.read','dashboard.audit.read',
  'analytics.security.read','analytics.disposition.read',
  'reports.read','reports.create','reports.download','reports.delete_own',
  'reports.read_audit','reports.download_audit','report_templates.manage',
  'system_health.read','system_alerts.read','system_alerts.read_security','system_alerts.read_audit',
  'system_alerts.acknowledge','system_alerts.acknowledge_security',
  'backups.read','backups.create','backups.verify','backups.restore','backups.delete',
  'backup_records.read','restore_records.read',
  'upgrades.read','upgrades.precheck','upgrades.execute','upgrades.rollback','upgrade_records.read',
  'delivery_checks.read','delivery_checks.run'
);

COMMIT;
