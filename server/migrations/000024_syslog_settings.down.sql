-- 回滚 000024_syslog_settings：删除 syslog 外发设置与权限点
BEGIN;

DELETE FROM role_permissions WHERE permission_id IN (
  SELECT id FROM permissions WHERE code = 'logging.syslog_test'
);
DELETE FROM permissions WHERE code = 'logging.syslog_test';

DELETE FROM system_settings WHERE setting_group = 'logging' AND setting_key IN (
  'syslog_enabled', 'syslog_protocol', 'syslog_address', 'syslog_facility',
  'syslog_forward_security_events', 'syslog_forward_access_control_events',
  'syslog_forward_access_logs'
);

COMMIT;
