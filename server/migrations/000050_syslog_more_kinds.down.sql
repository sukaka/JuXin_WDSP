-- 回滚 000047_syslog_more_kinds：删除 3 个 syslog 外发开关设置
BEGIN;

DELETE FROM system_settings WHERE setting_group = 'logging' AND setting_key IN (
  'syslog_forward_operation_audits', 'syslog_forward_login_logs', 'syslog_forward_system_alerts'
);

COMMIT;
