-- syslog 外发范围扩展（六类）：新增操作审计/登录日志/系统告警外发开关
BEGIN;

INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, is_sensitive, description) VALUES
('logging', 'syslog_forward_operation_audits', 'true', 'boolean', FALSE, '外发操作审计到 syslog'),
('logging', 'syslog_forward_login_logs',       'true', 'boolean', FALSE, '外发登录日志到 syslog'),
('logging', 'syslog_forward_system_alerts',    'true', 'boolean', FALSE, '外发系统告警到 syslog')
ON CONFLICT (setting_group, setting_key) DO NOTHING;

COMMIT;
