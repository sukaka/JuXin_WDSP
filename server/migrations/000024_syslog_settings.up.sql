-- syslog 外发（三期）：系统设置种子 + logging.syslog_test 权限点
BEGIN;

INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, is_sensitive, description) VALUES
('logging', 'syslog_enabled',                      'false', 'boolean', FALSE, 'syslog 外发总开关'),
('logging', 'syslog_protocol',                     '"udp"', 'string',  FALSE, 'syslog 传输协议（udp / tcp）'),
('logging', 'syslog_address',                      '""',    'string',  FALSE, 'syslog 服务器地址（host:port）'),
('logging', 'syslog_facility',                     '1',     'integer', FALSE, 'syslog facility 数值（默认 1=user-level）'),
('logging', 'syslog_forward_security_events',      'true',  'boolean', FALSE, '外发安全事件到 syslog'),
('logging', 'syslog_forward_access_control_events','true',  'boolean', FALSE, '外发访问控制事件到 syslog'),
('logging', 'syslog_forward_access_logs',          'false', 'boolean', FALSE, '外发全量访问日志到 syslog')
ON CONFLICT (setting_group, setting_key) DO NOTHING;

-- 权限点：发送 syslog 测试消息
INSERT INTO permissions (code, name, module, description) VALUES
('logging.syslog_test', '发送syslog测试消息', 'system', '向配置的 syslog 服务器发送测试消息')
ON CONFLICT (code) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code IN ('SYSTEM_ADMIN', 'SECURITY_ADMIN') AND p.code = 'logging.syslog_test'
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
