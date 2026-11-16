BEGIN;

INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, is_sensitive, description) VALUES
('software_bypass', 'enabled', 'false', 'boolean', FALSE, 'CPU/内存超阈值时自动切换纯透传；保存后需发布配置'),
('software_bypass', 'cpu_threshold_percent', '80', 'integer', FALSE, 'CPU 使用率旁路触发阈值（严格大于，1-100）'),
('software_bypass', 'memory_threshold_percent', '80', 'integer', FALSE, '内存使用率旁路触发阈值（严格大于，1-100）'),
('software_bypass', 'min_hold_seconds', '10', 'integer', FALSE, '旁路最短保持秒数（1-300）；回落阈值为触发阈值减 5 个百分点'),
('software_bypass', 'session_cookie_names', '"JSESSIONID,PHPSESSID,SESSION,SESSIONID,connect.sid"', 'string', FALSE, 'HTTP 会话监控 Cookie 名（逗号分隔，最多 16 个；留空关闭会话统计）')
ON CONFLICT (setting_group, setting_key) DO NOTHING;

COMMIT;
