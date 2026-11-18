BEGIN;
INSERT INTO permissions (code,name,module,description) VALUES
('request_pcap.capture_control','控制系统管理员PCAP采集','api','仅系统管理员配置采集范围并启动或停止pcapd，关闭不删除历史证据')
ON CONFLICT (code) DO NOTHING;
INSERT INTO role_permissions (role_id,permission_id)
SELECT r.id,p.id FROM roles r,permissions p WHERE r.code='SYSTEM_ADMIN' AND p.code='request_pcap.capture_control'
ON CONFLICT (role_id,permission_id) DO NOTHING;
COMMIT;
