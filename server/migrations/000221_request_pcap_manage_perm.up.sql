BEGIN;
INSERT INTO permissions (code,name,module,description) VALUES
('request_pcap.manage','管理请求PCAP密钥','api','密码二次确认后轮转证据密钥并签发节点公钥，保留历史证据解封能力')
ON CONFLICT (code) DO NOTHING;
INSERT INTO role_permissions (role_id,permission_id)
SELECT r.id,p.id FROM roles r,permissions p WHERE r.code='SECURITY_ADMIN' AND p.code='request_pcap.manage'
ON CONFLICT (role_id,permission_id) DO NOTHING;
COMMIT;
