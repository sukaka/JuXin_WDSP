BEGIN;

INSERT INTO permissions (code,name,module,description) VALUES
('request_pcap.read','查看请求PCAP状态','api','查看请求关联、完整性状态和非内容证据清单'),
('request_pcap.verify','核验请求PCAP完整性','api','填写理由执行有界完整性核验并记录审计'),
('request_pcap.download','下载请求PCAP证据','api','密码二次确认后按真实包范围执行单次派生下载')
ON CONFLICT (code) DO NOTHING;

INSERT INTO role_permissions (role_id,permission_id)
SELECT r.id,p.id FROM roles r,permissions p
WHERE r.code IN ('SECURITY_ADMIN','AUDIT_ADMIN') AND p.code IN ('request_pcap.read','request_pcap.verify')
ON CONFLICT (role_id,permission_id) DO NOTHING;

INSERT INTO role_permissions (role_id,permission_id)
SELECT r.id,p.id FROM roles r,permissions p
WHERE r.code='SECURITY_ADMIN' AND p.code='request_pcap.download'
ON CONFLICT (role_id,permission_id) DO NOTHING;

COMMIT;
