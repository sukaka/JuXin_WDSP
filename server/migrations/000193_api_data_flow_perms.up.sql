BEGIN;

INSERT INTO permissions (code, name, module, description) VALUES
('api_data_flow.read', '查看数据流向', 'api', '查看服务/API/Kafka数据流图、节点和采集质量'),
('api_data_flow.evidence.read', '查看数据流证据', 'api', '查看数据流字段级脱敏证据与样本Trace')
ON CONFLICT (code) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id,p.id FROM roles r,permissions p
WHERE r.code='SECURITY_ADMIN' AND p.code IN ('api_data_flow.read','api_data_flow.evidence.read')
ON CONFLICT (role_id,permission_id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id,p.id FROM roles r,permissions p
WHERE r.code='AUDIT_ADMIN' AND p.code IN ('api_data_flow.read','api_data_flow.evidence.read')
ON CONFLICT (role_id,permission_id) DO NOTHING;

COMMIT;
