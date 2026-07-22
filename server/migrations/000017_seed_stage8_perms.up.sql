BEGIN;

INSERT INTO permissions (code, name, module, description) VALUES
('api_endpoints.read',     '查看API端点',   'api', '查看API资产与发现结果'),
('api_endpoints.manage',   '管理API端点',   'api', '确认/废弃API端点'),
('api_models.read',        '查看API模型',   'api', '查看学习版本与正式模型'),
('api_models.manage',      '管理API模型',   'api', '确认冻结/候选模型'),
('api_runtime_events.read','查看API运行事件','api', '查看统一API运行时事件')
ON CONFLICT (code) DO NOTHING;

-- 安全管理员：API 资产与模型全量
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN' AND p.code IN (
  'api_endpoints.read','api_endpoints.manage',
  'api_models.read','api_models.manage',
  'api_runtime_events.read'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- 审计管理员：只读
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'AUDIT_ADMIN' AND p.code IN (
  'api_endpoints.read','api_models.read','api_runtime_events.read'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- 系统管理员：只读端点/事件（运维可见）
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SYSTEM_ADMIN' AND p.code IN (
  'api_endpoints.read','api_runtime_events.read'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
