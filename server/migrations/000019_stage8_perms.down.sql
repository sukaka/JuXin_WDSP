-- 000019 回滚：恢复 000017 的 5 个临时权限点，删除阶段8 正式 27 个权限点
BEGIN;

-- 删除阶段8 正式权限点及其角色关联
DELETE FROM role_permissions WHERE permission_id IN (
  SELECT id FROM permissions WHERE code IN (
    'api_asset.read','api_asset.confirm','api_asset.edit','api_asset.merge','api_asset.split','api_asset.ignore',
    'api_learning.read','api_learning.start','api_learning.stop',
    'api_model.read','api_model.edit','api_model.review','api_model.confirm','api_model.activate','api_model.archive',
    'api_parameter.read','api_parameter.edit',
    'api_classification.read','api_classification.manage',
    'api_spec.read','api_spec.import',
    'api_graph.read','api_runtime.read',
    'api_policy.read','api_policy.edit','api_policy.publish',
    'api_audit.read'
  )
);
DELETE FROM permissions WHERE code IN (
  'api_asset.read','api_asset.confirm','api_asset.edit','api_asset.merge','api_asset.split','api_asset.ignore',
  'api_learning.read','api_learning.start','api_learning.stop',
  'api_model.read','api_model.edit','api_model.review','api_model.confirm','api_model.activate','api_model.archive',
  'api_parameter.read','api_parameter.edit',
  'api_classification.read','api_classification.manage',
  'api_spec.read','api_spec.import',
  'api_graph.read','api_runtime.read',
  'api_policy.read','api_policy.edit','api_policy.publish',
  'api_audit.read'
);

-- 恢复 000017 临时权限点
INSERT INTO permissions (code, name, module, description) VALUES
('api_endpoints.read',     '查看API端点',   'api', '查看API资产与发现结果'),
('api_endpoints.manage',   '管理API端点',   'api', '确认/废弃API端点'),
('api_models.read',        '查看API模型',   'api', '查看学习版本与正式模型'),
('api_models.manage',      '管理API模型',   'api', '确认冻结/候选模型'),
('api_runtime_events.read','查看API运行事件','api', '查看统一API运行时事件')
ON CONFLICT (code) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN' AND p.code IN (
  'api_endpoints.read','api_endpoints.manage','api_models.read','api_models.manage','api_runtime_events.read'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'AUDIT_ADMIN' AND p.code IN (
  'api_endpoints.read','api_models.read','api_runtime_events.read'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SYSTEM_ADMIN' AND p.code IN (
  'api_endpoints.read','api_runtime_events.read'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
