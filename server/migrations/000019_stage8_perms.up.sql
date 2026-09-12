-- 阶段8 任务书第五十二章：API 动态防护 27 个权限点种子。
-- 000017 的 5 个临时权限点（api_endpoints.*/api_models.*/api_runtime_events.*）随命名空间
-- /api/v1/api-security/* 启用一并替换（阶段8 未发版，无兼容负担）。
BEGIN;

INSERT INTO permissions (code, name, module, description) VALUES
('api_asset.read',          '查看API资产',      'api', '查看API端点资产与发现结果'),
('api_asset.confirm',       '确认API资产',      'api', '确认发现的API端点为正式资产'),
('api_asset.edit',          '编辑API资产',      'api', '编辑API端点资产属性'),
('api_asset.merge',         '合并API端点',      'api', '合并重复/误拆的API端点'),
('api_asset.split',         '拆分API端点',      'api', '拆分误合并的API端点'),
('api_asset.ignore',        '忽略API端点',      'api', '将API端点标记为忽略'),
('api_learning.read',       '查看学习任务',     'api', '查看API学习状态与样本统计'),
('api_learning.start',      '启动API学习',      'api', '启动端点模型学习任务'),
('api_learning.stop',       '停止API学习',      'api', '停止端点模型学习任务'),
('api_model.read',          '查看API模型',      'api', '查看模型版本与差异'),
('api_model.edit',          '编辑API模型',      'api', '编辑候选模型内容'),
('api_model.review',        '评审API模型',      'api', '提交/执行模型评审'),
('api_model.confirm',       '确认API模型',      'api', '确认候选模型冻结为正式模型'),
('api_model.activate',      '激活API模型',      'api', '激活正式模型版本'),
('api_model.archive',       '归档API模型',      'api', '归档历史模型版本'),
('api_parameter.read',      '查看参数模型',     'api', '查看参数模型与约束'),
('api_parameter.edit',      '编辑参数模型',     'api', '修改参数确认约束'),
('api_classification.read', '查看用途分类',     'api', '查看API用途分类与维度'),
('api_classification.manage','管理用途分类',    'api', '维护分类体系与端点分类'),
('api_spec.read',           '查看规范导入',     'api', '查看导入的API规范与对比'),
('api_spec.import',         '导入API规范',      'api', '导入OpenAPI规范并触发对比'),
('api_graph.read',          '查看API图谱',      'api', '查看API调用图谱与拓扑'),
('api_runtime.read',        '查看API运行时',    'api', '查看API运行时事件与统计'),
('api_policy.read',         '查看API策略',      'api', '查看API动态防护策略'),
('api_policy.edit',         '编辑API策略',      'api', '编辑API动态防护策略'),
('api_policy.publish',      '发布API策略',      'api', '发布API动态防护策略到网关'),
('api_audit.read',          '查看API审计',      'api', '查看API动态防护操作审计')
ON CONFLICT (code) DO NOTHING;

-- 安全管理员：全部 27 个权限点
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN' AND p.code IN (
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
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- 审计管理员：全部只读权限（含 API 审计）
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'AUDIT_ADMIN' AND p.code IN (
  'api_asset.read','api_learning.read','api_model.read','api_parameter.read',
  'api_classification.read','api_spec.read','api_graph.read','api_runtime.read',
  'api_policy.read','api_audit.read'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- 系统管理员：资产/运行时/策略只读（运维可见，与 000017 口径一致）
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SYSTEM_ADMIN' AND p.code IN (
  'api_asset.read','api_runtime.read','api_policy.read'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- 移除 000017 的 5 个临时权限点（路由已切换命名空间）
DELETE FROM role_permissions WHERE permission_id IN (
  SELECT id FROM permissions WHERE code IN (
    'api_endpoints.read','api_endpoints.manage','api_models.read','api_models.manage','api_runtime_events.read'
  )
);
DELETE FROM permissions WHERE code IN (
  'api_endpoints.read','api_endpoints.manage','api_models.read','api_models.manage','api_runtime_events.read'
);

COMMIT;
