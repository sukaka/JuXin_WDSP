-- 阶段7 种子：AI 权限（安全管理员全量AI分析能力；系统管理员运维诊断；审计管理员只读审计）

BEGIN;

INSERT INTO permissions (code, name, module, description) VALUES
('ai.chat.use',                    '使用AI安全助手',   'ai', 'AI安全助手多轮对话'),
('ai.event_analysis.use',          '安全事件AI分析',   'ai', '单事件与批量事件AI分析'),
('ai.false_positive_analysis.use', '误报AI分析',       'ai', '误报研判与例外建议'),
('ai.attack_profile.use',          '攻击画像',         'ai', 'IP/URI/应用攻击画像'),
('ai.attack_chain.use',            '攻击链分析',       'ai', '攻击链关联分析'),
('ai.root_cause.use',              '根因分析',         'ai', '运行异常根因分析'),
('ai.policy_recommendation.use',   '策略优化建议',     'ai', 'WAF策略优化建议与What-If'),
('ai.what_if.use',                 'What-If模拟',      'ai', '策略变更历史模拟'),
('ai.report_summary.use',          'AI报告总结',       'ai', '日报周报月报AI总结'),
('ai.draft.exception',             '生成例外草稿',     'ai', 'AI生成例外策略草稿'),
('ai.draft.blacklist',             '生成黑名单草稿',   'ai', 'AI生成黑名单草稿'),
('ai.draft.cc_policy',             '生成CC策略草稿',   'ai', 'AI生成CC策略草稿'),
('ai.draft.custom_rule',           '生成自定义规则草稿','ai', 'AI生成自定义规则草稿'),
('ai.sessions.read_own',           '查看本人AI会话',   'ai', '查看与使用本人AI会话'),
('ai.sessions.delete_own',         '删除本人AI会话',   'ai', '删除与归档本人AI会话'),
('ai.memories.read_own',           '查看本人AI记忆',   'ai', '查看本人AI记忆'),
('ai.memories.manage_own',         '管理本人AI记忆',   'ai', '新增/修改/禁用/删除本人AI记忆'),
('ai.models.read',                 '查看AI模型',       'ai', '查看模型配置与连通性健康检查'),
('ai.models.manage',               '管理AI模型',       'ai', '配置/启停模型与密钥轮换、路由档位'),
('ai.agents.read',                 '查看Agent',        'ai', '查看Agent配置与调用记录'),
('ai.agents.manage',               '管理Agent',        'ai', '配置Agent与测试'),
('ai.tools.read',                  '查看Tool',         'ai', '查看Tool配置与调用记录'),
('ai.tools.manage',                '管理Tool',         'ai', '配置Tool与测试'),
('ai.prompts.read',                '查看Prompt',       'ai', '查看Prompt与版本'),
('ai.prompts.create',              '创建Prompt',       'ai', '创建Prompt与版本'),
('ai.prompts.test',                '测试Prompt',       'ai', 'Prompt回归与对抗测试'),
('ai.prompts.publish',             '发布Prompt',       'ai', '发布Prompt版本'),
('ai.prompts.rollback',            '回滚Prompt',       'ai', '回滚Prompt版本'),
('ai.audits.read',                 '查看AI审计',       'ai', '查看AI调用与Tool调用审计'),
('ai.usage.read',                  '查看AI用量',       'ai', '查看Token与成本统计'),
('ai.evaluations.run',             '运行AI评估',       'ai', '执行评估集与回归')
ON CONFLICT (code) DO NOTHING;

-- 安全管理员：AI 分析与草稿全量（不含模型/Agent/Tool/Prompt管理）
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN' AND p.code IN (
  'ai.chat.use','ai.event_analysis.use','ai.false_positive_analysis.use',
  'ai.attack_profile.use','ai.attack_chain.use','ai.root_cause.use',
  'ai.policy_recommendation.use','ai.what_if.use','ai.report_summary.use',
  'ai.draft.exception','ai.draft.blacklist','ai.draft.cc_policy','ai.draft.custom_rule',
  'ai.sessions.read_own','ai.sessions.delete_own','ai.memories.read_own','ai.memories.manage_own',
  'ai.models.read','ai.agents.read','ai.tools.read','ai.prompts.read','ai.audits.read','ai.usage.read'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- 系统管理员：AI 运维诊断 + 模型/Agent/Tool/Prompt/评估管理
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SYSTEM_ADMIN' AND p.code IN (
  'ai.chat.use','ai.root_cause.use',
  'ai.sessions.read_own','ai.sessions.delete_own','ai.memories.read_own','ai.memories.manage_own',
  'ai.models.read','ai.models.manage',
  'ai.agents.read','ai.agents.manage','ai.tools.read','ai.tools.manage',
  'ai.prompts.read','ai.prompts.create','ai.prompts.test','ai.prompts.publish','ai.prompts.rollback',
  'ai.audits.read','ai.usage.read','ai.evaluations.run'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- 审计管理员：AI 审计只读
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'AUDIT_ADMIN' AND p.code IN (
  'ai.audits.read','ai.usage.read'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
