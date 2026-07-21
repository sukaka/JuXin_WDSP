-- 阶段4 种子：三套内置防护策略模板 + 阶段4权限

BEGIN;

-- ---------- 内置防护策略模板（部分唯一索引不支持 ON CONFLICT (code)，用 WHERE NOT EXISTS） ----------
INSERT INTO protection_policies (code, name, description, is_builtin, status, protection_mode,
  paranoia_level, inbound_anomaly_threshold, outbound_anomaly_threshold,
  request_body_access, response_body_access)
SELECT 'relaxed', '宽松策略', '适用于首次上线和复杂旧系统。观察模式，PL1，较高入站阈值，建议先观察后开启阻断。', TRUE, 'ACTIVE', 'OBSERVE', 1, 10, 5, TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM protection_policies WHERE code = 'relaxed');

INSERT INTO protection_policies (code, name, description, is_builtin, status, protection_mode,
  paranoia_level, inbound_anomaly_threshold, outbound_anomaly_threshold,
  request_body_access, response_body_access)
SELECT 'standard', '标准策略', '适用于常规生产系统。防护模式，PL1，标准阈值。', TRUE, 'ACTIVE', 'PROTECT', 1, 5, 4, TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM protection_policies WHERE code = 'standard');

INSERT INTO protection_policies (code, name, description, is_builtin, status, protection_mode,
  paranoia_level, inbound_anomaly_threshold, outbound_anomaly_threshold,
  request_body_access, response_body_access)
SELECT 'strict', '严格策略', '适用于高安全要求应用。防护模式，PL2，更低阈值，启用前必须完成误报测试。', TRUE, 'ACTIVE', 'PROTECT', 2, 5, 4, TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM protection_policies WHERE code = 'strict');

-- ---------- 阶段4权限 ----------
INSERT INTO permissions (code, name, module, description) VALUES
('protection_policies.read',     '查看防护策略', 'policies',  '查看WAF防护策略'),
('protection_policies.create',   '创建防护策略', 'policies',  '创建WAF防护策略'),
('protection_policies.update',   '修改防护策略', 'policies',  '修改WAF防护策略'),
('protection_policies.delete',   '删除防护策略', 'policies',  '删除未引用防护策略'),
('protection_policies.publish',  '发布防护策略', 'policies',  '发布WAF防护策略'),
('waf_rules.read',               '查看WAF规则',  'waf_rules', '查看CRS与自定义规则'),
('waf_rules.sync',               '同步CRS规则',  'waf_rules', '同步CRS规则元数据'),
('rule_overrides.manage',        '规则覆盖管理', 'waf_rules', '创建与管理规则覆盖'),
('custom_rules.manage',          '自定义规则管理','custom_rules','创建与管理自定义规则'),
('exceptions.read',              '查看例外策略', 'exceptions','查看例外策略'),
('exceptions.manage',            '例外策略管理', 'exceptions','创建与管理例外策略'),
('security_events.read',         '查看安全事件', 'security_events','查看安全事件列表与详情'),
('security_events.disposition',  '处置安全事件', 'security_events','确认攻击/误报/忽略/备注'),
('security_events.export',       '导出安全事件', 'security_events','导出安全事件'),
('policy_versions.read',         '查看策略版本', 'policies',  '查看策略版本与差异')
ON CONFLICT (code) DO NOTHING;

-- 安全管理员：全量业务权限
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN' AND p.code IN (
  'protection_policies.read','protection_policies.create','protection_policies.update','protection_policies.delete','protection_policies.publish',
  'waf_rules.read','waf_rules.sync','rule_overrides.manage','custom_rules.manage',
  'exceptions.read','exceptions.manage',
  'security_events.read','security_events.disposition','security_events.export',
  'policy_versions.read'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- 审计管理员：只读
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'AUDIT_ADMIN' AND p.code IN (
  'protection_policies.read','waf_rules.read','exceptions.read',
  'security_events.read','policy_versions.read'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
