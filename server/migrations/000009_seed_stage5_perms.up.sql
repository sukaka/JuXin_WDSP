-- 阶段5 种子：访问控制与CC防护权限
-- 安全管理员：全量；审计管理员：只读；系统管理员：系统可信代理与保护地址维护

BEGIN;

INSERT INTO permissions (code, name, module, description) VALUES
('trusted_proxies.read',        '查看可信代理',   'access_control', '查看可信代理配置'),
('trusted_proxies.manage',      '管理可信代理',   'access_control', '创建与管理可信代理'),
('protected_addresses.read',    '查看保护地址',   'access_control', '查看保护地址'),
('protected_addresses.manage',  '管理保护地址',   'access_control', '维护自定义保护地址与刷新'),
('access_rules.read',           '查看IP黑白名单', 'access_control', '查看IP访问控制规则'),
('access_rules.manage',         '管理IP黑白名单', 'access_control', '创建与管理IP访问控制规则'),
('access_rules.publish',        '发布访问控制',   'access_control', '发布访问控制配置到网关'),
('access_rules.import',         '导入黑白名单',   'access_control', '批量导入IP访问控制规则'),
('rate_limits.read',            '查看CC策略',     'access_control', '查看CC防护策略'),
('rate_limits.manage',          '管理CC策略',     'access_control', '创建与管理CC防护策略'),
('rate_limits.publish',         '发布CC策略',     'access_control', '发布CC防护配置到网关'),
('temporary_blocks.read',       '查看临时封禁',   'access_control', '查看临时封禁记录'),
('temporary_blocks.manage',     '管理临时封禁',   'access_control', '解封/延期/转永久临时封禁'),
('access_control_events.read',  '查看访问控制事件','access_control','查看访问控制与CC事件'),
('access_control_events.export','导出访问控制事件','access_control','导出访问控制与CC事件'),
('access_control_versions.read','查看访问控制版本','access_control','查看访问控制配置版本与差异'),
('access_control_versions.rollback','回滚访问控制版本','access_control','回滚访问控制配置到历史版本')
ON CONFLICT (code) DO NOTHING;

-- 安全管理员：全量
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN' AND p.code IN (
  'trusted_proxies.read','trusted_proxies.manage',
  'protected_addresses.read','protected_addresses.manage',
  'access_rules.read','access_rules.manage','access_rules.publish','access_rules.import',
  'rate_limits.read','rate_limits.manage','rate_limits.publish',
  'temporary_blocks.read','temporary_blocks.manage',
  'access_control_events.read','access_control_events.export',
  'access_control_versions.read','access_control_versions.rollback'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- 审计管理员：只读
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'AUDIT_ADMIN' AND p.code IN (
  'trusted_proxies.read','protected_addresses.read',
  'access_rules.read','rate_limits.read',
  'temporary_blocks.read','access_control_events.read','access_control_versions.read'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- 系统管理员：系统可信代理与保护地址维护（组件级，不含业务黑白名单与CC策略）
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SYSTEM_ADMIN' AND p.code IN (
  'trusted_proxies.read','trusted_proxies.manage',
  'protected_addresses.read','protected_addresses.manage'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
