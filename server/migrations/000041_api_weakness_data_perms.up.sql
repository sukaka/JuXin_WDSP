-- API 安全补全：弱点中心（api_weakness.*）与敏感数据管理面（api_data.*）权限点种子。
-- 三权分配口径与 000019 一致：SECURITY_ADMIN 全量；AUDIT_ADMIN 只读；
-- SYSTEM_ADMIN 仅弱点只读（运维可见整改工单，不涉敏感数据内容）。
BEGIN;

INSERT INTO permissions (code, name, module, description) VALUES
('api_weakness.read',   '查看API弱点',   'api', '查看API弱点列表与详情'),
('api_weakness.handle', '处置API弱点',   'api', '弱点确认/指派/整改/复测/忽略/归档'),
('api_data.read',       '查看敏感数据',  'api', '查看敏感数据类型/态势与脱敏规则'),
('api_data.manage',     '管理敏感数据',  'api', '维护敏感数据类型与响应脱敏规则')
ON CONFLICT (code) DO NOTHING;

-- 安全管理员：全部 4 个权限点
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN' AND p.code IN (
  'api_weakness.read','api_weakness.handle','api_data.read','api_data.manage'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- 审计管理员：只读
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'AUDIT_ADMIN' AND p.code IN ('api_weakness.read','api_data.read')
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- 系统管理员：仅弱点只读
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SYSTEM_ADMIN' AND p.code IN ('api_weakness.read')
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
