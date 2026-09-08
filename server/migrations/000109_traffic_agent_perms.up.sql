-- 000109 流量采集 Agent 权限种子（WDSP 分布式流量采集 Agent Phase 1，契约 §4/§7）。
--   traffic.agents.view   查看 Agent/令牌/流量事件/策略（GET）；
--   traffic.agents.manage 令牌签发/撤销、Agent 禁用/启用/删除、策略 CRUD 与绑定（写操作，HIGH 级审计）。
-- 授予口径（契约 §7 冻结）：view 授 SYSTEM_ADMIN/SECURITY_ADMIN/AUDIT_ADMIN；
--   manage 授 SYSTEM_ADMIN/SECURITY_ADMIN（AUDIT_ADMIN 不授——只读三权分离口径，
--   与 000102 风险策略 edit 的授予纪律不同，此处按契约原文执行）。
BEGIN;

INSERT INTO permissions (code, name, module, description) VALUES
('traffic.agents.view', '查看流量采集Agent', 'traffic', '查看流量采集 Agent、注册令牌、流量事件与采集策略'),
('traffic.agents.manage', '管理流量采集Agent', 'traffic', '签发/撤销注册令牌、禁用/启用/删除 Agent、采集策略 CRUD 与绑定下发')
ON CONFLICT (code) DO NOTHING;

-- 系统管理员：读 + 管理
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SYSTEM_ADMIN' AND p.code IN ('traffic.agents.view', 'traffic.agents.manage')
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- 安全管理员：读 + 管理
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN' AND p.code IN ('traffic.agents.view', 'traffic.agents.manage')
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- 审计管理员：只读
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'AUDIT_ADMIN' AND p.code IN ('traffic.agents.view')
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
