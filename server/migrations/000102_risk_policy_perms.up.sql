-- 000102 风险策略权限种子（WDSP AI 自动化渗透防护增强 阶段3）。
--   risk_policy.read  查看身份风险处置策略；
--   risk_policy.edit  编辑身份风险处置策略（全量更新 + 乐观锁 + 触发发布；
--                     OBSERVE→PROTECT 升级为高风险审计）。
-- 授予口径：read 照 000099 对 behavior_policy.read 的授予集合（三内置角色）；
--   edit 仅 SECURITY_ADMIN——000100_role_perm_rebalance 已把 behavior_policy.* 编辑权
--   从 SYSTEM_ADMIN 移交 SECURITY_ADMIN，新权限编辑权与之对齐（SYSTEM_ADMIN 不再授予 edit）。
BEGIN;

INSERT INTO permissions (code, name, module, description) VALUES
('risk_policy.read', '查看风险策略', 'security', '查看身份风险处置全局策略（阻断/限速阈值、信号分值与风险等级）'),
('risk_policy.edit', '编辑风险策略', 'security', '编辑身份风险处置全局策略并触发网关发布')
ON CONFLICT (code) DO NOTHING;

-- 系统管理员：只读（编辑权已随 000100 口径划归安全管理员）
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SYSTEM_ADMIN' AND p.code IN ('risk_policy.read')
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- 安全管理员：读 + 编辑
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN' AND p.code IN ('risk_policy.read', 'risk_policy.edit')
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- 审计管理员：只读
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'AUDIT_ADMIN' AND p.code IN ('risk_policy.read')
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
