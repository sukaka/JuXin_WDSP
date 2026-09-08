-- 000099 client_identity 体系与行为策略权限种子（WDSP AI 自动化渗透防护增强 阶段1）。
--   security_identities.read  查看客户身份（身份列表/详情/行为序列/信号事件）；
--   behavior_policy.read      查看行为策略；
--   behavior_policy.edit      编辑行为策略（全量更新 + 乐观锁 + 触发发布）。
-- 三权口径与 000019/000063 一致：只读三角色全授，编辑仅 SYSTEM_ADMIN/SECURITY_ADMIN。
BEGIN;

INSERT INTO permissions (code, name, module, description) VALUES
('security_identities.read', '查看客户身份', 'security', '查看客户身份列表、身份详情、行为窗口序列与侦察信号事件'),
('behavior_policy.read',     '查看行为策略', 'security', '查看侦察/枚举行为检测全局策略'),
('behavior_policy.edit',     '编辑行为策略', 'security', '编辑侦察/枚举行为检测全局策略并触发网关发布')
ON CONFLICT (code) DO NOTHING;

-- 系统管理员：全部 3 个权限点
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SYSTEM_ADMIN' AND p.code IN (
  'security_identities.read','behavior_policy.read','behavior_policy.edit'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- 安全管理员：全部 3 个权限点
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN' AND p.code IN (
  'security_identities.read','behavior_policy.read','behavior_policy.edit'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- 审计管理员：只读
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'AUDIT_ADMIN' AND p.code IN (
  'security_identities.read','behavior_policy.read'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
