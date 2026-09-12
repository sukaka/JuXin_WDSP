-- 000129 应用级 Bot 策略管理面权限种子（WDSP P1-02 B1）。
--   bot_policy.read  查看应用 Bot 策略（草稿/已发布版本/节点同步状态摘要）；
--   bot_policy.edit  编辑应用 Bot 策略（保存草稿 + 路由保留冲突预检；保存后经既有
--                    发布通道触发发布，命名对齐 risk_policy.edit 口径）。
-- 授权口径照 000126/000099 惯例：只读三角色全授（SYSTEM_ADMIN/SECURITY_ADMIN/AUDIT_ADMIN），
-- edit 仅 SYSTEM_ADMIN/SECURITY_ADMIN。
BEGIN;

INSERT INTO permissions (code, name, module, description) VALUES
('bot_policy.read', '查看Bot策略', 'security', '查看应用Bot挑战策略草稿、已发布版本与节点同步状态摘要'),
('bot_policy.edit', '管理Bot策略', 'security', '编辑应用Bot挑战策略并执行路由保留冲突预检')
ON CONFLICT (code) DO NOTHING;

-- 系统管理员：全部 2 个权限点
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SYSTEM_ADMIN' AND p.code IN ('bot_policy.read', 'bot_policy.edit')
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- 安全管理员：全部 2 个权限点
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN' AND p.code IN ('bot_policy.read', 'bot_policy.edit')
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- 审计管理员：只读
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'AUDIT_ADMIN' AND p.code IN ('bot_policy.read')
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
