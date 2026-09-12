-- 000126 业务 JWT 信任链管理面权限种子（WDSP P0-03）。
--   jwt_trust.read    查看应用 JWT 信任策略（草稿/已发布版本/状态摘要/预检结果）；
--   jwt_trust.manage  编辑应用 JWT 信任策略（保存草稿 + 预检；发布走既有发布通道）。
-- 授权口径照 000099 惯例：只读三角色全授（SYSTEM_ADMIN/SECURITY_ADMIN/AUDIT_ADMIN），
-- manage 仅 SYSTEM_ADMIN/SECURITY_ADMIN。
BEGIN;

INSERT INTO permissions (code, name, module, description) VALUES
('jwt_trust.read',   '查看JWT信任策略', 'security', '查看应用业务JWT信任策略草稿、已发布版本与状态摘要'),
('jwt_trust.manage', '管理JWT信任策略', 'security', '编辑应用业务JWT信任策略并执行发布预检')
ON CONFLICT (code) DO NOTHING;

-- 系统管理员：全部 2 个权限点
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SYSTEM_ADMIN' AND p.code IN ('jwt_trust.read', 'jwt_trust.manage')
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- 安全管理员：全部 2 个权限点
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN' AND p.code IN ('jwt_trust.read', 'jwt_trust.manage')
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- 审计管理员：只读
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'AUDIT_ADMIN' AND p.code IN ('jwt_trust.read')
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
