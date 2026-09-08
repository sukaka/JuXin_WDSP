-- API 安全补全第三波：授权基线（apiauthz 包）权限点种子。
-- 三权分配口径与 000019/000041 一致：SECURITY_ADMIN 全量；AUDIT_ADMIN 只读；SYSTEM_ADMIN 无。
BEGIN;

INSERT INTO permissions (code, name, module, description) VALUES
('api_authorization.read',   '查看授权基线', 'api', '查看角色基线/对象权属/字段权限与 BOLA 评估'),
('api_authorization.manage', '管理授权基线', 'api', '维护角色基线与字段权限配置')
ON CONFLICT (code) DO NOTHING;

-- 安全管理员：全部 2 个权限点
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN' AND p.code IN ('api_authorization.read','api_authorization.manage')
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- 审计管理员：只读
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'AUDIT_ADMIN' AND p.code IN ('api_authorization.read')
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
