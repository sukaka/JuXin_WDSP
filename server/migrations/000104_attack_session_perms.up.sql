-- 000104 攻击活动会话权限种子（WDSP AI 自动化渗透防护增强 阶段4）。
--   attack_sessions.read  查看攻击活动会话列表与事件明细（只读；会话由聚合器异步维护，
--                         无管理面写接口，故不设 edit 权限点）。
-- 授予口径：照 000102 先例对 SYSTEM_ADMIN/SECURITY_ADMIN/AUDIT_ADMIN 三内置角色授予只读
--   （本权限无编辑面，000100 的编辑权移交口径不涉及；审计管理员可只读审计攻击活动）。
BEGIN;

INSERT INTO permissions (code, name, module, description) VALUES
('attack_sessions.read', '查看攻击活动', 'security', '查看攻击活动会话（Attack Session）列表与事件明细')
ON CONFLICT (code) DO NOTHING;

-- 系统管理员 / 安全管理员 / 审计管理员：只读
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code IN ('SYSTEM_ADMIN', 'SECURITY_ADMIN', 'AUDIT_ADMIN')
  AND p.code IN ('attack_sessions.read')
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
