-- 000169 统一执行覆盖查询权限种子（NG-COV-02 查询侧；RD_PLAN §13.2 候选权限
-- api_protection.read）。
--
--   api_protection.read：「统一执行覆盖查询」，module api_protection；只读权限点，
--     保护 GET /api/v1/api-security/protection/coverage（覆盖聚合 agg / 节点阶段
--     计数 stages 两视图）。
--   角色口径（与 000100 再平衡后一致）：SECURITY_ADMIN（安全运营域）与
--     AUDIT_ADMIN（纯审计角色，只读契合）授予；SYSTEM_ADMIN 不授——执行覆盖
--     属安全运营域数据，非系统管理域（对照 000161 network_tools 属系统域仅授
--     SYSTEM_ADMIN，两者域分工正交）。
BEGIN;

INSERT INTO permissions (code, name, module, description) VALUES
('api_protection.read', '统一执行覆盖查询', 'api_protection', '查询统一执行覆盖（五态聚合与节点阶段计数快照；NG-COV-01/02）')
ON CONFLICT (code) DO NOTHING;

-- 安全管理员 + 审计管理员（只读）
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code IN ('SECURITY_ADMIN', 'AUDIT_ADMIN') AND p.code IN ('api_protection.read')
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- 系统管理员不授予（安全运营域，与 network_tools 系统域分工正交）。

COMMIT;
