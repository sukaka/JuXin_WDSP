-- 000090 APM 阶段3 第一批查询接口：SQL 指纹聚合权限种子。
-- 依据 docs/BUSINESS_PERFORMANCE_APM_DESIGN.md §16.1（GET /api/v1/apm/sql →
-- apm.sql.read）；三权口径与 000088 一致：SECURITY_ADMIN 全量、AUDIT_ADMIN 只读
-- （本权限点为纯查询只读）、SYSTEM_ADMIN 不含业务观测权限。
-- 同批的 /apm/exceptions 复用 000088 的 apm.traces.read、/apm/dependencies 复用
-- apm.services.read，不新增权限点。
BEGIN;

INSERT INTO permissions (code, name, module, description) VALUES
('apm.sql.read', '查看APM SQL指纹聚合', 'apm', '查看SQL指纹聚合列表与示例trace（只出指纹，不含原始statement）')
ON CONFLICT (code) DO NOTHING;

-- 安全管理员：全量
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN' AND p.code IN ('apm.sql.read')
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- 审计管理员：只读（本权限点为纯查询，全量授予）
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'AUDIT_ADMIN' AND p.code IN ('apm.sql.read')
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
