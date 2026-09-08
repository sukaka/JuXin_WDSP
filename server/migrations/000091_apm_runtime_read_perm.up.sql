-- 000091 APM 阶段3 第二批：运行时指标查询接口权限种子。
-- 依据 docs/BUSINESS_PERFORMANCE_APM_DESIGN.md §16.1（GET /api/v1/apm/runtime →
-- apm.runtime.read）；三权口径与 000088/000090 一致：SECURITY_ADMIN 全量、
-- AUDIT_ADMIN 只读（本权限点为纯查询只读）、SYSTEM_ADMIN 不含业务观测权限。
BEGIN;

INSERT INTO permissions (code, name, module, description) VALUES
('apm.runtime.read', '查看APM运行时指标', 'apm', '查看服务实例运行时指标（goroutine/堆内存/GC/调度器等，按语言Agent上报原样返回）')
ON CONFLICT (code) DO NOTHING;

-- 安全管理员：全量
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN' AND p.code IN ('apm.runtime.read')
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- 审计管理员：只读（本权限点为纯查询，全量授予）
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'AUDIT_ADMIN' AND p.code IN ('apm.runtime.read')
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
