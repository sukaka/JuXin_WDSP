-- 000063 API 安全补全第八波：AI 定时运营任务（apiops 包，P1-02 续）权限点种子。
-- 三权分配口径与 000019/000056 一致：SECURITY_ADMIN 全量；AUDIT_ADMIN 只读；SYSTEM_ADMIN 无。
BEGIN;

INSERT INTO permissions (code, name, module, description) VALUES
('api_ai.read',    '查看AI运营任务', 'api', '查看AI运营定时计划与执行记录'),
('api_ai.execute', '执行AI运营任务', 'api', '创建/修改/启停AI运营定时计划并立即执行')
ON CONFLICT (code) DO NOTHING;

-- 安全管理员：全部 2 个权限点
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN' AND p.code IN ('api_ai.read','api_ai.execute')
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- 审计管理员：只读
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'AUDIT_ADMIN' AND p.code IN ('api_ai.read')
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
