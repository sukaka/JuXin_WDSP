-- API 安全补全第六波：主动扫描（apiscan 包，P1-07）权限点种子。
-- 三权分配口径与 000019/000041 一致：SECURITY_ADMIN 全量；AUDIT_ADMIN 只读；SYSTEM_ADMIN 无。
BEGIN;

INSERT INTO permissions (code, name, module, description) VALUES
('api_scan.read',    '查看API扫描', 'api', '查看扫描目标/任务/发现'),
('api_scan.execute', '执行API扫描', 'api', '启动/停止扫描任务与复测'),
('api_scan.manage',  '管理API扫描', 'api', '管理扫描目标与授权（授权须双人分离）')
ON CONFLICT (code) DO NOTHING;

-- 安全管理员：全部 3 个权限点
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN' AND p.code IN ('api_scan.read','api_scan.execute','api_scan.manage')
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- 审计管理员：只读
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'AUDIT_ADMIN' AND p.code IN ('api_scan.read')
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
