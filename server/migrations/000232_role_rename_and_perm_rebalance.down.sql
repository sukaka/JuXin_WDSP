-- 回滚 000232 角色更名与三权权限再平衡
BEGIN;

UPDATE roles
SET name = '安全管理员',
    description = '负责Web应用管理、防护策略、黑白名单、CC防护、规则配置、例外策略、安全事件处置、安全报表。不得管理系统管理员和审计管理员账号。',
    updated_at = now()
WHERE code = 'SECURITY_ADMIN';

UPDATE roles
SET description = '负责用户管理、角色分配、系统参数、网关维护、备份恢复、系统运行维护。不得查看完整安全事件敏感内容，不得删除审计日志。',
    updated_at = now()
WHERE code = 'SYSTEM_ADMIN';

-- 恢复系统管理员被剥离的 17 个权限点
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SYSTEM_ADMIN' AND p.code IN (
  'gateway_runtime.read',
  'jwt_trust.read', 'jwt_trust.manage',
  'bot_policy.read', 'bot_policy.edit',
  'security_regression.read', 'security_regression.import', 'security_regression.policy',
  'risk_policy.read',
  'attack_sessions.read', 'security_identities.block',
  'traffic.agents.view', 'traffic.agents.manage',
  'system_alerts.read', 'system_alerts.acknowledge',
  'vuln_intel.read', 'vuln_intel.manage'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- 撤销补授给 SECURITY_ADMIN 的 5 个权限点
DELETE FROM role_permissions rp
USING roles r, permissions p
WHERE rp.role_id = r.id
  AND rp.permission_id = p.id
  AND r.code = 'SECURITY_ADMIN'
  AND p.code IN (
    'big_screen.runtime.read',
    'system_alerts.read',
    'system_alerts.acknowledge',
    'vuln_intel.manage',
    'gateway_runtime.read'
  );

-- 清理新增大屏权限点
DELETE FROM role_permissions WHERE permission_id IN (
  SELECT id FROM permissions WHERE code = 'big_screen.runtime.read'
);
DELETE FROM permissions WHERE code = 'big_screen.runtime.read';

COMMIT;
