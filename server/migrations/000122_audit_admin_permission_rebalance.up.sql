-- 审计管理员职责收敛：仅保留审计、日志、审计报表与安全总览等审计所需权限。
-- license.read 在 000100 已撤销，此处重复清理用于修复历史环境中的异常授权。
BEGIN;

DELETE FROM role_permissions rp
USING roles r, permissions p
WHERE rp.role_id = r.id
  AND rp.permission_id = p.id
  AND r.code = 'AUDIT_ADMIN'
  AND p.code IN (
    'risk_policy.read',
    'attack_sessions.read',
    'traffic.agents.view',
    'license.read'
  );

COMMIT;
