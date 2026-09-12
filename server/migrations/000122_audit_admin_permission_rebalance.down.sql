BEGIN;

-- 恢复 000102/000104/000109 原始授权；license.read 在 000100 已被撤销，不应恢复。
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.code = 'AUDIT_ADMIN'
  AND p.code IN ('risk_policy.read', 'attack_sessions.read', 'traffic.agents.view')
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
