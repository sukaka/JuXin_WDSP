-- 回滚 000002_seed_rbac

BEGIN;

DELETE FROM role_permissions WHERE role_id IN (SELECT id FROM roles WHERE code IN ('SYSTEM_ADMIN','SECURITY_ADMIN','AUDIT_ADMIN'));
DELETE FROM roles WHERE code IN ('SYSTEM_ADMIN','SECURITY_ADMIN','AUDIT_ADMIN');
DELETE FROM permissions WHERE code IN (
'dashboard.read_basic','profile.read','profile.update',
'sessions.read_self','sessions.revoke_self','sessions.read','sessions.revoke',
'users.read','users.read_summary','users.create','users.update','users.disable',
'users.reset_password','users.unlock','users.force_logout',
'roles.read','permissions.read',
'system_settings.read','system_settings.update',
'login_logs.read','login_logs.read_limited','login_logs.export',
'audits.read','audits.export'
);

COMMIT;
