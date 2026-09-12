-- 回滚 000001_init

BEGIN;

DROP TABLE IF EXISTS system_settings;
DROP RULE IF EXISTS operation_audits_no_delete ON operation_audits;
DROP RULE IF EXISTS operation_audits_no_update ON operation_audits;
DROP TABLE IF EXISTS operation_audits;
DROP TABLE IF EXISTS login_logs;
DROP TABLE IF EXISTS login_sessions;
DROP TABLE IF EXISTS password_histories;
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS users;

COMMIT;
