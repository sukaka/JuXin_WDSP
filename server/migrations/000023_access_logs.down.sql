-- 000023 回滚：删除 logging 组设置、访问日志权限与 access_logs 表
BEGIN;

DELETE FROM system_settings WHERE setting_group = 'logging' AND setting_key IN (
  'access_log_enabled','capture_request_headers','capture_request_body',
  'capture_response_headers','capture_response_body','body_limit_kb','retention_days'
);

DELETE FROM role_permissions WHERE permission_id IN (
  SELECT id FROM permissions WHERE code IN ('access_logs.read', 'access_logs.export')
);
DELETE FROM permissions WHERE code IN ('access_logs.read', 'access_logs.export');

DROP TABLE IF EXISTS access_logs;

COMMIT;
