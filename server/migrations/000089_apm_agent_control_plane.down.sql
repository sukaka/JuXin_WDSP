-- 000089 回滚：删除 apm_alert 设置种子、APM manage 权限种子与控制面五表
BEGIN;

DELETE FROM system_settings
WHERE setting_group = 'apm_alert'
  AND setting_key IN ('endpoint_p95_ms', 'endpoint_error_rate', 'min_requests', 'sustain_minutes');

DELETE FROM role_permissions WHERE permission_id IN (
  SELECT id FROM permissions WHERE code IN ('apm.agents.manage', 'apm.settings.manage')
);
DELETE FROM permissions WHERE code IN ('apm.agents.manage', 'apm.settings.manage');

DROP TABLE IF EXISTS apm_agent_cert_revocations;
DROP TABLE IF EXISTS apm_agent_policies;
DROP TABLE IF EXISTS apm_enrollment_tokens;
DROP TABLE IF EXISTS apm_agents;
DROP TABLE IF EXISTS apm_services;

COMMIT;
