-- 000100 回滚：恢复三权内置角色既有 role_permissions 映射（按 000099 之后的终态精确回滚）。
BEGIN;

-- 系统管理员：回退六组权限点
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SYSTEM_ADMIN' AND p.code IN (
  'access_logs.read','access_logs.export',
  'api_asset.read','api_policy.read','api_runtime.read','api_weakness.read',
  'certificates.read_metadata','config_versions.read','gateway_status.read','publish_tasks.read',
  'l7rules.read','trusted_proxies.read','trusted_proxies.manage',
  'protected_addresses.read','protected_addresses.manage',
  'ai.chat.use','ai.noise_reduction.use','ai.noise_reduction.manage','ai.root_cause.use',
  'security_identities.read','behavior_policy.read','behavior_policy.edit'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- 安全管理员：撤销补授（仅撤销 000100 新增的 3 个；security_identities/behavior_policy 由 000099 授予，不在此移除）
DELETE FROM role_permissions
WHERE role_id = (SELECT id FROM roles WHERE code = 'SECURITY_ADMIN')
  AND permission_id IN (SELECT id FROM permissions WHERE code IN (
    'certificates.read_metadata','ai.noise_reduction.manage','ai.root_cause.use'
  ));

-- 安全管理员：回退智能能力管理 8 个权限点
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN' AND p.code IN (
  'ai.models.read','ai.agents.read','ai.tools.read','ai.prompts.read',
  'ai.usage.read','ai.audits.read','ai.memories.read_own','ai.memories.manage_own'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- 审计管理员：回退被移除的只读权限点
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'AUDIT_ADMIN' AND p.code IN (
  'access_control_events.read','access_control_versions.read','access_rules.read',
  'ai.audits.read','ai.usage.read','analytics.disposition.read',
  'api_ai.read','api_asset.read','api_audit.read','api_authorization.read','api_classification.read',
  'api_data.read','api_graph.read','api_learning.read','api_model.read','api_parameter.read',
  'api_policy.read','api_risk.read','api_runtime.read','api_scan.read','api_spec.read','api_weakness.read',
  'apm.overview.read','apm.runtime.read','apm.services.read','apm.sql.read','apm.traces.read',
  'applications.read_audit','backup_records.read','certificates.read_metadata','config_versions.read',
  'dashboard.audit.read','delivery_checks.read','exceptions.read','gateway_changes.read','ha.read',
  'l7rules.read','license.read','permissions.read','policy_versions.read','protected_addresses.read',
  'protection_policies.read','publish_tasks.read','rate_limits.read','reports.download_audit',
  'reports.read_audit','restore_records.read','roles.read','security_events.read',
  'system_alerts.read_audit','temporary_blocks.read','trusted_proxies.read','upgrade_records.read',
  'upstreams.read_audit','users.read_summary','waf_rules.read',
  'security_identities.read','behavior_policy.read'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
