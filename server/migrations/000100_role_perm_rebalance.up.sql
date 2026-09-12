-- 000100 三权内置角色权限重划（菜单与功能归属调整）：
--   系统管理员 SYSTEM_ADMIN：移交「应用防护/访问控制/API防护/事件中心/安全态势(除系统告警)/智能安全运营」
--     六组权限点，保留系统告警（system_alerts.*）与全部智能能力管理（ai 管理类）权限；
--   安全管理员 SECURITY_ADMIN：接管上述六组（补授 certificates.read_metadata、ai.noise_reduction.manage、
--     ai.root_cause.use），交出「智能能力管理」整组（ai.models/agents/tools/prompts/usage/audits/memories）；
--   审计管理员 AUDIT_ADMIN：收紧为纯审计角色，仅保留操作审计、登录日志、个人资料、会话自助与工作台基础信息。
-- 仅调整内置三角色的 role_permissions 映射，不新增/删除权限点；自定义角色不受影响。
BEGIN;

-- ---------- 系统管理员：移除六组权限点 ----------
DELETE FROM role_permissions
WHERE role_id = (SELECT id FROM roles WHERE code = 'SYSTEM_ADMIN')
  AND permission_id IN (SELECT id FROM permissions WHERE code IN (
    -- 事件中心
    'access_logs.read','access_logs.export',
    -- API 防护
    'api_asset.read','api_policy.read','api_runtime.read','api_weakness.read',
    -- 应用防护
    'certificates.read_metadata','config_versions.read','gateway_status.read','publish_tasks.read',
    -- 访问控制（含可信代理页面的保护地址）
    'l7rules.read','trusted_proxies.read','trusted_proxies.manage',
    'protected_addresses.read','protected_addresses.manage',
    -- 智能安全运营
    'ai.chat.use','ai.noise_reduction.use','ai.noise_reduction.manage','ai.root_cause.use',
    -- 应用防护策略/安全风险（菜单组随应用防护一并划归安全管理员）
    'security_identities.read','behavior_policy.read','behavior_policy.edit'
  ));

-- ---------- 安全管理员：补授六组缺口 ----------
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN' AND p.code IN (
  'certificates.read_metadata','ai.noise_reduction.manage','ai.root_cause.use',
  'security_identities.read','behavior_policy.read','behavior_policy.edit'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- ---------- 安全管理员：移除智能能力管理 ----------
DELETE FROM role_permissions
WHERE role_id = (SELECT id FROM roles WHERE code = 'SECURITY_ADMIN')
  AND permission_id IN (SELECT id FROM permissions WHERE code IN (
    'ai.models.read','ai.agents.read','ai.tools.read','ai.prompts.read',
    'ai.usage.read','ai.audits.read','ai.memories.read_own','ai.memories.manage_own'
  ));

-- ---------- 审计管理员：仅保留审计与自助权限 ----------
DELETE FROM role_permissions
WHERE role_id = (SELECT id FROM roles WHERE code = 'AUDIT_ADMIN')
  AND permission_id NOT IN (SELECT id FROM permissions WHERE code IN (
    'audits.read','audits.export',
    'login_logs.read','login_logs.export',
    'profile.read','profile.update',
    'sessions.read_self','sessions.revoke_self',
    'dashboard.read_basic'
  ));

COMMIT;
