-- 000232 角色更名与三权权限再平衡：
--   1. 内置角色 SECURITY_ADMIN 保持编码不变，显示名称由「安全管理员」更名为「运维管理员」，同步更新角色描述；
--   2. 新增权限点 big_screen.runtime.read（仅授予 SECURITY_ADMIN/运维管理员），隔离系统运行监控大屏、
--      网关连接与会话大屏的只读访问，系统管理员（SYSTEM_ADMIN）保留系统运维页但不再拥有任何大屏权限；
--   3. 从 SYSTEM_ADMIN 剥离 7 大业务/安全菜单（应用防护、应用防护策略、API防护、安全风险、数据接入、
--      安全态势、安全运营）对应的 17 个残留或独有权限点，并将其中原 SYSTEM_ADMIN 独有的 4 个权限点
--      （system_alerts.read、system_alerts.acknowledge、vuln_intel.manage、gateway_runtime.read）补授给运维管理员。
-- 仅调整内置角色元信息与权限映射，自定义角色与既有用户绑定不受影响。
BEGIN;

-- ---------- 1. 更新内置角色名称与描述（保留既有 code 不变） ----------
UPDATE roles
SET name = '运维管理员',
    description = '负责Web应用管理、防护策略、黑白名单、CC防护、规则配置、例外策略、API动态防护、数据接入、安全态势与大屏展示、系统告警处置、漏洞情报与安全报表。不得管理系统管理员和审计管理员账号。',
    updated_at = now()
WHERE code = 'SECURITY_ADMIN';

UPDATE roles
SET description = '负责用户管理、角色分配、系统参数、网口与网络配置、容器运维、高可用、备份恢复、系统升级、授权管理与智能能力管理。不得查看安全事件与业务防护策略，不得访问大屏展示，不得删除审计日志。',
    updated_at = now()
WHERE code = 'SYSTEM_ADMIN';

-- ---------- 2. 新增大屏运行监控只读权限点 ----------
INSERT INTO permissions (code, name, module, description) VALUES
('big_screen.runtime.read', '查看运行监控大屏', 'big_screen', '在大屏展示中查看系统运行监控与网关连接会话大屏')
ON CONFLICT (code) DO NOTHING;

-- ---------- 3. 运维管理员（SECURITY_ADMIN）：补授大屏及原系统管理员独有权限 ----------
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN' AND p.code IN (
  'big_screen.runtime.read',
  'system_alerts.read',
  'system_alerts.acknowledge',
  'vuln_intel.manage',
  'gateway_runtime.read'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- ---------- 4. 系统管理员（SYSTEM_ADMIN）：剥离 7 大菜单对应的 17 个权限点 ----------
DELETE FROM role_permissions rp
USING roles r, permissions p
WHERE rp.role_id = r.id
  AND rp.permission_id = p.id
  AND r.code = 'SYSTEM_ADMIN'
  AND p.code IN (
    -- 应用防护 / API 防护
    'gateway_runtime.read',
    'jwt_trust.read', 'jwt_trust.manage',
    'bot_policy.read', 'bot_policy.edit',
    'security_regression.read', 'security_regression.import', 'security_regression.policy',
    -- 应用防护策略
    'risk_policy.read',
    -- 安全风险
    'attack_sessions.read', 'security_identities.block',
    -- 数据接入
    'traffic.agents.view', 'traffic.agents.manage',
    -- 安全态势（系统告警）
    'system_alerts.read', 'system_alerts.acknowledge',
    -- 安全运营（漏洞情报）
    'vuln_intel.read', 'vuln_intel.manage'
  );

COMMIT;
