-- 000093 APM 阶段4：深度诊断会话控制面（设计 docs/BUSINESS_PERFORMANCE_APM_DESIGN.md
-- §6.3 深度诊断流程 / §9.2 策略内容 / §16.2 管理接口 / §21.2 深度诊断性能预算）。
--
--   1) apm_diagnostic_sessions：诊断会话生命周期（ACTIVE→EXPIRED/STOPPED/KILLED 均终态，
--      CHECK 约束兜底；状态机纯函数见 apm/diagnostics_types.go）。
--      scope/capabilities 为 JSONB（scope = {application_id, service?, environment?,
--      instance_ids?}）；policy_version 记录创建会话时下发的诊断叠加策略版本
--      （对应 apm_agent_policies 中 application:<uuid> 作用域的版本号，不建 FK——
--      策略为追加式版本表）；baseline_restored 标记终态会话是否已下发基线恢复策略
--      （§21.2"诊断结束 1 分钟内恢复基线"的对账标记，到期扫描任务兜底重试）。
--   2) 部分唯一索引：同一应用同一时刻仅允许一个 ACTIVE 会话——诊断叠加策略按应用
--      作用域发布，并发会话会造成恢复语义歧义，DB 层兜底防 check-then-insert 竞态。
--   3) 权限种子 apm.diagnostics.manage（manage 类，对照 000089 先例：
--      SECURITY_ADMIN 全量；AUDIT_ADMIN/SYSTEM_ADMIN 不授——会话列表/详情也挂
--      manage 权限点，读面不外放）。
--   4) kill switch 设置种子 apm_diagnostics.kill_switch=false（boolean）；
--      接口修改白名单登记在 settings.AllowedSettingKeys（代码侧）。
BEGIN;

-- ---------- apm_diagnostic_sessions ----------
CREATE TABLE IF NOT EXISTS apm_diagnostic_sessions (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scope             JSONB NOT NULL,           -- {application_id, service?, environment?, instance_ids?}
    capabilities      JSONB NOT NULL,           -- ["sql_detail","function_probe","thread_block","gc_detail","mq_wait"] 子集
    sampling_rate     DOUBLE PRECISION NOT NULL, -- 生效采样率（下限夹紧 0.1；上限按能力分级，应用层校验）
    duration_minutes  INTEGER NOT NULL,          -- 生效时长（下限夹紧 15；上限 120，应用层校验）
    status            VARCHAR(16) NOT NULL DEFAULT 'ACTIVE'
                      CHECK (status IN ('ACTIVE', 'EXPIRED', 'STOPPED', 'KILLED')),
    created_by        UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at        TIMESTAMPTZ NOT NULL,      -- 硬截止：同步写入诊断策略信封 expires_at，Agent 失联时本地自动失效（§9.2）
    stopped_at        TIMESTAMPTZ,
    stopped_by        UUID REFERENCES users(id) ON DELETE SET NULL,
    stop_reason       TEXT NOT NULL DEFAULT '',  -- manual / expired / kill switch 等
    policy_version    BIGINT NOT NULL,           -- 创建时下发的诊断叠加策略版本（application:<uuid> 作用域）
    baseline_restored BOOLEAN NOT NULL DEFAULT FALSE  -- 终态后是否已下发基线恢复策略（扫描任务对账重试）
);
CREATE INDEX IF NOT EXISTS idx_apm_diag_sessions_status_expires ON apm_diagnostic_sessions (status, expires_at);
CREATE INDEX IF NOT EXISTS idx_apm_diag_sessions_created ON apm_diagnostic_sessions (created_at DESC);
-- 同一应用仅允许一个 ACTIVE 诊断会话（并发创建竞态的 DB 层兜底）
CREATE UNIQUE INDEX IF NOT EXISTS uq_apm_diag_sessions_active_app
    ON apm_diagnostic_sessions ((scope->>'application_id')) WHERE status = 'ACTIVE';

-- ---------- 权限种子（manage 类；SECURITY_ADMIN 全量，AUDIT_ADMIN/SYSTEM_ADMIN 不授） ----------
INSERT INTO permissions (code, name, module, description) VALUES
('apm.diagnostics.manage', '管理APM深度诊断', 'apm', '创建/停止深度诊断会话、操作诊断 kill switch（高风险操作）')
ON CONFLICT (code) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN' AND p.code = 'apm.diagnostics.manage'
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- ---------- kill switch 设置种子（接口修改白名单登记于 settings.AllowedSettingKeys） ----------
INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, is_sensitive, description) VALUES
('apm_diagnostics', 'kill_switch', 'false', 'boolean', FALSE, 'APM深度诊断全局kill switch：开启后全部活跃会话置KILLED、下发基线恢复策略并拒绝新建（高风险）')
ON CONFLICT (setting_group, setting_key) DO NOTHING;

COMMIT;
