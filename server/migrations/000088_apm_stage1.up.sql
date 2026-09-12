-- 000088 APM 阶段1（WP3 服务端数据层，决策见 docs/APM_STAGE0_ADR.md D6/D7/D9/D12）：
--   1) access_logs 增加 trace/端点/TTFB 列（全部 nullable：旧网关上报缺省为 NULL，
--      新管理端可收旧日志；不改历史行，waf_action 空串按 ALLOW 口径由写入侧/查询层归一）；
--   2) trace_id 与应用时间窗部分索引（trace 双向检索 + APM 按应用查询）；
--   3) apm 权限种子（三权口径与 000019/000063 一致：SECURITY_ADMIN 全量、
--      AUDIT_ADMIN 只读、SYSTEM_ADMIN 不含业务观测权限）。
BEGIN;

-- ---------- access_logs 新列 ----------
ALTER TABLE access_logs
    ADD COLUMN IF NOT EXISTS trace_id      TEXT,
    ADD COLUMN IF NOT EXISTS span_id       TEXT,
    ADD COLUMN IF NOT EXISTS endpoint_key  TEXT,
    ADD COLUMN IF NOT EXISTS path_template TEXT,
    ADD COLUMN IF NOT EXISTS ttfb_ms       INTEGER;

-- trace 检索（安全事件 ↔ 访问记录双向定位）；部分索引排除 NULL（旧数据不占索引）
CREATE INDEX IF NOT EXISTS idx_access_logs_trace_id ON access_logs (trace_id) WHERE trace_id IS NOT NULL;
-- APM 按应用 + 时间窗查询（端点级聚合扫描走既有 occurred_at 索引，不再重复建）
CREATE INDEX IF NOT EXISTS idx_access_logs_app_occurred ON access_logs (application_id, occurred_at) WHERE application_id IS NOT NULL;

-- ---------- APM 权限种子（D12） ----------
INSERT INTO permissions (code, name, module, description) VALUES
('apm.overview.read', '查看业务性能概览', 'apm', '查看APM概览（无Agent模式应用/端点级RED指标）'),
('apm.services.read', '查看APM服务列表', 'apm', '查看APM服务（应用）列表与服务详情'),
('apm.traces.read',   '查看APM追踪记录', 'apm', '按trace_id检索访问记录并关联安全事件')
ON CONFLICT (code) DO NOTHING;

-- 安全管理员：全部 3 个权限点
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN' AND p.code IN ('apm.overview.read','apm.services.read','apm.traces.read')
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- 审计管理员：只读（本批权限点均为只读，全量授予）
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'AUDIT_ADMIN' AND p.code IN ('apm.overview.read','apm.services.read','apm.traces.read')
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
