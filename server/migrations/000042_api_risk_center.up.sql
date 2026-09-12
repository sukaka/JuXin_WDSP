-- 000042 API 风险中心（WDSP 任务书 P0-13：Risk/Weakness 分离之 Risk 侧处置闭环）。
--
-- 语义边界（与 000039 同一纪律，互不混用）：
--   Risk（api_runtime_findings，本迁移）= 运行时异常信号（谁、何时、命中了什么），
--     由 apiruntime 采集器按 dedup_fingerprint 物化，处置闭环为
--     确认→处理→解决/误报/忽略→归档；
--   Weakness（api_weaknesses，apiweakness 包）= 长期缺陷，
--     确认→指派→整改→复测→关闭，跨天持续跟踪。
--
-- 本迁移内容：
--   1. status 词表扩展为七态：NEW / CONFIRMED / IN_PROGRESS / FALSE_POSITIVE /
--      IGNORED / RESOLVED / ARCHIVED（000018 建表时仅注释约定四态，无 CHECK）；
--      存量 OPEN→NEW、ACKNOWLEDGED→IN_PROGRESS（RESOLVED/FALSE_POSITIVE 同名保留）；
--   2. 列默认值 OPEN→NEW，并补 chk_api_runtime_findings_status CHECK 约束；
--   3. 风险中心常用维度索引：subject（主体维度降噪聚合）与 status+last_seen
--      （处置队列）；endpoint/type 两维索引 000018 已建，不重复；
--   4. 权限点种子 api_risk.read / api_risk.handle，三权口径仿 000019：
--      SECURITY_ADMIN 全量、AUDIT_ADMIN 只读、SYSTEM_ADMIN 无（风险主体含
--      身份/来源指纹，运维角色不开放）。
BEGIN;

-- 1. 存量状态映射（须在 CHECK 添加之前；四态词表之外不应存在其他取值，
--    若存在异常取值则 CHECK 添加失败、迁移如实报错，不静默改写）
UPDATE api_runtime_findings SET status = 'NEW' WHERE status = 'OPEN';
UPDATE api_runtime_findings SET status = 'IN_PROGRESS' WHERE status = 'ACKNOWLEDGED';

-- 2. 默认值与 CHECK 切换到七态词表
ALTER TABLE api_runtime_findings ALTER COLUMN status SET DEFAULT 'NEW';
ALTER TABLE api_runtime_findings
    ADD CONSTRAINT chk_api_runtime_findings_status
    CHECK (status IN ('NEW','CONFIRMED','IN_PROGRESS','FALSE_POSITIVE','IGNORED','RESOLVED','ARCHIVED'));
COMMENT ON COLUMN api_runtime_findings.status IS
    'NEW / CONFIRMED / IN_PROGRESS / FALSE_POSITIVE / IGNORED / RESOLVED / ARCHIVED';

-- 3. 风险中心索引（subject 降噪聚合 + 处置队列）
CREATE INDEX IF NOT EXISTS idx_api_runtime_findings_subject
    ON api_runtime_findings (subject_type, subject_id, status);
CREATE INDEX IF NOT EXISTS idx_api_runtime_findings_status_last_seen
    ON api_runtime_findings (status, last_seen_at DESC);

-- 4. 权限点种子
INSERT INTO permissions (code, name, module, description) VALUES
('api_risk.read',   '查看API风险', 'api', '查看API风险发现列表/详情与聚合视图'),
('api_risk.handle', '处置API风险', 'api', '风险确认/处理/解决/误报/忽略/归档')
ON CONFLICT (code) DO NOTHING;

-- 安全管理员：全部 2 个权限点
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN' AND p.code IN ('api_risk.read','api_risk.handle')
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- 审计管理员：只读
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'AUDIT_ADMIN' AND p.code IN ('api_risk.read')
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- 系统管理员：无（与 000019 口径一致，不授权）

COMMIT;
