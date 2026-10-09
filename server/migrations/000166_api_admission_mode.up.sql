-- 000166 API 准入防护 P1：应用级准入模式列（docs/API_ADMISSION_CONTROL_DESIGN.md §3.1）。
--
--   applications.api_admission_mode：OFF / OBSERVE / PROTECT，默认 OFF。
--     OFF     不做准入判定（现状行为）；
--     OBSERVE 检测/学习期：未确认端点照常放行，仅记录 admission.* 观测 finding；
--     PROTECT 防护期：未确认端点（asset_status<>CONFIRMED 或基线不存在）由网关 403。
--   模式随整站发布经 guardconfig api_admission 段下发网关（确认集=该应用 CONFIRMED
--   端点键）；与全局 api_protection.mode（模型偏离防护）正交。
--
-- 同步 api_runtime_findings.finding_type 词表注释：新增 ADMISSION_UNCONFIRMED
-- （网关 admission.unconfirmed_endpoint 映射；admission.unknown_endpoint 沿用 SHADOW，
-- 映射表见 server/internal/apiruntime/findings.go findingTypeOverrides）。
BEGIN;

ALTER TABLE applications
    ADD COLUMN IF NOT EXISTS api_admission_mode VARCHAR(8) NOT NULL DEFAULT 'OFF';

ALTER TABLE applications
    ADD CONSTRAINT chk_applications_api_admission_mode
    CHECK (api_admission_mode IN ('OFF', 'OBSERVE', 'PROTECT'));

COMMENT ON COLUMN applications.api_admission_mode IS
    'API 准入模式：OFF（不判定，默认）/ OBSERVE（未确认端点仅观测）/ PROTECT（未确认端点 403）；'
    '确认集随整站发布下发（guardconfig api_admission 段），设计见 docs/API_ADMISSION_CONTROL_DESIGN.md';

COMMENT ON COLUMN api_runtime_findings.finding_type IS
    'SHADOW / ZOMBIE / DEPRECATED / BOLA / BFLA / SCHEMA_DEVIATION / SENSITIVE_LEAK / '
    'ADMISSION_UNCONFIRMED / ...（网关规则 ID 机械映射，覆盖表见 apiruntime/findings.go）';

COMMIT;
