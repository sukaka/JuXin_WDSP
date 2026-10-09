-- 000166 回滚：移除应用 API 准入模式列与 finding_type 词表注释（恢复原无列注释状态）。
BEGIN;

ALTER TABLE applications
    DROP CONSTRAINT IF EXISTS chk_applications_api_admission_mode;

ALTER TABLE applications
    DROP COLUMN IF EXISTS api_admission_mode;

COMMENT ON COLUMN api_runtime_findings.finding_type IS NULL;

COMMIT;
