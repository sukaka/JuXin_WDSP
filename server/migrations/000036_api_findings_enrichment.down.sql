-- 000036 回滚：移除 api_runtime_findings 物化承载列与去重指纹唯一索引。
BEGIN;

DROP INDEX IF EXISTS idx_api_runtime_findings_dedup;
ALTER TABLE api_runtime_findings
    DROP COLUMN IF EXISTS subject_type,
    DROP COLUMN IF EXISTS subject_id,
    DROP COLUMN IF EXISTS risk_score,
    DROP COLUMN IF EXISTS risk_level,
    DROP COLUMN IF EXISTS count,
    DROP COLUMN IF EXISTS evidence_json,
    DROP COLUMN IF EXISTS model_version,
    DROP COLUMN IF EXISTS policy_version,
    DROP COLUMN IF EXISTS updated_at,
    DROP COLUMN IF EXISTS dedup_fingerprint;

COMMIT;
