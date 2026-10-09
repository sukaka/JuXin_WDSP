-- 000174 回滚：移除两表 enforcement 相关列，恢复 decision 三值词表。
-- 注意：若 api_authorization_decisions 已存在 VERIFIED_VIOLATION 行，词表回缩会失败——
-- 回滚前须由运维确认无新决策值行（回滚不回退历史事实，证据行保留）。
BEGIN;

-- D1 词表回缩（三值）
ALTER TABLE api_authorization_decisions DROP CONSTRAINT IF EXISTS api_authorization_decisions_decision_check;
ALTER TABLE api_authorization_decisions
    ADD CONSTRAINT api_authorization_decisions_decision_check
    CHECK (decision IN ('ALLOW','OBSERVE_VIOLATION','UNKNOWN'));

ALTER TABLE api_role_baselines DROP CONSTRAINT IF EXISTS api_role_baselines_enforcement_check;
ALTER TABLE api_role_baselines DROP COLUMN IF EXISTS enforcement;

ALTER TABLE api_object_models DROP CONSTRAINT IF EXISTS api_object_models_on_unknown_check;
ALTER TABLE api_object_models DROP CONSTRAINT IF EXISTS api_object_models_evidence_source_check;
ALTER TABLE api_object_models DROP CONSTRAINT IF EXISTS api_object_models_enforcement_check;
ALTER TABLE api_object_models DROP COLUMN IF EXISTS on_unknown;
ALTER TABLE api_object_models DROP COLUMN IF EXISTS evidence_source;
ALTER TABLE api_object_models DROP COLUMN IF EXISTS enforcement_owner;
ALTER TABLE api_object_models DROP COLUMN IF EXISTS enforcement;

COMMIT;
