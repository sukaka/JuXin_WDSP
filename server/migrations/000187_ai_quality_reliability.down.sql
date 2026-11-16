-- 000187 down：完整回滚 AI 质量与可靠性增强
-- 删除种子评估集（按 code 精确删除，不动既有集合）→ 回退熔断三列 → 回退回归明细列。
BEGIN;

DELETE FROM ai_evaluation_sets WHERE code = 'eval_api_security_analysis';

ALTER TABLE api_ai_schedules
    DROP COLUMN IF EXISTS circuit_reason,
    DROP COLUMN IF EXISTS circuit_opened_at,
    DROP COLUMN IF EXISTS consecutive_failures;

ALTER TABLE ai_prompt_versions
    DROP COLUMN IF EXISTS test_detail;

COMMIT;
