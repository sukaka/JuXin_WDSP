-- 000131 API 运行时事件最终处置列（WDSP P0-04，任务书
-- docs/tasks/wdsp-p0/P0-04_DECISION_SCOPED_EXCEPTIONS.md §4）。
--   api_runtime_events.final_decision：可选 JSONB 对象，承载整条请求的最终处置事实
--   （schema_version/completion_status/security_action/executor_module/response_source/
--   http_status/response_committed/reason_codes/rule_refs/effective_config/findings/steps/
--   matched_exceptions/identity_verification/evidence_refs/finalized_at）。
--   与 API 决策 final_action 语义独立：final_action 是 API 管线决策，final_decision
--   是整条请求实际执行者归因；API ALLOW 后 Coraza BLOCK 时两者分别记录。
--   可空：旧版网关事件与无安全相关事实的正常请求落 NULL，历史事件不回填。
BEGIN;

ALTER TABLE api_runtime_events
    ADD COLUMN IF NOT EXISTS final_decision JSONB;

COMMIT;
