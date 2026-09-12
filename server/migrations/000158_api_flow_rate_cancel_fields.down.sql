-- 回滚 000158：移除流程基线批量执行/取消语义字段（步骤级三列 + 流程级两列）。
BEGIN;

ALTER TABLE api_flow_baseline_steps
    DROP CONSTRAINT IF EXISTS chk_api_flow_baseline_steps_rate,
    DROP COLUMN IF EXISTS cancels_flow,
    DROP COLUMN IF EXISTS rate_window_seconds,
    DROP COLUMN IF EXISTS max_per_window;

ALTER TABLE api_flow_baselines
    DROP CONSTRAINT IF EXISTS chk_api_flow_baselines_rate,
    DROP COLUMN IF EXISTS rate_window_seconds,
    DROP COLUMN IF EXISTS max_per_window;

COMMIT;
