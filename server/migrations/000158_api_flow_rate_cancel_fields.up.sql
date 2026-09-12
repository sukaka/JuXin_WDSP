-- 000158 流程基线批量执行与取消语义字段（阶段8 §44 rapid_batch/post_cancel_operation
-- 配置面）：对齐网关 detectors/flow.go FlowStep/FlowBaseline 契约——
--   步骤级 api_flow_baseline_steps：max_per_window / rate_window_seconds / cancels_flow；
--   流程级 api_flow_baselines：max_per_window / rate_window_seconds。
-- 口径（与网关 checkFlowRateFields 一致，应用层同口径校验）：
--   0 = 不判定（向后兼容，存量行默认 0，旧基线零行为）；
--   声明 max_per_window > 0 时有效窗口为 rate_window_seconds（>0）否则缺省 60s，
--   有效窗口不得超会话 TTL 600s（网关 FlowSessionTTL=10min，窗口长于会话生命即不可判定，
--   属配置错误）；rate_window_seconds 上限 600 在库层恒约束（管理面严于网关，网关上同值
--   恒通过）。cancels_flow=true 声明取消语义步骤（post_cancel_operation 判定的唯一来源，
--   无声明不判定）。
BEGIN;

ALTER TABLE api_flow_baselines
    ADD COLUMN IF NOT EXISTS max_per_window      INTEGER NOT NULL DEFAULT 0,  -- 流程级短窗调用上限（0 = 不判定）
    ADD COLUMN IF NOT EXISTS rate_window_seconds INTEGER NOT NULL DEFAULT 0,  -- 流程级短窗秒数（0 = 缺省 60s）
    ADD CONSTRAINT chk_api_flow_baselines_rate
        CHECK (max_per_window >= 0 AND rate_window_seconds >= 0 AND rate_window_seconds <= 600);

ALTER TABLE api_flow_baseline_steps
    ADD COLUMN IF NOT EXISTS max_per_window      INTEGER NOT NULL DEFAULT 0,     -- 步骤级短窗调用上限（0 = 不判定）
    ADD COLUMN IF NOT EXISTS rate_window_seconds INTEGER NOT NULL DEFAULT 0,     -- 步骤级短窗秒数（0 = 缺省 60s）
    ADD COLUMN IF NOT EXISTS cancels_flow        BOOLEAN NOT NULL DEFAULT FALSE, -- 取消语义声明（post_cancel 判定唯一来源）
    ADD CONSTRAINT chk_api_flow_baseline_steps_rate
        CHECK (max_per_window >= 0 AND rate_window_seconds >= 0 AND rate_window_seconds <= 600);

COMMIT;
