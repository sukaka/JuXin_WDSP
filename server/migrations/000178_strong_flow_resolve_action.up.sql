-- 000178 强流程步骤事件 action 词表放宽（NG-FLOW-03 §1.5/D5 管理恢复留痕）：
-- 加入 RESOLVE——仅由管理面对账恢复（POST .../instances/{id}/resolve）的
-- KEEP_UNKNOWN 落行（状态不推进；reason_code=FLOW-RESOLVE-001、result=UNKNOWN
-- 如实留痕，未知不显示安全通过）。网关执行侧不产出该动作（CONFIRM_* 推进复用
-- 词表内 INSTANCE_CONFIRMED/INSTANCE_FAILED + reason_code=FLOW-RESOLVE-001 区分来源）。
BEGIN;

ALTER TABLE api_strong_flow_step_events DROP CONSTRAINT api_strong_flow_step_events_action_check;
ALTER TABLE api_strong_flow_step_events ADD CONSTRAINT api_strong_flow_step_events_action_check
  CHECK (action = ANY (ARRAY['RESERVE','COMMIT','RELEASE','EXPIRE','INSTANCE_NEW',
    'INSTANCE_CONFIRMED','INSTANCE_INDETERMINATE','INSTANCE_CANCELLED','INSTANCE_FAILED','RESOLVE']));

COMMIT;
