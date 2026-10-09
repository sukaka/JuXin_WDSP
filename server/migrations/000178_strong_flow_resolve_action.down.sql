-- 000178 回滚：清退 RESOLVE 留痕行后回缩 action 词表至 000177 九词
-- （管理恢复留痕属操作历史，回滚即放弃该留痕——与词表回缩同事务，无半状态）。
BEGIN;

DELETE FROM api_strong_flow_step_events WHERE action = 'RESOLVE';

ALTER TABLE api_strong_flow_step_events DROP CONSTRAINT api_strong_flow_step_events_action_check;
ALTER TABLE api_strong_flow_step_events ADD CONSTRAINT api_strong_flow_step_events_action_check
  CHECK (action = ANY (ARRAY['RESERVE','COMMIT','RELEASE','EXPIRE','INSTANCE_NEW',
    'INSTANCE_CONFIRMED','INSTANCE_INDETERMINATE','INSTANCE_CANCELLED','INSTANCE_FAILED']));

COMMIT;
