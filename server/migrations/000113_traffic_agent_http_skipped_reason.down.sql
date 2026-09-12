-- 000113 回滚：删除 agent_http_events 的 skipped_reason 两列
BEGIN;

ALTER TABLE agent_http_events
    DROP COLUMN IF EXISTS req_skipped_reason,
    DROP COLUMN IF EXISTS resp_skipped_reason;

COMMIT;
