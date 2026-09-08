-- 000110 回滚：删除策略版本快照表与时钟偏移列
BEGIN;

DROP TABLE IF EXISTS agent_policy_versions;
ALTER TABLE agents DROP COLUMN IF EXISTS last_clock_offset_ms;

COMMIT;
