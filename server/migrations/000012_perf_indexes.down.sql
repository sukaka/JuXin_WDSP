-- 阶段6 性能索引回滚

BEGIN;

DROP INDEX IF EXISTS idx_security_events_disposition_severity;
DROP INDEX IF EXISTS idx_ac_events_disposition_time;
ALTER TABLE uri_security_summaries DROP COLUMN IF EXISTS waf_blocks;

COMMIT;
