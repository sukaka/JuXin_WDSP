-- 000237 回滚：移除 upgrade_node_executions 表及 upgrade_jobs.cluster_mode 列。
BEGIN;

DROP INDEX IF EXISTS idx_upgrade_node_executions_job_seq;
DROP TABLE IF EXISTS upgrade_node_executions;

ALTER TABLE upgrade_jobs
    DROP COLUMN IF EXISTS cluster_mode;

COMMIT;
