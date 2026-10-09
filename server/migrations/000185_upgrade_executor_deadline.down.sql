-- 000185 回滚：移除升级任务执行器等待截止列。
BEGIN;

ALTER TABLE upgrade_jobs DROP COLUMN IF EXISTS executor_deadline;

COMMIT;
