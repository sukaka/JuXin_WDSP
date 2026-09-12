-- 回滚：删除定时报告计划
BEGIN;

ALTER TABLE report_jobs DROP COLUMN IF EXISTS schedule_id;
DROP TABLE IF EXISTS report_schedules;

COMMIT;
