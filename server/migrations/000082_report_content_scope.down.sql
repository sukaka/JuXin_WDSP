-- 回滚：删除 report_jobs.content_scope
BEGIN;

ALTER TABLE report_jobs DROP COLUMN IF EXISTS content_scope;

COMMIT;
