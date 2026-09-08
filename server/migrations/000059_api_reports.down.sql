-- 000059 回滚：report_jobs.report_type 注释词表重置为 NULL（000010 起原列无 COMMENT）。
BEGIN;

COMMENT ON COLUMN report_jobs.report_type IS NULL;

COMMIT;
