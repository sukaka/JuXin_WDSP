-- 回滚：删除纸张方向选项
BEGIN;

ALTER TABLE report_jobs DROP COLUMN IF EXISTS page_orientation;
ALTER TABLE report_schedules DROP COLUMN IF EXISTS page_orientation;

COMMIT;
