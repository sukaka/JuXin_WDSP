-- 回滚：删除全量 API 资产清单选项
BEGIN;

ALTER TABLE report_jobs DROP COLUMN IF EXISTS include_api_assets;
ALTER TABLE report_schedules DROP COLUMN IF EXISTS include_api_assets;

COMMIT;
