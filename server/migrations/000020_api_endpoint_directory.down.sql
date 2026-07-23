-- 000020 回滚
BEGIN;

DROP INDEX IF EXISTS idx_api_endpoints_directory;
ALTER TABLE api_endpoints DROP COLUMN IF EXISTS directory_path;

COMMIT;
