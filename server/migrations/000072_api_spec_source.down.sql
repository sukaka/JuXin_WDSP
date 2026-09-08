-- 000072 回滚：移除 api_import_specs.source 列
BEGIN;

ALTER TABLE api_import_specs DROP COLUMN IF EXISTS source;

COMMIT;
