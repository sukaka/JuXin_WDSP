-- 000105 down：移除 api_assets.business_type。
BEGIN;

ALTER TABLE api_assets DROP COLUMN IF EXISTS business_type;

COMMIT;
