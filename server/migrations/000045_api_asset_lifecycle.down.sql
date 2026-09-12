-- 000045 回滚：删除 api_endpoints 生命周期增强三列并重置注释词表。
-- 注意：asset_value / zombie_since 的存量赋值随列删除丢失（如实记录，非无损）。
BEGIN;

ALTER TABLE api_endpoints
    DROP COLUMN IF EXISTS asset_value,
    DROP COLUMN IF EXISTS asset_value_explain,
    DROP COLUMN IF EXISTS zombie_since;

-- 恢复原状：000045 之前 asset_status 无 COMMENT（词表仅 SQL 注释约定）
COMMENT ON COLUMN api_endpoints.asset_status IS NULL;

COMMIT;
