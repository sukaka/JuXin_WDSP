-- 000074 回滚：移除 api_gateway_nodes 同步登记与结果列（聚合/心跳 upsert 不引用这些列，回滚不影响既有视图维护）。
BEGIN;

ALTER TABLE api_gateway_nodes
    DROP COLUMN IF EXISTS admin_addr,
    DROP COLUMN IF EXISTS sync_enabled,
    DROP COLUMN IF EXISTS last_sync_at,
    DROP COLUMN IF EXISTS last_sync_result,
    DROP COLUMN IF EXISTS last_sync_error,
    DROP COLUMN IF EXISTS last_sync_version_id;

COMMIT;
