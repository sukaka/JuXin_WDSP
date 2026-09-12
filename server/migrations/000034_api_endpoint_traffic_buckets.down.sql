-- 000034 回滚：删除 api_endpoint_traffic_buckets。
BEGIN;

DROP TABLE IF EXISTS api_endpoint_traffic_buckets;

COMMIT;
