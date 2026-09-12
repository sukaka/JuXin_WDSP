-- 000152 down：移除 gateway_runtime 组限流阈值设置种子行
BEGIN;

DELETE FROM system_settings
WHERE setting_group = 'gateway_runtime'
  AND setting_key IN ('api_quota_per_hour', 'api_quota_per_day', 'object_rate_per_minute', 'max_page_size', 'max_batch_size');

COMMIT;
