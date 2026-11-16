BEGIN;

DELETE FROM system_settings
WHERE setting_group = 'gateway_runtime'
  AND setting_key IN ('api_rate_limit_action', 'api_temp_block_seconds');

COMMIT;
