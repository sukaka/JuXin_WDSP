BEGIN;

DELETE FROM system_settings
WHERE setting_group = 'gateway_runtime'
  AND setting_key = 'action_rate_per_minute';

COMMIT;
