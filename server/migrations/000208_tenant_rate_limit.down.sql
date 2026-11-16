BEGIN;

DELETE FROM system_settings
WHERE setting_group = 'gateway_runtime'
  AND setting_key = 'tenant_rate_per_minute';

COMMIT;
