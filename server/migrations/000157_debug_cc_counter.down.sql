BEGIN;

DELETE FROM system_settings WHERE setting_group = 'gateway_runtime' AND setting_key = 'debug_cc_counter';

COMMIT;
