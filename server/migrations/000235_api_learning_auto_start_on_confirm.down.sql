BEGIN;

DELETE FROM system_settings
WHERE setting_group = 'api_learning' AND setting_key = 'auto_start_on_confirm';

COMMIT;
