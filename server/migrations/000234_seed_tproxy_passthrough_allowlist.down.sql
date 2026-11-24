BEGIN;

DELETE FROM system_settings
WHERE setting_group = 'network' AND setting_key = 'tproxy_passthrough_allowlist';

COMMIT;
