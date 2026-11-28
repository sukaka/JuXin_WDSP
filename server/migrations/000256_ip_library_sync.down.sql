BEGIN;

DELETE FROM role_permissions
WHERE permission_id IN (
    SELECT id FROM permissions
    WHERE code IN ('geoip.read', 'geoip.manage', 'threat_intel.read', 'threat_intel.manage')
);

DELETE FROM permissions
WHERE code IN ('geoip.read', 'geoip.manage', 'threat_intel.read', 'threat_intel.manage');

DELETE FROM system_settings
WHERE (setting_group = 'ip_library' AND setting_key IN (
    'outbound_allowlist', 'allow_insecure_http_mirror', 'proxy_url', 'proxy_auth_encrypted', 'http_timeout_seconds'
)) OR (setting_group = 'geoip' AND setting_key IN (
    'auto_update_enabled', 'schedule_cron', 'ha_sync_enabled', 'maxmind_account_id', 'maxmind_license_key_encrypted'
)) OR (setting_group = 'threat_intel' AND setting_key IN (
    'auto_update_enabled', 'circuit_threshold'
));

DROP TABLE IF EXISTS threat_intel_sync_runs;
DROP TABLE IF EXISTS threat_intel_feeds;
DROP TABLE IF EXISTS geoip_sync_runs;
DROP TABLE IF EXISTS geoip_slot_configs;

COMMIT;
