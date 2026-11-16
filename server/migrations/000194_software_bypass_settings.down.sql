BEGIN;

DELETE FROM system_settings
WHERE setting_group = 'software_bypass'
  AND setting_key IN ('enabled', 'cpu_threshold_percent', 'memory_threshold_percent', 'min_hold_seconds', 'session_cookie_names');

COMMIT;
