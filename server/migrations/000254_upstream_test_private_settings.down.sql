BEGIN;

DELETE FROM system_settings
WHERE setting_group = 'network'
  AND setting_key IN ('upstream_test_allow_private', 'upstream_test_allowed_private_cidrs');

COMMIT;
