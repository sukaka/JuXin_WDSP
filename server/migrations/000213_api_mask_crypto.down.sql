BEGIN;

DELETE FROM system_settings
WHERE setting_group = 'gateway_runtime'
  AND setting_key IN ('api_mask_encryption_kid', 'api_mask_encryption_key');
DELETE FROM api_masking_rules WHERE algorithm IN ('ENCRYPT', 'MAP');

ALTER TABLE api_masking_rules DROP CONSTRAINT IF EXISTS api_masking_rules_algorithm_check;
ALTER TABLE api_masking_rules
    ADD CONSTRAINT api_masking_rules_algorithm_check
    CHECK (algorithm IN ('MASK','HASH','REMOVE'));

COMMIT;
