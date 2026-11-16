BEGIN;

ALTER TABLE api_llm_security_policies
    DROP COLUMN IF EXISTS output_content_enabled,
    DROP COLUMN IF EXISTS output_pii_enabled;

COMMIT;
