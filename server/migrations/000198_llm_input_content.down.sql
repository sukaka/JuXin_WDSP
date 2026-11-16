BEGIN;

ALTER TABLE api_llm_security_policies
    DROP COLUMN IF EXISTS input_content_enabled;

COMMIT;
