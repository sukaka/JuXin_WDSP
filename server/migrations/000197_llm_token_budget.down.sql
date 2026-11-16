BEGIN;

ALTER TABLE api_llm_security_policies
    DROP COLUMN IF EXISTS max_output_tokens;

COMMIT;
