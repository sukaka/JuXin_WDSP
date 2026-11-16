BEGIN;

ALTER TABLE api_llm_security_policies
    ADD COLUMN IF NOT EXISTS max_output_tokens INTEGER NOT NULL DEFAULT 0
        CHECK (max_output_tokens >= 0 AND max_output_tokens <= 1000000);

COMMENT ON COLUMN api_llm_security_policies.max_output_tokens IS '单次请求声明的输出 Token 上限；0=不限制，非实际用量或累计配额';

COMMIT;
