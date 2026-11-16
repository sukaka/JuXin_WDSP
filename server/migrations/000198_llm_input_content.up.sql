BEGIN;

ALTER TABLE api_llm_security_policies
    ADD COLUMN IF NOT EXISTS input_content_enabled BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN api_llm_security_policies.input_content_enabled IS 'LLM 输入有害内容高置信规则检测；默认 false，既有策略需显式开启';

COMMIT;
