BEGIN;

ALTER TABLE api_llm_security_policies
    ADD COLUMN IF NOT EXISTS output_content_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS output_pii_enabled BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN api_llm_security_policies.output_content_enabled IS 'LLM 输出有害内容规则检测；默认 false，既有策略需显式开启';
COMMENT ON COLUMN api_llm_security_policies.output_pii_enabled IS 'LLM 输出 PII 检测；默认 false，既有策略需显式开启';

COMMIT;
