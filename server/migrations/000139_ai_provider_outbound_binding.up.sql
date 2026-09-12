BEGIN;

ALTER TABLE ai_model_providers
    ADD COLUMN IF NOT EXISTS canonical_origin VARCHAR(320) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS allowed_targets TEXT[] NOT NULL DEFAULT '{}';

COMMENT ON COLUMN ai_model_providers.canonical_origin IS
    'Credential binding: canonical scheme://host:port for the provider BaseURL';
COMMENT ON COLUMN ai_model_providers.allowed_targets IS
    'Provider-scoped private/local outbound target allowlist';

COMMIT;
