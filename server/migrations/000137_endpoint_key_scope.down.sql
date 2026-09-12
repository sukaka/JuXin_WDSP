BEGIN;

DROP INDEX IF EXISTS uq_api_endpoints_scope;
DROP INDEX IF EXISTS idx_api_endpoints_binding;
DROP INDEX IF EXISTS idx_api_endpoints_host;
ALTER TABLE api_endpoints
    DROP COLUMN IF EXISTS application_binding_id,
    DROP COLUMN IF EXISTS host;
CREATE UNIQUE INDEX IF NOT EXISTS idx_api_endpoints_key
    ON api_endpoints (endpoint_key);

COMMIT;
