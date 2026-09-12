-- R11: keep endpoint_key as the runtime METHOD + normalized path contract.
-- Scope ownership is persisted separately so equal runtime keys can coexist.
BEGIN;

ALTER TABLE api_endpoints
    ADD COLUMN IF NOT EXISTS application_binding_id UUID,
    ADD COLUMN IF NOT EXISTS host VARCHAR(255) NOT NULL DEFAULT '';

-- Existing rows came from the former globally unique key. Their ownership
-- cannot be reconstructed, so retain them as deterministic legacy rows.
UPDATE api_endpoints
SET host = lower(trim(trailing '.' FROM btrim(host)))
WHERE host IS NOT NULL;

DROP INDEX IF EXISTS idx_api_endpoints_key;
CREATE UNIQUE INDEX IF NOT EXISTS uq_api_endpoints_scope
    ON api_endpoints (application_id, domain_id, application_binding_id, host,
                      endpoint_key, protocol_type) NULLS NOT DISTINCT;
CREATE INDEX IF NOT EXISTS idx_api_endpoints_binding
    ON api_endpoints (application_binding_id);
CREATE INDEX IF NOT EXISTS idx_api_endpoints_host
    ON api_endpoints (host);

COMMIT;
