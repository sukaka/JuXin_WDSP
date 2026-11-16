BEGIN;

ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS api_observation_schemas SMALLINT[] NOT NULL DEFAULT '{}';

CREATE TABLE IF NOT EXISTS agent_api_observation_receipts (
    agent_id UUID NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    event_id VARCHAR(128) NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_id, event_id)
);
CREATE INDEX IF NOT EXISTS idx_agent_api_observation_receipts_received
    ON agent_api_observation_receipts (received_at);

CREATE TABLE IF NOT EXISTS agent_api_observation_asset_events (
    agent_id UUID NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    event_id VARCHAR(128) NOT NULL,
    endpoint_key TEXT NOT NULL,
    projected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_id, event_id, endpoint_key)
);

CREATE TABLE IF NOT EXISTS agent_workload_bindings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    traffic_agent_id UUID NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    apm_agent_id UUID NULL,
    application_id UUID NULL REFERENCES applications(id) ON DELETE CASCADE,
    service_name VARCHAR(128) NOT NULL,
    environment VARCHAR(64) NOT NULL DEFAULT '',
    binding_version BIGINT NOT NULL CHECK (binding_version > 0),
    status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','REVOKED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (traffic_agent_id, service_name, environment, binding_version)
);
CREATE INDEX IF NOT EXISTS idx_agent_workload_bindings_app_service
    ON agent_workload_bindings (application_id, service_name, environment, status);

COMMIT;
