BEGIN;
DROP TABLE IF EXISTS agent_workload_bindings;
DROP TABLE IF EXISTS agent_api_observation_asset_events;
DROP TABLE IF EXISTS agent_api_observation_receipts;
ALTER TABLE agents DROP COLUMN IF EXISTS api_observation_schemas;
COMMIT;
