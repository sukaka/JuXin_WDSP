ALTER TABLE wdsp.api_observations ADD COLUMN IF NOT EXISTS client_address String CODEC(ZSTD(1)) AFTER peer_address;
ALTER TABLE wdsp.api_observations ADD COLUMN IF NOT EXISTS client_address_source LowCardinality(String) CODEC(ZSTD(1)) AFTER client_address;
ALTER TABLE wdsp.api_observations ADD COLUMN IF NOT EXISTS server_address String CODEC(ZSTD(1)) AFTER client_address_source;

ALTER TABLE wdsp.data_flow_contributions ADD COLUMN IF NOT EXISTS peer_address String CODEC(ZSTD(1)) AFTER span_id;
ALTER TABLE wdsp.data_flow_contributions ADD COLUMN IF NOT EXISTS client_address String CODEC(ZSTD(1)) AFTER peer_address;
ALTER TABLE wdsp.data_flow_contributions ADD COLUMN IF NOT EXISTS client_address_source LowCardinality(String) CODEC(ZSTD(1)) AFTER client_address;
ALTER TABLE wdsp.data_flow_contributions ADD COLUMN IF NOT EXISTS server_address String CODEC(ZSTD(1)) AFTER client_address_source;
ALTER TABLE wdsp.data_flow_contributions ADD COLUMN IF NOT EXISTS source_zone LowCardinality(String) CODEC(ZSTD(1)) AFTER server_address;
ALTER TABLE wdsp.data_flow_contributions ADD COLUMN IF NOT EXISTS target_zone LowCardinality(String) CODEC(ZSTD(1)) AFTER source_zone;
ALTER TABLE wdsp.data_flow_contributions ADD COLUMN IF NOT EXISTS boundary_type LowCardinality(String) CODEC(ZSTD(1)) AFTER target_zone;
ALTER TABLE wdsp.data_flow_contributions ADD COLUMN IF NOT EXISTS boundary_evidence LowCardinality(String) CODEC(ZSTD(1)) AFTER boundary_type;
