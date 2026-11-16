CREATE DATABASE IF NOT EXISTS wdsp;

CREATE TABLE IF NOT EXISTS wdsp.data_flow_contributions (
    agent_id UUID,
    event_id String,
    edge_id FixedString(64),
    occurred_at DateTime64(6, 'UTC'),
    received_at DateTime64(6, 'UTC') DEFAULT now64(6),
    application_id Nullable(UUID),
    source_node String,
    source_type LowCardinality(String),
    target_node String,
    target_type LowCardinality(String),
    protocol LowCardinality(String),
    method LowCardinality(String),
    path_template String,
    status UInt16,
    latency_ms UInt32,
    error UInt8,
    count_weight UInt64,
    data_types_json String,
    field_evidence_json String,
    evidence_type LowCardinality(String),
    confidence Float32,
    trace_id FixedString(32),
    span_id FixedString(16),
    peer_address String,
    client_address String,
    client_address_source LowCardinality(String),
    server_address String,
    source_zone LowCardinality(String),
    target_zone LowCardinality(String),
    boundary_type LowCardinality(String),
    boundary_evidence LowCardinality(String)
) ENGINE = ReplacingMergeTree(received_at)
ORDER BY (agent_id, event_id, edge_id)
SETTINGS index_granularity = 8192;
