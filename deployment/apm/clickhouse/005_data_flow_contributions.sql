CREATE DATABASE IF NOT EXISTS wdsp;

CREATE TABLE IF NOT EXISTS wdsp.data_flow_contributions (
    agent_id UUID CODEC(ZSTD(1)),
    event_id String CODEC(ZSTD(1)),
    edge_id FixedString(64) CODEC(ZSTD(1)),
    occurred_at DateTime64(6, 'UTC') CODEC(Delta, ZSTD(1)),
    received_at DateTime64(6, 'UTC') DEFAULT now64(6) CODEC(Delta, ZSTD(1)),
    application_id Nullable(UUID) CODEC(ZSTD(1)),
    source_node String CODEC(ZSTD(1)),
    source_type LowCardinality(String) CODEC(ZSTD(1)),
    target_node String CODEC(ZSTD(1)),
    target_type LowCardinality(String) CODEC(ZSTD(1)),
    protocol LowCardinality(String) CODEC(ZSTD(1)),
    method LowCardinality(String) CODEC(ZSTD(1)),
    path_template String CODEC(ZSTD(1)),
    status UInt16 CODEC(ZSTD(1)),
    latency_ms UInt32 CODEC(ZSTD(1)),
    error UInt8 CODEC(ZSTD(1)),
    count_weight UInt64 CODEC(ZSTD(1)),
    data_types_json String CODEC(ZSTD(1)),
    field_evidence_json String CODEC(ZSTD(1)),
    evidence_type LowCardinality(String) CODEC(ZSTD(1)),
    confidence Float32 CODEC(ZSTD(1)),
    trace_id FixedString(32) CODEC(ZSTD(1)),
    span_id FixedString(16) CODEC(ZSTD(1)),
    peer_address String CODEC(ZSTD(1)),
    client_address String CODEC(ZSTD(1)),
    client_address_source LowCardinality(String) CODEC(ZSTD(1)),
    server_address String CODEC(ZSTD(1)),
    source_zone LowCardinality(String) CODEC(ZSTD(1)),
    target_zone LowCardinality(String) CODEC(ZSTD(1)),
    boundary_type LowCardinality(String) CODEC(ZSTD(1)),
    boundary_evidence LowCardinality(String) CODEC(ZSTD(1)),
    INDEX idx_occurred_at occurred_at TYPE minmax GRANULARITY 1,
    INDEX idx_edge_id edge_id TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_application_id application_id TYPE set(100) GRANULARITY 1,
    INDEX idx_trace_id trace_id TYPE bloom_filter(0.001) GRANULARITY 1
) ENGINE = ReplacingMergeTree(received_at)
PARTITION BY toDate(occurred_at)
ORDER BY (agent_id, event_id, edge_id)
TTL occurred_at + toIntervalDay(30)
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;
