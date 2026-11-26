CREATE DATABASE IF NOT EXISTS wdsp;

CREATE TABLE IF NOT EXISTS wdsp.api_observations (
    agent_id UUID CODEC(ZSTD(1)),
    event_id String CODEC(ZSTD(1)),
    application_id Nullable(UUID) CODEC(ZSTD(1)),
    application_binding_id Nullable(UUID) CODEC(ZSTD(1)),
    binding_version Nullable(Int64) CODEC(ZSTD(1)),
    occurred_at DateTime64(6, 'UTC') CODEC(Delta, ZSTD(1)),
    received_at DateTime64(6, 'UTC') CODEC(Delta, ZSTD(1)),
    source_type LowCardinality(String) CODEC(ZSTD(1)),
    language LowCardinality(String) CODEC(ZSTD(1)),
    framework LowCardinality(String) CODEC(ZSTD(1)),
    agent_version String CODEC(ZSTD(1)),
    source_epoch Int64 CODEC(ZSTD(1)),
    service_name String CODEC(ZSTD(1)),
    service_instance_id String CODEC(ZSTD(1)),
    service_version String CODEC(ZSTD(1)),
    environment LowCardinality(String) CODEC(ZSTD(1)),
    namespace String CODEC(ZSTD(1)),
    cluster String CODEC(ZSTD(1)),
    trace_id FixedString(32) CODEC(ZSTD(1)),
    span_id FixedString(16) CODEC(ZSTD(1)),
    parent_span_id FixedString(16) CODEC(ZSTD(1)),
    direction LowCardinality(String) CODEC(ZSTD(1)),
    method LowCardinality(String) CODEC(ZSTD(1)),
    scheme LowCardinality(String) CODEC(ZSTD(1)),
    host String CODEC(ZSTD(1)),
    route String CODEC(ZSTD(1)),
    path_template String CODEC(ZSTD(1)),
    status UInt16 CODEC(ZSTD(1)),
    latency_ms UInt32 CODEC(ZSTD(1)),
    request_content_type String CODEC(ZSTD(1)),
    response_content_type String CODEC(ZSTD(1)),
    peer_service String CODEC(ZSTD(1)),
    peer_address String CODEC(ZSTD(1)),
    client_address String CODEC(ZSTD(1)),
    client_address_source LowCardinality(String) CODEC(ZSTD(1)),
    server_address String CODEC(ZSTD(1)),
    messaging_system LowCardinality(String) CODEC(ZSTD(1)),
    messaging_destination String CODEC(ZSTD(1)),
    quality_json String CODEC(ZSTD(1)),
    ingested_at DateTime64(6, 'UTC') DEFAULT now64(6) CODEC(Delta, ZSTD(1)),
    INDEX idx_trace_id trace_id TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_occurred_at occurred_at TYPE minmax GRANULARITY 1,
    INDEX idx_application_id application_id TYPE set(100) GRANULARITY 1
) ENGINE = ReplacingMergeTree(received_at)
PARTITION BY toDate(occurred_at)
ORDER BY (agent_id, event_id)
TTL occurred_at + toIntervalDay(14)
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;

CREATE TABLE IF NOT EXISTS wdsp.api_field_observations (
    agent_id UUID CODEC(ZSTD(1)),
    event_id String CODEC(ZSTD(1)),
    occurred_at DateTime64(6, 'UTC') CODEC(Delta, ZSTD(1)),
    side LowCardinality(String) CODEC(ZSTD(1)),
    location LowCardinality(String) CODEC(ZSTD(1)),
    field_path String CODEC(ZSTD(1)),
    data_type LowCardinality(String) CODEC(ZSTD(1)),
    level LowCardinality(String) CODEC(ZSTD(1)),
    value_hmac String CODEC(ZSTD(1)),
    hmac_key_id String CODEC(ZSTD(1)),
    value_present Bool CODEC(ZSTD(1)),
    truncated Bool CODEC(ZSTD(1)),
    ingested_at DateTime64(6, 'UTC') DEFAULT now64(6) CODEC(Delta, ZSTD(1)),
    INDEX idx_occurred_at occurred_at TYPE minmax GRANULARITY 1
) ENGINE = ReplacingMergeTree(ingested_at)
PARTITION BY toDate(occurred_at)
ORDER BY (agent_id, event_id, side, location, field_path, data_type, hmac_key_id, value_hmac)
TTL occurred_at + toIntervalDay(14)
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;

CREATE TABLE IF NOT EXISTS wdsp.api_observation_dlq (
    agent_id String CODEC(ZSTD(1)),
    event_id String CODEC(ZSTD(1)),
    topic String CODEC(ZSTD(1)),
    partition_id Int32 CODEC(ZSTD(1)),
    offset_id Int64 CODEC(ZSTD(1)),
    payload String CODEC(ZSTD(1)),
    error_category LowCardinality(String) CODEC(ZSTD(1)),
    error_message String CODEC(ZSTD(1)),
    retry_count UInt32 CODEC(ZSTD(1)),
    created_at DateTime64(6, 'UTC') DEFAULT now64(6) CODEC(Delta, ZSTD(1)),
    INDEX idx_created_at created_at TYPE minmax GRANULARITY 1
) ENGINE = MergeTree
PARTITION BY toDate(created_at)
ORDER BY (event_id, created_at)
TTL created_at + toIntervalDay(7)
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;

ALTER TABLE wdsp.api_observations ADD COLUMN IF NOT EXISTS peer_address String CODEC(ZSTD(1)) AFTER peer_service;
