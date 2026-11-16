CREATE DATABASE IF NOT EXISTS wdsp;

CREATE TABLE IF NOT EXISTS wdsp.api_observations (
    agent_id UUID,
    event_id String,
    application_id Nullable(UUID),
    application_binding_id Nullable(UUID),
    binding_version Nullable(Int64),
    occurred_at DateTime64(6, 'UTC'),
    received_at DateTime64(6, 'UTC'),
    source_type LowCardinality(String),
    language LowCardinality(String),
    framework LowCardinality(String),
    agent_version String,
    source_epoch Int64,
    service_name String,
    service_instance_id String,
    service_version String,
    environment LowCardinality(String),
    namespace String,
    cluster String,
    trace_id FixedString(32),
    span_id FixedString(16),
    parent_span_id FixedString(16),
    direction LowCardinality(String),
    method LowCardinality(String),
    scheme LowCardinality(String),
    host String,
    route String,
    path_template String,
    status UInt16,
    latency_ms UInt32,
    request_content_type String,
    response_content_type String,
    peer_service String,
    peer_address String,
    client_address String,
    client_address_source LowCardinality(String),
    server_address String,
    messaging_system LowCardinality(String),
    messaging_destination String,
    quality_json String,
    ingested_at DateTime64(6, 'UTC') DEFAULT now64(6)
) ENGINE = ReplacingMergeTree(received_at)
ORDER BY (agent_id, event_id)
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS wdsp.api_field_observations (
    agent_id UUID,
    event_id String,
    occurred_at DateTime64(6, 'UTC'),
    side LowCardinality(String),
    location LowCardinality(String),
    field_path String,
    data_type LowCardinality(String),
    level LowCardinality(String),
    value_hmac String,
    hmac_key_id String,
    value_present Bool,
    truncated Bool,
    ingested_at DateTime64(6, 'UTC') DEFAULT now64(6)
) ENGINE = ReplacingMergeTree(ingested_at)
ORDER BY (agent_id, event_id, side, location, field_path, data_type, hmac_key_id, value_hmac)
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS wdsp.api_observation_dlq (
    agent_id String,
    event_id String,
    topic String,
    partition_id Int32,
    offset_id Int64,
    payload String,
    error_category LowCardinality(String),
    error_message String,
    retry_count UInt32,
    created_at DateTime64(6, 'UTC') DEFAULT now64(6)
) ENGINE = MergeTree
ORDER BY (event_id, created_at)
TTL created_at + INTERVAL 7 DAY;

ALTER TABLE wdsp.api_observations ADD COLUMN IF NOT EXISTS peer_address String AFTER peer_service;
