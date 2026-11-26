#!/usr/bin/env bash
set -euo pipefail

# Idempotent ClickHouse wdsp.* upgrade script for existing volumes.
# Migrates unpartitioned wdsp.{api_observations,api_field_observations,api_observation_dlq,data_flow_contributions}
# tables via atomic shadow-table rebuild + EXCHANGE TABLES, and idempotently ensures
# skip indexes, TTL, and ttl_only_drop_parts = 1 on already-partitioned tables.

CLICKHOUSE_HOST="${CLICKHOUSE_HOST:-127.0.0.1}"
CLICKHOUSE_PORT="${CLICKHOUSE_PORT:-9000}"
CLICKHOUSE_USER="${CLICKHOUSE_USER:-default}"
CLICKHOUSE_PASSWORD="${CLICKHOUSE_PASSWORD:-}"
CLICKHOUSE_CONTAINER="${CLICKHOUSE_CONTAINER:-}"
CLICKHOUSE_CLIENT="${CLICKHOUSE_CLIENT:-clickhouse-client}"

usage() {
    cat <<'EOF'
Usage: upgrade_wdsp_partition_ttl.sh [options]

Options:
  --host <host>            ClickHouse host (env: CLICKHOUSE_HOST, default: 127.0.0.1)
  --port <port>            ClickHouse native TCP port (env: CLICKHOUSE_PORT, default: 9000)
  --user <user>            ClickHouse user (env: CLICKHOUSE_USER, default: default)
  --password <password>    ClickHouse password (env: CLICKHOUSE_PASSWORD, default: empty)
  --container <name>       Docker container name to exec clickhouse-client inside (env: CLICKHOUSE_CONTAINER)
  --client <bin>           clickhouse-client binary path/name (env: CLICKHOUSE_CLIENT, default: clickhouse-client)
  -h, --help               Show this help message
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)
            CLICKHOUSE_HOST="$2"
            shift 2
            ;;
        --port)
            CLICKHOUSE_PORT="$2"
            shift 2
            ;;
        --user)
            CLICKHOUSE_USER="$2"
            shift 2
            ;;
        --password)
            CLICKHOUSE_PASSWORD="$2"
            shift 2
            ;;
        --container)
            CLICKHOUSE_CONTAINER="$2"
            shift 2
            ;;
        --client)
            CLICKHOUSE_CLIENT="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

run_ch() {
    local mode="$1"
    shift
    local -a cmd=("$CLICKHOUSE_CLIENT" "--host" "$CLICKHOUSE_HOST" "--port" "$CLICKHOUSE_PORT" "--user" "$CLICKHOUSE_USER")
    if [[ -n "$CLICKHOUSE_PASSWORD" ]]; then
        cmd+=("--password" "$CLICKHOUSE_PASSWORD")
    fi
    if [[ "$mode" == "multiquery" ]]; then
        cmd+=("--multiquery")
    else
        cmd+=("--format" "TabSeparatedRaw")
    fi

    if [[ -n "$CLICKHOUSE_CONTAINER" ]]; then
        docker exec -i "$CLICKHOUSE_CONTAINER" "${cmd[@]}" "$@"
    else
        "${cmd[@]}" "$@"
    fi
}

ch_query() {
    local sql="$1"
    printf '%s\n' "$sql" | run_ch query
}

ch_exec() {
    local sql="$1"
    printf '%s\n' "$sql" | run_ch multiquery
}

log() {
    printf '[%s] %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*"
}

table_exists() {
    local table="$1"
    local count
    count="$(ch_query "SELECT count() FROM system.tables WHERE database = 'wdsp' AND name = '${table}'")"
    [[ "$count" == "1" ]]
}

get_partition_key() {
    local table="$1"
    ch_query "SELECT partition_key FROM system.tables WHERE database = 'wdsp' AND name = '${table}'"
}

ensure_skip_index() {
    local table="$1"
    local idx_name="$2"
    local idx_def="$3"
    local exists
    exists="$(ch_query "SELECT count() FROM system.data_skipping_indices WHERE database = 'wdsp' AND table = '${table}' AND name = '${idx_name}'")"
    if [[ "$exists" == "0" ]]; then
        log "Adding and materializing skip index ${idx_name} on wdsp.${table}"
        ch_exec "
            ALTER TABLE wdsp.${table} ADD INDEX IF NOT EXISTS ${idx_name} ${idx_def};
            ALTER TABLE wdsp.${table} MATERIALIZE INDEX ${idx_name} SETTINGS mutations_sync = 1;
        "
    else
        log "Skip index ${idx_name} already exists on wdsp.${table}; skipping materialize"
    fi
}

ensure_legacy_columns_api_observations() {
    ch_exec "
        ALTER TABLE wdsp.api_observations ADD COLUMN IF NOT EXISTS peer_address String CODEC(ZSTD(1)) AFTER peer_service;
        ALTER TABLE wdsp.api_observations ADD COLUMN IF NOT EXISTS client_address String CODEC(ZSTD(1)) AFTER peer_address;
        ALTER TABLE wdsp.api_observations ADD COLUMN IF NOT EXISTS client_address_source LowCardinality(String) CODEC(ZSTD(1)) AFTER client_address;
        ALTER TABLE wdsp.api_observations ADD COLUMN IF NOT EXISTS server_address String CODEC(ZSTD(1)) AFTER client_address_source;
    "
}

ensure_legacy_columns_data_flow_contributions() {
    ch_exec "
        ALTER TABLE wdsp.data_flow_contributions ADD COLUMN IF NOT EXISTS peer_address String CODEC(ZSTD(1)) AFTER span_id;
        ALTER TABLE wdsp.data_flow_contributions ADD COLUMN IF NOT EXISTS client_address String CODEC(ZSTD(1)) AFTER peer_address;
        ALTER TABLE wdsp.data_flow_contributions ADD COLUMN IF NOT EXISTS client_address_source LowCardinality(String) CODEC(ZSTD(1)) AFTER client_address;
        ALTER TABLE wdsp.data_flow_contributions ADD COLUMN IF NOT EXISTS server_address String CODEC(ZSTD(1)) AFTER client_address_source;
        ALTER TABLE wdsp.data_flow_contributions ADD COLUMN IF NOT EXISTS source_zone LowCardinality(String) CODEC(ZSTD(1)) AFTER server_address;
        ALTER TABLE wdsp.data_flow_contributions ADD COLUMN IF NOT EXISTS target_zone LowCardinality(String) CODEC(ZSTD(1)) AFTER source_zone;
        ALTER TABLE wdsp.data_flow_contributions ADD COLUMN IF NOT EXISTS boundary_type LowCardinality(String) CODEC(ZSTD(1)) AFTER target_zone;
        ALTER TABLE wdsp.data_flow_contributions ADD COLUMN IF NOT EXISTS boundary_evidence LowCardinality(String) CODEC(ZSTD(1)) AFTER boundary_type;
    "
}

create_target_table_sql() {
    local target_name="$1"
    case "$target_name" in
        api_observations*)
            cat <<EOF
CREATE TABLE wdsp.${target_name} (
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
EOF
            ;;
        api_field_observations*)
            cat <<EOF
CREATE TABLE wdsp.${target_name} (
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
EOF
            ;;
        api_observation_dlq*)
            cat <<EOF
CREATE TABLE wdsp.${target_name} (
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
EOF
            ;;
        data_flow_contributions*)
            cat <<EOF
CREATE TABLE wdsp.${target_name} (
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
EOF
            ;;
        *)
            echo "Unknown table target: $target_name" >&2
            exit 1
            ;;
    esac
}

columns_for_table() {
    case "$1" in
        api_observations)
            echo "agent_id, event_id, application_id, application_binding_id, binding_version, occurred_at, received_at, source_type, language, framework, agent_version, source_epoch, service_name, service_instance_id, service_version, environment, namespace, cluster, trace_id, span_id, parent_span_id, direction, method, scheme, host, route, path_template, status, latency_ms, request_content_type, response_content_type, peer_service, peer_address, client_address, client_address_source, server_address, messaging_system, messaging_destination, quality_json, ingested_at"
            ;;
        api_field_observations)
            echo "agent_id, event_id, occurred_at, side, location, field_path, data_type, level, value_hmac, hmac_key_id, value_present, truncated, ingested_at"
            ;;
        api_observation_dlq)
            echo "agent_id, event_id, topic, partition_id, offset_id, payload, error_category, error_message, retry_count, created_at"
            ;;
        data_flow_contributions)
            echo "agent_id, event_id, edge_id, occurred_at, received_at, application_id, source_node, source_type, target_node, target_type, protocol, method, path_template, status, latency_ms, error, count_weight, data_types_json, field_evidence_json, evidence_type, confidence, trace_id, span_id, peer_address, client_address, client_address_source, server_address, source_zone, target_zone, boundary_type, boundary_evidence"
            ;;
        *)
            echo "Unknown table: $1" >&2
            exit 1
            ;;
    esac
}

shadow_rebuild_table() {
    local table="$1"
    local catchup_mode="$2"
    local cols
    cols="$(columns_for_table "$table")"
    local migrating="${table}_migrating"
    local upgrade_start_utc
    upgrade_start_utc="$(ch_query "SELECT toString(now64(6, 'UTC'))")"

    local pre_dlq_count="0"
    local pre_dlq_max_ts=""
    if [[ "$catchup_mode" == "dlq" ]]; then
        pre_dlq_count="$(ch_query "SELECT count() FROM wdsp.${table}")"
        if [[ "$pre_dlq_count" != "0" ]]; then
            pre_dlq_max_ts="$(ch_query "SELECT toString(max(created_at)) FROM wdsp.${table}")"
        fi
    fi

    log "Rebuilding wdsp.${table} via atomic shadow table wdsp.${migrating} (start=${upgrade_start_utc})"
    ch_exec "DROP TABLE IF EXISTS wdsp.${migrating};"
    ch_exec "$(create_target_table_sql "$migrating")"
    ch_exec "INSERT INTO wdsp.${migrating} (${cols}) SELECT ${cols} FROM wdsp.${table};"
    ch_exec "EXCHANGE TABLES wdsp.${table} AND wdsp.${migrating};"

    case "$catchup_mode" in
        received_at)
            ch_exec "INSERT INTO wdsp.${table} (${cols}) SELECT ${cols} FROM wdsp.${migrating} WHERE received_at >= toDateTime64('${upgrade_start_utc}', 6, 'UTC');"
            ;;
        ingested_at)
            ch_exec "INSERT INTO wdsp.${table} (${cols}) SELECT ${cols} FROM wdsp.${migrating} WHERE ingested_at >= toDateTime64('${upgrade_start_utc}', 6, 'UTC');"
            ;;
        dlq)
            if [[ "$pre_dlq_count" == "0" ]]; then
                ch_exec "INSERT INTO wdsp.${table} (${cols}) SELECT ${cols} FROM wdsp.${migrating};"
            else
                ch_exec "INSERT INTO wdsp.${table} (${cols}) SELECT ${cols} FROM wdsp.${migrating} WHERE created_at > toDateTime64('${pre_dlq_max_ts}', 6, 'UTC');"
            fi
            ;;
        *)
            echo "Unknown catchup mode: $catchup_mode" >&2
            exit 1
            ;;
    esac

    ch_exec "DROP TABLE IF EXISTS wdsp.${migrating};"
    log "Completed shadow rebuild for wdsp.${table}"
}

upgrade_table() {
    local table="$1"
    local expected_partition_key="$2"
    local ttl_expr="$3"
    local catchup_mode="$4"

    if ! table_exists "$table"; then
        log "Table wdsp.${table} does not exist yet; creating with target schema"
        ch_exec "$(create_target_table_sql "$table")"
        return 0
    fi

    if [[ "$table" == "api_observations" ]]; then
        ensure_legacy_columns_api_observations
    elif [[ "$table" == "data_flow_contributions" ]]; then
        ensure_legacy_columns_data_flow_contributions
    fi

    local current_partition_key
    current_partition_key="$(get_partition_key "$table")"
    if [[ "$current_partition_key" != "$expected_partition_key" ]]; then
        log "wdsp.${table} partition_key='${current_partition_key}' != '${expected_partition_key}'"
        shadow_rebuild_table "$table" "$catchup_mode"
        return 0
    fi

    log "wdsp.${table} already partitioned (${current_partition_key}); verifying indexes, TTL, and settings"
    case "$table" in
        api_observations)
            ensure_skip_index "$table" "idx_trace_id" "trace_id TYPE bloom_filter(0.001) GRANULARITY 1"
            ensure_skip_index "$table" "idx_occurred_at" "occurred_at TYPE minmax GRANULARITY 1"
            ensure_skip_index "$table" "idx_application_id" "application_id TYPE set(100) GRANULARITY 1"
            ;;
        api_field_observations)
            ensure_skip_index "$table" "idx_occurred_at" "occurred_at TYPE minmax GRANULARITY 1"
            ;;
        api_observation_dlq)
            ensure_skip_index "$table" "idx_created_at" "created_at TYPE minmax GRANULARITY 1"
            ;;
        data_flow_contributions)
            ensure_skip_index "$table" "idx_occurred_at" "occurred_at TYPE minmax GRANULARITY 1"
            ensure_skip_index "$table" "idx_edge_id" "edge_id TYPE bloom_filter(0.001) GRANULARITY 1"
            ensure_skip_index "$table" "idx_application_id" "application_id TYPE set(100) GRANULARITY 1"
            ensure_skip_index "$table" "idx_trace_id" "trace_id TYPE bloom_filter(0.001) GRANULARITY 1"
            ;;
    esac

    ch_exec "
        ALTER TABLE wdsp.${table} MODIFY SETTING ttl_only_drop_parts = 1;
        ALTER TABLE wdsp.${table} MODIFY TTL ${ttl_expr};
    "
}

main() {
    log "Ensuring wdsp database exists"
    ch_exec "CREATE DATABASE IF NOT EXISTS wdsp;"

    upgrade_table "api_observations" "toDate(occurred_at)" "occurred_at + toIntervalDay(14)" "received_at"
    upgrade_table "api_field_observations" "toDate(occurred_at)" "occurred_at + toIntervalDay(14)" "ingested_at"
    upgrade_table "api_observation_dlq" "toDate(created_at)" "created_at + toIntervalDay(7)" "dlq"
    upgrade_table "data_flow_contributions" "toDate(occurred_at)" "occurred_at + toIntervalDay(30)" "received_at"

    log "wdsp.* partition, TTL, codec, and skip-index upgrade completed successfully"
}

main
