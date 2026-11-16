#!/usr/bin/env bash
set -euo pipefail

: "${BOOTSTRAP_SERVERS:?required}"
PARTITIONS="${API_OBSERVATION_PARTITIONS:-3}"
REPLICATION="${TOPIC_REPLICATION_FACTOR:-1}"
CLIENT_CONFIG=""

cleanup() {
  if [[ -n "${CLIENT_CONFIG}" ]]; then
    rm -f "${CLIENT_CONFIG}"
  fi
}
trap cleanup EXIT

ARGS=()
if [[ "${KAFKA_SSL_ENABLED:-false}" == "true" ]]; then
  umask 077
  CLIENT_CONFIG="$(mktemp)"
  {
    printf 'security.protocol=SSL\n'
    printf 'ssl.keystore.location=%s\n' "${KAFKA_SSL_KEYSTORE_LOCATION:?required}"
    printf 'ssl.keystore.password=%s\n' "${KAFKA_SSL_KEYSTORE_PASSWORD:?required}"
    printf 'ssl.key.password=%s\n' "${KAFKA_SSL_KEY_PASSWORD:?required}"
    printf 'ssl.truststore.location=%s\n' "${KAFKA_SSL_TRUSTSTORE_LOCATION:?required}"
    printf 'ssl.truststore.password=%s\n' "${KAFKA_SSL_TRUSTSTORE_PASSWORD:?required}"
  } >"${CLIENT_CONFIG}"
  ARGS+=(--command-config "${CLIENT_CONFIG}")
fi

create_topic() {
  local name="$1"
  local retention="$2"
  /opt/kafka/bin/kafka-topics.sh \
    --bootstrap-server "${BOOTSTRAP_SERVERS}" \
    "${ARGS[@]}" \
    --create --if-not-exists \
    --topic "${name}" \
    --partitions "${PARTITIONS}" \
    --replication-factor "${REPLICATION}" \
    --config "retention.ms=${retention}" \
    --config cleanup.policy=delete
}

create_topic wdsp.api.observations.v1 259200000
create_topic wdsp.api.observations.dlq.v1 604800000

/opt/kafka/bin/kafka-topics.sh \
  --bootstrap-server "${BOOTSTRAP_SERVERS}" \
  "${ARGS[@]}" \
  --describe \
  --topic 'wdsp.api.observations.*'
