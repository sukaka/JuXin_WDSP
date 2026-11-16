#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
ROOT="$(cd ../.. && pwd)"
RUN_ID="wdsp-cloud-e2e-$$-$(date +%s)"
NETWORK="${RUN_ID}-net"
PG_NAME="${RUN_ID}-pg"
VALKEY_NAME="${RUN_ID}-valkey"
KAFKA_NAME="${RUN_ID}-kafka"
CLICKHOUSE_NAME="${RUN_ID}-ch"
PG_PASSWORD="$(openssl rand -hex 24)"
VALKEY_PASSWORD="$(openssl rand -hex 24)"
CLICKHOUSE_PASSWORD="$(openssl rand -hex 24)"

cleanup() {
  docker rm -f "${PG_NAME}" "${VALKEY_NAME}" "${KAFKA_NAME}" "${CLICKHOUSE_NAME}" >/dev/null 2>&1 || true
  docker network rm "${NETWORK}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker network create "${NETWORK}" >/dev/null
docker run --rm -d --name "${PG_NAME}" --network "${NETWORK}" \
  -e POSTGRES_USER=wdsp_test -e POSTGRES_PASSWORD="${PG_PASSWORD}" \
  -p 127.0.0.1::5432 \
  postgres:16.4-alpine@sha256:5660c2cbfea50c7a9127d17dc4e48543eedd3d7a41a595a2dfa572471e37e64c >/dev/null
docker run --rm -d --name "${VALKEY_NAME}" --network "${NETWORK}" \
  -p 127.0.0.1::6379 \
  valkey/valkey:8.1.8-alpine@sha256:94365b275456ae14621001c03556c732b1d93a0cdeacc317d1bdd52eba680885 \
  valkey-server --requirepass "${VALKEY_PASSWORD}" >/dev/null
docker run --rm -d --name "${CLICKHOUSE_NAME}" --network "${NETWORK}" \
  -e CLICKHOUSE_USER=default -e CLICKHOUSE_PASSWORD="${CLICKHOUSE_PASSWORD}" \
  -v "${ROOT}/deployment/apm/clickhouse:/docker-entrypoint-initdb.d:ro" \
  -p 127.0.0.1::9000 \
  clickhouse/clickhouse-server:25.8-alpine@sha256:87e0a5b72f5465b18eacca7c76850e7ff551c9795c50e451f5646299e5e24146 >/dev/null

KAFKA_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
docker run --rm -d --name "${KAFKA_NAME}" --network "${NETWORK}" \
  -e KAFKA_NODE_ID=1 \
  -e KAFKA_PROCESS_ROLES=broker,controller \
  -e KAFKA_LISTENER_SECURITY_PROTOCOL_MAP=INTERNAL:PLAINTEXT,EXTERNAL:PLAINTEXT,CONTROLLER:PLAINTEXT \
  -e KAFKA_LISTENERS=INTERNAL://:29092,EXTERNAL://:9092,CONTROLLER://:9093 \
  -e KAFKA_ADVERTISED_LISTENERS="INTERNAL://${KAFKA_NAME}:29092,EXTERNAL://127.0.0.1:${KAFKA_PORT}" \
  -e KAFKA_INTER_BROKER_LISTENER_NAME=INTERNAL \
  -e KAFKA_CONTROLLER_LISTENER_NAMES=CONTROLLER \
  -e KAFKA_CONTROLLER_QUORUM_VOTERS="1@${KAFKA_NAME}:9093" \
  -e KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR=1 \
  -e KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR=1 \
  -e KAFKA_TRANSACTION_STATE_LOG_MIN_ISR=1 \
  -e KAFKA_GROUP_INITIAL_REBALANCE_DELAY_MS=0 \
  -e KAFKA_AUTO_CREATE_TOPICS_ENABLE=false \
  -p "127.0.0.1:${KAFKA_PORT}:9092" \
  apache/kafka:4.1.2@sha256:5cc2a2fd93fa2687b44015eee04fb2c3edd9e526bd64bf8bec5ff1e268772e0e >/dev/null

kafka_ready() {
  python3 - "${KAFKA_NAME}" <<'PY'
import subprocess
import sys

subprocess.run([
    'docker', 'exec', sys.argv[1], '/opt/kafka/bin/kafka-topics.sh',
    '--bootstrap-server', f'{sys.argv[1]}:29092', '--list',
], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=True)
PY
}

for ((i=0; i<90; i++)); do
  if docker exec "${PG_NAME}" pg_isready -U wdsp_test >/dev/null 2>&1 \
    && docker exec "${VALKEY_NAME}" valkey-cli --no-auth-warning -a "${VALKEY_PASSWORD}" ping >/dev/null 2>&1 \
    && docker exec "${CLICKHOUSE_NAME}" clickhouse-client --password "${CLICKHOUSE_PASSWORD}" --query 'SELECT 1' >/dev/null 2>&1 \
    && kafka_ready; then
    break
  fi
  if [ "${i}" -eq 89 ]; then
    echo "测试数据面未在 90 次探测内就绪" >&2
    docker ps -a --filter "name=${RUN_ID}-" --format '{{.Names}}: {{.Status}}' >&2
    docker logs --tail 80 "${KAFKA_NAME}" >&2 || true
    exit 1
  fi
  sleep 1
done

docker run --rm --network "${NETWORK}" \
  -e BOOTSTRAP_SERVERS="${KAFKA_NAME}:29092" \
  -e API_OBSERVATION_PARTITIONS=3 \
  -v "${ROOT}/deployment/kafka/init-topics.sh:/etc/jiuzhang/init-topics.sh:ro" \
  apache/kafka:4.1.2@sha256:5cc2a2fd93fa2687b44015eee04fb2c3edd9e526bd64bf8bec5ff1e268772e0e \
  /bin/bash /etc/jiuzhang/init-topics.sh

PG_ENDPOINT="$(docker port "${PG_NAME}" 5432/tcp)"
VALKEY_ENDPOINT="$(docker port "${VALKEY_NAME}" 6379/tcp)"
CLICKHOUSE_ENDPOINT="$(docker port "${CLICKHOUSE_NAME}" 9000/tcp)"
cd "${ROOT}/server"
POSTGRES_HOST=127.0.0.1 \
POSTGRES_PORT="${PG_ENDPOINT##*:}" \
POSTGRES_USER=wdsp_test \
POSTGRES_PASSWORD="${PG_PASSWORD}" \
VALKEY_HOST=127.0.0.1 \
VALKEY_PORT="${VALKEY_ENDPOINT##*:}" \
VALKEY_PASSWORD="${VALKEY_PASSWORD}" \
WDSP_KAFKA_TEST_ADDR="127.0.0.1:${KAFKA_PORT}" \
WDSP_CLICKHOUSE_TEST_DSN="clickhouse://default:${CLICKHOUSE_PASSWORD}@127.0.0.1:${CLICKHOUSE_ENDPOINT##*:}/wdsp" \
WDSP_DATA_FLOW_BROWSER_E2E=1 \
go test ./tests -run '^TestCloudAPIDataFlowEndToEnd$' -count=1 -v -timeout 300s
