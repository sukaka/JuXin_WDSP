#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
ROOT="$(cd ../.. && pwd)"
WORK="$(mktemp -d /tmp/wdsp-cloud-agent-e2e.XXXXXX)"
JAVA_PID=""
CAPTURE_PID=""
cleanup() {
  [ -n "${JAVA_PID}" ] && kill "${JAVA_PID}" >/dev/null 2>&1 || true
  [ -n "${CAPTURE_PID}" ] && kill "${CAPTURE_PID}" >/dev/null 2>&1 || true
  if [ "${KEEP_WORK:-0}" = "1" ]; then
    echo "保留现场: ${WORK}"
  else
    rm -rf "${WORK}"
  fi
}
trap cleanup EXIT

SOCKET="${WORK}/api.sock"
OBSERVATIONS="${WORK}/observations.jsonl"

docker run --rm -v wdsp-maven-cache:/root/.m2 -v "$ROOT":/workspace -w /workspace/test/cloud-agent-e2e \
  maven:3.9.11-eclipse-temurin-21@sha256:6fdc855a6ed81d288ca7ca37ac6ff5e9308b612485c0801d70b25a858c83d237 \
  mvn -B -q -s settings.xml package
if [ ! -f "$ROOT/wdsp-agent/instrumentation/java/target/wdsp-api-agent-1.0.0.jar" ]; then
  (cd "$ROOT/wdsp-agent/instrumentation/java" && ./build.sh)
fi

(cd "$ROOT/wdsp-agent" && go run ./test/cloud-agent-e2e/capture_server.go -socket "${SOCKET}" -output "${OBSERVATIONS}") &
CAPTURE_PID=$!
for i in {1..30}; do
  [ -S "${SOCKET}" ] && break
  sleep 1
done
[ -S "${SOCKET}" ] || { echo "本机 Socket 未就绪"; exit 1; }

java -javaagent:"$ROOT/wdsp-agent/instrumentation/java/target/wdsp-api-agent-1.0.0.jar" \
  -Dwdsp.api.socket="${SOCKET}" \
  -Dwdsp.service.name=orders \
  -Dwdsp.service.instance=orders-e2e-1 \
  -Dwdsp.service.environment=test \
  -Dserver.port=18081 \
  -jar target/cloud-agent-demo-1.0.0.jar >"${WORK}/application.log" 2>&1 &
JAVA_PID=$!

for i in {1..45}; do
  if curl -fsS http://127.0.0.1:18081/profiles/42 >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
curl -fsS -H 'Content-Type: application/json' -d '{"mobile":"13800138000","note":"e2e"}' http://127.0.0.1:18081/orders >/dev/null

for i in {1..20}; do
  lines=$(wc -l <"${OBSERVATIONS}" 2>/dev/null || echo 0)
  [ "${lines}" -ge 3 ] && break
  sleep 1
done

python3 - "${OBSERVATIONS}" <<'PY'
import json, sys
path = sys.argv[1]
raw = open(path, encoding='utf-8').read()
records = [json.loads(line) for line in raw.splitlines() if line.strip()]
assert len(records) >= 3, f'expected at least 3 observations, got {len(records)}'
assert '13800138000' not in raw, 'raw phone number leaked'
assert 'body_base64' not in raw, 'body escaped local boundary'
assert any(field.get('data_type') == 'PHONE' for record in records for field in record.get('fields', [])), 'missing PHONE observation'
assert any(record['source']['framework'] == 'spring-webmvc' for record in records), 'missing Spring MVC observation'
assert any(record['source']['framework'] == 'spring-resttemplate' for record in records), 'missing RestTemplate observation'
assert any(record['source']['framework'] == 'spring-webmvc' and record['http'].get('peer_address') == '127.0.0.1' for record in records), 'missing observed peer address'
print(f'PASS: {len(records)} real Spring observations, no raw sensitive values')
PY

echo "真实 Java Agent 端到端验收通过"
