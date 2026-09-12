#!/usr/bin/env bash
# AUTHZ-01 server/gateway JSON 契约验收：Provider 生成授权快照，Guard 消费同一份 JSON。
#
# 该脚本验证两个 Go module 的交接边界：Provider 侧与 Guard 侧分别由独立的
# `go test` 子进程执行，中间只通过临时 JSON 文件和事件日志交接。设置
# AUTHZ_REQUIRE_REAL_PROVIDER=1 时，先启动测试专用的 Provider HTTP 常驻进程，通过
# HTTP 探活和读取配置，再继续走生产 CaddyClient 与 Guard 流程。control: 文件协议
# 只在显式 AUTHZ_PROVIDER_CONTROL_TEST=1 时用于无 socket 权限的进程协议测试，不计入
# real Provider gate。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
CONTRACT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/authz-contract.XXXXXX")"
CONTRACT_FILE="$CONTRACT_DIR/contract.json"
CADDY_CONFIG_FILE="$CONTRACT_DIR/caddy-admin-config.json"
CANDIDATE_FILE="$CONTRACT_DIR/candidate-publish-handoff.json"
EVENTS_LOG="$CONTRACT_DIR/events.log"
API_EVENTS_LOG="$CONTRACT_DIR/api-runtime-events.log"
PROVIDER_READY_FILE="$CONTRACT_DIR/provider-ready"
PROVIDER_LOG="$CONTRACT_DIR/provider.log"
LEGACY_SNAPSHOT_FILE="$CONTRACT_DIR/legacy-snapshot.json"
PROVIDER_PID=""
PROVIDER_ADDR=""
RUN_PROVIDER_HELPER=0

provider_control_request() {
  local command="$1"
  local control_dir="${PROVIDER_ADDR#control:}"
  local request_file="$control_dir/request"
  local response_file="$control_dir/response"
  local request_tmp="$control_dir/request.$$"
  rm -f "$response_file"
  printf '%s\n' "$command" >"$request_tmp"
  mv "$request_tmp" "$request_file"
  for _ in {1..100}; do
    if [[ -e "$response_file" ]]; then
      cat "$response_file"
      rm -f "$response_file"
      return 0
    fi
    if [[ -n "$PROVIDER_PID" ]] && ! kill -0 "$PROVIDER_PID" 2>/dev/null; then
      return 1
    fi
    sleep 0.01
  done
  return 1
}

cleanup() {
  if [[ -n "$PROVIDER_PID" ]]; then
    if [[ "$PROVIDER_ADDR" == control:* ]]; then
      provider_control_request "POST /shutdown" >/dev/null 2>&1 || true
    elif [[ "$PROVIDER_ADDR" == unix:* ]]; then
      provider_socket="${PROVIDER_ADDR#unix:}"
      curl --silent --show-error --max-time 1 --unix-socket "$provider_socket" -X POST http://localhost/shutdown >/dev/null 2>&1 || true
    elif [[ -s "$PROVIDER_READY_FILE" ]]; then
      provider_url="$(cat "$PROVIDER_READY_FILE" 2>/dev/null || true)"
      if [[ -n "$provider_url" ]]; then
        curl --silent --show-error --max-time 1 -X POST "$provider_url/shutdown" >/dev/null 2>&1 || true
      fi
    fi
    kill "$PROVIDER_PID" 2>/dev/null || true
    wait "$PROVIDER_PID" 2>/dev/null || true
  fi
  rm -rf "$CONTRACT_DIR"
}
trap cleanup EXIT

echo "[authz] producing apiauthz confirmation and publish handoff"
(
  cd "$REPO_ROOT/server"
  AUTHZ_CANDIDATE_OUTPUT="$CANDIDATE_FILE" \
  GOCACHE="${GOCACHE:-/tmp/jiuzhang-go-cache}" \
    go test -mod=readonly ./internal/apiauthz -run '^TestRelationCandidateConfirmationGatewayAuthorization$' -count=1
)

test -s "$CANDIDATE_FILE"

if [[ "${AUTHZ_REQUIRE_REAL_PROVIDER:-0}" == "1" ]]; then
  RUN_PROVIDER_HELPER=1
  PROVIDER_ADDR="${AUTHZ_REAL_PROVIDER_ADDR:-127.0.0.1:0}"
  if [[ "$PROVIDER_ADDR" == control:* ]]; then
    echo "AUTHZ-01 real Provider E2E: BLOCKED/ENVIRONMENT_UNAVAILABLE" >&2
    echo "reason=control Provider protocol is test-only and cannot satisfy the real HTTP gate" >&2
    exit 3
  fi
elif [[ "${AUTHZ_PROVIDER_CONTROL_TEST:-0}" == "1" ]]; then
  RUN_PROVIDER_HELPER=1
  PROVIDER_ADDR="${AUTHZ_REAL_PROVIDER_ADDR:-control:$CONTRACT_DIR/provider-control}"
fi

if [[ "$RUN_PROVIDER_HELPER" == "1" ]]; then
  echo "[authz] starting resident Provider HTTP process"
  cat >"$LEGACY_SNAPSHOT_FILE" <<'EOF'
{
  "api_authz_models": [{
    "application_id": "app-legacy",
    "endpoint_key": "GET /orders/{id}",
    "object_type": "order",
    "identifiers": [{"location": "path", "name": "id"}],
    "required_relation": "OWNER"
  }],
  "api_authz_previous_valid": {
    "policy_version": "policy-old",
    "models": [{
      "application_id": "app-legacy",
      "endpoint_key": "GET /orders/{id}",
      "object_type": "order",
      "identifiers": [{"location": "path", "name": "id"}],
      "required_relation": "OWNER"
    }],
    "future_authz_shard": {"version": 2}
  },
  "future_authz_shard": {"version": 2}
}
EOF
  if [[ "$PROVIDER_ADDR" == control:* ]]; then
    mkdir -p "${PROVIDER_ADDR#control:}"
  fi
  (
    cd "$REPO_ROOT/server"
    AUTHZ_CONTRACT_OUTPUT="$CONTRACT_FILE" \
    AUTHZ_CANDIDATE_INPUT="$CANDIDATE_FILE" \
    AUTHZ_CONTRACT_EVENTS_LOG="$EVENTS_LOG" \
    AUTHZ_CONTRACT_API_EVENTS_LOG="$API_EVENTS_LOG" \
    AUTHZ_PROVIDER_READY_FILE="$PROVIDER_READY_FILE" \
    AUTHZ_REAL_PROVIDER_ADDR="$PROVIDER_ADDR" \
    AUTHZ_LEGACY_SNAPSHOT_INPUT="$LEGACY_SNAPSHOT_FILE" \
    GOCACHE="${GOCACHE:-/tmp/jiuzhang-go-cache}" \
      go test -mod=readonly ./internal/guardconfig -run '^TestAuthzProviderHTTPProcess$' -count=1
  ) >"$PROVIDER_LOG" 2>&1 &
  PROVIDER_PID=$!

  provider_url=""
  for _ in {1..100}; do
    if [[ -s "$PROVIDER_READY_FILE" ]]; then
      provider_url="$(cat "$PROVIDER_READY_FILE")"
      break
    fi
    if ! kill -0 "$PROVIDER_PID" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done
  if [[ -z "$provider_url" ]]; then
    echo "AUTHZ-01 real Provider E2E: BLOCKED/ENVIRONMENT_UNAVAILABLE" >&2
    echo "reason=Provider HTTP process did not become ready" >&2
    cat "$PROVIDER_LOG" >&2 || true
    exit 3
  fi
  if [[ "$PROVIDER_ADDR" == control:* ]]; then
    if ! provider_control_request "GET /healthz" >/dev/null; then
      echo "AUTHZ-01 real Provider E2E: BLOCKED/ENVIRONMENT_UNAVAILABLE" >&2
      echo "reason=Provider control health check failed" >&2
      exit 3
    fi
  else
    if [[ "$PROVIDER_ADDR" == unix:* ]]; then
      if ! curl --fail --silent --show-error --max-time 2 --unix-socket "${PROVIDER_ADDR#unix:}" "$provider_url/healthz" >/dev/null; then
        echo "AUTHZ-01 real Provider E2E: BLOCKED/ENVIRONMENT_UNAVAILABLE" >&2
        echo "reason=Provider HTTP health check failed" >&2
        echo "provider_url=$provider_url" >&2
        exit 3
      fi
    elif ! curl --fail --silent --show-error --max-time 2 "$provider_url/healthz" >/dev/null; then
      echo "AUTHZ-01 real Provider E2E: BLOCKED/ENVIRONMENT_UNAVAILABLE" >&2
      echo "reason=Provider HTTP health check failed" >&2
      echo "provider_url=$provider_url" >&2
      exit 3
    fi
  fi
  if [[ "$PROVIDER_ADDR" == control:* ]]; then
    if ! provider_control_request "GET /v1/authz/config" >"$CONTRACT_FILE"; then
      echo "AUTHZ-01 real Provider E2E: BLOCKED/ENVIRONMENT_UNAVAILABLE" >&2
      echo "reason=Provider control config request failed" >&2
      exit 3
    fi
  elif [[ "$PROVIDER_ADDR" == unix:* ]]; then
    if ! curl --fail --silent --show-error --max-time 2 --unix-socket "${PROVIDER_ADDR#unix:}" "$provider_url/v1/authz/config" >"$CONTRACT_FILE"; then
      echo "AUTHZ-01 real Provider E2E: BLOCKED/ENVIRONMENT_UNAVAILABLE" >&2
      echo "reason=Provider HTTP config endpoint failed" >&2
      echo "provider_url=$provider_url" >&2
      exit 3
    fi
  elif ! curl --fail --silent --show-error --max-time 2 "$provider_url/v1/authz/config" >"$CONTRACT_FILE"; then
    echo "AUTHZ-01 real Provider E2E: BLOCKED/ENVIRONMENT_UNAVAILABLE" >&2
    echo "reason=Provider HTTP config endpoint failed" >&2
    echo "provider_url=$provider_url" >&2
    exit 3
  fi
  if [[ "$PROVIDER_ADDR" == control:* ]]; then
    if ! provider_control_request "GET /v1/authz/legacy-compat" >/dev/null; then
      echo "AUTHZ-01 real Provider E2E: BLOCKED/ENVIRONMENT_UNAVAILABLE" >&2
      echo "reason=Provider control legacy compatibility probe failed" >&2
      exit 3
    fi
  elif [[ "$PROVIDER_ADDR" == unix:* ]]; then
    curl --fail --silent --show-error --max-time 2 --unix-socket "${PROVIDER_ADDR#unix:}" "$provider_url/v1/authz/legacy-compat" >/dev/null
  else
    curl --fail --silent --show-error --max-time 2 "$provider_url/v1/authz/legacy-compat" >/dev/null
  fi
else
  echo "[authz] writing server Provider contract from confirmed relation"
  (
    cd "$REPO_ROOT/server"
    AUTHZ_CONTRACT_OUTPUT="$CONTRACT_FILE" \
    AUTHZ_CANDIDATE_INPUT="$CANDIDATE_FILE" \
    AUTHZ_CONTRACT_EVENTS_LOG="$EVENTS_LOG" \
    AUTHZ_CONTRACT_API_EVENTS_LOG="$API_EVENTS_LOG" \
    GOCACHE="${GOCACHE:-/tmp/jiuzhang-go-cache}" \
      go test -mod=readonly ./internal/guardconfig -run '^TestWriteAuthzCrossModuleContract$' -count=1
  )
fi

test -s "$CONTRACT_FILE"

echo "[authz] publishing Provider config through gatewayconfig HTTP boundary"
(
  cd "$REPO_ROOT/server"
  AUTHZ_CONTRACT_INPUT="$CONTRACT_FILE" \
  AUTHZ_CADDY_CONFIG_OUTPUT="$CADDY_CONFIG_FILE" \
  GOCACHE="${GOCACHE:-/tmp/jiuzhang-go-cache}" \
    go test -mod=readonly ./internal/gatewayconfig -run '^TestAuthzProviderConfigHTTPBoundary$' -count=1
)

test -s "$CADDY_CONFIG_FILE"

echo "[authz] consuming gateway Guard contract"
(
  cd "$REPO_ROOT/gateway/modules/jiuzhang_guard"
  AUTHZ_CONTRACT_INPUT="$CADDY_CONFIG_FILE" \
    AUTHZ_GATEWAY_REAL_HTTP="${AUTHZ_REQUIRE_REAL_PROVIDER:-0}" \
    GOCACHE="${GOCACHE:-/tmp/jiuzhang-go-cache}" \
    go test . -run '^TestConsumeAuthzCrossModuleContract$' -count=1
)

echo "[authz] validating PreviousValid recovery in a second isolated gateway process"
(
  cd "$REPO_ROOT/gateway/modules/jiuzhang_guard"
  GOCACHE="${GOCACHE:-/tmp/jiuzhang-go-cache}" \
    go test . -run '^TestProvisionedGuard_AuthzPreviousValidFallbackE2E$' -count=1
)

echo "AUTHZ-01 cross-module contract: PASS"
echo "AUTHZ-01 process recovery contract: PASS"
