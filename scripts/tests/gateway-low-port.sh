#!/usr/bin/env bash
# 真实低端口验收：Go 降权器瞬时 root，最终 Caddy 仅保留 ambient NET_BIND_SERVICE。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
IMAGE="${LOW_PORT_IMAGE:-jiuzhang-gateway:low-port-test}"
CONTAINER="jiuzhang-low-port-test-$$"
FAIL_CONTAINER="${CONTAINER}-failure"
CONTAINER_PORT="${LOW_PORT_CONTAINER_PORT:-82}"
BUILD_IMAGE="${LOW_PORT_BUILD:-1}"
REMOVE_IMAGE=false
WORK="$(mktemp -d "${TMPDIR:-/tmp}/jz-low-port.XXXXXX")"

cleanup() {
  docker rm -f "$CONTAINER" "$FAIL_CONTAINER" >/dev/null 2>&1 || true
  case "$WORK" in
    */jz-low-port.*) rm -rf "$WORK" ;;
  esac
  if [[ "$REMOVE_IMAGE" == "true" ]]; then
    docker image rm "$IMAGE" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM HUP

for cmd in docker curl awk; do
  command -v "$cmd" >/dev/null || { echo "缺少命令: $cmd" >&2; exit 2; }
done
if ! [[ "$CONTAINER_PORT" =~ ^[0-9]+$ ]] || (( CONTAINER_PORT < 1 || CONTAINER_PORT > 1023 )); then
  echo "LOW_PORT_CONTAINER_PORT 必须在 1..1023" >&2
  exit 2
fi

cat > "$WORK/low-port.json" <<EOF
{"admin":{"listen":"unix//tmp/low-port-admin.sock"},"apps":{"http":{"servers":{"low-port":{"listen":[":${CONTAINER_PORT}"],"routes":[{"handle":[{"handler":"static_response","body":"low-port-ok"}]}]}}}}}
EOF

if [[ "$BUILD_IMAGE" == "1" ]]; then
  docker build -t "$IMAGE" "$REPO_ROOT/gateway"
  REMOVE_IMAGE=true
fi

docker run -d \
  --name "$CONTAINER" \
  --sysctl net.ipv4.ip_unprivileged_port_start=1024 \
  --cap-drop ALL \
  --cap-add NET_BIND_SERVICE \
  --cap-add SETUID \
  --cap-add SETGID \
  --cap-add SETPCAP \
  --security-opt no-new-privileges:true \
  --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m \
  -e XDG_CONFIG_HOME=/tmp/config \
  -e XDG_DATA_HOME=/tmp/data \
  -p "127.0.0.1::${CONTAINER_PORT}" \
  -v "$WORK/low-port.json:/etc/caddy/low-port.json:ro" \
  "$IMAGE" run --config /etc/caddy/low-port.json >/dev/null

if [[ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER")" != "true" ]]; then
  docker logs "$CONTAINER" >&2 || true
  echo "低端口进程在读取端口映射前已退出" >&2
  exit 1
fi

HOST_ADDR="$(docker port "$CONTAINER" "${CONTAINER_PORT}/tcp")"
HOST_PORT="${HOST_ADDR##*:}"
RESPONSE_BODY="$WORK/response-body"
: > "$RESPONSE_BODY"
HTTP_CODE=""
BODY=""
for _ in {1..30}; do
  HTTP_CODE="$(curl -sS --max-time 2 -o "$RESPONSE_BODY" -w '%{http_code}' "http://127.0.0.1:${HOST_PORT}/" 2>/dev/null || true)"
  BODY="$(<"$RESPONSE_BODY")"
  [[ "$HTTP_CODE" == "200" && "$BODY" == "low-port-ok" ]] && break
  if [[ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER")" != "true" ]]; then
    docker logs "$CONTAINER" >&2 || true
    echo "低端口进程已退出" >&2
    exit 1
  fi
  sleep 1
done
if [[ "$HTTP_CODE" != "200" ]] || [[ "$BODY" != "low-port-ok" ]]; then
  docker logs "$CONTAINER" >&2 || true
  echo "低端口 ${CONTAINER_PORT} 未返回 HTTP 200 与预期响应: HTTP=${HTTP_CODE:-无} body=${BODY:-空}" >&2
  exit 1
fi

PROCESS_NAME="$(docker exec "$CONTAINER" awk '/^Name:/ {print $2}' /proc/1/status)"
UIDS="$(docker exec "$CONTAINER" awk '/^Uid:/ {print $2, $3, $4, $5}' /proc/1/status)"
GIDS="$(docker exec "$CONTAINER" awk '/^Gid:/ {print $2, $3, $4, $5}' /proc/1/status)"
GROUP_COUNT="$(docker exec "$CONTAINER" awk '/^Groups:/ {print NF-1}' /proc/1/status)"
CAP_EFF="$(docker exec "$CONTAINER" awk '/^CapEff:/ {print $2}' /proc/1/status)"
CAP_BND="$(docker exec "$CONTAINER" awk '/^CapBnd:/ {print $2}' /proc/1/status)"
CAP_AMB="$(docker exec "$CONTAINER" awk '/^CapAmb:/ {print $2}' /proc/1/status)"
NO_NEW_PRIVS="$(docker exec "$CONTAINER" awk '/^NoNewPrivs:/ {print $2}' /proc/1/status)"
UNPRIVILEGED_PORT_START="$(docker exec "$CONTAINER" awk 'NR == 1 {print $1}' /proc/sys/net/ipv4/ip_unprivileged_port_start)"
ADMIN_SOCKET_META="$(docker exec "$CONTAINER" stat -c '%a:%u:%g' /tmp/low-port-admin.sock)"
if [[ "$UNPRIVILEGED_PORT_START" != "1024" ]]; then
  echo "测试网络命名空间低端口阈值不是现场值 1024: $UNPRIVILEGED_PORT_START" >&2
  exit 1
fi
if [[ "$PROCESS_NAME" != "caddy" ]]; then
  echo "PID 1 不是 Caddy: $PROCESS_NAME" >&2
  exit 1
fi
if [[ "$UIDS" != "1000 1000 1000 1000" ]] || [[ "$GIDS" != "1000 1000 1000 1000" ]]; then
  echo "低端口进程 UID/GID 降权不完整: Uid=$UIDS Gid=$GIDS" >&2
  exit 1
fi
if [[ "$GROUP_COUNT" != "0" ]]; then
  echo "低端口进程仍有补充组: Groups 数量=$GROUP_COUNT" >&2
  exit 1
fi
if [[ "$CAP_EFF" != "0000000000000400" ]] || [[ "$CAP_BND" != "0000000000000400" ]] || [[ "$CAP_AMB" != "0000000000000400" ]]; then
  echo "低端口能力不完整: CapEff=$CAP_EFF CapBnd=$CAP_BND CapAmb=$CAP_AMB" >&2
  exit 1
fi
if [[ "$NO_NEW_PRIVS" != "1" ]]; then
  echo "低端口进程 no-new-privileges 未启用: NoNewPrivs=$NO_NEW_PRIVS" >&2
  exit 1
fi
if [[ "$ADMIN_SOCKET_META" != "200:1000:1000" ]]; then
  echo "Admin Unix Socket 权限或属主异常: ${ADMIN_SOCKET_META}（期望 200:1000:1000）" >&2
  exit 1
fi
LOGS="$(docker logs "$CONTAINER" 2>&1)"
if [[ "$LOGS" != *"wdsp-gateway-bind: verified"* ]] || [[ "$LOGS" != *"CapAmb=0000000000000400"* ]]; then
  printf '%s\n' "$LOGS" >&2
  echo "缺少降权器成功审计记录" >&2
  exit 1
fi

assert_start_failure() {
  local expected_step="$1"
  shift
  docker rm -f "$FAIL_CONTAINER" >/dev/null 2>&1 || true
  docker run -d \
    --name "$FAIL_CONTAINER" \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --read-only \
    --tmpfs /tmp:rw,nosuid,nodev,size=64m \
    -e XDG_CONFIG_HOME=/tmp/config \
    -e XDG_DATA_HOME=/tmp/data \
    "$@" \
    -v "$WORK/low-port.json:/etc/caddy/low-port.json:ro" \
    "$IMAGE" run --config /etc/caddy/low-port.json >/dev/null

  local running=true
  for _ in {1..20}; do
    running="$(docker inspect -f '{{.State.Running}}' "$FAIL_CONTAINER")"
    [[ "$running" != "true" ]] && break
    sleep 0.2
  done
  if [[ "$running" == "true" ]]; then
    docker logs "$FAIL_CONTAINER" >&2 || true
    echo "失败场景未退出: 期望 $expected_step" >&2
    return 1
  fi
  local failure_logs
  failure_logs="$(docker logs "$FAIL_CONTAINER" 2>&1)"
  if [[ "$failure_logs" != *"step=$expected_step"* ]]; then
    printf '%s\n' "$failure_logs" >&2
    echo "失败场景未指出步骤 $expected_step" >&2
    return 1
  fi
}

assert_start_failure "set-uid" \
  --cap-add NET_BIND_SERVICE \
  --cap-add SETGID \
  --cap-add SETPCAP
assert_start_failure "check-root" \
  --user 1000:1000 \
  --cap-add NET_BIND_SERVICE \
  --cap-add SETUID \
  --cap-add SETGID \
  --cap-add SETPCAP

printf 'PASS: :%s 返回 HTTP 200；Uid=%s；Gid=%s；补充组=0；CapEff=%s；CapBnd=%s；CapAmb=%s；NoNewPrivs=%s；AdminSocket=%s；失败路径明确退出\n' \
  "$CONTAINER_PORT" "$UIDS" "$GIDS" "$CAP_EFF" "$CAP_BND" "$CAP_AMB" "$NO_NEW_PRIVS" "$ADMIN_SOCKET_META"
