#!/usr/bin/env bash
# check.sh —— 组件健康检查：容器状态 / 管理 API / 防护网关 / PostgreSQL / Valkey。
# 退出码：0=全部健康 1=存在异常 2=用法错误
set -euo pipefail
API_URL_EXPLICIT=false
[[ -z "${JZ_API_BASE+x}" ]] || API_URL_EXPLICIT=true
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

usage() {
  cat <<'EOF'
用法: check.sh [选项]

组件健康检查（容器状态、管理 API、防护网关、PostgreSQL、Valkey）。

选项:
  -c, --compose-file FILE   docker compose 文件（默认 docker-compose.yml，或 JZ_COMPOSE_FILE）
  -e, --env-file FILE       环境变量文件（默认 .env，或 JZ_ENV_FILE）
      --api-url URL            管理 API 地址（默认从 Compose 的 API 发布端口读取，或 JZ_API_BASE）
      --gateway-url URL      显式覆盖网关探测地址；缺省读取 Caddy Admin 实际 listeners
  -h, --help                显示帮助

退出码: 0=全部健康 1=存在异常 2=用法错误
EOF
}

GATEWAY_URL="${JZ_GATEWAY_URL:-}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    -c|--compose-file) JZ_COMPOSE_FILE="$2"; shift 2 ;;
    -e|--env-file)     JZ_ENV_FILE="$2"; shift 2 ;;
    --api-url)         JZ_API_BASE="$2"; API_URL_EXPLICIT=true; shift 2 ;;
    --gateway-url)     GATEWAY_URL="$2"; shift 2 ;;
    -h|--help)         usage; exit 0 ;;
    *) log_err "未知参数: $1"; usage; exit 2 ;;
  esac
done

require_cmd docker
require_cmd curl
if [[ "$API_URL_EXPLICIT" == false && -f "$JZ_COMPOSE_FILE" && -f "$JZ_ENV_FILE" ]]; then
  require_cmd jq
  JZ_API_BASE="$(compose_api_url "$JZ_COMPOSE_FILE" "$JZ_ENV_FILE")" \
    || { log_err "无法从 Compose 读取 API 发布端口，请显式传 --api-url"; exit 1; }
fi

FAILED=0
report() { # report NAME OK|FAIL DETAIL
  local name="$1" result="$2" detail="${3:-}"
  if [[ "$result" == "OK" ]]; then
    printf '  [OK]   %-16s %s\n' "$name" "$detail"
  else
    printf '  [FAIL] %-16s %s\n' "$name" "$detail"
    FAILED=1
  fi
}

log_info "开始组件健康检查（compose: ${JZ_COMPOSE_FILE}）"

# ---- 1. 容器状态 ----
if [[ -f "$JZ_COMPOSE_FILE" ]]; then
  if [[ -f "$JZ_ENV_FILE" ]]; then
    ps_out="$(compose ps --format '{{.Name}} {{.State}}' 2>/dev/null || true)"
  else
    ps_out="$(docker compose -f "$JZ_COMPOSE_FILE" ps --format '{{.Name}} {{.State}}' 2>/dev/null || true)"
  fi
  if [[ -z "$ps_out" ]]; then
    report "containers" FAIL "未获取到容器状态（compose 项目未启动？）"
  else
    bad=""
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      name="${line%% *}"
      state="${line#* }"
      if [[ "$state" != "running" ]]; then
        bad="$bad $name($state)"
      fi
    done <<< "$ps_out"
    if [[ -n "$bad" ]]; then
      report "containers" FAIL "异常容器:$bad"
    else
      report "containers" OK "$(wc -l <<< "$ps_out" | tr -d ' ') 个容器运行中"
    fi
  fi
else
  log_warn "compose 文件 $JZ_COMPOSE_FILE 不存在，跳过容器状态检查"
fi

# ---- 2. 管理 API ----
api_resp="$(curl -sS --max-time 5 "$JZ_API_BASE/api/v1/health" 2>/dev/null || true)"
if printf '%s' "$api_resp" | grep -q '"status":"ok"'; then
  report "api" OK "$JZ_API_BASE"
elif printf '%s' "$api_resp" | grep -q '"status":"degraded"'; then
  report "api" FAIL "API 降级: $api_resp"
else
  report "api" FAIL "不可达: $JZ_API_BASE"
fi

# ---- 3. 防护网关（缺省读取实际 Caddy listeners，不猜开发端口） ----
if [[ -n "$GATEWAY_URL" ]]; then
  gw_host="$(printf '%s' "$GATEWAY_URL" | sed -E 's#^[a-z]+://([^:/]+).*#\1#')"
  gw_port="$(printf '%s' "$GATEWAY_URL" | sed -E 's#^[a-z]+://[^:/]+:([0-9]+).*#\1#')"
  [[ "$gw_port" =~ ^[0-9]+$ ]] || gw_port=80
  if (exec 3<>"/dev/tcp/$gw_host/$gw_port") 2>/dev/null; then
    exec 3>&- 3<&- || true
    report "gateway" OK "$gw_host:$gw_port 可连接"
  else
    report "gateway" FAIL "$gw_host:$gw_port 不可连接"
  fi
else
  require_cmd jq
  gateway_id="$(compose ps -q gateway 2>/dev/null || true)"
  socket_dir=""
  if [[ "$gateway_id" =~ ^[a-fA-F0-9]+$ ]]; then
    socket_dir="$(docker inspect --format '{{json .Mounts}}' "$gateway_id" 2>/dev/null \
      | jq -er '[.[] | select(.Destination == "/var/run/caddy") | .Source] | if length == 1 then .[0] else empty end' 2>/dev/null || true)"
  fi
  listeners=""
  if [[ -n "$socket_dir" && -S "$socket_dir/admin.sock" ]]; then
    listeners="$(curl -fsS --max-time 5 --unix-socket "$socket_dir/admin.sock" http://localhost/config/apps/http/servers 2>/dev/null || true)"
  fi
  gateway_ports=()
  while IFS= read -r listen; do
    port="${listen##*:}"
    [[ "$port" =~ ^[0-9]+$ ]] || continue
    (( 10#$port >= 1 && 10#$port <= 65535 )) || continue
    gateway_ports+=("$port")
  done < <(jq -r '.[]?.listen[]?' <<<"$listeners" 2>/dev/null | LC_ALL=C sort -u)
  if [[ ${#gateway_ports[@]} -eq 0 ]]; then
    if jq -e 'type == "object" and length == 0' <<<"$listeners" >/dev/null 2>&1; then
      report "gateway" OK "Caddy Admin 可访问，当前无站点监听"
    else
      report "gateway" FAIL "无法从 Caddy Admin Unix Socket 读取实际监听端口"
    fi
  else
    gw_fail=""
    for gw_port in "${gateway_ports[@]}"; do
      if (exec 3<>"/dev/tcp/127.0.0.1/$gw_port") 2>/dev/null; then
        exec 3>&- 3<&- || true
      else
        gw_fail="$gw_fail $gw_port"
      fi
    done
    if [[ -n "$gw_fail" ]]; then
      report "gateway" FAIL "实际监听端口不可连接:$gw_fail"
    else
      report "gateway" OK "Caddy 实际监听 ${gateway_ports[*]} 均可连接"
    fi
  fi
fi

# ---- 4. PostgreSQL ----
pg_container="$(docker ps --format '{{.Names}}' | grep -E 'postgres' | head -1 || true)"
if [[ -n "$pg_container" ]]; then
  pg_user="${POSTGRES_USER:-jiuzhang}"
  if docker exec "$pg_container" pg_isready -U "$pg_user" >/dev/null 2>&1; then
    report "postgres" OK "容器 $pg_container"
  else
    report "postgres" FAIL "pg_isready 失败（容器 ${pg_container}）"
  fi
else
  report "postgres" FAIL "未找到 postgres 容器"
fi

# ---- 5. Valkey（口令从 env 文件读取，不回显） ----
vk_container="$(docker ps --format '{{.Names}}' | grep -E 'valkey' | head -1 || true)"
if [[ -n "$vk_container" ]]; then
  vk_pass=""
  if [[ -f "$JZ_ENV_FILE" ]]; then
    vk_pass="$(grep -E '^VALKEY_PASSWORD=' "$JZ_ENV_FILE" | head -1 | cut -d= -f2- || true)"
  fi
  if [[ -n "$vk_pass" ]]; then
    if docker exec -e REDISCLI_AUTH="$vk_pass" "$vk_container" sh -c 'valkey-cli --no-auth-warning ping 2>/dev/null | grep -q PONG'; then
      report "valkey" OK "容器 $vk_container"
    else
      report "valkey" FAIL "ping 失败（容器 ${vk_container}）"
    fi
  else
    report "valkey" FAIL "未读取到 VALKEY_PASSWORD（${JZ_ENV_FILE}）"
  fi
else
  report "valkey" FAIL "未找到 valkey 容器"
fi

if [[ "$FAILED" -eq 0 ]]; then
  log_info "健康检查通过"
  exit 0
fi
log_err "健康检查存在异常项"
exit 1
