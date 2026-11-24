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
      --strict-clickhouse-network
                             同机 APM ClickHouse 运行时，强制要求 api 已接入其数据面网络（升级后校验用）
  -h, --help                显示帮助

退出码: 0=全部健康 1=存在异常 2=用法错误
EOF
}

GATEWAY_URL="${JZ_GATEWAY_URL:-}"
STRICT_CLICKHOUSE_NETWORK=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    -c|--compose-file) JZ_COMPOSE_FILE="$2"; shift 2 ;;
    -e|--env-file)     JZ_ENV_FILE="$2"; shift 2 ;;
    --api-url)         JZ_API_BASE="$2"; API_URL_EXPLICIT=true; shift 2 ;;
    --gateway-url)     GATEWAY_URL="$2"; shift 2 ;;
    --strict-clickhouse-network) STRICT_CLICKHOUSE_NETWORK=true; shift ;;
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

run_with_timeout() {
  local secs="$1"; shift
  if command -v timeout >/dev/null 2>&1; then
    timeout "$secs" "$@"
  else
    "$@"
  fi
}

# parse_caddy_listen RAW_LISTEN —— 输出 tab 分隔: dial_host \t port \t is_wildcard \t display
# 仅处理 TCP 监听地址，跳过 unix/udp；保留显式绑定主机，不把非回环 IP 强转为 127.0.0.1。
parse_caddy_listen() {
  local addr="$1" host="" port="" wildcard="false" display=""
  case "$addr" in
    unix/*|udp/*|udp4/*|udp6/*) return 1 ;;
    tcp/*)  addr="${addr#tcp/}" ;;
    tcp4/*) addr="${addr#tcp4/}" ;;
    tcp6/*) addr="${addr#tcp6/}" ;;
  esac
  if [[ "$addr" =~ ^:([0-9]+)$ ]]; then
    host="127.0.0.1"
    port="${BASH_REMATCH[1]}"
    wildcard="true"
    display=":${port}"
  elif [[ "$addr" =~ ^\[([^\]]*)\]:([0-9]+)$ ]]; then
    host="${BASH_REMATCH[1]}"
    port="${BASH_REMATCH[2]}"
    if [[ -z "$host" || "$host" == "::" ]]; then
      host="127.0.0.1"
      wildcard="true"
      display="[::]:${port}"
    else
      display="[${host}]:${port}"
    fi
  elif [[ "$addr" =~ ^([^:]+):([0-9]+)$ ]]; then
    host="${BASH_REMATCH[1]}"
    port="${BASH_REMATCH[2]}"
    if [[ "$host" == "0.0.0.0" || "$host" == "*" ]]; then
      host="127.0.0.1"
      wildcard="true"
      display="0.0.0.0:${port}"
    else
      display="${host}:${port}"
    fi
  else
    return 1
  fi
  [[ "$port" =~ ^[0-9]+$ ]] && (( 10#$port >= 1 && 10#$port <= 65535 )) || return 1
  printf '%s\t%s\t%s\t%s\n' "$host" "$port" "$wildcard" "$display"
}

ss_listen_matches() {
  local host="$1" port="$2" wildcard="$3"
  command -v ss >/dev/null 2>&1 || return 1
  ss -ltnH 2>/dev/null | awk -v h="$host" -v p="$port" -v w="$wildcard" '
    {
      addr = $4
      if (addr == h ":" p || addr == "[" h "]:" p || addr == "[::ffff:" h "]:" p) { found = 1; exit }
      if (w == "true" && (addr == "0.0.0.0:" p || addr == "*:" p || addr == "[::]:" p || addr == ":::" p)) { found = 1; exit }
    }
    END { exit(found ? 0 : 1) }
  '
}

probe_tcp_endpoint() {
  local host="$1" port="$2" wildcard="$3" is_pp="$4"
  # proxy_protocol 监听（含透明串接内部 127.0.0.1:15080/15443）：优先用 ss 核对 LISTEN 套接字
  # 避免空 TCP 探针在 Caddy 产生 proxy_protocol EOF 告警；无 ss 时发送合规 PROXY UNKNOWN 头。
  if [[ "$is_pp" == "true" ]]; then
    if ss_listen_matches "$host" "$port" "$wildcard"; then
      return 0
    fi
    if (exec 3<>"/dev/tcp/$host/$port" && printf 'PROXY UNKNOWN\r\n' >&3 && exec 3>&- 3<&-) 2>/dev/null; then
      return 0
    fi
    if [[ "$wildcard" == "true" ]] && (exec 3<>"/dev/tcp/::1/$port" && printf 'PROXY UNKNOWN\r\n' >&3 && exec 3>&- 3<&-) 2>/dev/null; then
      return 0
    fi
    return 1
  fi
  if (exec 3<>"/dev/tcp/$host/$port" && exec 3>&- 3<&-) 2>/dev/null; then
    return 0
  fi
  if [[ "$wildcard" == "true" ]] && (exec 3<>"/dev/tcp/::1/$port" && exec 3>&- 3<&-) 2>/dev/null; then
    return 0
  fi
  return 1
}

# ---- 1. 容器状态 ----
if [[ -f "$JZ_COMPOSE_FILE" ]]; then
  if [[ -f "$JZ_ENV_FILE" ]]; then
    ps_out="$(compose ps --format '{{.Name}} {{.State}} {{.Health}}' 2>/dev/null || true)"
  else
    ps_out="$(docker compose -f "$JZ_COMPOSE_FILE" ps --format '{{.Name}} {{.State}} {{.Health}}' 2>/dev/null || true)"
  fi
  if [[ -z "$ps_out" ]]; then
    report "containers" FAIL "未获取到容器状态（compose 项目未启动？）"
  else
    bad=""
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      read -r name state health _extra <<<"$line"
      if [[ "$state" != "running" ]]; then
        bad="$bad $name($state)"
      elif [[ -n "$health" && "$health" != "healthy" && "$health" != "starting" ]]; then
        bad="$bad $name($health)"
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
  if [[ "$GATEWAY_URL" =~ ^[a-zA-Z]+://\[([^\]]+)\]:([0-9]+) ]]; then
    gw_host="${BASH_REMATCH[1]}"
    gw_port="${BASH_REMATCH[2]}"
  elif [[ "$GATEWAY_URL" =~ ^[a-zA-Z]+://\[([^\]]+)\] ]]; then
    gw_host="${BASH_REMATCH[1]}"
    gw_port=80
  else
    gw_host="$(printf '%s' "$GATEWAY_URL" | sed -E 's#^[a-z]+://([^:/]+).*#\1#')"
    gw_port="$(printf '%s' "$GATEWAY_URL" | sed -E 's#^[a-z]+://[^:/]+:([0-9]+).*#\1#')"
    [[ "$gw_port" =~ ^[0-9]+$ ]] || gw_port=80
  fi
  if (exec 3<>"/dev/tcp/$gw_host/$gw_port" && exec 3>&- 3<&-) 2>/dev/null; then
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
  gateway_endpoints=()
  while IFS=$'\t' read -r is_pp listen; do
    [[ -n "$listen" ]] || continue
    parsed="$(parse_caddy_listen "$listen" 2>/dev/null || true)"
    [[ -n "$parsed" ]] || continue
    IFS=$'\t' read -r dial_host dial_port is_wildcard display <<<"$parsed"
    if [[ "$dial_host" == "127.0.0.1" && ( "$dial_port" == "15080" || "$dial_port" == "15443" ) ]]; then
      is_pp="true"
    fi
    gateway_endpoints+=("${dial_host}"$'\t'"${dial_port}"$'\t'"${is_wildcard}"$'\t'"${is_pp}"$'\t'"${display}")
  done < <(jq -r '
    to_entries
    | map(select(.value | type == "object"))
    | map(
        (((.value.listener_wrappers // []) | any(type == "object" and .wrapper == "proxy_protocol"))) as $pp
        | (.value.listen // [])[]?
        | select(type == "string")
        | {listen: ., pp: $pp}
      )
    | group_by(.listen)
    | map({listen: .[0].listen, pp: (any(.pp))})
    | .[] | [(.pp | tostring), .listen] | @tsv
  ' <<<"$listeners" 2>/dev/null || true)
  if [[ ${#gateway_endpoints[@]} -eq 0 ]]; then
    if jq -e 'type == "object" and length == 0' <<<"$listeners" >/dev/null 2>&1; then
      report "gateway" OK "Caddy Admin 可访问，当前无站点监听"
    else
      report "gateway" FAIL "无法从 Caddy Admin Unix Socket 读取实际监听端口"
    fi
  else
    gw_fail=""
    gw_ok_list=()
    for ep in "${gateway_endpoints[@]}"; do
      IFS=$'\t' read -r dial_host dial_port is_wildcard is_pp display <<<"$ep"
      gw_ok_list+=("$display")
      if ! probe_tcp_endpoint "$dial_host" "$dial_port" "$is_wildcard" "$is_pp"; then
        gw_fail="$gw_fail $display"
      fi
    done
    if [[ -n "$gw_fail" ]]; then
      report "gateway" FAIL "实际监听端点不可连接:$gw_fail"
    else
      report "gateway" OK "Caddy 实际监听 ${gw_ok_list[*]} 均可连接"
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

# ---- 6. ClickHouse 数据面（仅同机运行独立 APM ClickHouse 时校验） ----
ch_container="$(colocated_apm_clickhouse_container)"
if [[ -n "$ch_container" ]]; then
  if docker exec "$ch_container" wget -q -O /dev/null http://127.0.0.1:8123/ping >/dev/null 2>&1; then
    ch_nets=()
    while IFS= read -r _net; do
      valid_docker_network_name "$_net" && ch_nets+=("$_net")
    done < <(container_network_names "$ch_container")
    api_id=""
    if [[ -f "$JZ_COMPOSE_FILE" ]]; then
      if [[ -f "$JZ_ENV_FILE" ]]; then
        api_id="$(compose ps -q api 2>/dev/null || true)"
      else
        api_id="$(docker compose -f "$JZ_COMPOSE_FILE" ps -q api 2>/dev/null || true)"
      fi
    fi
    shared_net=""
    if [[ -n "$api_id" && ${#ch_nets[@]} -gt 0 ]]; then
      api_nets="$(container_network_names "$api_id")"
      for _net in "${ch_nets[@]}"; do
        if [[ -n "$api_nets" ]] && printf '%s\n' "$api_nets" | grep -Fxq "$_net"; then
          shared_net="$_net"
          break
        fi
      done
    fi
    if [[ -n "$shared_net" ]]; then
      report "clickhouse" OK "容器 ${ch_container}（api 已接入网络 ${shared_net}）"
    elif [[ ${#ch_nets[@]} -eq 0 ]]; then
      report "clickhouse" OK "容器 ${ch_container}（/ping 正常）"
    elif [[ "$STRICT_CLICKHOUSE_NETWORK" == "true" ]]; then
      report "clickhouse" FAIL "api 容器未接入 ClickHouse 网络（${ch_nets[*]}），数据流存储将不可用"
    else
      log_warn "ClickHouse 容器 ${ch_container} 运行中，但 api 容器未接入其网络（${ch_nets[*]}）；升级时将自动修复"
      report "clickhouse" OK "容器 ${ch_container}（/ping 正常；api 待接入网络 ${ch_nets[*]}）"
    fi
    unset ch_nets api_id api_nets shared_net _net
  else
    report "clickhouse" FAIL "ping 失败（容器 ${ch_container}）"
  fi
fi

# ---- 7. 网络与透明串接 sidecar（Compose 声明时校验 --healthcheck） ----
compose_declared_services=""
if [[ -f "$JZ_COMPOSE_FILE" ]]; then
  if [[ -f "$JZ_ENV_FILE" ]]; then
    compose_declared_services="$(compose config --services 2>/dev/null || true)"
  fi
  if [[ -z "$compose_declared_services" ]]; then
    compose_declared_services="$(docker compose -f "$JZ_COMPOSE_FILE" ps --services 2>/dev/null || true)"
  fi
fi

probe_sidecar_healthcheck() {
  local svc="$1" bin="$2" cid=""
  [[ -n "$compose_declared_services" ]] || return 0
  printf '%s\n' "$compose_declared_services" | grep -Fxq "$svc" || return 0
  if [[ -f "$JZ_ENV_FILE" ]]; then
    cid="$(compose ps -q "$svc" 2>/dev/null | head -n 1 || true)"
  else
    cid="$(docker compose -f "$JZ_COMPOSE_FILE" ps -q "$svc" 2>/dev/null | head -n 1 || true)"
  fi
  if [[ -z "$cid" ]]; then
    report "$svc" FAIL "Compose 已声明 ${svc} 但未找到运行容器"
    return 0
  fi
  if run_with_timeout 8 docker exec "$cid" "$bin" --healthcheck >/dev/null 2>&1; then
    report "$svc" OK "容器 ${cid}（--healthcheck）"
  else
    report "$svc" FAIL "${svc} --healthcheck 失败（容器 ${cid}）"
  fi
}

probe_sidecar_healthcheck netmgrd /usr/local/bin/netmgrd
probe_sidecar_healthcheck tproxyd /usr/local/bin/tproxyd

if [[ "$FAILED" -eq 0 ]]; then
  log_info "健康检查通过"
  exit 0
fi
log_err "健康检查存在异常项"
exit 1
