#!/usr/bin/env bash
# apply.sh —— 完整升级：健康预检、已验证备份、全组件切换、健康确认与失败回滚。
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

STATE_FILE="$SCRIPT_DIR/.upgrade-state.env"
FULL_UPGRADE=false
IMAGES_DIR=""
IMAGES_TAR=""
NEW_COMPOSE_FILE=""
SERVER_IMAGE=""
GATEWAY_IMAGE=""
USER="${JZ_ADMIN_USER:-jiuzhang_admin}"
TIMEOUT=600
PREVIOUS_COMPOSE_FILE=""
CURRENT_LINK=""
SERVICES=()
TARGET_IMAGES=()
OLD_IMAGES=()
OLD_IDS=()
SWITCH_STARTED=false

usage() {
  cat <<'EOF'
用法: apply.sh [选项]

  --server-image IMG       目标 API 镜像；完整升级缺省取目标 Compose 的实际镜像
  --gateway-image IMG      目标网关镜像；完整升级缺省取目标 Compose 的实际镜像
  --images-tar FILE        可选的合并镜像 tar
  --images-dir DIR         完整包的 images/ 目录，逐个加载其中的 tar
  --new-compose-file FILE  目标 Compose；gateway 启动契约变化时必填
  --full                   完整升级，要求并更新 api/web/gateway/netmgrd/logrotator/containerops
  --previous-compose-file FILE
                           原 Compose，供自动/手工回滚恢复原 release 入口
  --current-link FILE      可选的 current 符号链接，只在全部健康后由调用方切换
  -u, --user USER          管理员用户名（默认 jiuzhang_admin）
  --api-url URL            管理 API（默认 http://127.0.0.1:18081）
  -c, --compose-file FILE  当前 Compose（默认 docker-compose.yml）
  -e, --env-file FILE      当前及目标环境变量文件（默认 .env）
  --timeout SEC            各等待阶段超时（默认 600）
  -h, --help               显示帮助

JZ_ADMIN_PASSWORD 可预置管理员口令，缺省时交互读取。备份未验证成功前绝不加载/切换镜像。
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --server-image) SERVER_IMAGE="${2:-}"; shift 2 ;;
    --gateway-image) GATEWAY_IMAGE="${2:-}"; shift 2 ;;
    --images-tar) IMAGES_TAR="${2:-}"; shift 2 ;;
    --images-dir) IMAGES_DIR="${2:-}"; shift 2 ;;
    --new-compose-file) NEW_COMPOSE_FILE="${2:-}"; shift 2 ;;
    --full) FULL_UPGRADE=true; shift ;;
    --previous-compose-file) PREVIOUS_COMPOSE_FILE="${2:-}"; shift 2 ;;
    --current-link) CURRENT_LINK="${2:-}"; shift 2 ;;
    -u|--user) USER="${2:-}"; shift 2 ;;
    --api-url) JZ_API_BASE="${2:-}"; shift 2 ;;
    -c|--compose-file) JZ_COMPOSE_FILE="${2:-}"; shift 2 ;;
    -e|--env-file) JZ_ENV_FILE="${2:-}"; shift 2 ;;
    --timeout) TIMEOUT="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) log_err "未知参数: $1"; usage; exit 2 ;;
  esac
done
[[ "$TIMEOUT" =~ ^[1-9][0-9]*$ ]] || { log_err "--timeout 必须为正整数"; exit 2; }
for cmd in docker curl jq base64 timeout; do require_cmd "$cmd"; done
[[ -f "$JZ_COMPOSE_FILE" && -f "$JZ_ENV_FILE" ]] || die "当前 Compose 或 env 文件不存在"
JZ_COMPOSE_FILE="$(cd "$(dirname "$JZ_COMPOSE_FILE")" && pwd -P)/$(basename "$JZ_COMPOSE_FILE")"
JZ_ENV_FILE="$(cd "$(dirname "$JZ_ENV_FILE")" && pwd -P)/$(basename "$JZ_ENV_FILE")"

render_compose() { docker compose -f "$1" --env-file "$2" config --format json 2>/dev/null; }
compose_service_image() { jq -er --arg service "$2" '.services[$service].image | select(type == "string" and length > 0)' <<<"$1"; }
image_entrypoint() {
  local raw
  raw="$(docker image inspect "$1" --format '{{json .Config.Entrypoint}}' 2>/dev/null)" || return 1
  jq -er 'if type == "array" and length == 1 and (.[0] | type == "string") then .[0] else empty end' <<<"$raw"
}
assert_bind_gateway_compose() {
  jq -e '.services.gateway as $g | $g.user == "0:0" and
    ($g.entrypoint == null or $g.entrypoint == ["/usr/local/bin/wdsp-gateway-bind"]) and
    $g.cap_drop == ["ALL"] and
    (($g.cap_add // []) | sort == (["NET_BIND_SERVICE", "SETUID", "SETGID", "SETPCAP"] | sort)) and
    (($g.security_opt // []) | index("no-new-privileges:true") != null)' <<<"$1" >/dev/null
}
legacy_gateway_compose_is_safe() {
  jq -e '.services.gateway as $g |
    ($g.user == null or $g.user == "1000:1000" or $g.user == "caddy" or $g.user == "caddy:caddy") and
    ($g.entrypoint == null or $g.entrypoint == ["/usr/local/bin/docker-entrypoint.sh"]) and
    ($g.cap_add == null or $g.cap_add == ["NET_BIND_SERVICE"]) and
    ($g.cap_drop == null or $g.cap_drop == ["ALL"])' <<<"$1" >/dev/null
}
array_encode() { jq -cn '$ARGS.positional' --args "$@" | base64 | tr -d '\r\n'; }
schema_version() {
  local pg="$1"
  docker exec "$pg" sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc "SELECT COALESCE(MAX(version),0) FROM schema_migrations"' 2>/dev/null
}

log_info "步骤 1/5：升级前健康检查"
if [[ -x "$SCRIPT_DIR/../healthcheck/check.sh" ]]; then
  "$SCRIPT_DIR/../healthcheck/check.sh" -c "$JZ_COMPOSE_FILE" -e "$JZ_ENV_FILE" --api-url "$JZ_API_BASE" \
    || die "升级前健康检查未通过，已中止"
else
  wait_http_ok "$JZ_API_BASE/api/v1/health" 10 || die "管理 API 不可达，已中止"
fi

log_info "步骤 2/5：创建并验证 FULL 加密备份"
trap api_cleanup EXIT
api_login "$USER"
resp="$(api_req POST /api/v1/backups '{"backup_type":"FULL"}')"
[[ "$(api_code "$resp")" == "SUCCESS" ]] || die "创建备份失败: $(printf '%s' "$resp" | jq -r '.message // "未知错误"')"
BACKUP_JOB_ID="$(printf '%s' "$resp" | jq -r '.data.job.id // empty')"
[[ "$BACKUP_JOB_ID" =~ ^[0-9a-fA-F-]{36}$ ]] || die "备份任务 ID 无效"
elapsed=0
while :; do
  resp="$(api_req GET "/api/v1/backups/$BACKUP_JOB_ID")"
  status="$(printf '%s' "$resp" | jq -r '.data.job.status // empty')"
  verified="$(printf '%s' "$resp" | jq -r '.data.job.verified // false')"
  [[ "$status" == "SUCCESS" && "$verified" == "true" ]] && break
  [[ "$status" == "FAILED" || "$status" == "CANCELLED" ]] && die "升级前备份未成功，未切换镜像"
  (( elapsed >= TIMEOUT )) && die "等待备份超时，未切换镜像"
  sleep 5; elapsed=$((elapsed + 5))
done
api_cleanup
trap - EXIT
log_info "升级前备份已完成并通过验证"

OLD_COMPOSE_FILE="$JZ_COMPOSE_FILE"
TARGET_COMPOSE_FILE="${NEW_COMPOSE_FILE:-$OLD_COMPOSE_FILE}"
[[ -f "$TARGET_COMPOSE_FILE" ]] || die "目标 Compose 不存在"
TARGET_COMPOSE_FILE="$(cd "$(dirname "$TARGET_COMPOSE_FILE")" && pwd -P)/$(basename "$TARGET_COMPOSE_FILE")"
TARGET_INSTALL_ROOT="$(dirname "$TARGET_COMPOSE_FILE")"
[[ -z "$PREVIOUS_COMPOSE_FILE" ]] || PREVIOUS_COMPOSE_FILE="$(cd "$(dirname "$PREVIOUS_COMPOSE_FILE")" && pwd -P)/$(basename "$PREVIOUS_COMPOSE_FILE")"
OLD_COMPOSE_JSON="$(render_compose "$OLD_COMPOSE_FILE" "$JZ_ENV_FILE")" || die "无法渲染当前 Compose"
TARGET_COMPOSE_JSON="$(render_compose "$TARGET_COMPOSE_FILE" "$JZ_ENV_FILE")" || die "无法渲染目标 Compose"
CUR_SERVER_IMAGE="$(compose_service_image "$TARGET_COMPOSE_JSON" api)" || die "目标 Compose 缺少 api 镜像"
CUR_GATEWAY_IMAGE="$(compose_service_image "$TARGET_COMPOSE_JSON" gateway)" || die "目标 Compose 缺少 gateway 镜像"
[[ -n "$SERVER_IMAGE" ]] || { [[ "$FULL_UPGRADE" == true ]] && SERVER_IMAGE="$CUR_SERVER_IMAGE"; }
[[ -n "$GATEWAY_IMAGE" ]] || { [[ "$FULL_UPGRADE" == true ]] && GATEWAY_IMAGE="$CUR_GATEWAY_IMAGE"; }
[[ -n "$SERVER_IMAGE" && -n "$GATEWAY_IMAGE" ]] || die "必须指定 --server-image 与 --gateway-image"

candidates=(api web gateway netmgrd logrotator containerops)
if [[ "$FULL_UPGRADE" == true ]]; then
  SERVICES=("${candidates[@]}")
  if jq -e '.services.pcapd.image | strings' <<<"$OLD_COMPOSE_JSON" >/dev/null 2>&1; then
    SERVICES+=(pcapd)
  fi
else
  for service in "${candidates[@]}"; do
    jq -e --arg s "$service" '.services[$s].image' <<<"$OLD_COMPOSE_JSON" >/dev/null 2>&1 || continue
    jq -e --arg s "$service" '.services[$s].image' <<<"$TARGET_COMPOSE_JSON" >/dev/null 2>&1 || continue
    SERVICES+=("$service")
  done
fi
for service in "${SERVICES[@]}"; do
  target="$(compose_service_image "$TARGET_COMPOSE_JSON" "$service")" || die "目标 Compose 缺少 $service 镜像"
  TARGET_IMAGES+=("$target")
  if old="$(compose_service_image "$OLD_COMPOSE_JSON" "$service" 2>/dev/null)"; then
    old_id="$(docker image inspect "$old" --format '{{.Id}}' 2>/dev/null)" || die "无法读取当前 $service 镜像 ID"
    OLD_IMAGES+=("$old"); OLD_IDS+=("$old_id")
  else
    [[ "$FULL_UPGRADE" == true ]] || die "当前 Compose 缺少 $service"
    OLD_IMAGES+=(""); OLD_IDS+=("")
  fi
done
GATEWAY_ENTRYPOINT="$(image_entrypoint "$GATEWAY_IMAGE")" || die "无法读取目标 gateway 镜像入口"
case "$GATEWAY_ENTRYPOINT" in
  /usr/local/bin/wdsp-gateway-bind)
    assert_bind_gateway_compose "$TARGET_COMPOSE_JSON" || die "新 gateway 启动器要求匹配的 Compose 安全契约，请使用 --new-compose-file；未切换镜像" ;;
  /usr/local/bin/docker-entrypoint.sh)
    legacy_gateway_compose_is_safe "$TARGET_COMPOSE_JSON" || die "legacy gateway 镜像不能使用新启动器 Compose，未切换镜像" ;;
  *) die "拒绝未知 gateway 镜像入口: $GATEWAY_ENTRYPOINT" ;;
esac

SCHEMA_BEFORE=""
if [[ "$FULL_UPGRADE" == true ]]; then
  [[ -n "$IMAGES_DIR" && -d "$IMAGES_DIR" ]] || die "完整升级必须指定 --images-dir"
  [[ -n "$PREVIOUS_COMPOSE_FILE" && -f "$PREVIOUS_COMPOSE_FILE" ]] || die "完整升级必须指定有效的原 Compose"
  pg_container="$(docker compose -f "$OLD_COMPOSE_FILE" --env-file "$JZ_ENV_FILE" ps -q postgres)" || die "无法定位升级前 PostgreSQL"
  SCHEMA_BEFORE="$(schema_version "$pg_container")"
  [[ "$SCHEMA_BEFORE" =~ ^[0-9]+$ ]] || die "无法读取升级前数据库迁移版本"
fi

log_info "步骤 3/5：加载镜像并记录回滚点"
if [[ -n "$IMAGES_TAR" ]]; then
  [[ -f "$IMAGES_TAR" ]] || die "镜像 tar 不存在"
  docker load -i "$IMAGES_TAR" >/dev/null || die "加载镜像失败"
fi
if [[ -n "$IMAGES_DIR" ]]; then
  for image_tar in "$IMAGES_DIR"/*.tar; do
    [[ -f "$image_tar" ]] || die "镜像目录缺少 tar 文件"
    docker load -i "$image_tar" >/dev/null || die "加载镜像失败: $(basename "$image_tar")"
  done
fi
for target in "${TARGET_IMAGES[@]}" "$SERVER_IMAGE" "$GATEWAY_IMAGE"; do
  docker image inspect "$target" >/dev/null 2>&1 || die "目标镜像不存在: $target"
done
[[ "$SERVER_IMAGE" == "$CUR_SERVER_IMAGE" ]] || docker image inspect "$SERVER_IMAGE" >/dev/null
NEW_SERVER_IMAGE_ID="$(docker image inspect "$SERVER_IMAGE" --format '{{.Id}}')" || die "无法读取目标 API 镜像 ID"

JZ_COMPOSE_FILE="$TARGET_COMPOSE_FILE"
umask 077
cat > "$STATE_FILE" <<EOF
OLD_SERVER_IMAGE=${OLD_IMAGES[0]}
OLD_GATEWAY_IMAGE=$(compose_service_image "$OLD_COMPOSE_JSON" gateway)
OLD_SERVER_IMAGE_ID=${OLD_IDS[0]}
OLD_GATEWAY_IMAGE_ID=$(docker image inspect "$(compose_service_image "$OLD_COMPOSE_JSON" gateway)" --format '{{.Id}}')
NEW_SERVER_IMAGE=$SERVER_IMAGE
NEW_GATEWAY_IMAGE=$GATEWAY_IMAGE
NEW_SERVER_IMAGE_ID=$NEW_SERVER_IMAGE_ID
TARGET_COMPOSE_FILE=$TARGET_COMPOSE_FILE
TARGET_ENV_FILE=$JZ_ENV_FILE
PREVIOUS_COMPOSE_FILE=$PREVIOUS_COMPOSE_FILE
CURRENT_LINK=$CURRENT_LINK
FULL_UPGRADE=$FULL_UPGRADE
SCHEMA_BEFORE=$SCHEMA_BEFORE
UPGRADE_SERVICES=$(printf '%s,' "${SERVICES[@]}" | sed 's/,$//')
TARGET_IMAGES_B64=$(array_encode "${TARGET_IMAGES[@]}")
OLD_IMAGES_B64=$(array_encode "${OLD_IMAGES[@]}")
OLD_IDS_B64=$(array_encode "${OLD_IDS[@]}")
BACKUP_JOB_ID=$BACKUP_JOB_ID
UPGRADE_TIME=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
EOF
chmod 600 "$STATE_FILE"

rollback_failed_upgrade() {
  local rc=$?
  trap - EXIT
  api_cleanup
  if [[ "$SWITCH_STARTED" == true ]]; then
    log_err "升级失败，自动恢复原镜像及新增迁移"
    if bash "$SCRIPT_DIR/rollback.sh" --yes --timeout "$TIMEOUT"; then
      log_err "自动回滚完成；current 保持原 release，备份任务 $BACKUP_JOB_ID"
    else
      log_err "自动回滚未完成；请勿继续启动其他版本，使用备份任务 $BACKUP_JOB_ID 诊断恢复"
    fi
  fi
  exit "$rc"
}
trap rollback_failed_upgrade EXIT

SWITCH_STARTED=true
[[ "$SERVER_IMAGE" == "$CUR_SERVER_IMAGE" ]] || docker tag "$SERVER_IMAGE" "$CUR_SERVER_IMAGE"
[[ "$GATEWAY_IMAGE" == "$CUR_GATEWAY_IMAGE" ]] || docker tag "$GATEWAY_IMAGE" "$CUR_GATEWAY_IMAGE"

log_info "步骤 4/5：同次重建 ${SERVICES[*]}（PCAP profile 不启动）"
compose rm -sf "${SERVICES[@]}" >/dev/null 2>&1 || true
compose up -d --no-deps --force-recreate "${SERVICES[@]}" || die "新容器创建失败"
wait_selected_services() {
  local deadline=$((SECONDS + TIMEOUT)) service id snapshot state health image restarts started extra ready
  while (( SECONDS < deadline )); do
    ready=true
    for i in "${!SERVICES[@]}"; do
      service="${SERVICES[$i]}"
      id="$(compose ps -q "$service" 2>/dev/null)" || { log_warn "$service 容器不存在"; ready=false; break; }
      [[ "$id" =~ ^[a-fA-F0-9]+$ ]] || { ready=false; break; }
      snapshot="$(timeout 8 docker inspect --format '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}|{{.Image}}|{{.RestartCount}}|{{.State.StartedAt}}' "$id" 2>/dev/null)" || { ready=false; break; }
      IFS='|' read -r state health image restarts started extra <<<"$snapshot"
      expected="$(docker image inspect "${TARGET_IMAGES[$i]}" --format '{{.Id}}' 2>/dev/null)" || { ready=false; break; }
      if [[ "$state" != running || -n "$extra" || ( -n "$health" && "$health" != healthy ) || "$image" != "$expected" || ! "$restarts" =~ ^[0-9]+$ || -z "$started" ]]; then
        log_warn "$service 尚未运行目标镜像并通过自身健康检查"
        ready=false; break
      fi
      case "$service" in
        api) timeout 8 docker exec "$id" wget -q -T 5 -O /dev/null http://127.0.0.1:8080/api/v1/health || { ready=false; break; } ;;
        web) timeout 12 docker exec "$id" sh -ec 'wget -q -T 5 -O /dev/null http://127.0.0.1:8080/ && wget -q -T 5 -O /dev/null http://127.0.0.1:8080/api/v1/health' || { ready=false; break; } ;;
        netmgrd) timeout 8 docker exec "$id" /usr/local/bin/netmgrd --healthcheck || { ready=false; break; } ;;
      esac
    done
    if [[ "$ready" == true ]] && curl -fsS --max-time 5 "$JZ_API_BASE/api/v1/health" >/dev/null 2>&1; then
      sleep 10
      for service in "${SERVICES[@]}"; do
        id="$(compose ps -q "$service" 2>/dev/null)" || return 1
        [[ "$(docker inspect --format '{{.State.Status}}' "$id" 2>/dev/null)" == running ]] || return 1
      done
      return 0
    fi
    sleep 2
  done
  return 1
}
wait_selected_services || die "组件镜像、运行状态或 HTTP 健康检查未通过"

log_info "步骤 5/5：完整健康检查及 hostctl 单元更新"
if [[ -x "$SCRIPT_DIR/../healthcheck/check.sh" ]]; then
  "$SCRIPT_DIR/../healthcheck/check.sh" -c "$TARGET_COMPOSE_FILE" -e "$JZ_ENV_FILE" --api-url "$JZ_API_BASE" \
    || die "升级后健康检查失败"
fi
bash "$TARGET_INSTALL_ROOT/ops/install/install-hostctl.sh" --install-root "$TARGET_INSTALL_ROOT" --strict \
  || die "升级后 hostctl 单元更新失败（目标 release: $TARGET_INSTALL_ROOT），开始自动回滚"
SWITCH_STARTED=false
trap - EXIT
log_info "容器与数据库升级完成；备份任务 $BACKUP_JOB_ID。current 由完整升级入口在后续宿主检查通过后切换"
