#!/usr/bin/env bash
# rollback.sh —— 恢复升级前镜像、精确回退本轮新增迁移并验证实际服务。
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

STATE_FILE="$SCRIPT_DIR/.upgrade-state.env"
GATEWAY_OVERRIDE=""
GATEWAY_VALUE_OVERRIDE=""
RESTORE_BACKUP=false
COMPOSE_FILE_EXPLICIT=false
ENV_FILE_EXPLICIT=false
USER="${JZ_ADMIN_USER:-jiuzhang_admin}"
TIMEOUT=600

usage() {
  cat <<'EOF'
用法: rollback.sh [选项]
  --restore-backup       镜像及迁移回滚后，再确认恢复升级前 FULL 备份（会覆盖现有数据）
  -u, --user USER        管理员用户名
  --api-url URL          管理 API（默认 http://127.0.0.1:18081）
  -c, --compose-file FILE 默认复用升级状态中的目标 Compose
  -e, --env-file FILE    默认复用升级状态中的目标 env
  --timeout SEC          健康检查超时（默认 600）
  -y, --yes              跳过交互确认
  -h, --help             显示帮助
EOF
}
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
assert_legacy_gateway_override() {
  jq -e '.services.gateway as $g | $g.entrypoint == ["/usr/local/bin/docker-entrypoint.sh"] and
    $g.user == "1000:1000" and $g.cap_add == ["NET_BIND_SERVICE"] and $g.cap_drop == ["ALL"] and
    (($g.security_opt // []) | index("no-new-privileges:true") != null)' <<<"$1" >/dev/null
}
legacy_reset_values_were_ignored() {
  jq -e '.services.gateway as $g | $g.entrypoint == ["/usr/local/bin/docker-entrypoint.sh"] and
    $g.user == "1000:1000" and (($g | has("cap_add")) | not) and (($g | has("cap_drop")) | not) and
    (($g.security_opt // []) | index("no-new-privileges:true") != null)' <<<"$1" >/dev/null
}
cleanup_gateway_override() {
  [[ -z "$GATEWAY_OVERRIDE" ]] || rm -f -- "$GATEWAY_OVERRIDE"
  [[ -z "$GATEWAY_VALUE_OVERRIDE" ]] || rm -f -- "$GATEWAY_VALUE_OVERRIDE"
  GATEWAY_OVERRIDE=""; GATEWAY_VALUE_OVERRIDE=""
}
compose() {
  local args=(-f "$JZ_COMPOSE_FILE")
  [[ -z "$GATEWAY_OVERRIDE" ]] || args+=(-f "$GATEWAY_OVERRIDE")
  [[ -z "$GATEWAY_VALUE_OVERRIDE" ]] || args+=(-f "$GATEWAY_VALUE_OVERRIDE")
  docker compose "${args[@]}" --env-file "$JZ_ENV_FILE" "$@"
}
schema_version() {
  docker exec "$1" sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc "SELECT COALESCE(MAX(version),0) FROM schema_migrations"' 2>/dev/null
}
array_decode() { printf '%s' "$1" | base64 --decode | jq -er '.[]'; }
switch_current() {
  [[ -n "$CURRENT_LINK" && -n "$OLD_INSTALL_ROOT" ]] || return 0
  [[ -d "$OLD_INSTALL_ROOT" ]] || die "原 release 目录不存在，拒绝切换 current"
  local parent tmp
  parent="$(dirname "$CURRENT_LINK")"
  tmp="$parent/.current.rollback.$$"
  ln -s "$OLD_INSTALL_ROOT" "$tmp"
  mv -Tf "$tmp" "$CURRENT_LINK"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --restore-backup) RESTORE_BACKUP=true; shift ;;
    -u|--user) USER="${2:-}"; shift 2 ;;
    --api-url) JZ_API_BASE="${2:-}"; shift 2 ;;
    -c|--compose-file) JZ_COMPOSE_FILE="${2:-}"; COMPOSE_FILE_EXPLICIT=true; shift 2 ;;
    -e|--env-file) JZ_ENV_FILE="${2:-}"; ENV_FILE_EXPLICIT=true; shift 2 ;;
    --timeout) TIMEOUT="${2:-}"; shift 2 ;;
    -y|--yes) JZ_ASSUME_YES=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) log_err "未知参数: $1"; usage; exit 2 ;;
  esac
done
[[ "$TIMEOUT" =~ ^[1-9][0-9]*$ ]] || { log_err "--timeout 必须为正整数"; exit 2; }
[[ -f "$STATE_FILE" ]] || die "回滚状态文件不存在"
for cmd in docker jq mktemp base64 timeout; do require_cmd "$cmd"; done

OLD_SERVER_IMAGE=""; OLD_GATEWAY_IMAGE=""; NEW_SERVER_IMAGE=""; NEW_GATEWAY_IMAGE=""; BACKUP_JOB_ID=""
OLD_SERVER_IMAGE_ID=""; OLD_GATEWAY_IMAGE_ID=""; NEW_SERVER_IMAGE_ID=""
TARGET_COMPOSE_FILE=""; TARGET_ENV_FILE=""; PREVIOUS_COMPOSE_FILE=""; CURRENT_LINK=""
FULL_UPGRADE=false; SCHEMA_BEFORE=""; UPGRADE_SERVICES=""; TARGET_IMAGES_B64=""; OLD_IMAGES_B64=""; OLD_IDS_B64=""
load_env_file "$STATE_FILE"
[[ -n "$OLD_SERVER_IMAGE" && -n "$OLD_GATEWAY_IMAGE" ]] || die "回滚状态缺少旧镜像信息"
[[ -n "$BACKUP_JOB_ID" ]] || log_warn "回滚状态无备份任务 ID"
if [[ "$COMPOSE_FILE_EXPLICIT" == false && -n "$TARGET_COMPOSE_FILE" ]]; then JZ_COMPOSE_FILE="$TARGET_COMPOSE_FILE"; fi
if [[ "$ENV_FILE_EXPLICIT" == false && -n "$TARGET_ENV_FILE" ]]; then JZ_ENV_FILE="$TARGET_ENV_FILE"; fi
[[ -f "$JZ_COMPOSE_FILE" && -f "$JZ_ENV_FILE" ]] || die "回滚 Compose 或 env 文件不存在"
OLD_INSTALL_ROOT=""
[[ -z "$PREVIOUS_COMPOSE_FILE" ]] || OLD_INSTALL_ROOT="$(cd "$(dirname "$PREVIOUS_COMPOSE_FILE")" && pwd -P)"

TARGET_COMPOSE_JSON="$(render_compose "$JZ_COMPOSE_FILE" "$JZ_ENV_FILE")" || die "无法渲染目标 Compose"
CUR_GATEWAY_IMAGE="$(compose_service_image "$TARGET_COMPOSE_JSON" gateway)" || die "目标 Compose 无 gateway"
SERVICES=(); OLD_IDS=(); RESTORE_IMAGES=(); REMOVE_SERVICES=()
if [[ -n "$UPGRADE_SERVICES" && -n "$OLD_IDS_B64" ]]; then
  IFS=',' read -ra SERVICES <<<"$UPGRADE_SERVICES"
  TARGET_IMAGES=(); OLD_IMAGES=(); OLD_IDS=()
  while IFS= read -r item; do TARGET_IMAGES+=("$item"); done < <(array_decode "$TARGET_IMAGES_B64")
  while IFS= read -r item; do OLD_IMAGES+=("$item"); done < <(array_decode "$OLD_IMAGES_B64")
  while IFS= read -r item; do OLD_IDS+=("$item"); done < <(array_decode "$OLD_IDS_B64")
  [[ ${#SERVICES[@]} -eq ${#TARGET_IMAGES[@]} && ${#SERVICES[@]} -eq ${#OLD_IMAGES[@]} && ${#SERVICES[@]} -eq ${#OLD_IDS[@]} ]] \
    || die "回滚组件清单长度不一致"
else
  SERVICES=(api gateway netmgrd)
  TARGET_IMAGES=("$(compose_service_image "$TARGET_COMPOSE_JSON" api)" "$CUR_GATEWAY_IMAGE" "$(compose_service_image "$TARGET_COMPOSE_JSON" netmgrd)")
  OLD_IMAGES=("$OLD_SERVER_IMAGE" "$OLD_GATEWAY_IMAGE" "${TARGET_IMAGES[2]}")
  OLD_IDS=("$OLD_SERVER_IMAGE_ID" "$OLD_GATEWAY_IMAGE_ID" "$(docker image inspect "${TARGET_IMAGES[2]}" --format '{{.Id}}')")
fi
for i in "${!SERVICES[@]}"; do
  service="${SERVICES[$i]}"
  if [[ -z "${OLD_IDS[$i]}" ]]; then
    REMOVE_SERVICES+=("$service")
    continue
  fi
  docker image inspect "${OLD_IDS[$i]}" >/dev/null 2>&1 || die "原 $service 镜像已被清理，禁止切换"
  RESTORE_IMAGES+=("${TARGET_IMAGES[$i]}")
done

OLD_GATEWAY_ENTRYPOINT="$(image_entrypoint "$OLD_GATEWAY_IMAGE_ID")" || die "无法读取旧 gateway 镜像入口"
case "$OLD_GATEWAY_ENTRYPOINT" in
  /usr/local/bin/wdsp-gateway-bind) assert_bind_gateway_compose "$TARGET_COMPOSE_JSON" || die "旧 Compose 不符合新运行契约（gateway 启动契约）" ;;
  /usr/local/bin/docker-entrypoint.sh)
    if ! legacy_gateway_compose_is_safe "$TARGET_COMPOSE_JSON"; then
      GATEWAY_OVERRIDE="$(mktemp "${TMPDIR:-/tmp}/jz-gateway-legacy.XXXXXX.yml")"
      chmod 600 "$GATEWAY_OVERRIDE"
      trap cleanup_gateway_override EXIT
      cat > "$GATEWAY_OVERRIDE" <<'EOF'
services:
  gateway:
    entrypoint: !override ["/usr/local/bin/docker-entrypoint.sh"]
    user: "1000:1000"
    cap_add: !reset ["NET_BIND_SERVICE"]
    cap_drop: !reset ["ALL"]
EOF
      MERGED_COMPOSE_JSON="$(compose config --format json 2>/dev/null)" || die "无法渲染回滚 Compose"
      if ! assert_legacy_gateway_override "$MERGED_COMPOSE_JSON"; then
        legacy_reset_values_were_ignored "$MERGED_COMPOSE_JSON" || die "legacy gateway override 渲染不符合精确契约，禁止 retag/up"
        GATEWAY_VALUE_OVERRIDE="$(mktemp "${TMPDIR:-/tmp}/jz-gateway-legacy-values.XXXXXX.yml")"
        chmod 600 "$GATEWAY_VALUE_OVERRIDE"
        cat > "$GATEWAY_VALUE_OVERRIDE" <<'EOF'
services:
  gateway:
    cap_add: ["NET_BIND_SERVICE"]
    cap_drop: ["ALL"]
EOF
        MERGED_COMPOSE_JSON="$(compose config --format json 2>/dev/null)" || die "无法渲染 capability 补值层"
        assert_legacy_gateway_override "$MERGED_COMPOSE_JSON" || die "legacy gateway 最终渲染不符合精确契约"
      fi
    fi ;;
  *) die "拒绝回滚到未知 gateway 镜像入口" ;;
esac

confirm "确认恢复原容器镜像及本轮新增迁移？" || { log_warn "已取消"; exit 3; }
if [[ "$FULL_UPGRADE" == true ]]; then
  [[ "$SCHEMA_BEFORE" =~ ^[0-9]+$ ]] || die "缺少升级前迁移版本，禁止猜测回退"
  pg_container="$(compose ps -q postgres)" || die "无法定位 PostgreSQL，停止回滚"
  current_schema="$(schema_version "$pg_container")"
  [[ "$current_schema" =~ ^[0-9]+$ ]] || die "无法读取当前数据库迁移版本"
  (( current_schema >= SCHEMA_BEFORE )) || die "数据库迁移版本低于升级前记录，停止回滚"
  rollback_steps=$((current_schema - SCHEMA_BEFORE))
  for ((i=0; i<rollback_steps; i++)); do
    docker run --rm --network "container:$pg_container" --env-file "$JZ_ENV_FILE" \
      -e POSTGRES_HOST=127.0.0.1 -e POSTGRES_PORT=5432 -e MIGRATIONS_DIR=/app/migrations \
      --entrypoint /usr/local/bin/jiuzhang-api "$NEW_SERVER_IMAGE_ID" migrate down >/dev/null \
      || die "数据库迁移回退失败，保留当前容器供诊断；可使用备份 $BACKUP_JOB_ID 恢复"
  done
  [[ "$(schema_version "$pg_container")" == "$SCHEMA_BEFORE" ]] || die "数据库迁移版本未恢复到升级前记录"
fi

for i in "${!SERVICES[@]}"; do
  [[ -z "${OLD_IDS[$i]}" ]] || docker tag "${OLD_IDS[$i]}" "${TARGET_IMAGES[$i]}"
done
((${#REMOVE_SERVICES[@]} == 0)) || compose rm -sf "${REMOVE_SERVICES[@]}" >/dev/null 2>&1 || true
EXISTING_SERVICES=()
for i in "${!SERVICES[@]}"; do [[ -z "${OLD_IDS[$i]}" ]] || EXISTING_SERVICES+=("${SERVICES[$i]}"); done
log_info "重建原组件: ${EXISTING_SERVICES[*]}"
compose rm -sf "${EXISTING_SERVICES[@]}" >/dev/null 2>&1 || true
compose up -d --no-deps --force-recreate "${EXISTING_SERVICES[@]}" || die "原容器重建失败"
cleanup_gateway_override
trap - EXIT

end=$((SECONDS + TIMEOUT))
while (( SECONDS < end )); do
  ready=true
  for i in "${!SERVICES[@]}"; do
    [[ -n "${OLD_IDS[$i]}" ]] || continue
    service="${SERVICES[$i]}"
    id="$(compose ps -q "$service" 2>/dev/null)" || { ready=false; break; }
    snapshot="$(timeout 8 docker inspect --format '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}|{{.Image}}' "$id" 2>/dev/null)" || { ready=false; break; }
    IFS='|' read -r state health image <<<"$snapshot"
    [[ "$state" == running && "$image" == "${OLD_IDS[$i]}" && ( -z "$health" || "$health" == healthy ) ]] || { ready=false; break; }
    case "$service" in
      api) timeout 8 docker exec "$id" wget -q -T 5 -O /dev/null http://127.0.0.1:8080/api/v1/health || { ready=false; break; } ;;
      web) timeout 12 docker exec "$id" sh -ec 'wget -q -T 5 -O /dev/null http://127.0.0.1:8080/ && wget -q -T 5 -O /dev/null http://127.0.0.1:8080/api/v1/health' || { ready=false; break; } ;;
      netmgrd) timeout 8 docker exec "$id" /usr/local/bin/netmgrd --healthcheck || { ready=false; break; } ;;
    esac
  done
  [[ "$ready" == true ]] && curl -fsS --max-time 5 "$JZ_API_BASE/api/v1/health" >/dev/null 2>&1 && break
  sleep 2
done
[[ "$ready" == true ]] || die "回滚后容器或 HTTP 健康检查未通过"
wait_http_ok "$JZ_API_BASE/api/v1/health" "$TIMEOUT" || die "回滚后管理 API 未就绪"
if [[ -n "$OLD_INSTALL_ROOT" && -f "$SCRIPT_DIR/../install/install-hostctl.sh" ]]; then
  bash "$SCRIPT_DIR/../install/install-hostctl.sh" --install-root "$OLD_INSTALL_ROOT" --strict \
    || die "hostctl 尚未恢复原 release 路径"
fi
switch_current

if [[ "$RESTORE_BACKUP" == true ]]; then
  [[ -n "$BACKUP_JOB_ID" ]] || die "无升级前备份任务 ID"
  log_warn "恢复 FULL 备份将覆盖范围内现有数据"
  "$SCRIPT_DIR/../restore/restore.sh" --backup-id "$BACKUP_JOB_ID" --scope FULL \
    --user "$USER" --api-url "$JZ_API_BASE" --yes
fi
log_info "回滚完成；原镜像、迁移版本和实际服务已复核"
