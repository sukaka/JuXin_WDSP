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
USER=""
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
schema_migrations_above() {
  local pg="$1" before="$2"
  docker exec "$pg" sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc "SELECT COUNT(*) FROM schema_migrations WHERE version > '"$before"'"' 2>/dev/null
}
array_decode() { printf '%s' "$1" | base64 --decode | jq -er '.[]'; }
switch_current() {
  [[ -n "$CURRENT_LINK" && -n "$OLD_INSTALL_ROOT" ]] || return 0
  [[ -d "$OLD_INSTALL_ROOT" ]] || die "原 release 目录不存在，拒绝切换 current"
  local parent tmp
  parent="$(dirname "$CURRENT_LINK")"
  tmp="$parent/.current.rollback.$$"
  ln -s "$OLD_INSTALL_ROOT" "$tmp"
  if ! mv -Tf "$tmp" "$CURRENT_LINK" 2>/dev/null \
    && ! mv -hf "$tmp" "$CURRENT_LINK" 2>/dev/null \
    && ! { command -v python3 >/dev/null 2>&1 && python3 -c 'import os,sys; os.replace(sys.argv[1], sys.argv[2])' "$tmp" "$CURRENT_LINK" 2>/dev/null; }; then
    rm -f -- "$tmp"
    die "回滚切换 current 软链失败: ${CURRENT_LINK}"
  fi
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
FULL_UPGRADE=false; SCHEMA_BEFORE=""; UPGRADE_SERVICES=""; TARGET_IMAGES_B64=""; OLD_IMAGES_B64=""; OLD_IDS_B64=""; API_EXTRA_NETWORKS_B64=""
RULES_VOLUME_NAME=""; RULES_PREVIOUS_CURRENT_TARGET=""
load_env_file "$STATE_FILE"
[[ -n "$OLD_SERVER_IMAGE" && -n "$OLD_GATEWAY_IMAGE" ]] || die "回滚状态缺少旧镜像信息"
[[ -n "$BACKUP_JOB_ID" ]] || log_warn "回滚状态无备份任务 ID"
if [[ "$COMPOSE_FILE_EXPLICIT" == false && -n "$TARGET_COMPOSE_FILE" ]]; then JZ_COMPOSE_FILE="$TARGET_COMPOSE_FILE"; fi
if [[ "$ENV_FILE_EXPLICIT" == false && -n "$TARGET_ENV_FILE" ]]; then JZ_ENV_FILE="$TARGET_ENV_FILE"; fi
[[ -f "$JZ_COMPOSE_FILE" && -f "$JZ_ENV_FILE" ]] || die "回滚 Compose 或 env 文件不存在"
OLD_INSTALL_ROOT=""
[[ -z "$PREVIOUS_COMPOSE_FILE" ]] || OLD_INSTALL_ROOT="$(cd "$(dirname "$PREVIOUS_COMPOSE_FILE")" && pwd -P)"
ROLLBACK_TO_PREVIOUS_RELEASE=false
NEW_COMPOSE_FOR_CLEANUP="$JZ_COMPOSE_FILE"
NEW_ENV_FOR_CLEANUP="$JZ_ENV_FILE"
if [[ "$FULL_UPGRADE" == true && "$COMPOSE_FILE_EXPLICIT" == false && -n "$PREVIOUS_COMPOSE_FILE" && -f "$PREVIOUS_COMPOSE_FILE" ]]; then
  ROLLBACK_TO_PREVIOUS_RELEASE=true
  JZ_COMPOSE_FILE="$PREVIOUS_COMPOSE_FILE"
  if [[ "$ENV_FILE_EXPLICIT" == false && -n "$OLD_INSTALL_ROOT" && -f "$OLD_INSTALL_ROOT/.env" ]]; then
    JZ_ENV_FILE="$OLD_INSTALL_ROOT/.env"
  fi
fi
[[ -n "$USER" ]] || USER="$(resolve_default_admin_user "$JZ_ENV_FILE")"

TARGET_COMPOSE_JSON="$(render_compose "$JZ_COMPOSE_FILE" "$JZ_ENV_FILE")" || die "无法渲染回滚 Compose"
CUR_GATEWAY_IMAGE="$(compose_service_image "$TARGET_COMPOSE_JSON" gateway)" || die "回滚 Compose 无 gateway"
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
  if [[ "$ROLLBACK_TO_PREVIOUS_RELEASE" == true ]]; then
    RESTORE_IMAGES+=("${OLD_IMAGES[$i]}")
  else
    RESTORE_IMAGES+=("${TARGET_IMAGES[$i]}")
  fi
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

restore_sidecars_permissions_for_legacy_netmgrd() {
  # 目标回滚 Compose 的 netmgrd 使用 cap_drop: [ALL] 且未配置 group_add: ["1000"] 时（如 1.10.1），
  # 升级前 apply.sh 可能已将 sidecars 改为 1000:1000 0770，回滚后 UID 0 且无 CAP_DAC_OVERRIDE 的旧
  # netmgrd 会因 permission denied 持续 503；将其收敛为 0:1000 0770，同时兼容旧 netmgrd(UID 0) 与 api/gateway(GID 1000)。
  jq -e '
    .services.netmgrd as $n |
    ($n != null) and
    (($n.cap_drop // []) | index("ALL") != null) and
    ((($n.group_add // []) | map(tostring) | index("1000")) == null)
  ' <<<"$TARGET_COMPOSE_JSON" >/dev/null 2>&1 || return 0

  local admin_dir="" cur_gw_id="" admin_vol="" admin_vol_name=""
  cur_gw_id="$(docker compose -f "$NEW_COMPOSE_FOR_CLEANUP" --env-file "$NEW_ENV_FOR_CLEANUP" ps -q gateway 2>/dev/null || true)"
  [[ -n "$cur_gw_id" ]] || cur_gw_id="$(compose ps -q gateway 2>/dev/null || true)"
  if [[ "$cur_gw_id" =~ ^[a-fA-F0-9]+$ ]]; then
    admin_dir="$(docker inspect --format '{{json .Mounts}}' "$cur_gw_id" 2>/dev/null \
      | jq -r '[.[]? | select(.Destination == "/var/run/caddy") | .Source] | if length == 1 then .[0] | select(type == "string" and startswith("/")) else empty end' 2>/dev/null || true)"
  fi
  if [[ -z "$admin_dir" ]]; then
    admin_vol="$(jq -r '[.services.netmgrd.volumes[]? | select(.type == "volume" and .target == "/var/run/caddy") | .source] | if length == 1 then .[0] | select(type == "string" and length > 0) else empty end' <<<"$TARGET_COMPOSE_JSON" 2>/dev/null || true)"
    if [[ -n "$admin_vol" ]]; then
      admin_vol_name="$(jq -r --arg k "$admin_vol" '(.volumes[$k].name // empty) as $e | (.name // empty) as $p | if ($e | length) > 0 then $e elif ($p | length) > 0 then ($p + "_" + $k) else $k end' <<<"$TARGET_COMPOSE_JSON" 2>/dev/null || true)"
      admin_dir="$(docker volume inspect --format '{{.Mountpoint}}' "$admin_vol_name" 2>/dev/null || true)"
    fi
  fi
  [[ -n "$admin_dir" && "$admin_dir" == /* && -d "$admin_dir" && ! -L "$admin_dir" ]] || return 0
  local sidecars_dir="$admin_dir/sidecars"
  [[ -d "$sidecars_dir" && ! -L "$sidecars_dir" ]] || return 0
  if [[ "$(id -u)" == "0" ]]; then
    chown 0:1000 "$sidecars_dir" || die "无法恢复 sidecars 目录属主: $sidecars_dir"
  fi
  chmod 0770 "$sidecars_dir" || die "无法恢复 sidecars 目录权限: $sidecars_dir"
  local diag_dir="$sidecars_dir/diag"
  if [[ -d "$diag_dir" && ! -L "$diag_dir" ]]; then
    if [[ "$(id -u)" == "0" ]]; then
      chown 0:1000 "$diag_dir" || die "无法恢复 sidecars/diag 目录属主: $diag_dir"
    fi
    chmod 0770 "$diag_dir" || die "无法恢复 sidecars/diag 目录权限: $diag_dir"
  fi
  log_info "已恢复 sidecars 目录权限（0:1000 0770，兼容旧版无 group_add 的 netmgrd）"
}
restore_gateway_rules_symlink_if_needed() {
  # 仅当升级期间将 builtin-* current 切换到了新版 builtin-* 时才回切；
  # 若原环境已使用客户日期规则包（apply.sh 未改动 current）或旧版仍挂载宿主目录，则不触碰。
  [[ -n "$RULES_VOLUME_NAME" && -n "$RULES_PREVIOUS_CURRENT_TARGET" ]] || return 0
  [[ "$RULES_PREVIOUS_CURRENT_TARGET" =~ ^releases/builtin-[0-9A-Za-z._-]+$ ]] || return 0
  local dst tmp_link rel
  dst="$(docker volume inspect --format '{{.Mountpoint}}' "$RULES_VOLUME_NAME" 2>/dev/null || true)"
  [[ -n "$dst" && "$dst" == /* && -d "$dst" && ! -L "$dst" ]] || return 0
  for rel in coraza.conf crs/crs-setup.conf jiuzhang/post-contrib-blocking.conf; do
    [[ -f "$dst/$RULES_PREVIOUS_CURRENT_TARGET/$rel" && ! -L "$dst/$RULES_PREVIOUS_CURRENT_TARGET/$rel" && -s "$dst/$RULES_PREVIOUS_CURRENT_TARGET/$rel" ]] || return 0
  done
  tmp_link="$dst/.current.rollback.$$.$RANDOM"
  rm -f -- "$tmp_link"
  ln -s "$RULES_PREVIOUS_CURRENT_TARGET" "$tmp_link" || die "创建回滚规则软链失败: $dst"
  if [[ "$(id -u)" == "0" ]]; then
    chown -h 1000:1000 "$tmp_link" 2>/dev/null || true
  fi
  if ! mv -Tf "$tmp_link" "$dst/current" 2>/dev/null \
    && ! mv -hf "$tmp_link" "$dst/current" 2>/dev/null \
    && ! { command -v python3 >/dev/null 2>&1 && python3 -c 'import os,sys; os.replace(sys.argv[1], sys.argv[2])' "$tmp_link" "$dst/current" 2>/dev/null; }; then
    rm -f -- "$tmp_link"
    die "回滚恢复规则卷 current 软链失败: $dst"
  fi
  log_info "已恢复规则卷 current 软链（卷: ${RULES_VOLUME_NAME}，current -> ${RULES_PREVIOUS_CURRENT_TARGET}）"
}

confirm "确认恢复原容器镜像及本轮新增迁移？" || { log_warn "已取消"; exit 3; }
EXISTING_SERVICES=()
for i in "${!SERVICES[@]}"; do [[ -z "${OLD_IDS[$i]}" ]] || EXISTING_SERVICES+=("${SERVICES[$i]}"); done
API_EXTRA_NETWORKS=()
if printf '%s\n' "${EXISTING_SERVICES[@]}" | grep -Fxq api; then
  CUR_API_ID="$(docker compose -f "$NEW_COMPOSE_FOR_CLEANUP" --env-file "$NEW_ENV_FOR_CLEANUP" ps -q api 2>/dev/null || true)"
  [[ -n "$CUR_API_ID" ]] || CUR_API_ID="$(compose ps -q api 2>/dev/null || true)"
  _raw_nets=()
  if [[ -n "$API_EXTRA_NETWORKS_B64" ]]; then
    while IFS= read -r _net; do
      [[ -n "$_net" ]] && _raw_nets+=("$_net")
    done < <(printf '%s' "$API_EXTRA_NETWORKS_B64" | base64 --decode 2>/dev/null | jq -r '.[]? | strings' 2>/dev/null || true)
  fi
  while IFS= read -r _net; do
    [[ -n "$_net" ]] && _raw_nets+=("$_net")
  done < <(collect_api_extra_networks "$CUR_API_ID" "$TARGET_COMPOSE_JSON")
  if ((${#_raw_nets[@]} > 0)); then
    _target_api_nets=()
    while IFS= read -r _net; do
      [[ -n "$_net" ]] && _target_api_nets+=("$_net")
    done < <(compose_service_network_names "$TARGET_COMPOSE_JSON" api)
    while IFS= read -r _net; do
      [[ -n "$_net" ]] || continue
      valid_docker_network_name "$_net" || continue
      _skip=false
      for _ex in ${_target_api_nets[@]+"${_target_api_nets[@]}"}; do
        if [[ "$_net" == "$_ex" ]]; then _skip=true; break; fi
      done
      [[ "$_skip" == false ]] && API_EXTRA_NETWORKS+=("$_net")
    done < <(printf '%s\n' "${_raw_nets[@]}" | LC_ALL=C sort -u)
    unset _target_api_nets _skip _ex
  fi
  unset _raw_nets _net
fi

if [[ "$FULL_UPGRADE" == true ]]; then
  # 回退迁移前先停止可能处于 Restarting 循环的 api 容器，防止并发重新执行 migrate up 导致版本未递减
  docker compose -f "$NEW_COMPOSE_FOR_CLEANUP" --env-file "$NEW_ENV_FOR_CLEANUP" stop api >/dev/null 2>&1 || true
  compose stop api >/dev/null 2>&1 || true
  [[ "$SCHEMA_BEFORE" =~ ^[0-9]+$ ]] || die "缺少升级前迁移版本，禁止猜测回退"
  pg_container="$(compose ps -q postgres)" || die "无法定位 PostgreSQL，停止回滚"
  current_schema="$(schema_version "$pg_container")"
  [[ "$current_schema" =~ ^[0-9]+$ ]] || die "无法读取当前数据库迁移版本"
  (( current_schema >= SCHEMA_BEFORE )) || die "数据库迁移版本低于升级前记录，停止回滚"
  expected_steps="$(schema_migrations_above "$pg_container" "$SCHEMA_BEFORE")"
  [[ "$expected_steps" =~ ^[0-9]+$ ]] || die "无法统计待回退迁移数量，停止回滚"
  max_steps=$((expected_steps + 1))
  (( max_steps > 200 )) && max_steps=200
  steps_done=0
  while (( current_schema > SCHEMA_BEFORE )); do
    (( steps_done < max_steps )) || die "数据库迁移回退步数超过安全上限（${max_steps}），停止回滚"
    docker run --rm --network "container:$pg_container" --env-file "$JZ_ENV_FILE" \
      -e POSTGRES_HOST=127.0.0.1 -e POSTGRES_PORT=5432 -e MIGRATIONS_DIR=/app/migrations \
      --entrypoint /usr/local/bin/jiuzhang-api "$NEW_SERVER_IMAGE_ID" migrate down >/dev/null \
      || die "数据库迁移回退失败，保留当前容器供诊断；可使用备份 $BACKUP_JOB_ID 恢复"
    steps_done=$((steps_done + 1))
    next_schema="$(schema_version "$pg_container")"
    [[ "$next_schema" =~ ^[0-9]+$ ]] || die "无法读取回退后数据库迁移版本"
    (( next_schema < current_schema )) || die "数据库迁移版本未递减（仍为 ${next_schema}），停止回滚"
    current_schema="$next_schema"
  done
  [[ "$current_schema" == "$SCHEMA_BEFORE" ]] || die "数据库迁移版本未恢复到升级前记录"
fi

if [[ "$ROLLBACK_TO_PREVIOUS_RELEASE" == true ]]; then
  # 完整升级回滚：使用原 release 的 Compose 与旧镜像标签恢复，绝不覆盖/污染新版本镜像标签
  for i in "${!SERVICES[@]}"; do
    [[ -z "${OLD_IDS[$i]}" || -z "${OLD_IMAGES[$i]}" ]] || {
      cur_old_id="$(docker image inspect "${OLD_IMAGES[$i]}" --format '{{.Id}}' 2>/dev/null || true)"
      [[ "$cur_old_id" == "${OLD_IDS[$i]}" ]] || docker tag "${OLD_IDS[$i]}" "${OLD_IMAGES[$i]}"
    }
  done
  if ((${#REMOVE_SERVICES[@]} > 0)); then
    docker compose -f "$NEW_COMPOSE_FOR_CLEANUP" --env-file "$NEW_ENV_FOR_CLEANUP" rm -sf "${REMOVE_SERVICES[@]}" >/dev/null 2>&1 || true
  fi
else
  for i in "${!SERVICES[@]}"; do
    [[ -z "${OLD_IDS[$i]}" ]] || docker tag "${OLD_IDS[$i]}" "${TARGET_IMAGES[$i]}"
  done
  ((${#REMOVE_SERVICES[@]} == 0)) || compose rm -sf "${REMOVE_SERVICES[@]}" >/dev/null 2>&1 || true
fi
restore_sidecars_permissions_for_legacy_netmgrd
restore_gateway_rules_symlink_if_needed
log_info "重建原组件: ${EXISTING_SERVICES[*]}"
compose rm -sf "${EXISTING_SERVICES[@]}" >/dev/null 2>&1 || true
compose up -d --no-deps --force-recreate "${EXISTING_SERVICES[@]}" || die "原容器重建失败"
if ((${#API_EXTRA_NETWORKS[@]} > 0)); then
  RESTORED_API_ID="$(compose ps -q api 2>/dev/null || true)"
  reattach_api_extra_networks "$RESTORED_API_ID" rollback "${API_EXTRA_NETWORKS[@]}" \
    || die "回滚后恢复 api 附加网络失败"
fi
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
      mirrorcap) timeout 8 docker exec "$id" /usr/local/bin/mirrorcap --healthcheck || { ready=false; break; } ;;
      tproxyd) timeout 8 docker exec "$id" /usr/local/bin/tproxyd --healthcheck || { ready=false; break; } ;;
      havipd) timeout 8 docker exec "$id" /usr/local/bin/havipd --healthcheck || { ready=false; break; } ;;
      hasyncd) timeout 8 docker exec "$id" /usr/local/bin/hasyncd --healthcheck || { ready=false; break; } ;;
    esac
  done
  [[ "$ready" == true ]] && curl -fsS --max-time 5 "$JZ_API_BASE/api/v1/health" >/dev/null 2>&1 && break
  sleep 2
done
[[ "$ready" == true ]] || die "回滚后容器或 HTTP 健康检查未通过"
wait_http_ok "$JZ_API_BASE/api/v1/health" "$TIMEOUT" || die "回滚后管理 API 未就绪"
if [[ -n "$OLD_INSTALL_ROOT" ]]; then
  if [[ -f "$OLD_INSTALL_ROOT/ops/install/install-hostctl.sh" ]]; then
    bash "$OLD_INSTALL_ROOT/ops/install/install-hostctl.sh" --install-root "$OLD_INSTALL_ROOT" --strict \
      || die "hostctl 尚未恢复原 release 路径"
  elif [[ -f "$SCRIPT_DIR/../install/install-hostctl.sh" ]]; then
    bash "$SCRIPT_DIR/../install/install-hostctl.sh" --install-root "$OLD_INSTALL_ROOT" --strict \
      || die "hostctl 尚未恢复原 release 路径"
  fi
fi
if [[ "$FULL_UPGRADE" == true && -n "$OLD_INSTALL_ROOT" ]]; then
  [[ -f "$OLD_INSTALL_ROOT/ops/upgrade/install-executor.sh" ]] \
    || die "原 release 缺少升级执行器安装脚本: $OLD_INSTALL_ROOT/ops/upgrade/install-executor.sh"
  old_exec_env="$OLD_INSTALL_ROOT/.env"
  [[ -f "$old_exec_env" ]] || old_exec_env="$JZ_ENV_FILE"
  bash "$OLD_INSTALL_ROOT/ops/upgrade/install-executor.sh" --compose-file "$PREVIOUS_COMPOSE_FILE" \
    --env-file "$old_exec_env" --api-url "$JZ_API_BASE" \
    || die "升级执行器尚未恢复原 release 配置"
fi
switch_current

if [[ "$RESTORE_BACKUP" == true ]]; then
  [[ -n "$BACKUP_JOB_ID" ]] || die "无升级前备份任务 ID"
  log_warn "恢复 FULL 备份将覆盖范围内现有数据"
  "$SCRIPT_DIR/../restore/restore.sh" --backup-id "$BACKUP_JOB_ID" --scope FULL \
    --user "$USER" --api-url "$JZ_API_BASE" --yes
fi
# 标记并归档回滚状态文件，避免外层 update-full.sh EXIT trap 触发二次回滚
if [[ -f "$STATE_FILE" ]]; then
  mv -f "$STATE_FILE" "${STATE_FILE}.rolled-back.$(date -u '+%Y%m%dT%H%M%SZ')"
fi
log_info "回滚完成；原镜像、迁移版本和实际服务已复核"
