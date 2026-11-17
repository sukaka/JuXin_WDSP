#!/usr/bin/env bash
# rollback.sh —— 升级回滚：恢复旧镜像 + （可选）恢复升级前备份。
# 退出码：0=成功 1=失败 2=用法错误 3=用户取消
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

STATE_FILE="$SCRIPT_DIR/.upgrade-state.env"
GATEWAY_OVERRIDE=""

usage() {
  cat <<'EOF'
用法: rollback.sh [选项]

升级回滚流程：
  1. 读取 ops/upgrade/.upgrade-state.env（apply.sh 生成的回滚状态）
  2. 将目标 compose 服务镜像 retag 回升级前镜像并重启
  3. 等待健康检查
  4. （可选，--restore-backup）经 API 恢复升级前备份（validate→create→confirm）

选项:
      --restore-backup     镜像回退后同时恢复升级前备份（数据回滚，高风险）
  -u, --user USER          管理员用户名（默认 jiuzhang_admin）
      --api-url URL        管理 API 地址（默认 http://127.0.0.1:18081）
  -c, --compose-file FILE  目标 docker compose 文件（默认复用状态文件记录）
  -e, --env-file FILE      目标环境变量文件（默认复用状态文件记录）
      --timeout SEC        等待超时（默认 600）
  -y, --yes                跳过交互确认
  -h, --help               显示帮助

环境变量:
  JZ_ADMIN_PASSWORD        管理员密码（--restore-backup 时需要）

退出码: 0=成功 1=失败 2=用法错误 3=用户取消
EOF
}

render_compose() {
  docker compose -f "$1" --env-file "$2" config --format json 2>/dev/null
}

compose_service_image() {
  jq -er --arg service "$2" \
    '.services[$service].image | select(type == "string" and length > 0)' <<<"$1"
}

image_entrypoint() {
  local raw
  raw="$(docker image inspect "$1" --format '{{json .Config.Entrypoint}}' 2>/dev/null)" || return 1
  jq -er 'if type == "array" and length == 1 and (.[0] | type == "string") then .[0] else empty end' <<<"$raw"
}

assert_bind_gateway_compose() {
  jq -e '
    .services.gateway as $gateway |
    ($gateway.user == "0:0") and
    ($gateway.entrypoint == null or $gateway.entrypoint == ["/usr/local/bin/wdsp-gateway-bind"]) and
    ($gateway.cap_drop == ["ALL"]) and
    (($gateway.cap_add // []) | sort == (["NET_BIND_SERVICE", "SETUID", "SETGID", "SETPCAP"] | sort)) and
    ((($gateway.security_opt // []) | type) == "array") and
    (($gateway.security_opt // []) | index("no-new-privileges:true") != null)
  ' <<<"$1" >/dev/null
}

legacy_gateway_compose_is_safe() {
  jq -e '
    .services.gateway as $gateway |
    ($gateway.user == null or $gateway.user == "1000:1000" or $gateway.user == "caddy" or $gateway.user == "caddy:caddy") and
    ($gateway.entrypoint == null or $gateway.entrypoint == ["/usr/local/bin/docker-entrypoint.sh"]) and
    ($gateway.cap_add == null or $gateway.cap_add == ["NET_BIND_SERVICE"]) and
    ($gateway.cap_drop == null or $gateway.cap_drop == ["ALL"])
  ' <<<"$1" >/dev/null
}

assert_legacy_gateway_override() {
  jq -e '
    .services.gateway as $gateway |
    ($gateway.entrypoint == ["/usr/local/bin/docker-entrypoint.sh"]) and
    ($gateway.user == "1000:1000") and
    ($gateway.cap_add == ["NET_BIND_SERVICE"]) and
    ($gateway.cap_drop == ["ALL"]) and
    ((($gateway.security_opt // []) | type) == "array") and
    (($gateway.security_opt // []) | index("no-new-privileges:true") != null)
  ' <<<"$1" >/dev/null
}

legacy_reset_values_were_ignored() {
  jq -e '
    .services.gateway as $gateway |
    ($gateway.entrypoint == ["/usr/local/bin/docker-entrypoint.sh"]) and
    ($gateway.user == "1000:1000") and
    (($gateway | has("cap_add")) | not) and
    (($gateway | has("cap_drop")) | not) and
    ((($gateway.security_opt // []) | type) == "array") and
    (($gateway.security_opt // []) | index("no-new-privileges:true") != null)
  ' <<<"$1" >/dev/null
}

cleanup_gateway_override() {
  if [[ -n "$GATEWAY_OVERRIDE" ]]; then
    rm -f -- "$GATEWAY_OVERRIDE"
    GATEWAY_OVERRIDE=""
  fi
  if [[ -n "${GATEWAY_VALUE_OVERRIDE:-}" ]]; then
    rm -f -- "$GATEWAY_VALUE_OVERRIDE"
    GATEWAY_VALUE_OVERRIDE=""
  fi
}

compose() {
  local args=(-f "$JZ_COMPOSE_FILE")
  [[ -z "$GATEWAY_OVERRIDE" ]] || args+=(-f "$GATEWAY_OVERRIDE")
  [[ -z "${GATEWAY_VALUE_OVERRIDE:-}" ]] || args+=(-f "$GATEWAY_VALUE_OVERRIDE")
  docker compose "${args[@]}" --env-file "$JZ_ENV_FILE" "$@"
}

RESTORE_BACKUP=false
COMPOSE_FILE_EXPLICIT=false
ENV_FILE_EXPLICIT=false
USER="${JZ_ADMIN_USER:-jiuzhang_admin}"
TIMEOUT=600
while [[ $# -gt 0 ]]; do
  case "$1" in
    --restore-backup) RESTORE_BACKUP=true; shift ;;
    -u|--user)        USER="$2"; shift 2 ;;
    --api-url)        JZ_API_BASE="$2"; shift 2 ;;
    -c|--compose-file) JZ_COMPOSE_FILE="$2"; COMPOSE_FILE_EXPLICIT=true; shift 2 ;;
    -e|--env-file)   JZ_ENV_FILE="$2"; ENV_FILE_EXPLICIT=true; shift 2 ;;
    --timeout)        TIMEOUT="$2"; shift 2 ;;
    -y|--yes)         JZ_ASSUME_YES="true"; shift ;;
    -h|--help)        usage; exit 0 ;;
    *) log_err "未知参数: $1"; usage; exit 2 ;;
  esac
done

[[ -f "$STATE_FILE" ]] || die "回滚状态文件不存在: ${STATE_FILE}（无升级记录或已被清理）"
require_cmd docker
require_cmd jq
require_cmd mktemp

# shellcheck disable=SC1090
OLD_SERVER_IMAGE=""; OLD_GATEWAY_IMAGE=""; NEW_SERVER_IMAGE=""; NEW_GATEWAY_IMAGE=""; BACKUP_JOB_ID=""
OLD_SERVER_IMAGE_ID=""; OLD_GATEWAY_IMAGE_ID=""; TARGET_COMPOSE_FILE=""; TARGET_ENV_FILE=""
load_env_file "$STATE_FILE"
[[ -n "$OLD_SERVER_IMAGE" && -n "$OLD_GATEWAY_IMAGE" ]] || die "回滚状态文件缺少旧镜像信息"
[[ -n "$BACKUP_JOB_ID" ]] || log_warn "回滚状态文件无备份任务ID（数据恢复将不可用）"
if [[ "$COMPOSE_FILE_EXPLICIT" == false && -n "$TARGET_COMPOSE_FILE" ]]; then
  JZ_COMPOSE_FILE="$TARGET_COMPOSE_FILE"
fi
if [[ "$ENV_FILE_EXPLICIT" == false && -n "$TARGET_ENV_FILE" ]]; then
  JZ_ENV_FILE="$TARGET_ENV_FILE"
fi

log_info "回滚镜像: api=$OLD_SERVER_IMAGE gateway=$OLD_GATEWAY_IMAGE"
confirm "确认回滚镜像并重启 api/gateway/netmgrd？" || { log_warn "已取消"; exit 3; }

TARGET_COMPOSE_JSON="$(render_compose "$JZ_COMPOSE_FILE" "$JZ_ENV_FILE")" \
  || die "无法渲染目标 compose 配置: $JZ_COMPOSE_FILE"
CUR_SERVER_IMAGE="$(compose_service_image "$TARGET_COMPOSE_JSON" api)" || die "无法从目标 compose 解析 api 镜像名"
CUR_GATEWAY_IMAGE="$(compose_service_image "$TARGET_COMPOSE_JSON" gateway)" || die "无法从目标 compose 解析 gateway 镜像名"

# 旧镜像必须仍在本机（apply.sh retag 后原镜像 ID 保留）
[[ -n "$OLD_SERVER_IMAGE_ID" && -n "$OLD_GATEWAY_IMAGE_ID" ]] || \
  die "回滚状态文件缺少旧镜像 ID（无法安全回滚，请手工恢复旧版本镜像）"
if ! docker image inspect "$OLD_SERVER_IMAGE_ID" >/dev/null 2>&1; then
  die "旧镜像已被清理: ${OLD_SERVER_IMAGE_ID}（请重新加载旧版本镜像后重试）"
fi
if ! docker image inspect "$OLD_GATEWAY_IMAGE_ID" >/dev/null 2>&1; then
  die "旧镜像已被清理: $OLD_GATEWAY_IMAGE_ID"
fi

# 旧镜像的入口以 ID 对应镜像的实际配置为准，不能根据新旧标签或版本号猜测。
OLD_GATEWAY_ENTRYPOINT="$(image_entrypoint "$OLD_GATEWAY_IMAGE_ID")" \
  || die "无法读取旧 gateway 镜像 ID 的实际 Config.Entrypoint: $OLD_GATEWAY_IMAGE_ID"
case "$OLD_GATEWAY_ENTRYPOINT" in
  /usr/local/bin/wdsp-gateway-bind)
    assert_bind_gateway_compose "$TARGET_COMPOSE_JSON" \
      || die "回滚目标仍是新 gateway 启动器，旧 Compose 不符合新运行契约；禁止 retag/up"
    ;;
  /usr/local/bin/docker-entrypoint.sh)
    if ! legacy_gateway_compose_is_safe "$TARGET_COMPOSE_JSON"; then
      GATEWAY_OVERRIDE="$(mktemp "${TMPDIR:-/tmp}/jz-gateway-legacy.XXXXXX.yml")" \
        || die "无法创建 legacy gateway 一次性 Compose override"
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
      MERGED_COMPOSE_JSON="$(compose config --format json 2>/dev/null)" \
        || die "无法渲染 legacy gateway 一次性 Compose override"
      if ! assert_legacy_gateway_override "$MERGED_COMPOSE_JSON"; then
        # 部分 Compose 版本按 !reset 原义忽略列表值；仅对这种已核验形态追加临时补值层。
        legacy_reset_values_were_ignored "$MERGED_COMPOSE_JSON" \
          || die "legacy gateway override 渲染结果不符合精确契约（原入口、1000:1000、仅 NET_BIND_SERVICE、cap_drop ALL、保留 no-new-privileges）；禁止 retag/up"
        GATEWAY_VALUE_OVERRIDE="$(mktemp "${TMPDIR:-/tmp}/jz-gateway-legacy-values.XXXXXX.yml")" \
          || die "无法创建 legacy gateway capability 临时补值层"
        chmod 600 "$GATEWAY_VALUE_OVERRIDE"
        cat > "$GATEWAY_VALUE_OVERRIDE" <<'EOF'
services:
  gateway:
    cap_add: ["NET_BIND_SERVICE"]
    cap_drop: ["ALL"]
EOF
        MERGED_COMPOSE_JSON="$(compose config --format json 2>/dev/null)" \
          || die "无法渲染 legacy gateway capability 临时补值层"
        assert_legacy_gateway_override "$MERGED_COMPOSE_JSON" \
          || die "legacy gateway 最终渲染结果不符合精确契约；禁止 retag/up"
      fi
    fi
    ;;
  *) die "拒绝回滚到未知 gateway 镜像入口: $OLD_GATEWAY_ENTRYPOINT" ;;
esac

# 所有镜像与渲染门禁通过后才可以 retag；用户 Compose 文件始终不变。
docker tag "$OLD_SERVER_IMAGE_ID" "$CUR_SERVER_IMAGE"
docker tag "$OLD_GATEWAY_IMAGE_ID" "$CUR_GATEWAY_IMAGE"

# netmgrd 共用 gateway 网络命名空间，回滚时也必须随 gateway 重建。
log_info "重启 api/gateway/netmgrd ..."
compose up -d --no-deps --force-recreate api gateway netmgrd
cleanup_gateway_override
trap - EXIT
log_info "等待管理 API 健康（超时 ${TIMEOUT}s）..."
wait_http_ok "$JZ_API_BASE/api/v1/health" "$TIMEOUT" || die "回滚后管理 API 未就绪，请检查容器日志"

if [[ "$RESTORE_BACKUP" == "true" ]]; then
  [[ -n "$BACKUP_JOB_ID" ]] || die "无升级前备份任务ID，无法执行数据回滚"
  log_warn "即将恢复升级前备份 ${BACKUP_JOB_ID}（覆盖范围内生产数据）"
  extra_args=()
  [[ "$JZ_ASSUME_YES" == "true" ]] && extra_args+=(--yes)
  "$SCRIPT_DIR/../restore/restore.sh" --backup-id "$BACKUP_JOB_ID" --scope FULL \
    --user "$USER" --api-url "$JZ_API_BASE" "${extra_args[@]}"
fi

log_info "回滚完成"
