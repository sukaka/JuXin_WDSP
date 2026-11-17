#!/usr/bin/env bash
# apply.sh —— 升级执行：健康预检 → API 全量备份 → 镜像切换 → 等待迁移/健康 → 验证。
# 升级前必须备份（AGENTS.md 安全底线）；失败时提示使用 rollback.sh 回滚。
# 退出码：0=成功 1=失败 2=用法错误
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

STATE_FILE="$SCRIPT_DIR/.upgrade-state.env"

usage() {
  cat <<'EOF'
用法: apply.sh [选项]

升级执行流程：
  1. 预检：组件健康检查（调用 ops/healthcheck/check.sh）
  2. 备份：调用管理 API 创建 FULL 加密备份并等待验证成功
  3. 镜像切换：加载/检查新镜像，记录当前镜像（供回滚），切换 compose 服务镜像
  4. 启动并等待管理 API 健康（数据库迁移随服务启动自动执行）
  5. 升级后健康检查

选项:
      --server-image IMG    新管理后端镜像（如 jiuzhang-server:2.1.0，必填）
      --gateway-image IMG   新网关镜像（如 jiuzhang-gateway:2.1.0，必填）
      --images-tar FILE     离线镜像包（可选；存在则先 docker load）
      --new-compose-file FILE
                            目标 Compose；跨 gateway 启动契约升级时必填
  -u, --user USER           管理员用户名（默认 jiuzhang_admin）
      --api-url URL         管理 API 地址（默认 http://127.0.0.1:18081）
  -c, --compose-file FILE   当前 docker compose 文件（默认 docker-compose.yml）
  -e, --env-file FILE       当前及目标环境变量文件（默认 .env）
      --timeout SEC         各等待阶段超时（默认 600）
  -h, --help                显示帮助

环境变量:
  JZ_ADMIN_PASSWORD         管理员密码（未设置时交互读取，不回显）

说明: 镜像切换采用 retag 方式（新镜像标记为目标 compose 配置使用的镜像名），
      旧镜像引用记录到 ops/upgrade/.upgrade-state.env 供 rollback.sh 使用。
      未指定 --new-compose-file 时，当前 Compose 同时作为目标 Compose。
退出码: 0=成功 1=失败 2=用法错误
EOF
}

SERVER_IMAGE=""
GATEWAY_IMAGE=""
IMAGES_TAR=""
NEW_COMPOSE_FILE=""
USER="${JZ_ADMIN_USER:-jiuzhang_admin}"
TIMEOUT=600
while [[ $# -gt 0 ]]; do
  case "$1" in
    --server-image)  SERVER_IMAGE="$2"; shift 2 ;;
    --gateway-image) GATEWAY_IMAGE="$2"; shift 2 ;;
    --images-tar)    IMAGES_TAR="$2"; shift 2 ;;
    --new-compose-file) NEW_COMPOSE_FILE="$2"; shift 2 ;;
    -u|--user)       USER="$2"; shift 2 ;;
    --api-url)       JZ_API_BASE="$2"; shift 2 ;;
    -c|--compose-file) JZ_COMPOSE_FILE="$2"; shift 2 ;;
    -e|--env-file)   JZ_ENV_FILE="$2"; shift 2 ;;
    --timeout)       TIMEOUT="$2"; shift 2 ;;
    -h|--help)       usage; exit 0 ;;
    *) log_err "未知参数: $1"; usage; exit 2 ;;
  esac
done

[[ -n "$SERVER_IMAGE" && -n "$GATEWAY_IMAGE" ]] || { log_err "必须同时指定 --server-image 与 --gateway-image"; exit 2; }
[[ "$TIMEOUT" =~ ^[0-9]+$ ]] || { log_err "--timeout 必须为整数"; exit 2; }
require_cmd docker
require_cmd curl
require_cmd jq

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

# ---------- 1. 预检 ----------
log_info "步骤 1/5：升级前健康检查"
if [[ -x "$SCRIPT_DIR/../healthcheck/check.sh" ]]; then
  "$SCRIPT_DIR/../healthcheck/check.sh" -c "$JZ_COMPOSE_FILE" -e "$JZ_ENV_FILE" --api-url "$JZ_API_BASE" \
    || die "升级前健康检查未通过，请先处理异常项"
else
  wait_http_ok "$JZ_API_BASE/api/v1/health" 10 || die "管理 API 不可达，无法进行升级前检查"
fi

# ---------- 2. 备份（升级前必须备份） ----------
log_info "步骤 2/5：创建升级前全量备份"
trap api_cleanup EXIT
api_login "$USER"
resp="$(api_req POST /api/v1/backups '{"backup_type":"FULL"}')"
[[ "$(api_code "$resp")" == "SUCCESS" ]] || die "创建备份失败: $(printf '%s' "$resp" | jq -r '.message // "未知错误"')"
BACKUP_JOB_ID="$(printf '%s' "$resp" | jq -r '.data.job.id // empty')"
[[ -n "$BACKUP_JOB_ID" ]] || die "响应中无备份任务ID"
log_info "备份任务 $BACKUP_JOB_ID 执行中（超时 ${TIMEOUT}s）..."
elapsed=0
while :; do
  resp="$(api_req GET "/api/v1/backups/$BACKUP_JOB_ID")"
  status="$(printf '%s' "$resp" | jq -r '.data.job.status // empty')"
  verified="$(printf '%s' "$resp" | jq -r '.data.job.verified // false')"
  if [[ "$status" == "SUCCESS" && "$verified" == "true" ]]; then
    log_info "升级前备份完成且已验证"
    break
  fi
  if [[ "$status" == "FAILED" || "$status" == "CANCELLED" ]]; then
    die "升级前备份失败（${status}），已中止升级: $(printf '%s' "$resp" | jq -r '.data.job.failure_message // empty')"
  fi
  (( elapsed >= TIMEOUT )) && die "等待备份超时，已中止升级"
  sleep 5; elapsed=$((elapsed + 5))
done
api_cleanup
trap - EXIT

# ---------- 3. 镜像切换 ----------
log_info "步骤 3/5：切换镜像"
if [[ -n "$IMAGES_TAR" ]]; then
  [[ -f "$IMAGES_TAR" ]] || die "离线镜像包不存在: $IMAGES_TAR"
  log_info "加载离线镜像包 $IMAGES_TAR ..."
  docker load -i "$IMAGES_TAR" >/dev/null
fi
docker image inspect "$SERVER_IMAGE" >/dev/null 2>&1 || die "镜像不存在: ${SERVER_IMAGE}（可先 --images-tar 加载）"
docker image inspect "$GATEWAY_IMAGE" >/dev/null 2>&1 || die "镜像不存在: $GATEWAY_IMAGE"

OLD_COMPOSE_FILE="$JZ_COMPOSE_FILE"
TARGET_COMPOSE_FILE="${NEW_COMPOSE_FILE:-$OLD_COMPOSE_FILE}"
TARGET_ENV_FILE="$JZ_ENV_FILE"
OLD_COMPOSE_JSON="$(render_compose "$OLD_COMPOSE_FILE" "$JZ_ENV_FILE")" \
  || die "无法渲染当前 compose 配置: $OLD_COMPOSE_FILE"
TARGET_COMPOSE_JSON="$(render_compose "$TARGET_COMPOSE_FILE" "$TARGET_ENV_FILE")" \
  || die "无法渲染目标 compose 配置: $TARGET_COMPOSE_FILE"

# 旧镜像名和旧 ID 只能来自当前 Compose；目标 Compose 只提供升级后的 retag 标签。
OLD_SERVER_IMAGE="$(compose_service_image "$OLD_COMPOSE_JSON" api)" || die "无法从当前 compose 解析 api 镜像名"
OLD_GATEWAY_IMAGE="$(compose_service_image "$OLD_COMPOSE_JSON" gateway)" || die "无法从当前 compose 解析 gateway 镜像名"
CUR_SERVER_IMAGE="$(compose_service_image "$TARGET_COMPOSE_JSON" api)" || die "无法从目标 compose 解析 api 镜像名"
CUR_GATEWAY_IMAGE="$(compose_service_image "$TARGET_COMPOSE_JSON" gateway)" || die "无法从目标 compose 解析 gateway 镜像名"
log_info "旧镜像: api=$OLD_SERVER_IMAGE gateway=$OLD_GATEWAY_IMAGE"
log_info "目标 compose 镜像标签: api=$CUR_SERVER_IMAGE gateway=$CUR_GATEWAY_IMAGE"

OLD_SERVER_IMAGE_ID="$(docker image inspect "$OLD_SERVER_IMAGE" --format '{{.Id}}' 2>/dev/null || true)"
OLD_GATEWAY_IMAGE_ID="$(docker image inspect "$OLD_GATEWAY_IMAGE" --format '{{.Id}}' 2>/dev/null || true)"
[[ -n "$OLD_SERVER_IMAGE_ID" && -n "$OLD_GATEWAY_IMAGE_ID" ]] || die "无法获取当前镜像 ID（服务尚未启动过？）"

# 入口类型只认镜像实际 Config.Entrypoint；门禁必须先于状态写入和任何 retag/up。
GATEWAY_ENTRYPOINT="$(image_entrypoint "$GATEWAY_IMAGE")" || die "无法读取目标 gateway 镜像的实际 Config.Entrypoint"
case "$GATEWAY_ENTRYPOINT" in
  /usr/local/bin/wdsp-gateway-bind)
    assert_bind_gateway_compose "$TARGET_COMPOSE_JSON" \
      || die "新 gateway 启动器要求目标 Compose 契约：user=0:0、cap_drop=ALL、恰好 cap_add=NET_BIND_SERVICE/SETUID/SETGID/SETPCAP、no-new-privileges；请使用 --new-compose-file"
    ;;
  /usr/local/bin/docker-entrypoint.sh)
    legacy_gateway_compose_is_safe "$TARGET_COMPOSE_JSON" \
      || die "legacy gateway 镜像不能直接套用新启动器 Compose（避免旧 Caddy 以 root 常驻）；请使用旧 Compose 目标标签"
    ;;
  *) die "拒绝未知 gateway 镜像入口: $GATEWAY_ENTRYPOINT" ;;
esac

JZ_COMPOSE_FILE="$TARGET_COMPOSE_FILE"
JZ_ENV_FILE="$TARGET_ENV_FILE"

# 记录回滚状态（不含敏感信息）；rollback 默认复用目标 Compose/env。
cat > "$STATE_FILE" <<EOF
# 升级状态（ops/upgrade/apply.sh 生成于 $(date -u '+%Y-%m-%dT%H:%M:%SZ')），供 rollback.sh 使用
OLD_SERVER_IMAGE=$OLD_SERVER_IMAGE
OLD_GATEWAY_IMAGE=$OLD_GATEWAY_IMAGE
OLD_SERVER_IMAGE_ID=$OLD_SERVER_IMAGE_ID
OLD_GATEWAY_IMAGE_ID=$OLD_GATEWAY_IMAGE_ID
NEW_SERVER_IMAGE=$SERVER_IMAGE
NEW_GATEWAY_IMAGE=$GATEWAY_IMAGE
TARGET_COMPOSE_FILE=$TARGET_COMPOSE_FILE
TARGET_ENV_FILE=$TARGET_ENV_FILE
BACKUP_JOB_ID=$BACKUP_JOB_ID
UPGRADE_TIME=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
EOF
chmod 600 "$STATE_FILE"

# retag：新镜像 → 目标 compose 使用的镜像名（旧镜像 ID 保留在本机，可回滚）
docker tag "$SERVER_IMAGE" "$CUR_SERVER_IMAGE"
docker tag "$GATEWAY_IMAGE" "$CUR_GATEWAY_IMAGE"

# ---------- 4. 重启并等待健康 ----------
# netmgrd 共用 gateway 网络命名空间，必须同次重建，避免继续附着旧 gateway 容器。
log_info "步骤 4/5：重启 api/gateway/netmgrd（数据库迁移随服务启动执行）"
compose up -d --no-deps --force-recreate api gateway netmgrd
log_info "等待管理 API 健康（超时 ${TIMEOUT}s）..."
if ! wait_http_ok "$JZ_API_BASE/api/v1/health" "$TIMEOUT"; then
  log_err "升级后管理 API 未就绪"
  die "升级失败，请执行 ops/upgrade/rollback.sh 回滚（备份任务 ${BACKUP_JOB_ID}）"
fi

# ---------- 5. 升级后验证 ----------
log_info "步骤 5/5：升级后健康检查"
if [[ -x "$SCRIPT_DIR/../healthcheck/check.sh" ]]; then
  if ! "$SCRIPT_DIR/../healthcheck/check.sh" -c "$JZ_COMPOSE_FILE" -e "$JZ_ENV_FILE" --api-url "$JZ_API_BASE"; then
    die "升级后健康检查未通过，请执行 ops/upgrade/rollback.sh 回滚（备份任务 ${BACKUP_JOB_ID}）"
  fi
fi
log_info "升级完成（备份任务 ${BACKUP_JOB_ID}；如需回滚: ops/upgrade/rollback.sh）"
