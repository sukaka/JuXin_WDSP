#!/usr/bin/env bash
# rollback.sh —— 升级回滚：恢复旧镜像 + （可选）恢复升级前备份。
# 退出码：0=成功 1=失败 2=用法错误 3=用户取消
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

STATE_FILE="$SCRIPT_DIR/.upgrade-state.env"

usage() {
  cat <<'EOF'
用法: rollback.sh [选项]

升级回滚流程：
  1. 读取 ops/upgrade/.upgrade-state.env（apply.sh 生成的回滚状态）
  2. 将 compose 服务镜像 retag 回升级前镜像并重启
  3. 等待健康检查
  4. （可选，--restore-backup）经 API 恢复升级前备份（validate→create→confirm）

选项:
      --restore-backup     镜像回退后同时恢复升级前备份（数据回滚，高风险）
  -u, --user USER          管理员用户名（默认 jiuzhang_admin）
      --api-url URL        管理 API 地址（默认 http://127.0.0.1:18081）
  -c, --compose-file FILE  docker compose 文件（默认 docker-compose.yml）
  -e, --env-file FILE      环境变量文件（默认 .env）
      --timeout SEC        等待超时（默认 600）
  -y, --yes                跳过交互确认
  -h, --help               显示帮助

环境变量:
  JZ_ADMIN_PASSWORD        管理员密码（--restore-backup 时需要）

退出码: 0=成功 1=失败 2=用法错误 3=用户取消
EOF
}

RESTORE_BACKUP=false
USER="${JZ_ADMIN_USER:-jiuzhang_admin}"
TIMEOUT=600
while [[ $# -gt 0 ]]; do
  case "$1" in
    --restore-backup) RESTORE_BACKUP=true; shift ;;
    -u|--user)        USER="$2"; shift 2 ;;
    --api-url)        JZ_API_BASE="$2"; shift 2 ;;
    -c|--compose-file) JZ_COMPOSE_FILE="$2"; shift 2 ;;
    -e|--env-file)    JZ_ENV_FILE="$2"; shift 2 ;;
    --timeout)        TIMEOUT="$2"; shift 2 ;;
    -y|--yes)         JZ_ASSUME_YES="true"; shift ;;
    -h|--help)        usage; exit 0 ;;
    *) log_err "未知参数: $1"; usage; exit 2 ;;
  esac
done

[[ -f "$STATE_FILE" ]] || die "回滚状态文件不存在: ${STATE_FILE}（无升级记录或已被清理）"
require_cmd docker

# shellcheck disable=SC1090
OLD_SERVER_IMAGE=""; OLD_GATEWAY_IMAGE=""; NEW_SERVER_IMAGE=""; NEW_GATEWAY_IMAGE=""; BACKUP_JOB_ID=""
load_env_file "$STATE_FILE"
[[ -n "$OLD_SERVER_IMAGE" && -n "$OLD_GATEWAY_IMAGE" ]] || die "回滚状态文件缺少旧镜像信息"
[[ -n "$BACKUP_JOB_ID" ]] || log_warn "回滚状态文件无备份任务ID（数据恢复将不可用）"

log_info "回滚镜像: api=$OLD_SERVER_IMAGE gateway=$OLD_GATEWAY_IMAGE"
confirm "确认回滚镜像并重启 api/gateway？" || { log_warn "已取消"; exit 3; }

# 旧镜像必须仍在本机（apply.sh retag 后原镜像 ID 保留）
CUR_SERVER_IMAGE="$(docker compose -f "$JZ_COMPOSE_FILE" --env-file "$JZ_ENV_FILE" config 2>/dev/null | awk '/^  api:/{f=1} f && /^    image:/{print $2; exit}')"
CUR_GATEWAY_IMAGE="$(docker compose -f "$JZ_COMPOSE_FILE" --env-file "$JZ_ENV_FILE" config 2>/dev/null | awk '/^  gateway:/{f=1} f && /^    image:/{print $2; exit}')"
[[ -n "$CUR_SERVER_IMAGE" && -n "$CUR_GATEWAY_IMAGE" ]] || die "无法从 compose 配置解析当前镜像名"

# retag 回旧镜像：升级时 retag 覆盖了 compose 镜像名，旧镜像以 ID 留存，
# 必须用状态文件中的镜像 ID 恢复标签。
[[ -n "${OLD_SERVER_IMAGE_ID:-}" && -n "${OLD_GATEWAY_IMAGE_ID:-}" ]] || \
  die "回滚状态文件缺少旧镜像 ID（无法安全回滚，请手工恢复旧版本镜像）"
if ! docker image inspect "$OLD_SERVER_IMAGE_ID" >/dev/null 2>&1; then
  die "旧镜像已被清理: ${OLD_SERVER_IMAGE_ID}（请重新加载旧版本镜像后重试）"
fi
if ! docker image inspect "$OLD_GATEWAY_IMAGE_ID" >/dev/null 2>&1; then
  die "旧镜像已被清理: $OLD_GATEWAY_IMAGE_ID"
fi
docker tag "$OLD_SERVER_IMAGE_ID" "$CUR_SERVER_IMAGE"
docker tag "$OLD_GATEWAY_IMAGE_ID" "$CUR_GATEWAY_IMAGE"

log_info "重启 api/gateway ..."
compose up -d --no-deps api gateway
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
