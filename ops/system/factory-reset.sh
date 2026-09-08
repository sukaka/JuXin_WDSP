#!/usr/bin/env bash
# factory-reset.sh —— 恢复出厂：回到初始安装状态。
#
# 【危险操作：清空全部数据】包括数据库（postgres-data）、缓存（valkey-data）、
# runtime 命名卷、仓库根 runtime/ 下全部数据子目录（备份/证书/配置/日志/报告/
# 授权 license 等）。执行后系统回到首次安装完成前的状态，需重新初始化。
# 正常入口为管理控制台「系统运维 → 系统控制」经 hostctl 标志文件触发
# （ops/system/hostctl-exec.sh 调用本脚本）；手工执行前请确认已备份。
#
# 流程：定位 compose 项目 → docker compose down -v → 清空 runtime 数据子目录
# （保留 runtime/hostctl/ 本身，避免删掉正在处理的标志文件导致 systemd 误触发；
# 保留 runtime/geoip/ 部署资产）→ docker compose up -d → 等待 api 健康。
#
# 用法: factory-reset.sh [--yes]
# 环境变量:
#   JZ_INSTALL_ROOT     安装根目录（默认取仓库根，参照 ops/install/install.sh 的推断）
#   JZ_COMPOSE_FILE     docker compose 文件（默认 <安装根>/docker-compose.yml）
#   JZ_ENV_FILE         环境变量文件（默认 <安装根>/.env）
#   JZ_API_BASE         管理 API 地址（默认 http://127.0.0.1:18081）
#   JZ_HEALTH_TIMEOUT   api 健康等待超时秒数（默认 180）
# 退出码: 0=成功 1=失败 2=用法错误
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes|-y) JZ_ASSUME_YES=true; shift ;;
    -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
    *) log_err "未知参数: $1"; exit 2 ;;
  esac
done

INSTALL_ROOT="${JZ_INSTALL_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
JZ_COMPOSE_FILE="${JZ_COMPOSE_FILE:-$INSTALL_ROOT/docker-compose.yml}"
JZ_ENV_FILE="${JZ_ENV_FILE:-$INSTALL_ROOT/.env}"
HEALTH_TIMEOUT="${JZ_HEALTH_TIMEOUT:-180}"
[[ "$HEALTH_TIMEOUT" =~ ^[0-9]+$ ]] || die "JZ_HEALTH_TIMEOUT 必须为整数: $HEALTH_TIMEOUT" 2

[[ -d "$INSTALL_ROOT" ]] || die "安装根目录不存在: $INSTALL_ROOT"
[[ -f "$JZ_COMPOSE_FILE" ]] || die "compose 文件不存在: $JZ_COMPOSE_FILE"
[[ -f "$JZ_ENV_FILE" ]] || die "环境文件不存在: ${JZ_ENV_FILE}（系统是否已安装？）"
require_cmd docker
require_cmd curl
docker compose version >/dev/null 2>&1 || die "缺少 docker compose 插件"

log_warn "危险操作：恢复出厂将清空全部数据（数据库/缓存/配置/备份/日志/授权），不可恢复"
confirm "确认恢复出厂并清空全部数据？" || { log_info "已取消"; exit 0; }

cd "$INSTALL_ROOT"

# ---------- 1. 停止并删除命名卷 ----------
log_info "步骤 1/4：docker compose down -v（删除 postgres-data/valkey-data/runtime 等命名卷）"
compose down -v || die "compose down -v 失败，请检查 docker 状态后重试"

# ---------- 2. 清空 runtime 数据子目录 ----------
# 保留 runtime/hostctl/：当前执行的标志文件（.done）在其中，删除目录会导致
# systemd path 单元状态异常；恢复出厂后该目录由容器继续写入。
# 保留 runtime/geoip/：GeoIP 数据库属部署资产而非业务数据，清除会破坏安装。
log_info "步骤 2/4：清空 $INSTALL_ROOT/runtime/ 数据子目录（保留 hostctl/ 与 geoip/）"
RUNTIME_DIR="$INSTALL_ROOT/runtime"
if [[ -d "$RUNTIME_DIR" ]]; then
  shopt -s nullglob dotglob
  for entry in "$RUNTIME_DIR"/*; do
    name="$(basename "$entry")"
    case "$name" in
      hostctl|geoip) log_info "保留 $entry" ;;
      *) rm -rf "$entry" ;;
    esac
  done
  shopt -u nullglob dotglob
else
  log_warn "runtime 目录不存在: ${RUNTIME_DIR}，跳过清理"
fi

# ---------- 3. 重新启动 ----------
log_info "步骤 3/4：docker compose up -d（数据库迁移随服务启动执行）"
compose up -d || die "compose up -d 失败，请用 ops/diagnostics/collect.sh 收集诊断信息"

# ---------- 4. 等待 api 健康 ----------
log_info "步骤 4/4：等待管理 API 健康（最长 ${HEALTH_TIMEOUT}s）..."
wait_http_ok "$JZ_API_BASE/api/v1/health" "$HEALTH_TIMEOUT" \
  || die "管理 API 启动超时，请用 ops/diagnostics/collect.sh 收集诊断信息"

logger -t jiuzhang-hostctl -- "factory_reset completed install_root=$INSTALL_ROOT"
log_info "恢复出厂完成：全部数据已清空，系统已回到初始安装状态（三权账号需重新初始化）"
