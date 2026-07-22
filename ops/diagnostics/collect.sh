#!/usr/bin/env bash
# collect.sh —— 诊断信息收集：版本/配置（脱敏）/容器状态/最近日志/磁盘，打包输出。
# 退出码：0=成功 1=失败 2=用法错误
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

usage() {
  cat <<'EOF'
用法: collect.sh [选项]

收集诊断信息并打包为 dist/diagnostics-YYYYMMDD-HHMMSS.tar.gz。
收集内容：系统与组件版本、脱敏后的环境配置、compose 容器状态、
各服务最近日志（默认 500 行）、管理 API 健康、磁盘占用。

选项:
  -o, --output DIR       输出目录（默认 <仓库>/dist）
  -c, --compose-file FILE docker compose 文件（默认 docker-compose.yml）
  -e, --env-file FILE    环境变量文件（默认 .env）
      --api-url URL      管理 API 地址（默认 http://127.0.0.1:18081）
      --log-lines N      每服务日志行数（默认 500）
  -h, --help             显示帮助

说明: 配置中 PASSWORD/SECRET/KEY/TOKEN 类敏感值一律脱敏为 ********。
退出码: 0=成功 1=失败 2=用法错误
EOF
}

REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUT_DIR="$REPO_ROOT/dist"
LOG_LINES=500
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|--output)       OUT_DIR="$2"; shift 2 ;;
    -c|--compose-file) JZ_COMPOSE_FILE="$2"; shift 2 ;;
    -e|--env-file)     JZ_ENV_FILE="$2"; shift 2 ;;
    --api-url)         JZ_API_BASE="$2"; shift 2 ;;
    --log-lines)       LOG_LINES="$2"; shift 2 ;;
    -h|--help)         usage; exit 0 ;;
    *) log_err "未知参数: $1"; usage; exit 2 ;;
  esac
done

[[ "$LOG_LINES" =~ ^[0-9]+$ ]] || { log_err "--log-lines 必须为整数"; exit 2; }
require_cmd tar
require_cmd curl

ts="$(date '+%Y%m%d-%H%M%S')"
work="$(mktemp -d "${TMPDIR:-/tmp}/jzdiag.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$OUT_DIR"

log_info "收集诊断信息到临时目录 $work"

# ---- 版本信息 ----
{
  echo "== 采集时间: $(date -u '+%Y-%m-%dT%H:%M:%SZ') =="
  echo "-- uname: $(uname -a)"
  if command -v docker >/dev/null 2>&1; then
    echo "-- docker: $(docker --version 2>/dev/null || echo 不可用)"
    docker compose version 2>/dev/null | sed 's/^/-- compose: /' || true
  fi
  if [[ -f "$REPO_ROOT/CHANGELOG.md" ]]; then
    echo "-- CHANGELOG 头部:"
    head -20 "$REPO_ROOT/CHANGELOG.md"
  fi
  if [[ -f "$REPO_ROOT/docs/DEPENDENCIES.md" ]]; then
    echo "-- 锁定依赖清单见 docs/DEPENDENCIES.md（随包附带）"
    cp "$REPO_ROOT/docs/DEPENDENCIES.md" "$work/DEPENDENCIES.md" 2>/dev/null || true
  fi
} > "$work/versions.txt"

# ---- 脱敏配置 ----
if [[ -f "$JZ_ENV_FILE" ]]; then
  sed -E 's/^([A-Za-z_][A-Za-z0-9_]*(PASSWORD|SECRET|KEY|TOKEN)[A-Za-z0-9_]*)=.*/\1=********/I' \
    "$JZ_ENV_FILE" > "$work/env.sanitized.txt"
  log_info "环境配置已脱敏（PASSWORD/SECRET/KEY/TOKEN → ********）"
else
  log_warn "环境文件 $JZ_ENV_FILE 不存在，跳过"
fi

# ---- 容器状态与日志 ----
if command -v docker >/dev/null 2>&1 && [[ -f "$JZ_COMPOSE_FILE" ]]; then
  if [[ -f "$JZ_ENV_FILE" ]]; then
    compose ps > "$work/compose-ps.txt" 2>&1 || true
    compose logs --no-color --tail="$LOG_LINES" > "$work/compose-logs.txt" 2>&1 || true
  else
    docker compose -f "$JZ_COMPOSE_FILE" ps > "$work/compose-ps.txt" 2>&1 || true
    docker compose -f "$JZ_COMPOSE_FILE" logs --no-color --tail="$LOG_LINES" > "$work/compose-logs.txt" 2>&1 || true
  fi
  docker ps -a --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}' > "$work/docker-ps.txt" 2>&1 || true
else
  log_warn "docker 或 compose 文件不可用，跳过容器信息"
fi

# ---- API 健康 ----
curl -sS --max-time 5 "$JZ_API_BASE/api/v1/health" > "$work/api-health.json" 2>/dev/null || \
  echo "unreachable" > "$work/api-health.json"

# ---- 磁盘 ----
{
  df -h
  echo
  docker system df 2>/dev/null || true
} > "$work/disk.txt"

out="$OUT_DIR/diagnostics-$ts.tar.gz"
tar -czf "$out" -C "$work" .
size="$(stat -f%z "$out" 2>/dev/null || stat -c%s "$out")"
log_info "诊断包已生成: ${out}（${size} 字节）"
