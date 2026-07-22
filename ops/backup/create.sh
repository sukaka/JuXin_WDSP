#!/usr/bin/env bash
# create.sh —— 调用管理 API 创建加密备份并下载到本地。
# 退出码：0=成功 1=失败 2=用法错误
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

usage() {
  cat <<'EOF'
用法: create.sh [选项]

调用管理 API 创建备份（FULL / CONFIG_ONLY），等待完成并下载 .jzbk 备份文件。

选项:
  -t, --type TYPE        备份类型 FULL|CONFIG_ONLY（默认 FULL）
  -o, --output DIR       下载目录（默认当前目录）
  -u, --user USER        管理员用户名（默认 jiuzhang_admin，或 JZ_ADMIN_USER）
      --api-url URL      管理 API 地址（默认 http://127.0.0.1:18081）
      --timeout SEC      等待备份完成秒数（默认 1800）
  -h, --help             显示帮助

环境变量:
  JZ_ADMIN_PASSWORD      管理员密码（未设置时交互读取，不回显）

退出码: 0=成功 1=失败 2=用法错误
EOF
}

BACKUP_TYPE="FULL"
OUT_DIR="."
USER="${JZ_ADMIN_USER:-jiuzhang_admin}"
TIMEOUT=1800
while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--type)   BACKUP_TYPE="$2"; shift 2 ;;
    -o|--output) OUT_DIR="$2"; shift 2 ;;
    -u|--user)   USER="$2"; shift 2 ;;
    --api-url)   JZ_API_BASE="$2"; shift 2 ;;
    --timeout)   TIMEOUT="$2"; shift 2 ;;
    -h|--help)   usage; exit 0 ;;
    *) log_err "未知参数: $1"; usage; exit 2 ;;
  esac
done

[[ "$BACKUP_TYPE" == "FULL" || "$BACKUP_TYPE" == "CONFIG_ONLY" ]] || { log_err "无效备份类型: $BACKUP_TYPE"; exit 2; }
[[ "$TIMEOUT" =~ ^[0-9]+$ ]] || { log_err "--timeout 必须为整数"; exit 2; }
[[ -d "$OUT_DIR" ]] || die "输出目录不存在: $OUT_DIR"
require_cmd curl
require_cmd jq

trap api_cleanup EXIT
api_login "$USER"

# ---- 创建备份任务 ----
resp="$(api_req POST /api/v1/backups "{\"backup_type\":\"$BACKUP_TYPE\"}")"
[[ "$(api_code "$resp")" == "SUCCESS" ]] || die "创建备份失败: $(printf '%s' "$resp" | jq -r '.message // "未知错误"')"
JOB_ID="$(printf '%s' "$resp" | jq -r '.data.job.id // empty')"
[[ -n "$JOB_ID" ]] || die "响应中无备份任务ID"
log_info "备份任务已创建: ${JOB_ID}（类型 ${BACKUP_TYPE}）"

# ---- 等待完成 ----
elapsed=0
while :; do
  resp="$(api_req GET "/api/v1/backups/$JOB_ID")"
  [[ "$(api_code "$resp")" == "SUCCESS" ]] || die "查询备份任务失败"
  status="$(printf '%s' "$resp" | jq -r '.data.job.status // empty')"
  case "$status" in
    SUCCESS)
      verified="$(printf '%s' "$resp" | jq -r '.data.job.verified // false')"
      [[ "$verified" == "true" ]] || die "备份成功但未通过完整性验证"
      log_info "备份完成且已验证"
      break
      ;;
    FAILED|CANCELLED)
      msg="$(printf '%s' "$resp" | jq -r '.data.job.failure_message // empty')"
      die "备份任务失败（${status}）: $msg"
      ;;
  esac
  if (( elapsed >= TIMEOUT )); then
    die "等待备份完成超时（${TIMEOUT}s，任务ID ${JOB_ID}）"
  fi
  sleep 5
  elapsed=$((elapsed + 5))
done

# ---- 下载 ----
out_file="$OUT_DIR/backup-$JOB_ID.jzbk"
api_download "/api/v1/backups/$JOB_ID/download" "$out_file" || die "下载备份文件失败"
size="$(stat -f%z "$out_file" 2>/dev/null || stat -c%s "$out_file")"
[[ "$size" -gt 0 ]] || die "下载文件为空"
log_info "备份文件已下载: ${out_file}（${size} 字节）"
log_warn "请妥善保管备份文件与主密钥（JIUZHANG_MASTER_KEY），二者缺一无法恢复"
