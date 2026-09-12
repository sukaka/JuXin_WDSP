#!/usr/bin/env bash
# restore.sh —— 隔离恢复引导：validate → create → 等待 AWAITING_CONFIRM → 人工确认 → confirm。
# 全程逐步确认，绝不未经确认覆盖生产数据。
# 退出码：0=成功 1=失败 2=用法错误 3=用户取消
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

usage() {
  cat <<'EOF'
用法: restore.sh [选项]

隔离恢复引导（逐步人工确认）：
  1. 校验备份并输出预览（validate）
  2. 创建隔离恢复任务（create，绝不触碰正式表）
  3. 等待隔离恢复完成（AWAITING_CONFIRM）
  4. 人工确认后正式恢复（confirm，进入维护模式整组替换）

选项:
  -b, --backup-id ID     备份任务ID（必填；可用 ops/backup/create.sh 产生）
  -s, --scope SCOPE      恢复范围 FULL|CONFIG|DATABASE|CERTIFICATE（默认 FULL）
  -u, --user USER        管理员用户名（默认 jiuzhang_admin）
      --api-url URL      管理 API 地址（默认 http://127.0.0.1:18081）
      --timeout SEC      等待隔离恢复秒数（默认 3600）
  -y, --yes              跳过交互确认（仅自动化场景；高风险，慎用）
  -h, --help             显示帮助

环境变量:
  JZ_ADMIN_PASSWORD      管理员密码（未设置时交互读取，不回显）

退出码: 0=成功 1=失败 2=用法错误 3=用户取消
EOF
}

BACKUP_ID=""
SCOPE="FULL"
USER="${JZ_ADMIN_USER:-jiuzhang_admin}"
TIMEOUT=3600
while [[ $# -gt 0 ]]; do
  case "$1" in
    -b|--backup-id) BACKUP_ID="$2"; shift 2 ;;
    -s|--scope)     SCOPE="$2"; shift 2 ;;
    -u|--user)      USER="$2"; shift 2 ;;
    --api-url)      JZ_API_BASE="$2"; shift 2 ;;
    --timeout)      TIMEOUT="$2"; shift 2 ;;
    -y|--yes)       JZ_ASSUME_YES="true"; shift ;;
    -h|--help)      usage; exit 0 ;;
    *) log_err "未知参数: $1"; usage; exit 2 ;;
  esac
done

[[ -n "$BACKUP_ID" ]] || { log_err "必须指定 --backup-id"; usage; exit 2; }
[[ "$SCOPE" =~ ^(FULL|CONFIG|DATABASE|CERTIFICATE)$ ]] || { log_err "无效恢复范围: $SCOPE"; exit 2; }
require_cmd curl
require_cmd jq

trap api_cleanup EXIT
api_login "$USER"

# ---- 1. 校验备份 ----
log_info "步骤 1/4：校验备份 $BACKUP_ID ..."
resp="$(api_req POST /api/v1/restores/validate "{\"backup_job_id\":\"$BACKUP_ID\"}")"
if [[ "$(api_code "$resp")" != "SUCCESS" ]]; then
  die "备份校验未通过: $(printf '%s' "$resp" | jq -r '.message // "未知错误"')"
fi
printf '%s\n' "$resp" | jq -r '.data.preview | "备份时间: \(.backup_time)\nschema 版本: \(.schema_version)（当前 \(.current_schema_version)，兼容 \(.compatible)）\n表数: \(.tables | length)，总行数: \(.total_rows)"'
confirm "备份校验通过。确认创建隔离恢复任务（范围 ${SCOPE}）？" || { log_warn "已取消"; exit 3; }

# ---- 2. 创建隔离恢复 ----
log_info "步骤 2/4：创建隔离恢复任务（范围 ${SCOPE}）..."
resp="$(api_req POST /api/v1/restores "{\"backup_job_id\":\"$BACKUP_ID\",\"scope\":\"$SCOPE\"}")"
[[ "$(api_code "$resp")" == "SUCCESS" ]] || die "创建恢复任务失败: $(printf '%s' "$resp" | jq -r '.message // "未知错误"')"
JOB_ID="$(printf '%s' "$resp" | jq -r '.data.job.id // empty')"
[[ -n "$JOB_ID" ]] || die "响应中无恢复任务ID"
log_info "隔离恢复任务: $JOB_ID"

# ---- 3. 等待 AWAITING_CONFIRM ----
log_info "步骤 3/4：等待隔离恢复完成（超时 ${TIMEOUT}s）..."
elapsed=0
while :; do
  resp="$(api_req GET "/api/v1/restores/$JOB_ID")"
  [[ "$(api_code "$resp")" == "SUCCESS" ]] || die "查询恢复任务失败"
  status="$(printf '%s' "$resp" | jq -r '.data.job.status // empty')"
  case "$status" in
    AWAITING_CONFIRM)
      log_info "隔离恢复完成，等待确认"
      printf '%s\n' "$resp" | jq -r '.data.job.preview | "预览: 表数 \(.tables | length)，总行数 \(.total_rows)"' 2>/dev/null || true
      break
      ;;
    FAILED|CANCELLED)
      msg="$(printf '%s' "$resp" | jq -r '.data.job.failure_message // empty')"
      die "隔离恢复失败（${status}）: $msg"
      ;;
  esac
  if (( elapsed >= TIMEOUT )); then
    die "等待隔离恢复超时（任务ID ${JOB_ID}，可稍后重新执行 confirm）"
  fi
  sleep 10
  elapsed=$((elapsed + 10))
done

# ---- 4. 人工确认正式恢复 ----
log_warn "步骤 4/4：正式恢复将进入维护模式并整组替换范围内表数据（高风险）"
confirm "确认执行正式恢复？" || {
  log_warn "已取消。隔离环境保留，可通过 API 取消任务: POST /api/v1/restores/$JOB_ID/cancel"
  exit 3
}
resp="$(api_req POST "/api/v1/restores/$JOB_ID/confirm" "{\"reason\":\"ops restore.sh 人工确认\"}")"
[[ "$(api_code "$resp")" == "SUCCESS" ]] || die "正式恢复失败: $(printf '%s' "$resp" | jq -r '.message // "未知错误"')"
log_info "正式恢复完成"
printf '%s\n' "$resp" | jq -r '.data.post_verify | to_entries[] | "  核对 \(.key): \(.value) 行"' 2>/dev/null || true
