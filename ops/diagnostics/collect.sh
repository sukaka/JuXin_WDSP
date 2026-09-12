#!/usr/bin/env bash
# collect.sh —— 诊断信息收集：版本/配置（脱敏）/容器状态/最近日志/磁盘，打包输出。
# 默认策略：只收集 allowlist 内的文本诊断信息；不收集私钥、会话文件、内存转储、
# 客户请求体或响应体。配置、健康响应和容器日志统一经过 redact_stream 处理。
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

说明: 配置中 PASSWORD/SECRET/KEY/TOKEN/DSN/URL/URI 类敏感值一律脱敏为 ********；
      任意值内嵌的 scheme://user:pass@ 凭据段也会脱敏为 scheme://***:***@；
      日志与 API 响应中的 Bearer/Cookie/JSON 敏感字段、PEM 私钥和请求/响应体字段也会脱敏。
      诊断包发送到外部前，必须通过组织批准的加密通道转交；本脚本不上传数据。
      可通过 WDSP_RELEASE_ID 传入非敏感发布标识；未提供时记录为 unavailable。
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

# redact_stream —— 对诊断文本做防御性脱敏。
#
# 这里故意不做“猜测式”数据采集：诊断脚本只处理已经收集到的 allowlist 文本，
# 并把常见凭据、认证头、请求/响应体字段和 PEM 块替换掉。awk 是 macOS/Linux
# 基础环境都具备的依赖；如果未来新增采集项，必须继续通过本函数输出。
redact_stream() {
  awk '
    BEGIN { pem = 0 }
    /-----BEGIN ([A-Za-z0-9 -]*PRIVATE KEY|OPENSSH PRIVATE KEY|EC PRIVATE KEY|RSA PRIVATE KEY)-----/ {
      pem = 1
      print "[REDACTED PEM PRIVATE KEY BLOCK]"
      next
    }
    pem {
      if (/-----END ([A-Za-z0-9 -]*PRIVATE KEY|OPENSSH PRIVATE KEY|EC PRIVATE KEY|RSA PRIVATE KEY)-----/) {
        pem = 0
      }
      next
    }
    {
      # HTTP authentication and session headers.
      gsub(/[Aa]uthorization:[[:space:]]*[Bb]earer[[:space:]]+[^[:space:]]+/, "Authorization: Bearer [REDACTED]")
      gsub(/[Cc]ookie:[^\r\n]*/, "Cookie: [REDACTED]")
      gsub(/[Ss]et-[Cc]ookie:[^\r\n]*/, "Set-Cookie: [REDACTED]")

      # JSON/log key-value forms. Keep the key and redact only the value.
      gsub(/\"([Pp]assword|[Pp]asswd|[Ss]ecret|[Tt]oken|[Aa]ccess[_-][Tt]oken|[Rr]efresh[_-][Tt]oken|[Aa]pi[_-]?[Kk]ey|[Cc]lient[_-][Ss]ecret|[Pp]rivate[_-]?[Kk]ey|[Ss]ignature|[Rr]equest[_-]?[Bb]ody|[Rr]esponse[_-]?[Bb]ody|[Pp]ayload)[\"]?[[:space:]]*:[[:space:]]*\"[^\"]*\"/, "\"REDACTED\":\"[REDACTED]\"")
      gsub(/(^|[[:space:],;])([Pp]assword|[Pp]asswd|[Ss]ecret|[Tt]oken|[Aa]ccess[_-][Tt]oken|[Rr]efresh[_-][Tt]oken|[Aa]pi[_-]?[Kk]ey|[Cc]lient[_-][Ss]ecret|[Pp]rivate[_-]?[Kk]ey|[Ss]ignature|[Rr]equest[_-]?[Bb]ody|[Rr]esponse[_-]?[Bb]ody|[Pp]ayload)[[:space:]]*[:=][[:space:]]*[^,;[:space:]]+/, "[REDACTED]=[REDACTED]")

      # URL credentials, including credentials in otherwise non-sensitive keys.
      gsub(/:\/\/[^\/:@[:space:]]+:[^\/@[:space:]]+@/, "://***:***@")

      # Do not ship obvious inline request/response body labels from text logs.
      gsub(/[Rr]equest[[:space:]_-]*[Bb]ody[[:space:]]*[:=][[:space:]]*[^[:space:]]+/, "request_body=[REDACTED]")
      gsub(/[Rr]esponse[[:space:]_-]*[Bb]ody[[:space:]]*[:=][[:space:]]*[^[:space:]]+/, "response_body=[REDACTED]")
      print
    }
  '
}

write_redacted() {
  local destination="$1"
  redact_stream > "$destination"
}

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
# 两道掩码（MED-21）：
#  1) 键名含 PASSWORD/SECRET/KEY/TOKEN/DSN/URL/URI 的整行掩码（DSN 类键值内嵌口令）；
#  2) 兜底通用掩码：任意值中 scheme://user:pass@ 的 user:pass 段（覆盖键名不含上述
#     关键字但值里内嵌凭据的形态，如 EXTRA_HOSTS、自定义连接串）。
if [[ -f "$JZ_ENV_FILE" ]]; then
  sed -E \
    -e 's/^([A-Za-z_][A-Za-z0-9_]*(PASSWORD|SECRET|KEY|TOKEN|DSN|URL|URI)[A-Za-z0-9_]*)=.*/\1=********/I' \
    -e 's#(://)[^/:@[:space:]]+:[^/@[:space:]]+@#\1***:***@#g' \
    "$JZ_ENV_FILE" | redact_stream > "$work/env.sanitized.txt"
  log_info "环境配置已脱敏（PASSWORD/SECRET/KEY/TOKEN/DSN/URL/URI → ********，值内 user:pass@ → ***:***@）"
else
  log_warn "环境文件 $JZ_ENV_FILE 不存在，跳过"
fi

# ---- 容器状态与日志 ----
if command -v docker >/dev/null 2>&1 && [[ -f "$JZ_COMPOSE_FILE" ]]; then
  if [[ -f "$JZ_ENV_FILE" ]]; then
    compose ps > "$work/compose-ps.txt" 2>&1 || true
    compose logs --no-color --tail="$LOG_LINES" 2>&1 | redact_stream > "$work/compose-logs.txt" || true
  else
    docker compose -f "$JZ_COMPOSE_FILE" ps > "$work/compose-ps.txt" 2>&1 || true
    docker compose -f "$JZ_COMPOSE_FILE" logs --no-color --tail="$LOG_LINES" 2>&1 | redact_stream > "$work/compose-logs.txt" || true
  fi
  docker ps -a --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}' > "$work/docker-ps.txt" 2>&1 || true
else
  log_warn "docker 或 compose 文件不可用，跳过容器信息"
fi

# ---- API 健康 ----
curl -sS --max-time 5 "$JZ_API_BASE/api/v1/health" 2>/dev/null | redact_stream > "$work/api-health.json" || \
  echo "unreachable" > "$work/api-health.json"

# ---- 磁盘 ----
{
  df -h
  echo
  docker system df 2>/dev/null || true
} > "$work/disk.txt"

# ---- 诊断包清单 ----
# 清单本身不包含诊断内容，只记录 allowlist 文件名、大小和 SHA-256，便于支持侧
# 复核包是否在传输过程中被替换。禁止把临时目录之外的文件递归打入压缩包。
release_id="${WDSP_RELEASE_ID:-unavailable}"
# 发布标识来自调用方，不能让换行或控制字符破坏清单格式；它不是密钥，不做内容猜测。
release_id="$(printf '%s' "$release_id" | LC_ALL=C tr -cd 'A-Za-z0-9._:-' | cut -c1-128)"
[[ -n "$release_id" ]] || release_id=unavailable
{
  echo "policy_version=wdsp-diagnostics-v1"
  echo "collected_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo "release_id=$release_id"
  echo "package_scope=customer_support_allowlist"
  echo "private_debug_archive=not_in_customer_package"
  if command -v git >/dev/null 2>&1 && [[ -d "$REPO_ROOT/.git" ]]; then
    echo "repository_commit=$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unavailable)"
  else
    echo "repository_commit=unavailable"
  fi
  echo "files:"
  while IFS= read -r file; do
    [[ "$file" == "$work/diagnostic-manifest.txt" ]] && continue
    size_bytes="$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file")"
    digest="$(sha256_of "$file" | awk '{print $1}')"
    printf '%s\t%s\t%s\n' "${file#"$work"/}" "$size_bytes" "$digest"
  done < <(find "$work" -type f -print | sort)
} > "$work/diagnostic-manifest.txt"

out="$OUT_DIR/diagnostics-$ts.tar.gz"
tar -czf "$out" -C "$work" .
size="$(stat -f%z "$out" 2>/dev/null || stat -c%s "$out")"
log_info "诊断包已生成: ${out}（${size} 字节）"
