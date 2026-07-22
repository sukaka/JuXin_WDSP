#!/usr/bin/env bash
# common.sh —— 九章 WAF 运维脚本公共函数库。
# 约束：敏感值（口令/密钥/Token）不输出到日志；所有函数在 set -euo pipefail 下安全。
# 使用方式：SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
#           source "$SCRIPT_DIR/../lib/common.sh"

# 可被调用方覆盖的全局参数
JZ_API_BASE="${JZ_API_BASE:-http://127.0.0.1:18081}"
JZ_COMPOSE_FILE="${JZ_COMPOSE_FILE:-docker-compose.yml}"
JZ_ENV_FILE="${JZ_ENV_FILE:-.env}"
JZ_ASSUME_YES="${JZ_ASSUME_YES:-false}"

log_info() { printf '[INFO]  %s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }
log_warn() { printf '[WARN]  %s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_err()  { printf '[ERROR] %s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2; }

# die MSG [CODE]
die() {
  log_err "${1:-未知错误}"
  exit "${2:-1}"
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "缺少必需命令: $1（请先安装）"
}

# confirm "提示信息" —— 交互确认；JZ_ASSUME_YES=true 时跳过。
confirm() {
  local prompt="$1"
  if [[ "$JZ_ASSUME_YES" == "true" ]]; then
    return 0
  fi
  local ans
  read -r -p "$prompt [y/N] " ans
  [[ "$ans" == "y" || "$ans" == "Y" || "$ans" == "yes" ]]
}

# load_env_file FILE —— 安全解析 KEY=VALUE（不 eval，不执行任何代码）。
load_env_file() {
  local f="$1"
  [[ -f "$f" ]] || die "环境文件不存在: $f"
  local line key val
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    [[ -z "${line//[[:space:]]/}" ]] && continue
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    [[ "$line" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]] || continue
    key="${line%%=*}"
    val="${line#*=}"
    val="${val%\"}"; val="${val#\"}"
    val="${val%\'}"; val="${val#\'}"
    printf -v "$key" '%s' "$val"
    export "$key"
  done < "$f"
}

# compose ARGS... —— 统一 docker compose 入口。
compose() {
  docker compose -f "$JZ_COMPOSE_FILE" --env-file "$JZ_ENV_FILE" "$@"
}

# wait_http_ok URL TIMEOUT_SEC —— 等待 HTTP 200。
wait_http_ok() {
  local url="$1" timeout="${2:-60}" i
  for ((i = 0; i < timeout; i++)); do
    if curl -fsS -o /dev/null --max-time 3 "$url" 2>/dev/null; then
      return 0
    fi
    sleep 1
  done
  return 1
}

# random_hex NBYTES —— 生成随机十六进制（口令/密钥用，不回显）。
random_hex() {
  openssl rand -hex "${1:-32}"
}

# ---- 管理 API 助手（会话 Cookie + CSRF Token） ----

JZ_COOKIE_JAR=""
JZ_CSRF_TOKEN=""

# api_login USERNAME —— 口令从 JZ_ADMIN_PASSWORD 读；缺失时交互读取（不回显）。
api_login() {
  local user="$1"
  require_cmd curl
  require_cmd jq
  local pass="${JZ_ADMIN_PASSWORD:-}"
  if [[ -z "$pass" ]]; then
    read -r -s -p "请输入 $user 的密码: " pass
    printf '\n' >&2
  fi
  [[ -n "$pass" ]] || die "密码不能为空"
  JZ_COOKIE_JAR="$(mktemp "${TMPDIR:-/tmp}/jz_cookies.XXXXXX")"
  chmod 600 "$JZ_COOKIE_JAR"
  # 图形验证码：优先从本机 Valkey 容器读取（本地安装/运维场景），
  # 读不到时回退交互输入（JZ_CAPTCHA_CODE 可预置）。
  local capid capcode="${JZ_CAPTCHA_CODE:-}"
  if [[ -z "$capcode" ]] && command -v docker >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
    capid="$(curl -sS "$JZ_API_BASE/api/v1/auth/captcha" | jq -r '.data.captcha_id // empty')" || true
    if [[ -n "$capid" ]]; then
      local vcont vpass
      vcont="$(docker ps --format '{{.Names}}' | grep -E 'valkey$' | head -1 || true)"
      vpass="$(grep -E '^VALKEY_PASSWORD=' .env 2>/dev/null | cut -d= -f2 || true)"
      if [[ -n "$vcont" && -n "$vpass" ]]; then
        capcode="$(docker exec "$vcont" valkey-cli -a "$vpass" --no-auth-warning GET "jiuzhang:captcha:$capid" 2>/dev/null || true)"
      fi
    fi
  fi
  if [[ -z "$capcode" ]]; then
    read -r -p "请输入图形验证码（管理端登录页可见，或设置 login:captcha_enabled=false）: " capcode
  fi
  local body resp code msg
  body="$(jq -n --arg u "$user" --arg p "$pass" --arg ci "${capid:-}" --arg cc "$capcode" \
    '{username:$u, password:$p, captcha_id:$ci, captcha_code:$cc}')"
  resp="$(curl -sS -c "$JZ_COOKIE_JAR" -H 'Content-Type: application/json' \
    -d "$body" "$JZ_API_BASE/api/v1/auth/login")" || die "登录请求发送失败"
  code="$(printf '%s' "$resp" | jq -r '.code // ""')"
  if [[ "$code" != "SUCCESS" ]]; then
    msg="$(printf '%s' "$resp" | jq -r '.message // "未知错误"')"
    rm -f "$JZ_COOKIE_JAR"
    if [[ "$code" == "CAPTCHA_INVALID" || "$code" == "CAPTCHA_REQUIRED" ]]; then
      die "登录需要图形验证码：请先在系统设置中临时关闭 login:captcha_enabled 后重试（${msg}）"
    fi
    die "登录失败：$msg"
  fi
  JZ_CSRF_TOKEN="$(printf '%s' "$resp" | jq -r '.data.csrf_token // empty')"
  [[ -n "$JZ_CSRF_TOKEN" ]] || { rm -f "$JZ_COOKIE_JAR"; die "未获取到 CSRF Token"; }
  log_info "已登录管理 API（${JZ_API_BASE}，用户 ${user}）"
}

api_cleanup() {
  if [[ -n "$JZ_COOKIE_JAR" ]]; then
    rm -f "$JZ_COOKIE_JAR"
    JZ_COOKIE_JAR=""
  fi
}

# api_req METHOD PATH [JSON_BODY] —— 输出响应体；HTTP 层错误由调用方判断 .code。
api_req() {
  local method="$1" path="$2" data="${3:-}"
  local args=(-sS -b "$JZ_COOKIE_JAR" -X "$method" -H "X-CSRF-Token: $JZ_CSRF_TOKEN")
  if [[ -n "$data" ]]; then
    args+=(-H 'Content-Type: application/json' -d "$data")
  fi
  curl "${args[@]}" "$JZ_API_BASE$path"
}

# api_download PATH OUT_FILE —— 下载文件（备份等）。
api_download() {
  local path="$1" out="$2"
  curl -fsS -b "$JZ_COOKIE_JAR" -H "X-CSRF-Token: $JZ_CSRF_TOKEN" -o "$out" "$JZ_API_BASE$path"
}

# api_code RESP —— 提取响应 code 字段。
api_code() {
  printf '%s' "$1" | jq -r '.code // ""'
}
