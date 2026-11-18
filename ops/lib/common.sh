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

# compose_api_url FILE ENV_FILE —— 从实际发布的 API 端口生成本机健康检查地址。
compose_api_url() {
  local file="$1" env_file="$2" rendered endpoint host port
  rendered="$(docker compose -f "$file" --env-file "$env_file" config --format json 2>/dev/null)" || return 1
  endpoint="$(jq -er '[.services.api.ports[]? | select(.target == 8080) | {host:(.host_ip // "127.0.0.1"),port:(.published | tostring)}][0] // empty' <<<"$rendered")" || return 1
  host="$(jq -er .host <<<"$endpoint")"; port="$(jq -er .port <<<"$endpoint")"
  [[ "$port" =~ ^[0-9]+$ ]] && (( 10#$port >= 1 && 10#$port <= 65535 )) || return 1
  case "$host" in ''|'0.0.0.0'|'::') host='127.0.0.1' ;; '::1') host='[::1]' ;; esac
  printf 'http://%s:%s\n' "$host" "$port"
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

# validate_port_list LIST —— 校验逗号分隔端口清单（每项为 1-65535 或 起点-终点 区间，
# 区间起点<=终点）。用于 firewalld 精确放行参数校验（install.sh / install-gateway-baremetal.sh）。
validate_port_list() {
  local list="$1" item lo hi
  # 先做整体形态校验（拒绝空项/尾逗号/非数字字符），再逐项校验范围
  [[ "$list" =~ ^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$ ]] || return 1
  local old_ifs="$IFS"; IFS=','
  read -ra _vpl_items <<< "$list"
  IFS="$old_ifs"
  for item in "${_vpl_items[@]}"; do
    if [[ "$item" =~ ^([0-9]+)-([0-9]+)$ ]]; then
      lo="${BASH_REMATCH[1]}"; hi="${BASH_REMATCH[2]}"
      (( 10#$lo >= 1 && 10#$hi <= 65535 && 10#$lo <= 10#$hi )) || return 1
    elif [[ "$item" =~ ^[0-9]+$ ]]; then
      (( 10#$item >= 1 && 10#$item <= 65535 )) || return 1
    else
      return 1
    fi
  done
  return 0
}

# detect_arch —— 输出规范化架构名（amd64/arm64），用于离线交付包架构匹配。
# x86_64/amd64 → amd64；aarch64/arm64 → arm64；其余架构报错退出。
# 注：海光 C86、兆芯 KX/KH 均为 x86-64 兼容架构，按 amd64 处理（直接使用 amd64 产物，不单独出包）。
detect_arch() {
  local m
  m="$(uname -m)"
  case "$m" in
    x86_64|amd64)  printf 'amd64\n' ;;
    aarch64|arm64) printf 'arm64\n' ;;
    *) die "不支持的 CPU 架构: ${m}（仅提供 amd64/arm64 产物；海光 C86、兆芯 KX/KH 等 x86-64 兼容平台请使用 amd64 包）" ;;
  esac
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
      # 读取调用方经 -e/--env-file 传入的 $JZ_ENV_FILE（而非硬编码 CWD 下 .env）
      vpass="$(grep -E '^VALKEY_PASSWORD=' "$JZ_ENV_FILE" 2>/dev/null | cut -d= -f2 || true)"
      if [[ -n "$vcont" && -n "$vpass" ]]; then
        # 口令经 REDISCLI_AUTH 环境变量传入，不出现在进程命令行（同 ops/healthcheck/check.sh）
        capcode="$(docker exec -e REDISCLI_AUTH="$vpass" "$vcont" \
          valkey-cli --no-auth-warning GET "jiuzhang:captcha:$capid" 2>/dev/null || true)"
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

# ---- 交付包完整性校验（install.sh / install-gateway-baremetal.sh 共用） ----

# sha256_of FILE... —— 计算 SHA-256（GNU sha256sum 优先，BSD shasum 兜底）。
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$@"
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$@"
  else
    die "缺少 sha256sum/shasum，无法计算 SHA-256"
  fi
}

# sha256_check_sidecar ARCHIVE —— 用包外旁车 <ARCHIVE>.sha256（sha256sum 文本格式：
# "<hash>  <文件名>"，随 dist 交付）校验包文件哈希。旁车与包分离分发，是唯一能
# 锚定 tarball 整体的哈希（包内 sha256sums/manifest 属自证，篡改者可同步重算）。
# 返回：0=校验通过 1=校验失败（旁车格式非法或哈希不符） 2=无旁车（交由调用方降级告警）。
sha256_check_sidecar() {
  local archive="$1" sidecar="$1.sha256" expected actual
  [[ -f "$sidecar" ]] || return 2
  [[ -f "$archive" ]] || { log_err "旁车存在但包文件缺失: $archive"; return 1; }
  expected="$(awk 'NR==1{print $1}' "$sidecar" | tr '[:upper:]' '[:lower:]')"
  [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || { log_err "旁车哈希格式非法: $sidecar"; return 1; }
  actual="$(sha256_of "$archive" | awk '{print $1}' | tr '[:upper:]' '[:lower:]')"
  if [[ "$actual" == "$expected" ]]; then
    return 0
  fi
  log_err "旁车哈希不匹配: ${archive}（期望 ${expected}，实际 ${actual}）"
  return 1
}

# manifest_files_verify MANIFEST ROOT —— 按离线包 manifest.json 的 files 清单逐一
# 校验 ROOT 下文件的存在性、大小与 SHA-256（清单路径必须是相对路径且不得含 ..）。
# 反向核对：盘上存在但清单未收录的文件仅告警列示（重装场景 .env/runtime 等安装
# 产物属正常），不阻断。
# 返回：0=全部通过 1=校验失败 2=清单无 files 字段（历史包，由调用方决定降级策略）。
manifest_files_verify() {
  local manifest="$1" root="$2"
  require_cmd jq
  jq -e '.files | type == "array" and length > 0' "$manifest" >/dev/null 2>&1 || return 2
  local sha size path f actual_size actual_sha checked=0
  while IFS=$'\t' read -r sha size path; do
    case "$path" in
      /*|*..*) log_err "manifest.files 含非法路径: $path"; return 1 ;;
    esac
    f="$root/$path"
    [[ -f "$f" ]] || { log_err "包内文件缺失: $path"; return 1; }
    actual_size="$(stat -f%z "$f" 2>/dev/null || stat -c%s "$f")"
    [[ "$actual_size" == "$size" ]] || { log_err "包内文件大小不符: ${path}（期望 ${size}B，实际 ${actual_size}B）"; return 1; }
    actual_sha="$(sha256_of "$f" | awk '{print $1}')"
    [[ "$actual_sha" == "$sha" ]] || { log_err "包内文件 SHA-256 不符: $path"; return 1; }
    checked=$((checked + 1))
  done < <(jq -er '.files[] | [.sha256, (.size | tostring), .path] | @tsv' "$manifest")
  log_info "manifest.files 完整性校验通过（${checked} 个文件）"

  # 反向核对（仅告警）：盘上多出清单未收录的文件可能意味着投递夹带
  local listed extra=0 rel
  listed="$(mktemp "${TMPDIR:-/tmp}/jzmanifest.XXXXXX")"
  jq -r '.files[].path' "$manifest" > "$listed"
  while IFS= read -r f; do
    rel="${f#"$root"/}"
    [[ "$rel" == "manifest.json" ]] && continue
    grep -Fxq "$rel" "$listed" 2>/dev/null && continue
    if (( extra == 0 )); then
      log_warn "以下文件不在 manifest.files 清单内（重装产物属正常，首次安装出现请核对投递来源）:"
    fi
    extra=$((extra + 1))
    (( extra <= 5 )) && log_warn "  未收录: $rel"
  done < <(find "$root" -type f | LC_ALL=C sort)
  (( extra > 5 )) && log_warn "  ……另有 $((extra - 5)) 个未收录文件"
  rm -f "$listed"
  return 0
}
