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
      gsub(/[Aa][Uu][Tt][Hh][Oo][Rr][Ii][Zz][Aa][Tt][Ii][Oo][Nn]:[[:space:]]*[Bb][Ee][Aa][Rr][Ee][Rr][[:space:]]+[^[:space:]"]+/, "Authorization: Bearer [REDACTED]")
      gsub(/[Aa][Uu][Tt][Hh][Oo][Rr][Ii][Zz][Aa][Tt][Ii][Oo][Nn]:[[:space:]]*[Bb][Aa][Ss][Ii][Cc][[:space:]]+[^[:space:]"]+/, "Authorization: Basic [REDACTED]")
      gsub(/[Xx]-[Aa][Pp][Ii]-[Kk][Ee][Yy]:[^\r\n]*/, "X-API-Key: [REDACTED]")
      gsub(/[Xx]-[Cc][Ss][Rr][Ff]-[Tt][Oo][Kk][Ee][Nn]:[^\r\n]*/, "X-CSRF-Token: [REDACTED]")
      gsub(/[Cc][Oo][Oo][Kk][Ii][Ee]:[^\r\n]*/, "Cookie: [REDACTED]")
      gsub(/[Ss][Ee][Tt]-[Cc][Oo][Oo][Kk][Ii][Ee]:[^\r\n]*/, "Set-Cookie: [REDACTED]")

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

umask 077
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
  awk '
    {
      line = $0
      sub(/\r$/, "", line)
      idx = index(line, "=")
      if (idx > 1) {
        key = substr(line, 1, idx - 1)
        if (key ~ /^[A-Za-z_][A-Za-z0-9_]*$/ && toupper(key) ~ /(PASSWORD|SECRET|KEY|TOKEN|DSN|URL|URI)/) {
          print key "=********"
          next
        }
      }
      gsub(/:\/\/[^\/:@[:space:]]+:[^\/@[:space:]]+@/, "://***:***@")
      print
    }
  ' "$JZ_ENV_FILE" | redact_stream > "$work/env.sanitized.txt"
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

# ---- 透明串接 / 网桥 / 路由 / 内核参数 / Netfilter 诊断（只读 allowlist，全部脱敏） ----
{
  echo "== ip -d link show =="
  if command -v ip >/dev/null 2>&1; then
    ip -d link show 2>&1 || true
  else
    echo "(ip unavailable)"
  fi
  echo
  echo "== bridge link show =="
  if command -v bridge >/dev/null 2>&1; then
    bridge link show 2>&1 || true
  else
    echo "(bridge unavailable)"
  fi
  echo
  echo "== ip route show =="
  if command -v ip >/dev/null 2>&1; then
    ip route show 2>&1 || true
    echo "-- ipv6 --"
    ip -6 route show 2>&1 || true
  else
    echo "(ip unavailable)"
  fi
  echo
  echo "== sysctl (transparent allowlist) =="
  for _key in \
    net.ipv4.ip_forward \
    net.bridge.bridge-nf-call-iptables \
    net.bridge.bridge-nf-call-ip6tables \
    net.ipv4.conf.all.route_localnet \
    net.ipv4.conf.default.route_localnet \
    net.netfilter.nf_conntrack_max \
    net.netfilter.nf_conntrack_count; do
    _proc="/proc/sys/${_key//./\/}"
    if [[ -r "$_proc" ]]; then
      printf '%s = %s\n' "$_key" "$(cat "$_proc" 2>/dev/null || echo unreadable)"
    elif command -v sysctl >/dev/null 2>&1; then
      sysctl -n "$_key" >/dev/null 2>&1 && sysctl "$_key" 2>&1 || true
    fi
  done
  shopt -s nullglob
  for _proc in /proc/sys/net/ipv4/conf/br*/route_localnet; do
    [[ -r "$_proc" ]] || continue
    _if="${_proc#/proc/sys/net/ipv4/conf/}"
    _if="${_if%/route_localnet}"
    printf 'net.ipv4.conf.%s.route_localnet = %s\n' "$_if" "$(cat "$_proc" 2>/dev/null || echo unreadable)"
  done
  shopt -u nullglob
  echo
  echo "== netfilter (iptables/nft read-only) =="
  if command -v iptables >/dev/null 2>&1; then
    echo "-- iptables -t nat -S --"
    (iptables -t nat -S 2>&1 | head -n 200) || true
    echo "-- iptables -t filter -S FORWARD --"
    (iptables -t filter -S FORWARD 2>&1 | head -n 200) || true
    echo "-- iptables -t filter -S INPUT --"
    (iptables -t filter -S INPUT 2>&1 | head -n 200) || true
  else
    echo "(iptables unavailable)"
  fi
  if command -v nft >/dev/null 2>&1; then
    echo "-- nft list tables --"
    nft list tables 2>&1 || true
    echo "-- nft list ruleset (bounded) --"
    (nft list ruleset 2>&1 | head -n 400) || true
  else
    echo "(nft unavailable)"
  fi
} | redact_stream > "$work/network-transparent.txt"

# ---- Sidecar 非密配置（严格白名单，绝不采集 capability.json / ha-vip.json） ----
sidecar_dir=""
if [[ -n "${GATEWAY_SIDECAR_DIR:-}" && -d "$GATEWAY_SIDECAR_DIR" && ! -L "$GATEWAY_SIDECAR_DIR" ]]; then
  sidecar_dir="$GATEWAY_SIDECAR_DIR"
elif command -v docker >/dev/null 2>&1 && command -v jq >/dev/null 2>&1 && [[ -f "$JZ_COMPOSE_FILE" ]]; then
  _gw_id=""
  if [[ -f "$JZ_ENV_FILE" ]]; then
    _gw_id="$(compose ps -q gateway 2>/dev/null | head -n 1 || true)"
  else
    _gw_id="$(docker compose -f "$JZ_COMPOSE_FILE" ps -q gateway 2>/dev/null | head -n 1 || true)"
  fi
  if [[ "$_gw_id" =~ ^[a-fA-F0-9]+$ ]]; then
    _admin_dir="$(docker inspect --format '{{json .Mounts}}' "$_gw_id" 2>/dev/null \
      | jq -er '[.[] | select(.Destination == "/var/run/caddy") | .Source] | if length == 1 then .[0] else empty end' 2>/dev/null || true)"
    if [[ -n "$_admin_dir" && -d "$_admin_dir/sidecars" && ! -L "$_admin_dir/sidecars" ]]; then
      sidecar_dir="$_admin_dir/sidecars"
    fi
  fi
fi
if [[ -z "$sidecar_dir" && -d /var/run/caddy/sidecars && ! -L /var/run/caddy/sidecars ]]; then
  sidecar_dir="/var/run/caddy/sidecars"
fi
{
  echo "== sidecars (allowlist: network.json, network-status.json, tproxyd.json) =="
  if [[ -n "$sidecar_dir" ]]; then
    echo "source_dir=$sidecar_dir"
    for _fname in network.json network-status.json tproxyd.json; do
      _fpath="$sidecar_dir/$_fname"
      echo "-- $_fname --"
      if [[ -f "$_fpath" && ! -L "$_fpath" && -r "$_fpath" ]]; then
        head -c 65536 "$_fpath" 2>/dev/null || true
        echo
      else
        echo "(not present or unreadable)"
      fi
    done
  else
    echo "(sidecar directory unavailable)"
  fi
} | redact_stream > "$work/sidecars.txt"

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
chmod 600 "$out"
size="$(stat -f%z "$out" 2>/dev/null || stat -c%s "$out")"
log_info "诊断包已生成: ${out}（${size} 字节）"
