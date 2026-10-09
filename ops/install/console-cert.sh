#!/usr/bin/env bash
# console-cert.sh —— 管理控制台 HTTPS 证书生成（离线包）。
#
# 默认生成自签证书：RSA-2048、SHA-256、有效期 100 年（一次生成、永久免续期）、
# SAN 覆盖宿主机全部 IPv4 与 hostname/localhost。输出到
#   <包根>/runtime/certificates/console.crt / console.key
# 由 compose 只读挂载进 web 容器（/etc/caddy/console-certs/）。
#
# 幂等：两个文件都已存在时不重新生成（证书永久有效，重装/升级不轮换）；
# 确需重签用 --force。用户自备证书（内网 CA 签发）直接替换这两个文件后
# docker compose up -d web 即可。
#
# 用法: console-cert.sh [--output DIR] [--days N] [--extra-san "DNS:x,IP:y"] [--force]
# 退出码: 0=成功 1=失败 2=用法错误
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

OUTPUT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)/runtime/certificates"
DAYS=36500
EXTRA_SAN=""
FORCE=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)     OUTPUT_DIR="$2"; shift 2 ;;
    --days)       DAYS="$2"; shift 2 ;;
    --extra-san)  EXTRA_SAN="$2"; shift 2 ;;  # 追加 SAN，逗号分隔，须带类型前缀（DNS: / IP:）
    --force)      FORCE=true; shift ;;
    -h|--help)    grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) log_err "未知参数: $1"; exit 2 ;;
  esac
done
[[ "$DAYS" =~ ^[0-9]+$ ]] && (( DAYS >= 1 )) || { log_err "--days 须为正整数: $DAYS"; exit 2; }

CRT="$OUTPUT_DIR/console.crt"
KEY="$OUTPUT_DIR/console.key"
if [[ -s "$CRT" && -s "$KEY" && "$FORCE" != "true" ]]; then
  log_info "控制台证书已存在（${CRT}），保持现状不重新生成；确需重签请加 --force"
  exit 0
fi
require_cmd openssl

# ---------- 收集 SAN：宿主机全部 IPv4 + hostname + localhost ----------
sans="DNS:localhost,IP:127.0.0.1"
add_san() {
  [[ -n "$1" ]] || return 0
  case ",$sans," in
    *",$1,"*) return 0 ;;  # 去重
  esac
  sans="$sans,$1"
}

host_name="$(hostname 2>/dev/null || true)"
host_fqdn="$(hostname -f 2>/dev/null || true)"
[[ -n "$host_name" ]] && add_san "DNS:$host_name"
[[ -n "$host_fqdn" && "$host_fqdn" != "$host_name" ]] && add_san "DNS:$host_fqdn"

# 非回环 IPv4：优先 ip 命令，兜底 hostname -I（GNU），再兜底 ifconfig
if command -v ip >/dev/null 2>&1; then
  while IFS= read -r ip4; do add_san "IP:$ip4"; done \
    < <(ip -4 -o addr show 2>/dev/null | awk '{split($4,a,"/"); print a[1]}')
elif ips_line="$(hostname -I 2>/dev/null)" && [[ -n "$ips_line" ]]; then
  for ip4 in $ips_line; do add_san "IP:$ip4"; done
elif command -v ifconfig >/dev/null 2>&1; then
  while IFS= read -r ip4; do add_san "IP:$ip4"; done \
    < <(ifconfig 2>/dev/null | awk '/inet / {print $2}')
fi
# 自定义 SAN（如外部访问域名 / VIP）：逐项必须是 DNS: 或 IP: 前缀
if [[ -n "$EXTRA_SAN" ]]; then
  IFS=',' read -ra _extra <<< "$EXTRA_SAN"
  for item in "${_extra[@]}"; do
    item="$(printf '%s' "$item" | tr -d '[:space:]')"
    case "$item" in
      DNS:*|IP:*) add_san "$item" ;;
      *) die "--extra-san 项须带 DNS: / IP: 前缀: $item" ;;
    esac
  done
  unset _extra
fi
SAN_LIST="$sans"

mkdir -p "$OUTPUT_DIR"
chmod 755 "$OUTPUT_DIR"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

# CN 取首个主机 IPv4（无则 hostname），仅为证书可读性；身份校验全部走 SAN
cn_value="$(printf '%s' "$SAN_LIST" | tr ',' '\n' | awk -F: '$1=="IP" && $2!="127.0.0.1" {print $2; exit}')"
[[ -n "$cn_value" ]] || cn_value="${host_name:-jiuzhang-console}"

(umask 077
 openssl req -x509 -newkey rsa:2048 -nodes -sha256 \
   -keyout "$tmp_dir/console.key" -out "$tmp_dir/console.crt" \
   -days "$DAYS" \
   -subj "/O=JiuZhang/CN=$cn_value" \
   -addext "subjectAltName=$SAN_LIST" \
   -addext "extendedKeyUsage=serverAuth" \
   -addext "basicConstraints=critical,CA:FALSE")

mv "$tmp_dir/console.crt" "$CRT"
mv "$tmp_dir/console.key" "$KEY"
chmod 644 "$CRT"
chmod 600 "$KEY"

not_after="$(openssl x509 -in "$CRT" -noout -enddate 2>/dev/null | cut -d= -f2- || echo unknown)"
log_info "控制台 HTTPS 证书已生成：${CRT}（有效期至：${not_after}）"
log_info "SAN：${SAN_LIST}"
log_info "生效：docker compose up -d web；浏览器首次访问提示自签告警属预期，导入 ${CRT} 到受信根证书可消除"
