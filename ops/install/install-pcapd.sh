#!/usr/bin/env bash
# 独立裸机请求PCAP安装：只有显式执行本脚本才启用持续抓包。
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
if [[ -f "$SCRIPT_DIR/lib/common.sh" ]]; then
  source "$SCRIPT_DIR/lib/common.sh"
  source "$SCRIPT_DIR/lib/signing.sh"
  source "$SCRIPT_DIR/pcap.sh"
else
  source "$REPO_ROOT/ops/lib/common.sh"
  source "$REPO_ROOT/ops/lib/signing.sh"
  source "$REPO_ROOT/ops/install/pcap.sh"
fi

PKG=""
PCAP_ENABLE=true
ALLOW_UNSIGNED=false
DRY_RUN=false
PCAP_NODE="${GATEWAY_NODE_NAME:-gateway-poc-01}"
usage() {
  cat <<'EOF'
用法: install-pcapd.sh --package gateway-linux-ARCH.tar.gz --iface IFACE --ports LIST --hot-dir SSD_DIR --warm-dir SAS_DIR [--node NODE] [--dry-run]
仅在显式执行时安装并启动加密PCAP daemon。需要同时指定网卡、明确端口、SSD热目录和SAS温目录。
默认不启用混杂模式；不开放TCP管理端口。正式包必须带Ed25519签名；--allow-unsigned仅用于开发包。
EOF
}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --package) PKG="$2"; shift 2 ;;
    --iface) PCAP_IFACE="$2"; shift 2 ;;
    --ports) PCAP_PORTS="$2"; shift 2 ;;
    --hot-dir) PCAP_HOT_DIR="$2"; shift 2 ;;
    --warm-dir) PCAP_WARM_DIR="$2"; shift 2 ;;
    --node) PCAP_NODE="$2"; shift 2 ;;
    --dry-run) DRY_RUN=true; shift ;;
    --allow-unsigned) ALLOW_UNSIGNED=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "未知参数: $1" 2 ;;
  esac
done
pcap_validate_args
pcap_validate_enabled
[[ "$PCAP_NODE" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || die "节点ID不合法"
[[ -f "$PKG" ]] || die "裸机网关包不存在: $PKG"
if ! ed25519_verify_sidecar "$PKG"; then
  [[ "$ALLOW_UNSIGNED" == "true" ]] || die "PCAP包未通过签名验证，拒绝安装"
  log_warn "仅允许开发自验包绕过签名；生产禁止使用 --allow-unsigned"
fi
if [[ "$DRY_RUN" != "true" && "$(id -u)" != "0" ]]; then
  die "裸机PCAP安装需要root"
fi
command -v systemctl >/dev/null 2>&1 || [[ "$DRY_RUN" == "true" ]] || die "目标主机没有systemd"
work="$(mktemp -d "${TMPDIR:-/tmp}/jz-pcapd-install.XXXXXX")"
trap 'rm -rf "$work"' EXIT
tar -xzf "$PKG" -C "$work"
source_dir="$(find "$work" -mindepth 1 -maxdepth 1 -type d | head -1)"
[[ -n "$source_dir" ]] || source_dir="$work"
[[ -f "$source_dir/jiuzhang-pcapd" && -f "$source_dir/jiuzhang-pcapd.service" ]] || die "包内缺少pcapd二进制或systemd单元"
if [[ -f "$source_dir/delivery_mode" ]] && [[ "$(awk 'NF{print $1;exit}' "$source_dir/delivery_mode")" != "development" && "$ALLOW_UNSIGNED" == "true" ]]; then
  die "--allow-unsigned不能用于正式生产包"
fi
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$source_dir" && sha256sum -c sha256sums)
else
  (cd "$source_dir" && shasum -a 256 -c sha256sums)
fi
run() {
  if [[ "$DRY_RUN" == "true" ]]; then
    printf '[DRY-RUN] %s\n' "$*"
  else
    "$@"
  fi
}
run install -m 0755 -o root -g root "$source_dir/jiuzhang-pcapd" /usr/local/bin/jiuzhang-pcapd
run install -d -m 0700 -o 1000 -g 1000 "$PCAP_HOT_DIR" "$PCAP_WARM_DIR"
run install -d -m 0700 -o 1000 -g 1000 /var/lib/jiuzhang/pcap-private
run install -d -m 0755 -o 1000 -g 1000 /var/lib/jiuzhang/pcap-public
run install -d -m 0755 -o root -g root /etc/jiuzhang
if [[ "$DRY_RUN" != "true" ]]; then
  cat > /etc/jiuzhang/pcapd.env <<EOF
GATEWAY_NODE_NAME=$PCAP_NODE
REQUEST_PCAP_IFACE=$PCAP_IFACE
REQUEST_PCAP_PORTS=$PCAP_PORTS
REQUEST_PCAP_HOT_DIR=$PCAP_HOT_DIR
REQUEST_PCAP_GRANT=/var/lib/jiuzhang/pcap-public/pcap-public.json
REQUEST_PCAP_TRUST=/var/lib/jiuzhang/pcap-public/pcap-release.pub
REQUEST_PCAP_POLICY_VERSION=baremetal-approved-v1
EOF
  chmod 0644 /etc/jiuzhang/pcapd.env
else
  printf '[DRY-RUN] 写入 /etc/jiuzhang/pcapd.env（仅非秘密抓包配置）\n'
fi
if [[ -f /etc/systemd/system/jiuzhang-pcapd.service ]] && ! grep -qF 'jiuzhang-managed: request-pcap' /etc/systemd/system/jiuzhang-pcapd.service; then
  die "已有非九章管理的pcapd systemd单元，拒绝覆盖"
fi
run install -m 0644 -o root -g root "$source_dir/jiuzhang-pcapd.service" /etc/systemd/system/jiuzhang-pcapd.service
run systemctl daemon-reload
run systemctl enable --now jiuzhang-pcapd.service
log_info "pcapd已按显式范围启用；管理面须使用同一节点ID，并将私钥目录与公钥目录分别配置到/var/lib/jiuzhang/pcap-private和/var/lib/jiuzhang/pcap-public"
