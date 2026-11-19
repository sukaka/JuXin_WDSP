#!/usr/bin/env bash
# netapply.sh —— 运维控制台网络变更 root helper（唯一经 sudoers 放行的特权入口）。
# 由 jiuzhang-console 以 `sudo -n` 调用；所有参数在此处再次兜底校验（不信任调用方）。
#
# 子命令：
#   mgmt-ip <ifname> <ip/prefix> [gateway]   设置管理地址
#   route-add <dest/prefix> <gateway> [dev]  添加静态路由
#   route-del <dest/prefix>                  删除静态路由
#   dns <ip1> [ip2]                          设置 DNS
#
# 落地策略：netplan（Ubuntu 22.04+，推荐）重写 /etc/netplan/99-jz-console.yaml 后 apply（先备份）；
# 无 netplan 时用 nmcli（CentOS/RHEL 系）修改活动连接。状态记录在 /etc/jiuzhang/netconsole.env。
set -euo pipefail

STATE_FILE=/etc/jiuzhang/netconsole.env
NETPLAN_FILE=/etc/netplan/99-jz-console.yaml

log() { echo "[netapply] $*"; }
die() { echo "[netapply] 错误: $*" >&2; exit 1; }

[[ $(id -u) -eq 0 ]] || die "必须以 root 运行（经 sudo 调用）"

# ---------- 兜底校验（与 Go 侧 sysconsole/validate.go 同口径） ----------
IF_RE='^[a-zA-Z][a-zA-Z0-9_.:-]{0,31}$'
IP_RE='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
CIDR_RE='^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[12][0-9]|3[0-2])$'

valid_ip()   { [[ $1 =~ $IP_RE ]] && awk -F. '$1<=255&&$2<=255&&$3<=255&&$4<=255{f=1} END{exit !f}' <<<"$1"; }
valid_cidr() { [[ $1 =~ $CIDR_RE ]] && valid_ip "${1%/*}"; }
valid_if()   { [[ $1 =~ $IF_RE ]]; }

# ---------- 状态（本 helper 全权管理的网络配置） ----------
MGMT_IF=""; MGMT_CIDR=""; MGMT_GW=""; DNS1=""; DNS2=""; ROUTES=""  # ROUTES 元素: dest|gw|dev
[[ -f "$STATE_FILE" ]] && source "$STATE_FILE"

save_state() {
  local tmp
  install -d -m 0755 /etc/jiuzhang
  tmp="$(mktemp /etc/jiuzhang/.netconsole.env.XXXXXX)"
  chmod 0600 "$tmp"
  cat >"$tmp" <<EOF
MGMT_IF='$MGMT_IF'
MGMT_CIDR='$MGMT_CIDR'
MGMT_GW='$MGMT_GW'
DNS1='$DNS1'
DNS2='$DNS2'
ROUTES='$ROUTES'
EOF
  mv -f "$tmp" "$STATE_FILE"
  chmod 0600 "$STATE_FILE"
}

# ---------- netplan 落地 ----------
render_netplan() {
  [[ -n "$MGMT_IF" && -n "$MGMT_CIDR" ]] || die "尚未设置管理地址（先执行 set mgmt-ip）"
  local bak=""
  {
    echo "# 由九章运维控制台管理（netapply.sh），勿手改；改动会被覆盖"
    echo "network:"
    echo "  version: 2"
    echo "  ethernets:"
    printf '    "%s":\n' "$MGMT_IF"
    echo "      dhcp4: false"
    printf '      addresses: ["%s"]\n' "$MGMT_CIDR"
    if [[ -n "$MGMT_GW" || -n "$ROUTES" ]]; then
      echo "      routes:"
      [[ -n "$MGMT_GW" ]] && { echo "        - to: default"; printf '          via: "%s"\n' "$MGMT_GW"; }
      local r dest gw dev
      for r in $ROUTES; do
        IFS='|' read -r dest gw dev <<<"$r"
        printf '        - to: "%s"\n' "$dest"
        printf '          via: "%s"\n' "$gw"
      done
    fi
    if [[ -n "$DNS1" ]]; then
      echo "      nameservers:"
      if [[ -n "$DNS2" ]]; then
        printf '        addresses: ["%s", "%s"]\n' "$DNS1" "$DNS2"
      else
        printf '        addresses: ["%s"]\n' "$DNS1"
      fi
    fi
  } >"$NETPLAN_FILE.new"
  chmod 600 "$NETPLAN_FILE.new"
  if [[ -f "$NETPLAN_FILE" ]]; then
    bak="$NETPLAN_FILE.bak.$(date +%Y%m%d%H%M%S)"
    cp -a "$NETPLAN_FILE" "$bak"
  fi
  mv -f "$NETPLAN_FILE.new" "$NETPLAN_FILE"
  chmod 600 "$NETPLAN_FILE"
  if ! netplan generate; then
    if [[ -n "$bak" && -f "$bak" ]]; then
      cp -a "$bak" "$NETPLAN_FILE"
      chmod 600 "$NETPLAN_FILE"
    else
      rm -f "$NETPLAN_FILE"
    fi
    die "netplan generate 语法校验失败，已恢复原配置"
  fi
  netplan apply
}

# ---------- nmcli 落地（无 netplan 的 RHEL 系） ----------
nmcli_con_for() { nmcli -g GENERAL.CONNECTION device show "$1" 2>/dev/null | head -1; }

apply_nmcli() {
  [[ -n "$MGMT_IF" && -n "$MGMT_CIDR" ]] || die "尚未设置管理地址（先执行 set mgmt-ip）"
  local con; con=$(nmcli_con_for "$MGMT_IF")
  [[ -n "$con" && "$con" != "--" ]] || die "网口 $MGMT_IF 无活动连接（nmcli）"
  # 先清空 ipv4.routes 再按当前 ROUTES 全量回写，确保 route-del 能真正移除旧路由
  nmcli con mod "$con" ipv4.method manual ipv4.addresses "$MGMT_CIDR" \
    ipv4.gateway "${MGMT_GW:-}" ipv4.dns "${DNS1:-}${DNS2:+ $DNS2}" ipv4.routes ""
  local r dest gw dev
  for r in $ROUTES; do
    IFS='|' read -r dest gw dev <<<"$r"
    nmcli con mod "$con" +ipv4.routes "$dest $gw"
  done
  nmcli con up "$con" >/dev/null
}

apply() {
  if command -v netplan >/dev/null 2>&1; then
    render_netplan
    save_state
    log "已应用（netplan，备份在 ${NETPLAN_FILE}.bak.*）"
  elif command -v nmcli >/dev/null 2>&1; then
    apply_nmcli
    save_state
    log "已应用（nmcli）"
  else
    die "既不识别 netplan 也无 nmcli，当前发行版暂不支持自动网络配置"
  fi
}

# ---------- 子命令 ----------
cmd=${1:-}
case "$cmd" in
  mgmt-ip)
    [[ $# -ge 3 && $# -le 4 ]] || die "用法: mgmt-ip <ifname> <ip/prefix> [gateway]"
    valid_if "$2"   || die "非法网口名: $2"
    valid_cidr "$3" || die "非法 IP/前缀: $3"
    MGMT_IF=$2; MGMT_CIDR=$3; MGMT_GW=""
    if [[ $# -eq 4 ]]; then valid_ip "$4" || die "非法网关: $4"; MGMT_GW=$4; fi
    apply
    ;;
  route-add)
    [[ $# -ge 3 && $# -le 4 ]] || die "用法: route-add <dest/prefix> <gateway> [dev]"
    valid_cidr "$2" || die "非法目的网段: $2"
    valid_ip "$3"   || die "非法网关: $3"
    if [[ $# -eq 4 ]]; then valid_if "$4" || die "非法网口名: $4"; fi
    ROUTES=$(printf '%s\n' $ROUTES "$2|$3|${4:-}" | sort -u | tr '\n' ' ' | sed 's/ *$//')
    apply
    ;;
  route-del)
    [[ $# -eq 2 ]] || die "用法: route-del <dest/prefix>"
    valid_cidr "$2" || die "非法目的网段: $2"
    local_new=""
    for r in $ROUTES; do [[ ${r%%|*} == "$2" ]] || local_new="$local_new $r"; done
    ROUTES=${local_new# }
    apply
    ;;
  dns)
    [[ $# -ge 2 && $# -le 3 ]] || die "用法: dns <ip1> [ip2]"
    valid_ip "$2" || die "非法 DNS 地址: $2"
    DNS1=$2; DNS2=""
    if [[ $# -eq 3 ]]; then valid_ip "$3" || die "非法 DNS 地址: $3"; DNS2=$3; fi
    apply
    ;;
  *)
    die "未知子命令: ${cmd:-<空>}（支持 mgmt-ip / route-add / route-del / dns）"
    ;;
esac
