#!/usr/bin/env bash
# firewall-ensure.sh —— 在 firewalld 默认 zone 中精确确保指定 TCP 端口放行。
# 仅接受一个升序去重的十进制端口 CSV 参数，同时添加 runtime 与 permanent 规则。
# 不删除规则、不 reload、不修改端口清单以外的配置。
# 退出码: 0=成功 1=执行失败 2=用法或参数错误
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

command -v logger >/dev/null 2>&1 || die "缺少必需命令: logger"

fail() {
  local message="$1" code="${2:-1}"
  log_err "$message"
  logger -t jiuzhang-hostctl -- "firewall_ensure_failed reason=$message" || true
  exit "$code"
}

[[ $# -eq 1 ]] || fail "用法: firewall-ensure.sh <升序去重端口CSV>" 2
PORTS_CSV="$1"
[[ "$PORTS_CSV" =~ ^[1-9][0-9]{0,4}(,[1-9][0-9]{0,4})*$ ]] \
  || fail "端口清单必须为十进制整数 CSV，每项 1..65535: ${PORTS_CSV:-<空>}" 2

IFS=',' read -r -a PORTS <<< "$PORTS_CSV"
(( ${#PORTS[@]} >= 1 && ${#PORTS[@]} <= 128 )) \
  || fail "端口清单必须包含 1..128 项: ${#PORTS[@]}" 2

previous=0
for port in "${PORTS[@]}"; do
  port_number=$((10#$port))
  (( port_number >= 1 && port_number <= 65535 )) \
    || fail "端口超出 1..65535: $port" 2
  (( port_number > previous )) || fail "端口必须严格升序且无重复: $PORTS_CSV" 2
  previous="$port_number"
done

command -v firewall-cmd >/dev/null 2>&1 \
  || fail "firewalld 不可用：缺少 firewall-cmd，未修改防火墙"
firewall-cmd --state >/dev/null 2>&1 \
  || fail "firewalld 未运行或状态查询失败，未修改防火墙"
DEFAULT_ZONE="$(firewall-cmd --get-default-zone 2>/dev/null)" \
  || fail "无法获取 firewalld 默认 zone，未修改防火墙"
[[ "$DEFAULT_ZONE" =~ ^[A-Za-z0-9_.-]+$ ]] \
  || fail "firewalld 默认 zone 返回非法值，未修改防火墙"

for port in "${PORTS[@]}"; do
  firewall-cmd --zone="$DEFAULT_ZONE" --add-port="${port}/tcp" \
    || fail "添加 runtime 端口失败: zone=$DEFAULT_ZONE port=$port/tcp"
  firewall-cmd --permanent --zone="$DEFAULT_ZONE" --add-port="${port}/tcp" \
    || fail "添加 permanent 端口失败: zone=$DEFAULT_ZONE port=$port/tcp"
done

logger -t jiuzhang-hostctl -- "firewall_ensure_completed zone=$DEFAULT_ZONE ports=$PORTS_CSV"
log_info "firewalld 默认 zone=$DEFAULT_ZONE 已确保 runtime+permanent 放行: ${PORTS_CSV//,/、}/tcp"
