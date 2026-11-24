#!/usr/bin/env bash
# CentOS 7 / openEuler 压测机多源 IP 池配置脚本（聚信压测工具多客户端子网模拟，突破单 IP 65535 临时端口上限）
# 用法:
#   sudo bash setup-multi-ip.sh up     --iface ens1f0 --prefix 10.10.1 --start 101 --count 32 --mask 24
#   sudo bash setup-multi-ip.sh status --iface ens1f0
#   sudo bash setup-multi-ip.sh down   --iface ens1f0 --prefix 10.10.1 --start 101 --count 32 --mask 24
set -euo pipefail

ACTION="${1:-}"
shift || true

IFACE=""
PREFIX=""
START=101
COUNT=32
MASK=24

usage() {
  cat <<'EOF'
用法: setup-multi-ip.sh <up|down|status> [选项]

作用：在压测机万兆网卡上批量添加/清理连续辅助源 IP，供 l7bench --local-ips 轮询绑定，
      突破 Linux 单 IP 约 5 万临时端口墙（测高 CPS 与 10 万+ 并发连接必备）。

选项:
  --iface IFACE    网卡名（如 ens1f0）
  --prefix A.B.C   IPv4 前三段（如 10.10.1）
  --start N        起始末段（默认 101，即 10.10.1.101）
  --count N        添加数量（默认 32，范围 1..200；32 个 IP ≈ 160 万可用源端口）
  --mask CIDR      子网掩码位（默认 24）
  -h, --help       显示帮助

示例:
  sudo bash setup-multi-ip.sh up --iface ens1f0 --prefix 10.10.1 --start 101 --count 32 --mask 24
  # 对应 l7bench 参数: -local-ips 10.10.1.101-10.10.1.132
EOF
}

if [[ -z "$ACTION" || "$ACTION" == "-h" || "$ACTION" == "--help" ]]; then
  usage
  exit 0
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --iface) IFACE="$2"; shift 2 ;;
    --prefix) PREFIX="$2"; shift 2 ;;
    --start) START="$2"; shift 2 ;;
    --count) COUNT="$2"; shift 2 ;;
    --mask) MASK="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "未知参数: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ -n "$IFACE" ]] || { echo "错误: 必须指定 --iface" >&2; exit 2; }

if [[ "$ACTION" == "status" ]]; then
  ip -4 addr show dev "$IFACE"
  exit 0
fi

[[ "$(id -u)" -eq 0 ]] || { echo "错误: up/down 操作需要 root 权限（请使用 sudo）" >&2; exit 1; }
[[ -n "$PREFIX" ]] || { echo "错误: 必须指定 --prefix（如 10.10.1）" >&2; exit 2; }
if (( START < 1 || START + COUNT - 1 > 254 || COUNT < 1 )); then
  echo "错误: IP 末段范围非法 (start=${START}, count=${COUNT})" >&2
  exit 2
fi

END=$(( START + COUNT - 1 ))
case "$ACTION" in
  up)
    for (( i = START; i <= END; i++ )); do
      ip addr replace "${PREFIX}.${i}/${MASK}" dev "$IFACE"
    done
    echo "[multi-ip] 已在 ${IFACE} 配置 ${COUNT} 个源 IP: ${PREFIX}.${START}-${PREFIX}.${END}/${MASK}"
    echo "[multi-ip] l7bench 可直接使用: -local-ips ${PREFIX}.${START}-${PREFIX}.${END}"
    ;;
  down)
    for (( i = START; i <= END; i++ )); do
      ip addr del "${PREFIX}.${i}/${MASK}" dev "$IFACE" 2>/dev/null || true
    done
    echo "[multi-ip] 已清理 ${IFACE} 上的 ${PREFIX}.${START}-${PREFIX}.${END}/${MASK}"
    ;;
  *)
    echo "错误: 未知动作 ${ACTION}（支持 up | down | status）" >&2
    exit 2
    ;;
esac
