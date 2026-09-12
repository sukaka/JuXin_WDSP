#!/bin/sh
# 九章 havipd 主备 VIP 组件 lab 实验容器入口：
# 容器接入 docker bridge（eth0 自动获址），keepalived 在其上绑 VIP。
# 入口仅驻留；havipd 的启停与断言全部由 havip-lab-tests.sh 驱动（docker exec）。
set -u

ip link set lo up 2>/dev/null || true
mkdir -p /var/run/caddy/sidecars/keepalived
echo "[havip-lab] 拓扑就绪: eth0=$(ip -4 -o addr show eth0 | awk '{print $4}')（docker bridge）"
exec sleep infinity
