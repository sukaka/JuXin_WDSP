#!/bin/sh
# 九章 netmgrd 网络执行组件 lab 实验容器入口
#
# 在容器独立 netns（network_mode: none）内自建实验拓扑，不触碰任何真实网络：
#   eth2/eth3/eth4  空闲口（veth pair，模拟物理业务口；up 后内核自动分配
#                   inet6 link-local，顺带覆盖「link 本地地址不算已配 IP」路径）
#   mgmt0           192.168.50.1/24（带 IP 的「管理口」：安全红线负例——
#                   列入桥成员必须报 error 且不执行；其连接路由同时为
#                   静态路由用例提供 on-link 下一跳网段 192.168.50.0/24）
#
# 入口只建拓扑并驻留；netmgrd 的执行与断言全部由
# gateway/netmgrd/lab/netmgr-lab-tests.sh 驱动（docker exec）。
set -u

log() { echo "[netmgr-lab] $*"; }
fail() { log "FATAL: $*"; exit 1; }

ip link set lo up 2>/dev/null || true # network_mode: none 时确保 loopback 可用

# 幂等重建（容器重启后可重入）
for p in eth2 eth3 eth4 mgmt0; do
  ip link del "$p" 2>/dev/null || true
done
for p in eth2 eth3 eth4; do
  ip link add "$p" type veth peer name "${p}-peer" || fail "创建 $p 失败"
  ip link set "$p" up || fail "拉起 $p 失败"
done
ip link add mgmt0 type veth peer name mgmt0-peer || fail "创建 mgmt0 失败"
ip addr add 192.168.50.1/24 dev mgmt0 || fail "配置 mgmt0 地址失败"
ip link set mgmt0 up || fail "拉起 mgmt0 失败"

# 干净起点：断言 netmgrd 会把 ip_forward 置 1（独立 netns，默认即 0，显式摆出）
sysctl -w net.ipv4.ip_forward=0 >/dev/null || fail "ip_forward 初始化失败"

# 边车契约目录（Dockerfile 已建，此处幂等兜底）
mkdir -p /var/run/caddy/sidecars

log "拓扑就绪: eth2/eth3/eth4 空闲口, mgmt0=192.168.50.1/24（带 IP 管理口）, ip_forward=0"
exec sleep infinity
