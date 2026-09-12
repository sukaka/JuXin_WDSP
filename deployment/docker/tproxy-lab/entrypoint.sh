#!/bin/sh
# 九章阶段D 透明串接（透明代理）PoC 实验容器入口
# 设计依据：docs/NETWORK_MODES_DESIGN.md §4.3
#
# 单容器内以 network namespace 模拟二层串接（Docker 网桥间无法真二层桥接，
# 这是无交换机环境下的标准模拟法）：
#
#   client ns(192.168.50.10/24) ──veth── br0 ──veth── origin ns(192.168.50.20/24)
#                 （客户端与源站同网段，零代理配置，按普通直连访问源站）
#
# 数据面：bridge-nf-call-iptables=1 使桥接流量过 iptables → nat/PREROUTING
# REDIRECT 把桥上 tcp/8081 与 tcp/443 流量牵引到本机 tproxyd → tproxyd 读
# SO_ORIGINAL_DST 得原始目的：
#   - 明文 HTTP → 向 loopback 上的 Caddy（:8080）前置 PROXY protocol v1；
#   - TLS 且 SNI∈防护清单（www.test.com）→ 同样前置 PROXY v1 送 Caddy TLS
#     监听器（127.0.0.1:8443，自签名证书终结）检测回源；
#   - TLS 且 SNI∉清单（www.test1.com）→ 按原始目的直接 TCP 透传回源站
#     （origin ns 内 openssl s_server 携带 test1.com 证书终结），TLS 端到端
#     不断开、不注入 PROXY 头，WAF 无需该域名证书。
#
# fail-open：看门狗周期探测 tproxyd/caddy 存活，任一死亡即 flush 牵引链
# （桥接恢复二层直通、流量不再检测），随后看门狗退出监控职责、PID1 驻留维持
# 拓扑（避免故障持续时重启震荡），恢复由编排/运维重启容器完成。
set -u

BR=br0
CLIENT_NS=client
ORIGIN_NS=origin
CLIENT_IP=192.168.50.10
ORIGIN_IP=192.168.50.20
BR_IP=192.168.50.1
ORIGIN_PORT=8081
ORIGIN_TLS_PORT=443
TPROXY_PORT=15000
PROTECT_DOMAIN=www.test.com
PASS_DOMAIN=www.test1.com
CERTDIR=/etc/caddy/certs
CHAIN=TPROXYLAB
WATCHDOG_INTERVAL=${WATCHDOG_INTERVAL:-5}

log() { echo "[lab] $*"; }
fail() { log "FATAL: $*"; exit 1; }

# alive 判定含僵尸检查：PID1 为 shell 时，被杀的子进程可能短暂处于僵尸态，
# 此时 kill -0 仍返回成功，必须看 /proc 状态字段
alive() {
  [ -n "$1" ] && [ -f "/proc/$1/stat" ] || return 1
  [ "$(cut -d' ' -f3 "/proc/$1/stat")" != "Z" ]
}

# 等待本地监听出现（netstat 观察，不向端口发起探测连接——探测连接会被
# tproxyd 当作未牵引连接计入 origdst 错误）
wait_listen() { # pattern [netns] [max_iters=60]
  local pat="$1" ns="${2:-}" n="${3:-60}" i
  for i in $(seq 1 "$n"); do
    if [ -n "$ns" ]; then
      ip netns exec "$ns" netstat -ltn 2>/dev/null | grep -q "$pat" && return 0
    else
      netstat -ltn 2>/dev/null | grep -q "$pat" && return 0
    fi
    sleep 0.5
  done
  return 1
}

install_redirect() {
  iptables -t nat -N "$CHAIN" 2>/dev/null || true
  iptables -t nat -F "$CHAIN"
  iptables -t nat -A "$CHAIN" -p tcp --dport "$ORIGIN_PORT" -j REDIRECT --to-ports "$TPROXY_PORT" \
    || fail "REDIRECT 规则安装失败（xt_NAT/REDIRECT 不可用？）"
  iptables -t nat -A "$CHAIN" -p tcp --dport "$ORIGIN_TLS_PORT" -j REDIRECT --to-ports "$TPROXY_PORT" \
    || fail "HTTPS REDIRECT 规则安装失败"
  iptables -t nat -C PREROUTING -i "$BR" -j "$CHAIN" 2>/dev/null || \
    iptables -t nat -A PREROUTING -i "$BR" -j "$CHAIN"
  log "牵引规则已安装: nat/PREROUTING -i $BR -j $CHAIN; $CHAIN: tcp/$ORIGIN_PORT + tcp/$ORIGIN_TLS_PORT REDIRECT --> :$TPROXY_PORT"
}

flush_redirect() {
  iptables -t nat -F "$CHAIN" 2>/dev/null || true
  log "牵引规则已清除（nat/$CHAIN 已 flush），桥接恢复二层直通"
}

# ---------- 1. 二层桥接拓扑（幂等重建，容器重启后可重入） ----------
mount --make-rprivate / 2>/dev/null || true # ip netns 需挂载命名空间句柄
ip link set lo up 2>/dev/null || true       # network_mode: none 时确保 loopback 可用
ip netns del "$CLIENT_NS" 2>/dev/null || true
ip netns del "$ORIGIN_NS" 2>/dev/null || true
ip link del "$BR" 2>/dev/null || true

ip link add "$BR" type bridge || fail "创建网桥失败"
ip addr add "$BR_IP/24" dev "$BR"
ip link set "$BR" type bridge stp_state 0
ip link set "$BR" up

ip link add veth-c type veth peer name veth-client
ip link add veth-o type veth peer name veth-origin
ip link set veth-c master "$BR" up
ip link set veth-o master "$BR" up

ip netns add "$CLIENT_NS" || fail "创建 client netns 失败"
ip netns add "$ORIGIN_NS" || fail "创建 origin netns 失败"
ip link set veth-client netns "$CLIENT_NS"
ip link set veth-origin netns "$ORIGIN_NS"
ip netns exec "$CLIENT_NS" ip link set lo up
ip netns exec "$CLIENT_NS" ip addr add "$CLIENT_IP/24" dev veth-client
ip netns exec "$CLIENT_NS" ip link set veth-client up
ip netns exec "$ORIGIN_NS" ip link set lo up
ip netns exec "$ORIGIN_NS" ip addr add "$ORIGIN_IP/24" dev veth-origin
ip netns exec "$ORIGIN_NS" ip link set veth-origin up
log "拓扑就绪: $CLIENT_NS($CLIENT_IP) --veth-- $BR($BR_IP) --veth-- $ORIGIN_NS($ORIGIN_IP)"

# ---------- 2. 内核参数：桥接 IP 流量过 iptables（br_netfilter） ----------
sysctl -w net.bridge.bridge-nf-call-iptables=1 >/dev/null || fail "bridge-nf-call-iptables 不可用"
[ "$(cat /proc/sys/net/bridge/bridge-nf-call-iptables)" = "1" ] || fail "bridge-nf-call-iptables 未生效"

# ---------- 3. 在 origin ns 内启动测试源站（桥后真实服务器） ----------
ip netns exec "$ORIGIN_NS" env ORIGIN_ADDR=":$ORIGIN_PORT" \
  /usr/bin/testorigin >/var/log/lab/testorigin.log 2>&1 &
ORIGIN_PID=$!
wait_listen ":$ORIGIN_PORT" "$ORIGIN_NS" || fail "testorigin 未在 origin ns 监听 :$ORIGIN_PORT"
log "testorigin 已启动（origin ns $ORIGIN_IP:$ORIGIN_PORT, pid=$ORIGIN_PID）"

# ---------- 3.5 实验自签名证书 + origin ns 内 TLS 源站（SNI 分流实验） ----------
# 两张证书：PROTECT_DOMAIN 给 Caddy TLS 站点（清单内域名终结检测）；
# PASS_DOMAIN 给源站 s_server（清单外域名端到端透传，WAF 不持有其私钥以外
# 的任何角色——证书/私钥只存在于源站侧）。
mkdir -p "$CERTDIR"
for d in "$PROTECT_DOMAIN" "$PASS_DOMAIN"; do
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout "$CERTDIR/$d.key" -out "$CERTDIR/$d.crt" \
    -subj "/CN=$d" -addext "subjectAltName=DNS:$d" >/dev/null 2>&1 \
    || fail "自签名证书生成失败: $d"
done
log "自签名证书就绪: $PROTECT_DOMAIN（Caddy 终结）、$PASS_DOMAIN（源站终结）"

ip netns exec "$ORIGIN_NS" openssl s_server -accept "$ORIGIN_TLS_PORT" \
  -cert "$CERTDIR/$PASS_DOMAIN.crt" -key "$CERTDIR/$PASS_DOMAIN.key" -www \
  >/var/log/lab/s_server.log 2>&1 &
SSERVER_PID=$!
wait_listen ":$ORIGIN_TLS_PORT" "$ORIGIN_NS" || fail "s_server 未在 origin ns 监听 :$ORIGIN_TLS_PORT"
log "TLS 源站已启动（origin ns $ORIGIN_IP:$ORIGIN_TLS_PORT, s_server pid=$SSERVER_PID, CN=$PASS_DOMAIN）"

# ---------- 4. 启动 Caddy（loopback；proxy_protocol wrapper + coraza + 反代源站） ----------
SEC_RULE_ENGINE="${SEC_RULE_ENGINE:-On}" \
  caddy run --config /etc/caddy/Caddyfile --adapter caddyfile &
CADDY_PID=$!
alive "$CADDY_PID" || fail "caddy 启动即退出"
# CRS 全量规则编译较慢（实测可达 30s+），放宽等待
wait_listen "127.0.0.1:8080" "" 240 || fail "caddy 未监听 127.0.0.1:8080"
wait_listen "127.0.0.1:8443" "" 60 || fail "caddy 未监听 127.0.0.1:8443（TLS 站点）"
log "caddy 已启动（127.0.0.1:8080 + 127.0.0.1:8443, pid=$CADDY_PID, SEC_RULE_ENGINE=${SEC_RULE_ENGINE:-On}）"

# ---------- 5. 安装 REDIRECT 牵引规则 ----------
install_redirect

# ---------- 6. 启动 tproxyd 牵引进程（SNI 分流：清单内终结检测、清单外透传） ----------
TPROXY_LISTEN="${TPROXY_LISTEN:-0.0.0.0:$TPROXY_PORT}" \
TPROXY_TARGET="${TPROXY_TARGET:-127.0.0.1:8080}" \
TPROXY_TARGET_TLS="${TPROXY_TARGET_TLS:-127.0.0.1:8443}" \
TPROXY_PROTECT_HOSTS="${TPROXY_PROTECT_HOSTS:-$PROTECT_DOMAIN}" \
  tproxyd &
TPD_PID=$!
alive "$TPD_PID" || fail "tproxyd 启动即退出"
wait_listen ":$TPROXY_PORT" || fail "tproxyd 未监听 :$TPROXY_PORT"
log "ready: 透明牵引数据面就绪（client ns 内零配置直连 $ORIGIN_IP:$ORIGIN_PORT/$ORIGIN_TLS_PORT；HTTPS 按 SNI 分流，防护清单=[$PROTECT_DOMAIN]）"

# ---------- 7. 看门狗：任一关键进程死亡 → fail-open（清规则直通）并驻留 ----------
while true; do
  sleep "$WATCHDOG_INTERVAL"
  DEAD=""
  alive "$TPD_PID" || DEAD="tproxyd(pid=$TPD_PID)"
  alive "$CADDY_PID" || DEAD="${DEAD:+$DEAD }caddy(pid=$CADDY_PID)"
  if [ -n "$DEAD" ]; then
    log "watchdog: 检测到进程退出: $DEAD"
    flush_redirect
    log "watchdog: fail-open 生效（桥接直通，流量不再检测）；看门狗退出监控，等待编排/运维重启容器恢复"
    # PID1 驻留以维持 netns/桥接拓扑（fail-open 稳态）；docker restart 后本脚本
    # 从头重建拓扑并恢复检测
    exec sleep infinity
  fi
done
