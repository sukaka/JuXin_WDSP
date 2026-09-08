#!/usr/bin/env bash
# 九章 havipd 主备 VIP 组件 lab 验证（privileged 容器内真实 keepalived）
# 契约：/var/run/caddy/sidecars/ha-vip.json → ha-vip-status.json
# 拓扑：容器接入 docker bridge（eth0 自动获址），keepalived 在其上绑 VIP。
# 依赖：docker compose -f gateway/havipd/lab/docker-compose.havip-lab.yml up -d
# 用法：bash gateway/havipd/lab/havip-lab-tests.sh
set -u

LAB=haviplab-lab
SIDE=/var/run/caddy/sidecars
CFG=$SIDE/ha-vip.json
ST=$SIDE/ha-vip-status.json
RUN_ID="haviprun$(date +%s)"

TOTAL=0; PASS=0; FAIL=0; SKIP=0; FAILED=()
record() { # name ok(1/0/SKIP) [detail]
  local name="$1" ok="$2" detail="${3:-}"
  if [ "$ok" = "SKIP" ]; then
    SKIP=$((SKIP+1)); echo "SKIP  $name${detail:+ ($detail)}"; return
  fi
  TOTAL=$((TOTAL+1))
  if [ "$ok" = "1" ]; then PASS=$((PASS+1)); echo "PASS  $name"
  else FAIL=$((FAIL+1)); FAILED+=("$name: $detail"); echo "FAIL  $name ($detail)"; fi
}
jget() { python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print($1)" 2>/dev/null; }
# 存活 keepalived 判定：容器 PID1（sleep）不回收子进程，已退出的 keepalived 以
# zombie 残留导致 pidof 误报；须排除 Z 状态。
live_keepalived() {
  docker exec "$LAB" sh -c "ps -o stat,comm | awk '\$2==\"keepalived\" && \$1 !~ /^Z/ {f=1} END{exit !f}'"
}
wait_cond() { # desc cmd...
  local desc="$1"; shift; local i
  for i in $(seq 1 30); do
    "$@" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  echo "[err] 等待超时: $desc"; return 1
}
wcfg() { docker exec -i "$LAB" sh -c "cat > $CFG"; }
stget() { docker exec "$LAB" cat "$ST" 2>/dev/null; }

# VIP 取容器 eth0 网段内一个空闲地址（docker bridge 一般为 172.x.0.0/16）
ETH0_IP=$(docker exec "$LAB" sh -c "ip -4 -o addr show eth0 | awk '{print \$4}'" | cut -d/ -f1)
VIP_PREFIX=$(echo "$ETH0_IP" | cut -d. -f1-2)
VIP="$VIP_PREFIX.250.100/16"
VIP_ADDR=$(echo "$VIP" | cut -d/ -f1)

echo "============================================================"
echo "九章 havipd 主备 VIP 组件 lab 验证  run=$RUN_ID"
echo "拓扑: eth0=${ETH0_IP}（docker bridge）, VIP=$VIP"
echo "契约: ha-vip.json → keepalived 生命周期 → ha-vip-status.json"
echo "============================================================"

# ---------- 0. 前提与归零 ----------
echo ""
echo "---- 0. 前提与归零 ----"
docker ps --format '{{.Names}}' | grep -qx "$LAB" || { echo "ERROR: 容器 $LAB 未运行，请先 up 编排"; exit 1; }
docker exec "$LAB" sh -c '
  pidof havipd >/dev/null 2>&1 && kill "$(pidof havipd)" 2>/dev/null
  pidof keepalived >/dev/null 2>&1 && kill "$(pidof keepalived)" 2>/dev/null
  sleep 0.5
  rm -f /var/run/caddy/sidecars/ha-vip.json /var/run/caddy/sidecars/ha-vip-status.json \
        /var/run/caddy/sidecars/keepalived/*
  true'
docker exec "$LAB" sh -c "command -v keepalived >/dev/null" \
  && record "t0-keepalived-installed" 1 || record "t0-keepalived-installed" 0 "keepalived 未安装"
docker exec "$LAB" sh -c "command -v havipd >/dev/null" \
  && record "t0-havipd-installed" 1 || record "t0-havipd-installed" 0 "havipd 未安装"

# ---------- 1. ENABLED 下发：生成配置 + 启动 keepalived + 绑 VIP + MASTER ----------
echo ""
echo "---- 1. ENABLED 全链路 ----"
wcfg <<EOF
{"group":"ha-main","state":"ENABLED",
 "members":[{"node":"gw-a","priority":120},{"node":"gw-b","priority":100}],
 "vrrp":{"vrid":51,"vips":["$VIP"],"iface":"eth0","preempt":false,"advert_int_ms":1000,"auth_pass":"v1psecr8"},
 "updated_at":"$RUN_ID-t1"}
EOF
docker exec -d "$LAB" sh -c 'havipd --node gw-a --config-interval 1 --state-interval 1 >/var/log/havipd.log 2>&1'
wait_cond "生成 keepalived 配置" docker exec "$LAB" sh -c "test -f $SIDE/keepalived/ha-main.conf" \
  && record "t1-conf-generated" 1 || record "t1-conf-generated" 0 "conf 未生成"
CONF=$(docker exec "$LAB" cat "$SIDE/keepalived/ha-main.conf" 2>/dev/null)
echo "[info] keepalived 配置:"; echo "$CONF" | sed 's/^/  /'
echo "$CONF" | grep -q "priority 120" && record "t1-conf-priority" 1 || record "t1-conf-priority" 0 "$CONF"
echo "$CONF" | grep -q "nopreempt" && record "t1-conf-nopreempt" 1 || record "t1-conf-nopreempt" 0 "$CONF"
PERM=$(docker exec "$LAB" sh -c "stat -c %a $SIDE/keepalived/ha-main.conf 2>/dev/null")
[ "$PERM" = "600" ] && record "t1-conf-perm-0600" 1 || record "t1-conf-perm-0600" 0 "perm=$PERM"
wait_cond "keepalived 进程运行" docker exec "$LAB" pidof keepalived \
  && record "t1-keepalived-running" 1 || record "t1-keepalived-running" 0 "pidof 为空"
wait_cond "VIP 绑定到 eth0" docker exec "$LAB" sh -c "ip addr show eth0 | grep -q $VIP_ADDR" \
  && record "t1-vip-bound" 1 || record "t1-vip-bound" 0 "$(docker exec "$LAB" ip addr show eth0)"
wait_cond "status 为 MASTER" docker exec "$LAB" sh -c "grep -q '\"state\":\"MASTER\"' $ST" \
  && record "t1-status-master" 1 || record "t1-status-master" 0 "$(stget)"
STATUS=$(stget)
echo "[info] status: $STATUS"
[ "$(echo "$STATUS" | jget "d.get('node')")" = "gw-a" ] && record "t1-status-node" 1 || record "t1-status-node" 0 "$STATUS"
[ "$(echo "$STATUS" | jget "d.get('keepalived_running')")" = "True" ] && record "t1-status-running" 1 || record "t1-status-running" 0 "$STATUS"
[ "$(echo "$STATUS" | jget "len(d.get('vips_present',[]))")" = "1" ] && record "t1-status-vips" 1 || record "t1-status-vips" 0 "$STATUS"
[ "$(echo "$STATUS" | jget "len(d.get('events',[]))")" -ge 1 ] && record "t1-status-events" 1 || record "t1-status-events" 0 "$STATUS"
echo "$STATUS" | grep -q "v1psecr8" && record "t1-status-no-secret" 0 "status 泄露认证串" || record "t1-status-no-secret" 1
docker exec "$LAB" sh -c "ping -c1 -W2 $VIP_ADDR >/dev/null" \
  && record "t1-vip-pingable" 1 || record "t1-vip-pingable" 0 "VIP 不可达"

# ---------- 2. 配置变更：advert 调整 → SIGHUP 重载（进程不重启） ----------
echo ""
echo "---- 2. 配置变更重载 ----"
KPID1=$(docker exec "$LAB" pidof keepalived | awk '{print $1}')
wcfg <<EOF
{"group":"ha-main","state":"ENABLED",
 "members":[{"node":"gw-a","priority":120},{"node":"gw-b","priority":100}],
 "vrrp":{"vrid":51,"vips":["$VIP"],"iface":"eth0","preempt":false,"advert_int_ms":2000,"auth_pass":"v1psecr8"},
 "updated_at":"$RUN_ID-t2"}
EOF
sleep 3
KPID2=$(docker exec "$LAB" pidof keepalived | awk '{print $1}')
[ "$KPID1" = "$KPID2" ] && [ -n "$KPID1" ] \
  && record "t2-reload-no-restart" 1 || record "t2-reload-no-restart" 0 "pid 变化（$KPID1 → $KPID2）"
docker exec "$LAB" sh -c "grep -q 'advert_int 2' $SIDE/keepalived/ha-main.conf" \
  && record "t2-conf-updated" 1 || record "t2-conf-updated" 0 "$(docker exec "$LAB" cat "$SIDE/keepalived/ha-main.conf")"

# ---------- 3. DISABLED：实例停止 + VIP 释放 ----------
echo ""
echo "---- 3. DISABLED ----"
wcfg <<EOF
{"group":"ha-main","state":"DISABLED",
 "members":[{"node":"gw-a","priority":120},{"node":"gw-b","priority":100}],
 "vrrp":{"vrid":51,"vips":["$VIP"],"iface":"eth0","preempt":false,"advert_int_ms":1000},
 "updated_at":"$RUN_ID-t3"}
EOF
wait_cond "keepalived 停止" sh -c '! live_keepalived' \
  && record "t3-keepalived-stopped" 1 || record "t3-keepalived-stopped" 0 "keepalived 仍在运行"
wait_cond "VIP 已释放" docker exec "$LAB" sh -c "! ip addr show eth0 | grep -q $VIP_ADDR" \
  && record "t3-vip-released" 1 || record "t3-vip-released" 0 "VIP 仍绑定"
wait_cond "status 为 DISABLED" docker exec "$LAB" sh -c "grep -q '\"state\":\"DISABLED\"' $ST" \
  && record "t3-status-disabled" 1 || record "t3-status-disabled" 0 "$(stget)"

# ---------- 4. 重新 ENABLED 恢复 ----------
echo ""
echo "---- 4. 重新 ENABLED ----"
wcfg <<EOF
{"group":"ha-main","state":"ENABLED",
 "members":[{"node":"gw-a","priority":120},{"node":"gw-b","priority":100}],
 "vrrp":{"vrid":51,"vips":["$VIP"],"iface":"eth0","preempt":false,"advert_int_ms":1000},
 "updated_at":"$RUN_ID-t4"}
EOF
wait_cond "VIP 重新绑定" docker exec "$LAB" sh -c "ip addr show eth0 | grep -q $VIP_ADDR" \
  && record "t4-vip-rebound" 1 || record "t4-vip-rebound" 0 "VIP 未恢复"
wait_cond "status 回 MASTER" docker exec "$LAB" sh -c "grep -q '\"state\":\"MASTER\"' $ST" \
  && record "t4-status-master-again" 1 || record "t4-status-master-again" 0 "$(stget)"

# ---------- 5. 配置收回（删除）→ 停止实例回 STOPPED ----------
echo ""
echo "---- 5. 配置收回 ----"
docker exec "$LAB" rm -f "$CFG"
wait_cond "收回后 keepalived 停止" sh -c '! live_keepalived' \
  && record "t5-keepalived-stopped" 1 || record "t5-keepalived-stopped" 0 "keepalived 仍在运行"
wait_cond "收回后 VIP 已释放" docker exec "$LAB" sh -c "! ip addr show eth0 | grep -q $VIP_ADDR" \
  && record "t5-vip-released" 1 || record "t5-vip-released" 0 "VIP 仍绑定"
wait_cond "status 回 STOPPED" docker exec "$LAB" sh -c "grep -q '\"state\":\"STOPPED\"' $ST" \
  && record "t5-status-stopped" 1 || record "t5-status-stopped" 0 "$(stget)"

# ---------- 6. 坏配置：last-good 保留 + 不 crash-loop ----------
echo ""
echo "---- 6. 坏配置 ----"
wcfg <<EOF
{"group":"ha-main","state":"ENABLED",
 "members":[{"node":"gw-a","priority":120},{"node":"gw-b","priority":100}],
 "vrrp":{"vrid":51,"vips":["$VIP"],"iface":"eth0","advert_int_ms":1000},
 "updated_at":"$RUN_ID-t6"}
EOF
wait_cond "好配置生效（VIP 绑定）" docker exec "$LAB" sh -c "ip addr show eth0 | grep -q $VIP_ADDR" \
  && record "t6-good-config-first" 1 || record "t6-good-config-first" 0 "好配置未生效"
echo '{broken' | wcfg
sleep 3
HPID1=$(docker exec "$LAB" pidof havipd | awk '{print $1}')
STATUS=$(stget)
echo "$(echo "$STATUS" | jget "d.get('message','')")" | grep -q "配置不可用" \
  && record "t6-badcfg-message" 1 || record "t6-badcfg-message" 0 "$STATUS"
docker exec "$LAB" sh -c "ip addr show eth0 | grep -q $VIP_ADDR" \
  && record "t6-keeps-last-good" 1 || record "t6-keeps-last-good" 0 "坏配置影响了运行中实例"
HPID2=$(docker exec "$LAB" pidof havipd | awk '{print $1}')
[ "$HPID1" = "$HPID2" ] && [ -n "$HPID1" ] \
  && record "t6-no-crashloop" 1 || record "t6-no-crashloop" 0 "havipd pid 变化（$HPID1 → $HPID2）"

# ---------- 7. 非本节点配置：不启动实例 ----------
echo ""
echo "---- 7. 非本节点配置 ----"
docker exec "$LAB" sh -c 'pidof keepalived >/dev/null 2>&1 && kill "$(pidof keepalived)" 2>/dev/null; true'
wcfg <<EOF
{"group":"ha-other","state":"ENABLED",
 "members":[{"node":"gw-c","priority":120},{"node":"gw-b","priority":100}],
 "vrrp":{"vrid":52,"vips":["$VIP"],"iface":"eth0","advert_int_ms":1000},
 "updated_at":"$RUN_ID-t7"}
EOF
sleep 3
live_keepalived \
  && record "t7-not-my-group" 0 "非本节点却启动了 keepalived" || record "t7-not-my-group" 1
STATUS=$(stget)
echo "$(echo "$STATUS" | jget "d.get('message','')")" | grep -q "不含本节点" \
  && record "t7-not-my-message" 1 || record "t7-not-my-message" 0 "$STATUS"

# 清理
docker exec "$LAB" sh -c 'pidof havipd >/dev/null 2>&1 && kill "$(pidof havipd)" 2>/dev/null; true'
echo "[info] havipd 日志:"; docker exec "$LAB" cat /var/log/havipd.log 2>/dev/null | tail -8 | sed 's/^/  /'

echo ""
echo "============================================================"
echo "结果: PASS=$PASS FAIL=$FAIL SKIP=$SKIP (计入统计 TOTAL=$TOTAL)"
if [ "$FAIL" -gt 0 ]; then
  echo "失败用例:"
  for f in "${FAILED[@]}"; do echo "  - $f"; done
  exit 1
fi
echo "全部通过"
