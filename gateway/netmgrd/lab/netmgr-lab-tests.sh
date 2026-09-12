#!/usr/bin/env bash
# 九章 netmgrd 网络执行组件 lab 验证（privileged 容器内真实执行）
# 组件契约：/var/run/caddy/sidecars/network.json → network-status.json
# 拓扑（容器独立 netns 自建，不触碰任何真实网络）：
#   eth2/eth3/eth4  空闲口（veth pair，模拟物理业务口）
#   mgmt0           192.168.50.1/24（带 IP 的「管理口」，安全红线负例）
# 依赖：docker compose -f gateway/netmgrd/lab/docker-compose.netmgr-lab.yml up -d
# 用法：bash gateway/netmgrd/lab/netmgr-lab-tests.sh
#
# 复跑方式（仓库根目录，全流程）：
#   cd gateway && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath \
#     -ldflags="-s -w" -o netmgrd/lab/bin/netmgrd ./cmd/netmgrd && cd ..
#   docker compose -f gateway/netmgrd/lab/docker-compose.netmgr-lab.yml build
#   docker compose -f gateway/netmgrd/lab/docker-compose.netmgr-lab.yml up -d
#   bash gateway/netmgrd/lab/netmgr-lab-tests.sh
#   docker compose -f gateway/netmgrd/lab/docker-compose.netmgr-lab.yml down -v
set -u

LAB=netmgrlab-lab
SIDE=/var/run/caddy/sidecars
CFG=$SIDE/network.json
ST=$SIDE/network-status.json
RUN_ID="netmgrrun$(date +%s)"

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
# JSON 字段提取（与 routed/mirror/transparent-lab 用例同一风格）
jget() { python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print($1)" 2>/dev/null; }
# 等待 lab 容器健康（≤60s）
wait_healthy() {
  local i
  for i in $(seq 1 60); do
    [ "$(docker inspect -f '{{.State.Health.Status}}' "$LAB" 2>/dev/null)" = "healthy" ] && return 0
    sleep 1
  done
  return 1
}
# 写期望配置（stdin 内容 → 容器内 network.json）
wcfg() { docker exec -i "$LAB" sh -c "cat > $CFG"; }
# 读执行状态
stget() { docker exec "$LAB" cat "$ST" 2>/dev/null; }
# 等待条件成立（≤15s，daemon 轮询 1s 留足余量）
wait_cond() { # desc cmd...
  local desc="$1"; shift; local i
  for i in $(seq 1 30); do
    "$@" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  echo "[err] 等待超时: $desc"; return 1
}
br_has_master() { docker exec "$LAB" sh -c "ip link show $1 2>/dev/null | grep -q 'master $2'"; }
# 无任何一行含 master（grep -qv 的逐行语义在多行输出下不可靠，故用 ! grep -q）
br_no_master() { docker exec "$LAB" sh -c "! ip link show $1 2>/dev/null | grep -q master"; }

echo "============================================================"
echo "九章 netmgrd 网络执行组件 lab 验证  run=$RUN_ID"
echo "拓扑: eth2/eth3/eth4 空闲口(veth), mgmt0=192.168.50.1/24(带 IP 管理口)"
echo "契约: network.json → 幂等执行(桥/转发/路由) → network-status.json"
echo "============================================================"

# ---------- 0. 拓扑前提 ----------
echo ""
echo "---- 0. 拓扑前提 ----"
docker ps --format '{{.Names}}' | grep -qx "$LAB" || { echo "ERROR: 容器 $LAB 未运行，请先 up 编排"; exit 1; }
# 复跑归零：清理上一轮可能残留的 daemon/桥/路由/转发/契约文件
# （容器内独立 netns，操作不触碰宿主机与任何真实网络）
docker exec "$LAB" sh -c '
  pidof netmgrd >/dev/null 2>&1 && kill "$(pidof netmgrd)" 2>/dev/null
  sleep 0.3
  for b in br0 br1 br2; do ip link del "$b" 2>/dev/null; done
  ip route del 10.9.0.0/24 2>/dev/null
  sysctl -w net.ipv4.ip_forward=0 >/dev/null
  rm -f /var/run/caddy/sidecars/network.json /var/run/caddy/sidecars/network-status.json
  true' || { echo "ERROR: 复跑归零失败"; exit 1; }
wait_healthy && record "t0-lab-healthy" 1 || record "t0-lab-healthy" 0 "容器 60s 内未就绪"
docker exec "$LAB" ip link show eth2 >/dev/null 2>&1 && record "t0-eth2-exists" 1 || record "t0-eth2-exists" 0 "eth2 不存在"
docker exec "$LAB" sh -c "ip addr show mgmt0 | grep -q 192.168.50.1" && record "t0-mgmt0-has-ip" 1 || record "t0-mgmt0-has-ip" 0 "mgmt0 无 192.168.50.1"
FWD=$(docker exec "$LAB" cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)
[ "$FWD" = "0" ] && record "t0-ip-forward-starts-0" 1 || record "t0-ip-forward-starts-0" 0 "ip_forward=$FWD（应为干净起点 0）"

# ---------- 1. 基本执行：建桥/收编成员/转发/路由 + status 契约 ----------
echo ""
echo "---- 1. 基本执行（--once） ----"
wcfg <<EOF
{"bridges":[{"name":"br0","ports":["eth2","eth3"]}],"ip_forward":true,"routes":[{"dst":"10.9.0.0/24","via":"192.168.50.254"}],"updated_at":"$RUN_ID-t1"}
EOF
OUT=$(docker exec "$LAB" netmgrd --once 2>&1); RC=$?
echo "[info] netmgrd --once 输出: $OUT"
[ "$RC" = "0" ] && record "t1-once-exit-0" 1 || record "t1-once-exit-0" 0 "rc=$RC out=$OUT"
docker exec "$LAB" ip link show br0 >/dev/null 2>&1 && record "t1-br0-created" 1 || record "t1-br0-created" 0 "br0 不存在"
docker exec "$LAB" sh -c "ip link show br0 | head -1 | grep -qw UP" && record "t1-br0-up" 1 || record "t1-br0-up" 0 "br0 未 UP"
br_has_master eth2 br0 && record "t1-eth2-master" 1 || record "t1-eth2-master" 0 "eth2 未入桥"
br_has_master eth3 br0 && record "t1-eth3-master" 1 || record "t1-eth3-master" 0 "eth3 未入桥"
FWD=$(docker exec "$LAB" cat /proc/sys/net/ipv4/ip_forward)
[ "$FWD" = "1" ] && record "t1-ip-forward-1" 1 || record "t1-ip-forward-1" 0 "ip_forward=$FWD"
docker exec "$LAB" sh -c "ip route show 10.9.0.0/24 | grep -q 'via 192.168.50.254'" \
  && record "t1-route-installed" 1 || record "t1-route-installed" 0 "路由不存在: $(docker exec "$LAB" ip route show 10.9.0.0/24)"
STATUS=$(stget)
echo "[info] status: $STATUS"
[ "$(echo "$STATUS" | jget "d.get('ok')")" = "True" ] && record "t1-status-ok" 1 || record "t1-status-ok" 0 "$STATUS"
[ "$(echo "$STATUS" | jget "d['bridges'][0]['state']")" = "ok" ] && record "t1-status-bridge-ok" 1 || record "t1-status-bridge-ok" 0 "$STATUS"
[ "$(echo "$STATUS" | jget "d.get('ip_forward')")" = "ok" ] && record "t1-status-ipfwd-ok" 1 || record "t1-status-ipfwd-ok" 0 "$STATUS"
[ "$(echo "$STATUS" | jget "d['routes'][0]['state']")" = "ok" ] && record "t1-status-route-ok" 1 || record "t1-status-route-ok" 0 "$STATUS"
AT=$(echo "$STATUS" | jget "d.get('applied_at','')")
{ [ -n "$AT" ] && [ "$AT" != "None" ]; } && record "t1-status-applied-at" 1 || record "t1-status-applied-at" 0 "applied_at 为空"

# ---------- 2. 幂等：重复执行无副作用 ----------
echo ""
echo "---- 2. 幂等重放 ----"
docker exec "$LAB" netmgrd --once >/dev/null 2>&1; RC=$?
[ "$RC" = "0" ] && record "t2-rerun-exit-0" 1 || record "t2-rerun-exit-0" 0 "rc=$RC"
NBR=$(docker exec "$LAB" sh -c "ip -o link show | grep -c ': br0:'")
[ "$NBR" = "1" ] && record "t2-br0-single" 1 || record "t2-br0-single" 0 "br0 数量=$NBR"
{ br_has_master eth2 br0 && br_has_master eth3 br0; } && record "t2-members-stable" 1 || record "t2-members-stable" 0 "重放后成员关系变化"

# ---------- 3. reconcile：补缺失成员 ----------
echo ""
echo "---- 3. reconcile 补缺失成员 ----"
docker exec "$LAB" ip link set eth3 nomaster
br_no_master eth3 && record "t3-setup-eth3-removed" 1 || record "t3-setup-eth3-removed" 0 "前置摘除失败"
docker exec "$LAB" netmgrd --once >/dev/null 2>&1
br_has_master eth3 br0 && record "t3-rejoin-missing-member" 1 || record "t3-rejoin-missing-member" 0 "eth3 未补挂回 br0"

# ---------- 4. reconcile：摘除期望外成员 ----------
echo ""
echo "---- 4. reconcile 摘除多余成员 ----"
docker exec "$LAB" ip link set eth4 master br0
br_has_master eth4 br0 && record "t4-setup-eth4-added" 1 || record "t4-setup-eth4-added" 0 "前置挂入失败"
docker exec "$LAB" netmgrd --once >/dev/null 2>&1
br_no_master eth4 && record "t4-extra-member-removed" 1 || record "t4-extra-member-removed" 0 "eth4 未被 nomaster"

# ---------- 5. 安全红线：带 IP 的口列入桥成员 → error 且不执行 ----------
echo ""
echo "---- 5. 安全红线（带 IP 管理口拒绝入桥） ----"
wcfg <<EOF
{"bridges":[{"name":"br0","ports":["eth2","mgmt0"]}],"ip_forward":true,"updated_at":"$RUN_ID-t5"}
EOF
OUT=$(docker exec "$LAB" netmgrd --once 2>&1); RC=$?
echo "[info] 红线用例输出: $OUT"
[ "$RC" != "0" ] && record "t5-exit-nonzero" 1 || record "t5-exit-nonzero" 0 "存在失败项应非零退出"
STATUS=$(stget)
[ "$(echo "$STATUS" | jget "d.get('ok')")" = "False" ] && record "t5-status-not-ok" 1 || record "t5-status-not-ok" 0 "$STATUS"
[ "$(echo "$STATUS" | jget "d['bridges'][0]['state']")" = "error" ] && record "t5-status-bridge-error" 1 || record "t5-status-bridge-error" 0 "$STATUS"
MSG=$(echo "$STATUS" | jget "d['bridges'][0].get('message','')")
echo "[info] 桥错误信息: $MSG"
echo "$MSG" | grep -q mgmt0 && record "t5-message-mentions-mgmt0" 1 || record "t5-message-mentions-mgmt0" 0 "msg=$MSG"
br_no_master mgmt0 && record "t5-mgmt0-not-enslaved" 1 || record "t5-mgmt0-not-enslaved" 0 "mgmt0 被拉进桥（红线失守）"
br_has_master eth2 br0 && record "t5-eth2-untouched" 1 || record "t5-eth2-untouched" 0 "红线用例不应变更既有成员"
docker exec "$LAB" ip link show br0 >/dev/null 2>&1 && record "t5-br0-not-torn-down" 1 || record "t5-br0-not-torn-down" 0 "br0 被拆除"

# ---------- 6. --dry-run：只打印不执行、不写 status ----------
echo ""
echo "---- 6. --dry-run ----"
AT_BEFORE=$(stget | jget "d.get('applied_at','')")
wcfg <<EOF
{"bridges":[{"name":"br1","ports":["eth4"]}],"ip_forward":false,"updated_at":"$RUN_ID-t6"}
EOF
DRY=$(docker exec "$LAB" netmgrd --dry-run 2>&1); RC=$?
echo "[info] dry-run 输出:"; echo "$DRY" | sed 's/^/  /'
[ "$RC" = "0" ] && record "t6-dry-exit-0" 1 || record "t6-dry-exit-0" 0 "rc=$RC out=$DRY"
echo "$DRY" | grep -q "ip link add br1 type bridge" && record "t6-dry-plans-add-bridge" 1 || record "t6-dry-plans-add-bridge" 0 "缺建桥计划"
echo "$DRY" | grep -q "ip link set eth4 master br1" && record "t6-dry-plans-enslave" 1 || record "t6-dry-plans-enslave" 0 "缺成员计划"
! echo "$DRY" | grep -q sysctl && record "t6-dry-no-sysctl" 1 || record "t6-dry-no-sysctl" 0 "ip_forward=false 不应计划 sysctl"
docker exec "$LAB" ip link show br1 >/dev/null 2>&1 && record "t6-dry-not-executed" 0 "br1 被真实创建" || record "t6-dry-not-executed" 1
AT_AFTER=$(stget | jget "d.get('applied_at','')")
[ "$AT_AFTER" = "$AT_BEFORE" ] && record "t6-dry-no-status-write" 1 || record "t6-dry-no-status-write" 0 "dry-run 改写了 status（$AT_BEFORE → $AT_AFTER）"

# ---------- 7. daemon 模式：轮询生效 / 坏配置保 last-good 不 crash-loop / 收回不拆除 ----------
echo ""
echo "---- 7. daemon 模式 ----"
wcfg <<EOF
{"bridges":[{"name":"br2","ports":["eth4"]}],"updated_at":"$RUN_ID-t7"}
EOF
docker exec -d "$LAB" sh -c 'netmgrd --interval 1 >/var/log/netmgrd.log 2>&1'
wait_cond "daemon 应用 br2" docker exec "$LAB" ip link show br2 \
  && record "t7-daemon-applies-change" 1 || record "t7-daemon-applies-change" 0 "15s 内未建 br2"
DPID1=$(docker exec "$LAB" pidof netmgrd 2>/dev/null)
[ -n "$DPID1" ] && record "t7-daemon-running" 1 || record "t7-daemon-running" 0 "pidof 为空"
echo '{broken' | wcfg
wait_cond "坏配置 status ok=false" docker exec "$LAB" sh -c "grep -q '\"ok\":false' $ST" \
  && record "t7-daemon-badcfg-status" 1 || record "t7-daemon-badcfg-status" 0 "15s 内未回写错误 status"
STATUS=$(stget)
echo "$(echo "$STATUS" | jget "d.get('message','')")" | grep -q "配置不可用" \
  && record "t7-daemon-badcfg-message" 1 || record "t7-daemon-badcfg-message" 0 "$STATUS"
docker exec "$LAB" ip link show br2 >/dev/null 2>&1 && record "t7-daemon-keeps-last-good" 1 || record "t7-daemon-keeps-last-good" 0 "br2 被拆除"
DPID2=$(docker exec "$LAB" pidof netmgrd 2>/dev/null)
[ "$DPID2" = "$DPID1" ] && record "t7-daemon-no-crashloop" 1 || record "t7-daemon-no-crashloop" 0 "pid 变化（$DPID1 → $DPID2），进程发生重启"
echo '{}' | wcfg
wait_cond "恢复后 status ok=true" docker exec "$LAB" sh -c "grep -q '\"ok\":true' $ST" \
  && record "t7-daemon-recovers" 1 || record "t7-daemon-recovers" 0 "15s 内未恢复 ok"
docker exec "$LAB" ip link show br2 >/dev/null 2>&1 && record "t7-daemon-no-teardown" 1 || record "t7-daemon-no-teardown" 0 "空配置拆除了 br2（只增不拆红线）"
docker exec "$LAB" kill -TERM "$DPID1" 2>/dev/null
GONE=0
for i in $(seq 1 10); do
  docker exec "$LAB" pidof netmgrd >/dev/null 2>&1 || { GONE=1; break; }
  sleep 0.5
done
[ "$GONE" = "1" ] && record "t7-daemon-sigterm-exits" 1 || record "t7-daemon-sigterm-exits" 0 "SIGTERM 后 5s 内未退出"
echo "[info] daemon 日志:"; docker exec "$LAB" cat /var/log/netmgrd.log 2>/dev/null | tail -8 | sed 's/^/  /'

# ---------- 8. 端口联动（Link-Pair）：carrier 监控/联动 down/恢复回 up/频率抑制 ----------
# 拓扑机制：veth 对两端共享载波——对端（ethX-peer）down 则本端掉 LOWER_UP，
# 用对端的 up/down 模拟物理链路断/通（全程容器独立 netns，零外溢）。
echo ""
echo "---- 8. 端口联动（Link-Pair） ----"
# 归零联动面：清契约文件，拉起两端 peer 使 eth2/eth3 获得载波
docker exec "$LAB" sh -c '
  pidof netmgrd >/dev/null 2>&1 && kill "$(pidof netmgrd)" 2>/dev/null
  sleep 0.3
  for b in br0 br1 br2; do ip link del "$b" 2>/dev/null; done
  ip link set eth2-peer up; ip link set eth3-peer up
  ip link set eth2 up; ip link set eth3 up
  rm -f /var/run/caddy/sidecars/network.json /var/run/caddy/sidecars/network-status.json
  true'
LP_HAS_CARRIER() { docker exec "$LAB" sh -c "ip link show $1 | grep -q LOWER_UP"; }
LP_HAS_CARRIER eth2 && LP_HAS_CARRIER eth3 \
  && record "t8-setup-carrier-on" 1 || record "t8-setup-carrier-on" 0 "peer up 后 eth2/eth3 应带 LOWER_UP"

# 下发联动配置（hold_down 500ms / hold_up 1000ms / 上限 2 次）并起 daemon
wcfg <<EOF
{"bridges":[{"name":"br0","ports":["eth2","eth3"],"link_pair":{"enabled":true,"hold_down_ms":500,"hold_up_ms":1000,"max_flaps_per_hour":2}}],"ip_forward":false,"routes":[],"updated_at":"$RUN_ID-t8"}
EOF
docker exec -d "$LAB" sh -c 'netmgrd --interval 1 >/var/log/netmgrd-lp.log 2>&1'
wait_cond "br0 建立且双口入桥" docker exec "$LAB" sh -c "ip link show br0 >/dev/null 2>&1 && ip link show eth2 | grep -q 'master br0' && ip link show eth3 | grep -q 'master br0'" \
  && record "t8-br0-ready" 1 || record "t8-br0-ready" 0 "br0/成员未就绪"
wait_cond "status 出现 link_pairs BOTH_UP" docker exec "$LAB" sh -c "grep -q '\"state\":\"BOTH_UP\"' $ST" \
  && record "t8-initial-both-up" 1 || record "t8-initial-both-up" 0 "$(stget)"

# 8.1 链路故障：eth2-peer down → eth2 掉 carrier → eth3 被联动 down + 标记
docker exec "$LAB" ip link set eth2-peer down
wait_cond "eth3 被联动 down" docker exec "$LAB" sh -c "ip link show eth3 | head -1 | grep -q 'state DOWN\|,DOWN'" \
  && record "t8-propagate-peer-down" 1 || record "t8-propagate-peer-down" 0 "eth3 未被联动 down: $(docker exec "$LAB" ip link show eth3 | head -1)"
STATUS=$(stget)
echo "[info] 联动后 status: $STATUS"
[ "$(echo "$STATUS" | jget "d['link_pairs'][0]['state']")" = "PROPAGATED_DOWN" ] \
  && record "t8-status-propagated" 1 || record "t8-status-propagated" 0 "$STATUS"
[ "$(echo "$STATUS" | jget "d['link_pairs'][0].get('propagated_by_linkpair')")" = "True" ] \
  && record "t8-status-marker" 1 || record "t8-status-marker" 0 "$STATUS"
[ "$(echo "$STATUS" | jget "d['link_pairs'][0].get('down_port','')")" = "eth2" ] \
  && record "t8-status-down-port" 1 || record "t8-status-down-port" 0 "$STATUS"

# 8.2 故障恢复：eth2-peer up → hold_up 后 eth3 回 up + 状态归位
docker exec "$LAB" ip link set eth2-peer up
wait_cond "eth3 恢复 up" docker exec "$LAB" sh -c "ip link show eth3 | grep -q LOWER_UP" \
  && record "t8-recover-peer-up" 1 || record "t8-recover-peer-up" 0 "eth3 未恢复 up: $(docker exec "$LAB" ip link show eth3 | head -1)"
wait_cond "status 回 BOTH_UP" docker exec "$LAB" sh -c "grep -q '\"state\":\"BOTH_UP\"' $ST" \
  && record "t8-status-both-up-again" 1 || record "t8-status-both-up-again" 0 "$(stget)"

# 8.3 频率抑制：上限 2 次——再制造 1 次联动后第 3 次故障应 SUPPRESSED 且不动作
docker exec "$LAB" ip link set eth2-peer down
wait_cond "第 2 次联动 down" docker exec "$LAB" sh -c "ip link show eth3 | head -1 | grep -q 'state DOWN\|,DOWN'" \
  && record "t8-second-flap" 1 || record "t8-second-flap" 0 "第 2 次联动未发生"
docker exec "$LAB" ip link set eth2-peer up
wait_cond "第 2 次恢复" docker exec "$LAB" sh -c "ip link show eth3 | grep -q LOWER_UP" \
  && record "t8-second-recover" 1 || record "t8-second-recover" 0 "第 2 次恢复未发生"
docker exec "$LAB" ip link set eth2-peer down
wait_cond "进入 SUPPRESSED" docker exec "$LAB" sh -c "grep -q '\"state\":\"SUPPRESSED\"' $ST" \
  && record "t8-suppressed" 1 || record "t8-suppressed" 0 "$(stget)"
# 抑制态冻结：eth3 不应再被联动（保持当前 up 状态）
sleep 3
docker exec "$LAB" sh -c "ip link show eth3 | grep -q LOWER_UP" \
  && record "t8-suppressed-frozen" 1 || record "t8-suppressed-frozen" 0 "抑制态仍发生联动: $(docker exec "$LAB" ip link show eth3 | head -1)"

# 8.4 复位与清理：恢复 eth2 载波，杀 daemon，复位抑制（配置指纹变化触发重置）
docker exec "$LAB" ip link set eth2-peer up
wcfg <<EOF
{"bridges":[{"name":"br0","ports":["eth2","eth3"],"link_pair":{"enabled":true,"hold_down_ms":500,"hold_up_ms":1000,"max_flaps_per_hour":20}}],"ip_forward":false,"routes":[],"updated_at":"$RUN_ID-t8-reset"}
EOF
wait_cond "抑制复位回 BOTH_UP" docker exec "$LAB" sh -c "grep -q '\"state\":\"BOTH_UP\"' $ST" \
  && record "t8-suppression-reset" 1 || record "t8-suppression-reset" 0 "$(stget)"
docker exec "$LAB" sh -c 'pidof netmgrd >/dev/null 2>&1 && kill "$(pidof netmgrd)" 2>/dev/null; true'
echo "[info] 联动 daemon 日志:"; docker exec "$LAB" cat /var/log/netmgrd-lp.log 2>/dev/null | tail -6 | sed 's/^/  /'

echo ""
echo "============================================================"
echo "结果: PASS=$PASS FAIL=$FAIL SKIP=$SKIP (计入统计 TOTAL=$TOTAL)"
if [ "$FAIL" -gt 0 ]; then
  echo "失败用例:"
  for f in "${FAILED[@]}"; do echo "  - $f"; done
  exit 1
fi
echo "全部通过"
