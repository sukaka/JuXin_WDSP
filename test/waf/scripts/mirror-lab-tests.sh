#!/usr/bin/env bash
# 九章阶段C 镜像（旁路）部署模式 PoC 验证
# 设计依据：docs/NETWORK_MODES_DESIGN.md §4.2
# 拓扑：client(172.30.30.20) ──server_net──> origin(172.30.30.10:8081)
#       mirror 共享 origin 网络命名空间（等价 SPAN 镜像口），旁路抓包还原检测
# 依赖：docker compose -f deployment/docker-compose.mirror-lab.yml up -d
# 用法：bash test/waf/scripts/mirror-lab-tests.sh
#
# 事件关联说明：api-runtime-events 契约按数据最小化纪律不记录 query 明文，
# 无法按 RUN_ID 检索；本脚本利用「请求串行 + 事件按处理顺序追加」的事实，
# 以事件行数基线定位每个用例产生的新事件。Coraza 审计日志含完整请求行，
# 用例 c2 另以 RUN_ID 在审计日志中交叉佐证。
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
LOG_DIR="$REPO_ROOT/runtime/logs/mirror-lab"
EVENTS_LOG="$LOG_DIR/api-runtime-events.log"
AUDIT_LOG="$LOG_DIR/coraza-audit.log"

ORIGIN=mirrorlab-origin
MIRROR=mirrorlab-mirror
CLIENT=mirrorlab-client
ORIGIN_ADDR=172.30.30.10
CLIENT_ADDR=172.30.30.20
ORIGIN_PORT=8081
RUN_ID="mirrorun$(date +%s)"

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
# 从 client 容器发请求，输出 HTTP 状态码（超时/失败为 000）
ccode() { docker exec "$CLIENT" curl -s -o /dev/null -w '%{http_code}' --max-time 6 "$@" 2>/dev/null; }
# 从 client 容器发请求，输出响应体
cbody() { docker exec "$CLIENT" curl -s --max-time 6 "$@" 2>/dev/null; }
# 当前事件行数（文件不存在为 0）
evcount() { [ -f "$EVENTS_LOG" ] && wc -l < "$EVENTS_LOG" | tr -d ' ' || echo 0; }
# 等待第 N 行事件出现并输出该行（旁路抓包→重组→检测为异步，轮询最长 15s）
wait_event_line() { # lineno → 行内容（空=超时）
  local n="$1" i
  for i in $(seq 1 30); do
    if [ "$(evcount)" -ge "$n" ]; then
      sed -n "${n}p" "$EVENTS_LOG"; return 0
    fi
    sleep 0.5
  done
  return 1
}
# JSON 字段提取（python3 与 routed-lab 用例同一风格）
jget() { python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print($1)" 2>/dev/null; }

echo "============================================================"
echo "九章阶段C 镜像(旁路)模式 PoC  run=$RUN_ID"
echo "拓扑: $CLIENT_ADDR --server_net--> $ORIGIN_ADDR:$ORIGIN_PORT (mirror 共享 origin netns 旁路抓包)"
echo "============================================================"

# ---------- 0. 拓扑前提 ----------
echo ""
echo "---- 0. 拓扑前提 ----"
for c in "$ORIGIN" "$MIRROR" "$CLIENT"; do
  docker ps --format '{{.Names}}' | grep -qx "$c" || { echo "ERROR: 容器 $c 未运行，请先 up 编排"; exit 1; }
done
record "c0-containers-up" 1
# 启动断言：产品化文件配置模式下由 Supervisor 输出「生效配置」行；
# 本实验无下发文件（env 模式），应记录 source=env 且接口/端口来自环境变量
START_LINE=$(docker logs "$MIRROR" 2>&1 | grep '\[mirrorcap\] 生效配置' | tail -1)
echo "$START_LINE" | grep -q "source=env" && echo "$START_LINE" | grep -q "interfaces=\[eth0\]" \
  && echo "$START_LINE" | grep -q "ports=\[8081\]" \
  && record "c0-mirror-startup" 1 || record "c0-mirror-startup" 0 "start line=[$START_LINE]"
NETNS_MIRROR=$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$MIRROR")
echo "$NETNS_MIRROR" | grep -q "^container:" && record "c0-mirror-shares-origin-netns" 1 || record "c0-mirror-shares-origin-netns" 0 "network_mode=$NETNS_MIRROR"

# ---------- 1. 正常请求：捕获记录正确（端点发现语义） ----------
echo ""
echo "---- 1. 正常请求的旁路捕获 ----"
BASE=$(($(evcount) + 1))
ST=$(ccode "http://$ORIGIN_ADDR:$ORIGIN_PORT/echo?${RUN_ID}=c1")
EV1=$(wait_event_line "$BASE")
EK=$(echo "$EV1" | jget "d.get('endpoint_key','')")
MTH=$(echo "$EV1" | jget "d.get('method','')")
RP=$(echo "$EV1" | jget "d.get('raw_path','')")
MARK=$(echo "$EV1" | jget "(d.get('details') or [{}])[0].get('detector','') + '/' + (d.get('details') or [{}])[0].get('rule_id','')")
echo "[info] status=$ST endpoint_key=$EK method=$MTH raw_path=$RP marker=$MARK"
[ "$ST" = "200" ] && record "c1-benign-request-200" 1 || record "c1-benign-request-200" 0 "status=$ST"
{ [ -n "$EV1" ] && [ "$EK" = "GET /echo" ] && [ "$MTH" = "GET" ] && [ "$RP" = "/echo" ]; } \
  && record "c1-capture-record-correct" 1 || record "c1-capture-record-correct" 0 "ek=$EK method=$MTH raw=$RP"
[ "$MARK" = "mirror/mirror.capture" ] && record "c1-mirror-marker" 1 || record "c1-mirror-marker" 0 "details[0]=$MARK"

# ---------- 2. SQLi 特征请求：检测命中 + final_action 封顶 OBSERVE ----------
echo ""
echo "---- 2. SQLi 特征请求（CRS 命中，旁路只观察） ----"
BASE=$(($(evcount) + 1))
ST=$(ccode "http://$ORIGIN_ADDR:$ORIGIN_PORT/echo?id=1%27%20OR%20%271%27%3D%271&${RUN_ID}=c2")
EV2=$(wait_event_line "$BASE")
RL=$(echo "$EV2" | jget "d.get('risk_level','')")
FA=$(echo "$EV2" | jget "d.get('final_action','')")
RS=$(echo "$EV2" | jget "d.get('risk_score',0)")
WAFIDS=$(echo "$EV2" | jget "','.join(str(m.get('rule_id','')) for m in (d.get('details') or []) if m.get('detector')=='waf')")
echo "[info] status=$ST risk_level=$RL risk_score=$RS final_action=$FA waf_rules=[$WAFIDS]"
# 旁路铁律：攻击请求照样到达 origin 并正常响应（只检测、无阻断环节）
[ "$ST" = "200" ] && record "c2-sqli-passthrough-200" 1 || record "c2-sqli-passthrough-200" 0 "status=$ST want=200（旁路不得影响流量）"
{ [ -n "$WAFIDS" ] && [ "$RL" != "NONE" ] && [ -n "$RL" ] && [ "$RL" != "None" ]; } \
  && record "c2-sqli-detected" 1 || record "c2-sqli-detected" 0 "risk_level=$RL waf_rules=[$WAFIDS]"
[ "$FA" = "OBSERVE" ] && record "c2-final-action-observe" 1 || record "c2-final-action-observe" 0 "final_action=$FA want=OBSERVE"
# CRS SQLi 规则族命中佐证（942xxx 注入检测族；至少一条）
echo "$WAFIDS" | grep -qE "(^|,)942[0-9]{3}" && record "c2-crs-sqli-rule-family" 1 || record "c2-crs-sqli-rule-family" 0 "waf_rules=[$WAFIDS] 未见 942xxx 族"
# 交叉佐证：Coraza 审计日志（含完整请求行）应能按 RUN_ID 定位到本请求的事务
sleep 1
AUD_HIT=$(grep -c "$RUN_ID=c2" "$AUDIT_LOG" 2>/dev/null || true)
[ "${AUD_HIT:-0}" -ge 1 ] && record "c2-audit-log-xref" 1 || record "c2-audit-log-xref" 0 "coraza-audit.log 未找到 $RUN_ID=c2 事务"

# ---------- 3. 真实源 IP 记录（四元组源地址，无代理头伪造面） ----------
echo ""
echo "---- 3. 事件中的真实客户端 IP ----"
CIP=$(echo "$EV2" | jget "d.get('client_ip','')")
SFP=$(echo "$EV2" | jget "d.get('source_fingerprint','')")
[ "$CIP" = "$CLIENT_ADDR" ] && record "c3-real-client-ip" 1 || record "c3-real-client-ip" 0 "client_ip=$CIP want=$CLIENT_ADDR"
[ -n "$SFP" ] && [ "$SFP" != "None" ] && record "c3-source-fingerprint" 1 || record "c3-source-fingerprint" 0 "source_fingerprint 为空"

# ---------- 4. 旁路零侵入：origin 响应不受任何影响 ----------
echo ""
echo "---- 4. 旁路零侵入（响应一致性） ----"
# 同一 URL 两次请求（镜像抓包进行中），响应体必须逐字节一致
U="http://$ORIGIN_ADDR:$ORIGIN_PORT/echo?${RUN_ID}=c4"
B1=$(cbody "$U"); B2=$(cbody "$U")
SVC=$(echo "$B1" | jget "d.get('service','')")
{ [ -n "$B1" ] && [ "$B1" = "$B2" ] && [ "$SVC" = "jiuzhang-test-origin" ]; } \
  && record "c4-response-unaffected" 1 || record "c4-response-unaffected" 0 "service=$SVC b1==b2:$([ "$B1" = "$B2" ] && echo yes || echo no)"
# origin 看到的对端仍是真实客户端（旁路不经任何代理/回源改写）
OIP=$(echo "$B1" | jget "d.get('client_ip','')")
[ "$OIP" = "$CLIENT_ADDR" ] && record "c4-origin-sees-real-client" 1 || record "c4-origin-sees-real-client" 0 "origin client_ip=$OIP want=$CLIENT_ADDR"

# ---------- 5. 运行统计：抓包计数与事件计数 ----------
echo ""
echo "---- 5. 状态统计日志 ----"
# 统计每 5s 输出一行（编排 MIRROR_STATS_INTERVAL=5），等到覆盖全部用例的一行
for i in $(seq 1 12); do
  STATS_LINE=$(docker logs "$MIRROR" 2>&1 | grep '\[mirrorcap\] stats' | tail -1)
  EV=$(echo "$STATS_LINE" | sed -n 's/.*events=\([0-9]*\).*/\1/p')
  [ -n "$EV" ] && [ "$EV" -ge 4 ] && break
  sleep 1
done
echo "[info] $STATS_LINE"
PK=$(echo "$STATS_LINE" | sed -n 's/.*packets=\([0-9]*\).*/\1/p')
RQ=$(echo "$STATS_LINE" | sed -n 's/.*requests=\([0-9]*\).*/\1/p')
EV=$(echo "$STATS_LINE" | sed -n 's/.*events=\([0-9]*\).*/\1/p')
{ [ -n "$PK" ] && [ "$PK" -gt 0 ]; } && record "c5-stats-packets" 1 || record "c5-stats-packets" 0 "packets=$PK"
{ [ -n "$RQ" ] && [ "$RQ" -ge 4 ]; } && record "c5-stats-requests" 1 || record "c5-stats-requests" 0 "requests=$RQ want>=4（c1×1+c2×1+c4×2）"
{ [ -n "$EV" ] && [ "$EV" -ge 4 ]; } && record "c5-stats-events" 1 || record "c5-stats-events" 0 "events=$EV want>=4（与请求一一对应）"

echo ""
echo "============================================================"
echo "结果: PASS=$PASS FAIL=$FAIL SKIP=$SKIP (计入统计 TOTAL=$TOTAL)"
if [ "$FAIL" -gt 0 ]; then
  echo "失败用例:"
  for f in "${FAILED[@]}"; do echo "  - $f"; done
  exit 1
fi
echo "全部通过"
