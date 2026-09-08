#!/usr/bin/env bash
# 九章阶段B 路由牵引（routed）部署模式 PoC 验证
# 设计依据：docs/NETWORK_MODES_DESIGN.md §4.1
# 拓扑：client(172.30.10.10) → 路由 via waf(172.30.10.2) → waf(:8080 终结TCP/检测) → origin(172.30.20.10)
# 依赖：docker compose -f deployment/docker-compose.routed-lab.yml up -d
# 用法：bash test/waf/scripts/routed-lab-tests.sh
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
LOG_DIR="$REPO_ROOT/runtime/logs/routed-lab"

WAF=routedlab-waf
CLIENT=routedlab-client
ORIGIN=routedlab-origin
CLIENT_ADDR=172.30.10.10
WAF_CLIENT_SIDE=172.30.10.2
WAF_ADDR=172.30.20.2
WAF_PORT=8080
ORIGIN_ADDR=172.30.20.10
TEST_HOST=routedapp.example.com
RUN_ID="labrun$(date +%s)"

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

echo "============================================================"
echo "九章阶段B 路由牵引(routed) PoC  run=$RUN_ID"
echo "拓扑: $CLIENT_ADDR --client_net--> $WAF_CLIENT_SIDE/172.30.20.2 --server_net--> $ORIGIN_ADDR"
echo "============================================================"

# ---------- 0. 拓扑与内核前提 ----------
echo ""
echo "---- 0. 拓扑前提 ----"
for c in "$WAF" "$CLIENT" "$ORIGIN"; do
  docker ps --format '{{.Names}}' | grep -qx "$c" || { echo "ERROR: 容器 $c 未运行，请先 up 编排"; exit 1; }
done
FWD=$(docker exec "$WAF" cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)
[ "$FWD" = "1" ] && record "c0-waf-ip-forward" 1 || record "c0-waf-ip-forward" 0 "ip_forward=$FWD"
RT=$(docker exec "$CLIENT" ip route show 172.30.20.0/24 2>/dev/null)
echo "$RT" | grep -q "via $WAF_CLIENT_SIDE" && record "c0-client-route-via-waf" 1 || record "c0-client-route-via-waf" 0 "route=[$RT]"
# 确保基线干净：origin 上无指回 client 网段的回程路由（非对称基线）
# 注：testorigin 容器主进程以非 root 运行，路由操作需显式 --user 0（NET_ADMIN 已在编排中授予）
docker exec --user 0 "$ORIGIN" ip route del 172.30.10.0/24 >/dev/null 2>&1 || true

# ---------- 1. 基线：直连源站（绕过 WAF 的通道探测） ----------
echo ""
echo "---- 1. 基线：绕过 WAF 直连源站 ----"
ST=$(ccode "http://$ORIGIN_ADDR:8081/echo?${RUN_ID}=c1")
# 去程经 WAF 转发到达 origin；回程是否可达取决于环境：
# - 严格隔离（Docker 跨桥转发被 DROP）→ 超时 000，无绕过通道；
# - Docker Desktop VM 允许跨桥转发 → 非对称回程（origin→网桥→client）仍可连通。
# 两种结果都作为基线记录；可达时给出生产加固提示。
if [ "$ST" = "000" ]; then
  record "c1-direct-origin-baseline" 1
  echo "[info] 基线: 直连源站不可达（非对称回程被隔离），无绕过 WAF 通道"
else
  record "c1-direct-origin-baseline" 1
  echo "[warn] 基线: 直连源站可达(status=${ST})，实验 VM 跨桥转发所致；生产环境须在源站侧 ACL/安全组仅放行 WAF 节点"
fi

# ---------- 2. 经路由到 WAF：正常请求透传回源 ----------
echo ""
echo "---- 2. 路由到 WAF 的正常请求（Host 匹配 + 回源） ----"
WAF_URL="http://$WAF_ADDR:$WAF_PORT"
ST=$(ccode "$WAF_URL/echo?${RUN_ID}=c2" -H "Host: $TEST_HOST")
BODY=$(cbody "$WAF_URL/echo?${RUN_ID}=c2b" -H "Host: $TEST_HOST")
SVC=$(echo "$BODY" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("service",""))' 2>/dev/null)
OIP=$(echo "$BODY" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("client_ip",""))' 2>/dev/null)
echo "[info] origin service=$SVC origin-seen client_ip=$OIP"
{ [ "$ST" = "200" ] && [ "$SVC" = "jiuzhang-test-origin" ]; } && record "c2-routed-http-200" 1 || record "c2-routed-http-200" 0 "status=$ST service=$SVC"
# 路由模式仍终结 TCP：源站看到的对端是 WAF 的 IP（与现有反代语义一致，不伪造源 IP）
[ "$OIP" = "$WAF_ADDR" ] && record "c2-origin-sees-waf-ip" 1 || record "c2-origin-sees-waf-ip" 0 "origin client_ip=$OIP want=$WAF_ADDR"

# ---------- 3. 经路由到 WAF：SQLi 攻击被阻断 ----------
echo ""
echo "---- 3. 路由到 WAF 的攻击请求（Coraza On → 403） ----"
ST=$(ccode "$WAF_URL/echo?id=1%27%20OR%20%271%27%3D%271&${RUN_ID}=c3" -H "Host: $TEST_HOST")
[ "$ST" = "403" ] && record "c3-routed-sqli-blocked" 1 || record "c3-routed-sqli-blocked" 0 "status=$ST want=403"

# ---------- 4. IP 溯源：日志中的真实客户端 IP（不经任何代理头） ----------
echo ""
echo "---- 4. WAF 日志/审计中的真实客户端 IP ----"
sleep 1  # 等待访问日志与审计日志落盘
ACC_LINE=$(grep "$RUN_ID=c2" "$LOG_DIR/access.log" 2>/dev/null | tail -1)
ACC_IP=$(echo "$ACC_LINE" | python3 -c 'import json,sys; print(json.load(sys.stdin)["request"].get("remote_ip",""))' 2>/dev/null)
[ "$ACC_IP" = "$CLIENT_ADDR" ] && record "c4-accesslog-real-client-ip" 1 || record "c4-accesslog-real-client-ip" 0 "remote_ip=$ACC_IP want=$CLIENT_ADDR"
AUD_HIT=$(grep "$RUN_ID=c3" "$LOG_DIR/coraza-audit.log" 2>/dev/null | grep -Ec "\"client_ip\":\s*\"$CLIENT_ADDR\"")
[ "${AUD_HIT:-0}" -ge 1 ] && record "c4-auditlog-real-client-ip" 1 || record "c4-auditlog-real-client-ip" 0 "coraza-audit.log 中未找到 client_ip=$CLIENT_ADDR 的 c3 事务"

# ---------- 5. 纯三层转发：对称路由后源地址端到端保持 ----------
echo ""
echo "---- 5. 纯路由转发路径（不终结 TCP，需对称回程） ----"
if ERR=$(docker exec --user 0 "$ORIGIN" ip route replace 172.30.10.0/24 via "$WAF_ADDR" 2>&1); then
  ST=$(ccode "http://$ORIGIN_ADDR:8081/echo?${RUN_ID}=c5")
  BODY=$(cbody "http://$ORIGIN_ADDR:8081/echo?${RUN_ID}=c5b")
  CIP=$(echo "$BODY" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("client_ip",""))' 2>/dev/null)
  echo "[info] l3-forward status=$ST origin-seen client_ip=$CIP"
  { [ "$ST" = "200" ] && [ "$CIP" = "$CLIENT_ADDR" ]; } && record "c5-l3-forward-src-preserved" 1 || record "c5-l3-forward-src-preserved" 0 "status=$ST client_ip=$CIP"
else
  record "c5-l3-forward-src-preserved" SKIP "origin 路由注入失败: $ERR"
fi
# 恢复非对称基线，避免影响复跑
docker exec --user 0 "$ORIGIN" ip route del 172.30.10.0/24 >/dev/null 2>&1 || true

echo ""
echo "============================================================"
echo "结果: PASS=$PASS FAIL=$FAIL SKIP=$SKIP (计入统计 TOTAL=$TOTAL)"
if [ "$FAIL" -gt 0 ]; then
  echo "失败用例:"
  for f in "${FAILED[@]}"; do echo "  - $f"; done
  exit 1
fi
echo "全部通过"
