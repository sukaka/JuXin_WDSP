#!/usr/bin/env bash
# 九章阶段D 透明串接（透明代理）部署模式 PoC 验证
# 设计依据：docs/NETWORK_MODES_DESIGN.md §4.3
# 拓扑（单容器内 netns 模拟二层串接）：
#   client ns(192.168.50.10) ──veth── br0 ──veth── origin ns(192.168.50.20:8081/443)
#   桥上 tcp/8081 与 tcp/443 经 bridge-nf-call-iptables → nat REDIRECT → tproxyd(:15000)
#   → 明文 HTTP：PROXY v1 上报真实五元组 → Caddy(127.0.0.1:8080, coraza On) → 反代源站
#   → HTTPS：tproxyd 嗅探 SNI，清单内（www.test.com）→ Caddy TLS(127.0.0.1:8443)
#     终结检测；清单外（www.test1.com）→ 端到端透传源站 s_server（不检测）
# 依赖：docker compose -f deployment/docker-compose.tproxy-lab.yml up -d
# 用法：bash test/waf/scripts/transparent-lab-tests.sh
#
# 复跑方式（仓库根目录，全流程）：
#   cd gateway && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath \
#     -ldflags="-s -w" -o ../deployment/docker/tproxy-lab/tproxyd ./cmd/tproxyd && cd ..
#   docker compose -f deployment/docker-compose.tproxy-lab.yml build
#   docker compose -f deployment/docker-compose.tproxy-lab.yml up -d
#   bash test/waf/scripts/transparent-lab-tests.sh
#   docker compose -f deployment/docker-compose.tproxy-lab.yml down -v
#
# fail-open 用例（t5）会杀掉 tproxyd 进程并 docker restart 实验容器两次
# （看门狗清规则直通 → 重启恢复检测），属设计内行为；日志跨重启在卷上追加，
# RUN_ID 逐次运行唯一，互不干扰。
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
LOG_DIR="$REPO_ROOT/runtime/logs/tproxy-lab"
ACC_LOG="$LOG_DIR/access.log"
AUDIT_LOG="$LOG_DIR/coraza-audit.log"

LAB=tproxylab-lab
CLIENT_ADDR=192.168.50.10
ORIGIN_ADDR=192.168.50.20
ORIGIN_PORT=8081
WAF_BR_ADDR=192.168.50.1
RUN_ID="tproxyrun$(date +%s)"

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
# 从 client netns 发请求（客户端零代理配置，按同网段直连源站 IP）
ccode() { docker exec "$LAB" ip netns exec client curl -s -o /dev/null -w '%{http_code}' --max-time 6 "$@" 2>/dev/null; }
cbody() { docker exec "$LAB" ip netns exec client curl -s --max-time 6 "$@" 2>/dev/null; }
chdrs() { docker exec "$LAB" ip netns exec client curl -s -D - -o /dev/null --max-time 6 "$@" 2>/dev/null; }
# JSON 字段提取（与 routed/mirror-lab 用例同一风格）
jget() { python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print($1)" 2>/dev/null; }
# 等待 lab 容器健康（≤90s）
wait_healthy() {
  local i
  for i in $(seq 1 90); do
    [ "$(docker inspect -f '{{.State.Health.Status}}' "$LAB" 2>/dev/null)" = "healthy" ] && return 0
    sleep 1
  done
  return 1
}
# fail-open 日志行数（跨重启累计）
fo_count() { docker logs "$LAB" 2>&1 | grep -c 'fail-open 生效' || true; }
# 当前牵引链中 REDIRECT 规则条数
redirect_rules() { docker exec "$LAB" iptables -t nat -L TPROXYLAB -n 2>/dev/null | grep -c REDIRECT || true; }

echo "============================================================"
echo "九章阶段D 透明串接(transparent) PoC  run=$RUN_ID"
echo "拓扑: client ns($CLIENT_ADDR) --veth-- br0 --veth-- origin ns($ORIGIN_ADDR:$ORIGIN_PORT)"
echo "      桥上 REDIRECT -> tproxyd(:15000) --PROXY v1--> Caddy(127.0.0.1:8080) -> 源站"
echo "============================================================"

# ---------- 0. 拓扑与数据面前提 ----------
echo ""
echo "---- 0. 拓扑前提 ----"
docker ps --format '{{.Names}}' | grep -qx "$LAB" || { echo "ERROR: 容器 $LAB 未运行，请先 up 编排"; exit 1; }
wait_healthy && record "t0-lab-healthy" 1 || record "t0-lab-healthy" 0 "容器 90s 内未就绪"
docker exec "$LAB" ip link show br0 >/dev/null 2>&1 && record "t0-bridge-br0" 1 || record "t0-bridge-br0" 0 "br0 不存在"
BNF=$(docker exec "$LAB" cat /proc/sys/net/bridge/bridge-nf-call-iptables 2>/dev/null)
[ "$BNF" = "1" ] && record "t0-bridge-nf-call-iptables" 1 || record "t0-bridge-nf-call-iptables" 0 "value=$BNF"
NSLIST=$(docker exec "$LAB" ip netns list 2>/dev/null)
{ echo "$NSLIST" | grep -q '^client' && echo "$NSLIST" | grep -q '^origin'; } \
  && record "t0-netns-client-origin" 1 || record "t0-netns-client-origin" 0 "netns=[$NSLIST]"
[ "$(redirect_rules)" -ge 1 ] && record "t0-redirect-rule-installed" 1 || record "t0-redirect-rule-installed" 0 "nat/TPROXYLAB 无 REDIRECT 规则"

# ---------- 1. 正常请求：经桥 + 牵引 + Caddy 检测 + 源站 ----------
echo ""
echo "---- 1. 正常请求（客户端零代理配置，直连源站 IP） ----"
ST=$(ccode "http://$ORIGIN_ADDR:$ORIGIN_PORT/echo?${RUN_ID}=t1")
BODY=$(cbody "http://$ORIGIN_ADDR:$ORIGIN_PORT/echo?${RUN_ID}=t1b")
HDRS=$(chdrs "http://$ORIGIN_ADDR:$ORIGIN_PORT/echo?${RUN_ID}=t1c")
SVC=$(echo "$BODY" | jget "d.get('service','')")
MARK=$(echo "$BODY" | jget "d.get('upstream_mark','')")
RID=$(echo "$BODY" | jget "d.get('request_id','')")
echo "[info] status=$ST service=$SVC upstream_mark=$MARK request_id=$RID"
{ [ "$ST" = "200" ] && [ "$SVC" = "jiuzhang-test-origin" ] && [ "$MARK" = "REACHED_ORIGIN" ]; } \
  && record "t1-benign-200-origin-body" 1 || record "t1-benign-200-origin-body" 0 "status=$ST service=$SVC mark=$MARK"
# X-Request-Id 由 Caddy 生成并覆盖（源站回显非空）+ 安全响应头由 Caddy 注入：
# 两者共同证明流量确实经过了 WAF 检测管线而非桥接直通
{ [ -n "$RID" ] && [ "$RID" != "None" ]; } && record "t1-request-id-from-waf" 1 || record "t1-request-id-from-waf" 0 "request_id 为空"
echo "$HDRS" | grep -qi '^X-Frame-Options: DENY' && record "t1-waf-response-headers" 1 || record "t1-waf-response-headers" 0 "缺 X-Frame-Options"

# ---------- 2. SQLi 特征请求：inline 阻断 403 + 阻断页 ----------
echo ""
echo "---- 2. SQLi 特征请求（Coraza On → 403） ----"
ST=$(ccode "http://$ORIGIN_ADDR:$ORIGIN_PORT/echo?id=1%27%20OR%20%271%27%3D%271&${RUN_ID}=t2")
BODY=$(cbody "http://$ORIGIN_ADDR:$ORIGIN_PORT/echo?id=1%27%20OR%20%271%27%3D%271&${RUN_ID}=t2b")
[ "$ST" = "403" ] && record "t2-sqli-blocked-403" 1 || record "t2-sqli-blocked-403" 0 "status=$ST want=403"
echo "$BODY" | grep -q "请求已被安全策略阻断" && record "t2-blockpage-served" 1 || record "t2-blockpage-served" 0 "响应非九章阻断页"

# ---------- 3. WAF 日志/审计中的真实客户端 IP（经 PROXY 协议上报） ----------
echo ""
echo "---- 3. Caddy 访问日志 / Coraza 审计日志中的真实客户端 IP ----"
sleep 1 # 等待访问日志与审计日志落盘
ACC_LINE=$(grep "$RUN_ID=t1" "$ACC_LOG" 2>/dev/null | tail -1)
ACC_IP=$(echo "$ACC_LINE" | python3 -c 'import json,sys; print(json.load(sys.stdin)["request"].get("remote_ip",""))' 2>/dev/null)
[ "$ACC_IP" = "$CLIENT_ADDR" ] && record "t3-accesslog-real-client-ip" 1 || record "t3-accesslog-real-client-ip" 0 "remote_ip=$ACC_IP want=$CLIENT_ADDR"
AUD_HIT=$(grep "$RUN_ID=t2" "$AUDIT_LOG" 2>/dev/null | grep -Ec "\"client_ip\":\s*\"$CLIENT_ADDR\"")
[ "${AUD_HIT:-0}" -ge 1 ] && record "t3-auditlog-real-client-ip" 1 || record "t3-auditlog-real-client-ip" 0 "coraza-audit.log 中未找到 client_ip=$CLIENT_ADDR 的 t2 事务"

# ---------- 4. 源站视角：回源连接由 Caddy 发起（反代语义）+ XFF 携带真实客户端 ----------
echo ""
echo "---- 4. 源站视角（回源语义实测记录） ----"
BODY=$(cbody "http://$ORIGIN_ADDR:$ORIGIN_PORT/echo?${RUN_ID}=t4")
OIP=$(echo "$BODY" | jget "d.get('client_ip','')")
XFF=$(echo "$BODY" | jget "d.get('headers',{}).get('X-Forwarded-For','')")
echo "[info] 源站 TCP 对端 client_ip=${OIP}（REDIRECT 方案回源连接由 Caddy 发起，与反代语义一致）"
echo "[info] 源站收到 X-Forwarded-For=${XFF}（真实客户端经反代理头传达）"
[ "$OIP" = "$WAF_BR_ADDR" ] && record "t4-origin-sees-waf-ip" 1 || record "t4-origin-sees-waf-ip" 0 "client_ip=$OIP want=${WAF_BR_ADDR}（WAF 桥地址）"
[ "$XFF" = "$CLIENT_ADDR" ] && record "t4-xff-real-client" 1 || record "t4-xff-real-client" 0 "XFF=$XFF want=$CLIENT_ADDR"

# ---------- 5. fail-open：进程死亡 → 清规则直通 → 重启恢复检测 ----------
echo ""
echo "---- 5. fail-open（kill tproxyd → 桥接直通；重启恢复） ----"

failopen_case() { # sig signame tag → 全局 FO_OK/FO_DIRECT_OK
  local sig="$1" tag="$2" tpid base i
  base=$(fo_count)
  tpid=$(docker exec "$LAB" pidof tproxyd 2>/dev/null)
  [ -n "$tpid" ] || { FO_OK=0; FO_DIRECT_OK=0; echo "[err] 取不到 tproxyd pid"; return; }
  docker exec "$LAB" kill -"$sig" "$tpid"
  FO_OK=0
  for i in $(seq 1 40); do
    if [ "$(fo_count)" -gt "$base" ] && [ "$(redirect_rules)" = "0" ]; then FO_OK=1; break; fi
    sleep 0.5
  done
  # 直通验证：同一请求现在应直连源站（200），源站看到真实客户端，且无 WAF 注入的 X-Request-Id
  FO_DIRECT_OK=0
  if [ "$FO_OK" = "1" ]; then
    local body oip rid st
    st=$(ccode "http://$ORIGIN_ADDR:$ORIGIN_PORT/echo?${RUN_ID}=$tag")
    body=$(cbody "http://$ORIGIN_ADDR:$ORIGIN_PORT/echo?${RUN_ID}=${tag}b")
    oip=$(echo "$body" | jget "d.get('client_ip','')")
    rid=$(echo "$body" | jget "d.get('request_id','')")
    echo "[info] fail-open 直通: status=$st origin client_ip=$oip request_id=${rid:-<empty>}"
    { [ "$st" = "200" ] && [ "$oip" = "$CLIENT_ADDR" ] && { [ -z "$rid" ] || [ "$rid" = "None" ]; }; } && FO_DIRECT_OK=1
  fi
}

# 5a. SIGTERM（优雅退出场景）
failopen_case TERM t5a
[ "$FO_OK" = "1" ] && record "t5-sigterm-failopen" 1 || record "t5-sigterm-failopen" 0 "20s 内未清规则/未记录 fail-open"
[ "$FO_DIRECT_OK" = "1" ] && record "t5-sigterm-direct-passthrough" 1 || record "t5-sigterm-direct-passthrough" 0 "直通验证失败"
docker restart "$LAB" >/dev/null
wait_healthy && record "t5-restart-recovers" 1 || record "t5-restart-recovers" 0 "重启后 90s 未健康"
ST=$(ccode "http://$ORIGIN_ADDR:$ORIGIN_PORT/echo?id=1%27%20OR%20%271%27%3D%271&${RUN_ID}=t5r")
[ "$ST" = "403" ] && record "t5-detection-restored" 1 || record "t5-detection-restored" 0 "status=$ST want=403（重启后检测应恢复）"

# 5b. SIGKILL（kill -9 强制死亡场景）
failopen_case KILL t5b
[ "$FO_OK" = "1" ] && record "t5-sigkill-failopen" 1 || record "t5-sigkill-failopen" 0 "20s 内未清规则/未记录 fail-open"
[ "$FO_DIRECT_OK" = "1" ] && record "t5-sigkill-direct-passthrough" 1 || record "t5-sigkill-direct-passthrough" 0 "直通验证失败"
docker restart "$LAB" >/dev/null
wait_healthy || echo "[warn] 重启后 90s 未健康"
ST=$(ccode "http://$ORIGIN_ADDR:$ORIGIN_PORT/echo?${RUN_ID}=t5b2")
BODY=$(cbody "http://$ORIGIN_ADDR:$ORIGIN_PORT/echo?${RUN_ID}=t5b3")
RID=$(echo "$BODY" | jget "d.get('request_id','')")
{ [ "$ST" = "200" ] && [ -n "$RID" ] && [ "$RID" != "None" ]; } \
  && record "t5-recovery-after-sigkill" 1 || record "t5-recovery-after-sigkill" 0 "status=$ST request_id=$RID"

# ---------- 6. 运行统计：连接/字节计数 ----------
echo ""
echo "---- 6. 牵引进程统计日志 ----"
BASE=$(docker logs "$LAB" 2>&1 | grep -c '\[tproxyd\] stats' || true)
ccode "http://$ORIGIN_ADDR:$ORIGIN_PORT/echo?${RUN_ID}=t6" >/dev/null
STATS_LINE=""
for i in $(seq 1 30); do
  if [ "$(docker logs "$LAB" 2>&1 | grep -c '\[tproxyd\] stats' || true)" -gt "$BASE" ]; then
    STATS_LINE=$(docker logs "$LAB" 2>&1 | grep '\[tproxyd\] stats' | tail -1); break
  fi
  sleep 0.5
done
echo "[info] $STATS_LINE"
ACC=$(echo "$STATS_LINE" | sed -n 's/.*accepted=\([0-9]*\).*/\1/p')
BT=$(echo "$STATS_LINE" | sed -n 's/.*bytes(c2t=\([0-9]*\).*/\1/p')
{ [ -n "$ACC" ] && [ "$ACC" -ge 1 ]; } && [ -n "$BT" ] && [ "$BT" -gt 0 ] \
  && record "t6-stats-connections" 1 || record "t6-stats-connections" 0 "accepted=$ACC bytes_c2t=${BT}（统计周期 5s）"

# ---------- 7. HTTPS SNI 分流（同 IP 多虚拟主机：防护 www.test.com，透传 www.test1.com） ----------
# 拓扑：桥上 tcp/443 与 tcp/8081 同样 REDIRECT 到 tproxyd；tproxyd 嗅探 ClientHello SNI：
#   清单内（www.test.com）→ Caddy TLS 站点 127.0.0.1:8443 终结检测；
#   清单外（www.test1.com）→ 按原始目的透传 origin ns 内 s_server（端到端 TLS）。
echo ""
echo "---- 7. HTTPS SNI 分流 ----"
PROTECT_DOMAIN=www.test.com
PASS_DOMAIN=www.test1.com
CERTDIR=/etc/caddy/certs
# 经 WAF 的防护域名请求（--resolve 把域名指向源站 IP，模拟同网段直连）
pcode() { docker exec "$LAB" ip netns exec client curl -s -o /dev/null -w '%{http_code}' --max-time 8 \
  --cacert "$CERTDIR/$PROTECT_DOMAIN.crt" --resolve "$PROTECT_DOMAIN:443:$ORIGIN_ADDR" "$@" 2>/dev/null; }
pbody() { docker exec "$LAB" ip netns exec client curl -s --max-time 8 \
  --cacert "$CERTDIR/$PROTECT_DOMAIN.crt" --resolve "$PROTECT_DOMAIN:443:$ORIGIN_ADDR" "$@" 2>/dev/null; }

ST=$(pcode "https://$PROTECT_DOMAIN/echo?${RUN_ID}=t7")
BODY=$(pbody "https://$PROTECT_DOMAIN/echo?${RUN_ID}=t7b")
RID=$(echo "$BODY" | jget "d.get('request_id','')")
HDRS=$(docker exec "$LAB" ip netns exec client curl -s -D - -o /dev/null --max-time 8 \
  --cacert "$CERTDIR/$PROTECT_DOMAIN.crt" --resolve "$PROTECT_DOMAIN:443:$ORIGIN_ADDR" \
  "https://$PROTECT_DOMAIN/echo?${RUN_ID}=t7c" 2>/dev/null)
echo "[info] protected https status=$ST request_id=$RID"
{ [ "$ST" = "200" ] && [ -n "$RID" ] && [ "$RID" != "None" ]; } \
  && record "t7-protected-https-via-waf" 1 || record "t7-protected-https-via-waf" 0 "status=$ST request_id=${RID}（应经 WAF 终结检测回源）"
echo "$HDRS" | grep -qi '^X-Frame-Options: DENY' && record "t7-protected-https-waf-headers" 1 \
  || record "t7-protected-https-waf-headers" 0 "缺 X-Frame-Options（未进 WAF 管线？）"

# 防护域名 SQLi：TLS 终结后 Coraza 检测仍应阻断
ST=$(pcode "https://$PROTECT_DOMAIN/echo?id=1%27%20OR%20%271%27%3D%271&${RUN_ID}=t7sqli")
[ "$ST" = "403" ] && record "t7-protected-https-sqli-403" 1 || record "t7-protected-https-sqli-403" 0 "status=$ST want=403"

# 清单外域名：端到端透传——证书 CN 为源站证书、响应无 WAF 注入头
VOUT=$(docker exec "$LAB" ip netns exec client curl -sv --max-time 8 \
  --cacert "$CERTDIR/$PASS_DOMAIN.crt" --resolve "$PASS_DOMAIN:443:$ORIGIN_ADDR" \
  "https://$PASS_DOMAIN/" 2>&1)
ST=$(echo "$VOUT" | sed -n 's/.*HTTP\/[0-9.]* \([0-9]*\).*/\1/p' | tail -1)
CN=$(echo "$VOUT" | grep -i 'subject:' | head -1)
echo "[info] passthrough https status=$ST subject=$CN"
[ "$ST" = "200" ] && record "t7-passthrough-https-200" 1 || record "t7-passthrough-https-200" 0 "status=$ST"
echo "$CN" | grep -q "CN *= *$PASS_DOMAIN" && record "t7-passthrough-origin-cert" 1 \
  || record "t7-passthrough-origin-cert" 0 "证书 subject=[$CN] want CN=${PASS_DOMAIN}（应为源站证书端到端呈现）"
echo "$VOUT" | grep -qi '^X-Frame-Options' && record "t7-passthrough-no-waf-headers" 0 "响应含 WAF 注入头（流量误入检测管线）" \
  || record "t7-passthrough-no-waf-headers" 1

# 分流计数：stats 行应出现 protected/passthrough 非零
BASE=$(docker logs "$LAB" 2>&1 | grep -c '\[tproxyd\] stats' || true)
pcode "https://$PROTECT_DOMAIN/echo?${RUN_ID}=t7s" >/dev/null
STATS_LINE=""
for i in $(seq 1 30); do
  if [ "$(docker logs "$LAB" 2>&1 | grep -c '\[tproxyd\] stats' || true)" -gt "$BASE" ]; then
    STATS_LINE=$(docker logs "$LAB" 2>&1 | grep '\[tproxyd\] stats' | tail -1); break
  fi
  sleep 0.5
done
echo "[info] $STATS_LINE"
SNI_P=$(echo "$STATS_LINE" | sed -n 's/.*protected=\([0-9]*\).*/\1/p')
SNI_T=$(echo "$STATS_LINE" | sed -n 's/.*passthrough=\([0-9]*\).*/\1/p')
{ [ -n "$SNI_P" ] && [ "$SNI_P" -ge 1 ]; } && { [ -n "$SNI_T" ] && [ "$SNI_T" -ge 1 ]; } \
  && record "t7-sni-dispatch-stats" 1 || record "t7-sni-dispatch-stats" 0 "protected=${SNI_P:-?} passthrough=${SNI_T:-?}"

echo ""
echo "============================================================"
echo "结果: PASS=$PASS FAIL=$FAIL SKIP=$SKIP (计入统计 TOTAL=$TOTAL)"
if [ "$FAIL" -gt 0 ]; then
  echo "失败用例:"
  for f in "${FAILED[@]}"; do echo "  - $f"; done
  exit 1
fi
echo "全部通过"
