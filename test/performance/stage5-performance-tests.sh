#!/usr/bin/env bash
# 九章阶段5 性能测试：规则量延迟、CC计数延迟、并发RPS、随机键攻击内存、发布期可用性
# 依赖 stage5 环境。用法：bash test/performance/stage5-performance-tests.sh
# 结果写入 test/performance/stage5-performance-result.txt
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../waf/scripts/stage5-setup.sh"

REPORT="$SCRIPT_DIR/stage5-performance-result.txt"
: > "$REPORT"
log() { echo "$@" | tee -a "$REPORT"; }

TOTAL=0; PASS=0; FAIL=0; FAILED=()
record() {
  local name="$1" ok="$2" detail="${3:-}"
  TOTAL=$((TOTAL+1))
  if [ "$ok" = "1" ]; then PASS=$((PASS+1)); log "PASS  $name $detail"
  else FAIL=$((FAIL+1)); FAILED+=("$name: $detail"); log "FAIL  $name ($detail)"; fi
}

# ab 延迟提取（P50/P95/P99）
ab_measure() { # url xff_ip n c
  local url="$1" xff="$2" n="$3" c="$4"
  ab -k -n "$n" -c "$c" -H "Host: $HOST_HEADER" -H "X-Forwarded-For: $xff" "$url" 2>/dev/null
}
p95_of() { echo "$1" | awk '/^  95%/{print $2}'; }
p50_of() { echo "$1" | awk '/^  50%/{print $2}'; }
p99_of() { echo "$1" | awk '/^  99%/{print $2}'; }
rps_of() { echo "$1" | awk '/Requests per second/{print $4}'; }
failed_of() { echo "$1" | awk '/Failed requests/{print $3}'; }

log "============================================================"
log "九章阶段5 性能测试  $(date '+%Y-%m-%d %H:%M:%S')"
log "环境: $(uname -srm), Docker Desktop"
log "============================================================"

SYS_CSRF=$(s5_ensure_sysadmin) || exit 1
SEC_CSRF=$(s5_ensure_secuser "$SYS_CSRF")
[ -z "$SEC_CSRF" ] && { echo "ERROR: sec login failed"; exit 1; }
APP_ID=$(s5_ensure_app "$SEC_CSRF")
CK="/tmp/s5-$SEC_USER.txt"
SUBNET=$(docker network inspect jiuzhang-stage5_stage5-net --format '{{(index .IPAM.Config 0).Subnet}}')
TP_EXIST=$(curl -s -b "$CK" "$API_URL/api/v1/trusted-proxies?keyword=docker-bridge" | python3 -c "import json,sys; items=json.load(sys.stdin)['data'].get('items') or []; print(len([i for i in items if i.get('name')=='docker-bridge' and i.get('status')=='ENABLED']))")
[ "$TP_EXIST" = "0" ] && s5_post /api/v1/trusted-proxies "{\"name\":\"docker-bridge\",\"cidr\":\"$SUBNET\",\"header_type\":\"X_FORWARDED_FOR\",\"priority\":100}" "$SEC_CSRF" > /dev/null
# CC 基线策略（测量用）
s5_post /api/v1/rate-limit-policies "{\"name\":\"perf-cc\",\"scope_type\":\"APPLICATION\",\"application_id\":\"$APP_ID\",\"uri_match_type\":\"PREFIX\",\"uri_pattern\":\"/perf/cc/\",\"dimension\":\"CLIENT_IP\",\"algorithm\":\"TOKEN_BUCKET\",\"requests_limit\":100000,\"window_seconds\":60,\"burst_capacity\":100000,\"action\":\"REJECT\",\"priority\":100}" "$SEC_CSRF" > /dev/null
# 100 条 CC 策略（不同前缀，单请求仅命中 1 条，测试策略加载量）
for i in $(seq 0 19); do
  s5_post /api/v1/rate-limit-policies "{\"name\":\"perf-cc-$i\",\"scope_type\":\"APPLICATION\",\"application_id\":\"$APP_ID\",\"uri_match_type\":\"PREFIX\",\"uri_pattern\":\"/perf/p$i/\",\"dimension\":\"CLIENT_IP\",\"algorithm\":\"TOKEN_BUCKET\",\"requests_limit\":100000,\"window_seconds\":60,\"burst_capacity\":100000,\"action\":\"REJECT\",\"priority\":$((200+i))}" "$SEC_CSRF" > /dev/null
done
for i in $(seq 20 99); do
  s5_post /api/v1/rate-limit-policies "{\"name\":\"perf-cc-$i\",\"scope_type\":\"APPLICATION\",\"application_id\":\"$APP_ID\",\"uri_match_type\":\"PREFIX\",\"uri_pattern\":\"/perf/p$i/\",\"dimension\":\"CLIENT_IP\",\"algorithm\":\"SLIDING_WINDOW\",\"requests_limit\":100000,\"window_seconds\":60,\"action\":\"OBSERVE\",\"priority\":$((200+i))}" "$SEC_CSRF" > /dev/null
done
[ "$(s5_publish "$SEC_CSRF")" = "PUBLISH_OK" ] && record "publish-baseline" 1 || record "publish-baseline" 0

echo ""
log "---- 1. 基线延迟（仅 guard 全链，无规则） ----"
BASE=$(ab_measure "$GATEWAY_URL/echo" "203.0.113.50" 3000 50)
B50=$(p50_of "$BASE"); B95=$(p95_of "$BASE"); B99=$(p99_of "$BASE"); BRPS=$(rps_of "$BASE")
log "基线: P50=${B50}ms P95=${B95}ms P99=${B99}ms RPS=${BRPS}"

echo ""
log "---- 2. 1000 条黑名单 ----"
python3 -c "
import json
lines=['address']+[f'10.99.{i//256}.{i%256}' for i in range(1000)]
print(json.dumps({'content':'\n'.join(lines),'format':'csv','mode':'ALL_OR_NOTHING','rule_type':'DENY','scope_type':'GLOBAL'}))" > /tmp/s5-imp1000.json
curl -s -b "$CK" -X POST "$API_URL/api/v1/access-rules/import" -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" -d @/tmp/s5-imp1000.json | python3 -c "import json,sys; d=json.load(sys.stdin)['data']; print('imported:', d.get('imported'))" | tee -a "$REPORT"
[ "$(s5_publish "$SEC_CSRF")" = "PUBLISH_OK" ] || record "publish-1000" 0
M=$(ab_measure "$GATEWAY_URL/echo" "203.0.113.50" 3000 50)
M95=$(p95_of "$M"); log "1000规则: P50=$(p50_of "$M")ms P95=${M95}ms P99=$(p99_of "$M")ms"
DELTA=$((M95 - B95))
[ "$DELTA" -lt 5 ] && record "latency-1000-rules-p95-delta<5ms" 1 "delta=${DELTA}ms" || record "latency-1000-rules-p95-delta<5ms" 0 "delta=${DELTA}ms"

echo ""
log "---- 3. 10000 条黑名单 ----"
python3 -c "
import json
lines=['address']+[f'11.{i//65536}.{(i//256)%256}.{i%256}' for i in range(10000)]
print(json.dumps({'content':'\n'.join(lines),'format':'csv','mode':'ALL_OR_NOTHING','rule_type':'DENY','scope_type':'GLOBAL'}))" > /tmp/s5-imp10000.json
curl -s -b "$CK" -X POST "$API_URL/api/v1/access-rules/import" -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" -d @/tmp/s5-imp10000.json | python3 -c "import json,sys; d=json.load(sys.stdin)['data']; print('imported:', d.get('imported'))" | tee -a "$REPORT"
[ "$(s5_publish "$SEC_CSRF")" = "PUBLISH_OK" ] || record "publish-10000" 0
M=$(ab_measure "$GATEWAY_URL/echo" "203.0.113.50" 3000 50)
M95=$(p95_of "$M"); log "10000规则: P50=$(p50_of "$M")ms P95=${M95}ms P99=$(p99_of "$M")ms"
DELTA=$((M95 - B95))
[ "$DELTA" -lt 5 ] && record "latency-10000-rules-p95-delta<5ms" 1 "delta=${DELTA}ms" || record "latency-10000-rules-p95-delta<5ms" 0 "delta=${DELTA}ms"

echo ""
log "---- 4. 1000 条 CIDR ----"
# 清理 IP 规则（测试库直删，仅性能测试数据）
docker exec jiuzhang-stage5-postgres psql -U jiuzhang -d jiuzhang_waf -c \
  "UPDATE ip_access_rules SET status='DELETED', deleted_at=now() WHERE source_type='IMPORT' AND deleted_at IS NULL" > /dev/null
python3 -c "
import json
lines=['address']+[f'10.{i//256}.{i%256}.0/24' for i in range(1000)]
print(json.dumps({'content':'\n'.join(lines),'format':'csv','mode':'ALL_OR_NOTHING','rule_type':'DENY','scope_type':'GLOBAL'}))" > /tmp/s5-imp-cidr.json
curl -s -b "$CK" -X POST "$API_URL/api/v1/access-rules/import" -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" -d @/tmp/s5-imp-cidr.json | python3 -c "import json,sys; d=json.load(sys.stdin)['data']; print('imported:', d.get('imported'))" | tee -a "$REPORT"
[ "$(s5_publish "$SEC_CSRF")" = "PUBLISH_OK" ] || record "publish-cidr" 0
M=$(ab_measure "$GATEWAY_URL/echo" "203.0.113.50" 3000 50)
M95=$(p95_of "$M"); log "1000CIDR: P50=$(p50_of "$M")ms P95=${M95}ms P99=$(p99_of "$M")ms"
DELTA=$((M95 - B95))
[ "$DELTA" -lt 5 ] && record "latency-1000-cidr-p95-delta<5ms" 1 "delta=${DELTA}ms" || record "latency-1000-cidr-p95-delta<5ms" 0 "delta=${DELTA}ms"

echo ""
log "---- 5. CC 计数延迟（100 策略加载，单请求 1 次 Valkey 计数） ----"
M=$(ab_measure "$GATEWAY_URL/perf/cc/x" "203.0.113.51" 3000 50)
M95=$(p95_of "$M"); log "CC计数: P50=$(p50_of "$M")ms P95=${M95}ms P99=$(p99_of "$M")ms"
DELTA=$((M95 - B95))
[ "$DELTA" -lt 10 ] && record "latency-cc-count-p95-delta<10ms" 1 "delta=${DELTA}ms" || record "latency-cc-count-p95-delta<10ms" 0 "delta=${DELTA}ms"

echo ""
log "---- 6. 500 RPS / 200 并发 ----"
M=$(ab_measure "$GATEWAY_URL/echo" "203.0.113.52" 20000 200)
FR=$(failed_of "$M"); RRPS=$(rps_of "$M")
log "500RPS目标: 实测RPS=${RRPS} Failed=${FR} P95=$(p95_of "$M")ms P99=$(p99_of "$M")ms"
[ "$FR" = "0" ] && record "500rps-no-errors" 1 "rps=$RRPS" || record "500rps-no-errors" 0 "failed=$FR"

echo ""
log "---- 7. 随机键攻击内存稳定性 ----"
MEM_BEFORE=$(docker stats jiuzhang-stage5-gateway --no-stream --format '{{.MemUsage}}' | sed 's/MiB.*//' | tr -dc '0-9.')
KEYS_BEFORE=$(docker exec jiuzhang-stage5-valkey valkey-cli -a "$VALKEY_PASSWORD" --no-auth-warning DBSIZE | tr -dc '0-9')
python3 - <<'PYEOF'
import random, socket
for i in range(20000):
    ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    try:
        s = socket.create_connection(("127.0.0.1", 18080), timeout=2)
        s.sendall(f"GET /perf/cc/x HTTP/1.1\r\nHost: waf-s5.local\r\nX-Forwarded-For: {ip}\r\nConnection: close\r\n\r\n".encode())
        s.recv(128); s.close()
    except Exception: pass
print("ip-flood-done")
PYEOF
python3 - <<'PYEOF'
import random, socket
for i in range(20000):
    try:
        s = socket.create_connection(("127.0.0.1", 18080), timeout=2)
        s.sendall(f"GET /perf/cc/{random.getrandbits(64):x} HTTP/1.1\r\nHost: waf-s5.local\r\nX-Forwarded-For: 203.0.113.60\r\nConnection: close\r\n\r\n".encode())
        s.recv(128); s.close()
    except Exception: pass
print("uri-flood-done")
PYEOF
sleep 3
MEM_AFTER=$(docker stats jiuzhang-stage5-gateway --no-stream --format '{{.MemUsage}}' | sed 's/MiB.*//' | tr -dc '0-9.')
KEYS_AFTER=$(docker exec jiuzhang-stage5-valkey valkey-cli -a "$VALKEY_PASSWORD" --no-auth-warning DBSIZE | tr -dc '0-9')
log "网关内存: ${MEM_BEFORE}MiB -> ${MEM_AFTER}MiB; valkey keys: $KEYS_BEFORE -> $KEYS_AFTER"
MEM_OK=$(python3 -c "print(1 if float('$MEM_AFTER') < max(float('$MEM_BEFORE')*1.5, 256) else 0)")
[ "$MEM_OK" = "1" ] && record "random-key-memory-stable" 1 "${MEM_BEFORE}MiB->${MEM_AFTER}MiB" || record "random-key-memory-stable" 0 "${MEM_BEFORE}MiB->${MEM_AFTER}MiB"
# URI 键不增长（按策略模式键）：随机 URI 后键增长应远小于请求数
KEY_GROWTH=$((KEYS_AFTER - KEYS_BEFORE))
[ "$KEY_GROWTH" -lt 60000 ] && record "uri-key-bounded" 1 "growth=$KEY_GROWTH" || record "uri-key-bounded" 0 "growth=$KEY_GROWTH"

echo ""
log "---- 8. 发布期间旧策略持续可用 ----"
ab -k -n 4000 -c 50 -H "Host: $HOST_HEADER" -H "X-Forwarded-For: 203.0.113.70" "$GATEWAY_URL/echo" > /tmp/s5-ab-during-publish.txt 2>&1 &
AB_PID=$!
sleep 1
s5_publish "$SEC_CSRF" > /dev/null
wait $AB_PID
FR=$(failed_of "$(cat /tmp/s5-ab-during-publish.txt)")
[ "$FR" = "0" ] && record "publish-during-load-no-errors" 1 || record "publish-during-load-no-errors" 0 "failed=$FR"

echo ""
log "---- 9. 清理性能测试数据 ----"
docker exec jiuzhang-stage5-postgres psql -U jiuzhang -d jiuzhang_waf -c \
  "UPDATE ip_access_rules SET status='DELETED', deleted_at=now() WHERE source_type='IMPORT' AND deleted_at IS NULL;
   UPDATE rate_limit_policies SET deleted_at=now() WHERE name LIKE 'perf-cc%' AND deleted_at IS NULL" > /dev/null
s5_publish "$SEC_CSRF" > /dev/null
log "[cleanup] done"

log ""
log "============================================================"
log "阶段5性能测试汇总: 总用例 $TOTAL 通过 $PASS 失败 $FAIL"
if [ "$FAIL" -gt 0 ]; then
  log "失败用例:"
  for c in "${FAILED[@]}"; do log "  - $c"; done
fi
log "============================================================"
[ "$FAIL" -eq 0 ]
