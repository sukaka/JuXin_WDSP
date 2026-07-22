#!/usr/bin/env bash
# 九章阶段6 性能与容量测试：态势P95、趋势P95、并发统计查询、千万级事件容量、大报告
# 依赖 stage5 编排。用法：bash test/performance/stage6-capacity-tests.sh
# 结果写入 test/performance/stage6-capacity-result.txt
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../waf/scripts/stage5-setup.sh"
# 阶段6专用测试账号（避免与其他会话共用的测试账号被重置）
SEC_USER="${S6_SEC_USER:-s6_sec}"
SEC_PWD="${S6_SEC_PWD:-S6Sec@Test2026!}"
SYS_USER="${S6_SYS_USER:-s6_sys}"
SYS_PWD="${S6_SYS_PWD:-S6Sys@Test2026!}"

REPORT="$SCRIPT_DIR/stage6-capacity-result.txt"
: > "$REPORT"
log() { echo "$@" | tee -a "$REPORT"; }
TOTAL=0; PASS=0; FAIL=0; FAILED=()
record() {
  local name="$1" ok="$2" detail="${3:-}"
  TOTAL=$((TOTAL+1))
  if [ "$ok" = "1" ]; then PASS=$((PASS+1)); log "PASS  $name $detail"
  else FAIL=$((FAIL+1)); FAILED+=("$name: $detail"); log "FAIL  $name ($detail)"; fi
}
# 简单计时（毫秒）
time_ms() { python3 -c "import time,sys; t=time.time(); sys.stdin.read(); print(int((time.time()-t)*1000))" 2>/dev/null || echo 0; }
measure() { # 返回请求耗时 ms
  local start end
  start=$(python3 -c "import time; print(time.time())")
  "$@" > /dev/null 2>&1
  end=$(python3 -c "import time; print(time.time())")
  python3 -c "print(int(($end-$start)*1000))"
}
p95_of() { echo "$1" | awk '/^  95%/{print $2}'; }

log "============================================================"
log "阶段6 性能与容量测试  $(date '+%Y-%m-%d %H:%M:%S')"
log "============================================================"

SYS_CSRF=$(s5_login "$SYS_USER" "$SYS_PWD"); SCK="/tmp/s5-$SYS_USER.txt"
SEC_CSRF=$(s5_login "$SEC_USER" "$SEC_PWD"); CK="/tmp/s5-$SEC_USER.txt"

echo ""
log "---- 1. 态势首页 P95（目标 <2000ms） ----"
for i in 1 2 3 4 5; do measure curl -s -b "$CK" "$API_URL/api/v1/dashboard/security-overview"; done > /tmp/s6-perf.txt
SORTED=$(sort -n /tmp/s6-perf.txt)
P95=$(echo "$SORTED" | tail -1)
log "态势首页 5 次: $(echo $SORTED | tr ' ' ',') ms, P95=${P95}ms"
[ "$P95" -lt 2000 ] && record "overview-p95<2s" 1 "p95=${P95}ms" || record "overview-p95<2s" 0 "p95=${P95}ms"

log "---- 2. 24h 趋势 P95（目标 <1000ms） ----"
for i in 1 2 3 4 5; do measure curl -s -b "$CK" "$API_URL/api/v1/analytics/request-trend"; done > /tmp/s6-perf.txt
P95=$(sort -n /tmp/s6-perf.txt | tail -1)
log "24h趋势: P95=${P95}ms"
[ "$P95" -lt 1000 ] && record "trend-24h-p95<1s" 1 "p95=${P95}ms" || record "trend-24h-p95<1s" 0 "p95=${P95}ms"

log "---- 3. 30天趋势 P95（目标 <2000ms） ----"
T_START=$(date -u -v-30d +%Y-%m-%dT%H:%M:%SZ)
for i in 1 2 3 4 5; do measure curl -s -b "$CK" "$API_URL/api/v1/analytics/request-trend?start_time=$T_START"; done > /tmp/s6-perf.txt
P95=$(sort -n /tmp/s6-perf.txt | tail -1)
log "30天趋势: P95=${P95}ms"
[ "$P95" -lt 2000 ] && record "trend-30d-p95<2s" 1 "p95=${P95}ms" || record "trend-30d-p95<2s" 0 "p95=${P95}ms"

log "---- 4. 健康页面 P95（目标 <1000ms） ----"
for i in 1 2 3 4 5; do measure curl -s -b "$SCK" "$API_URL/api/v1/system-health"; done > /tmp/s6-perf.txt
P95=$(sort -n /tmp/s6-perf.txt | tail -1)
log "健康页面: P95=${P95}ms"
[ "$P95" -lt 1000 ] && record "health-p95<1s" 1 "p95=${P95}ms" || record "health-p95<1s" 0 "p95=${P95}ms"

log "---- 5. 100 并发统计查询 ----"
START=$(python3 -c "import time; print(time.time())")
for i in $(seq 1 100); do
  curl -s -b "$CK" "$API_URL/api/v1/analytics/attack-types" > /dev/null &
done
wait
END=$(python3 -c "import time; print(time.time())")
MS=$(python3 -c "print(int(($END-$START)*1000))")
ERRORS=$(docker logs jiuzhang-stage5-api 2>&1 | tail -50 | grep -c "status=500" || true)
log "100并发 attack-types: ${MS}ms 完成, 近50行日志500数=$ERRORS"
[ "$MS" -lt 30000 ] && record "concurrent-100-stats" 1 "${MS}ms" || record "concurrent-100-stats" 0 "${MS}ms"

log "---- 6. 千万级事件模拟与查询容量 ----"
# 分批插入 1000 万安全事件 + 1000 万访问控制事件（每批 50 万）
EXISTING_SE=$(docker exec jiuzhang-stage5-postgres psql -U jiuzhang -d jiuzhang_waf -tAc "SELECT count(*) FROM security_events")
EXISTING_AC=$(docker exec jiuzhang-stage5-postgres psql -U jiuzhang -d jiuzhang_waf -tAc "SELECT count(*) FROM access_control_events")
log "现有: security_events=$EXISTING_SE access_control_events=$EXISTING_AC"
if [ "$EXISTING_SE" -lt 10000000 ]; then
  log "插入安全事件模拟数据至 1000 万..."
  docker exec jiuzhang-stage5-postgres psql -U jiuzhang -d jiuzhang_waf -c "
    INSERT INTO security_events (request_id, occurred_at, application_id, domain, gateway_node_id, client_ip, request_method, request_path, attack_type, severity, action, rule_match_count, anomaly_score)
    SELECT 'cap-' || g, '2026-07-20'::timestamptz + (g || ' seconds')::interval,
      (SELECT id FROM applications LIMIT 1), 'cap-test.local', 'gateway-cap',
      ('203.0.113.' || (g % 250 + 1))::inet, 'GET', '/cap/' || (g % 100),
      (ARRAY['SQL_INJECTION','XSS','COMMAND_INJECTION','SCANNER_DETECTION'])[g % 4 + 1],
      (ARRAY['HIGH','MEDIUM','LOW','INFO'])[g % 4 + 1],
      (ARRAY['BLOCK','OBSERVE'])[g % 2 + 1], 2, 15
    FROM generate_series(1, 10000000 - $EXISTING_SE) g;" > /dev/null
fi
if [ "$EXISTING_AC" -lt 10000000 ]; then
  log "插入访问控制事件模拟数据至 1000 万..."
  docker exec jiuzhang-stage5-postgres psql -U jiuzhang -d jiuzhang_waf -c "
    INSERT INTO access_control_events (request_id, occurred_at, application_code, client_ip, domain, request_method, request_path, event_type, action, gateway_node_id)
    SELECT 'capac-' || g, '2026-07-20'::timestamptz + (g || ' seconds')::interval, 's5app',
      ('198.51.100.' || (g % 250 + 1))::inet, 'cap-test.local', 'GET', '/capac/' || (g % 100),
      (ARRAY['IP_DENY_MATCH','CC_REQUEST_REJECTED','CC_THRESHOLD_EXCEEDED','IP_ALLOW_MATCH'])[g % 4 + 1],
      'DENY', 'gateway-cap'
    FROM generate_series(1, 10000000 - $EXISTING_AC) g;" > /dev/null
fi
CNT_SE=$(docker exec jiuzhang-stage5-postgres psql -U jiuzhang -d jiuzhang_waf -tAc "SELECT count(*) FROM security_events")
CNT_AC=$(docker exec jiuzhang-stage5-postgres psql -U jiuzhang -d jiuzhang_waf -tAc "SELECT count(*) FROM access_control_events")
log "容量: security_events=$CNT_SE access_control_events=$CNT_AC"
[ "$CNT_SE" -ge 10000000 ] && [ "$CNT_AC" -ge 10000000 ] && record "capacity-10m-events" 1 || record "capacity-10m-events" 0 "$CNT_SE/$CNT_AC"
# 千万级下分页查询可用（180 天范围）
T180=$(date -u -v-180d +%Y-%m-%dT%H:%M:%SZ)
MS=$(measure curl -s -b "$CK" "$API_URL/api/v1/security-events?start_time=$T180&page_size=50")
log "180天事件查询: ${MS}ms"
[ "$MS" -lt 5000 ] && record "query-180d-events" 1 "${MS}ms" || record "query-180d-events" 0 "${MS}ms"
MS=$(measure curl -s -b "$CK" "$API_URL/api/v1/access-control-events?start_time=$T180&page_size=50")
log "180天访问控制事件查询: ${MS}ms"
[ "$MS" -lt 5000 ] && record "query-180d-ac-events" 1 "${MS}ms" || record "query-180d-ac-events" 0 "${MS}ms"

log "---- 7. 大型报告生成（千万事件背景下，不阻塞 API） ----"
RID=$(curl -s -b "$CK" -X POST "$API_URL/api/v1/reports" -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" \
  -d "{\"report_type\":\"CUSTOM\",\"start_time\":\"$T180\",\"end_time\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"format\":\"html\"}" | python3 -c "import json,sys; d=json.load(sys.stdin)['data']; print(d.get('id') or d.get('report',{}).get('id',''))" 2>/dev/null)
API_OK=1
for i in $(seq 1 10); do
  st=$(curl -s -o /dev/null -w "%{http_code}" -b "$CK" "$API_URL/api/v1/dashboard/security-overview")
  [ "$st" = "200" ] || API_OK=0
done
[ "$API_OK" = "1" ] && record "api-available-during-report" 1 || record "api-available-during-report" 0
ST=""
RSTART=$(python3 -c "import time; print(time.time())")
for i in $(seq 1 150); do
  ST=$(curl -s -b "$CK" "$API_URL/api/v1/reports/$RID" | python3 -c "import json,sys; d=json.load(sys.stdin)['data']; j=d.get('job') or d.get('report') or d; print(j.get('status',''))" 2>/dev/null)
  case "$ST" in SUCCESS|FAILED) break;; esac
  sleep 2
done
REND=$(python3 -c "import time; print(time.time())")
RMS=$(python3 -c "print(int(($REND-$RSTART)))")
[ "$ST" = "SUCCESS" ] && record "large-report-success" 1 "${RMS}s" || record "large-report-success" 0 "status=$ST"

log ""
log "============================================================"
log "阶段6性能容量汇总: 总用例 $TOTAL 通过 $PASS 失败 $FAIL"
if [ "$FAIL" -gt 0 ]; then
  for c in "${FAILED[@]}"; do log "  - $c"; done
fi
log "============================================================"
[ "$FAIL" -eq 0 ]
