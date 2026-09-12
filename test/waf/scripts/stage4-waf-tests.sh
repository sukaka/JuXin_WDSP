#!/usr/bin/env bash
# 九章阶段4 真实WAF测试：攻击检测 + 事件入库 + 误报例外验证
# 依赖 stage3 环境（api:18081, gateway:18080, testorigin）
# 用法：bash test/waf/scripts/stage4-waf-tests.sh
set -u

GATEWAY_URL="${GATEWAY_URL:-http://127.0.0.1:18080}"
API_URL="${API_URL:-http://127.0.0.1:18081}"
HOST_HEADER="${HOST_HEADER:-waf-test.local}"
SEC_USER="${SEC_USER:-sec_admin_s3}"
SEC_PWD="${SEC_PWD:-SecAdmin@S3!2026}"
VALKEY_CONTAINER="${VALKEY_CONTAINER:-jiuzhang-stage3-valkey}"
VALKEY_PASSWORD="${VALKEY_PASSWORD:-CHANGE_ME_STRONG_PASSWORD}"

TOTAL=0
PASS=0
FAIL=0
FAILED=()

record() {
  local name="$1" ok="$2" detail="${3:-}"
  TOTAL=$((TOTAL+1))
  if [ "$ok" = "1" ]; then
    PASS=$((PASS+1)); echo "PASS  $name"
  else
    FAIL=$((FAIL+1)); FAILED+=("$name: $detail"); echo "FAIL  $name ($detail)"
  fi
}

echo "============================================================"
echo "九章阶段4 真实WAF测试  gateway=$GATEWAY_URL host=$HOST_HEADER"
echo "============================================================"

# 登录获取 CSRF
login_api() {
  local capid capcode
  capid=$(curl -s "$API_URL/api/v1/auth/captcha" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['captcha_id'])")
  capcode=$(docker exec "$VALKEY_CONTAINER" valkey-cli -a "$VALKEY_PASSWORD" --no-auth-warning GET "jiuzhang:captcha:$capid")
  curl -s -c /tmp/s4waf-cookie.txt -X POST "$API_URL/api/v1/auth/login" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"$SEC_USER\",\"password\":\"$SEC_PWD\",\"captcha_id\":\"$capid\",\"captcha_code\":\"$capcode\"}" > /dev/null
  curl -s -b /tmp/s4waf-cookie.txt "$API_URL/api/v1/auth/me" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['csrf_token'])"
}

CSRF=$(login_api)
if [ -z "$CSRF" ]; then
  echo "ERROR: login failed, cannot get CSRF token"
  exit 1
fi
echo "[setup] logged in as $SEC_USER"

# 辅助：发请求检查状态码
check() {
  local name="$1" want_status="$2" path="$3"
  local status
  status=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $HOST_HEADER" "$GATEWAY_URL$path")
  TOTAL=$((TOTAL+1))
  if [ "$status" = "$want_status" ]; then
    PASS=$((PASS+1)); echo "PASS  $name (status=$status)"
  else
    FAIL=$((FAIL+1)); FAILED+=("$name: status=$status want=$want_status"); echo "FAIL  $name (status=$status want=$want_status)"
  fi
}

# 辅助：查询事件是否入库（按攻击类型，最近）
event_count() {
  local attack_type="$1"
  curl -s -b /tmp/s4waf-cookie.txt "$API_URL/api/v1/security-events?attack_type=$attack_type&page_size=1" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['total'])" 2>/dev/null || echo "0"
}

echo ""
echo "---- 1. 正常请求（应200通过） ----"
check "normal-get" 200 "/echo?a=1"
check "normal-post-form" 200 "/echo" -X POST -d "user=test" 2>/dev/null || check "normal-post-form2" 200 "/echo"

echo ""
echo "---- 2. SQL注入（PROTECT应403阻断） ----"
check "sqli-union" 403 "/echo?id=1%20UNION%20SELECT%20username,password%20FROM%20users--"
check "sqli-tautology" 403 "/echo?q=1'%20OR%20'1'='1"
check "sqli-encoded" 403 "/echo?q=%31%27%20%4F%52%20%27%31%27%3D%27%31"
SQ_COUNT_BEFORE=$(event_count "SQL_INJECTION")
sleep 4
SQ_COUNT_AFTER=$(event_count "SQL_INJECTION")
if [ "$SQ_COUNT_AFTER" -gt "$SQ_COUNT_BEFORE" ] 2>/dev/null || [ "$SQ_COUNT_AFTER" -ge 1 ] 2>/dev/null; then
  record "sqli-event-recorded" 1 ""
else
  record "sqli-event-recorded" 0 "no SQL_INJECTION event in db"
fi

echo ""
echo "---- 3. XSS（应403） ----"
check "xss-script" 403 "/echo?q=%3Cscript%3Ealert(1)%3C/script%3E"
check "xss-img" 403 "/echo?q=%3Cimg%20src=x%20onerror=alert(1)%3E"
sleep 4
XSS_COUNT=$(event_count "XSS")
[ "$XSS_COUNT" -ge 1 ] 2>/dev/null && record "xss-event-recorded" 1 || record "xss-event-recorded" 0 "count=$XSS_COUNT"

echo ""
echo "---- 4. 命令注入（应403） ----"
check "cmdi-semicolon" 403 "/echo?host=127.0.0.1;cat%20/etc/passwd"
check "cmdi-pipe-shell" 403 "/echo?x=a%7Cnc%20-e%20%2Fbin%2Fsh"

echo ""
echo "---- 5. 路径穿越（应403） ----"
check "path-traversal" 403 "/echo?f=../../../../etc/passwd"
check "path-encoded" 403 "/echo?f=%2e%2e%2f%2e%2e%2fetc%2fpasswd"

echo ""
echo "---- 6. 扫描器特征（应403） ----"
status=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $HOST_HEADER" -H "User-Agent: sqlmap/1.5" "$GATEWAY_URL/echo")
[ "$status" = "403" ] && record "scanner-sqlmap-ua" 1 || record "scanner-sqlmap-ua" 0 "status=$status"
status=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $HOST_HEADER" -H "User-Agent: Mozilla/5.00 (Nikto/2.1.6)" "$GATEWAY_URL/echo")
[ "$status" = "403" ] && record "scanner-nikto-ua" 1 || record "scanner-nikto-ua" 0 "status=$status"

echo ""
echo "---- 7. 协议异常（应403/400/501） ----"
status=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $HOST_HEADER" -X "HACKMETHOD" "$GATEWAY_URL/echo")
case "$status" in 403|400|405|501) record "proto-invalid-method" 1 ;; *) record "proto-invalid-method" 0 "status=$status";; esac

echo ""
echo "---- 8. 误报测试（合法请求应通过200） ----"
check "fp-chinese" 200 "/echo?msg=%E4%BD%A0%E5%A5%BD%E4%B8%96%E7%95%8C%E8%BF%99%E6%98%AF%E4%B8%AD%E6%96%87"
status=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $HOST_HEADER" -H "Content-Type: application/json" -d '{"name":"测试","desc":"select * from users"}' "$GATEWAY_URL/api/json")
[ "$status" = "200" ] && record "fp-json-sql-text" 1 || record "fp-json-sql-text" 0 "status=$status (SQL文本JSON被误拦)"
status=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $HOST_HEADER" -H "Content-Type: application/json" -d '{"html":"<p>富文本内容 with <b>tags</b></p>"}' "$GATEWAY_URL/api/json")
[ "$status" = "200" ] && record "fp-richtext" 1 || record "fp-richtext" 0 "status=$status (富文本被误拦)"
check "fp-long-param" 200 "/echo?data=$(python3 -c 'print("x"*1500)')"
check "fp-base64" 200 "/echo?data=aGVsbG8gd29ybGQ="

echo ""
echo "---- 9. 事件详情验证 ----"
EID=$(curl -s -b /tmp/s4waf-cookie.txt "$API_URL/api/v1/security-events?page_size=1&action=BLOCK" | python3 -c "import json,sys; items=json.load(sys.stdin)['data']['items']; print(items[0]['id'] if items else '')" 2>/dev/null)
if [ -n "$EID" ]; then
  HAS_MATCH=$(curl -s -b /tmp/s4waf-cookie.txt "$API_URL/api/v1/security-events/$EID" | python3 -c "import json,sys; d=json.load(sys.stdin)['data']; print(len(d['matches']))" 2>/dev/null)
  [ "${HAS_MATCH:-0}" -ge 1 ] 2>/dev/null && record "event-detail-matches" 1 || record "event-detail-matches" 0 "no matches"
else
  record "event-detail-matches" 0 "no BLOCK event found"
fi

echo ""
echo "============================================================"
echo "真实WAF测试汇总"
echo "总用例数: $TOTAL"
echo "通过:     $PASS"
echo "失败:     $FAIL"
if [ "$FAIL" -gt 0 ]; then
  echo "失败用例:"
  for c in "${FAILED[@]}"; do echo "  - $c"; done
fi
echo "============================================================"
[ "$FAIL" -eq 0 ]
