#!/usr/bin/env bash
# 九章阶段2 管理API安全测试
# 针对运行中的管理后端（默认 http://127.0.0.1:18081）
# 用法：API_URL=http://127.0.0.1:18081 bash test/security/stage2-api-security.sh
set -u

API_URL="${API_URL:-http://127.0.0.1:18081}"
TOTAL=0
PASS=0
FAIL=0
FAILED=()

# record <name> <pass:1=通过,0=失败> [detail]
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
echo "九章阶段2 管理API安全测试  $API_URL"
echo "============================================================"

# ---- 1. 注入与输入校验 ----
echo ""
echo "---- 1. 注入与输入校验 ----"

RESP=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API_URL/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin'\''OR '\''1'\''='\''1","password":"x","captcha_id":"","captcha_code":""}')
case "$RESP" in 400|401|429) record "sqli-login-username" 1 ;; *) record "sqli-login-username" 0 "status=$RESP";; esac

RESP=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API_URL/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"<script>alert(1)</script>","password":"x","captcha_id":"","captcha_code":""}')
case "$RESP" in 400|401|429) record "xss-login-username" 1 ;; *) record "xss-login-username" 0 "status=$RESP";; esac

BIG=$(python3 -c 'print("A"*200000)')
RESP=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API_URL/api/v1/auth/login" \
  -H 'Content-Type: application/json' -d "{\"username\":\"$BIG\",\"password\":\"x\"}")
case "$RESP" in 400|401|413|429) record "oversized-body" 1 ;; *) record "oversized-body" 0 "status=$RESP";; esac

RESP=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API_URL/api/v1/auth/login" \
  -H 'Content-Type: text/plain' -d 'not json')
case "$RESP" in 400|401|429) record "invalid-content-type" 1 ;; *) record "invalid-content-type" 0 "status=$RESP";; esac

# ---- 2. 认证与会话安全 ----
echo ""
echo "---- 2. 认证与会话安全 ----"

RESP=$(curl -s -o /dev/null -w "%{http_code}" "$API_URL/api/v1/users")
[ "$RESP" = "401" ] && record "unauth-protected-endpoint" 1 || record "unauth-protected-endpoint" 0 "status=$RESP"

RESP=$(curl -s -o /dev/null -w "%{http_code}" "$API_URL/api/v1/auth/me" \
  -H "Cookie: jiuzhang_session=forged-session-id-12345")
[ "$RESP" = "401" ] && record "forged-session-cookie" 1 || record "forged-session-cookie" 0 "status=$RESP"

RESP=$(curl -s -o /dev/null -w "%{http_code}" "$API_URL/api/v1/auth/me" \
  -H "Cookie: jiuzhang_session=../../etc/passwd")
[ "$RESP" = "401" ] && record "malformed-session-id" 1 || record "malformed-session-id" 0 "status=$RESP"

RESP=$(curl -s -o /dev/null -w "%{http_code}" "$API_URL/api/v1/auth/captcha")
[ "$RESP" = "200" ] && record "captcha-endpoint-available" 1 || record "captcha-endpoint-available" 0 "status=$RESP"

# ---- 3. 安全响应头 ----
echo ""
echo "---- 3. 安全响应头 ----"

HEADERS=$(curl -s -I "$API_URL/api/v1/health")
echo "$HEADERS" | grep -qi "X-Content-Type-Options: nosniff" && record "header-nosniff" 1 || record "header-nosniff" 0 "missing"
echo "$HEADERS" | grep -qi "X-Frame-Options: DENY" && record "header-xfo" 1 || record "header-xfo" 0 "missing"
echo "$HEADERS" | grep -qi "Cache-Control: no-store" && record "header-cache-control" 1 || record "header-cache-control" 0 "missing"
XPB=$(echo "$HEADERS" | grep -ci "x-powered-by" || true)
[ "$XPB" = "0" ] && record "no-x-powered-by" 1 || record "no-x-powered-by" 0 "present"

# ---- 4. 信息泄露 ----
echo ""
echo "---- 4. 信息泄露 ----"

BODY=$(curl -s "$API_URL/api/v1/nonexistent-endpoint-xyz")
if echo "$BODY" | grep -qiE "goroutine|panic|/Users/|/home/|stack trace"; then
  record "error-no-stack-404" 0 "leaks internal info"
else
  record "error-no-stack-404" 1
fi

BODY=$(curl -s -X POST "$API_URL/api/v1/auth/login" -H 'Content-Type: application/json' -d '{invalid')
if echo "$BODY" | grep -qiE "goroutine|panic|sql:|SELECT |/Users/|/home/"; then
  record "error-no-stack-badjson" 0 "leaks internal info"
else
  record "error-no-stack-badjson" 1
fi

# ---- 5. 枚举与限速 ----
echo ""
echo "---- 5. 枚举与限速 ----"

B1=$(curl -s -X POST "$API_URL/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d '{"username":"definitely_not_exist_user_12345","password":"x","captcha_id":"","captcha_code":""}' | python3 -c 'import json,sys; print(json.load(sys.stdin).get("message",""))' 2>/dev/null || echo "parse_error")
B2=$(curl -s -X POST "$API_URL/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d '{"username":"jiuzhang_admin","password":"wrongpassword","captcha_id":"","captcha_code":""}' | python3 -c 'import json,sys; print(json.load(sys.stdin).get("message",""))' 2>/dev/null || echo "parse_error")
if [ "$B1" = "$B2" ]; then
  record "no-user-enumeration" 1
else
  record "no-user-enumeration" 0 "msg1=[$B1] msg2=[$B2]"
fi

# ---- 6. 传输安全基线 ----
echo ""
echo "---- 6. 传输安全基线 ----"

BODY=$(curl -s "$API_URL/api/v1/health")
if echo "$BODY" | grep -qiE "password|secret|token|private"; then
  record "health-no-sensitive" 0 "leaks"
else
  record "health-no-sensitive" 1
fi

echo ""
echo "============================================================"
echo "安全测试汇总"
echo "总用例数: $TOTAL"
echo "通过:     $PASS"
echo "失败:     $FAIL"
if [ "$FAIL" -gt 0 ]; then
  echo "失败用例:"
  for c in "${FAILED[@]}"; do echo "  - $c"; done
fi
echo "============================================================"
[ "$FAIL" -eq 0 ]
