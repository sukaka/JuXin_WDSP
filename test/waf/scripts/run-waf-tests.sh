#!/usr/bin/env bash
# 九章阶段1 WAF 自动化测试
# 用法：
#   GATEWAY_URL=http://127.0.0.1:18080 EXPECT_MODE=on bash test/waf/scripts/run-waf-tests.sh
# EXPECT_MODE: on（防护模式，攻击期望 403）| detection（观察模式，攻击期望 200 到达源站）
set -u

GATEWAY_URL="${GATEWAY_URL:-http://127.0.0.1:18080}"
EXPECT_MODE="${EXPECT_MODE:-on}"
TMPDIR_TEST="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_TEST"' EXIT

TOTAL=0
PASS=0
FAIL=0
SKIP=0
FAILED_CASES=()

# 期望状态码判定
expected_attack_status() {
  if [ "$EXPECT_MODE" = "on" ]; then echo 403; else echo 200; fi
}

# run_case <name> <expect_status> <expect_origin:yes|no|any> <curl args...>
run_case() {
  local name="$1"; local want_status="$2"; local want_origin="$3"; shift 3
  TOTAL=$((TOTAL+1))
  local resp status body
  resp="$(curl -s -w $'\n%{http_code}' --max-time 10 "$@" 2>&1)"
  status="$(echo "$resp" | tail -n1)"
  body="$(echo "$resp" | sed '$d')"
  local ok=1 reason=""
  if [ "$status" != "$want_status" ]; then
    ok=0; reason="status=$status want=$want_status"
  fi
  if [ "$ok" = 1 ] && [ "$want_origin" != "any" ]; then
    local mark
    mark="$(echo "$body" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("upstream_mark",""))' 2>/dev/null || echo "")"
    if [ "$want_origin" = "yes" ] && [ "$mark" != "REACHED_ORIGIN" ]; then
      ok=0; reason="not reached origin (status=$status)"
    fi
    if [ "$want_origin" = "no" ]; then
      # 阻断时应返回九章阻断页面
      if ! echo "$body" | grep -q "请求已被安全策略阻断"; then
        ok=0; reason="blocked but no jiuzhang block page (status=$status)"
      fi
    fi
  fi
  if [ "$ok" = 1 ]; then
    PASS=$((PASS+1)); echo "PASS  $name"
  else
    FAIL=$((FAIL+1)); FAILED_CASES+=("$name: $reason"); echo "FAIL  $name ($reason)"
  fi
}

echo "============================================================"
echo "九章阶段1 WAF 自动化测试"
echo "GATEWAY_URL=$GATEWAY_URL EXPECT_MODE=$EXPECT_MODE"
echo "============================================================"

ATTACK_STATUS="$(expected_attack_status)"
if [ "$EXPECT_MODE" = "on" ]; then ATTACK_ORIGIN="no"; else ATTACK_ORIGIN="yes"; fi

echo ""
echo "---- 1. 正常业务请求（期望 200 且到达源站） ----"
run_case "normal-get-root"        200 yes "$GATEWAY_URL/"
run_case "normal-get-echo"        200 yes "$GATEWAY_URL/echo?a=1&b=2"
run_case "normal-post-form"       200 yes -X POST "$GATEWAY_URL/echo" -d "username=zhangsan&city=beijing"
run_case "normal-json"            200 yes -X POST "$GATEWAY_URL/api/json" -H "Content-Type: application/json" -d '{"name":"test","value":42}'
run_case "normal-chinese-param"   200 yes "$GATEWAY_URL/echo?msg=%E4%BD%A0%E5%A5%BD%E4%B8%96%E7%95%8C"
run_case "normal-urlencoded"      200 yes "$GATEWAY_URL/echo?q=a%2Bb%26c%3Dd"
run_case "normal-cookie"          200 yes "$GATEWAY_URL/echo" -H "Cookie: theme=dark; uid=1001"
run_case "normal-custom-header"   200 yes "$GATEWAY_URL/echo" -H "X-Biz-Token: abcdef123456"
run_case "normal-login-form"      200 yes -X POST "$GATEWAY_URL/login" -d "user=admin&pass=s3cret-normal"
# 文件上传
echo "jiuzhang upload test file" > "$TMPDIR_TEST/upload.txt"
run_case "normal-file-upload"     200 yes -X POST "$GATEWAY_URL/upload" -F "file=@$TMPDIR_TEST/upload.txt"
# 较长参数（约 2KB）
LONG_PARAM="$(python3 -c 'print("x"*2000)')"
run_case "normal-long-param"      200 yes "$GATEWAY_URL/echo?data=$LONG_PARAM"

echo ""
echo "---- 2. SQL 注入（期望 ${ATTACK_STATUS}） ----"
run_case "sqli-query-union"       "$ATTACK_STATUS" "$ATTACK_ORIGIN" "$GATEWAY_URL/echo?id=1%20UNION%20SELECT%20username,password%20FROM%20users--"
run_case "sqli-query-tautology"   "$ATTACK_STATUS" "$ATTACK_ORIGIN" "$GATEWAY_URL/echo?q=1'%20OR%20'1'='1"
run_case "sqli-post-form"         "$ATTACK_STATUS" "$ATTACK_ORIGIN" -X POST "$GATEWAY_URL/login" -d "user=admin'--&pass=x"
run_case "sqli-json-field"        "$ATTACK_STATUS" "$ATTACK_ORIGIN" -X POST "$GATEWAY_URL/api/json" -H "Content-Type: application/json" -d '{"q":"1'"'"' OR '"'"'1'"'"'='"'"'1"}'
run_case "sqli-encoded"           "$ATTACK_STATUS" "$ATTACK_ORIGIN" "$GATEWAY_URL/echo?q=%31%27%20%4F%52%20%27%31%27%3D%27%31"

echo ""
echo "---- 3. XSS（期望 ${ATTACK_STATUS}） ----"
run_case "xss-query-script"       "$ATTACK_STATUS" "$ATTACK_ORIGIN" "$GATEWAY_URL/echo?q=%3Cscript%3Ealert(1)%3C/script%3E"
run_case "xss-post-form"          "$ATTACK_STATUS" "$ATTACK_ORIGIN" -X POST "$GATEWAY_URL/echo" -d "comment=<img src=x onerror=alert(1)>"
run_case "xss-json-field"         "$ATTACK_STATUS" "$ATTACK_ORIGIN" -X POST "$GATEWAY_URL/api/json" -H "Content-Type: application/json" -d '{"html":"<svg onload=alert(1)>"}'
run_case "xss-event-attr"         "$ATTACK_STATUS" "$ATTACK_ORIGIN" "$GATEWAY_URL/echo?q=%22%20onfocus%3Dalert(1)%20autofocus%3D%22"
run_case "xss-encoded"            "$ATTACK_STATUS" "$ATTACK_ORIGIN" "$GATEWAY_URL/echo?q=%253Cscript%253Ealert(1)%253C/script%253E"

echo ""
echo "---- 4. 命令注入（期望 ${ATTACK_STATUS}） ----"
# 说明：CRS PL1 对含具体命令/路径的载荷有效拦截；
# 无实义的简单分隔符（如 ;id;、a|id）在 PL1 评分不足，属于 CRS 官方误报控制设计。
run_case "cmdi-semicolon"         "$ATTACK_STATUS" "$ATTACK_ORIGIN" "$GATEWAY_URL/echo?host=127.0.0.1;cat%20/etc/passwd"
run_case "cmdi-substitution"      "$ATTACK_STATUS" "$ATTACK_ORIGIN" "$GATEWAY_URL/echo?x=%24%28id%29"
run_case "cmdi-pipe-shell"        "$ATTACK_STATUS" "$ATTACK_ORIGIN" "$GATEWAY_URL/echo?x=a%7Cnc%20-e%20%2Fbin%2Fsh"
run_case "cmdi-backtick"          "$ATTACK_STATUS" "$ATTACK_ORIGIN" "$GATEWAY_URL/echo?x=%60cat%20%2Fetc%2Fpasswd%60"
run_case "cmdi-encoded"           "$ATTACK_STATUS" "$ATTACK_ORIGIN" "$GATEWAY_URL/echo?x=%3B%63%61%74%20%2F%65%74%63%2F%70%61%73%73%77%64"

echo ""
echo "---- 5. 路径攻击（期望 ${ATTACK_STATUS}） ----"
run_case "path-traversal"         "$ATTACK_STATUS" "$ATTACK_ORIGIN" "$GATEWAY_URL/echo?f=../../../../etc/passwd"
run_case "path-encoded"           "$ATTACK_STATUS" "$ATTACK_ORIGIN" "$GATEWAY_URL/echo?f=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
run_case "path-double-encoded"    "$ATTACK_STATUS" "$ATTACK_ORIGIN" "$GATEWAY_URL/echo?f=%252e%252e%252f%252e%252e%252fetc%252fpasswd"
run_case "path-lfi-proc"          "$ATTACK_STATUS" "$ATTACK_ORIGIN" "$GATEWAY_URL/echo?f=/proc/self/environ"

echo ""
echo "---- 6. 扫描器特征（期望 ${ATTACK_STATUS}） ----"
run_case "scanner-ua-sqlmap"      "$ATTACK_STATUS" "$ATTACK_ORIGIN" "$GATEWAY_URL/echo" -H "User-Agent: sqlmap/1.5.2"
run_case "scanner-ua-nikto"       "$ATTACK_STATUS" "$ATTACK_ORIGIN" "$GATEWAY_URL/echo" -H "User-Agent: Mozilla/5.00 (Nikto/2.1.6)"

echo ""
echo "============================================================"
echo "测试结果汇总"
echo "总用例数: $TOTAL"
echo "通过:     $PASS"
echo "失败:     $FAIL"
echo "跳过:     $SKIP"
if [ "$FAIL" -gt 0 ]; then
  echo ""
  echo "失败用例:"
  for c in "${FAILED_CASES[@]}"; do echo "  - $c"; done
fi
echo "============================================================"
[ "$FAIL" -eq 0 ]
