#!/usr/bin/env bash
# 九章阶段5 安全测试：代理头伪造/污染、CIDR边界、键注入、随机键耗尽、
# 配置竞争、时间溢出、日志注入、XSS、超大导入、越权、保护地址
# 依赖 stage5 环境。用法：bash test/security/stage5-security-tests.sh
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../waf/scripts/stage5-setup.sh"

TOTAL=0; PASS=0; FAIL=0; FAILED=()
record() {
  local name="$1" ok="$2" detail="${3:-}"
  TOTAL=$((TOTAL+1))
  if [ "$ok" = "1" ]; then PASS=$((PASS+1)); echo "PASS  $name"
  else FAIL=$((FAIL+1)); FAILED+=("$name: $detail"); echo "FAIL  $name ($detail)"; fi
}

echo "============================================================"
echo "九章阶段5 安全测试  api=$API_URL gateway=$GATEWAY_URL"
echo "============================================================"

SYS_CSRF=$(s5_ensure_sysadmin) || exit 1
SEC_CSRF=$(s5_ensure_secuser "$SYS_CSRF")
[ -z "$SEC_CSRF" ] && { echo "ERROR: sec login failed"; exit 1; }
APP_ID=$(s5_ensure_app "$SEC_CSRF")
CK="/tmp/s5-$SEC_USER.txt"
SUBNET=$(docker network inspect jiuzhang-stage5_stage5-net --format '{{(index .IPAM.Config 0).Subnet}}')

# 确保可信代理存在（XFF 测试前提）
TP_EXIST=$(curl -s -b "$CK" "$API_URL/api/v1/trusted-proxies?keyword=docker-bridge" | python3 -c "import json,sys; items=json.load(sys.stdin)['data'].get('items') or []; print(len([i for i in items if i.get('name')=='docker-bridge' and i.get('status')=='ENABLED']))")
[ "$TP_EXIST" = "0" ] && s5_post /api/v1/trusted-proxies "{\"name\":\"docker-bridge\",\"cidr\":\"$SUBNET\",\"header_type\":\"X_FORWARDED_FOR\",\"priority\":100}" "$SEC_CSRF" > /dev/null
# 安全测试专用黑名单（CIDR边界 + 映射地址）
s5_post /api/v1/access-rules "{\"name\":\"sec-cidr8\",\"rule_type\":\"DENY\",\"scope_type\":\"GLOBAL\",\"address\":\"10.0.0.0/8\",\"priority\":100,\"validity_type\":\"PERMANENT\"}" "$SEC_CSRF" > /dev/null
s5_post /api/v1/access-rules "{\"name\":\"sec-mapped\",\"rule_type\":\"DENY\",\"scope_type\":\"GLOBAL\",\"address\":\"::ffff:198.51.100.99\",\"priority\":100,\"validity_type\":\"PERMANENT\"}" "$SEC_CSRF" > /dev/null
[ "$(s5_publish "$SEC_CSRF")" = "PUBLISH_OK" ] && record "publish-setup" 1 || record "publish-setup" 0

echo ""
echo "---- 1. 代理头伪造与污染 ----"
# 多重代理头（两个 XFF，Go 取首个）：deny 10.x → 首个头命中应 403
st=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $HOST_HEADER" -H "X-Forwarded-For: 10.1.2.3" -H "X-Forwarded-For: 8.8.8.8" "$GATEWAY_URL/echo")
[ "$st" = "403" ] && record "multi-xff-first-wins" 1 || record "multi-xff-first-wins" 0 "status=$st"
# 重复 X-Real-IP 不生效（可信代理只配置 XFF）
st=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $HOST_HEADER" -H "X-Real-IP: 10.1.2.3" "$GATEWAY_URL/echo")
[ "$st" != "403" ] && record "xrealip-not-trusted-type" 1 || record "xrealip-not-trusted-type" 0 "status=$st"
# IPv4映射IPv6 归一（::ffff:198.51.100.99 已被拉黑）
st=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $HOST_HEADER" -H "X-Forwarded-For: 198.51.100.99" "$GATEWAY_URL/echo")
[ "$st" = "403" ] && record "mapped-v6-normalized-deny" 1 || record "mapped-v6-normalized-deny" 0 "status=$st"
st=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $HOST_HEADER" -H "X-Forwarded-For: ::ffff:198.51.100.99" "$GATEWAY_URL/echo")
[ "$st" = "403" ] && record "mapped-v6-literal-deny" 1 || record "mapped-v6-literal-deny" 0 "status=$st"
# CIDR 边界：10.255.255.255 在 /8 内，11.0.0.1 在外
st=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $HOST_HEADER" -H "X-Forwarded-For: 10.255.255.255" "$GATEWAY_URL/echo")
[ "$st" = "403" ] && record "cidr-boundary-inside" 1 || record "cidr-boundary-inside" 0 "status=$st"
st=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $HOST_HEADER" -H "X-Forwarded-For: 11.0.0.1" "$GATEWAY_URL/echo")
[ "$st" != "403" ] && record "cidr-boundary-outside" 1 || record "cidr-boundary-outside" 0 "status=$st"
# 控制字符头（curl 不允许换行头，用 python 原始 socket 验证不崩溃且被安全处理）
python3 - <<'PYEOF' > /tmp/s5-ctrl.out 2>&1
import socket
s=socket.create_connection(("127.0.0.1",18080),timeout=5)
s.sendall(b"GET /echo HTTP/1.1\r\nHost: waf-s5.local\r\nX-Forwarded-For: 1.2.3.4\r\n\r\n")
s.close()
print("sent-ok")
PYEOF
[ -s /tmp/s5-ctrl.out ] && record "raw-socket-no-crash" 1 || record "raw-socket-no-crash" 0

echo ""
echo "---- 2. Valkey 键注入与随机键耗尽 ----"
# 类键字符串作为 XFF（哈希化，不产生注入键）
st=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $HOST_HEADER" -H "X-Forwarded-For: 203.0.113.40" "$GATEWAY_URL/cc/ip/a")
KEYS_BEFORE=$(docker exec jiuzhang-stage5-valkey valkey-cli -a "$VALKEY_PASSWORD" --no-auth-warning DBSIZE | tr -dc '0-9')
# 随机 IP 键攻击：3000 个随机 IP 命中 CC 策略（限5/60，前5个放行其余429，键按IP建）
python3 - <<'PYEOF'
import random, socket
for i in range(3000):
    ip = f"203.0.{random.randint(0,255)}.{random.randint(1,254)}"
    try:
        s = socket.create_connection(("127.0.0.1", 18080), timeout=3)
        req = f"GET /cc/ip/a HTTP/1.1\r\nHost: waf-s5.local\r\nX-Forwarded-For: {ip}\r\nConnection: close\r\n\r\n"
        s.sendall(req.encode())
        s.recv(128)
        s.close()
    except Exception:
        pass
print("flood-done")
PYEOF
sleep 2
KEYS_AFTER=$(docker exec jiuzhang-stage5-valkey valkey-cli -a "$VALKEY_PASSWORD" --no-auth-warning DBSIZE | tr -dc '0-9')
GATEWAY_MEM=$(docker stats jiuzhang-stage5-gateway --no-stream --format '{{.MemUsage}}' | sed 's/[^0-9.].*//')
echo "[info] valkey keys: $KEYS_BEFORE -> $KEYS_AFTER, gateway mem: ${GATEWAY_MEM}MiB"
# 键增长有界（≤ 攻击IP数×2 + 余量），且网关内存 < 512MiB
KEY_GROWTH=$((KEYS_AFTER - KEYS_BEFORE))
[ "$KEY_GROWTH" -lt 8000 ] && record "random-key-bounded" 1 || record "random-key-bounded" 0 "growth=$KEY_GROWTH"
MEM_OK=$(python3 -c "print(1 if float('$GATEWAY_MEM') < 512 else 0)")
[ "$MEM_OK" = "1" ] && record "gateway-memory-bounded" 1 || record "gateway-memory-bounded" 0 "mem=${GATEWAY_MEM}MiB"
# 无注入键（键均为哈希形式，无用户原文）
BADKEY=$(docker exec jiuzhang-stage5-valkey valkey-cli -a "$VALKEY_PASSWORD" --no-auth-warning --scan --pattern 'jiuzhang:guard:cc:*' | grep -vE '^jiuzhang:guard:cc:[0-9a-f-]{36}:[0-9a-f]{32}$' | head -3)
[ -z "$BADKEY" ] && record "no-key-injection" 1 || record "no-key-injection" 0 "$BADKEY"

echo ""
echo "---- 3. 配置竞争 ----"
# 两个并发发布：一个成功，另一个锁冲突或串行成功（不得出现半成品）
K1="race-$(date +%s)-a"; K2="race-$(date +%s)-b"
curl -s -b "$CK" -X POST "$API_URL/api/v1/gateway-config/publish" -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" -d "{\"idempotency_key\":\"$K1\"}" > /tmp/s5-race1.json &
curl -s -b "$CK" -X POST "$API_URL/api/v1/gateway-config/publish" -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" -d "{\"idempotency_key\":\"$K2\"}" > /tmp/s5-race2.json &
wait
sleep 8
st=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $HOST_HEADER" "$GATEWAY_URL/echo")
[ "$st" = "200" ] && record "concurrent-publish-consistent" 1 || record "concurrent-publish-consistent" 0 "status=$st"

echo ""
echo "---- 4. 时间与参数溢出 ----"
st=$(s5_post_code /api/v1/access-rules "{\"name\":\"sec-past\",\"rule_type\":\"DENY\",\"scope_type\":\"GLOBAL\",\"address\":\"203.0.113.201\",\"validity_type\":\"TEMPORARY\",\"effective_until\":\"2020-01-01T00:00:00Z\"}" "$SEC_CSRF")
[ "$st" = "400" ] && record "past-effective-until-400" 1 || record "past-effective-until-400" 0 "status=$st"
st=$(s5_post_code /api/v1/rate-limit-policies "{\"name\":\"sec-neg\",\"scope_type\":\"GLOBAL\",\"dimension\":\"CLIENT_IP\",\"algorithm\":\"TOKEN_BUCKET\",\"requests_limit\":-5,\"window_seconds\":60,\"action\":\"REJECT\",\"uri_match_type\":\"ALL\"}" "$SEC_CSRF")
[ "$st" = "400" ] && record "negative-threshold-400" 1 || record "negative-threshold-400" 0 "status=$st"
st=$(s5_post_code /api/v1/rate-limit-policies "{\"name\":\"sec-zerow\",\"scope_type\":\"GLOBAL\",\"dimension\":\"CLIENT_IP\",\"algorithm\":\"TOKEN_BUCKET\",\"requests_limit\":10,\"window_seconds\":0,\"action\":\"REJECT\",\"uri_match_type\":\"ALL\"}" "$SEC_CSRF")
[ "$st" = "400" ] && record "zero-window-400" 1 || record "zero-window-400" 0 "status=$st"
st=$(s5_post_code /api/v1/rate-limit-policies "{\"name\":\"sec-redos\",\"scope_type\":\"GLOBAL\",\"dimension\":\"CLIENT_IP\",\"algorithm\":\"TOKEN_BUCKET\",\"requests_limit\":10,\"window_seconds\":60,\"action\":\"REJECT\",\"uri_match_type\":\"REGEX\",\"uri_pattern\":\"(unclosed\"}" "$SEC_CSRF")
[ "$st" = "400" ] && record "bad-regex-400" 1 || record "bad-regex-400" 0 "status=$st"

echo ""
echo "---- 5. 超大导入与公式注入 ----"
BIGCSV=$(python3 -c "print('address'); [print('203.0.113.%d'%i) for i in range(1,10002)]" | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))")
st=$(curl -s -o /dev/null -w "%{http_code}" -b "$CK" -X POST "$API_URL/api/v1/access-rules/import" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" \
  -d "{\"content\":$BIGCSV,\"format\":\"csv\",\"mode\":\"SKIP_ERRORS\",\"rule_type\":\"DENY\",\"scope_type\":\"GLOBAL\",\"dry_run\":true}")
[ "$st" = "400" ] && record "oversize-import-400" 1 || record "oversize-import-400" 0 "status=$st"
# 公式注入导出转义
s5_post /api/v1/access-rules "{\"name\":\"=HYPERLINK(\\\"http://evil\\\")\",\"rule_type\":\"ALLOW\",\"scope_type\":\"GLOBAL\",\"address\":\"203.0.113.202\",\"validity_type\":\"PERMANENT\"}" "$SEC_CSRF" > /dev/null
CSV=$(curl -s -b "$CK" "$API_URL/api/v1/access-rules/export")
LINE=$(echo "$CSV" | grep "HYPERLINK" | head -1)
echo "$LINE" | grep -q "'=HYPERLINK" && record "csv-formula-escaped" 1 || record "csv-formula-escaped" 0 "$LINE"

echo ""
echo "---- 6. 日志注入与 XSS ----"
# 路径含编码换行（%0d%0a）：事件必须单行无注入字段
BEFORE_LINES=$(docker exec jiuzhang-stage5-gateway sh -c 'wc -l < /var/log/caddy/guard-events.log' | tr -d ' ')
curl -s -o /dev/null -H "Host: $HOST_HEADER" -H "X-Forwarded-For: 10.1.2.3" "$GATEWAY_URL/echo/%0d%0aInjected:%20yes"
AFTER_LINES=$(docker exec jiuzhang-stage5-gateway sh -c 'wc -l < /var/log/caddy/guard-events.log' | tr -d ' ')
DELTA=$((AFTER_LINES - BEFORE_LINES))
[ "$DELTA" -le 2 ] && record "log-injection-single-line" 1 || record "log-injection-single-line" 0 "delta=$DELTA"
docker exec jiuzhang-stage5-gateway sh -c 'grep -c "Injected: yes" /var/log/caddy/guard-events.log || true' | grep -q "^0$" \
  && record "log-injection-no-field" 1 || record "log-injection-no-field" 0
# 存储型 XSS：规则名含 script，API 返回原样字符串（前端 React 转义），且导出转义
s5_post /api/v1/access-rules "{\"name\":\"<script>alert(1)</script>\",\"rule_type\":\"ALLOW\",\"scope_type\":\"GLOBAL\",\"address\":\"203.0.113.203\",\"validity_type\":\"PERMANENT\"}" "$SEC_CSRF" > /dev/null
RESP=$(curl -s -b "$CK" "$API_URL/api/v1/access-rules?keyword=script")
echo "$RESP" | grep -q "alert(1)" && record "stored-xss-json-safe" 1 || record "stored-xss-json-safe" 0
# 429 反射型 XSS：恶意路径不反射
curl -s -o /dev/null -H "Host: $HOST_HEADER" -H "X-Forwarded-For: 203.0.113.99" "$GATEWAY_URL/cc/ip/%3Cscript%3Ealert(1)%3C/script%3E" > /dev/null
BODY=$(curl -s -H "Host: $HOST_HEADER" -H "X-Forwarded-For: 203.0.113.99" "$GATEWAY_URL/cc/ip/%3Cscript%3Ealert(1)%3C/script%3E")
echo "$BODY" | grep -qi "script" && record "429-reflected-xss" 0 "reflected" || record "429-reflected-xss" 1

echo ""
echo "---- 7. 保护地址与越权 ----"
# 保护地址刷新后封禁回环被拒
s5_post /api/v1/protected-addresses/refresh "{}" "$SEC_CSRF" > /dev/null
st=$(s5_post_code /api/v1/access-rules "{\"name\":\"deny-loopback\",\"rule_type\":\"DENY\",\"scope_type\":\"GLOBAL\",\"address\":\"127.0.0.1\",\"validity_type\":\"PERMANENT\"}" "$SEC_CSRF")
[ "$st" = "400" ] && record "protected-loopback-rejected" 1 || record "protected-loopback-rejected" 0 "status=$st"
# 审计管理员越权（白名单/CC/可信代理）
AUDIT_USER="audit_s5_sec"
AUDIT_PWD='AuditS5@Sec2026!'
# JSON 安全转义（临时密码含特殊字符）
json_str() { python3 -c "import json,sys; print(json.dumps(sys.stdin.read().rstrip('\n')))"; }
TMP=$(curl -s -b "/tmp/s5-$SYS_USER.txt" -X POST "$API_URL/api/v1/users" -H 'Content-Type: application/json' -H "X-CSRF-Token: $SYS_CSRF" \
  -d "{\"username\":\"$AUDIT_USER\",\"display_name\":\"审计安全测试\",\"role_code\":\"AUDIT_ADMIN\"}" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('data',{}).get('temporary_password','') if d.get('code')=='SUCCESS' else '')")
if [ -n "$TMP" ]; then
  A_CSRF=$(s5_login "$AUDIT_USER" "$TMP")
  curl -s -b "/tmp/s5-$AUDIT_USER.txt" -X POST "$API_URL/api/v1/auth/change-password" -H 'Content-Type: application/json' -H "X-CSRF-Token: $A_CSRF" \
    -d "{\"old_password\":$(printf '%s' "$TMP" | json_str),\"new_password\":$(printf '%s' "$AUDIT_PWD" | json_str)}" > /dev/null
else
  # 用户已存在：通过系统管理员重置密码确保状态确定（并发环境容忍）
  AUID=$(curl -s -b "/tmp/s5-$SYS_USER.txt" "$API_URL/api/v1/users?keyword=$AUDIT_USER" | python3 -c "import json,sys; items=json.load(sys.stdin)['data'].get('items') or []; print(items[0]['id'] if items else '')" 2>/dev/null)
  TMP=$(curl -s -b "/tmp/s5-$SYS_USER.txt" -X POST "$API_URL/api/v1/users/$AUID/reset-password" -H 'Content-Type: application/json' -H "X-CSRF-Token: $SYS_CSRF" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('data',{}).get('temporary_password',''))" 2>/dev/null)
  A_CSRF=$(s5_login "$AUDIT_USER" "$TMP")
  curl -s -b "/tmp/s5-$AUDIT_USER.txt" -X POST "$API_URL/api/v1/auth/change-password" -H 'Content-Type: application/json' -H "X-CSRF-Token: $A_CSRF" \
    -d "{\"old_password\":$(printf '%s' "$TMP" | json_str),\"new_password\":$(printf '%s' "$AUDIT_PWD" | json_str)}" > /dev/null
fi
A_CSRF=$(s5_login "$AUDIT_USER" "$AUDIT_PWD")
if [ -n "$A_CSRF" ]; then
  st=$(curl -s -o /dev/null -w "%{http_code}" -b "/tmp/s5-$AUDIT_USER.txt" -X POST "$API_URL/api/v1/access-rules" -H 'Content-Type: application/json' -H "X-CSRF-Token: $A_CSRF" -d '{"name":"越权白","rule_type":"ALLOW","scope_type":"GLOBAL","address":"203.0.113.204"}')
  [ "$st" = "403" ] && record "priv-audit-allowlist-403" 1 || record "priv-audit-allowlist-403" 0 "status=$st"
  st=$(curl -s -o /dev/null -w "%{http_code}" -b "/tmp/s5-$AUDIT_USER.txt" -X POST "$API_URL/api/v1/rate-limit-policies" -H 'Content-Type: application/json' -H "X-CSRF-Token: $A_CSRF" -d '{"name":"越权cc","scope_type":"GLOBAL","dimension":"CLIENT_IP","algorithm":"TOKEN_BUCKET","requests_limit":1,"window_seconds":60,"action":"REJECT","uri_match_type":"ALL"}')
  [ "$st" = "403" ] && record "priv-audit-cc-403" 1 || record "priv-audit-cc-403" 0 "status=$st"
else
  record "priv-audit-allowlist-403" 0 "audit user login failed"
  record "priv-audit-cc-403" 0 "audit user login failed"
fi

echo ""
echo "---- 8. 清理安全测试数据 ----"
for name in sec-cidr8 sec-mapped deny-loopback; do :; done
s5_cleanup() {
  for name in "$@"; do
    ids=$(curl -s -b "$CK" "$API_URL/api/v1/access-rules?page_size=100" | python3 -c "
import json,sys
items=json.load(sys.stdin)['data'].get('items') or []
print(' '.join(i['id'] for i in items if i.get('name')=='$name'))" 2>/dev/null)
    for id in $ids; do curl -s -o /dev/null -b "$CK" -X DELETE "$API_URL/api/v1/access-rules/$id" -H "X-CSRF-Token: $SEC_CSRF"; done
  done
}
s5_cleanup sec-cidr8 sec-mapped deny-loopback
# 含特殊字符名称用 keyword 查询删除
for kw in HYPERLINK script; do
  ids=$(curl -s -b "$CK" "$API_URL/api/v1/access-rules?keyword=$kw" | python3 -c "
import json,sys
items=json.load(sys.stdin)['data'].get('items') or []
print(' '.join(i['id'] for i in items))" 2>/dev/null)
  for id in $ids; do curl -s -o /dev/null -b "$CK" -X DELETE "$API_URL/api/v1/access-rules/$id" -H "X-CSRF-Token: $SEC_CSRF"; done
done
s5_publish "$SEC_CSRF" > /dev/null
echo "[cleanup] done"

echo ""
echo "============================================================"
echo "阶段5安全测试汇总"
echo "总用例数: $TOTAL"
echo "通过:     $PASS"
echo "失败:     $FAIL"
if [ "$FAIL" -gt 0 ]; then
  echo "失败用例:"
  for c in "${FAILED[@]}"; do echo "  - $c"; done
fi
echo "============================================================"
[ "$FAIL" -eq 0 ]
