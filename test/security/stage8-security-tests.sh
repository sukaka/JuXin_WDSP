#!/usr/bin/env bash
# 九章阶段8 安全测试（任务书六十一章节选，WDSP）：
#   a) XML 实体攻击（XXE）：DOCTYPE/ENTITY 不被解析展开，引擎不崩溃（网关侧置 XMLDTDBlocked）；
#   b) 超大请求体（>1MB JSON）：解析截断而非 5xx；
#   c) 敏感数据 Query 明文：PROTECT 模式 sensitive.in_query（BLOCK 类）→ 403，恢复 OBSERVE 后放行；
#   d) 权限越权：无会话 401、AUDIT_ADMIN 无 api_asset.confirm 权限 403；
#   e) 注入：keyword/路径带 SQLi/XSS 载荷，list 接口不报错不泄露内部细节；
#   f) CSRF：写接口缺 X-CSRF-Token → 403。
#
# 与实现对齐的关键事实：
#   - 应用防护模式 OFF（s5_ensure_app），Coraza 不拦截，断言聚焦 API 动态防护管线自身行为；
#   - 解析限制 DefaultParseLimits：MaxBodyParseBytes=1MiB，超限截断采样后继续放行（fail-open 设计）；
#   - XML 遇 DOCTYPE 即停止解析并置 req.xml_dtd_blocked（parser/parse_xml.go，XXE 防御）；
#   - sensitive.in_query 为 BLOCK 类命中（detectors/sensitive.go），PROTECT 下定案 ActionBlock=403；
#   - 权限链：session → CSRFProtect → RequireAuth → RequirePermission（app.go），
#     AUDIT_ADMIN 仅有 api_asset.read（迁移 000019），无 confirm 权限；
#   - keyword 过滤为参数化 ILIKE（apiassets/store.go），注入载荷只当普通字符串。
#
# 依赖 stage5 编排 + wdsp 覆盖：
#   docker compose --env-file .env -f deployment/docker-compose.stage5.yml -f deployment/docker-compose.wdsp.yml up -d --build
# 用法：bash test/security/stage8-security-tests.sh
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../waf/scripts/stage5-setup.sh"

TS=$(date +%s)
CK="/tmp/s5-$SEC_USER.txt"
AUD_USER="${AUD_USER:-aud_admin_s8}"
AUD_PWD="${AUD_PWD:-AudAdmin@S8!2026}"

TOTAL=0; PASS=0; FAIL=0; FAILED=()
record() {
  local name="$1" ok="$2" detail="${3:-}"
  TOTAL=$((TOTAL+1))
  if [ "$ok" = "1" ]; then PASS=$((PASS+1)); echo "PASS  $name"
  else FAIL=$((FAIL+1)); FAILED+=("$name: $detail"); echo "FAIL  $name ($detail)"; fi
}

# 响应体内部信息泄露检查（panic/堆栈/SQL 错误等）；无泄露返回 0
no_leak() { # $1=响应体文件
  ! grep -Eiq 'panic|goroutine [0-9]|pgx|sqlstate|SQL syntax|pq: |stack trace|runtime error' "$1"
}

# 确保审计管理员用户存在（角色 AUDIT_ADMIN，无 api_asset.confirm 权限），打印其 CSRF
s8_ensure_audituser() {
  # 重新登录系统管理员（调用方传入的 token 可能已被 /auth/me 轮换）
  local sys_csrf
  sys_csrf=$(s5_login "$SYS_USER" "$SYS_PWD")
  [ -z "$sys_csrf" ] && sys_csrf=$(s5_login "$SYS_USER" "$SYS_NEW_PWD")
  local tmp
  tmp=$(curl -s -b "/tmp/s5-$SYS_USER.txt" -X POST "$API_URL/api/v1/users" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $sys_csrf" \
    -d "{\"username\":\"$AUD_USER\",\"display_name\":\"审计管理员S8\",\"role_code\":\"AUDIT_ADMIN\"}" \
    | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('data',{}).get('temporary_password','') if d.get('code')=='SUCCESS' else '')" 2>/dev/null)
  if [ -n "$tmp" ]; then
    local csrf
    csrf=$(s5_login "$AUD_USER" "$tmp")
    curl -s -b "/tmp/s5-$AUD_USER.txt" -X POST "$API_URL/api/v1/auth/change-password" \
      -H 'Content-Type: application/json' -H "X-CSRF-Token: $csrf" \
      -d "{\"old_password\":\"$tmp\",\"new_password\":\"$AUD_PWD\"}" > /dev/null
  fi
  s5_login "$AUD_USER" "$AUD_PWD"
}

echo "============================================================"
echo "九章阶段8 安全测试  gateway=$GATEWAY_URL api=$API_URL ts=$TS"
echo "============================================================"

# ---------- 准备：登录 / 应用 / 发布 ----------
SYS_CSRF=$(s5_ensure_sysadmin) || exit 1
SEC_CSRF=$(s5_ensure_secuser "$SYS_CSRF")
[ -z "$SEC_CSRF" ] && { echo "ERROR: sec login failed"; exit 1; }
APP_ID=$(s5_ensure_app "$SEC_CSRF")
echo "[setup] app=$APP_ID"

# 防护模式恢复保险：PROTECT 用例中途失败也能还原 OBSERVE，不污染后续脚本
PROTECT_ON=0
restore_observe() {
  [ "$PROTECT_ON" = "1" ] || return 0
  curl -s -o /dev/null -b "$CK" -X PUT "$API_URL/api/v1/api-security/policy" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" -d '{"mode":"OBSERVE"}'
  curl -s -o /dev/null -b "$CK" -X POST "$API_URL/api/v1/api-security/policy/publish" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" -d '{}'
  PROTECT_ON=0
}
trap restore_observe EXIT

PUB=$(s5_publish "$SEC_CSRF")
[ "$PUB" = "PUBLISH_OK" ] || { record "首次发布成功" 0 "$PUB"; echo "ABORT"; exit 1; }
echo "[setup] 首次发布成功"

# ---------- a) XML 实体攻击（XXE） ----------
# 带 DOCTYPE + 外部实体（file:///etc/passwd）的 XML：引擎必须拒绝 DTD 解析而不是展开实体
XXE_BODY='<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE order [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<order><id>1</id><name>&xxe;</name></order>'
CODE=$(curl -s -o "/tmp/s8-xxe-resp-$TS.txt" -w "%{http_code}" -H "Host: $HOST_HEADER" \
  -H 'Content-Type: application/xml' -X POST --data-binary "$XXE_BODY" "$GATEWAY_URL/v1/xxe$TS/1")
# 非 5xx 即可：OBSERVE 下应被正常代理（源站 echo 200），任何 4xx 也属于正常拒绝；
# 000（连接被重置/无响应）按失败计——那恰是引擎崩溃的信号
case "$CODE" in
  000|5*) record "a) XXE 请求不引发 5xx（引擎不解析 DTD）" 0 "status=$CODE" ;;
  *)  record "a) XXE 请求不引发 5xx（引擎不解析 DTD）" 1 ;;
esac
# 佐证：该请求产生主事件（无凭据+对象段必命中），证明管线在恶意 XML 下未崩溃、采集正常
sleep 6
XXE_EV=$(curl -s -b "$CK" -G "$API_URL/api/v1/api-security/runtime/events" \
  --data-urlencode "endpoint_key=POST /v1/xxe$TS/{id}" --data-urlencode "page_size=10" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['data'].get('total', 0))" 2>/dev/null)
[ "${XXE_EV:-0}" -ge 1 ] && record "a) XXE 后事件采集链路正常（有主事件）" 1 \
  || record "a) XXE 后事件采集链路正常（有主事件）" 0 "total=$XXE_EV"

# ---------- b) 超大请求体（>1MB JSON）截断而非 5xx ----------
# 目标必须为读取请求体的路径（/echo）：testorigin 对未知路径立即 404 并关闭连接，
# 代理续写大 body 会 broken pipe 返回 502（源站行为，与引擎无关）
BIG_BODY="/tmp/s8-big-body-$TS.json"
python3 -c "import json; print(json.dumps({'id':1,'name':'big','pad':'x'*1250000}))" > "$BIG_BODY"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $HOST_HEADER" \
  -H 'Content-Type: application/json' -X POST --data-binary @"$BIG_BODY" "$GATEWAY_URL/echo")
rm -f "$BIG_BODY"
case "$CODE" in
  000|5*) record "b) 超大 body（>1MB）截断而非 5xx" 0 "status=$CODE" ;;
  *)  record "b) 超大 body（>1MB）截断而非 5xx" 1 ;;
esac

# ---------- c) 敏感 Query 明文：PROTECT 下 sensitive.in_query（BLOCK 类）→ 403 ----------
# 命中前后对比该端点 sensitive.in_query 事件数（佐证 403 归因于该规则而非其他）
in_query_count() {
  curl -s -b "$CK" -G "$API_URL/api/v1/api-security/runtime/events" \
    --data-urlencode "endpoint_key=GET /v1/users/{id}" --data-urlencode "page_size=50" | python3 -c "
import json,sys
items=json.load(sys.stdin)['data'].get('items') or []
n=0
for e in items:
    for d in (e.get('details') or []):
        if d.get('rule_id')=='sensitive.in_query' or d.get('RuleID')=='sensitive.in_query': n+=1
print(n)" 2>/dev/null
}
PUT_MODE=$(curl -s -o /dev/null -w "%{http_code}" -b "$CK" -X PUT "$API_URL/api/v1/api-security/policy" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" -d '{"mode":"PROTECT"}')
PUBP=$(curl -s -b "$CK" -X POST "$API_URL/api/v1/api-security/policy/publish" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" -d '{}' \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['status'])" 2>/dev/null)
if [ "$PUT_MODE" = "200" ] && [ "$PUBP" = "SUCCESS" ]; then
  PROTECT_ON=1
  BEFORE=$(in_query_count)
  CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $HOST_HEADER" "$GATEWAY_URL/v1/users/1?id_card=110")
  [ "$CODE" = "403" ] && record "c) PROTECT 模式敏感 Query（id_card）被 403 阻断" 1 \
    || record "c) PROTECT 模式敏感 Query（id_card）被 403 阻断" 0 "status=$CODE"
  sleep 6
  AFTER=$(in_query_count)
  [ "${AFTER:-0}" -gt "${BEFORE:-0}" ] && record "c) 阻断事件含 sensitive.in_query 明细" 1 \
    || record "c) 阻断事件含 sensitive.in_query 明细" 0 "before=$BEFORE after=$AFTER"
  # 恢复 OBSERVE 并验证放行
  restore_observe
  CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $HOST_HEADER" "$GATEWAY_URL/v1/users/1?id_card=110")
  [ "$CODE" != "403" ] && record "c) 恢复 OBSERVE 后同请求放行（=${CODE}）" 1 \
    || record "c) 恢复 OBSERVE 后同请求放行" 0 "status=$CODE"
else
  record "c) PROTECT 模式敏感 Query（id_card）被 403 阻断" 0 "策略切换失败 put=$PUT_MODE publish=$PUBP"
  record "c) 阻断事件含 sensitive.in_query 明细" 0 "策略切换失败"
  record "c) 恢复 OBSERVE 后同请求放行" 0 "策略切换失败"
fi

# ---------- d) 权限越权 ----------
CODE=$(curl -s -o /dev/null -w "%{http_code}" "$API_URL/api/v1/api-security/endpoints?page_size=1")
[ "$CODE" = "401" ] && record "d) 无会话访问 endpoints 列表返回 401" 1 \
  || record "d) 无会话访问 endpoints 列表返回 401" 0 "status=$CODE"

AUD_CSRF=$(s8_ensure_audituser "$SYS_CSRF")
if [ -z "$AUD_CSRF" ]; then
  record "d) AUDIT_ADMIN 越权 confirm 返回 403" 0 "审计用户登录失败"
else
  # AUDIT_ADMIN 有 api_asset.read 但无 api_asset.confirm（迁移 000019）→ 权限层 403
  CODE=$(curl -s -o /dev/null -w "%{http_code}" -b "/tmp/s5-$AUD_USER.txt" \
    -X POST "$API_URL/api/v1/api-security/endpoints/confirm" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $AUD_CSRF" -d '{"ids":[]}')
  [ "$CODE" = "403" ] && record "d) AUDIT_ADMIN 越权 confirm 返回 403" 1 \
    || record "d) AUDIT_ADMIN 越权 confirm 返回 403" 0 "status=$CODE"
fi

# ---------- e) 注入：路径/字段名带攻击载荷，list 接口不报错不泄露 ----------
INJ_OK=1; INJ_DETAIL=""
for PAYLOAD in "' OR 1=1--" '<script>alert(1)</script>' '{"$gt":""}'; do
  RESP="/tmp/s8-inj-$TS.json"
  CODE=$(curl -s -o "$RESP" -w "%{http_code}" -b "$CK" -G "$API_URL/api/v1/api-security/endpoints" \
    --data-urlencode "keyword=$PAYLOAD" --data-urlencode "page_size=5")
  if [ "$CODE" != "200" ]; then INJ_OK=0; INJ_DETAIL="payload=$PAYLOAD status=$CODE"; break; fi
  if ! no_leak "$RESP"; then INJ_OK=0; INJ_DETAIL="payload=$PAYLOAD 响应泄露内部信息"; break; fi
done
rm -f "/tmp/s8-inj-$TS.json"
[ "$INJ_OK" = "1" ] && record "e) list 接口 keyword 注入不报错不泄露" 1 \
  || record "e) list 接口 keyword 注入不报错不泄露" 0 "$INJ_DETAIL"

# 路径段注入（SQLi 载荷作 {id}）：非法 UUID 应为参数校验 400，而非 5xx 或泄露
RESP="/tmp/s8-injpath-$TS.json"
CODE=$(curl -s -o "$RESP" -w "%{http_code}" -b "$CK" --path-as-is \
  "$API_URL/api/v1/api-security/endpoints/%27%20OR%201%3D1--")
if { [ "$CODE" = "400" ] || [ "$CODE" = "404" ]; } && no_leak "$RESP"; then
  record "e) 路径注入返回参数校验错误且无泄露（=${CODE}）" 1
else
  record "e) 路径注入返回参数校验错误且无泄露" 0 "status=$CODE"
fi
rm -f "$RESP" "/tmp/s8-xxe-resp-$TS.txt"

# ---------- f) CSRF：写接口缺 X-CSRF-Token → 403 ----------
CODE=$(curl -s -o /dev/null -w "%{http_code}" -b "$CK" \
  -X POST "$API_URL/api/v1/api-security/endpoints/confirm" \
  -H 'Content-Type: application/json' -d '{"ids":[]}')
[ "$CODE" = "403" ] && record "f) 缺 X-CSRF-Token 的写请求返回 403" 1 \
  || record "f) 缺 X-CSRF-Token 的写请求返回 403" 0 "status=$CODE"

echo "============================================================"
echo "阶段8 安全测试：$PASS/$TOTAL 通过，$FAIL 失败"
if [ "$FAIL" -gt 0 ]; then printf '失败项：\n'; printf '  %s\n' "${FAILED[@]}"; fi
echo "============================================================"
[ "$FAIL" = "0" ]
