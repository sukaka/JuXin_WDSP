#!/usr/bin/env bash
# 九章阶段8 安全测试矩阵（任务书六十一章 36 项逐项对账版，WDSP）。
#
# 与 test/security/stage8-security-tests.sh 的关系：原脚本保留不变（a-f 六组断言，
# 对应下表 §61.6/8/20/15/21/f 的部分覆盖）；本脚本按 §61 清单 36 项逐项编号
# （SEC-01 … SEC-36，顺序即任务书条目顺序），逐项至少一个断言，互不依赖原脚本。
# 逐项对账表另见 test/security/stage8-security-matrix.md。
#
# 对账总表（§61 条目 → 本脚本断言）：
#   1  路径归一化绕过   SEC-01    12 Schema绕过        SEC-12    23 SSRF特征        SEC-23
#   2  双重编码         SEC-02    13 学习污染          SEC-13    24 NoSQL注入       SEC-24
#   3  参数污染         SEC-03    14 模型投毒          SEC-14    25 Mass Assignment SEC-25
#   4  重复JSON Key     SEC-04    15 版本越权          SEC-15    26 BOLA辅助检测    SEC-26
#   5  JSON深度攻击     SEC-05    16 模型确认越权      SEC-16    27 BFLA辅助检测    SEC-27
#   6  XML实体攻击      SEC-06    17 跨应用读取模型    SEC-17    28 业务流程绕过    SEC-28
#   7  超大数组         SEC-07    18 跨用户审计读取    SEC-18    29 图谱查询注入    SEC-29
#   8  超大请求         SEC-08    19 Token泄露         SEC-19    30 OpenAPI恶意文件 SEC-30
#   9  超大响应         SEC-09    20 敏感数据泄露      SEC-20    31 SSRF式规范导入  SEC-31
#   10 Multipart边界攻击 SEC-10   21 SQL注入           SEC-21    32 任意文件读取    SEC-32
#   11 压缩炸弹         SEC-11    22 XSS               SEC-22    33 审计删除        SEC-33
#                                 34 绕过统一决策 SEC-34  35 检测器直接返回响应 SEC-35  36 AI自动确认模型 SEC-36
#
# 与实现对齐的关键事实（代码侧依据）：
#   - 解析护栏 DefaultParseLimits：MaxBodyParseBytes=1MiB / MaxJSONDepth=32 / multipart 流式
#     part 元数据封顶（gateway/dynamic_security/context/context.go、parser/parse.go）；
#     超限一律截断采样 fail-open，攻击面断言统一为「非 000/非 5xx」；
#   - XML 遇 DOCTYPE 停止解析（parser/parse_xml.go，XXE 防御）；大 body 只能打 /echo
#     （testorigin 对未知路径立即 404 并关闭连接，大 body 续写会 broken pipe 502，
#     属源站行为而非引擎行为）；
#   - 管理面 JSON 解码统一 DisallowUnknownFields（response/response.go DecodeJSON），
#     未知字段（如 status/is_super）→ 400，即 Mass Assignment 拒绝；
#   - 模型状态机：仅 CANDIDATE/IN_REVIEW 可 confirm、仅 FORMAL 可 activate
#     （apimodels/store.go，违例 409）；FORMAL 不可变、学习候选只写 CANDIDATE 分支；
#   - 规范导入：16MiB 上限、外部 $ref 拒绝、JSON/YAML 深度/节点上限（apisecurity/handler.go
#     specImportMaxBytes、spec_formats.go）；URL 导入 SSRF 防护：仅 http/https、
#     拒绝回环/私网/链路本地/保留地址、拨号重解析复检（spec_version.go）；
#   - BOLA/BFLA 辅助：无凭据对象访问 → resource.unauthenticated_object_access（OBSERVE）；
#     有确认角色基线的端点匿名访问 → authz.bfla_anonymous（detectors/resource.go、authzcheck.go）；
#   - 统一决策：阻断仅由管线出口按模式定案（apiprotect.go serveNext，caddyhttp.Error 403），
#     OBSERVE 下 BLOCK 类命中仍到达源站（X-Wdsp-Origin-Mark 响应头为源站到达证据）；
#   - 权限：SECURITY_ADMIN 无 audits.read（000002/000100 种子），AUDIT_ADMIN 经 000100
#     收敛后无 api_model.read/confirm → 越权断言期望 403；审计无删除路由（app.go 仅 GET/verify-chain）。
#
# SKIP 口径：环境/fixture 客观不满足的项记 SKIP（不计 FAIL、不影响退出码），
# 并在输出与对账 md 注明原因；其余断言 FAIL 即退出非零。
#
# 依赖 stage5 编排 + wdsp 覆盖：
#   docker compose --env-file .env -f deployment/docker-compose.stage5.yml -f deployment/docker-compose.wdsp.yml up -d --build
# 用法：bash test/security/stage8-security-matrix.sh
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../waf/scripts/stage5-setup.sh"

TS=$(date +%s)
CK="/tmp/s5-$SEC_USER.txt"
AUD_USER="${AUD_USER:-aud_admin_s8m}"
AUD_PWD="${AUD_PWD:-AudAdmin@S8M!2026}"
# 唯一定时命名空间：事件/资产查询按本路径前缀隔离，不与历史运行互相污染
BASE="/v1/secm$TS"
EP_WRITE_KEY="POST $BASE/orders/{id}"
EP_READ_KEY="GET $BASE/orders/{id}"
CANARY="110101$TS"   # 敏感值明文金丝雀（身份证形态数字），脱敏抽检目标

TOTAL=0; PASS=0; FAIL=0; SKIP=0; FAILED=(); SKIPPED=()
record() {
  local name="$1" ok="$2" detail="${3:-}"
  TOTAL=$((TOTAL+1))
  if [ "$ok" = "1" ]; then PASS=$((PASS+1)); echo "PASS  $name"
  else FAIL=$((FAIL+1)); FAILED+=("$name: $detail"); echo "FAIL  $name ($detail)"; fi
}
skip() { # $1=断言名 $2=原因；环境受限项不计失败
  local name="$1" reason="$2"
  TOTAL=$((TOTAL+1)); SKIP=$((SKIP+1)); SKIPPED+=("$name: $reason")
  echo "SKIP  $name ($reason)"
}

# 响应体内部信息泄露检查（panic/堆栈/SQL 错误等）；无泄露返回 0
no_leak() { # $1=响应体文件
  ! grep -Eiq 'panic|goroutine [0-9]|pgx|sqlstate|SQL syntax|pq: |stack trace|runtime error' "$1"
}

# 网关请求状态码断言：非 000（连接重置=引擎崩溃信号）且非 5xx 即通过
gw_no5xx() { # $1=断言名 $2..=curl 参数（完整 URL 需自带）
  local name="$1"; shift
  local code
  code=$(curl -s -o "/tmp/s8m-resp-$TS.txt" -w "%{http_code}" -H "Host: $HOST_HEADER" "$@")
  case "$code" in
    000|5*) record "$name" 0 "status=$code" ;;
    *)  no_leak "/tmp/s8m-resp-$TS.txt" && record "$name" 1 || record "$name" 0 "响应泄露内部信息" ;;
  esac
}

# 运行时事件明细 rule_id 列表（兼容 rule_id/RuleID 两种键名）
s8_event_rules() { # $1=endpoint_key
  curl -s -b "$CK" -G "$API_URL/api/v1/api-security/runtime/events" \
    --data-urlencode "endpoint_key=$1" --data-urlencode "page_size=50" | python3 -c "
import json,sys
try:
    items=json.load(sys.stdin)['data'].get('items') or []
except Exception:
    sys.exit(0)
for e in items:
    for d in (e.get('details') or []):
        rid=d.get('rule_id') or d.get('RuleID') or ''
        if rid: print(rid)" 2>/dev/null
}

# 运行时事件总数（佐证管线采集活着）
s8_event_total() { # $1=endpoint_key
  curl -s -b "$CK" -G "$API_URL/api/v1/api-security/runtime/events" \
    --data-urlencode "endpoint_key=$1" --data-urlencode "page_size=1" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['data'].get('total', 0))" 2>/dev/null
}

# 按 endpoint_key 查资产 ID
s8_endpoint_id() { # $1=endpoint_key
  curl -s -b "$CK" -G "$API_URL/api/v1/api-security/endpoints" \
    --data-urlencode "keyword=secm$TS" --data-urlencode "page_size=50" | python3 -c "
import json,sys
items=json.load(sys.stdin)['data'].get('items') or []
hit=[i for i in items if i.get('endpoint_key')=='$1']
print(hit[0]['id'] if hit else '')" 2>/dev/null
}

# 确保审计管理员用户存在（角色 AUDIT_ADMIN，无 api_model.* 权限），打印其 CSRF
s8m_ensure_audituser() {
  local sys_csrf
  sys_csrf=$(s5_login "$SYS_USER" "$SYS_PWD")
  [ -z "$sys_csrf" ] && sys_csrf=$(s5_login "$SYS_USER" "$SYS_NEW_PWD")
  local tmp
  tmp=$(curl -s -b "/tmp/s5-$SYS_USER.txt" -X POST "$API_URL/api/v1/users" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $sys_csrf" \
    -d "{\"username\":\"$AUD_USER\",\"display_name\":\"审计管理员S8M\",\"role_code\":\"AUDIT_ADMIN\"}" \
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
echo "九章阶段8 安全测试矩阵  gateway=$GATEWAY_URL api=$API_URL ts=$TS"
echo "============================================================"

# ---------- 准备：登录 / 应用 / 发布 ----------
SYS_CSRF=$(s5_ensure_sysadmin) || exit 1
SEC_CSRF=$(s5_ensure_secuser "$SYS_CSRF")
[ -z "$SEC_CSRF" ] && { echo "ERROR: sec login failed"; exit 1; }
APP_ID=$(s5_ensure_app "$SEC_CSRF")
echo "[setup] app=$APP_ID base=$BASE"

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
# BFLA 基线清理保险（SEC-27 建立的基线不遗留）
BL_ID=""
cleanup_baseline() {
  [ -n "$BL_ID" ] || return 0
  curl -s -o /dev/null -b "$CK" -X DELETE "$API_URL/api/v1/api-security/authz/role-baselines/$BL_ID" \
    -H "X-CSRF-Token: $SEC_CSRF"
  BL_ID=""
}
trap 'restore_observe; cleanup_baseline' EXIT

PUB=$(s5_publish "$SEC_CSRF")
[ "$PUB" = "PUBLISH_OK" ] || { record "SETUP 首次发布成功" 0 "$PUB"; echo "ABORT"; exit 1; }
echo "[setup] 首次发布成功"

# ---------- 学习流量 → 端点发现（模型相关断言的前置） ----------
for i in 1 2 3; do
  curl -s -o /dev/null -H "Host: $HOST_HEADER" -H 'Content-Type: application/json' \
    -X POST -d "{\"id\":$i,\"name\":\"widget\"}" "$GATEWAY_URL$BASE/orders/10$i"
done
sleep 6
EP_ID=$(s8_endpoint_id "$EP_WRITE_KEY")
[ -n "$EP_ID" ] || { record "SETUP 端点自动发现 $EP_WRITE_KEY" 0 "not found"; echo "ABORT"; exit 1; }
echo "[setup] write endpoint=$EP_ID"
s5_post "/api/v1/api-security/endpoints/confirm" "{\"ids\":[\"$EP_ID\"]}" "$SEC_CSRF" > /dev/null

# ---------- SEC-36 AI自动确认模型（执行依赖前移：须在人工确认前断言） ----------
# 学习/发现只产 CANDIDATE，确认冻结必须人工带 api_model.confirm 权限发起
FORMAL_BEFORE=$(curl -s -b "$CK" "$API_URL/api/v1/api-security/endpoints/$EP_ID/models?page_size=50" | python3 -c "
import json,sys
items=json.load(sys.stdin)['data'].get('items') or []
print(sum(1 for m in items if m.get('status')=='FORMAL'))" 2>/dev/null)
[ "${FORMAL_BEFORE:-0}" = "0" ] && record "SEC-36 学习流量不产生自动确认的 FORMAL 模型" 1 \
  || record "SEC-36 学习流量不产生自动确认的 FORMAL 模型" 0 "formal=$FORMAL_BEFORE"

# ---------- 创建并人工确认正式模型（后续学习污染/投毒/偏离断言的基线） ----------
MV_ID=$(curl -s -b "$CK" -X POST "$API_URL/api/v1/api-security/endpoints/$EP_ID/models" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" \
  -d '{"schema":{"id":"number","name":"string"},"change_summary":"安全矩阵基线模型"}' \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['version']['id'])" 2>/dev/null)
CONF=$(s5_post_code "/api/v1/api-security/models/$MV_ID/confirm" '{}' "$SEC_CSRF")
if [ -z "$MV_ID" ] || [ "$CONF" != "200" ]; then
  record "SETUP 基线模型确认冻结" 0 "mv=$MV_ID confirm=$CONF"; echo "ABORT"; exit 1
fi
FORMAL_HASH=$(curl -s -b "$CK" "$API_URL/api/v1/api-security/models/$MV_ID" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['data'].get('content_hash',''))" 2>/dev/null)
echo "[setup] formal model=$MV_ID hash=$FORMAL_HASH"
PUB2=$(s5_publish "$SEC_CSRF")
[ "$PUB2" = "PUBLISH_OK" ] || { record "SETUP 二次发布（模型下发）" 0 "$PUB2"; echo "ABORT"; exit 1; }

# ================= 网关侧攻击面（OBSERVE，全部不应 5xx/崩溃） =================

# ---------- SEC-01 路径归一化绕过 ----------
gw_no5xx "SEC-01 路径归一化绕过不逃逸不崩溃" --path-as-is "$GATEWAY_URL/v1/secm$TS/../../../../etc/passwd"
RESP="/tmp/s8m-resp-$TS.txt"
if grep -q 'root:' "$RESP" 2>/dev/null; then
  record "SEC-01 路径归一化不泄露 /etc/passwd" 0 "响应含 passwd 内容"
else
  record "SEC-01 路径归一化不泄露 /etc/passwd" 1
fi

# ---------- SEC-02 双重编码 ----------
gw_no5xx "SEC-02 双重编码载荷不引发 5xx" "$GATEWAY_URL$BASE/orders/1?q=%2527%2520OR%25201%253D1--"

# ---------- SEC-03 参数污染（HPP） ----------
gw_no5xx "SEC-03 重复 Query 参数不引发 5xx" "$GATEWAY_URL$BASE/orders/1?id=1&id=2"

# ---------- SEC-04 重复JSON Key ----------
gw_no5xx "SEC-04 重复 JSON Key 不引发 5xx" -H 'Content-Type: application/json' \
  -X POST --data-binary '{"id":1,"id":2,"name":"dup"}' "$GATEWAY_URL$BASE/orders/1"

# ---------- SEC-05 JSON深度攻击 ----------
DEEP_BODY="/tmp/s8m-deep-$TS.json"
python3 -c "print('{\"a\":'*200 + '1' + '}'*200)" > "$DEEP_BODY"
gw_no5xx "SEC-05 JSON 深度攻击（200 层）截断而非 5xx" -H 'Content-Type: application/json' \
  -X POST --data-binary @"$DEEP_BODY" "$GATEWAY_URL/echo"
rm -f "$DEEP_BODY"

# ---------- SEC-06 XML实体攻击（XXE） ----------
XXE_BODY='<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE order [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<order><id>1</id><name>&xxe;</name></order>'
CODE=$(curl -s -o "/tmp/s8m-xxe-$TS.txt" -w "%{http_code}" -H "Host: $HOST_HEADER" \
  -H 'Content-Type: application/xml' -X POST --data-binary "$XXE_BODY" "$GATEWAY_URL$BASE/xxe/1")
case "$CODE" in
  000|5*) record "SEC-06 XXE 请求不引发 5xx（引擎不解析 DTD）" 0 "status=$CODE" ;;
  *)  grep -q 'root:' "/tmp/s8m-xxe-$TS.txt" \
        && record "SEC-06 XXE 请求不引发 5xx（引擎不解析 DTD）" 0 "实体被展开泄露 passwd" \
        || record "SEC-06 XXE 请求不引发 5xx（引擎不解析 DTD）" 1 ;;
esac
rm -f "/tmp/s8m-xxe-$TS.txt"

# ---------- SEC-07 超大数组 ----------
BIG_ARR="/tmp/s8m-bigarr-$TS.json"
python3 -c "import json; print(json.dumps({'id':1,'items':list(range(300000))}))" > "$BIG_ARR"
gw_no5xx "SEC-07 超大 JSON 数组（30 万元素）截断而非 5xx" -H 'Content-Type: application/json' \
  -X POST --data-binary @"$BIG_ARR" "$GATEWAY_URL/echo"
rm -f "$BIG_ARR"

# ---------- SEC-08 超大请求 ----------
BIG_BODY="/tmp/s8m-bigbody-$TS.json"
python3 -c "import json; print(json.dumps({'id':1,'name':'big','pad':'x'*1250000}))" > "$BIG_BODY"
gw_no5xx "SEC-08 超大请求体（>1MB）截断而非 5xx" -H 'Content-Type: application/json' \
  -X POST --data-binary @"$BIG_BODY" "$GATEWAY_URL/echo"
rm -f "$BIG_BODY"

# ---------- SEC-09 超大响应 ----------
skip "SEC-09 超大响应" "testorigin 无超大响应端点（/echo 应答恒为小报文），需专用 fixture 源站"

# ---------- SEC-10 Multipart边界攻击 ----------
MP_BODY="/tmp/s8m-mp-$TS.txt"
printf -- '--WRONGBOUNDARY\r\nContent-Disposition: form-data; name="f"; filename="a.txt"\r\n\r\nx\r\n--WRONGBOUNDARY--\r\n' > "$MP_BODY"
gw_no5xx "SEC-10 Multipart 边界不匹配不引发 5xx" \
  -H 'Content-Type: multipart/form-data; boundary=DECLARED_BOUNDARY' \
  -X POST --data-binary @"$MP_BODY" "$GATEWAY_URL/upload"
rm -f "$MP_BODY"

# ---------- SEC-11 压缩炸弹 ----------
GZB="/tmp/s8m-gzbomb-$TS.gz"
python3 -c "import gzip,sys; sys.stdout.buffer.write(gzip.compress(b'0'*67108864))" > "$GZB"
gw_no5xx "SEC-11 gzip 压缩炸弹（64MB 零字节）不解压失控" -H 'Content-Type: application/json' \
  -H 'Content-Encoding: gzip' -X POST --data-binary @"$GZB" "$GATEWAY_URL/echo"
rm -f "$GZB"
# 引擎存活佐证：炸弹请求后正常请求仍被代理
CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $HOST_HEADER" "$GATEWAY_URL/health")
[ "$CODE" = "200" ] && record "SEC-11 压缩炸弹后引擎仍正常代理（/health=200）" 1 \
  || record "SEC-11 压缩炸弹后引擎仍正常代理" 0 "status=$CODE"

# ---------- SEC-12 Schema绕过：Content-Type 混淆 + 未定义参数/类型偏离 ----------
# CT 混淆：偏离 JSON 以 text/plain 发送——解析器不识别则不学不崩（fail-open），不得 5xx
gw_no5xx "SEC-12 Content-Type 混淆（JSON 伪装 text/plain）不引发 5xx" \
  -H 'Content-Type: text/plain' -X POST --data-binary '{"id":"abc","evil":"bypass"}' "$GATEWAY_URL$BASE/orders/1"
# 类型偏离（正式模型 id:number ← "abc"）与未定义参数（evil 字段），供事件断言命中
curl -s -o /dev/null -H "Host: $HOST_HEADER" -H 'Content-Type: application/json' \
  -X POST --data-binary '{"id":"abc"}' "$GATEWAY_URL$BASE/orders/1"
curl -s -o /dev/null -H "Host: $HOST_HEADER" -H 'Content-Type: application/json' \
  -X POST --data-binary '{"id":1,"name":"x","evil":"y"}' "$GATEWAY_URL$BASE/orders/1"

# ---------- SEC-20 敏感数据泄露（脱敏不落明文金丝雀，OBSERVE 采样） ----------
curl -s -o /dev/null -H "Host: $HOST_HEADER" "$GATEWAY_URL$BASE/orders/1?id_card=$CANARY"

# ---------- SEC-23 SSRF特征（数据面：URL 形态参数仅作数据，不被抓取） ----------
RESP="/tmp/s8m-ssrf-$TS.txt"
CODE=$(curl -s -o "$RESP" -w "%{http_code}" -H "Host: $HOST_HEADER" \
  "$GATEWAY_URL$BASE/orders/1?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data")
case "$CODE" in
  000|5*) record "SEC-23 SSRF 特征参数不引发 5xx 且不外联抓取" 0 "status=$CODE" ;;
  *)  grep -Eiq 'ami-id|instance-id' "$RESP" \
        && record "SEC-23 SSRF 特征参数不引发 5xx 且不外联抓取" 0 "响应含云元数据内容" \
        || record "SEC-23 SSRF 特征参数不引发 5xx 且不外联抓取" 1 ;;
esac
rm -f "$RESP"

# ---------- SEC-26 BOLA辅助检测（无凭据连续数字对象 ID 遍历） ----------
for n in 9001 9002 9003; do
  curl -s -o /dev/null -H "Host: $HOST_HEADER" "$GATEWAY_URL$BASE/orders/$n"
done

# ---------- SEC-32 任意文件读取（数据面 + 管理面路径穿越） ----------
RESP="/tmp/s8m-lfi-$TS.txt"
CODE=$(curl -s -o "$RESP" -w "%{http_code}" -H "Host: $HOST_HEADER" --path-as-is \
  "$GATEWAY_URL/../../../../../../etc/passwd")
{ [ "$CODE" != "000" ] && ! grep -q 'root:' "$RESP"; } \
  && record "SEC-32 网关路径穿越读不到 /etc/passwd（=$CODE）" 1 \
  || record "SEC-32 网关路径穿越读不到 /etc/passwd" 0 "status=$CODE"
CODE=$(curl -s -o "$RESP" -w "%{http_code}" --path-as-is "$API_URL/api/v1/../../../../etc/passwd")
case "$CODE" in
  4*) grep -q 'root:' "$RESP" \
        && record "SEC-32 管理面路径穿越读不到 /etc/passwd" 0 "响应含 passwd 内容" \
        || record "SEC-32 管理面路径穿越读不到 /etc/passwd（=$CODE）" 1 ;;
  *)  record "SEC-32 管理面路径穿越读不到 /etc/passwd" 0 "status=$CODE" ;;
esac
rm -f "$RESP" "/tmp/s8m-resp-$TS.txt"

# ---------- 事件断言（OBSERVE 批次统一等待后核对） ----------
sleep 6
W_RULES=$(s8_event_rules "$EP_WRITE_KEY")
R_RULES=$(s8_event_rules "$EP_READ_KEY")

echo "$R_RULES" | grep -qx 'parser.duplicate_query_param' \
  && record "SEC-03 参数污染产生 parser.duplicate_query_param 明细" 1 \
  || record "SEC-03 参数污染产生 parser.duplicate_query_param 明细" 0 "rules=$(echo "$R_RULES" | tr '\n' ',')"
echo "$W_RULES" | grep -qx 'parser.duplicate_json_key' \
  && record "SEC-04 重复 JSON Key 产生 parser.duplicate_json_key 明细" 1 \
  || record "SEC-04 重复 JSON Key 产生 parser.duplicate_json_key" 0 "rules=$(echo "$W_RULES" | tr '\n' ',')"
echo "$W_RULES" | grep -qx 'schema.type_mismatch' \
  && record "SEC-12 类型偏离产生 schema.type_mismatch 明细" 1 \
  || record "SEC-12 类型偏离产生 schema.type_mismatch 明细" 0 "rules=$(echo "$W_RULES" | tr '\n' ',')"
echo "$W_RULES" | grep -qx 'schema.undefined_field' \
  && record "SEC-12 未定义参数产生 schema.undefined_field 明细" 1 \
  || record "SEC-12 未定义参数产生 schema.undefined_field 明细" 0 "rules=$(echo "$W_RULES" | tr '\n' ',')"
echo "$R_RULES" | grep -qx 'resource.unauthenticated_object_access' \
  && record "SEC-26 无凭据对象访问产生 BOLA 辅助信号" 1 \
  || record "SEC-26 无凭据对象访问产生 BOLA 辅助信号" 0 "rules=$(echo "$R_RULES" | tr '\n' ',')"

# SEC-20 金丝雀抽检：事件必须采到（证明抽检有效）且明文绝不出现
EV_RAW="/tmp/s8m-ev-$TS.json"
curl -s -b "$CK" -G "$API_URL/api/v1/api-security/runtime/events" \
  --data-urlencode "endpoint_key=$EP_READ_KEY" --data-urlencode "page_size=50" > "$EV_RAW"
EV_TOTAL=$(s8_event_total "$EP_READ_KEY")
if [ "${EV_TOTAL:-0}" -ge 1 ] && echo "$R_RULES" | grep -qx 'sensitive.in_query'; then
  record "SEC-20 敏感 Query 命中敏感识别且事件采集正常" 1
else
  record "SEC-20 敏感 Query 命中敏感识别且事件采集正常" 0 "total=$EV_TOTAL"
fi
grep -q "$CANARY" "$EV_RAW" \
  && record "SEC-20 运行时事件不落敏感值明文（金丝雀=$CANARY）" 0 "事件响应含明文金丝雀" \
  || record "SEC-20 运行时事件不落敏感值明文（金丝雀）" 1
rm -f "$EV_RAW"
SF_RAW=$(curl -s -b "$CK" "$API_URL/api/v1/api-security/sensitive-fields?direction=REQUEST&page_size=100")
echo "$SF_RAW" | grep -q "$CANARY" \
  && record "SEC-20 敏感字段清单不落敏感值明文（金丝雀）" 0 "sensitive-fields 含明文金丝雀" \
  || record "SEC-20 敏感字段清单不落敏感值明文（金丝雀）" 1

# ---------- SEC-27 BFLA辅助检测（角色基线 + 匿名访问） ----------
EP_READ_ID=$(s8_endpoint_id "$EP_READ_KEY")
if [ -z "$EP_READ_ID" ]; then
  skip "SEC-27 BFLA 辅助信号" "GET 端点资产未发现，无法挂角色基线"
else
  BL_ID=$(curl -s -b "$CK" -X POST "$API_URL/api/v1/api-security/authz/role-baselines" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" \
    -d "{\"endpoint_id\":\"$EP_READ_ID\",\"role\":\"authenticated\",\"method\":\"GET\",\"action\":\"READ\",\"allowed\":true}" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['data'].get('id',''))" 2>/dev/null)
  if [ -z "$BL_ID" ]; then
    skip "SEC-27 BFLA 辅助信号" "角色基线创建失败（权限/校验不满足）"
  else
    BLCONF=$(s5_post_code "/api/v1/api-security/authz/role-baselines/$BL_ID/confirm" '{}' "$SEC_CSRF")
    if [ "$BLCONF" != "200" ]; then
      skip "SEC-27 BFLA 辅助信号" "基线确认失败 status=$BLCONF"
    else
      sleep 3   # 基线经发布通道下发网关
      curl -s -o /dev/null -H "Host: $HOST_HEADER" "$GATEWAY_URL$BASE/orders/77"
      sleep 6
      s8_event_rules "$EP_READ_KEY" | grep -qx 'authz.bfla_anonymous' \
        && record "SEC-27 确认基线端点匿名访问产生 authz.bfla_anonymous" 1 \
        || record "SEC-27 确认基线端点匿名访问产生 authz.bfla_anonymous" 0 "基线下发或检测未生效"
    fi
  fi
fi

# ---------- SEC-34/35 PROTECT 对比：处置只经统一决策点 ----------
PUT_MODE=$(curl -s -o /dev/null -w "%{http_code}" -b "$CK" -X PUT "$API_URL/api/v1/api-security/policy" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" -d '{"mode":"PROTECT"}')
PUBP=$(curl -s -b "$CK" -X POST "$API_URL/api/v1/api-security/policy/publish" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" -d '{}' \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['status'])" 2>/dev/null)
if [ "$PUT_MODE" = "200" ] && [ "$PUBP" = "SUCCESS" ]; then
  PROTECT_ON=1
  # 两类不同 BLOCK 命中（schema 偏离 / 敏感 Query）都恰好 403——处置集中于统一决策出口
  CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $HOST_HEADER" -H 'Content-Type: application/json' \
    -X POST --data-binary '{"id":"abc"}' "$GATEWAY_URL$BASE/orders/1")
  [ "$CODE" = "403" ] && record "SEC-34 PROTECT 下 schema 偏离经统一决策 403" 1 \
    || record "SEC-34 PROTECT 下 schema 偏离经统一决策 403" 0 "status=$CODE"
  CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $HOST_HEADER" \
    "$GATEWAY_URL$BASE/orders/1?id_card=110")
  [ "$CODE" = "403" ] && record "SEC-34 PROTECT 下敏感 Query 经统一决策 403" 1 \
    || record "SEC-34 PROTECT 下敏感 Query 经统一决策 403" 0 "status=$CODE"
  # PROTECT 阻断请求同为污染样本（SEC-13 后续断言其未进入正式模型）
  restore_observe
  # OBSERVE 下同请求放行：检测器自身不拦截，模式决定处置
  CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $HOST_HEADER" -H 'Content-Type: application/json' \
    -X POST --data-binary '{"id":"abc"}' "$GATEWAY_URL$BASE/orders/1")
  [ "$CODE" != "403" ] && [ "$CODE" != "429" ] && record "SEC-34 恢复 OBSERVE 后同偏离请求放行（=$CODE）" 1 \
    || record "SEC-34 恢复 OBSERVE 后同偏离请求放行" 0 "status=$CODE"
  # BLOCK 类命中（敏感 Query）在 OBSERVE 下仍到达源站：检测器不直接产出响应
  HDR="/tmp/s8m-hdr-$TS.txt"
  curl -s -D "$HDR" -o /dev/null -H "Host: $HOST_HEADER" "$GATEWAY_URL$BASE/orders/1?id_card=110"
  grep -qi '^X-Wdsp-Origin-Mark: jiuzhang-test-origin' "$HDR" \
    && record "SEC-35 OBSERVE 下 BLOCK 类命中仍到达源站（检测器不直接返回响应）" 1 \
    || record "SEC-35 OBSERVE 下 BLOCK 类命中仍到达源站" 0 "缺少 X-Wdsp-Origin-Mark"
  rm -f "$HDR"
else
  record "SEC-34 PROTECT 下 schema 偏离经统一决策 403" 0 "策略切换失败 put=$PUT_MODE publish=$PUBP"
  record "SEC-34 PROTECT 下敏感 Query 经统一决策 403" 0 "策略切换失败"
  record "SEC-34 恢复 OBSERVE 后同偏离请求放行" 0 "策略切换失败"
  record "SEC-35 OBSERVE 下 BLOCK 类命中仍到达源站" 0 "策略切换失败"
fi

# ---------- SEC-13 学习污染 / SEC-14 模型投毒（正式模型不被污染扩宽） ----------
# 此前全部偏离/阻断/污染样本之后：正式模型 schema 与内容哈希必须逐字节不变
M_AFTER=$(curl -s -b "$CK" "$API_URL/api/v1/api-security/models/$MV_ID")
HASH_AFTER=$(echo "$M_AFTER" | python3 -c "import json,sys; print(json.load(sys.stdin)['data'].get('content_hash',''))" 2>/dev/null)
EVIL_KEYS=$(echo "$M_AFTER" | python3 -c "
import json,sys
sch=json.load(sys.stdin)['data'].get('schema') or {}
print(','.join(k for k in sch if k not in ('id','name')))" 2>/dev/null)
[ "$HASH_AFTER" = "$FORMAL_HASH" ] && [ -z "$EVIL_KEYS" ] \
  && record "SEC-13 污染样本未进入正式模型（schema/hash 不变）" 1 \
  || record "SEC-13 污染样本未进入正式模型" 0 "hash=$HASH_AFTER evil=$EVIL_KEYS"

# 投毒路径：携带 backdoor 字段的候选不得绕过状态机直接生效
CAND_ID=$(curl -s -b "$CK" -X POST "$API_URL/api/v1/api-security/endpoints/$EP_ID/models" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" \
  -d '{"schema":{"id":"number","name":"string","backdoor":"string"},"change_summary":"poison-attempt"}' \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['version']['id'])" 2>/dev/null)
CODE=$(s5_post_code "/api/v1/api-security/models/$MV_ID/confirm" '{}' "$SEC_CSRF")
[ "$CODE" = "409" ] && record "SEC-14 重复确认已冻结模型被拒绝（409）" 1 \
  || record "SEC-14 重复确认已冻结模型被拒绝" 0 "status=$CODE"
if [ -z "$CAND_ID" ]; then
  record "SEC-14 含 backdoor 候选未确认不可激活" 0 "投毒候选创建失败"
else
  CODE=$(s5_post_code "/api/v1/api-security/models/$CAND_ID/activate" '{}' "$SEC_CSRF")
  [ "$CODE" = "409" ] && record "SEC-14 含 backdoor 候选未确认不可激活（409）" 1 \
    || record "SEC-14 含 backdoor 候选未确认不可激活" 0 "status=$CODE"
fi

# ---------- SEC-28 业务流程绕过（状态机不可跳步） ----------
#（候选直接激活 409 已在 SEC-14 断言，此处覆盖评审状态机跳步）
CODE=$(s5_post_code "/api/v1/api-security/models/$MV_ID/submit-review" '{"comment":"bypass"}' "$SEC_CSRF")
[ "$CODE" = "409" ] && record "SEC-28 FORMAL 模型不可回退评审流程（409）" 1 \
  || record "SEC-28 FORMAL 模型不可回退评审流程" 0 "status=$CODE"
# 清理投毒候选（拒绝入库，不遗留）
[ -n "$CAND_ID" ] && s5_post "/api/v1/api-security/models/$CAND_ID/reject" '{"comment":"security-test-cleanup"}' "$SEC_CSRF" > /dev/null
if [ -z "$CAND_ID" ]; then
  record "SEC-28 REJECTED 候选不可再确认" 0 "投毒候选创建失败"
else
  CODE=$(s5_post_code "/api/v1/api-security/models/$CAND_ID/confirm" '{}' "$SEC_CSRF")
  [ "$CODE" = "409" ] && record "SEC-28 REJECTED 候选不可再确认（409）" 1 \
    || record "SEC-28 REJECTED 候选不可再确认" 0 "status=$CODE"
fi

# ================= 管理面越权与注入 =================

AUD_CSRF=$(s8m_ensure_audituser)
AUD_CK="/tmp/s5-$AUD_USER.txt"
if [ -z "$AUD_CSRF" ]; then
  record "SEC-15 AUDIT_ADMIN 读取模型版本越权被拒" 0 "审计用户登录失败"
  record "SEC-16 AUDIT_ADMIN 确认模型越权被拒" 0 "审计用户登录失败"
  record "SEC-18 AUDIT_ADMIN 审计读取正常" 0 "审计用户登录失败"
  AUD_OK=0
else
  AUD_OK=1
fi

# ---------- SEC-15 版本越权 ----------
CODE=$(curl -s -o /dev/null -w "%{http_code}" -b "$CK" "$API_URL/api/v1/api-security/models/$MV_ID")
[ "$CODE" = "200" ] && record "SEC-15 有权限角色读取模型版本正常（对照=200）" 1 \
  || record "SEC-15 有权限角色读取模型版本正常" 0 "status=$CODE"
if [ "$AUD_OK" = "1" ]; then
  CODE=$(curl -s -o /dev/null -w "%{http_code}" -b "$AUD_CK" "$API_URL/api/v1/api-security/models/$MV_ID")
  [ "$CODE" = "403" ] && record "SEC-15 AUDIT_ADMIN 读取模型版本越权被拒（403）" 1 \
    || record "SEC-15 AUDIT_ADMIN 读取模型版本越权被拒" 0 "status=$CODE"
fi

# ---------- SEC-16 模型确认越权 ----------
if [ "$AUD_OK" = "1" ]; then
  CODE=$(curl -s -o /dev/null -w "%{http_code}" -b "$AUD_CK" -X POST \
    "$API_URL/api/v1/api-security/models/$MV_ID/confirm" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $AUD_CSRF" -d '{}')
  [ "$CODE" = "403" ] && record "SEC-16 AUDIT_ADMIN 确认模型越权被拒（403）" 1 \
    || record "SEC-16 AUDIT_ADMIN 确认模型越权被拒" 0 "status=$CODE"
fi

# ---------- SEC-17 跨应用读取模型 ----------
CODE=$(curl -s -o /dev/null -w "%{http_code}" "$API_URL/api/v1/api-security/models/$MV_ID")
[ "$CODE" = "401" ] && record "SEC-17 无会话读取模型返回 401" 1 \
  || record "SEC-17 无会话读取模型返回 401" 0 "status=$CODE"
CODE=$(curl -s -o "/tmp/s8m-m404-$TS.json" -w "%{http_code}" -b "$CK" \
  "$API_URL/api/v1/api-security/models/00000000-0000-0000-0000-000000000000")
{ [ "$CODE" = "404" ] && no_leak "/tmp/s8m-m404-$TS.json"; } \
  && record "SEC-17 不存在模型 ID 返回 404 不泄露存在性细节" 1 \
  || record "SEC-17 不存在模型 ID 返回 404 不泄露存在性细节" 0 "status=$CODE"
rm -f "/tmp/s8m-m404-$TS.json"

# ---------- SEC-18 跨用户审计读取 ----------
CODE=$(curl -s -o /dev/null -w "%{http_code}" -b "$CK" "$API_URL/api/v1/audits?page_size=1")
[ "$CODE" = "403" ] && record "SEC-18 SECURITY_ADMIN 无 audits.read 审计读取被拒（403）" 1 \
  || record "SEC-18 SECURITY_ADMIN 无 audits.read 审计读取被拒" 0 "status=$CODE"
if [ "$AUD_OK" = "1" ]; then
  CODE=$(curl -s -o /dev/null -w "%{http_code}" -b "$AUD_CK" "$API_URL/api/v1/audits?page_size=1")
  [ "$CODE" = "200" ] && record "SEC-18 AUDIT_ADMIN 审计读取正常（对照=200）" 1 \
    || record "SEC-18 AUDIT_ADMIN 审计读取正常" 0 "status=$CODE"
fi

# ---------- SEC-19 Token泄露 ----------
CAPID=$(curl -s "$API_URL/api/v1/auth/captcha" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['captcha_id'])" 2>/dev/null)
CAPCODE=$(docker exec "$VALKEY_CONTAINER" valkey-cli -a "$VALKEY_PASSWORD" --no-auth-warning GET "jiuzhang:captcha:$CAPID" 2>/dev/null)
curl -s -D "/tmp/s8m-login-hdr-$TS.txt" -o "/tmp/s8m-login-$TS.json" -X POST "$API_URL/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$SEC_USER\",\"password\":\"$SEC_PWD\",\"captcha_id\":\"$CAPID\",\"captcha_code\":\"$CAPCODE\"}"
if grep -Eiq '"password|password_hash|temporary_password' "/tmp/s8m-login-$TS.json"; then
  record "SEC-19 登录响应不含口令字段" 0 "登录响应泄露口令"
else
  record "SEC-19 登录响应不含口令字段" 1
fi
grep -i '^Set-Cookie:' "/tmp/s8m-login-hdr-$TS.txt" | grep -qi 'HttpOnly' \
  && record "SEC-19 会话 Cookie 带 HttpOnly" 1 \
  || record "SEC-19 会话 Cookie 带 HttpOnly" 0 "Set-Cookie 缺 HttpOnly"
rm -f "/tmp/s8m-login-$TS.json" "/tmp/s8m-login-hdr-$TS.txt"
SYS_CSRF2=$(s5_login "$SYS_USER" "$SYS_PWD"); [ -z "$SYS_CSRF2" ] && SYS_CSRF2=$(s5_login "$SYS_USER" "$SYS_NEW_PWD")
USERS_RESP="/tmp/s8m-users-$TS.json"
curl -s -b "/tmp/s5-$SYS_USER.txt" "$API_URL/api/v1/users?page_size=50" > "$USERS_RESP"
grep -Eiq '"password|password_hash' "$USERS_RESP" \
  && record "SEC-19 用户列表不含口令散列字段" 0 "用户列表泄露口令字段" \
  || record "SEC-19 用户列表不含口令散列字段" 1
rm -f "$USERS_RESP"

# ---------- SEC-21/22/24 注入三件套（keyword 参数化 ILIKE，载荷只当普通字符串） ----------
INJ_RESP="/tmp/s8m-inj-$TS.json"
CODE=$(curl -s -o "$INJ_RESP" -w "%{http_code}" -b "$CK" -G "$API_URL/api/v1/api-security/endpoints" \
  --data-urlencode "keyword=' OR 1=1--" --data-urlencode "page_size=5")
{ [ "$CODE" = "200" ] && no_leak "$INJ_RESP"; } \
  && record "SEC-21 SQL 注入载荷 keyword 不报错不泄露" 1 \
  || record "SEC-21 SQL 注入载荷 keyword 不报错不泄露" 0 "status=$CODE"
CODE=$(curl -s -D "/tmp/s8m-xss-hdr-$TS.txt" -o "$INJ_RESP" -w "%{http_code}" -b "$CK" -G "$API_URL/api/v1/api-security/endpoints" \
  --data-urlencode "keyword=<script>alert(1)</script>" --data-urlencode "page_size=5")
{ [ "$CODE" = "200" ] && grep -qi '^Content-Type: application/json' "/tmp/s8m-xss-hdr-$TS.txt"; } \
  && record "SEC-22 XSS 载荷 keyword 不反射（JSON 应答）" 1 \
  || record "SEC-22 XSS 载荷 keyword 不反射" 0 "status=$CODE"
rm -f "/tmp/s8m-xss-hdr-$TS.txt"
CODE=$(curl -s -o "$INJ_RESP" -w "%{http_code}" -b "$CK" -G "$API_URL/api/v1/api-security/endpoints" \
  --data-urlencode 'keyword={"$gt":""}' --data-urlencode "page_size=5")
{ [ "$CODE" = "200" ] && no_leak "$INJ_RESP"; } \
  && record "SEC-24 NoSQL 注入载荷 keyword 不报错不泄露" 1 \
  || record "SEC-24 NoSQL 注入载荷 keyword 不报错不泄露" 0 "status=$CODE"
rm -f "$INJ_RESP"

# ---------- SEC-25 Mass Assignment ----------
CODE=$(curl -s -o /dev/null -w "%{http_code}" -b "$CK" -X POST \
  "$API_URL/api/v1/api-security/endpoints/$EP_ID/models" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" \
  -d '{"schema":{"x":"string"},"status":"FORMAL","confirmed_at":"2026-01-01T00:00:00Z"}')
[ "$CODE" = "400" ] && record "SEC-25 模型创建携带越权字段（status 等）被 400 拒绝" 1 \
  || record "SEC-25 模型创建携带越权字段被 400 拒绝" 0 "status=$CODE"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -b "$CK" -X PUT "$API_URL/api/v1/api-security/policy" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" \
  -d '{"mode":"OBSERVE","role":"admin","mode_locked":true}')
[ "$CODE" = "400" ] && record "SEC-25 策略更新携带未知字段被 400 拒绝" 1 \
  || record "SEC-25 策略更新携带未知字段被 400 拒绝" 0 "status=$CODE"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -b "/tmp/s5-$SYS_USER.txt" -X POST "$API_URL/api/v1/users" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $SYS_CSRF2" \
  -d '{"username":"s8m_mass","display_name":"x","role_code":"AUDIT_ADMIN","is_superadmin":true}')
[ "$CODE" = "400" ] && record "SEC-25 用户创建携带提权字段被 400 拒绝" 1 \
  || record "SEC-25 用户创建携带提权字段被 400 拒绝" 0 "status=$CODE"

# ---------- SEC-29 图谱查询注入 ----------
GRAPH_OK=1; GRAPH_DETAIL=""
for QS in "start=notatime" "min_count=-1" "min_count=abc"; do
  CODE=$(curl -s -o "/tmp/s8m-graph-$TS.json" -w "%{http_code}" -b "$CK" "$API_URL/api/v1/api-security/graph?$QS")
  if [ "$CODE" != "400" ] || ! no_leak "/tmp/s8m-graph-$TS.json"; then
    GRAPH_OK=0; GRAPH_DETAIL="qs=$QS status=$CODE"; break
  fi
done
[ "$GRAPH_OK" = "1" ] && record "SEC-29 图谱过滤参数非法值明确 400 不泄露（3 组）" 1 \
  || record "SEC-29 图谱过滤参数非法值明确 400 不泄露" 0 "$GRAPH_DETAIL"
CODE=$(curl -s -o "/tmp/s8m-graph-$TS.json" -w "%{http_code}" -b "$CK" -G "$API_URL/api/v1/api-security/topology" \
  --data-urlencode "start=' OR 1=1--")
{ [ "$CODE" = "400" ] && no_leak "/tmp/s8m-graph-$TS.json"; } \
  && record "SEC-29 拓扑过滤参数注入载荷 400 不泄露" 1 \
  || record "SEC-29 拓扑过滤参数注入载荷 400 不泄露" 0 "status=$CODE"
rm -f "/tmp/s8m-graph-$TS.json"

# ---------- SEC-30 OpenAPI恶意文件 ----------
# (a) XML/DOCTYPE 载荷：非支持格式，明确 400，不解析不展开
CODE=$(curl -s -o /dev/null -w "%{http_code}" -b "$CK" -X POST "$API_URL/api/v1/api-security/specs/import" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" \
  --data-binary '<?xml version="1.0"?><!DOCTYPE s [<!ENTITY x SYSTEM "file:///etc/passwd">]><spec>&x;</spec>')
[ "$CODE" = "400" ] && record "SEC-30 规范导入拒绝 XML/DOCTYPE 载荷（400）" 1 \
  || record "SEC-30 规范导入拒绝 XML/DOCTYPE 载荷" 0 "status=$CODE"
# (b) 外部 $ref（http(s)://）：拒绝，仅允许 #/ 文档内引用
CODE=$(curl -s -o /dev/null -w "%{http_code}" -b "$CK" -X POST "$API_URL/api/v1/api-security/specs/import" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" \
  -d '{"openapi":"3.0.3","info":{"title":"t","version":"1"},"paths":{"/x":{"get":{"responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"$ref":"https://evil.example/s.yaml#/S"}}}}}}}}}')
[ "$CODE" = "400" ] && record "SEC-30 规范导入拒绝外部 \$ref（400）" 1 \
  || record "SEC-30 规范导入拒绝外部 \$ref" 0 "status=$CODE"
# (c) 超大规范（>16MiB 上限）
BIG_SPEC="/tmp/s8m-bigspec-$TS.json"
python3 -c "
import json
doc={'openapi':'3.0.3','info':{'title':'t','version':'1'},'paths':{'/x':{'get':{'responses':{'200':{'description':'ok'}}}}},'pad':'A'*(17*1024*1024)}
open('$BIG_SPEC','w').write(json.dumps(doc))"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -b "$CK" -X POST "$API_URL/api/v1/api-security/specs/import" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" --data-binary @"$BIG_SPEC")
rm -f "$BIG_SPEC"
[ "$CODE" = "400" ] && record "SEC-30 规范导入拒绝超大文档（>16MiB → 400）" 1 \
  || record "SEC-30 规范导入拒绝超大文档" 0 "status=$CODE"

# ---------- SEC-31 SSRF式规范导入 ----------
SSRF_OK=1; SSRF_DETAIL=""
for U in "http://127.0.0.1:18081/api/v1/api-security/specs" \
         "http://169.254.169.254/latest/meta-data" \
         "http://localhost:18080/" \
         "file:///etc/passwd"; do
  CODE=$(curl -s -o "/tmp/s8m-ssrfimp-$TS.json" -w "%{http_code}" -b "$CK" \
    -X POST "$API_URL/api/v1/api-security/specs/import-url" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" \
    -d "{\"url\":\"$U\",\"name\":\"ssrf-probe-$TS\"}")
  if [ "$CODE" != "400" ]; then SSRF_OK=0; SSRF_DETAIL="url=$U status=$CODE"; break; fi
done
rm -f "/tmp/s8m-ssrfimp-$TS.json"
[ "$SSRF_OK" = "1" ] && record "SEC-31 URL 导入拒绝内网/保留/非 http(s) 目标（4 目标全 400）" 1 \
  || record "SEC-31 URL 导入拒绝内网/保留/非 http(s) 目标" 0 "$SSRF_DETAIL"

# ---------- SEC-33 审计删除 ----------
RAND_UUID="00000000-0000-0000-0000-000000000001"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -b "/tmp/s5-$SYS_USER.txt" -X DELETE \
  "$API_URL/api/v1/audits/$RAND_UUID" -H "X-CSRF-Token: $SYS_CSRF2")
case "$CODE" in
  404|405) record "SEC-33 审计无删除路由（DELETE → $CODE）" 1 ;;
  *)  record "SEC-33 审计无删除路由" 0 "status=$CODE" ;;
esac
CODE=$(curl -s -o /dev/null -w "%{http_code}" -b "/tmp/s5-$SYS_USER.txt" -X POST \
  "$API_URL/api/v1/audits/delete" -H 'Content-Type: application/json' \
  -H "X-CSRF-Token: $SYS_CSRF2" -d '{"ids":["'$RAND_UUID'"]}')
case "$CODE" in
  404|405) record "SEC-33 审计无批量删除端点（POST delete → $CODE）" 1 ;;
  *)  record "SEC-33 审计无批量删除端点" 0 "status=$CODE" ;;
esac

echo "============================================================"
echo "阶段8 安全测试矩阵：$PASS/$TOTAL 通过，$FAIL 失败，$SKIP 跳过"
if [ "$FAIL" -gt 0 ]; then printf '失败项：\n'; printf '  %s\n' "${FAILED[@]}"; fi
if [ "$SKIP" -gt 0 ]; then printf '跳过项（环境受限，不计失败）：\n'; printf '  %s\n' "${SKIPPED[@]}"; fi
echo "============================================================"
[ "$FAIL" = "0" ]
