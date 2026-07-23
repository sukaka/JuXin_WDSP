#!/usr/bin/env bash
# 九章阶段8 流量回放测试（任务书五十八章，WDSP）：
#   a) 统一 Request ID：API 事件与 Web 访问日志共享同一网关生成的 ID；
#   b) 同一 request_id 重放（采集器重读）只产生一条主事件（入库幂等）；
#   c) Web 页面请求不产生 API 事件，Web 访问日志采集不受影响；
#   d) 带偏离 body 的请求重放产生 schema.type_mismatch 明细。
#
# 与网关实现对齐的关键事实（勿凭直觉改断言）：
#   - 网关在 headers handler 用 {http.request.uuid} 强制覆盖客户端 X-Request-Id
#     （server/internal/gatewayconfig/generator.go buildHandles 第 1 步，注释“覆盖客户端传入”），
#     该 UUID 同时写入访问日志（Caddy 内建 placeholder 副作用，json 行 uuid 字段）。
#     因此客户端自定义 X-Request-Id 不会出现在事件中：脚本按任务书携带
#     X-Request-Id: replay-<ts>-N 头发送，但断言走真实行为——从事件取 request_id，
#     再到网关访问日志交叉验证同一 ID（即“统一事件与 Web 路径共享同一 Request ID”）。
#   - api_runtime_events 只收录「有检测明细或动作非 ALLOW」的主事件（apiruntime collector notable()）；
#     无凭据访问带对象段路径必命中 resource.unauthenticated_object_access，故必有事件可查。
#   - 采集器按 request_id 幂等（SavePrimary：INSERT ... WHERE NOT EXISTS request_id），
#     重放同一 JSONL 行（模拟断点回退重读/重复上报）不产生重复行。
#   - 写方法 API 进程内限速 60/min/端点（detectors.ratelimit），本脚本每端点写请求数远低于该值。
#
# 依赖 stage5 编排 + wdsp 覆盖：
#   docker compose --env-file .env -f deployment/docker-compose.stage5.yml -f deployment/docker-compose.wdsp.yml up -d --build
# 环境变量：GATEWAY_CONTAINER（默认 jiuzhang-stage5-gateway，用于读取网关日志做交叉验证）
# 用法：bash test/waf/scripts/stage8-replay-tests.sh
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/stage5-setup.sh"

GATEWAY_CONTAINER="${GATEWAY_CONTAINER:-jiuzhang-stage5-gateway}"
TS=$(date +%s)          # 本次运行的唯一前缀，避免与历史数据串扰
CK="/tmp/s5-$SEC_USER.txt"

TOTAL=0; PASS=0; FAIL=0; FAILED=()
record() {
  local name="$1" ok="$2" detail="${3:-}"
  TOTAL=$((TOTAL+1))
  if [ "$ok" = "1" ]; then PASS=$((PASS+1)); echo "PASS  $name"
  else FAIL=$((FAIL+1)); FAILED+=("$name: $detail"); echo "FAIL  $name ($detail)"; fi
}

# 按 endpoint_key 精确过滤查运行时事件（响应 JSON 原样输出）
events_of() { # $1=endpoint_key
  curl -s -b "$CK" -G "$API_URL/api/v1/api-security/runtime/events" \
    --data-urlencode "endpoint_key=$1" --data-urlencode "page_size=50"
}

echo "============================================================"
echo "九章阶段8 流量回放测试  gateway=$GATEWAY_URL api=$API_URL ts=$TS"
echo "============================================================"

# ---------- 准备：登录 / 应用 / 首次发布 ----------
SYS_CSRF=$(s5_ensure_sysadmin) || exit 1
SEC_CSRF=$(s5_ensure_secuser "$SYS_CSRF")
[ -z "$SEC_CSRF" ] && { echo "ERROR: sec login failed"; exit 1; }
APP_ID=$(s5_ensure_app "$SEC_CSRF")
echo "[setup] app=$APP_ID"

PUB=$(s5_publish "$SEC_CSRF")
[ "$PUB" = "PUBLISH_OK" ] && record "首次发布成功" 1 || { record "首次发布成功" 0 "$PUB"; echo "ABORT"; exit 1; }

# ---------- 准备：端点发现 → 确认 → 正式模型冻结 → 发布（复用全链路脚本流程，幂等） ----------
# 端点发现流量：无凭据 JSON 写请求，路径段为纯数字，归一化后为 POST /v1/orders/{id}
for i in 1 2 3; do
  curl -s -o /dev/null -H "Host: $HOST_HEADER" -H 'Content-Type: application/json' \
    -X POST -d "{\"id\":$i,\"name\":\"replay\"}" "$GATEWAY_URL/v1/orders/9$TS$i"
done
sleep 6  # 等采集器（2s 轮询 + 余量）

EP_JSON=$(curl -s -b "$CK" "$API_URL/api/v1/api-security/endpoints?keyword=orders&page_size=20")
EP_ID=$(echo "$EP_JSON" | python3 -c "
import json,sys
items=json.load(sys.stdin)['data'].get('items') or []
hit=[i for i in items if i.get('endpoint_key')=='POST /v1/orders/{id}']
print(hit[0]['id'] if hit else '')" 2>/dev/null)
[ -n "$EP_ID" ] && record "回放准备：端点自动发现 POST /v1/orders/{id}" 1 \
  || { record "回放准备：端点自动发现 POST /v1/orders/{id}" 0 "not found"; echo "ABORT"; exit 1; }

# 端点确认（已确认则跳过；ConfirmBatch 幂等，重复确认无害）
EP_STATUS=$(echo "$EP_JSON" | python3 -c "
import json,sys
items=json.load(sys.stdin)['data'].get('items') or []
hit=[i for i in items if i.get('endpoint_key')=='POST /v1/orders/{id}']
print(hit[0].get('asset_status','') if hit else '')" 2>/dev/null)
[ "$EP_STATUS" != "CONFIRMED" ] && s5_post "/api/v1/api-security/endpoints/confirm" "{\"ids\":[\"$EP_ID\"]}" "$SEC_CSRF" > /dev/null

# 正式模型：已有 FORMAL 版本则跳过，否则创建候选并确认冻结（与全链路脚本同一模型）
HAS_FORMAL=$(curl -s -b "$CK" "$API_URL/api/v1/api-security/endpoints/$EP_ID/models?page_size=20" | python3 -c "
import json,sys
items=json.load(sys.stdin)['data'].get('items') or []
print(sum(1 for v in items if v.get('status')=='FORMAL'))" 2>/dev/null)
if [ "${HAS_FORMAL:-0}" -ge 1 ]; then
  record "回放准备：正式模型已冻结（FORMAL 复用）" 1
else
  MV_ID=$(curl -s -b "$CK" -X POST "$API_URL/api/v1/api-security/endpoints/$EP_ID/models" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" \
    -d '{"schema":{"id":"number","name":"string"},"change_summary":"回放测试初始模型"}' \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['version']['id'])" 2>/dev/null)
  CONF=$(s5_post_code "/api/v1/api-security/models/$MV_ID/confirm" '{}' "$SEC_CSRF")
  [ -n "$MV_ID" ] && [ "$CONF" = "200" ] && record "回放准备：候选模型创建并冻结（FORMAL）" 1 \
    || { record "回放准备：候选模型创建并冻结（FORMAL）" 0 "mv=$MV_ID confirm=$CONF"; echo "ABORT"; exit 1; }
fi

PUB2=$(s5_publish "$SEC_CSRF")
[ "$PUB2" = "PUBLISH_OK" ] && record "回放准备：模型发布下发成功" 1 || { record "回放准备：模型发布下发成功" 0 "$PUB2"; echo "ABORT"; exit 1; }

# ---------- a) 统一 Request ID：API 事件与 Web 访问日志共享同一 ID ----------
# 唯一端点（本次运行前缀），无凭据 → resource.unauthenticated_object_access 命中 → 必产生主事件。
# 客户端自带 X-Request-Id 会被网关覆盖（见文件头注释），仅作任务书要求的协议样例携带。
EK_A="POST /v1/replay$TS/{id}"
curl -s -o /dev/null -H "Host: $HOST_HEADER" -H 'Content-Type: application/json' \
  -H "X-Request-Id: replay-$TS-1" -X POST -d '{"id":1,"name":"replay"}' "$GATEWAY_URL/v1/replay$TS/1"
sleep 6

RID=$(events_of "$EK_A" | python3 -c "
import json,sys
items=json.load(sys.stdin)['data'].get('items') or []
print(items[0].get('request_id','') if items else '')" 2>/dev/null)
[ -n "$RID" ] && record "a) API 请求后主事件可按 request_id 检索（=${RID}）" 1 \
  || { record "a) API 请求后主事件可按 request_id 检索" 0 "endpoint=$EK_A 无事件"; RID=""; }

if [ -n "$RID" ]; then
  # 交叉验证：同一 Request ID 出现在网关访问日志（Caddy json 行 uuid / 请求头 X-Request-Id）
  ALOG=$(docker exec "$GATEWAY_CONTAINER" sh -c "grep -c -F '$RID' /var/log/caddy/access.log" 2>/dev/null | tr -d ' \r\n')
  [ "${ALOG:-0}" -ge 1 ] && record "a) 同一 Request ID 出现在 Web 访问日志（统一 ID）" 1 \
    || record "a) 同一 Request ID 出现在 Web 访问日志（统一 ID）" 0 "access.log 未找到 $RID"
fi

# ---------- b) 同一 request_id 重放：主事件幂等（采集器断点重读/重复上报场景） ----------
if [ -n "$RID" ]; then
  # 从网关事件日志取出该 request_id 的原始 JSONL 行，原样追加两次（字节级回放，不虚构记录）
  B64=$(docker exec "$GATEWAY_CONTAINER" sh -c "grep -F '$RID' /var/log/caddy/api-runtime-events.log | head -n 1 | base64" 2>/dev/null | tr -d ' \r\n')
  if [ -z "$B64" ]; then
    record "b) 同一 request_id 重放仍只有一条主事件（幂等）" 0 "网关日志中未找到 $RID 的原始行"
  else
    # 幂等语义：重放前后该 request_id 的主事件数不变（ SavePrimary 按 request_id 去重）
    count_rid() {
      events_of "$EK_A" | python3 -c "
import json,sys
items=json.load(sys.stdin)['data'].get('items') or []
print(sum(1 for e in items if e.get('request_id')=='$RID'))" 2>/dev/null
    }
    PRE_CNT=$(count_rid)
    docker exec "$GATEWAY_CONTAINER" sh -c \
      "echo '$B64' | base64 -d >> /var/log/caddy/api-runtime-events.log; echo '$B64' | base64 -d >> /var/log/caddy/api-runtime-events.log" 2>/dev/null
    sleep 6
    CNT=$(count_rid)
    [ -n "$PRE_CNT" ] && [ "$PRE_CNT" -ge 1 ] && [ "${CNT:-0}" = "$PRE_CNT" ] \
      && record "b) 同一 request_id 重放两次主事件数不变（幂等，=${CNT}）" 1 \
      || record "b) 同一 request_id 重放两次主事件数不变（幂等）" 0 "重放前=$PRE_CNT 重放后=$CNT"
  fi
fi

# ---------- c) Web 页面请求：不产生 API 事件，Web 访问日志采集不受影响 ----------
# 字面量路径（无对象段）+ HTML Accept：非 API 流量且无检测命中 → 不产生主事件、不参与端点发现
WEB_PATH="/web-replay$TS/"
curl -s -o /dev/null -H "Host: $HOST_HEADER" -H 'Accept: text/html' "$GATEWAY_URL$WEB_PATH"
sleep 6

# 端点键为归一化路径（normalizer 会去掉尾部斜杠），故查询用无尾斜杠形式
WEB_EV=$(events_of "GET /web-replay$TS" | python3 -c "
import json,sys; print(json.load(sys.stdin)['data'].get('total', -1))" 2>/dev/null)
WEB_EP=$(curl -s -b "$CK" -G "$API_URL/api/v1/api-security/endpoints" \
  --data-urlencode "keyword=web-replay$TS" --data-urlencode "page_size=10" | python3 -c "
import json,sys
items=json.load(sys.stdin)['data'].get('items') or []
print(len(items))" 2>/dev/null)
[ "${WEB_EV:-1}" = "0" ] && [ "${WEB_EP:-1}" = "0" ] && record "c) Web 页面请求不产生 API 事件/端点发现" 1 \
  || record "c) Web 页面请求不产生 API 事件/端点发现" 0 "ev_total=$WEB_EV endpoints=$WEB_EP"

WEB_ALOG=$(docker exec "$GATEWAY_CONTAINER" sh -c "grep -c -F '$WEB_PATH' /var/log/caddy/access.log" 2>/dev/null | tr -d ' \r\n')
[ "${WEB_ALOG:-0}" -ge 1 ] && record "c) Web 页面请求访问日志采集正常" 1 \
  || record "c) Web 页面请求访问日志采集正常" 0 "access.log 未找到 $WEB_PATH"

# ---------- d) 带偏离 body 的请求重放：产生 schema.type_mismatch 明细 ----------
# 该端点已有 FORMAL 模型 {id:number,name:string}；id 传字符串即类型偏离（OBSERVE 记录不阻断）
mismatch_count() {
  events_of "POST /v1/orders/{id}" | python3 -c "
import json,sys
items=json.load(sys.stdin)['data'].get('items') or []
n=0
for e in items:
    for d in (e.get('details') or []):
        if d.get('rule_id')=='schema.type_mismatch' or d.get('RuleID')=='schema.type_mismatch': n+=1
print(n)" 2>/dev/null
}
BEFORE=$(mismatch_count)
curl -s -o /dev/null -H "Host: $HOST_HEADER" -H 'Content-Type: application/json' \
  -H "X-Request-Id: replay-$TS-2" -X POST -d '{"id":"abc","name":"replay"}' "$GATEWAY_URL/v1/orders/8$TS"
sleep 6
AFTER=$(mismatch_count)
[ "${AFTER:-0}" -gt "${BEFORE:-0}" ] && record "d) 偏离 body 重放产生 schema.type_mismatch 明细（${BEFORE}→${AFTER}）" 1 \
  || record "d) 偏离 body 重放产生 schema.type_mismatch 明细" 0 "before=$BEFORE after=$AFTER"

echo "============================================================"
echo "阶段8 流量回放测试：$PASS/$TOTAL 通过，$FAIL 失败"
if [ "$FAIL" -gt 0 ]; then printf '失败项：\n'; printf '  %s\n' "${FAILED[@]}"; fi
echo "============================================================"
[ "$FAIL" = "0" ]
