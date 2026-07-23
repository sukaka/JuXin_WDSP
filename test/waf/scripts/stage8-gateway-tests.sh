#!/usr/bin/env bash
# 九章阶段8 真实网关全链路验证（WDSP）：
#   引擎挂接（guard 管线）→ 统一事件流 → 管理面采集入库 → 端点自动发现
#   → 模型冻结 → 发布下发正式模型 → OBSERVE/PROTECT 决策作用于响应 → 策略接口改模式
# 依赖 stage5 编排 + wdsp 覆盖：
#   docker compose --env-file .env -f deployment/docker-compose.stage5.yml -f deployment/docker-compose.wdsp.yml up -d --build
# 用法：bash test/waf/scripts/stage8-gateway-tests.sh
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/stage5-setup.sh"

TOTAL=0; PASS=0; FAIL=0; FAILED=()
record() {
  local name="$1" ok="$2" detail="${3:-}"
  TOTAL=$((TOTAL+1))
  if [ "$ok" = "1" ]; then PASS=$((PASS+1)); echo "PASS  $name"
  else FAIL=$((FAIL+1)); FAILED+=("$name: $detail"); echo "FAIL  $name ($detail)"; fi
}

echo "============================================================"
echo "九章阶段8 WDSP 全链路验证  gateway=$GATEWAY_URL api=$API_URL"
echo "============================================================"

# ---------- 准备：登录 / 应用 / 发布 ----------
SYS_CSRF=$(s5_ensure_sysadmin) || exit 1
SEC_CSRF=$(s5_ensure_secuser "$SYS_CSRF")
[ -z "$SEC_CSRF" ] && { echo "ERROR: sec login failed"; exit 1; }
APP_ID=$(s5_ensure_app "$SEC_CSRF")
echo "[setup] app=$APP_ID"

# ---------- 0. 产品形态：WDSP 且 API 动态防护开启 ----------
EDITION=$(curl -s -b "/tmp/s5-$SEC_USER.txt" "$API_URL/api/v1/product/edition" | python3 -c "
import json,sys
d=json.load(sys.stdin)['data']
print(d.get('edition'), d.get('api_dynamic_protection'))" 2>/dev/null)
[ "$EDITION" = "wdsp True" ] && record "product/edition=wdsp 且 API 防护开启" 1 || record "product/edition=wdsp 且 API 防护开启" 0 "got=$EDITION"

# ---------- 1. 发布（带 API 防护配置） ----------
PUB=$(s5_publish "$SEC_CSRF")
[ "$PUB" = "PUBLISH_OK" ] && record "首次发布成功" 1 || { record "首次发布成功" 0 "$PUB"; echo "ABORT"; exit 1; }

# ---------- 2. 发送 API 流量（JSON 写请求 → 引擎管线） ----------
CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $HOST_HEADER" -H 'Content-Type: application/json' \
  -X POST -d '{"id":1,"name":"widget"}' "$GATEWAY_URL/v1/orders/123")
[ "$CODE" != "403" ] && [ "$CODE" != "429" ] && record "OBSERVE 模式正常请求不被拦截" 1 || record "OBSERVE 模式正常请求不被拦截" 0 "status=$CODE"
# 再补两笔提高命中计数
for i in 2 3; do curl -s -o /dev/null -H "Host: $HOST_HEADER" -H 'Content-Type: application/json' -X POST -d "{\"id\":$i}" "$GATEWAY_URL/v1/orders/12$i"; done

# 等待采集器（2s 轮询 + 余量）
sleep 6

# ---------- 3. 端点自动发现（网关上报 → 采集器 upsert） ----------
EP_JSON=$(curl -s -b "/tmp/s5-$SEC_USER.txt" "$API_URL/api/v1/api-security/endpoints?keyword=orders&page_size=20")
EP_ID=$(echo "$EP_JSON" | python3 -c "
import json,sys
items=json.load(sys.stdin)['data'].get('items') or []
hit=[i for i in items if i.get('endpoint_key')=='POST /v1/orders/{id}']
print(hit[0]['id'] if hit else '')" 2>/dev/null)
[ -n "$EP_ID" ] && record "端点自动发现 POST /v1/orders/{id}" 1 || record "端点自动发现 POST /v1/orders/{id}" 0 "not found: $EP_JSON"

EP_HITS=$(echo "$EP_JSON" | python3 -c "
import json,sys
items=json.load(sys.stdin)['data'].get('items') or []
hit=[i for i in items if i.get('endpoint_key')=='POST /v1/orders/{id}']
print(hit[0]['hit_count'] if hit else 0)" 2>/dev/null)
[ "${EP_HITS:-0}" -ge 3 ] && record "端点命中计数≥3（实际=${EP_HITS}）" 1 || record "端点命中计数≥3（实际=${EP_HITS}）" 0

# ---------- 4. 统一运行时事件入库 ----------
EV_COUNT=$(curl -s -b "/tmp/s5-$SEC_USER.txt" "$API_URL/api/v1/api-security/runtime/events?page_size=50" | python3 -c "
import json,sys
items=json.load(sys.stdin)['data'].get('items') or []
print(sum(1 for e in items if e.get('endpoint_key')=='POST /v1/orders/{id}'))" 2>/dev/null)
[ "${EV_COUNT:-0}" -ge 1 ] && record "api_runtime_events 有该端点主事件（=${EV_COUNT}）" 1 || record "api_runtime_events 有该端点主事件（=${EV_COUNT}）" 0

# ---------- 5. 确认端点 + 创建并冻结正式模型 ----------
if [ -n "$EP_ID" ]; then
  s5_post "/api/v1/api-security/endpoints/confirm" "{\"ids\":[\"$EP_ID\"]}" "$SEC_CSRF" > /dev/null
  MV_ID=$(curl -s -b "/tmp/s5-$SEC_USER.txt" -X POST "$API_URL/api/v1/api-security/endpoints/$EP_ID/models" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" \
    -d '{"schema":{"id":"number","name":"string"},"change_summary":"初始模型"}' \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['version']['id'])" 2>/dev/null)
  [ -n "$MV_ID" ] && record "候选模型创建" 1 || record "候选模型创建" 0
  CONF=$(s5_post_code "/api/v1/api-security/models/$MV_ID/confirm" '{}' "$SEC_CSRF")
  [ "$CONF" = "200" ] && record "模型确认冻结（FORMAL）" 1 || record "模型确认冻结（FORMAL）" 0 "status=$CONF"
fi

# ---------- 6. 发布下发正式模型，验证 OBSERVE 记录偏离但不阻断 ----------
PUB2=$(s5_publish "$SEC_CSRF")
[ "$PUB2" = "PUBLISH_OK" ] && record "二次发布（含正式模型下发）" 1 || record "二次发布（含正式模型下发）" 0 "$PUB2"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $HOST_HEADER" -H 'Content-Type: application/json' \
  -X POST -d '{"id":"abc"}' "$GATEWAY_URL/v1/orders/123")
[ "$CODE" != "403" ] && [ "$CODE" != "429" ] && record "OBSERVE 模式类型偏离不阻断（=${CODE}）" 1 || record "OBSERVE 模式类型偏离不阻断（=${CODE}）" 0
sleep 6
DEV_COUNT=$(curl -s -b "/tmp/s5-$SEC_USER.txt" "$API_URL/api/v1/api-security/runtime/events?page_size=50" | python3 -c "
import json,sys
items=json.load(sys.stdin)['data'].get('items') or []
n=0
for e in items:
    if e.get('endpoint_key')!='POST /v1/orders/{id}': continue
    for d in (e.get('details') or []):
        if d.get('RuleID')=='schema.type_mismatch' or d.get('rule_id')=='schema.type_mismatch': n+=1
print(n)" 2>/dev/null)
[ "${DEV_COUNT:-0}" -ge 1 ] && record "偏离事件含 schema.type_mismatch 明细（=${DEV_COUNT}）" 1 || record "偏离事件含 schema.type_mismatch 明细（=${DEV_COUNT}）" 0

# ---------- 7. 策略接口切 PROTECT + 发布，验证阻断 ----------
PUT_MODE=$(curl -s -o /dev/null -w "%{http_code}" -b "/tmp/s5-$SEC_USER.txt" -X PUT "$API_URL/api/v1/api-security/policy" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" -d '{"mode":"PROTECT"}')
[ "$PUT_MODE" = "200" ] && record "策略接口设置 PROTECT" 1 || record "策略接口设置 PROTECT" 0 "status=$PUT_MODE"
PUBP=$(curl -s -b "/tmp/s5-$SEC_USER.txt" -X POST "$API_URL/api/v1/api-security/policy/publish" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" -d '{}' \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['status'])" 2>/dev/null)
[ "$PUBP" = "SUCCESS" ] && record "策略发布到网关成功" 1 || record "策略发布到网关成功" 0 "status=$PUBP"

CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $HOST_HEADER" -H 'Content-Type: application/json' \
  -X POST -d '{"id":"abc"}' "$GATEWAY_URL/v1/orders/123")
[ "$CODE" = "403" ] && record "PROTECT 模式类型偏离被 403 阻断" 1 || record "PROTECT 模式类型偏离被 403 阻断" 0 "status=$CODE"

CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $HOST_HEADER" -H 'Content-Type: application/json' \
  -X POST -d '{"id":9,"name":"ok"}' "$GATEWAY_URL/v1/orders/123")
[ "$CODE" != "403" ] && [ "$CODE" != "429" ] && record "PROTECT 模式合规请求不被误拦（=${CODE}）" 1 || record "PROTECT 模式合规请求不被误拦（=${CODE}）" 0

# ---------- 8. 还原 OBSERVE（不污染后续使用） ----------
curl -s -o /dev/null -b "/tmp/s5-$SEC_USER.txt" -X PUT "$API_URL/api/v1/api-security/policy" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" -d '{"mode":"OBSERVE"}'
curl -s -o /dev/null -b "/tmp/s5-$SEC_USER.txt" -X POST "$API_URL/api/v1/api-security/policy/publish" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" -d '{}'

echo "============================================================"
echo "阶段8 全链路验证：$PASS/$TOTAL 通过，$FAIL 失败"
if [ "$FAIL" -gt 0 ]; then printf '失败项：\n'; printf '  %s\n' "${FAILED[@]}"; fi
echo "============================================================"
[ "$FAIL" = "0" ]
