#!/usr/bin/env bash
# 九章阶段8 §207 统一决策真网关验证（WDSP / W5-C 分片）：
#   一个请求同时命中 Coraza SQLi（WAF）+ API Schema 偏离 + 敏感字段 + 行为突增，
#   断言统一事件契约：恰好 1 条 api-runtime-events 主事件 / details 覆盖 4 个检测器 /
#   final_action 唯一（BLOCK，按实记录）/ Coraza 归因明细存在（waf.downstream_intercept，G2 合流）。
#
# 与 stage8-gateway-tests.sh 同一 harness（stage5 编排 + wdsp 覆盖）：
#   docker compose --env-file .env -f deployment/docker-compose.stage5.yml -f deployment/docker-compose.wdsp.yml up -d --build
# 用法：bash test/waf/scripts/stage8-unified-decision-tests.sh
#
# 说明：
#   - 独立应用（默认 APP_CODE=s5ud / HOST_HEADER=waf-s5ud.local，protection_mode=PROTECT，
#     WAF 真实阻断）与独立端点 /v1/charge/{id}，不污染 stage5/stage8 既有场景状态；
#   - API 动态防护显式置 OBSERVE：统一引擎观察不拦截，请求到达下游 Coraza 被阻断，
#     由 guard 归因补记 waf 明细（这是 §207 多检测器同事件的唯一真实路径——
#     PROTECT 下引擎自身阻断时请求不会到达 WAF）；
#   - 行为基线为真实 1 分钟滑窗：5 个自然分钟窗口 × 每窗 2 次请求（约 5 分钟等待），
#     随后同分钟内突发 21 次 + 1 次投毒请求（窗口计数 22 > 阈值 max(20,3×2)）；
#   - 事件断言按每次运行唯一的 raw_path 精确定位（网关 headers 处理器以 {http.request.uuid}
#     覆盖客户端 X-Request-Id，客户端自定 request_id 不可用于匹配），不受同端点其他事件干扰。
set -u
export APP_CODE="${APP_CODE:-s5ud}"
export HOST_HEADER="${HOST_HEADER:-waf-s5ud.local}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/stage5-setup.sh"

UD_PATH="/v1/charge"
UD_ENDPOINT_KEY="POST /v1/charge/{id}"
# 投毒请求路径每次运行唯一（数字段归一化为 {id}，不影响端点键）：
# 网关 headers 处理器以 {http.request.uuid} 覆盖客户端 X-Request-Id（见 generator headers.go），
# 故事件断言不能按客户端 request_id 匹配，改用唯一 raw_path 定位。
UD_POISON_PATH="$UD_PATH/$(date +%s)$RANDOM"

TOTAL=0; PASS=0; FAIL=0; FAILED=()
record() {
  local name="$1" ok="$2" detail="${3:-}"
  TOTAL=$((TOTAL+1))
  if [ "$ok" = "1" ]; then PASS=$((PASS+1)); echo "PASS  $name"
  else FAIL=$((FAIL+1)); FAILED+=("$name: $detail"); echo "FAIL  $name ($detail)"; fi
}

# 等待下一个自然分钟边界 +2s（行为滑窗按自然分钟对齐，防跨窗计数重置）
wait_minute_boundary() {
  local s=$((10#$(date +%S)))
  sleep $(( 62 - s ))
}

echo "============================================================"
echo "§207 统一决策验证  gateway=$GATEWAY_URL api=$API_URL"
echo "  app=$APP_CODE host=$HOST_HEADER endpoint=$UD_ENDPOINT_KEY"
echo "  poison_path=$UD_POISON_PATH"
echo "============================================================"

# ---------- 准备：登录 / 独立应用（PROTECT：WAF 真实阻断） ----------
SYS_CSRF=$(s5_ensure_sysadmin) || exit 1
SEC_CSRF=$(s5_ensure_secuser "$SYS_CSRF")
[ -z "$SEC_CSRF" ] && { echo "ERROR: sec login failed"; exit 1; }

SEC_COOKIE="/tmp/s5-$SEC_USER.txt"
APP_ID=$(curl -s -b "$SEC_COOKIE" "$API_URL/api/v1/applications?keyword=$APP_CODE" | python3 -c "
import json,sys
items=json.load(sys.stdin)['data'].get('items') or []
print(next((i['id'] for i in items if i.get('code')=='$APP_CODE'),''))" 2>/dev/null)
if [ -z "$APP_ID" ]; then
  APP_ID=$(curl -s -b "$SEC_COOKIE" -X POST "$API_URL/api/v1/applications" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" \
    -d "{\"code\":\"$APP_CODE\",\"name\":\"§207统一决策验证应用\",\"description\":\"统一决策多检测器单事件场景\",\"business_owner\":\"test\",\"technical_owner\":\"test\",\"protection_mode\":\"PROTECT\"}" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['id'])" 2>/dev/null)
  [ -n "$APP_ID" ] || { echo "ERROR: create app failed"; exit 1; }
  curl -s -b "$SEC_COOKIE" -X POST "$API_URL/api/v1/applications/$APP_ID/domains" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" \
    -d "{\"hostname\":\"$HOST_HEADER\",\"is_primary\":true,\"http_enabled\":true,\"https_enabled\":false,\"http_port\":8080,\"redirect_http_to_https\":false}" > /dev/null
  curl -s -b "$SEC_COOKIE" -X POST "$API_URL/api/v1/applications/$APP_ID/upstreams" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" \
    -d '{"name":"testorigin","scheme":"http","host":"testorigin","port":8081,"weight":1,"priority":1,"health_check_enabled":false,"health_check_path":"/health","health_check_method":"GET","health_check_interval_seconds":10,"health_check_timeout_seconds":3,"expected_status_codes":"200","connect_timeout_ms":3000,"response_header_timeout_ms":10000,"tls_server_name":"","tls_verify":false}' > /dev/null
  curl -s -b "$SEC_COOKIE" -X POST "$API_URL/api/v1/applications/$APP_ID/enable" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" > /dev/null
fi
echo "[setup] app=$APP_ID"

# API 动态防护显式 OBSERVE（统一引擎只观察；WAF 腿由下游 Coraza 执行）
MODE_CODE=$(curl -s -o /dev/null -w "%{http_code}" -b "$SEC_COOKIE" -X PUT "$API_URL/api/v1/api-security/policy" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" -d '{"mode":"OBSERVE"}')
[ "$MODE_CODE" = "200" ] && record "API 防护模式置 OBSERVE" 1 || record "API 防护模式置 OBSERVE" 0 "status=$MODE_CODE"
POLPUB=$(curl -s -b "$SEC_COOKIE" -X POST "$API_URL/api/v1/api-security/policy/publish" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" -d '{}' \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['status'])" 2>/dev/null)
[ "$POLPUB" = "SUCCESS" ] && record "策略发布成功（OBSERVE 生效）" 1 || { record "策略发布成功（OBSERVE 生效）" 0 "status=$POLPUB"; echo "ABORT"; exit 1; }

# ---------- 1. 种子流量 → 端点自动发现 ----------
for i in 1 2 3; do
  curl -s -o /dev/null -H "Host: $HOST_HEADER" -H 'Content-Type: application/json' \
    -X POST -d "{\"id\":$i,\"name\":\"seed\"}" "$GATEWAY_URL$UD_PATH/10$i"
done
sleep 6
EP_ID=$(curl -s -b "$SEC_COOKIE" "$API_URL/api/v1/api-security/endpoints?keyword=charge&page_size=20" | python3 -c "
import json,sys
items=json.load(sys.stdin)['data'].get('items') or []
hit=[i for i in items if i.get('endpoint_key')=='$UD_ENDPOINT_KEY']
print(hit[0]['id'] if hit else '')" 2>/dev/null)
[ -n "$EP_ID" ] && record "端点自动发现 $UD_ENDPOINT_KEY" 1 || { record "端点自动发现 $UD_ENDPOINT_KEY" 0; echo "ABORT"; exit 1; }

# ---------- 2. 确认端点 + 冻结 FORMAL 模型 + 发布下发 ----------
s5_post "/api/v1/api-security/endpoints/confirm" "{\"ids\":[\"$EP_ID\"]}" "$SEC_CSRF" > /dev/null
MV_ID=$(curl -s -b "$SEC_COOKIE" -X POST "$API_URL/api/v1/api-security/endpoints/$EP_ID/models" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" \
  -d '{"schema":{"id":"number","name":"string"},"change_summary":"§207 正式模型"}' \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['version']['id'])" 2>/dev/null)
[ -n "$MV_ID" ] && record "FORMAL 模型创建" 1 || { record "FORMAL 模型创建" 0; echo "ABORT"; exit 1; }
CONF=$(s5_post_code "/api/v1/api-security/models/$MV_ID/confirm" '{}' "$SEC_CSRF")
[ "$CONF" = "200" ] && record "模型确认冻结（FORMAL）" 1 || { record "模型确认冻结（FORMAL）" 0 "status=$CONF"; echo "ABORT"; exit 1; }
PUB=$(s5_publish "$SEC_CSRF")
[ "$PUB" = "PUBLISH_OK" ] && record "发布下发（正式模型+OBSERVE）" 1 || { record "发布下发（正式模型+OBSERVE）" 0 "$PUB"; echo "ABORT"; exit 1; }

# ---------- 3. 行为基线：5 个自然分钟窗口 × 每窗 2 次（约 5 分钟） ----------
echo "[behavior] 构建行为基线（5 个自然分钟窗口，约 5 分钟）..."
for w in 1 2 3 4 5; do
  wait_minute_boundary
  for i in 1 2; do
    curl -s -o /dev/null -H "Host: $HOST_HEADER" -H 'Content-Type: application/json' \
      -X POST -d "{\"id\":$w$i,\"name\":\"baseline\"}" "$GATEWAY_URL$UD_PATH/20$w$i"
  done
  echo "[behavior] 窗口 $w/5 已落 2 次请求"
done

# ---------- 4. 同分钟突发 21 次 + 1 次投毒请求（四检测器同命中） ----------
wait_minute_boundary
for i in $(seq 1 21); do
  curl -s -o /dev/null -H "Host: $HOST_HEADER" -H 'Content-Type: application/json' \
    -X POST -d "{\"id\":$i,\"name\":\"burst\"}" "$GATEWAY_URL$UD_PATH/30$i"
done
# 投毒请求：SQLi 载荷（下游 Coraza 阻断）+ id 类型偏离（FORMAL 期望 number）+ password 未定义且敏感
POISON_CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $HOST_HEADER" -H 'Content-Type: application/json' \
  -X POST -d '{"id":"1'"'"' OR '"'"'1'"'"'='"'"'1","name":"n","password":"Pw0rd!"}' "$GATEWAY_URL$UD_POISON_PATH")
[ "$POISON_CODE" = "403" ] && record "投毒请求被下游 WAF 阻断（403）" 1 || record "投毒请求被下游 WAF 阻断（403）" 0 "status=$POISON_CODE"

sleep 6

# ---------- 5. 统一事件断言（按唯一 raw_path 精确定位） ----------
curl -s -b "$SEC_COOKIE" "$API_URL/api/v1/api-security/runtime/events?page_size=100" > /tmp/ud-events.json
EVAL=$(python3 - "$UD_ENDPOINT_KEY" "$UD_POISON_PATH" /tmp/ud-events.json <<'PYEOF'
import json, sys
ek, raw_path, path = sys.argv[1], sys.argv[2], sys.argv[3]
data = json.load(open(path))
items = data['data'].get('items') or []
hits = [e for e in items if e.get('endpoint_key') == ek and e.get('raw_path') == raw_path]
if len(hits) != 1:
    print(json.dumps({'event_count': len(hits)}))
    sys.exit(0)
ev = hits[0]
details = ev.get('details') or []
def get(d, *keys):
    for k in keys:
        if isinstance(d, dict) and k in d: return d[k]
    return None
rules = {get(d, 'RuleID', 'rule_id'): d for d in details}
detectors = {get(d, 'Detector', 'detector') for d in details}
waf = rules.get('waf.downstream_intercept') or {}
evid = get(waf, 'Evidence', 'evidence') or {}
print(json.dumps({
    'event_count': len(hits),
    'final_action': ev.get('final_action'),
    'response_status': ev.get('response_status'),
    'detectors': sorted(x for x in detectors if x),
    'rules': sorted(k for k in rules if k),
    'waf_attribution': evid.get('attribution'),
    'waf_tx': evid.get('coraza_tx_id'),
    'waf_status': evid.get('status_code'),
}, ensure_ascii=False))
PYEOF
)
echo "[assert] event=$EVAL"
py_get() { python3 -c "import json,sys; d=json.loads(sys.argv[1]); print(d.get(sys.argv[2],''))" "$EVAL" "$1" 2>/dev/null; }
py_has() { python3 -c "import json,sys; d=json.loads(sys.argv[1]); print('1' if sys.argv[2] in (d.get(sys.argv[3]) or []) else '0')" "$EVAL" "$1" "$2" 2>/dev/null; }

[ "$(py_get event_count)" = "1" ] && record "恰好 1 条主事件（按唯一 raw_path 定位）" 1 || record "恰好 1 条主事件（按唯一 raw_path 定位）" 0 "count=$(py_get event_count)"
[ "$(py_get final_action)" = "BLOCK" ] && record "final_action 唯一=BLOCK（按实记录）" 1 || record "final_action 唯一=BLOCK（按实记录）" 0 "got=$(py_get final_action)"
[ "$(py_get response_status)" = "403" ] && record "response_status=403（Coraza 中断码）" 1 || record "response_status=403（Coraza 中断码）" 0 "got=$(py_get response_status)"
NDET=$(python3 -c "import json,sys; print(len(json.loads(sys.argv[1]).get('detectors') or []))" "$EVAL" 2>/dev/null)
[ "${NDET:-0}" -ge 4 ] && record "details 覆盖 4 以上检测器（实际=${NDET}）" 1 || record "details 覆盖 4 以上检测器（实际=${NDET}）" 0 "$(py_get detectors)"
for want in waf api_schema sensitive_data behavior; do
  [ "$(py_has "$want" detectors)" = "1" ] && record "检测器明细存在：$want" 1 || record "检测器明细存在：$want" 0
done
for want in schema.type_mismatch schema.undefined_field sensitive.field behavior.rate_spike waf.downstream_intercept; do
  [ "$(py_has "$want" rules)" = "1" ] && record "规则明细存在：$want" 1 || record "规则明细存在：$want" 0
done
[ "$(py_get waf_attribution)" = "downstream_intercept" ] && record "Coraza 归因 evidence.attribution=downstream_intercept" 1 || record "Coraza 归因 evidence.attribution=downstream_intercept" 0 "got=$(py_get waf_attribution)"
[ -n "$(py_get waf_tx)" ] && [ "$(py_get waf_tx)" != "None" ] && record "Coraza 归因携带事务 ID" 1 || record "Coraza 归因携带事务 ID" 0
[ "$(py_get waf_status)" = "403" ] && record "Coraza 归因 status_code=403" 1 || record "Coraza 归因 status_code=403" 0 "got=$(py_get waf_status)"

echo "============================================================"
echo "§207 统一决策验证：$PASS/$TOTAL 通过，$FAIL 失败"
if [ "$FAIL" -gt 0 ]; then printf '失败项：\n'; printf '  %s\n' "${FAILED[@]}"; fi
echo "============================================================"
[ "$FAIL" = "0" ]
