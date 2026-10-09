#!/usr/bin/env bash
# 九章阶段5 真实网关测试：真实IP识别、黑白名单、CC限速、临时封禁、Valkey故障
# 依赖 stage5 编排环境（api:18081, gateway:18080, testorigin）
# 用法：bash test/waf/scripts/stage5-gateway-tests.sh
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
check() { # name want path [curl args...]
  local name="$1" want="$2" path="$3"; shift 3
  local st
  st=$(s5_req "$path" "$@")
  [ "$st" = "$want" ] && record "$name" 1 || record "$name" 0 "status=$st want=$want"
}

echo "============================================================"
echo "九章阶段5 真实网关测试  gateway=$GATEWAY_URL api=$API_URL"
echo "============================================================"

# ---------- 准备 ----------
SYS_CSRF=$(s5_ensure_sysadmin) || exit 1
SEC_CSRF=$(s5_ensure_secuser "$SYS_CSRF")
[ -z "$SEC_CSRF" ] && { echo "ERROR: sec login failed"; exit 1; }
APP_ID=$(s5_ensure_app "$SEC_CSRF")
echo "[setup] app=$APP_ID"

# 幂等清理：删除上次运行的测试策略/规则/可信代理
s5_cleanup_by_name() { # endpoint keyword_field names...
  local endpoint="$1"; shift
  for name in "$@"; do
    local ids
    ids=$(curl -s -b "/tmp/s5-$SEC_USER.txt" "$API_URL/api/v1/$endpoint?page_size=100" | python3 -c "
import json,sys
items=json.load(sys.stdin)['data'].get('items') or []
print(' '.join(i['id'] for i in items if i.get('name')=='$name'))" 2>/dev/null)
    for id in $ids; do
      curl -s -o /dev/null -b "/tmp/s5-$SEC_USER.txt" -X DELETE "$API_URL/api/v1/$endpoint/$id" -H "X-CSRF-Token: $SEC_CSRF"
    done
  done
}
s5_cleanup_by_name rate-limit-policies cc-reject-ip cc-observe cc-uri cc-temp
s5_cleanup_by_name access-rules deny-doc-99 deny-conn gd-cidr ga-60 ad-70 aa-70 ga-cc-bypass
s5_cleanup_by_name trusted-proxies docker-bridge
# 释放遗留 ACTIVE 临时封禁
for bid in $(curl -s -b "/tmp/s5-$SEC_USER.txt" "$API_URL/api/v1/temporary-blocks?status=ACTIVE&page_size=100" | python3 -c "
import json,sys
items=json.load(sys.stdin)['data'].get('items') or []
print(' '.join(i['id'] for i in items))" 2>/dev/null); do
  s5_post_code "/api/v1/temporary-blocks/$bid/release" "{}" "$SEC_CSRF" > /dev/null
done
# 说明：CC 计数键按新策略 ID 命名空间隔离，重建后无需等待旧窗口过期

# 连接源 IP（经 /echo 的 X-Real-Ip 获取）——人工解封经轮询传播到网关有数秒延迟，
# 轮询等待 /echo 可用；读取失败时立即中止，避免空 CONN_IP 造成级联误判
# （历史故障：遗留 CC_AUTO 封禁致 CONN_IP 为空，deny-conn 用例全链误判）
CONN_IP=""
for _ in $(seq 1 15); do
  ECHO_BODY=$(curl -s -H "Host: $HOST_HEADER" "$GATEWAY_URL/echo")
  CONN_IP=$(echo "$ECHO_BODY" | python3 -c "import json,sys; print(json.load(sys.stdin)['headers'].get('X-Real-Ip',''))" 2>/dev/null)
  [ -n "$CONN_IP" ] && break
  sleep 1
done
if [ -z "$CONN_IP" ]; then
  echo "ERROR: 无法从 /echo 读取连接源 IP（临时封禁未解除或网关异常），中止避免级联误判" >&2
  exit 1
fi
echo "[setup] connection ip: $CONN_IP"
# Docker 网络子网（可信代理注册用）
SUBNET=$(docker network inspect jiuzhang-stage5_stage5-net --format '{{(index .IPAM.Config 0).Subnet}}' 2>/dev/null)
echo "[setup] docker subnet: $SUBNET"
# 会话性残留清理（伪造防护用例的前置条件）：删除任何覆盖连接源的可信代理——
# 历史手工验收曾遗留覆盖 docker 子网的代理条目（DISABLED 后仍占用唯一索引
# ux_trusted_proxies_cidr，导致本套件 docker-bridge 重建被 409 拒绝）；
# 按 CIDR 包含关系判定（不限名称），不影响不覆盖连接源的演示种子。
for pid in $(curl -s -b "/tmp/s5-$SEC_USER.txt" "$API_URL/api/v1/trusted-proxies?page_size=100" | CONN_IP="$CONN_IP" python3 -c "
import json,sys,ipaddress,os
conn = ipaddress.ip_address(os.environ['CONN_IP'])
items = json.load(sys.stdin)['data'].get('items') or []
for i in items:
    try:
        if conn in ipaddress.ip_network(i['cidr']):
            print(i['id'])
    except Exception:
        pass" 2>/dev/null); do
  curl -s -o /dev/null -b "/tmp/s5-$SEC_USER.txt" -X DELETE "$API_URL/api/v1/trusted-proxies/$pid" -H "X-CSRF-Token: $SEC_CSRF"
  echo "[setup] 已删除覆盖连接源的可信代理残留: $pid"
done

# CC 策略（一次性创建，后续按 URI 前缀与 IP 隔离测试）
s5_post /api/v1/rate-limit-policies "{\"name\":\"cc-reject-ip\",\"scope_type\":\"APPLICATION\",\"application_id\":\"$APP_ID\",\"uri_match_type\":\"PREFIX\",\"uri_pattern\":\"/cc/ip/\",\"dimension\":\"CLIENT_IP\",\"algorithm\":\"TOKEN_BUCKET\",\"requests_limit\":5,\"window_seconds\":60,\"burst_capacity\":5,\"action\":\"REJECT\",\"priority\":100}" "$SEC_CSRF" > /dev/null
s5_post /api/v1/rate-limit-policies "{\"name\":\"cc-observe\",\"scope_type\":\"APPLICATION\",\"application_id\":\"$APP_ID\",\"uri_match_type\":\"PREFIX\",\"uri_pattern\":\"/cc/obs/\",\"dimension\":\"CLIENT_IP\",\"algorithm\":\"TOKEN_BUCKET\",\"requests_limit\":1,\"window_seconds\":60,\"action\":\"OBSERVE\",\"priority\":100}" "$SEC_CSRF" > /dev/null
s5_post /api/v1/rate-limit-policies "{\"name\":\"cc-uri\",\"scope_type\":\"URI\",\"application_id\":\"$APP_ID\",\"uri_match_type\":\"PREFIX\",\"uri_pattern\":\"/cc/api/\",\"dimension\":\"CLIENT_IP_AND_URI\",\"algorithm\":\"SLIDING_WINDOW\",\"requests_limit\":3,\"window_seconds\":60,\"action\":\"REJECT\",\"priority\":100}" "$SEC_CSRF" > /dev/null
s5_post /api/v1/rate-limit-policies "{\"name\":\"cc-temp\",\"scope_type\":\"APPLICATION\",\"application_id\":\"$APP_ID\",\"uri_match_type\":\"PREFIX\",\"uri_pattern\":\"/cc/temp/\",\"dimension\":\"CLIENT_IP\",\"algorithm\":\"TOKEN_BUCKET\",\"requests_limit\":2,\"window_seconds\":60,\"burst_capacity\":2,\"action\":\"TEMP_BLOCK\",\"block_duration_seconds\":300,\"priority\":100}" "$SEC_CSRF" > /dev/null
# 伪造防护验证用黑名单（文档保留段，永不真实存在）
s5_post /api/v1/access-rules "{\"name\":\"deny-doc-99\",\"rule_type\":\"DENY\",\"scope_type\":\"GLOBAL\",\"address\":\"198.51.100.99\",\"priority\":100,\"validity_type\":\"PERMANENT\"}" "$SEC_CSRF" > /dev/null

echo ""
echo "---- 0. 伪造防护（无可信代理时代理头无效） ----"
[ "$(s5_publish "$SEC_CSRF")" = "PUBLISH_OK" ] && record "publish-p0" 1 || record "publish-p0" 0
# 伪造 XFF 为黑名单 IP：连接源不可信，XFF 必须被忽略 → 200
check "forge-xff-ignored" 200 "/echo" -H "X-Forwarded-For: 198.51.100.99"
check "forge-realip-ignored" 200 "/echo" -H "X-Real-IP: 198.51.100.99"
# X-Real-Ip 被网关覆盖为连接源（不信任客户端传入）
REAL=$(curl -s -H "Host: $HOST_HEADER" -H "X-Real-IP: 9.9.9.9" "$GATEWAY_URL/echo" | python3 -c "import json,sys; print(json.load(sys.stdin)['headers'].get('X-Real-Ip',''))")
[ "$REAL" = "$CONN_IP" ] && record "xrealip-overwritten" 1 || record "xrealip-overwritten" 0 "got=$REAL want=$CONN_IP"
# 伪造 IP 头不能绕过 CC（轮换 XFF 仍按连接源计数）
CC_FORGE_OK=1
for i in 1 2 3 4 5; do
  st=$(s5_req /cc/ip/x -H "X-Forwarded-For: 10.9.9.$i")
  [ "$st" = "404" ] || CC_FORGE_OK=0
done
st=$(s5_req /cc/ip/x -H "X-Forwarded-For: 10.9.9.9")
[ "$CC_FORGE_OK" = "1" ] && [ "$st" = "429" ] && record "cc-forge-rotation-still-limited" 1 || record "cc-forge-rotation-still-limited" 0 "last=$st first5=$CC_FORGE_OK"
# 连接源黑名单：全局 DENY 连接源 IP → 全部 403 且伪造头无效
s5_post /api/v1/access-rules "{\"name\":\"deny-conn\",\"rule_type\":\"DENY\",\"scope_type\":\"GLOBAL\",\"address\":\"$CONN_IP\",\"priority\":100,\"validity_type\":\"PERMANENT\"}" "$SEC_CSRF" > /dev/null
[ "$(s5_publish "$SEC_CSRF")" = "PUBLISH_OK" ] || record "publish-p0b" 0
check "deny-conn-ip" 403 "/echo"
check "deny-conn-ip-forge-bypass" 403 "/echo" -H "X-Forwarded-For: 8.8.8.8"
# 被阻断请求未到源站（403 不含源站标记）
BODY=$(curl -s -H "Host: $HOST_HEADER" "$GATEWAY_URL/echo")
echo "$BODY" | grep -q "REACHED_ORIGIN" && record "blocked-not-upstream" 0 "reached origin" || record "blocked-not-upstream" 1
# 清理连接源黑名单（恢复后续测试）
DENY_CONN_ID=$(curl -s -b "/tmp/s5-$SEC_USER.txt" "$API_URL/api/v1/access-rules?keyword=deny-conn" | python3 -c "import json,sys; items=json.load(sys.stdin)['data']['items']; print(next((i['id'] for i in items if i['name']=='deny-conn'),''))")
s5_post_code "/api/v1/access-rules/$DENY_CONN_ID/disable" "{}" "$SEC_CSRF" > /dev/null

echo ""
echo "---- 1. 可信代理与真实IP ----"
s5_post /api/v1/trusted-proxies "{\"name\":\"docker-bridge\",\"cidr\":\"$SUBNET\",\"header_type\":\"X_FORWARDED_FOR\",\"priority\":100}" "$SEC_CSRF" > /dev/null
# 校验 docker-bridge 创建成功（CIDR 唯一索引冲突等静默失败会级联误判，必须显式中止）
DB_PROXY_ID=$(curl -s -b "/tmp/s5-$SEC_USER.txt" "$API_URL/api/v1/trusted-proxies?keyword=docker-bridge" | python3 -c "
import json,sys
items=json.load(sys.stdin)['data'].get('items') or []
print(next((i['id'] for i in items if i.get('name')=='docker-bridge'),''))" 2>/dev/null)
if [ -z "$DB_PROXY_ID" ]; then
  echo "ERROR: docker-bridge 可信代理创建失败（CIDR 可能被残留条目占用），中止" >&2
  exit 1
fi
# 优先级验证规则：全局黑 CIDR + 全局白单IP + 应用黑单IP + 应用白单IP
s5_post /api/v1/access-rules "{\"name\":\"gd-cidr\",\"rule_type\":\"DENY\",\"scope_type\":\"GLOBAL\",\"address\":\"198.51.100.0/24\",\"priority\":100,\"validity_type\":\"PERMANENT\"}" "$SEC_CSRF" > /dev/null
s5_post /api/v1/access-rules "{\"name\":\"ga-60\",\"rule_type\":\"ALLOW\",\"scope_type\":\"GLOBAL\",\"address\":\"198.51.100.60\",\"priority\":100,\"validity_type\":\"PERMANENT\"}" "$SEC_CSRF" > /dev/null
s5_post /api/v1/access-rules "{\"name\":\"ad-70\",\"rule_type\":\"DENY\",\"scope_type\":\"APPLICATION\",\"application_id\":\"$APP_ID\",\"address\":\"198.51.100.70\",\"priority\":100,\"validity_type\":\"PERMANENT\"}" "$SEC_CSRF" > /dev/null
s5_post /api/v1/access-rules "{\"name\":\"aa-70\",\"rule_type\":\"ALLOW\",\"scope_type\":\"APPLICATION\",\"application_id\":\"$APP_ID\",\"address\":\"198.51.100.70\",\"priority\":100,\"validity_type\":\"PERMANENT\"}" "$SEC_CSRF" > /dev/null
[ "$(s5_publish "$SEC_CSRF")" = "PUBLISH_OK" ] && record "publish-p1" 1 || record "publish-p1" 0
# 真实IP识别：单级可信代理，X-Real-Ip 透传真实客户端
REAL=$(curl -s -H "Host: $HOST_HEADER" -H "X-Forwarded-For: 203.0.113.123" "$GATEWAY_URL/echo" | python3 -c "import json,sys; print(json.load(sys.stdin)['headers'].get('X-Real-Ip',''))")
[ "$REAL" = "203.0.113.123" ] && record "realip-single-proxy" 1 || record "realip-single-proxy" 0 "got=$REAL"
# 多级代理：client, 可信<本子网地址> → 右跳可信取 client（子网随 compose 变化，动态取第 9 个主机位）
TRUSTED_HOP=$(python3 -c "import ipaddress;print(list(ipaddress.ip_network('$SUBNET').hosts())[8])" 2>/dev/null)
TRUSTED_HOP=${TRUSTED_HOP:-172.20.0.9}
REAL=$(curl -s -H "Host: $HOST_HEADER" -H "X-Forwarded-For: 203.0.113.124, $TRUSTED_HOP" "$GATEWAY_URL/echo" | python3 -c "import json,sys; print(json.load(sys.stdin)['headers'].get('X-Real-Ip',''))")
[ "$REAL" = "203.0.113.124" ] && record "realip-multi-proxy" 1 || record "realip-multi-proxy" 0 "got=$REAL"
# 超长代理链（>16）→ 回退连接源 + 事件
LONG_CHAIN=$(python3 -c "print(', '.join('10.0.0.%d'%i for i in range(1,21)))")
REAL=$(curl -s -H "Host: $HOST_HEADER" -H "X-Forwarded-For: $LONG_CHAIN" "$GATEWAY_URL/echo" | python3 -c "import json,sys; print(json.load(sys.stdin)['headers'].get('X-Real-Ip',''))")
[ "$REAL" = "$CONN_IP" ] && record "realip-chain-too-long-fallback" 1 || record "realip-chain-too-long-fallback" 0 "got=$REAL"
# 非法头 → 回退连接源
REAL=$(curl -s -H "Host: $HOST_HEADER" -H "X-Forwarded-For: not-an-ip" "$GATEWAY_URL/echo" | python3 -c "import json,sys; print(json.load(sys.stdin)['headers'].get('X-Real-Ip',''))")
[ "$REAL" = "$CONN_IP" ] && record "realip-invalid-header-fallback" 1 || record "realip-invalid-header-fallback" 0 "got=$REAL"
# 黑白名单优先级
check "deny-real-ip-cidr" 403 "/echo" -H "X-Forwarded-For: 198.51.100.51"     # 全局黑 CIDR
check "global-allow-over-deny" 200 "/echo" -H "X-Forwarded-For: 198.51.100.60" # 全局白 > 全局黑
check "app-allow-over-deny" 200 "/echo" -H "X-Forwarded-For: 198.51.100.70"    # 应用白 > 应用黑

echo ""
echo "---- 2. CC限速 ----"
# 阈值以下与达阈值（IP 203.0.113.21，限 5/60s）
CC_OK=1
for i in 1 2 3 4 5; do st=$(s5_req /cc/ip/a -H "X-Forwarded-For: 203.0.113.21"); [ "$st" = "404" ] || CC_OK=0; done
[ "$CC_OK" = "1" ] && record "cc-under-threshold" 1 || record "cc-under-threshold" 0
st=$(s5_req /cc/ip/a -H "X-Forwarded-For: 203.0.113.21")
[ "$st" = "429" ] && record "cc-reject-429" 1 || record "cc-reject-429" 0 "status=$st"
# 429 响应头与无内部信息泄露
HDRS=$(curl -s -D - -o /dev/null -H "Host: $HOST_HEADER" -H "X-Forwarded-For: 203.0.113.21" "$GATEWAY_URL/cc/ip/a")
echo "$HDRS" | grep -qi "^Retry-After:" && echo "$HDRS" | grep -qi "^X-Jiuzhang-Request-ID:" \
  && record "cc-429-headers" 1 || record "cc-429-headers" 0 "$HDRS"
BODY=$(curl -s -H "Host: $HOST_HEADER" -H "X-Forwarded-For: 203.0.113.21" "$GATEWAY_URL/cc/ip/a")
echo "$BODY" | grep -qiE "token|bucket|cc-reject|limit|window|count|stage5" && record "cc-429-no-internals" 0 "leak: $BODY" || record "cc-429-no-internals" 1
# 不同 IP 独立计数
check "cc-ip-independent" 404 "/cc/ip/a" -H "X-Forwarded-For: 203.0.113.22"
# URI 级共享计数（/cc/api/ 前缀，限 3/60s，滑动窗口）
for i in a b c; do s5_req /cc/api/$i -H "X-Forwarded-For: 203.0.113.23" > /dev/null; done
check "cc-uri-shared-count" 429 "/cc/api/d" -H "X-Forwarded-For: 203.0.113.23"
check "cc-uri-other-path-ok" 404 "/cc/ip/a" -H "X-Forwarded-For: 203.0.113.23"
# 观察模式不阻断
OBS_OK=1
for i in 1 2 3 4; do st=$(s5_req /cc/obs/x -H "X-Forwarded-For: 203.0.113.24"); [ "$st" = "404" ] || OBS_OK=0; done
[ "$OBS_OK" = "1" ] && record "cc-observe-not-block" 1 || record "cc-observe-not-block" 0
# 临时封禁（限 2/60s → 第3次 429，之后 403）
s5_req /cc/temp/x -H "X-Forwarded-For: 203.0.113.25" > /dev/null
s5_req /cc/temp/x -H "X-Forwarded-For: 203.0.113.25" > /dev/null
st=$(s5_req /cc/temp/x -H "X-Forwarded-For: 203.0.113.25")
[ "$st" = "429" ] && record "cc-tempblock-trigger-429" 1 || record "cc-tempblock-trigger-429" 0 "status=$st"
sleep 1
st=$(s5_req /cc/temp/x -H "X-Forwarded-For: 203.0.113.25")
[ "$st" = "403" ] && record "cc-tempblock-enforced" 1 || record "cc-tempblock-enforced" 0 "status=$st"
# 白名单绕过 CC：为 203.0.113.26 建全局白名单后超限请求仍放行（需发布）
s5_post /api/v1/access-rules "{\"name\":\"ga-cc-bypass\",\"rule_type\":\"ALLOW\",\"scope_type\":\"GLOBAL\",\"address\":\"203.0.113.26\",\"priority\":100,\"validity_type\":\"PERMANENT\"}" "$SEC_CSRF" > /dev/null
[ "$(s5_publish "$SEC_CSRF")" = "PUBLISH_OK" ] || record "publish-p2" 0
BYPASS_OK=1
for i in 1 2 3 4 5 6 7 8; do st=$(s5_req /cc/ip/a -H "X-Forwarded-For: 203.0.113.26"); [ "$st" = "404" ] || BYPASS_OK=0; done
[ "$BYPASS_OK" = "1" ] && record "cc-whitelist-bypass" 1 || record "cc-whitelist-bypass" 0

echo ""
echo "---- 3. 临时封禁管理与自动解封链路 ----"
# 封禁记录已入管理平台（采集器联动）
sleep 4
BLOCKS=$(curl -s -b "/tmp/s5-$SEC_USER.txt" "$API_URL/api/v1/temporary-blocks?status=ACTIVE&page_size=10")
BCOUNT=$(echo "$BLOCKS" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['total'])")
[ "$BCOUNT" -ge 1 ] && record "tempblock-recorded" 1 || record "tempblock-recorded" 0 "total=$BCOUNT"
BLOCK_ID=$(echo "$BLOCKS" | python3 -c "import json,sys; items=json.load(sys.stdin)['data']['items']; print(items[0]['id'] if items else '')")
# 人工解封 → 网关轮询生效 → 恢复 200
s5_post_code "/api/v1/temporary-blocks/$BLOCK_ID/release" "{}" "$SEC_CSRF" > /dev/null
sleep 3
REL_ST=$(curl -s -b "/tmp/s5-$SEC_USER.txt" "$API_URL/api/v1/temporary-blocks/$BLOCK_ID" | python3 -c "import json,sys; d=json.load(sys.stdin)['data']; b=d.get('block',d); print(b.get('status',''))" 2>/dev/null)
st=$(s5_req /cc/temp/x -H "X-Forwarded-For: 203.0.113.25")
# 封禁已解除（状态 MANUALLY_RELEASED），下次请求不再因封禁 403（CC 窗口仍在则可能 429 重新封禁，属正确防护行为）
[ "$REL_ST" = "MANUALLY_RELEASED" ] && [ "$st" != "403" ] && record "tempblock-manual-release" 1 || record "tempblock-manual-release" 0 "rel=$REL_ST http=$st"

echo ""
echo "---- 4. 事件入库验证 ----"
sleep 3
for t in IP_DENY_MATCH IP_ALLOW_MATCH CC_REQUEST_REJECTED CC_THRESHOLD_EXCEEDED CC_TEMP_BLOCK_CREATED TRUSTED_PROXY_INVALID FORWARDED_CHAIN_TOO_LONG FORWARDED_HEADER_INVALID; do
  C=$(s5_event_count "$t")
  [ "$C" -ge 1 ] && record "event-$t" 1 || record "event-$t" 0 "count=0"
done
# Request ID 可关联
RID_E=$(curl -s -b "/tmp/s5-$SEC_USER.txt" "$API_URL/api/v1/access-control-events?event_type=IP_DENY_MATCH&page_size=1" | python3 -c "import json,sys; items=json.load(sys.stdin)['data']['items']; print(items[0]['request_id'] if items else '')")
[ -n "$RID_E" ] && record "event-request-id-linked" 1 || record "event-request-id-linked" 0

echo ""
echo "---- 5. Valkey 故障（Fail-open 默认策略） ----"
docker pause jiuzhang-stage5-valkey > /dev/null
sleep 2
FAILOPEN_OK=1
for i in 1 2 3; do st=$(s5_req /cc/ip/a -H "X-Forwarded-For: 203.0.113.30"); [ "$st" = "404" ] || FAILOPEN_OK=0; done
docker unpause jiuzhang-stage5-valkey > /dev/null
[ "$FAILOPEN_OK" = "1" ] && record "valkey-down-failopen" 1 || record "valkey-down-failopen" 0
sleep 6
C=$(s5_event_count RATE_LIMIT_ENGINE_ERROR)
[ "$C" -ge 1 ] && record "valkey-down-alert-event" 1 || record "valkey-down-alert-event" 0 "count=0"

echo ""
echo "============================================================"
echo "阶段5真实网关测试汇总"
echo "总用例数: $TOTAL"
echo "通过:     $PASS"
echo "失败:     $FAIL"
if [ "$FAIL" -gt 0 ]; then
  echo "失败用例:"
  for c in "${FAILED[@]}"; do echo "  - $c"; done
fi
echo "============================================================"
[ "$FAIL" -eq 0 ]
