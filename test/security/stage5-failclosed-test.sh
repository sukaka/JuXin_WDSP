#!/usr/bin/env bash
# 九章阶段5 Fail-closed 真实验证：GUARD_FAIL_OPEN=false 时 Valkey 故障按 429 拒绝，
# 恢复 Fail-open 后故障放行。会临时切换 api 环境并暂停 Valkey，测试结束恢复原状。
# 用法：bash test/security/stage5-failclosed-test.sh
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../waf/scripts/stage5-setup.sh"

COMPOSE="docker compose --env-file .env -f deployment/docker-compose.stage5.yml"
TOTAL=0; PASS=0; FAIL=0; FAILED=()
record() {
  local name="$1" ok="$2" detail="${3:-}"
  TOTAL=$((TOTAL+1))
  if [ "$ok" = "1" ]; then PASS=$((PASS+1)); echo "PASS  $name"
  else FAIL=$((FAIL+1)); FAILED+=("$name: $detail"); echo "FAIL  $name ($detail)"; fi
}

echo "============================================================"
echo "阶段5 Fail-closed 真实验证"
echo "============================================================"

# 0. 等待 API 就绪
wait_api() {
  for _ in $(seq 1 45); do
    curl -s -o /dev/null "$API_URL/api/v1/health" && return 0
    sleep 2
  done
  return 1
}

# 1. 切换 api 到 Fail-closed 并重建容器
GUARD_FAIL_OPEN=false $COMPOSE up -d api > /dev/null 2>&1
wait_api || { echo "ERROR: api not ready"; exit 1; }
SYS_CSRF=$(s5_ensure_sysadmin) || exit 1
SEC_CSRF=$(s5_ensure_secuser "$SYS_CSRF")
[ -z "$SEC_CSRF" ] && { echo "ERROR: sec login failed"; exit 1; }
APP_ID=$(s5_ensure_app "$SEC_CSRF")
# 确保有 CC 策略覆盖 /cc/ip/（复用网关测试策略，没有则建）
EXIST=$(curl -s -b "/tmp/s5-$SEC_USER.txt" "$API_URL/api/v1/rate-limit-policies?keyword=cc-reject-ip" | python3 -c "import json,sys; items=json.load(sys.stdin)['data'].get('items') or []; print(len(items))")
[ "$EXIST" = "0" ] && s5_post /api/v1/rate-limit-policies "{\"name\":\"cc-reject-ip\",\"scope_type\":\"APPLICATION\",\"application_id\":\"$APP_ID\",\"uri_match_type\":\"PREFIX\",\"uri_pattern\":\"/cc/ip/\",\"dimension\":\"CLIENT_IP\",\"algorithm\":\"TOKEN_BUCKET\",\"requests_limit\":100000,\"window_seconds\":60,\"burst_capacity\":100000,\"action\":\"REJECT\",\"priority\":100}" "$SEC_CSRF" > /dev/null
# 发布（fail_open=false 下发到网关）
[ "$(s5_publish "$SEC_CSRF")" = "PUBLISH_OK" ] && record "publish-failclosed" 1 || record "publish-failclosed" 0

# 2. 暂停 Valkey → CC 计数引擎故障 → Fail-closed 应 429
docker pause jiuzhang-stage5-valkey > /dev/null
sleep 2
st=$(s5_req /cc/ip/a -H "X-Forwarded-For: 203.0.113.231")
docker unpause jiuzhang-stage5-valkey > /dev/null
[ "$st" = "429" ] && record "failclosed-valkey-down-429" 1 || record "failclosed-valkey-down-429" 0 "status=$st"
sleep 6
C=$(s5_event_count RATE_LIMIT_ENGINE_ERROR)
[ "$C" -ge 1 ] && record "failclosed-alert-event" 1 || record "failclosed-alert-event" 0 "count=0"

# 3. 恢复 Fail-open → 发布 → 暂停 Valkey → 应放行（404 代理到源站）
GUARD_FAIL_OPEN=true $COMPOSE up -d > /dev/null 2>&1
# 兜底：容器卡在 Created 时手动启动（并发环境下的 compose 时序问题）
if ! wait_api; then
  docker start jiuzhang-stage5-api > /dev/null 2>&1 || true
  wait_api || { echo "ERROR: api not ready after restore"; exit 1; }
fi
SYS_CSRF=$(s5_ensure_sysadmin) || exit 1
SEC_CSRF=$(s5_ensure_secuser "$SYS_CSRF")
[ "$(s5_publish "$SEC_CSRF")" = "PUBLISH_OK" ] && record "publish-failopen-restore" 1 || record "publish-failopen-restore" 0
docker pause jiuzhang-stage5-valkey > /dev/null
sleep 2
st=$(s5_req /cc/ip/a -H "X-Forwarded-For: 203.0.113.232")
docker unpause jiuzhang-stage5-valkey > /dev/null
[ "$st" = "404" ] && record "failopen-valkey-down-pass" 1 || record "failopen-valkey-down-pass" 0 "status=$st"

echo ""
echo "============================================================"
echo "Fail-closed 验证汇总: 总用例 $TOTAL 通过 $PASS 失败 $FAIL"
[ "$FAIL" -gt 0 ] && for c in "${FAILED[@]}"; do echo "  - $c"; done
echo "============================================================"
[ "$FAIL" -eq 0 ]
