#!/usr/bin/env bash
# CI edition 矩阵冒烟（阶段8 任务书退出条件 #92；.github/workflows/ci.yml smoke-waf/smoke-wdsp）：
#
#   EDITION=waf   API 关闭态：/api/v1/api-security 命名空间未注册（未认证请求 404）
#                 + 核心防护冒烟（默认 Caddyfile：正常反代 200 到达源站、SQLi 被拦 403）
#   EDITION=wdsp  API 开启态：导入 CI 临时授权后 /api/v1/api-security/* 可认证访问（200），
#                 发布应用后经网关发送一次请求即产生 API 运行时事件（采集入库可查）
#
# 栈：deployment/docker-compose.stage5.yml（wdsp 叠加 docker-compose.wdsp.yml），
# 仅启动 postgres/valkey/api/gateway/testorigin（ollama/logrotator 与冒烟无关，不启动）。
# 镜像：CI 由 docker/build-push-action 预建（type=gha 缓存）；本地缺镜像时经 compose 现建。
# 口令/授权签名密钥每轮随机生成于 mktemp 目录，脚本退出即清理，不落仓库。
#
# 用法：EDITION=waf|wdsp bash test/e2e/ci-edition-smoke.sh
# 依赖：docker(compose 插件)、curl、openssl（支持 Ed25519）、python3
set -euo pipefail

EDITION="${EDITION:?用法：EDITION=waf|wdsp bash test/e2e/ci-edition-smoke.sh}"
case "$EDITION" in
  waf|wdsp) ;;
  *) echo "ERROR: EDITION 仅支持 waf|wdsp，got=$EDITION" >&2; exit 2 ;;
esac

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

API_PORT="${API_PORT:-18081}"
GATEWAY_PORT="${GATEWAY_PORT:-18080}"
API_URL="http://127.0.0.1:$API_PORT"
GATEWAY_URL="http://127.0.0.1:$GATEWAY_PORT"

# ---- 每轮随机口令/密钥（仅本轮临时栈使用）----
WORK_DIR="$(mktemp -d)"
ENV_FILE="$WORK_DIR/ci-smoke.env"
PG_PWD="$(openssl rand -hex 16)"
VK_PWD="$(openssl rand -hex 16)"
ADMIN_PWD="Ci$(openssl rand -hex 8)1!"     # 满足复杂度：大小写+数字+特殊字符
ADMIN_NEW_PWD="Ci$(openssl rand -hex 8)2!"
SEC_PWD_CI="CiSec@$(openssl rand -hex 6)1"
MASTER_KEY="$(openssl rand -hex 32)"
API_ENABLED="false"
[ "$EDITION" = "wdsp" ] && API_ENABLED="true"

# ---- wdsp：生成 CI 临时 Ed25519 验签密钥对（公钥经 env 注入 api 容器）----
# .lic 语义与 server/tests/license_helper_test.go buildTestLicense 完全一致：
# 签名输入 = payload map 的 Go json.Marshal 规范字节（键字典序、紧凑、无 HTML 字符），
# python json.dumps(sort_keys, 紧凑分隔符, 全 ASCII) 逐字节等价（已由口径校验脚本比对）。
LIC_KEY_ID="ci-smoke-key"
if [ "$EDITION" = "wdsp" ]; then
  openssl genpkey -algorithm ed25519 -out "$WORK_DIR/lic-key.pem" >/dev/null 2>&1
  LIC_PUB_HEX="$(openssl pkey -in "$WORK_DIR/lic-key.pem" -pubout -outform DER 2>/dev/null \
    | tail -c 32 | python3 -c 'import sys; print(sys.stdin.buffer.read().hex())')"
  python3 - "$WORK_DIR" "$LIC_KEY_ID" <<'PY'
import json, sys, datetime
work_dir, key_id = sys.argv[1], sys.argv[2]
payload = {
    "license_id": "LIC-CI-SMOKE-0001",
    "license_type": "FORMAL",
    "product": "wdsp",
    "customer": "CI Smoke",
    "issued_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "expires_at": None,            # 永久授权
    "perpetual": True,
    "machine_fingerprint": None,   # 不绑定机器指纹（CI 容器无指纹材料也可生效）
    "quotas": {"max_applications": 0, "max_api_endpoints": 0, "max_qps": 0},  # 0 = 不限制
    "features": ["api", "waf"],
    "version": 1,
    "key_id": key_id,
}
canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
with open(work_dir + "/lic-payload.bin", "w") as f:
    f.write(canonical)
PY
  openssl pkeyutl -sign -rawin -inkey "$WORK_DIR/lic-key.pem" \
    -in "$WORK_DIR/lic-payload.bin" -out "$WORK_DIR/lic-sig.bin"
  LIC_SIG_HEX="$(python3 -c 'import sys; print(open(sys.argv[1], "rb").read().hex())' "$WORK_DIR/lic-sig.bin")"
  python3 - "$WORK_DIR" "$LIC_SIG_HEX" <<'PY'
import json, sys
work_dir, sig = sys.argv[1], sys.argv[2]
with open(work_dir + "/lic-payload.bin") as f:
    payload = json.load(f)
with open(work_dir + "/license.lic", "w") as f:
    json.dump({"payload": payload, "signature": sig}, f)
PY
fi

# ---- 生成本轮 compose env 文件（mktemp 内，不污染仓库 .env）----
{
  echo "POSTGRES_PASSWORD=$PG_PWD"
  echo "VALKEY_PASSWORD=$VK_PWD"
  echo "INITIAL_ADMIN_USERNAME=jiuzhang_admin"
  echo "INITIAL_ADMIN_PASSWORD=$ADMIN_PWD"
  echo "JIUZHANG_MASTER_KEY=$MASTER_KEY"
  echo "PRODUCT_EDITION=$EDITION"
  echo "API_DYNAMIC_PROTECTION_ENABLED=$API_ENABLED"
  echo "API_PORT=$API_PORT"
  echo "GATEWAY_PORT=$GATEWAY_PORT"
  if [ "$EDITION" = "wdsp" ]; then
    echo "LICENSE_VENDOR_PUBLIC_KEY=$LIC_KEY_ID:$LIC_PUB_HEX"
  fi
} > "$ENV_FILE"

COMPOSE=(docker compose --env-file "$ENV_FILE" -f deployment/docker-compose.stage5.yml)
[ "$EDITION" = "wdsp" ] && COMPOSE+=(-f deployment/docker-compose.wdsp.yml -f deployment/docker-compose.test-license.yml)

# ---- 本地安全防护：既有 stage5 容器在运行时拒绝接管（CI runner 恒为空）----
if [ "${CI:-}" != "true" ] && [ -n "$("${COMPOSE[@]}" ps -q 2>/dev/null)" ]; then
  echo "ERROR: 检测到 stage5 编排已有容器在运行；本地冒烟会互相干扰，请先 make stage5-down" >&2
  rm -rf "$WORK_DIR"
  exit 1
fi

cleanup() {
  local rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "==== 失败诊断：compose ps ===="
    "${COMPOSE[@]}" ps 2>&1 || true
    echo "==== 失败诊断：api/gateway 日志尾部 ===="
    "${COMPOSE[@]}" logs --tail=150 api gateway 2>&1 | tail -n 320 || true
  fi
  # 不删卷（-v）：CI runner 一次性无需清理；避免误伤本地同名历史卷
  "${COMPOSE[@]}" down --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK_DIR"
  exit "$rc"
}
trap cleanup EXIT

TOTAL=0; PASS=0; FAIL=0; FAILED=()
record() {
  local name="$1" ok="$2" detail="${3:-}"
  TOTAL=$((TOTAL+1))
  if [ "$ok" = "1" ]; then PASS=$((PASS+1)); echo "PASS  $name"
  else FAIL=$((FAIL+1)); FAILED+=("$name: $detail"); echo "FAIL  $name ($detail)"; fi
}
# expect_code <name> <want> <got>
expect_code() { [ "$2" = "$3" ] && record "$1" 1 || record "$1" 0 "status=$3 want=$2"; }

# wait_http <url> <want_code> <timeout_s>
wait_http() {
  local url="$1" want="$2" deadline=$(( $(date +%s) + ${3:-120} )) code
  while [ "$(date +%s)" -lt "$deadline" ]; do
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$url" 2>/dev/null || echo 000)"
    [ "$code" = "$want" ] && return 0
    sleep 3
  done
  echo "ERROR: 等待 $url 返回 $want 超时（last=$code）" >&2
  return 1
}

echo "============================================================"
echo "CI edition 冒烟  edition=$EDITION  api=$API_URL  gateway=$GATEWAY_URL"
echo "============================================================"

# ---- 镜像：CI 已预建（build-push-action + gha 缓存）；本地缺失时现建 ----
NEED_BUILD=0
for img in jiuzhang-server:stage5 jiuzhang-gateway:stage5 jiuzhang-testorigin:stage1; do
  docker image inspect "$img" >/dev/null 2>&1 || NEED_BUILD=1
done
if [ "$NEED_BUILD" = "1" ]; then
  echo "[build] 本地缺失镜像，经 compose 构建 api/gateway/testorigin ..."
  "${COMPOSE[@]}" build api gateway testorigin
fi

# compose 只读挂载源（仓库 runtime/license 被 .gitignore 排除，CI 检出不存在）
mkdir -p runtime/license

echo "[up] 启动 postgres/valkey/testorigin/gateway/api ..."
"${COMPOSE[@]}" up -d api gateway

# 迁移约 90 个文件随 api 启动执行，健康等待放宽到 240s
wait_http "$API_URL/api/v1/health" 200 240
record "api 健康检查通过" 1

if [ "$EDITION" = "waf" ]; then
  # ---------- WAF 形态：API 命名空间不可用 + 核心防护冒烟 ----------
  # 命名空间未注册时请求直达 mux 兜底 404（认证链按路由挂载，不拦截未注册路径）
  expect_code "api-security/endpoints 未注册（404）" 404 \
    "$(curl -s -o /dev/null -w '%{http_code}' "$API_URL/api/v1/api-security/endpoints")"
  expect_code "api-security/runtime/events 未注册（404）" 404 \
    "$(curl -s -o /dev/null -w '%{http_code}' "$API_URL/api/v1/api-security/runtime/events")"

  # 默认 Caddyfile（SEC_RULE_ENGINE=On）反代 testorigin：与阶段1 run-waf-tests.sh 同口径
  wait_http "$GATEWAY_URL/health" 200 90
  resp="$(curl -s -w $'\n%{http_code}' "$GATEWAY_URL/echo?a=1&b=2")"
  code="$(echo "$resp" | tail -n1)"
  mark="$(echo "$resp" | sed '$d' | python3 -c 'import json,sys; print(json.load(sys.stdin).get("upstream_mark",""))' 2>/dev/null || echo '')"
  [ "$code" = "200" ] && [ "$mark" = "REACHED_ORIGIN" ] \
    && record "正常请求 200 到达源站" 1 || record "正常请求 200 到达源站" 0 "status=$code mark=$mark"

  resp="$(curl -s -w $'\n%{http_code}' "$GATEWAY_URL/echo?id=1%20UNION%20SELECT%20username,password%20FROM%20users--")"
  code="$(echo "$resp" | tail -n1)"
  body="$(echo "$resp" | sed '$d')"
  [ "$code" = "403" ] && echo "$body" | grep -q "请求已被安全策略阻断" \
    && record "SQLi 被拦 403（九章阻断页）" 1 || record "SQLi 被拦 403（九章阻断页）" 0 "status=$code"
else
  # ---------- WDSP 形态：API 命名空间可认证访问 + 运行时事件 ----------
  wait_http "$GATEWAY_URL/health" 200 90
  # 未认证命中已注册命名空间 → 认证链 401（区别于 waf 形态的 404）
  expect_code "api-security 命名空间已注册（未认证 401）" 401 \
    "$(curl -s -o /dev/null -w '%{http_code}' "$API_URL/api/v1/api-security/endpoints")"

  # 登录/建用户/建应用/发布复用阶段5公共函数（与 stage8-gateway-tests.sh 同口径）
  export API_URL GATEWAY_URL
  export HOST_HEADER="ci-smoke-wdsp.local"
  export VALKEY_PASSWORD="$VK_PWD" VALKEY_CONTAINER="jiuzhang-stage5-valkey"
  export SYS_USER="jiuzhang_admin" SYS_PWD="$ADMIN_PWD" SYS_NEW_PWD="$ADMIN_NEW_PWD"
  export SEC_USER="ci_smoke_sec" SEC_PWD="$SEC_PWD_CI"
  export APP_CODE="cismoke"
  # shellcheck source=../waf/scripts/stage5-setup.sh
  source test/waf/scripts/stage5-setup.sh

  SYS_CSRF="$(s5_ensure_sysadmin)" || { echo "ERROR: sysadmin 登录失败" >&2; exit 1; }
  record "系统管理员登录（含强制改密）" 1

  # 导入 CI 临时 wdsp 授权（解锁授权门控；产品形态生效）
  LIC_BODY="$(python3 -c 'import json,sys; print(json.dumps({"file_content": open(sys.argv[1]).read()}))' "$WORK_DIR/license.lic")"
  expect_code "导入 CI 临时 wdsp 授权" 200 \
    "$(curl -s -o /dev/null -w '%{http_code}' -b "/tmp/s5-$SYS_USER.txt" -X POST "$API_URL/api/v1/license/import" \
      -H 'Content-Type: application/json' -H "X-CSRF-Token: $SYS_CSRF" -d "$LIC_BODY")"

  EDITION_OK="$(curl -s -b "/tmp/s5-$SYS_USER.txt" "$API_URL/api/v1/product/edition" | python3 -c "
import json,sys
d=json.load(sys.stdin)['data']
print('OK' if (d.get('edition')=='wdsp' and d.get('api_dynamic_protection') is True
      and d.get('license_valid') is True) else 'BAD')" 2>/dev/null || echo BAD)"
  [ "$EDITION_OK" = "OK" ] && record "product/edition=wdsp 且授权生效" 1 \
    || record "product/edition=wdsp 且授权生效" 0 "probe=$EDITION_OK"

  SEC_CSRF="$(s5_ensure_secuser "$SYS_CSRF")"
  [ -n "$SEC_CSRF" ] || { echo "ERROR: 安全管理员登录失败" >&2; exit 1; }
  APP_ID="$(s5_ensure_app "$SEC_CSRF")"
  echo "[setup] app=$APP_ID"
  PUB="$(s5_publish "$SEC_CSRF")"
  [ "$PUB" = "PUBLISH_OK" ] && record "配置发布成功（含 API 防护下发）" 1 \
    || { record "配置发布成功（含 API 防护下发）" 0 "$PUB"; echo "ABORT"; exit 1; }

  # 可认证访问 API 命名空间（授权+权限齐备 → 200）
  expect_code "api-security/endpoints 可认证访问（200）" 200 \
    "$(curl -s -o /dev/null -w '%{http_code}' -b "/tmp/s5-$SEC_USER.txt" "$API_URL/api/v1/api-security/endpoints?page_size=1")"

  # 经网关发送一次 JSON 写请求（源站任意路径 404 亦算到达；非 403/429 即未被误拦）
  code="$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $HOST_HEADER" -H 'Content-Type: application/json' \
    -X POST -d '{"id":1,"name":"widget"}' "$GATEWAY_URL/v1/orders/123")"
  [ "$code" != "403" ] && [ "$code" != "429" ] \
    && record "API 请求经网关到达源站（=$code）" 1 || record "API 请求经网关到达源站" 0 "status=$code"

  # 采集器 2s 轮询：30s 内应能在管理面查到该请求的运行时事件
  EV_TOTAL=""
  for _ in $(seq 1 15); do
    EV_TOTAL="$(curl -s -b "/tmp/s5-$SEC_USER.txt" "$API_URL/api/v1/api-security/runtime/events?page_size=1" \
      | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["total"])' 2>/dev/null || echo '')"
    [ "${EV_TOTAL:-0}" -ge 1 ] && break
    sleep 2
  done
  [ "${EV_TOTAL:-0}" -ge 1 ] && record "一次请求产生 API 运行时事件（total=$EV_TOTAL）" 1 \
    || record "一次请求产生 API 运行时事件" 0 "total=${EV_TOTAL:-查询失败}"
fi

echo "============================================================"
echo "CI edition 冒烟（$EDITION）汇总: 总用例 $TOTAL 通过 $PASS 失败 $FAIL"
if [ "$FAIL" -gt 0 ]; then
  for c in "${FAILED[@]}"; do echo "  - $c"; done
fi
echo "============================================================"
[ "$FAIL" -eq 0 ]
