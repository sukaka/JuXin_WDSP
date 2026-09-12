#!/usr/bin/env bash
# P0-04 受限例外与最终处置 真实 Caddy 网关集成冒烟（WDSP）：
# 任务书 docs/tasks/wdsp-p0/P0-04_DECISION_SCOPED_EXCEPTIONS.md 验收要求
# 「真实网关组合验证」；本脚本在 stage5+wdsp 栈上端到端验证 S4 交付。
#
# 覆盖断言（括号内为任务书用例映射）：
#   基线：无例外时 SQLi（query 参数 comment）→ WAF 403（对照组）
#   EXC-01 例外字段放行：comment 字段 SQLi → 到达源站 200（规则目标级摘除生效）
#   EXC-02 目标外字段仍拦截：name 字段 SQLi → 403（摘除不过宽）
#   EXC-08 范围外不生效：其他路径 / 其他方法（GET）→ 403
#   EXC-09 时间窗：未来生效例外由运行时 TIME_EPOCH 链控制 → 当前请求 403
#   EXC-08 伪造 XFF：source_ips 限定例外 + X-Forwarded-For 伪造 → 不生效 403
#   EXC-13 引擎侧审计：Coraza 审计日志含 exc:<uuid>/excv:<version> 命中标记
#   DEC-03/04 WAF 拦截事件 final_decision：ABORTED/BLOCK/WAF/GATEWAY/403 +
#             rule_refs 含 942100 + matched_exceptions 含例外 uuid（EXC-13 管理侧）
#   DEC-02 源站归因：源站 200 应答 → final_decision.response_source=ORIGIN/action=NONE
#   DEC-05 同请求对证：API 决策结果不被改写（final_decision.steps 留 OBSERVED），
#          事件 final_action 按实记 BLOCK（apicoraza.go attributeWAFIntercept 契约），
#          final_decision.executor_module=WAF/BLOCK
#   DEC-01 跨侧关联：security_events 与 api_runtime_events 同 request_id
#   API OBSERVE_RULE：重复 query 参数 finding 被豁免打标（excepted=true +
#          exception_id），范围外路径同 finding 不打标（EXC-11/13 API 侧）
#
# 素材说明（2026-09-08 第七轮起）：DEC-01/02/05 需要「API 分类」流量的
# api_runtime_events final_decision。/api/json 素材已带 Content-Type/Accept:
# application/json 与合法 JSON body（分类器 content_type_json 0.35 + api_prefix
# 0.15 + json_fields 0.25 + accept_json 0.15 + write_json 0.1 → is_api=true）。
# 不要去掉这些头/body：纯 /api/ 前缀只有 0.15 < 0.35 阈值，会回退为
# is_api=false，非 API 流量不落 api_runtime_events final_decision（E25/E3/E4 无行）。
#
# 栈：deployment/docker-compose.stage5.yml + docker-compose.wdsp.yml（EDITION=wdsp），
# 仅 postgres/valkey/api/gateway/testorigin。镜像从当前工作树现建。
# 口令/授权签名密钥每轮随机生成于 mktemp 目录（0600），脚本退出即清理，不落仓库。
#
# 用法：bash test/e2e/exception-p0-smoke.sh
# 依赖：docker(compose 插件)、curl、openssl、python3（仅标准库）
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

API_PORT="${API_PORT:-18081}"
GATEWAY_PORT="${GATEWAY_PORT:-18080}"
API_URL="http://127.0.0.1:$API_PORT"
GATEWAY_URL="http://127.0.0.1:$GATEWAY_PORT"
PG_PORT="${PG_PORT:-5432}"
VK_PORT="${VK_PORT:-6379}"

# ---- 每轮随机口令/密钥（仅本轮临时栈使用；mktemp 目录权限 0700）----
WORK_DIR="$(mktemp -d)"
chmod 700 "$WORK_DIR"
DUMP_DIR=""
ENV_FILE="$WORK_DIR/exc-smoke.env"
PG_USER="jiuzhang"
PG_DB="jiuzhang_waf"
PG_PWD="$(openssl rand -hex 16)"
VK_PWD="$(openssl rand -hex 16)"
ADMIN_PWD="Ci$(openssl rand -hex 8)1!"
ADMIN_NEW_PWD="Ci$(openssl rand -hex 8)2!"
SEC_PWD_CI="CiSec@$(openssl rand -hex 6)1"
MASTER_KEY="$(openssl rand -hex 32)"
IDENTITY_SALT="$(openssl rand -hex 32)"
LIC_KEY_ID="exc-smoke-key"

# ---- CI 临时 Ed25519 授权（与 jwt-trust-smoke.sh 同口径）----
openssl genpkey -algorithm ed25519 -out "$WORK_DIR/lic-key.pem" >/dev/null 2>&1
chmod 600 "$WORK_DIR/lic-key.pem"
LIC_PUB_HEX="$(openssl pkey -in "$WORK_DIR/lic-key.pem" -pubout -outform DER 2>/dev/null \
  | tail -c 32 | python3 -c 'import sys; print(sys.stdin.buffer.read().hex())')"
python3 - "$WORK_DIR" "$LIC_KEY_ID" <<'PY'
import json, sys, datetime
work_dir, key_id = sys.argv[1], sys.argv[2]
payload = {
    "license_id": "LIC-EXC-SMOKE-0001",
    "license_type": "FORMAL",
    "product": "wdsp",
    "customer": "Exception Smoke",
    "issued_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "expires_at": None,
    "perpetual": True,
    "machine_fingerprint": None,
    "quotas": {"max_applications": 0, "max_api_endpoints": 0, "max_qps": 0},
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

{
  echo "POSTGRES_USER=$PG_USER"
  echo "POSTGRES_DB=$PG_DB"
  echo "POSTGRES_PASSWORD=$PG_PWD"
  echo "POSTGRES_PORT=$PG_PORT"
  echo "VALKEY_PASSWORD=$VK_PWD"
  echo "VALKEY_PORT=$VK_PORT"
  echo "INITIAL_ADMIN_USERNAME=jiuzhang_admin"
  echo "INITIAL_ADMIN_PASSWORD=$ADMIN_PWD"
  echo "JIUZHANG_MASTER_KEY=$MASTER_KEY"
  echo "PRODUCT_EDITION=wdsp"
  echo "API_DYNAMIC_PROTECTION_ENABLED=true"
  echo "API_PORT=$API_PORT"
  echo "GATEWAY_PORT=$GATEWAY_PORT"
  echo "LICENSE_VENDOR_PUBLIC_KEY=$LIC_KEY_ID:$LIC_PUB_HEX"
} > "$ENV_FILE"
chmod 600 "$ENV_FILE"

# test-license 覆盖：显式构建 wdsp_testkeys 测试产物，LICENSE_VENDOR_PUBLIC_KEY 才被读取
# （授权信任根在正式构建中内嵌——本冒烟用的是 CI 临时密钥，必须启用测试构建）
COMPOSE=(docker compose --env-file "$ENV_FILE"
  -f deployment/docker-compose.stage5.yml -f deployment/docker-compose.wdsp.yml
  -f deployment/docker-compose.test-license.yml)

port_free() { ! python3 -c "
import socket,sys
s=socket.socket(); s.settimeout(0.3)
sys.exit(0 if s.connect_ex(('127.0.0.1',$1))==0 else 1)"; }
for p in "$PG_PORT" "$VK_PORT" "$API_PORT" "$GATEWAY_PORT" 81 443; do
  if ! port_free "$p"; then
    echo "ERROR: 127.0.0.1:$p 已被占用，请先释放" >&2; rm -rf "$WORK_DIR"; exit 1
  fi
done
if [ -n "$("${COMPOSE[@]}" ps -q 2>/dev/null)" ]; then
  echo "ERROR: 检测到 stage5 编排已有容器在运行；请先停止" >&2
  rm -rf "$WORK_DIR"; exit 1
fi

cleanup() {
  local rc=$?
  if [ "$rc" -eq 0 ] && [ "${SCRIPT_DONE:-0}" != "1" ]; then rc=1; fi
  if [ "$rc" -ne 0 ]; then
    DUMP_DIR="$(mktemp -d /tmp/exc-smoke-dump.XXXXXX)"
    {
      echo "==== compose ps ===="; "${COMPOSE[@]}" ps 2>&1
      echo; echo "==== api 日志尾部 ===="; "${COMPOSE[@]}" logs --tail=200 api 2>&1
      echo; echo "==== gateway 日志尾部 ===="; "${COMPOSE[@]}" logs --tail=200 gateway 2>&1
      echo; echo "==== gateway caddy.log 尾部 ===="
      docker exec jiuzhang-stage5-gateway sh -c 'tail -n 80 /var/log/caddy/caddy.log' 2>&1 || true
      echo; echo "==== gateway coraza-audit 尾部 ===="
      docker exec jiuzhang-stage5-gateway sh -c 'tail -n 200 /var/log/caddy/coraza-audit.log' 2>&1 || true
      echo; echo "==== gateway api-runtime-events 尾部 ===="
      docker exec jiuzhang-stage5-gateway sh -c 'tail -n 40 /var/log/caddy/api-runtime-events.log' 2>&1 || true
      echo; echo "==== api 采集器错误文件 ===="
      docker exec jiuzhang-stage5-api sh -c 'tail -n 60 /var/log/caddy-audit/api-runtime-events.log.errors' 2>&1 || true
      echo; echo "==== security_events 全量（含 final_decision） ===="
      docker exec -i jiuzhang-stage5-postgres psql -U "$PG_USER" -d "$PG_DB" -At -c "SELECT request_method || ' ' || request_path || ' uri=' || request_uri || ' status=' || coalesce(response_status::text,'-') || ' fd=' || coalesce(final_decision::text,'NULL') FROM security_events ORDER BY occurred_at" 2>&1 || true
      echo; echo "==== api_runtime_events 全量 ===="
      docker exec -i jiuzhang-stage5-postgres psql -U "$PG_USER" -d "$PG_DB" -At -c "SELECT coalesce(method,'-') || ' ' || coalesce(raw_path,'-') || ' action=' || final_action || ' status=' || coalesce(response_status::text,'-') || ' details=' || coalesce(details_json::text,'NULL') || ' fd=' || coalesce(final_decision::text,'NULL') FROM api_runtime_events ORDER BY occurred_at DESC LIMIT 40" 2>&1 || true
      echo; echo "==== exception_policies 全量 ===="
      docker exec -i jiuzhang-stage5-postgres psql -U "$PG_USER" -d "$PG_DB" -At -c "SELECT name || ' status=' || status || ' v=' || version || ' engine=' || coalesce(target_engine,'-') || ' action=' || exception_action || ' rules=' || rule_ids::text || ' params=' || param_names::text || ' uri=' || uri_exact || ' methods=' || methods::text || ' win=' || coalesce(effective_from::text,'-') || '~' || coalesce(effective_until::text,'-') FROM exception_policies ORDER BY created_at" 2>&1 || true
    } > "$DUMP_DIR/stack-dump.log" 2>&1 || true
    echo "失败诊断日志（不含密钥）：$DUMP_DIR/stack-dump.log" >&2
  fi
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
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
expect_code() { [ "$2" = "$3" ] && record "$1" 1 || record "$1" 0 "status=$3 want=$2"; }

wait_http() {
  local url="$1" want="$2" deadline=$(( $(date +%s) + ${3:-120} )) code
  while [ "$(date +%s)" -lt "$deadline" ]; do
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$url" 2>/dev/null || echo 000)"
    [ "$code" = "$want" ] && return 0
    sleep 3
  done
  echo "ERROR: 等待 $url 返回 $want 超时（last=${code}）" >&2
  return 1
}

psqlq() { docker exec -i jiuzhang-stage5-postgres psql -U "$PG_USER" -d "$PG_DB" -At -v ON_ERROR_STOP=1 -c "$1" 2>/dev/null; }

echo "============================================================"
echo "P0-04 受限例外与最终处置 真实网关冒烟  api=$API_URL  gateway=$GATEWAY_URL"
echo "============================================================"

echo "[build] 从当前工作树构建 api/gateway/testorigin 镜像 ..."
"${COMPOSE[@]}" build api gateway testorigin

mkdir -p runtime/license

echo "[up] 启动 postgres/valkey/testorigin/gateway/api ..."
"${COMPOSE[@]}" up -d api gateway

wait_http "$API_URL/api/v1/health" 200 600 || {
  "${COMPOSE[@]}" logs --tail=120 api >&2 || true
  exit 1
}
record "api 健康检查通过" 1

wait_gateway_app() {
  local deadline=$(( $(date +%s) + ${1:-90} )) code
  while [ "$(date +%s)" -lt "$deadline" ]; do
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -H "Host: $HOST_HEADER" "$GATEWAY_URL/echo?ping=1" 2>/dev/null || true)"
    [ -n "$code" ] && [ "$code" != "000" ] && { echo "[gw] 网关已应答（Host=${HOST_HEADER} status=${code}）"; return 0; }
    sleep 2
  done
  echo "ERROR: 发布后网关未应答（Host=${HOST_HEADER}，last=${code:-none}）" >&2
  return 1
}

# ---- 登录/建用户/建应用/发布 复用阶段5公共函数 ----
export API_URL GATEWAY_URL
export HOST_HEADER="exc-smoke.local"
export VALKEY_PASSWORD="$VK_PWD" VALKEY_CONTAINER="jiuzhang-stage5-valkey"
export SYS_USER="jiuzhang_admin" SYS_PWD="$ADMIN_PWD" SYS_NEW_PWD="$ADMIN_NEW_PWD"
export SEC_USER="exc_smoke_sec" SEC_PWD="$SEC_PWD_CI"
export APP_CODE="excsmoke"
# shellcheck source=../waf/scripts/stage5-setup.sh
source test/waf/scripts/stage5-setup.sh

SYS_CSRF="$(s5_ensure_sysadmin)" || { echo "ERROR: sysadmin 登录失败" >&2; exit 1; }
record "系统管理员登录（含强制改密）" 1

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
record "安全管理员就绪" 1

# ---- 建应用（protection_mode=PROTECT：WAF 真实阻断为前提）----
APP_ID="$(curl -s -b "/tmp/s5-$SEC_USER.txt" -X POST "$API_URL/api/v1/applications" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" \
  -d "{\"code\":\"$APP_CODE\",\"name\":\"受限例外冒烟应用\",\"description\":\"P0-04 真实网关集成验证\",\"business_owner\":\"test\",\"technical_owner\":\"test\",\"protection_mode\":\"PROTECT\"}" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['id'])" 2>/dev/null)"
[ -n "$APP_ID" ] && record "创建 PROTECT 应用" 1 || { record "创建 PROTECT 应用" 0 "app_id 为空"; echo ABORT; exit 1; }
curl -s -b "/tmp/s5-$SEC_USER.txt" -X POST "$API_URL/api/v1/applications/$APP_ID/domains" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" \
  -d "{\"hostname\":\"$HOST_HEADER\",\"is_primary\":true,\"http_enabled\":true,\"https_enabled\":false,\"http_port\":8080,\"redirect_http_to_https\":false}" > /dev/null
curl -s -b "/tmp/s5-$SEC_USER.txt" -X POST "$API_URL/api/v1/applications/$APP_ID/upstreams" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" \
  -d '{"name":"testorigin","scheme":"http","host":"testorigin","port":8081,"weight":1,"priority":1,"health_check_enabled":false,"health_check_path":"/health","health_check_method":"GET","health_check_interval_seconds":10,"health_check_timeout_seconds":3,"expected_status_codes":"200","connect_timeout_ms":3000,"response_header_timeout_ms":10000,"tls_server_name":"","tls_verify":false}' > /dev/null
curl -s -b "/tmp/s5-$SEC_USER.txt" -X POST "$API_URL/api/v1/applications/$APP_ID/enable" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" > /dev/null
echo "[setup] app=$APP_ID host=$HOST_HEADER"

docker exec -i jiuzhang-stage5-postgres psql -U "$PG_USER" -d "$PG_DB" -v ON_ERROR_STOP=1 >/dev/null <<SQL
INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, description)
VALUES ('gateway_runtime','identity_salt','"$IDENTITY_SALT"','string','exc-smoke：身份指纹盐（随机，仅本轮栈）')
ON CONFLICT (setting_group, setting_key) DO UPDATE
SET setting_value = EXCLUDED.setting_value, updated_at = now(), version = system_settings.version + 1;
SQL
record "身份指纹盐（identity_salt）播种" 1

sec_api() { # <method> <path> [bodyfile] —— 打印响应体，状态码写入 $WORK_DIR/last_code
  local m="$1" p="$2" bf="${3:-}"
  if [ -n "$bf" ]; then
    curl -s -w $'\n%{http_code}' -b "/tmp/s5-$SEC_USER.txt" -X "$m" "$API_URL$p" \
      -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" --data-binary "@$bf" > "$WORK_DIR/last_resp"
  else
    curl -s -w $'\n%{http_code}' -b "/tmp/s5-$SEC_USER.txt" -X "$m" "$API_URL$p" \
      -H "X-CSRF-Token: $SEC_CSRF" > "$WORK_DIR/last_resp"
  fi
  tail -n1 "$WORK_DIR/last_resp" > "$WORK_DIR/last_code"
  sed '$d' "$WORK_DIR/last_resp"
}

# 例外创建载荷由 python heredoc 生成（防注入）

# 已验证攻击载荷（与 jwt-trust-smoke 同 payload，基线已证 403）
SQLI="1%20UNION%20SELECT%20username,password%20FROM%20users--"

# ==================== 阶段A：基线（无例外） ====================
PUB="$(s5_publish "$SEC_CSRF")"
[ "$PUB" = "PUBLISH_OK" ] && record "基线配置发布成功" 1 \
  || { record "基线配置发布成功" 0 "$PUB"; echo ABORT; exit 1; }
wait_gateway_app 90 || { record "基线发布后网关可达" 0 "超时"; echo ABORT; exit 1; }
record "基线发布后网关可达" 1

code="$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $HOST_HEADER" -X POST "$GATEWAY_URL/echo?comment=$SQLI")"
expect_code "基线：无例外 comment 字段 SQLi → 403（对照组）" 403 "$code"

# ==================== 阶段B：WAF 受限例外（目标级摘除） ====================
NOW="$(date +%s)"
python3 - "$WORK_DIR/exc1.json" "$APP_ID" "$HOST_HEADER" "$NOW" <<'PY'
import json, sys, datetime
out, app_id, host, now = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
fmt = lambda t: datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
print(json.dumps({
    "name": "exc1-comment-sqli",
    "description": "冒烟：SQLi 规则组对 ARGS:comment 目标级摘除",
    "scope_type": "APPLICATION", "application_id": app_id,
    "domain": host, "uri_exact": "/echo", "methods": ["POST"],
    # 该 payload 实测命中 CRS 942100/942190/942270/942360 + contrib 1001209
    # （后者在 CRS 之后求值，只摘 CRS 四条时残余 critical 单独达阈，
    #  见 gateway/corazasemantics/payload_coverage_test.go 不动点实测）
    "rule_ids": [942100, 942190, 942270, 942360, 1001209], "param_names": ["comment"],
    "exception_action": "REMOVE_VAR_DETECTION",
    "is_temporary": True,
    "effective_from": fmt(now - 120), "effective_until": fmt(now + 1800),
    "reason": "P0-04 冒烟",
}), file=open(out, "w"))
PY

resp="$(sec_api POST /api/v1/exceptions "$WORK_DIR/exc1.json")"
EXC1_ID="$(echo "$resp" | python3 -c "import json,sys; d=json.load(sys.stdin); e=d['data'].get('exception') or d['data']; print(e['id'])" 2>/dev/null)"
EXC1_VER="$(echo "$resp" | python3 -c "import json,sys; d=json.load(sys.stdin); e=d['data'].get('exception') or d['data']; print(e.get('version',''))" 2>/dev/null)"
EXC1_STATUS="$(echo "$resp" | python3 -c "import json,sys; d=json.load(sys.stdin); e=d['data'].get('exception') or d['data']; print(e.get('status',''))" 2>/dev/null)"
if [ -n "$EXC1_ID" ] && [ "$EXC1_STATUS" = "DRAFT" ]; then
  record "创建 WAF 例外草稿（DRAFT）" 1
else
  record "创建 WAF 例外草稿（DRAFT）" 0 "id=$EXC1_ID status=$EXC1_STATUS resp=$(echo "$resp" | head -c 300)"
fi

# 预览（EXC-12 预览契约：指纹 + 规则引用 + 保护模块清单）
printf '{"expected_version": %s}' "${EXC1_VER:-1}" > "$WORK_DIR/preview.json"
PREV="$(sec_api POST "/api/v1/exceptions/$EXC1_ID/preview" "$WORK_DIR/preview.json")"
PREV_OK="$(echo "$PREV" | python3 -c "
import json,sys
d=json.load(sys.stdin)['data']
fp=d.get('compiled_fingerprint') or ''
refs=[r.get('rule_id') for r in (d.get('resolved_rule_refs') or [])]
mods=d.get('protected_modules_unchanged') or []
ok=(d.get('validation_status')=='VALID' and len(fp)==64 and 942100 in refs
    and 'ACCESS_CONTROL' in mods and 'CC' in mods and d.get('estimated_match_count') is None)
print('OK' if ok else 'BAD:%s' % json.dumps(d, ensure_ascii=False)[:300])" 2>/dev/null || echo 'BAD:解析失败')"
[ "$PREV_OK" = "OK" ] && record "预览：VALID + 指纹 + 942100 引用 + 保护模块清单 + 不可估量为 null" 1 \
  || record "预览：VALID + 指纹 + 942100 引用 + 保护模块清单 + 不可估量为 null" 0 "$PREV_OK"

expect_code "启用 WAF 例外（门禁通过）" 200 \
  "$(sec_api POST "/api/v1/exceptions/$EXC1_ID/enable" >/dev/null; cat "$WORK_DIR/last_code")"

PUB="$(s5_publish "$SEC_CSRF")"
[ "$PUB" = "PUBLISH_OK" ] && record "例外配置发布成功" 1 \
  || { record "例外配置发布成功" 0 "$PUB"; echo ABORT; exit 1; }
sleep 3

# A1：例外字段（comment）攻击 → 放行到源站
resp="$(curl -s -w $'\n%{http_code}' -H "Host: $HOST_HEADER" -X POST "$GATEWAY_URL/echo?comment=$SQLI&name=ok")"
code="$(echo "$resp" | tail -n1)"
mark="$(echo "$resp" | sed '$d' | python3 -c 'import json,sys; print(json.load(sys.stdin).get("upstream_mark",""))' 2>/dev/null || echo '')"
if [ "$code" = "200" ] && [ "$mark" = "REACHED_ORIGIN" ]; then
  record "EXC-01 例外字段（comment）SQLi → 到达源站 200" 1
else
  record "EXC-01 例外字段（comment）SQLi → 到达源站 200" 0 "status=$code mark=$mark"
fi

# A2：目标外字段（name）同攻击 → 仍 403
code="$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $HOST_HEADER" -X POST "$GATEWAY_URL/echo?comment=ok&name=$SQLI")"
expect_code "EXC-02 目标外字段（name）SQLi → 403" 403 "$code"

# A3：范围外路径 → 403
code="$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $HOST_HEADER" -X POST "$GATEWAY_URL/echo-other?comment=$SQLI")"
expect_code "EXC-08 范围外路径 SQLi → 403" 403 "$code"

# A4：范围外方法（GET）→ 403
code="$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $HOST_HEADER" "$GATEWAY_URL/echo?comment=$SQLI")"
expect_code "EXC-08 范围外方法（GET）SQLi → 403" 403 "$code"

# ==================== 阶段C：时间窗 / 伪造 XFF / API OBSERVE_RULE ====================
# exc2/exc3 与 exc1 路径隔离（marker 链只含 host+path+method，同路径会互相命中）；
# /echo-future、/echo-xff 源站不存在——例外若错误生效请求漏到 origin 得 404 而非 403，
# 断言 403 依然能检出错误。
python3 - "$WORK_DIR" "$APP_ID" "$HOST_HEADER" "$NOW" <<'PY'
import json, sys, datetime
wd, app_id, host, now = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
fmt = lambda t: datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
base = {"scope_type": "APPLICATION", "application_id": app_id, "domain": host,
        "methods": ["POST"], "rule_ids": [942100, 942190, 942270, 942360, 1001209],
        "exception_action": "REMOVE_VAR_DETECTION", "is_temporary": True,
        "reason": "P0-04 冒烟"}
e2 = dict(base, name="exc2-future-window", uri_exact="/echo-future", param_names=["futureq"],
          effective_from=fmt(now + 3600), effective_until=fmt(now + 7200))
e3 = dict(base, name="exc3-xff-scope", uri_exact="/echo-xff", param_names=["xffq"], source_ips=["203.0.113.9"],
          effective_from=fmt(now - 120), effective_until=fmt(now + 1800))
e4 = {"name": "exc4-api-dup-query", "description": "冒烟：API 引擎豁免重复 query 参数 finding",
      "scope_type": "APPLICATION", "application_id": app_id, "domain": host,
      "uri_exact": "/api/json", "methods": ["POST"], "target_engine": "API",
      "api_rule_refs": [{"detector_id": "api_parser", "rule_id": "parser.duplicate_query_param"}],
      "exception_action": "OBSERVE_RULE", "reason": "P0-04 冒烟"}
for name, obj in [("exc2", e2), ("exc3", e3), ("exc4", e4)]:
    with open(f"{wd}/{name}.json", "w") as f:
        json.dump(obj, f)
PY

EXC4_ID=""
for n in exc2 exc3 exc4; do
  resp="$(sec_api POST /api/v1/exceptions "$WORK_DIR/$n.json")"
  id="$(echo "$resp" | python3 -c "import json,sys; d=json.load(sys.stdin); e=d['data'].get('exception') or d['data']; print(e.get('id',''))" 2>/dev/null)"
  [ "$n" = "exc4" ] && EXC4_ID="$id"
  if [ -z "$id" ]; then record "创建 $n 草稿" 0 "$(echo "$resp" | head -c 200)"; continue; fi
  code="$(sec_api POST "/api/v1/exceptions/$id/enable" >/dev/null; cat "$WORK_DIR/last_code")"
  [ "$code" = "200" ] && record "创建并启用 $n" 1 || record "创建并启用 $n" 0 "enable status=$code $(sec_api GET "/api/v1/exceptions/$id" | head -c 200)"
done

PUB="$(s5_publish "$SEC_CSRF")"
[ "$PUB" = "PUBLISH_OK" ] && record "时间窗/XFF/API 例外发布成功" 1 \
  || { record "时间窗/XFF/API 例外发布成功" 0 "$PUB"; echo ABORT; exit 1; }
sleep 3

# A5：未来生效例外（运行时 TIME_EPOCH 未到期）→ 仍 403
code="$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $HOST_HEADER" -X POST "$GATEWAY_URL/echo-future?futureq=$SQLI")"
expect_code "EXC-09 未来生效例外当前不生效 → 403" 403 "$code"

# A6：source_ips 限定例外 + 伪造 XFF（直连无可信代理，XFF 不生效）→ 403
code="$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $HOST_HEADER" -H 'X-Forwarded-For: 203.0.113.9' -X POST "$GATEWAY_URL/echo-xff?xffq=$SQLI")"
expect_code "EXC-08 伪造 XFF 不命中 source_ips 例外 → 403" 403 "$code"

# A7：API OBSERVE_RULE 范围：重复 query 参数（范围内 POST /api/json 与对照 /api/json2 各一次）
# 素材带 JSON CT/Accept/body 使统一管线分类 is_api=true（classifier 0.35+0.15+0.25+0.15+0.1），
# 否则非 API 流量不落 api_runtime_events final_decision（见头部注释）。
code="$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $HOST_HEADER" -H 'Content-Type: application/json' -H 'Accept: application/json' --data '{"smoke":"p0","case":"dup-in"}' -X POST "$GATEWAY_URL/api/json?dup=1&dup=2")"
expect_code "API 例外范围内重复参数请求放行（200）" 200 "$code"
code="$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $HOST_HEADER" -H 'Content-Type: application/json' -H 'Accept: application/json' --data '{"smoke":"p0","case":"dup-out"}' -X POST "$GATEWAY_URL/api/json2?dup=1&dup=2")"
expect_code "API 例外范围外重复参数请求（对照，源站 404）" 404 "$code"

# A8：DEC-05/E4 素材——API 分类路径攻击（attack 参数无例外覆盖）→ API 管线 ALLOW + WAF 403
code="$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $HOST_HEADER" -H 'Content-Type: application/json' -H 'Accept: application/json' --data '{"smoke":"p0","case":"atk"}' -X POST "$GATEWAY_URL/api/json?attack=$SQLI")"
expect_code "DEC-05 素材：API 路径 SQLi → WAF 403" 403 "$code"

# ==================== 阶段D：引擎审计与事件断言 ====================
# EXC-13 引擎侧：Coraza 审计日志含 exc:<uuid> 标记（例外命中可审计）
AUDIT_OK=""
for _ in $(seq 1 15); do
  AUDIT_OK="$(docker exec jiuzhang-stage5-gateway sh -c "grep -l 'exc:$EXC1_ID' /var/log/caddy/coraza-audit*.log 2>/dev/null" | head -n1 || true)"
  [ -n "$AUDIT_OK" ] && break
  sleep 2
done
[ -n "$AUDIT_OK" ] && record "EXC-13 引擎侧：Coraza 审计日志含 exc:<uuid> 命中标记" 1 \
  || record "EXC-13 引擎侧：Coraza 审计日志含 exc:<uuid> 命中标记" 0 "审计日志未检出 exc:$EXC1_ID"

# 事件轮询助手：psql 查询直至非空（结果经 stdout 返回，进度走 stderr 防混入捕获）
poll_sql() { # <描述> <sql>
  local desc="$1" sql="$2" out=""
  for _ in $(seq 1 20); do
    out="$(psqlq "$sql" | head -n1)"
    [ -n "$out" ] && { echo "  [event] $desc => $out" >&2; printf '%s' "$out"; return 0; }
    sleep 2
  done
  echo "  [event] $desc => <empty>" >&2
  return 1
}

# E1：DEC-03/04 + EXC-13 管理侧——被拦请求（name 字段）的 WAF 事件 final_decision
# （request_path='/echo' + response_status=403 + request_uri 含 name= 唯一锁定 A2；
#   A5/A6 已隔离到 /echo-future、/echo-xff，不会混入）
# 注意：psql 里布尔值被 || 拼接进文本时渲染为 true/false（不是 t/f）。
E1_SQL="SELECT coalesce(final_decision->>'completion_status','') || '|' || coalesce(final_decision->>'security_action','') || '|' || coalesce(final_decision->>'executor_module','') || '|' || coalesce(final_decision->>'response_source','') || '|' || coalesce(final_decision->>'http_status','') || '|' || ((final_decision->'rule_refs')::text LIKE '%942100%') || '|' || ((final_decision->'matched_exceptions')::text LIKE '%$EXC1_ID%') FROM security_events WHERE request_path='/echo' AND response_status=403 AND request_uri LIKE '%name=%' ORDER BY occurred_at DESC LIMIT 1"
E1_OUT="$(poll_sql "security_events final_decision（WAF 拦截）" "$E1_SQL" || true)"
if [ "$E1_OUT" = "ABORTED|BLOCK|WAF|GATEWAY|403|true|true" ]; then
  record "DEC-03/04+EXC-13 WAF 事件 final_decision 全字段（含 942100 与例外 uuid）" 1
else
  record "DEC-03/04+EXC-13 WAF 事件 final_decision 全字段（含 942100 与例外 uuid）" 0 "actual=$E1_OUT"
fi

# E2+E5 同行断言：A7 范围内 dup 请求（POST /api/json）的 api_runtime_events 行
# 同时承载 DEC-02 源站归因（COMPLETED/NONE/ORIGIN/200）与 EXC-11/13 豁免打标
E25_SQL="SELECT coalesce(final_decision->>'completion_status','') || '|' || coalesce(final_decision->>'security_action','') || '|' || coalesce(final_decision->>'response_source','') || '|' || coalesce(final_decision->>'http_status','') || '|' || coalesce((SELECT bool_or((m->>'excepted')::boolean AND m->>'exception_id'='$EXC4_ID') FROM jsonb_array_elements(CASE WHEN jsonb_typeof(details_json)='array' THEN details_json ELSE '[]'::jsonb END) m WHERE m->>'rule_id'='parser.duplicate_query_param'), false) || '|' || ((final_decision->'matched_exceptions')::text LIKE '%$EXC4_ID%') FROM api_runtime_events WHERE raw_path='/api/json' AND method='POST' AND details_json::text LIKE '%parser.duplicate_query_param%' ORDER BY occurred_at DESC LIMIT 1"
E25_OUT="$(poll_sql "api_runtime_events dup 行（源站归因 + 豁免打标）" "$E25_SQL" || true)"
if [ "$(echo "$E25_OUT" | cut -d'|' -f1-4)" = "COMPLETED|NONE|ORIGIN|200" ]; then
  record "DEC-02 源站 200 归因（COMPLETED/NONE/ORIGIN/200）" 1
else
  record "DEC-02 源站 200 归因（COMPLETED/NONE/ORIGIN/200）" 0 "actual=$E25_OUT"
fi
if [ "$(echo "$E25_OUT" | cut -d'|' -f5-6)" = "true|true" ]; then
  record "EXC-11/13 API OBSERVE_RULE 豁免打标 + matched_exceptions（范围内）" 1
else
  record "EXC-11/13 API OBSERVE_RULE 豁免打标 + matched_exceptions（范围内）" 0 "actual=$E25_OUT"
fi

# E3：DEC-05 同请求对证——API 决策结果不被改写，最终如实归 WAF/BLOCK。
# final_action=BLOCK 是 apicoraza.go attributeWAFIntercept 的既定契约：统一管线未判阻断、
# 下游 Coraza 真实中断时按实记 BLOCK（事实记录而非引擎决策）；引擎自身动作留在
# final_decision.steps（module=API result=OBSERVED），即任务书 DEC-01「API 结果不变」语义。
E3_SQL="SELECT final_action || '|' || coalesce(final_decision->>'executor_module','') || '|' || coalesce(final_decision->>'security_action','') || '|' || coalesce(final_decision->>'http_status','') || '|' || coalesce((SELECT s->>'result' FROM jsonb_array_elements(final_decision->'steps') s WHERE s->>'module'='API' LIMIT 1),'') FROM api_runtime_events WHERE raw_path='/api/json' AND final_decision->>'executor_module'='WAF' ORDER BY occurred_at DESC LIMIT 1"
E3_OUT="$(poll_sql "api_runtime_events（API 决策不改写 + WAF BLOCK 同请求）" "$E3_SQL" || true)"
if [ "$E3_OUT" = "BLOCK|WAF|BLOCK|403|OBSERVED" ]; then
  record "DEC-05 API 决策不改写，final_decision 归 WAF/BLOCK" 1
else
  record "DEC-05 API 决策不改写，final_decision 归 WAF/BLOCK" 0 "actual=$E3_OUT"
fi

# E4：DEC-01 跨侧 request_id 关联（A8：security_events ⋈ api_runtime_events）
E4_SQL="SELECT count(*) FROM security_events se JOIN api_runtime_events ar ON ar.request_id=se.request_id WHERE se.request_path='/api/json' AND se.response_status=403 AND se.final_decision IS NOT NULL AND ar.final_decision IS NOT NULL"
E4_OUT="$(poll_sql "跨侧 request_id 关联计数" "$E4_SQL" || true)"
if [ "${E4_OUT:-0}" -ge 1 ] 2>/dev/null; then
  record "DEC-01 跨侧 request_id 关联（security_events ⋈ api_runtime_events）" 1
else
  record "DEC-01 跨侧 request_id 关联（security_events ⋈ api_runtime_events）" 0 "count=${E4_OUT:-empty}"
fi

# E6：范围外对照——同 finding 不打标（A7 对照 POST /api/json2）
E6_SQL="SELECT coalesce((SELECT bool_or((m->>'excepted')::boolean) FROM jsonb_array_elements(CASE WHEN jsonb_typeof(details_json)='array' THEN details_json ELSE '[]'::jsonb END) m WHERE m->>'rule_id'='parser.duplicate_query_param'), false) FROM api_runtime_events WHERE raw_path='/api/json2' ORDER BY occurred_at DESC LIMIT 1"
E6_OUT="$(poll_sql "API 例外范围外 finding 不打标" "$E6_SQL" || true)"
if [ "$E6_OUT" = "f" ]; then
  record "EXC-08 API 例外范围外 finding 不打标（对照）" 1
else
  record "EXC-08 API 例外范围外 finding 不打标（对照）" 0 "actual=$E6_OUT"
fi

echo "============================================================"
echo "P0-04 受限例外与最终处置 真实网关冒烟汇总: 总用例 $TOTAL 通过 $PASS 失败 $FAIL"
if [ "$FAIL" -gt 0 ]; then
  for c in "${FAILED[@]}"; do echo "  - $c"; done
fi
echo "============================================================"
SCRIPT_DONE=1
[ "$FAIL" -eq 0 ]
