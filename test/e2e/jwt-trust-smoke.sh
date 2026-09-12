#!/usr/bin/env bash
# P0-03 业务 JWT 信任链 真实 Caddy 网关集成冒烟（WDSP）：
# 任务书 docs/tasks/wdsp-p0/P0-03_JWT_TRUST_CHAIN.md §10 要求 JWT-01～12 需
# 「单元与真实网关组合验证」；本脚本补齐真实网关侧组合验证（S3 阶段验收硬性缺口）。
#
# 覆盖断言（括号内为任务书用例映射）：
#   OBSERVE 发布生效：无 Token / 伪造签名 Token 均放行（JWT-10/JWT-02 观测侧）
#   PROTECT 发布生效：缺必需 Bearer → 401 + WWW-Authenticate Bearer challenge（JWT-05/JWT-10）
#                     伪造签名 → 401（JWT-02）；合法 RS256 Token → 到达源站 200（JWT-01）
#   JWT-12 真实组合：VERIFIED Token + SQLi → Coraza 403（JWT 不产生全局放行）
#   事件：access_control_events JWT_AUTH_FAILED ≥2（details 含 reason_code/policy_version/
#         keyset_version）；api_runtime_events 含 jwt_verification.status=VERIFIED 摘要
#
# 栈：deployment/docker-compose.stage5.yml + docker-compose.wdsp.yml（EDITION=wdsp 同口径），
# 仅 postgres/valkey/api/gateway/testorigin。镜像从当前工作树现建（JWT 代码为新代码）。
# 口令/授权签名密钥/JWT 测试密钥每轮随机生成于 mktemp 目录（0600），脚本退出即清理，
# 不落仓库；完整 Token 只打印首尾各 12 字符。
#
# 用法：bash test/e2e/jwt-trust-smoke.sh
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
ENV_FILE="$WORK_DIR/jwt-smoke.env"
PG_USER="jiuzhang"
PG_DB="jiuzhang_waf"
PG_PWD="$(openssl rand -hex 16)"
VK_PWD="$(openssl rand -hex 16)"
ADMIN_PWD="Ci$(openssl rand -hex 8)1!"
ADMIN_NEW_PWD="Ci$(openssl rand -hex 8)2!"
SEC_PWD_CI="CiSec@$(openssl rand -hex 6)1"
MASTER_KEY="$(openssl rand -hex 32)"
IDENTITY_SALT="$(openssl rand -hex 32)"   # 身份指纹盐：随机，仅本轮栈，经 psql 播种（管理面 PUT 仅支持既有行）
LIC_KEY_ID="jwt-smoke-key"

# ---- CI 临时 Ed25519 授权（与 ci-edition-smoke.sh 同口径，解锁授权门控）----
openssl genpkey -algorithm ed25519 -out "$WORK_DIR/lic-key.pem" >/dev/null 2>&1
chmod 600 "$WORK_DIR/lic-key.pem"
LIC_PUB_HEX="$(openssl pkey -in "$WORK_DIR/lic-key.pem" -pubout -outform DER 2>/dev/null \
  | tail -c 32 | python3 -c 'import sys; print(sys.stdin.buffer.read().hex())')"
python3 - "$WORK_DIR" "$LIC_KEY_ID" <<'PY'
import json, sys, datetime
work_dir, key_id = sys.argv[1], sys.argv[2]
payload = {
    "license_id": "LIC-JWT-SMOKE-0001",
    "license_type": "FORMAL",
    "product": "wdsp",
    "customer": "JWT Smoke",
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

# ---- 本轮 compose env（mktemp 内，不污染仓库 .env）----
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

# 授权临时公钥只供显式 wdsp_testkeys 测试产物使用；正式镜像不读取该变量。
COMPOSE=(docker compose --env-file "$ENV_FILE"
  -f deployment/docker-compose.stage5.yml -f deployment/docker-compose.wdsp.yml
  -f deployment/docker-compose.test-license.yml)

# ---- 启动前检查：端口占用 + 既有 stage5 容器（不动 p0s3-* 等其他栈）----
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
  echo "ERROR: 检测到 stage5 编排已有容器在运行；本冒烟会互相干扰，请先停止" >&2
  rm -rf "$WORK_DIR"; exit 1
fi

cleanup() {
  local rc=$?
  # macOS bash 3.2 下 set -u 未绑定变量致死时 EXIT trap 看到的 $? 可能为 0——
  # 用显式完成标记兜底：未走到脚本末尾（汇总行）一律按失败处理，杜绝假绿。
  if [ "$rc" -eq 0 ] && [ "${SCRIPT_DONE:-0}" != "1" ]; then rc=1; fi
  if [ "$rc" -ne 0 ]; then
    DUMP_DIR="$(mktemp -d /tmp/jwt-smoke-dump.XXXXXX)"
    {
      echo "==== compose ps ===="; "${COMPOSE[@]}" ps 2>&1
      echo; echo "==== api 日志尾部 ===="; "${COMPOSE[@]}" logs --tail=200 api 2>&1
      echo; echo "==== gateway 日志尾部 ===="; "${COMPOSE[@]}" logs --tail=200 gateway 2>&1
      echo; echo "==== gateway caddy.log 尾部（运行日志重定向到文件） ===="
      docker exec jiuzhang-stage5-gateway sh -c 'tail -n 80 /var/log/caddy/caddy.log' 2>&1 || true
      echo; echo "==== gateway guard-events 尾部 ===="
      docker exec jiuzhang-stage5-gateway sh -c 'tail -n 60 /var/log/caddy/guard-events.log' 2>&1 || true
      echo; echo "==== gateway api-runtime-events 尾部 ===="
      docker exec jiuzhang-stage5-gateway sh -c 'tail -n 40 /var/log/caddy/api-runtime-events.log' 2>&1 || true
    } > "$DUMP_DIR/stack-dump.log" 2>&1 || true
    echo "失败诊断日志（不含密钥/Token）：$DUMP_DIR/stack-dump.log" >&2
  fi
  # 本栈卷为专用命名卷（随机口令/全新 DB），随 down -v 一并清理，保证下次可重跑
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK_DIR"   # 密钥/口令/Token 材料随退出清理
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

# Token 脱敏打印（仅首尾各 12 字符）
mask_token() { local t="$1"; echo "${t:0:12}...${t: -12}"; }

b64url() { openssl base64 -e -A | tr '+/' '-_' | tr -d '='; }

# 现场签发 RS256 Token（openssl dgst 签名；不引入 PyJWT 等依赖）
# mk_token <key.pem> <iss> <aud> <sub> <kid>
mk_token() {
  local key="$1" iss="$2" aud="$3" sub="$4" kid="$5"
  local h p sig now exp
  now="$(date +%s)"; exp=$((now+600))
  h="$(printf '%s' "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"$kid\"}" | b64url)"
  p="$(printf '%s' "{\"iss\":\"$iss\",\"aud\":\"$aud\",\"sub\":\"$sub\",\"iat\":$now,\"exp\":$exp}" | b64url)"
  sig="$(printf '%s' "$h.$p" | openssl dgst -sha256 -sign "$key" | b64url)"
  printf '%s' "$h.$p.$sig"
}

echo "============================================================"
echo "P0-03 JWT 信任链真实网关冒烟  api=$API_URL  gateway=$GATEWAY_URL"
echo "============================================================"

# ---- 镜像：JWT 代码为新代码，api/gateway 必须从当前工作树重建 ----
echo "[build] 从当前工作树构建 api/gateway/testorigin 镜像 ..."
"${COMPOSE[@]}" build api gateway testorigin

# compose 只读挂载源（仓库 runtime/license 被 .gitignore 排除）
mkdir -p runtime/license

echo "[up] 启动 postgres/valkey/testorigin/gateway/api ..."
"${COMPOSE[@]}" up -d api gateway

wait_http "$API_URL/api/v1/health" 200 600 || {
  echo "==== api 容器状态与日志尾部（健康等待超时即时诊断）====" >&2
  "${COMPOSE[@]}" ps api >&2 || true
  "${COMPOSE[@]}" logs --tail=120 api >&2 || true
  exit 1
}
record "api 健康检查通过" 1
# 注意：新栈无有效授权时 api 启动即触发一次「透传发布」（apps.http.servers 为空，
# 网关 :8080 不再监听，/health 消失）——gateway 可达性只能在首个应用发布成功后探测，
# 不能照搬 ci-edition-smoke 的 GATEWAY_URL/health 前置等待。
# wait_gateway_app：发布成功后轮询直至网关对本应用 Host 返回任意 HTTP 状态（非 000）。
wait_gateway_app() {
  local deadline=$(( $(date +%s) + ${1:-90} )) code
  while [ "$(date +%s)" -lt "$deadline" ]; do
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -H "Host: $HOST_HEADER" "$GATEWAY_URL/api/v1/orders/1" 2>/dev/null || true)"
    [ -n "$code" ] && [ "$code" != "000" ] && { echo "[gw] 网关已应答（Host=${HOST_HEADER} status=${code}）"; return 0; }
    sleep 2
  done
  echo "ERROR: 发布后网关未应答（Host=${HOST_HEADER}，last=${code:-none}）" >&2
  return 1
}

# ---- 登录/建用户/建应用/发布 复用阶段5公共函数 ----
export API_URL GATEWAY_URL
export HOST_HEADER="jwt-smoke.local"
export VALKEY_PASSWORD="$VK_PWD" VALKEY_CONTAINER="jiuzhang-stage5-valkey"
export SYS_USER="jiuzhang_admin" SYS_PWD="$ADMIN_PWD" SYS_NEW_PWD="$ADMIN_NEW_PWD"
export SEC_USER="jwt_smoke_sec" SEC_PWD="$SEC_PWD_CI"
export APP_CODE="jwtsmoke"
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

# ---- 建应用（protection_mode=PROTECT：WAF 真实阻断，JWT-12 组合断言前提；
#      与 ha-lab ha_ensure_app 同口径；JWT PROTECT 发布门禁只要求 API 管线模式，
#      应用 protection_mode 不进门禁判定）----
APP_ID="$(curl -s -b "/tmp/s5-$SEC_USER.txt" -X POST "$API_URL/api/v1/applications" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" \
  -d "{\"code\":\"$APP_CODE\",\"name\":\"JWT信任链冒烟应用\",\"description\":\"P0-03 真实网关集成验证\",\"business_owner\":\"test\",\"technical_owner\":\"test\",\"protection_mode\":\"PROTECT\"}" \
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

# ---- 身份指纹盐播种（gateway_runtime:identity_salt；PROTECT 发布门禁要求，
#      管理面 PUT 仅支持既有行（乐观锁），行播种走 psql，与 test/ha/ha-lab-verify.sh 同口径）----
docker exec -i jiuzhang-stage5-postgres psql -U "$PG_USER" -d "$PG_DB" -v ON_ERROR_STOP=1 >/dev/null <<SQL
INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, description)
VALUES ('gateway_runtime','identity_salt','"$IDENTITY_SALT"','string','jwt-trust-smoke：身份指纹盐（随机，仅本轮栈）')
ON CONFLICT (setting_group, setting_key) DO UPDATE
SET setting_value = EXCLUDED.setting_value, updated_at = now(), version = system_settings.version + 1;
SQL
record "身份指纹盐（identity_salt）播种" 1

# ---- JWT 测试密钥：RSA-2048 真钥 k1 + 伪造者密钥 k2（mktemp 目录 0600，退出清理）----
KID="jwt-smoke-k1"
ISSUER="https://idp.jwt-smoke.local"
AUDIENCE="orders-api"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$WORK_DIR/jwt-k1.pem" >/dev/null 2>&1
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$WORK_DIR/jwt-k2-forger.pem" >/dev/null 2>&1
chmod 600 "$WORK_DIR/jwt-k1.pem" "$WORK_DIR/jwt-k2-forger.pem"
openssl rsa -in "$WORK_DIR/jwt-k1.pem" -pubout -out "$WORK_DIR/jwt-k1-pub.pem" >/dev/null 2>&1
MOD_HEX="$(openssl rsa -pubin -in "$WORK_DIR/jwt-k1-pub.pem" -noout -modulus 2>/dev/null | sed 's/^Modulus=//')"
EXP_DEC="$(openssl rsa -pubin -in "$WORK_DIR/jwt-k1-pub.pem" -noout -text 2>/dev/null \
  | grep -m1 'Exponent:' | sed -E 's/.*Exponent: ([0-9]+).*/\1/')"
[ -n "$MOD_HEX" ] && [ -n "$EXP_DEC" ] || { echo "ERROR: RSA 公钥参数提取失败" >&2; exit 1; }
python3 - "$MOD_HEX" "$EXP_DEC" "$KID" > "$WORK_DIR/jwks.json" <<'PY'
import sys, json, base64
mod_hex, e_dec, kid = sys.argv[1], int(sys.argv[2]), sys.argv[3]
n = bytes.fromhex(mod_hex).lstrip(b"\x00")
def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
e = e_dec.to_bytes((e_dec.bit_length() + 7) // 8, "big")
print(json.dumps({"keys": [{"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
                            "n": b64u(n), "e": b64u(e)}]}))
PY
record "RSA-2048 测试密钥生成并导出公钥 JWKS" 1

# 签发 Token（VALID=真钥签名；FORGED=伪造者密钥签名、同 kid，签名校验必失败）
VALID_TOKEN="$(mk_token "$WORK_DIR/jwt-k1.pem" "$ISSUER" "$AUDIENCE" "smoke-user-1" "$KID")"
FORGED_TOKEN="$(mk_token "$WORK_DIR/jwt-k2-forger.pem" "$ISSUER" "$AUDIENCE" "forged-user" "$KID")"
echo "[setup] valid_token=$(mask_token "$VALID_TOKEN")"
echo "[setup] forged_token=$(mask_token "$FORGED_TOKEN")"

# 策略请求体（selectors: path_prefix=/api token_required=true；issuer: 静态 JWKS）
mk_policy_body() { # <mode> <expected_version> <out>
  python3 - "$WORK_DIR/jwks.json" "$ISSUER" "$AUDIENCE" "$1" "$2" > "$3" <<'PY'
import json, sys
jwks = open(sys.argv[1]).read()
iss, aud, mode, ev = sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5])
print(json.dumps({
    "mode": mode,
    "expected_version": ev,
    "selectors": [{"methods": ["GET", "POST"], "path_prefix": "/api", "token_required": True}],
    "issuers": [{"issuer": iss, "audiences": [aud], "algorithms": ["RS256"],
                 "key_source": {"type": "STATIC_JWKS", "jwks": jwks},
                 "clock_skew_seconds": 30}],
    "reason": "jwt-trust-smoke: %s 草稿" % mode,
}))
PY
}

sec_put() { # <path> <bodyfile>
  curl -s -o /dev/null -w '%{http_code}' -b "/tmp/s5-$SEC_USER.txt" -X PUT "$API_URL$1" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" --data-binary "@$2"
}

# ==================== 阶段A：OBSERVE 草稿 → 发布 → 观测断言 ====================
mk_policy_body OBSERVE 0 "$WORK_DIR/policy-observe.json"
expect_code "保存 JWT 策略 OBSERVE 草稿" 200 \
  "$(sec_put "/api/v1/applications/$APP_ID/jwt-trust-policy" "$WORK_DIR/policy-observe.json")"

PUB="$(s5_publish "$SEC_CSRF")"
[ "$PUB" = "PUBLISH_OK" ] && record "OBSERVE 配置发布成功" 1 \
  || { record "OBSERVE 配置发布成功" 0 "$PUB"; echo ABORT; exit 1; }
wait_gateway_app 90 || { record "OBSERVE 发布生效后网关可达" 0 "超时"; echo ABORT; exit 1; }
record "OBSERVE 发布生效后网关可达" 1

# OBSERVE：无 Token 请求 in-scope 路径 → 仍放行（只记录不实断）
code="$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $HOST_HEADER" "$GATEWAY_URL/api/v1/orders/1")"
case "$code" in 401|403|429) record "OBSERVE 无 Token 仍放行（JWT-10）" 0 "status=$code" ;;
  *) record "OBSERVE 无 Token 仍放行（JWT-10）" 1 ;; esac
echo "  [observe] no-token status=$code"

# OBSERVE：伪造签名 Token → 仍放行（OBSERVE 不产生可信主体、不实断）
code="$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $HOST_HEADER" \
  -H "Authorization: Bearer $FORGED_TOKEN" "$GATEWAY_URL/api/v1/orders/1")"
case "$code" in 401|403|429) record "OBSERVE 伪造签名仍放行（JWT-02 观测侧）" 0 "status=$code" ;;
  *) record "OBSERVE 伪造签名仍放行（JWT-02 观测侧）" 1 ;; esac
echo "  [observe] forged status=$code"

# OBSERVE 事件：JWT_OBSERVED 应落 access_control_events（两次放行各一条）
OBS_EV=""
for _ in $(seq 1 20); do
  OBS_EV="$(s5_event_count JWT_OBSERVED)"
  [ "${OBS_EV:-0}" -ge 2 ] && break
  sleep 2
done
[ "${OBS_EV:-0}" -ge 2 ] && record "OBSERVE 产生 JWT_OBSERVED 事件（=${OBS_EV}）" 1 \
  || record "OBSERVE 产生 JWT_OBSERVED 事件" 0 "total=${OBS_EV:-查询失败}"

# ==================== 阶段B：管线 PROTECT → PROTECT 草稿 → 预检 → 发布 ====================
# 发布门禁（server/internal/guardconfig/jwt_trust.go loadJWTTrust）：JWT PROTECT 策略要求
# API 动态管线有效模式为 PROTECT（settings 表 api_protection:mode 覆盖，db>env>default），
# 且 identity_salt 已配置（上已播种）；门禁不满足发布会 fail-hard 拒绝。
expect_code "API 动态管线模式置为 PROTECT（发布门禁前提）" 200 \
  "$(curl -s -o /dev/null -w '%{http_code}' -b "/tmp/s5-$SEC_USER.txt" -X PUT "$API_URL/api/v1/api-security/policy" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" -d '{"mode":"PROTECT"}')"

DRAFT_VER="$(curl -s -b "/tmp/s5-$SEC_USER.txt" "$API_URL/api/v1/applications/$APP_ID/jwt-trust-policy" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['policy']['version'])" 2>/dev/null)"
[ -n "$DRAFT_VER" ] || { echo "ERROR: 读取 JWT 策略草稿版本失败" >&2; exit 1; }
mk_policy_body PROTECT "$DRAFT_VER" "$WORK_DIR/policy-protect.json"
expect_code "保存 JWT 策略 PROTECT 草稿（乐观锁 v${DRAFT_VER}）" 200 \
  "$(sec_put "/api/v1/applications/$APP_ID/jwt-trust-policy" "$WORK_DIR/policy-protect.json")"

# 预检：publishable 必须为 true 且 pipeline_gate 通过
PRE="$(curl -s -b "/tmp/s5-$SEC_USER.txt" -X POST "$API_URL/api/v1/applications/$APP_ID/jwt-trust-policy/preflight" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" -d '{}')"
PRE_OK="$(echo "$PRE" | python3 -c "
import json,sys
d=json.load(sys.stdin)['data']
gate=next((c['status'] for c in d.get('checks',[]) if c.get('name')=='pipeline_gate'),'MISSING')
print('OK' if d.get('publishable') is True and gate=='PASS' else 'BAD:publishable=%s,gate=%s'%(d.get('publishable'),gate))" 2>/dev/null || echo "BAD:解析失败")"
[ "$PRE_OK" = "OK" ] && record "PROTECT 预检 publishable=true 且 pipeline_gate=PASS" 1 \
  || record "PROTECT 预检 publishable=true 且 pipeline_gate=PASS" 0 "$PRE_OK"

PUB="$(s5_publish "$SEC_CSRF")"
[ "$PUB" = "PUBLISH_OK" ] && record "PROTECT 配置发布成功（门禁通过）" 1 \
  || { record "PROTECT 配置发布成功（门禁通过）" 0 "$PUB"; echo ABORT; exit 1; }
wait_gateway_app 60 || echo "WARN: PROTECT 发布后网关探测超时（后续断言将如实反映）" >&2

# ==================== 阶段C：PROTECT 真实网关断言 ====================
# C1：无 Token → 401 + 规范 Bearer challenge
resp_headers="$(curl -s -D - -o /dev/null -H "Host: $HOST_HEADER" "$GATEWAY_URL/api/v1/orders/1")"
code="$(printf '%s' "$resp_headers" | head -n1 | awk '{print $2}')"
expect_code "PROTECT 缺必需 Bearer → 401（JWT-10）" 401 "$code"
if printf '%s' "$resp_headers" | grep -qi '^WWW-Authenticate: *Bearer realm="jiuzhang-waf"'; then
  record "401 携带 WWW-Authenticate Bearer challenge" 1
else
  record "401 携带 WWW-Authenticate Bearer challenge" 0 \
    "header=$(printf '%s' "$resp_headers" | grep -i '^WWW-Authenticate:' || echo '<absent>')"
fi

# C2：伪造签名 Token → 401
code="$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $HOST_HEADER" \
  -H "Authorization: Bearer $FORGED_TOKEN" "$GATEWAY_URL/api/v1/orders/1")"
expect_code "PROTECT 伪造签名 Token → 401（JWT-02）" 401 "$code"

# C3：合法 Token（正确 iss/aud/exp/sub/kid）→ 到达源站（POST /api/json 为源站 200 回显路径）
resp="$(curl -s -w $'\n%{http_code}' -H "Host: $HOST_HEADER" -H 'Content-Type: application/json' \
  -H 'Accept: application/json' -H "Authorization: Bearer $VALID_TOKEN" \
  -X POST -d '{"order_id":1,"item":"widget"}' "$GATEWAY_URL/api/json")"
code="$(echo "$resp" | tail -n1)"
mark="$(echo "$resp" | sed '$d' | python3 -c 'import json,sys; print(json.load(sys.stdin).get("upstream_mark",""))' 2>/dev/null || echo '')"
if [ "$code" = "200" ] && [ "$mark" = "REACHED_ORIGIN" ]; then
  record "PROTECT 合法 Token VERIFIED → 到达源站 200（JWT-01）" 1
else
  record "PROTECT 合法 Token VERIFIED → 到达源站 200（JWT-01）" 0 "status=$code mark=$mark"
fi

# C4 / JWT-12 真实组合：VERIFIED Token + SQLi → Coraza 拦截 403（JWT 不产生全局放行）
code="$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $HOST_HEADER" \
  -H "Authorization: Bearer $VALID_TOKEN" \
  "$GATEWAY_URL/api/v1/orders?id=1%20UNION%20SELECT%20username,password%20FROM%20users--")"
expect_code "VERIFIED + SQLi → WAF 拦截 403（JWT-12）" 403 "$code"

# ==================== 阶段D：事件断言 ====================
# D1：access_control_events JWT_AUTH_FAILED ≥2（两次 401），details 含 reason_code/policy_version/keyset_version
EV_TOTAL=""
for _ in $(seq 1 20); do
  EV_TOTAL="$(s5_event_count JWT_AUTH_FAILED)"
  [ "${EV_TOTAL:-0}" -ge 2 ] && break
  sleep 2
done
[ "${EV_TOTAL:-0}" -ge 2 ] && record "JWT_AUTH_FAILED 事件计数 ≥2（=${EV_TOTAL}）" 1 \
  || record "JWT_AUTH_FAILED 事件计数 ≥2" 0 "total=${EV_TOTAL:-查询失败}"

EV_DETAIL_OK="$(curl -s -b "/tmp/s5-$SEC_USER.txt" \
  "$API_URL/api/v1/access-control-events?event_type=JWT_AUTH_FAILED&page_size=5" | python3 -c "
import json,sys
items=json.load(sys.stdin)['data'].get('items') or []
for it in items:
    j=(it.get('details') or {}).get('jwt_verification') or {}
    if j.get('reason_code') and j.get('policy_version') and j.get('keyset_version'):
        print('OK rc=%s pv=%s kv=%s' % (j['reason_code'], j['policy_version'], j['keyset_version'])); break
else:
    print('BAD items=%d' % len(items))" 2>/dev/null || echo 'BAD:解析失败')"
case "$EV_DETAIL_OK" in OK*)
  record "JWT_AUTH_FAILED 事件 details 含 reason_code/policy_version/keyset_version" 1
  echo "  [event] $EV_DETAIL_OK" ;;
*) record "JWT_AUTH_FAILED 事件 details 含 reason_code/policy_version/keyset_version" 0 "$EV_DETAIL_OK" ;; esac

# D2：api_runtime_events 落库 jwt_verification 摘要（合法 Token 的 POST /api/json）。
# 注：管理面 GET /api/v1/api-security/runtime/events 的 RuntimeEvent 结构未投影
# jwt_verification 列（无任何路由暴露该列，apiruntime.Store.List 仅供单测）——
# 按任务口径「接口形态不允许直接断言字段时至少断言摘要可查」，此处以 psql 只读
# 查询落库内容为准（与 identity_salt 播种同一测试夹具通道；管理面投影缺口如实记录）。
RT_OK=""
for _ in $(seq 1 20); do
  RT_OK="$(docker exec -i jiuzhang-stage5-postgres psql -U "$PG_USER" -d "$PG_DB" -At -v ON_ERROR_STOP=1 -c \
    "SELECT coalesce(jwt_verification->>'status','') || '|' || coalesce(jwt_verification->>'policy_version','') || '|' || coalesce(jwt_verification->>'keyset_version','') || '|' || coalesce(jwt_verification->>'verified_principal_id','') FROM api_runtime_events WHERE jwt_verification IS NOT NULL AND raw_path LIKE '/api/%' ORDER BY occurred_at DESC LIMIT 5" 2>/dev/null \
    | grep -E -m1 '^VERIFIED\|[^|]+\|[^|]+\|[^|]+$' || true)"
  [ -n "$RT_OK" ] && break
  sleep 2
done
if [ -n "$RT_OK" ]; then
  record "api_runtime_events 落库 jwt_verification.status=VERIFIED 摘要（库层可查）" 1
  echo "  [event] status|policy_version|keyset_version|verified_principal_id = $RT_OK"
else
  record "api_runtime_events 落库 jwt_verification.status=VERIFIED 摘要（库层可查）" 0 "未查到 VERIFIED 摘要"
fi

echo "============================================================"
echo "P0-03 JWT 信任链真实网关冒烟汇总: 总用例 $TOTAL 通过 $PASS 失败 $FAIL"
if [ "$FAIL" -gt 0 ]; then
  for c in "${FAILED[@]}"; do echo "  - $c"; done
fi
echo "============================================================"
SCRIPT_DONE=1
[ "$FAIL" -eq 0 ]
