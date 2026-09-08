#!/usr/bin/env bash
# P1-02 B4 Bot 挑战浏览器/自动化基准（BOT-004 / BOT-005 / BOT-021）真实网关驱动：
# 栈：deployment/docker-compose.stage5.yml + docker-compose.wdsp.yml（与 jwt-trust-smoke 同口径），
# 自建 HTTPS 应用（自签证书，仅本轮栈），Bot 策略 PROTECT（path_exact=/，
# difficulty=12 基准用值），经管理面真实配置发布生效。
#
# 三组分别如实报告（不混分母）：
#   http-script    非浏览器 HTTP 脚本组（curl）：不能执行 JS → 挑战即阻断；BOT-005 不适用请求
#                  （HEAD/POST/JSON）不返回 HTML 挑战、不重放业务写
#   browser        真实浏览器组（Playwright Chromium，BOT-004）：挑战 → 内嵌 JS 求解 →
#                  verify 204 → 最多一次自动刷新 → 源站成功（REACHED_ORIGIN）
#   automation-js  能执行 JS 的自动化浏览器组（BOT-021）：headless Chromium（navigator.webdriver=true）
#                  如实记录其可通过 PoW 挑战——挑战只增加自动化成本，不证明真人
#
# 词表：PASS / FAIL / BLOCKED / NOT_RUN（与 p0bench 一致）；环境缺失 → BLOCKED/ENVIRONMENT_UNAVAILABLE。
# 用法：bash test/e2e/bot-challenge/run.sh
# 依赖：docker(compose 插件)、curl、openssl、python3（cryptography 包）、node/npx（web/ 的 Playwright）
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT"

API_PORT="${API_PORT:-18081}"
GATEWAY_PORT="${GATEWAY_PORT:-18080}"
SITE_HTTPS_PORT="${SITE_HTTPS_PORT:-443}"
API_URL="http://127.0.0.1:$API_PORT"
SITE_HOST="bot-bench.local"
SITE_URL="https://${SITE_HOST}${SITE_HTTPS_PORT:+:$SITE_HTTPS_PORT}"
[ "$SITE_HTTPS_PORT" = "443" ] && SITE_URL="https://${SITE_HOST}"
PG_PORT="${PG_PORT:-5432}"
VK_PORT="${VK_PORT:-6379}"
RUN_ID="$(date +%Y%m%dT%H%M%S)-$(openssl rand -hex 3)"
EVIDENCE_DIR="test/e2e/bot-challenge/runs/$RUN_ID"

# ---- 每轮随机口令/密钥（仅本轮临时栈使用；mktemp 目录权限 0700）----
WORK_DIR="$(mktemp -d)"
chmod 700 "$WORK_DIR"
DUMP_DIR=""
ENV_FILE="$WORK_DIR/bot-bench.env"
PG_USER="jiuzhang"
PG_DB="jiuzhang_waf"
PG_PWD="$(openssl rand -hex 16)"
VK_PWD="$(openssl rand -hex 16)"
ADMIN_PWD="Ci$(openssl rand -hex 8)1!"
ADMIN_NEW_PWD="Ci$(openssl rand -hex 8)2!"
SEC_PWD_CI="CiSec@$(openssl rand -hex 6)1"
MASTER_KEY="$(openssl rand -hex 32)"
IDENTITY_SALT="$(openssl rand -hex 32)"
BOT_KEY_REF="bot-bench-hmac"
BOT_KEY_HEX="$(openssl rand -hex 32)"
LIC_KEY_ID="bot-bench-key"

# ---- 结果记录（PASS/FAIL/BLOCKED；失败明细落 evidence）----
TOTAL=0; PASS=0; FAIL=0; BLOCKED=0; FAILED=(); BLOCKED_ITEMS=()
record() { # <name> <ok> [detail]
  local name="$1" ok="$2" detail="${3:-}"
  TOTAL=$((TOTAL+1))
  if [ "$ok" = "1" ]; then PASS=$((PASS+1)); echo "PASS  $name"
  else FAIL=$((FAIL+1)); FAILED+=("$name: $detail"); echo "FAIL  $name ($detail)"; fi
}
blocked() { # <name> <reason>
  local name="$1" reason="$2"
  TOTAL=$((TOTAL+1)); BLOCKED=$((BLOCKED+1)); BLOCKED_ITEMS+=("$name: $reason")
  echo "BLOCKED  $name ($reason)"
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

# ---- 环境预检：任一缺失即如实 BLOCKED，不伪造通过 ----
preflight_fail() { echo "BLOCKED/ENVIRONMENT_UNAVAILABLE: $1" >&2; exit 3; }
command -v docker >/dev/null 2>&1 || preflight_fail "docker 不可用"
docker compose version >/dev/null 2>&1 || preflight_fail "docker compose 插件不可用"
command -v openssl >/dev/null 2>&1 || preflight_fail "openssl 不可用"
command -v curl >/dev/null 2>&1 || preflight_fail "curl 不可用"
python3 -c "import cryptography" >/dev/null 2>&1 || preflight_fail "python3 cryptography 包不可用（bot_signing_keys 播种需要）"

# ---- CI 临时 Ed25519 授权（与 jwt-trust-smoke 同口径，解锁授权门控）----
openssl genpkey -algorithm ed25519 -out "$WORK_DIR/lic-key.pem" >/dev/null 2>&1
chmod 600 "$WORK_DIR/lic-key.pem"
LIC_PUB_HEX="$(openssl pkey -in "$WORK_DIR/lic-key.pem" -pubout -outform DER 2>/dev/null \
  | tail -c 32 | python3 -c 'import sys; print(sys.stdin.buffer.read().hex())')"
python3 - "$WORK_DIR" "$LIC_KEY_ID" <<'PY'
import json, sys, datetime
work_dir, key_id = sys.argv[1], sys.argv[2]
payload = {
    "license_id": "LIC-BOT-BENCH-0001", "license_type": "FORMAL", "product": "wdsp",
    "customer": "Bot Bench", "issued_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "expires_at": None, "perpetual": True, "machine_fingerprint": None,
    "quotas": {"max_applications": 0, "max_api_endpoints": 0, "max_qps": 0},
    "features": ["api", "waf"], "version": 1, "key_id": key_id,
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
  echo "GATEWAY_SITE_HTTPS_PORT=$SITE_HTTPS_PORT"
  echo "LICENSE_VENDOR_PUBLIC_KEY=$LIC_KEY_ID:$LIC_PUB_HEX"
} > "$ENV_FILE"
chmod 600 "$ENV_FILE"

COMPOSE=(docker compose --env-file "$ENV_FILE"
  -f deployment/docker-compose.stage5.yml -f deployment/docker-compose.wdsp.yml
  -f deployment/docker-compose.test-license.yml)

port_free() { ! python3 -c "
import socket,sys
s=socket.socket(); s.settimeout(0.3)
sys.exit(0 if s.connect_ex(('127.0.0.1',$1))==0 else 1)"; }
for p in "$PG_PORT" "$VK_PORT" "$API_PORT" "$GATEWAY_PORT" 81 "$SITE_HTTPS_PORT"; do
  if ! port_free "$p"; then
    echo "BLOCKED/ENVIRONMENT_UNAVAILABLE: 127.0.0.1:$p 已被占用" >&2
    rm -rf "$WORK_DIR"; exit 3
  fi
done
if [ -n "$("${COMPOSE[@]}" ps -q 2>/dev/null)" ]; then
  echo "BLOCKED/ENVIRONMENT_UNAVAILABLE: 检测到 stage5 编排已有容器在运行" >&2
  rm -rf "$WORK_DIR"; exit 3
fi
# 防御性清卷：上次运行若未正常 down -v（如被杀），残留命名卷里的旧随机口令会让
# api 起不来（SASL auth failed）；本栈口令每轮随机，卷必须随之全新
"${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true

mkdir -p "$EVIDENCE_DIR"

cleanup() {
  local rc=$?
  if [ "$rc" -eq 0 ] && [ "${SCRIPT_DONE:-0}" != "1" ]; then rc=1; fi
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 3 ]; then
    DUMP_DIR="$EVIDENCE_DIR/stack-dump"
    mkdir -p "$DUMP_DIR"
    {
      echo "==== compose ps ===="; "${COMPOSE[@]}" ps 2>&1
      echo; echo "==== api 日志尾部 ===="; "${COMPOSE[@]}" logs --tail=200 api 2>&1
      echo; echo "==== gateway 日志尾部 ===="; "${COMPOSE[@]}" logs --tail=200 gateway 2>&1
      echo; echo "==== gateway guard-events 尾部 ===="
      docker exec jiuzhang-stage5-gateway sh -c 'tail -n 60 /var/log/caddy/guard-events.log' 2>&1 || true
    } > "$DUMP_DIR/stack-dump.log" 2>&1 || true
    echo "失败诊断日志（不含密钥/Token）：$DUMP_DIR/stack-dump.log" >&2
  fi
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK_DIR"
  exit "$rc"
}
trap cleanup EXIT

echo "============================================================"
echo "P1-02 B4 Bot 挑战基准  run_id=$RUN_ID"
echo "api=$API_URL site=$SITE_URL"
echo "============================================================"

# ---- 镜像：Bot 代码为新代码，必须从当前工作树重建 ----
echo "[build] 从当前工作树构建 api/gateway/testorigin 镜像 ..."
"${COMPOSE[@]}" build api gateway testorigin

mkdir -p runtime/license

echo "[up] 启动 postgres/valkey/testorigin/gateway/api ..."
"${COMPOSE[@]}" up -d api gateway

wait_http "$API_URL/api/v1/health" 200 600 || {
  echo "==== api 容器状态与日志尾部 ====" >&2
  "${COMPOSE[@]}" ps api >&2 || true
  "${COMPOSE[@]}" logs --tail=120 api >&2 || true
  exit 1
}
record "api 健康检查通过" 1

wait_gateway_app() {
  local deadline=$(( $(date +%s) + ${1:-90} )) code
  while [ "$(date +%s)" -lt "$deadline" ]; do
    code="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 \
      --resolve "$SITE_HOST:$SITE_HTTPS_PORT:127.0.0.1" "$SITE_URL/" 2>/dev/null || true)"
    [ -n "$code" ] && [ "$code" != "000" ] && { echo "[gw] 网关 HTTPS 已应答（status=${code}）"; return 0; }
    sleep 2
  done
  echo "ERROR: 发布后网关 HTTPS 未应答（last=${code:-none}）" >&2
  return 1
}

# ---- 登录/用户/发布 复用阶段5公共函数 ----
export API_URL GATEWAY_URL="http://127.0.0.1:$GATEWAY_PORT"
export HOST_HEADER="$SITE_HOST"
export VALKEY_PASSWORD="$VK_PWD" VALKEY_CONTAINER="jiuzhang-stage5-valkey"
export SYS_USER="jiuzhang_admin" SYS_PWD="$ADMIN_PWD" SYS_NEW_PWD="$ADMIN_NEW_PWD"
export SEC_USER="bot_bench_sec" SEC_PWD="$SEC_PWD_CI"
export APP_CODE="botbench"
# shellcheck source=../../waf/scripts/stage5-setup.sh
source test/waf/scripts/stage5-setup.sh

SYS_CSRF="$(s5_ensure_sysadmin)" || { echo "ERROR: sysadmin 登录失败" >&2; exit 1; }
record "系统管理员登录（含强制改密）" 1

LIC_BODY="$(python3 -c 'import json,sys; print(json.dumps({"file_content": open(sys.argv[1]).read()}))' "$WORK_DIR/license.lic")"
expect_code "导入 CI 临时 wdsp 授权" 200 \
  "$(curl -s -o /dev/null -w '%{http_code}' -b "/tmp/s5-$SYS_USER.txt" -X POST "$API_URL/api/v1/license/import" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $SYS_CSRF" -d "$LIC_BODY")"

SEC_CSRF="$(s5_ensure_secuser "$SYS_CSRF")"
[ -n "$SEC_CSRF" ] || { echo "ERROR: 安全管理员登录失败" >&2; exit 1; }
record "安全管理员就绪" 1

sec_api() { # <method> <path> [bodyfile]
  local m="$1" p="$2" bf="${3:-}"
  local args=(-s -b "/tmp/s5-$SEC_USER.txt" -X "$m" "$API_URL$p"
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF")
  [ -n "$bf" ] && args+=(--data-binary "@$bf")
  curl "${args[@]}"
}
sec_api_code() { # <method> <path> [bodyfile] → http code
  local m="$1" p="$2" bf="${3:-}"
  local args=(-s -o /dev/null -w '%{http_code}' -b "/tmp/s5-$SEC_USER.txt" -X "$m" "$API_URL$p"
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF")
  [ -n "$bf" ] && args+=(--data-binary "@$bf")
  curl "${args[@]}"
}

# ---- 自签证书（仅本轮栈；Hostname=bot-bench.local）----
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$WORK_DIR/site-key.pem" -out "$WORK_DIR/site-cert.pem" \
  -days 2 -subj "/CN=$SITE_HOST" \
  -addext "subjectAltName=DNS:$SITE_HOST" >/dev/null 2>&1
chmod 600 "$WORK_DIR/site-key.pem"
python3 - "$WORK_DIR" > "$WORK_DIR/cert-upload.json" <<'PY'
import json, sys
w = sys.argv[1]
cert = open(w + "/site-cert.pem").read()
key = open(w + "/site-key.pem").read()
print(json.dumps({"name": "bot-bench-selfsigned", "cert_pem": cert, "key_pem": key, "chain_pem": cert}))
PY
CERT_ID="$(sec_api POST /api/v1/certificates "$WORK_DIR/cert-upload.json" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['id'])" 2>/dev/null)"
[ -n "$CERT_ID" ] && record "上传自签测试证书" 1 || { record "上传自签测试证书" 0 "cert_id 为空"; echo ABORT; exit 1; }

# ---- 建 HTTPS 应用（challenge 仅覆盖 HTTPS 导航；protection_mode=PROTECT 供 BOT-014 组合）----
APP_ID="$(sec_api POST /api/v1/applications /dev/stdin <<EOF \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['id'])" 2>/dev/null
{"code":"$APP_CODE","name":"Bot挑战基准应用","description":"P1-02 B4 浏览器/自动化基准","business_owner":"test","technical_owner":"test","protection_mode":"PROTECT"}
EOF
)"
[ -n "$APP_ID" ] && record "创建 PROTECT 应用" 1 || { record "创建 PROTECT 应用" 0 "app_id 为空"; echo ABORT; exit 1; }
sec_api POST "/api/v1/applications/$APP_ID/domains" /dev/stdin > /dev/null <<EOF
{"hostname":"$SITE_HOST","is_primary":true,"http_enabled":false,"https_enabled":true,"https_port":$SITE_HTTPS_PORT,"redirect_http_to_https":false}
EOF
sec_api POST "/api/v1/applications/$APP_ID/upstreams" /dev/stdin > /dev/null <<'EOF'
{"name":"testorigin","scheme":"http","host":"testorigin","port":8081,"weight":1,"priority":1,"health_check_enabled":false,"health_check_path":"/health","health_check_method":"GET","health_check_interval_seconds":10,"health_check_timeout_seconds":3,"expected_status_codes":"200","connect_timeout_ms":3000,"response_header_timeout_ms":10000,"tls_server_name":"","tls_verify":false}
EOF
expect_code "绑定证书到应用" 200 \
  "$(sec_api_code POST "/api/v1/applications/$APP_ID/certificate" /dev/stdin <<EOF
{"certificate_id":"$CERT_ID"}
EOF
)"
sec_api POST "/api/v1/applications/$APP_ID/enable" > /dev/null
echo "[setup] app=$APP_ID host=$SITE_HOST cert=$CERT_ID"

# ---- 身份指纹盐播种（identity_behavior 依赖；与 jwt-trust-smoke 同口径 psql 夹具通道）----
docker exec -i jiuzhang-stage5-postgres psql -U "$PG_USER" -d "$PG_DB" -v ON_ERROR_STOP=1 >/dev/null <<SQL
INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, description)
VALUES ('gateway_runtime','identity_salt','"$IDENTITY_SALT"','string','bot-bench：身份指纹盐（随机，仅本轮栈）')
ON CONFLICT (setting_group, setting_key) DO UPDATE
SET setting_value = EXCLUDED.setting_value, updated_at = now(), version = system_settings.version + 1;
SQL
record "身份指纹盐（identity_salt）播种" 1

# ---- Bot 签名密钥播种（gateway_runtime:bot_signing_keys 密文 JSON；
#      管理面写入入口属 B5 工作，本夹具经 psql + AES-256-GCM（JIUZHANG_MASTER_KEY）现场加密播种，
#      密钥材料只存 mktemp 与 Valkey/DB 密文，退出即清理）----
BOT_KEYS_CIPHER="$(python3 - "$MASTER_KEY" "$BOT_KEY_REF" "$BOT_KEY_HEX" <<'PY'
import sys, json, base64, os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
master_hex, key_ref, key_hex = sys.argv[1], sys.argv[2], sys.argv[3]
key = bytes.fromhex(master_hex)
nonce = os.urandom(12)
ct = AESGCM(key).encrypt(nonce, json.dumps({key_ref: key_hex}).encode(), None)
print(base64.b64encode(nonce + ct).decode())
PY
)"
python3 - "$BOT_KEYS_CIPHER" > "$WORK_DIR/seed-keys.sql" <<'PY'
import sys
cipher = sys.argv[1]
print("INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, description)")
print("VALUES ('gateway_runtime','bot_signing_keys','\"%s\"','string','bot-bench：Bot签名密钥（随机，仅本轮栈）')" % cipher)
print("ON CONFLICT (setting_group, setting_key) DO UPDATE")
print("SET setting_value = EXCLUDED.setting_value, updated_at = now(), version = system_settings.version + 1;")
PY
docker exec -i jiuzhang-stage5-postgres psql -U "$PG_USER" -d "$PG_DB" -v ON_ERROR_STOP=1 \
  < "$WORK_DIR/seed-keys.sql" >/dev/null
record "Bot 签名密钥（bot_signing_keys 密文）播种" 1

# ---- 启用身份行为观测（Bot 行为信号数据源；GLOBAL 策略，GET→改 enabled→PUT 回）----
sec_api GET /api/v1/security/behavior-policy > "$WORK_DIR/behavior-policy.json"
python3 - "$WORK_DIR/behavior-policy.json" > "$WORK_DIR/behavior-policy-on.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))["data"]["policy"]
d["enabled"] = True
# 剔除只读字段（DecodeJSON 严格解码，含未知字段 400）
for k in ("id", "updated_by", "updated_at", "created_at"):
    d.pop(k, None)
print(json.dumps(d))
PY
BP_CODE="$(sec_api_code PUT /api/v1/security/behavior-policy "$WORK_DIR/behavior-policy-on.json")"
if [ "$BP_CODE" != "200" ]; then
  sec_api PUT /api/v1/security/behavior-policy "$WORK_DIR/behavior-policy-on.json" \
    > "$EVIDENCE_DIR/behavior-policy-put-error.json" 2>/dev/null || true
fi
expect_code "启用身份行为观测（behavior-policy enabled=true）" 200 "$BP_CODE"

# ---- Bot 策略 PROTECT 草稿（选择器 path_exact=/；行为双组：URI 集中度≥0.5 + 已知 URI 占比≤0.99；
#      Peek 快照不含本次请求记账，前两次导航建立观测基线，第三次导航评估时双组达阈提出挑战——
#      判定口径可复算）----
python3 - "$BOT_KEY_REF" > "$WORK_DIR/bot-policy.json" <<'PY'
import json, sys
key_ref = sys.argv[1]
print(json.dumps({
    "mode": "PROTECT",
    "expected_version": 0,
    "selectors": [{"path_exact": "/"}],
    "signal_rules": {
        "min_independent_groups": 2,
        "require_behavior_group": True,
        "rules": [
            {"id": "uri_concentration_high", "group": "request_behavior",
             "metric": "uri_concentration", "window_seconds": 300,
             "weight": 1, "threshold": 0.5},
            {"id": "known_uri_ratio_low", "group": "access_sequence",
             "metric": "known_uri_ratio", "window_seconds": 300,
             "weight": 1, "threshold": 0.99},
        ],
    },
    "challenge": {"type": "JS", "nonce_ttl_seconds": 90, "clearance_ttl_seconds": 900,
                  "difficulty": 12, "max_attempts": 3, "key_ref": key_ref},
    "route_reservation": {"state": "ENABLED", "namespace": "/_wdsp/bot/v1/"},
    "reason": "bot-bench: B4 浏览器/自动化基准 PROTECT 草稿",
}))
PY
expect_code "保存 Bot 策略 PROTECT 草稿（乐观锁 v0）" 200 \
  "$(sec_api_code PUT "/api/v1/applications/$APP_ID/bot-policy" "$WORK_DIR/bot-policy.json")"

# ---- 预检：publishable 必须为 true 且 signing_key/shared_state 通过 ----
sec_api POST "/api/v1/applications/$APP_ID/bot-policy/preflight" /dev/stdin > "$WORK_DIR/preflight.json" <<'EOF'
{}
EOF
cp "$WORK_DIR/preflight.json" "$EVIDENCE_DIR/preflight.json"
PRE_OK="$(python3 - "$WORK_DIR/preflight.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))["data"]
names = {c["name"]: c["status"] for c in d.get("checks", [])}
ok = (d.get("publishable") is True and names.get("shared_state") == "PASS"
      and names.get("signing_key") == "PASS")
print("OK" if ok else "BAD:publishable=%s checks=%s" % (d.get("publishable"), names))
PY
)"
[ "$PRE_OK" = "OK" ] && record "预检 publishable=true 且 shared_state/signing_key=PASS" 1 \
  || { record "预检 publishable=true 且 shared_state/signing_key=PASS" 0 "$PRE_OK"; echo ABORT; exit 1; }

PUB="$(s5_publish "$SEC_CSRF" || true)"
echo "[setup] publish result=$PUB"
if [ "$PUB" != "PUBLISH_OK" ]; then
  # 失败诊断：最近发布任务状态/错误留档（不得静默）
  sec_api GET "/api/v1/publish-tasks?page=1&page_size=3" \
    > "$EVIDENCE_DIR/publish-tasks.json" 2>/dev/null || true
fi
[ "$PUB" = "PUBLISH_OK" ] && record "PROTECT 配置发布成功（门禁通过）" 1 \
  || { record "PROTECT 配置发布成功（门禁通过）" 0 "$PUB"; echo ABORT; exit 1; }
wait_gateway_app 90 || { record "发布生效后网关 HTTPS 可达" 0 "超时"; echo ABORT; exit 1; }
record "发布生效后网关 HTTPS 可达" 1

# ---- 网关侧探测（curl --resolve 固定 Host 解析到本机栈；-k 自签证书）----
gw() { # curl 参数透传（Host 解析与自签已内置）
  curl -sk --max-time 15 --resolve "$SITE_HOST:$SITE_HTTPS_PORT:127.0.0.1" "$@"
}

# 浏览器文档导航请求头（合格挑战条件：GET + HTTPS + Accept text/html + 无 X-Requested-With）
NAV_HEADERS=(-H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,*/*;q=0.8'
  -H 'Accept-Language: zh-CN,zh;q=0.9'
  -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36')

echo "============================================================"
echo "组 1/3：http-script（非浏览器 HTTP 脚本组，BOT-021 之普通自动化 + BOT-005）"
echo "============================================================"
GROUP1_DIR="$EVIDENCE_DIR/group-http-script"
mkdir -p "$GROUP1_DIR"

# BOT-005a：HEAD / —— 不适用挑战（方法非 GET），不返回 HTML 挑战
code="$(gw -o "$GROUP1_DIR/head.txt" -w '%{http_code}' -I "$SITE_URL/")"
ctype="$(gw -sI "$SITE_URL/" | grep -i '^content-type:' || true)"
echo "$ctype" > "$GROUP1_DIR/head-content-type.txt"
if [ "$code" = "200" ] && ! echo "$ctype" | grep -qi 'text/html'; then
  record "BOT-005 HEAD 不返回 HTML 挑战（status=${code}）" 1
else
  record "BOT-005 HEAD 不返回 HTML 挑战" 0 "status=$code ctype=$ctype"
fi

# BOT-005b：POST /login（选择器外 JSON 写操作）—— 不被挑战、不重放
code="$(gw -o "$GROUP1_DIR/post-login.json" -w '%{http_code}' -X POST \
  -H 'Content-Type: application/json' -H 'Accept: application/json' \
  -d '{"username":"bench","password":"bench"}' "$SITE_URL/login")"
mark="$(python3 -c "import json; print(json.load(open('$GROUP1_DIR/post-login.json')).get('upstream_mark',''))" 2>/dev/null || echo '')"
if [ "$code" = "200" ] && [ "$mark" = "REACHED_ORIGIN" ]; then
  record "BOT-005 POST /login 直达源站不挑战（status=${code}）" 1
else
  record "BOT-005 POST /login 直达源站不挑战" 0 "status=$code mark=$mark"
fi

# BOT-005c：GET / 带 Accept: application/json（非文档导航）—— 不适用挑战
code="$(gw -o "$GROUP1_DIR/get-json.json" -w '%{http_code}' \
  -H 'Accept: application/json' "$SITE_URL/")"
mark="$(python3 -c "import json; print(json.load(open('$GROUP1_DIR/get-json.json')).get('upstream_mark',''))" 2>/dev/null || echo '')"
if [ "$code" = "200" ] && [ "$mark" = "REACHED_ORIGIN" ]; then
  record "BOT-005 JSON 客户端 GET 不返回 HTML 挑战（status=${code}）" 1
else
  record "BOT-005 JSON 客户端 GET 不返回 HTML 挑战" 0 "status=$code mark=$mark"
fi

# 脚本组合格导航探测：Peek 只读快照不含本次请求记账（Observe 在请求收束时才记账，
# peek.go 头部纪律），故第 1、2 次导航建立观测基线（放行 200）；第 3 次评估时窗口内
# 已有 2 请求/1 个唯一 URI → uri_concentration=0.5 与 known_uri_ratio=0.5 双组达阈 → 挑战。
code1="$(gw -o "$GROUP1_DIR/nav-1.html" -w '%{http_code}' "${NAV_HEADERS[@]}" "$SITE_URL/")"
echo "[group1] 第 1 次文档导航 status=${code1}（观测基线 1/2）"
code2="$(gw -o "$GROUP1_DIR/nav-2.html" -w '%{http_code}' "${NAV_HEADERS[@]}" "$SITE_URL/")"
echo "[group1] 第 2 次文档导航 status=${code2}（观测基线 2/2）"
if [ "$code1" = "200" ] && [ "$code2" = "200" ]; then
  record "BOT-021 脚本组：基线导航放行 200（达阈前选择器/阈值门控正常）" 1
else
  record "BOT-021 脚本组：基线导航放行 200（达阈前选择器/阈值门控正常）" 0 "code1=${code1} code2=${code2}"
fi
code3="$(gw -D "$GROUP1_DIR/nav-3.headers" -o "$GROUP1_DIR/nav-3.html" -w '%{http_code}' \
  "${NAV_HEADERS[@]}" "$SITE_URL/")"
echo "[group1] 第 3 次文档导航 status=${code3}"
if [ "$code3" = "403" ] && grep -q '安全验证' "$GROUP1_DIR/nav-3.html"; then
  record "BOT-021 脚本组：合格导航被挑战 403 + 挑战页 HTML" 1
  grep -qi '^content-security-policy:.*nonce-' "$GROUP1_DIR/nav-3.headers" \
    && record "挑战页携带 CSP nonce 严格策略" 1 \
    || record "挑战页携带 CSP nonce 严格策略" 0 "headers 见 nav-3.headers"
  grep -qi '^cache-control:.*no-store' "$GROUP1_DIR/nav-3.headers" \
    && record "挑战页 Cache-Control: no-store（不进共享缓存）" 1 \
    || record "挑战页 Cache-Control: no-store（不进共享缓存）" 0 "headers 见 nav-3.headers"
else
  record "BOT-021 脚本组：合格导航被挑战 403 + 挑战页 HTML" 0 "status=${code3}（链路未通则属 B3 缺口，如实 FAIL）"
fi

# 脚本组不能执行 JS：挑战即业务阻断（结果如实 = 无法通行）
if [ "$code3" = "403" ]; then
  record "BOT-021 脚本组业务结果：不能执行 JS → 无法通过挑战（通行率 0/1，如实）" 1
else
  record "BOT-021 脚本组业务结果：不能执行 JS → 无法通过挑战" 0 "未触发挑战 status=${code3}"
fi

# verify 固定协议：无会话伪造提交 → 拒绝且不设置 clearance Cookie
vcode="$(gw -D "$GROUP1_DIR/verify-forged.headers" -o "$GROUP1_DIR/verify-forged.json" -w '%{http_code}' \
  -X POST -H 'Content-Type: application/json' -H "Origin: $SITE_URL" \
  -d '{"challenge_id":"00000000000000000000000000000000","solution":"0"}' \
  "$SITE_URL/_wdsp/bot/v1/verify")"
echo "[group1] 伪造 verify status=$vcode"
case "$vcode" in
  400|403|404|409|429)
    if grep -qi '^set-cookie:.*__Host-wdsp-bot-clearance' "$GROUP1_DIR/verify-forged.headers"; then
      record "伪造 verify 被拒绝且不签发 clearance" 0 "错误响应设置了 clearance Cookie"
    else
      record "伪造 verify 被拒绝且不签发 clearance（status=${vcode}）" 1
    fi ;;
  *) record "伪造 verify 被拒绝且不签发 clearance" 0 "status=$vcode" ;;
esac

# verify 错误方法 → 405，未知子路径 → 404（均本地处理不转发源站，BOT-016 侧面）
mcode="$(gw -o /dev/null -w '%{http_code}' -X GET "$SITE_URL/_wdsp/bot/v1/verify")"
expect_code "verify 错误方法 GET → 405" 405 "$mcode"
ucode="$(gw -o /dev/null -w '%{http_code}' "${NAV_HEADERS[@]}" "$SITE_URL/_wdsp/bot/v1/unknown")"
expect_code "保留命名空间未知子路径 → 本地 404" 404 "$ucode"

echo "============================================================"
echo "组 2/3 + 3/3：browser（BOT-004）与 automation-js（BOT-021）"
echo "============================================================"
# Playwright 可用性预检（浏览器二进制缺失时两组如实 BLOCKED，不影响组 1 结论）。
# 模块解析：@playwright/test 仅安装在 web/node_modules；在本夹具目录建 node_modules 软链，
# 使 specs/config 的 import 经 Node 逐层向上查找命中。软链用相对目标（跨机可解析），
# 本目录 .gitignore 忽略 node_modules（根 .gitignore 的 node_modules/ 只匹配真实目录，
# 不匹配符号链接，故须目录级规则兜底）；重跑幂等 -sfn 覆盖。
ln -sfn ../../../web/node_modules "$REPO_ROOT/test/e2e/bot-challenge/node_modules"
PW_OK=0
if (cd web && npx playwright --version >/dev/null 2>&1); then
  CHROMIUM_BIN="$(cd web && node -e "try{console.log(require('playwright-core').chromium.executablePath())}catch(e){process.exit(1)}" 2>/dev/null || true)"
  if [ -n "$CHROMIUM_BIN" ] && [ -x "$CHROMIUM_BIN" ]; then
    PW_OK=1
  fi
fi
if [ "$PW_OK" != "1" ]; then
  blocked "BOT-004 真实浏览器组" "Playwright/Chromium 不可用（ENVIRONMENT_UNAVAILABLE；可 cd web && npx playwright install chromium 后重跑）"
  blocked "BOT-021 自动化浏览器组" "Playwright/Chromium 不可用（ENVIRONMENT_UNAVAILABLE）"
else
  export BOT_BENCH_SITE_URL="$SITE_URL"
  export BOT_BENCH_SITE_HOST="$SITE_HOST"
  export BOT_BENCH_REPORT_DIR="$REPO_ROOT/$EVIDENCE_DIR"
  export BOT_BENCH_NAV_WARMUP="${BOT_BENCH_NAV_WARMUP:-1}"
  for GROUP in browser automation-js; do
    echo "[pw] 运行组：$GROUP"
    set +e
    (cd web && npx playwright test \
      --config ../test/e2e/bot-challenge/playwright.config.ts \
      --grep "@$GROUP" \
      --reporter=json > "$REPO_ROOT/$EVIDENCE_DIR/group-$GROUP.playwright.json" 2>&1)
    pw_rc=$?
    set -e
    echo "[pw] 组 $GROUP 退出码=${pw_rc}（报告 $EVIDENCE_DIR/group-$GROUP.playwright.json）"
    if [ "$pw_rc" = "0" ]; then
      record "组 ${GROUP}：Playwright 全例通过" 1
    else
      # 区分「链路未通（B3 缺口/环境）」与「断言失败」：报告原文留档，如实 FAIL
      record "组 ${GROUP}：Playwright 全例通过" 0 "退出码=${pw_rc}，详见 group-$GROUP.playwright.json"
    fi
  done
fi

# ---- 汇总与证据落盘 ----
echo "============================================================"
echo "P1-02 B4 Bot 挑战基准汇总: 总项 $TOTAL 通过 $PASS 失败 $FAIL 阻塞 $BLOCKED"
if [ "$FAIL" -gt 0 ]; then
  for c in "${FAILED[@]}"; do echo "  FAIL - $c"; done
fi
if [ "$BLOCKED" -gt 0 ]; then
  for c in "${BLOCKED_ITEMS[@]}"; do echo "  BLOCKED - $c"; done
fi
echo "证据目录: $EVIDENCE_DIR"
echo "============================================================"

python3 - "$EVIDENCE_DIR" "$RUN_ID" "$TOTAL" "$PASS" "$FAIL" "$BLOCKED" <<'PY'
import json, sys, datetime, os
ev, run_id, total, passed, failed, blocked_n = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5]), int(sys.argv[6])
status = {
    "run_id": run_id,
    "task": "P1-02 B4 BOT-004/005/021 浏览器与自动化基准",
    "finished_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "totals": {"total": total, "pass": passed, "fail": failed, "blocked": blocked_n},
    "groups": {
        "http-script": {"evidence": "group-http-script/"},
        "browser": {"evidence": "group-browser.playwright.json"},
        "automation-js": {"evidence": "group-automation-js.playwright.json"},
    },
    "verdict": "FAIL" if failed > 0 else ("PASS" if blocked_n == 0 else "PASS_WITH_BLOCKED"),
}
with open(os.path.join(ev, "status.json"), "w") as f:
    json.dump(status, f, ensure_ascii=False, indent=2)
PY

SCRIPT_DONE=1
[ "$FAIL" -eq 0 ]
