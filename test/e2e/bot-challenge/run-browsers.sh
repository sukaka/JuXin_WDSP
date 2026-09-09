#!/usr/bin/env bash
# P1-02 BOT-004 多浏览器通道 + BOT-006 慢设备/键盘导航补证（真实 stage5 栈，
# 夹具口径与 run.sh 一致：postgres/valkey/api/gateway/testorigin、自签 HTTPS 应用、
# Bot 策略 PROTECT path_exact=/ difficulty=12 经管理面真实发布）。
#
# 跨浏览器解析（诚实方案）：--host-resolver-rules 为 Chromium 专有，Firefox/WebKit
# 不支持；本夹具给基准应用登记第二域名 bot-bench.localhost（RFC 6761 localhost 域，
# macOS 系统解析器实测原生解析 127.0.0.1，dscacheutil/getaddrinfo 双验证），
# 非 Chromium 通道统一走该域名，无需任何浏览器专有参数或 /etc/hosts 改写。
# 挑战题目与通行按 Host 绑定（pow_test.go:TestPowBinding），各通道 Host 自洽。
#
# 通道矩阵（playwright.config.ts projects，均跑 @browser 同链路）：
#   chromium      Desktop Chrome（对照通道，bot-bench.local + host-resolver-rules）
#   firefox       Desktop Firefox → bot-bench.localhost
#   webkit        Desktop Safari → bot-bench.localhost（对应 Safari 桌面维度）
#   mobile-safari iPhone 14 仿真（WebKit 移动 UA/视口/触控）
#   mobile-chrome Pixel 7 仿真（Chromium 移动 UA/视口/触控）
# @a11y 组（BOT-006）固定 chromium 通道：CDP CPU 6x 节流慢设备 + 键盘导航。
#
# 词表：PASS / FAIL / BLOCKED / NOT_RUN（与 run.sh 一致）；
# 环境缺失 → BLOCKED/ENVIRONMENT_UNAVAILABLE（退出码 3），不伪造通过。
# 用法：bash test/e2e/bot-challenge/run-browsers.sh
# 依赖：docker(compose 插件)、curl、openssl、python3（cryptography 包）、
#       node/npx（web/ 的 Playwright，firefox/webkit 二进制缺失时
#       cd web && npx playwright install firefox webkit）
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT"

API_PORT="${API_PORT:-18081}"
GATEWAY_PORT="${GATEWAY_PORT:-18080}"
SITE_HTTPS_PORT="${SITE_HTTPS_PORT:-443}"
API_URL="http://127.0.0.1:$API_PORT"
SITE_HOST="bot-bench.local"
SITE_HOST_NATIVE="bot-bench.localhost"
SITE_URL="https://${SITE_HOST}"
SITE_URL_NATIVE="https://${SITE_HOST_NATIVE}"
[ "$SITE_HTTPS_PORT" != "443" ] && { SITE_URL="${SITE_URL}:$SITE_HTTPS_PORT"; SITE_URL_NATIVE="${SITE_URL_NATIVE}:$SITE_HTTPS_PORT"; }
PG_PORT="${PG_PORT:-5432}"
VK_PORT="${VK_PORT:-6379}"
RUN_ID="$(date +%Y%m%dT%H%M%S)-$(openssl rand -hex 3)"
EVIDENCE_DIR="test/e2e/bot-challenge/runs/$RUN_ID"

# ---- 每轮随机口令/密钥（仅本轮临时栈使用；mktemp 目录权限 0700）----
WORK_DIR="$(mktemp -d)"
chmod 700 "$WORK_DIR"
DUMP_DIR=""
ENV_FILE="$WORK_DIR/bot-browsers.env"
PG_USER="jiuzhang"
PG_DB="jiuzhang_waf"
PG_PWD="$(openssl rand -hex 16)"
VK_PWD="$(openssl rand -hex 16)"
ADMIN_PWD="Ci$(openssl rand -hex 8)1!"
ADMIN_NEW_PWD="Ci$(openssl rand -hex 8)2!"
SEC_PWD_CI="CiSec@$(openssl rand -hex 6)1"
MASTER_KEY="$(openssl rand -hex 32)"
IDENTITY_SALT="$(openssl rand -hex 32)"
BOT_KEY_REF="bot-browsers-hmac"
BOT_KEY_HEX="$(openssl rand -hex 32)"
LIC_KEY_ID="bot-browsers-key"

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

# 非 Chromium 通道解析前提：bot-bench.localhost 经系统解析器原生到回环（不改 /etc/hosts）
NATIVE_IP="$(python3 -c "import socket; print(socket.gethostbyname('$SITE_HOST_NATIVE'))" 2>/dev/null || true)"
if [ "$NATIVE_IP" != "127.0.0.1" ]; then
  preflight_fail "$SITE_HOST_NATIVE 未解析到 127.0.0.1（got=${NATIVE_IP:-none}）；本机系统解析器不支持 localhost 子域"
fi

# ---- CI 临时 Ed25519 授权（与 run.sh 同口径，解锁授权门控）----
openssl genpkey -algorithm ed25519 -out "$WORK_DIR/lic-key.pem" >/dev/null 2>&1
chmod 600 "$WORK_DIR/lic-key.pem"
LIC_PUB_HEX="$(openssl pkey -in "$WORK_DIR/lic-key.pem" -pubout -outform DER 2>/dev/null \
  | tail -c 32 | python3 -c 'import sys; print(sys.stdin.buffer.read().hex())')"
python3 - "$WORK_DIR" "$LIC_KEY_ID" <<'PY'
import json, sys, datetime
work_dir, key_id = sys.argv[1], sys.argv[2]
payload = {
    "license_id": "LIC-BOT-BROWSERS-0001", "license_type": "FORMAL", "product": "wdsp",
    "customer": "Bot Browsers Bench", "issued_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
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
# 防御性清卷：口令每轮随机，卷必须随之全新（与 run.sh 同口径）
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
echo "P1-02 BOT-004/006 多浏览器与无障碍补证  run_id=$RUN_ID"
echo "api=$API_URL site=$SITE_URL native=$SITE_URL_NATIVE"
echo "============================================================"

# ---- 环境标注（证据可复核）----
{
  echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "uname: $(uname -srm)"
  sw_vers 2>/dev/null || true
  echo "docker: $(docker version --format 'server={{.Server.Version}}' 2>/dev/null)"
  echo "git HEAD: $(git rev-parse HEAD 2>/dev/null)"
  echo "git 工作树状态（他人未提交改动随镜像进入，如实记录）："
  git status --porcelain 2>/dev/null | head -40
  [ -n "${BOT_BENCH_ENV_NOTE:-}" ] && echo "note: $BOT_BENCH_ENV_NOTE"
} > "$EVIDENCE_DIR/environment.txt"

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
export SEC_USER="bot_browsers_sec" SEC_PWD="$SEC_PWD_CI"
export APP_CODE="botbrowsers"
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

# ---- 自签证书（仅本轮栈；SAN 覆盖两个基准域名）----
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$WORK_DIR/site-key.pem" -out "$WORK_DIR/site-cert.pem" \
  -days 2 -subj "/CN=$SITE_HOST" \
  -addext "subjectAltName=DNS:$SITE_HOST,DNS:$SITE_HOST_NATIVE" >/dev/null 2>&1
chmod 600 "$WORK_DIR/site-key.pem"
python3 - "$WORK_DIR" > "$WORK_DIR/cert-upload.json" <<'PY'
import json, sys
w = sys.argv[1]
cert = open(w + "/site-cert.pem").read()
key = open(w + "/site-key.pem").read()
print(json.dumps({"name": "bot-browsers-selfsigned", "cert_pem": cert, "key_pem": key, "chain_pem": cert}))
PY
CERT_ID="$(sec_api POST /api/v1/certificates "$WORK_DIR/cert-upload.json" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['id'])" 2>/dev/null)"
[ -n "$CERT_ID" ] && record "上传自签测试证书（SAN 双域名）" 1 || { record "上传自签测试证书（SAN 双域名）" 0 "cert_id 为空"; echo ABORT; exit 1; }

# ---- 建 HTTPS 应用（双域名：bot-bench.local 对照 + bot-bench.localhost 非 Chromium 通道）----
APP_ID="$(sec_api POST /api/v1/applications /dev/stdin <<EOF \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['id'])" 2>/dev/null
{"code":"$APP_CODE","name":"Bot多浏览器基准应用","description":"P1-02 BOT-004/006 补证","business_owner":"test","technical_owner":"test","protection_mode":"PROTECT"}
EOF
)"
[ -n "$APP_ID" ] && record "创建 PROTECT 应用" 1 || { record "创建 PROTECT 应用" 0 "app_id 为空"; echo ABORT; exit 1; }
sec_api POST "/api/v1/applications/$APP_ID/domains" /dev/stdin > /dev/null <<EOF
{"hostname":"$SITE_HOST","is_primary":true,"http_enabled":false,"https_enabled":true,"https_port":$SITE_HTTPS_PORT,"redirect_http_to_https":false}
EOF
expect_code "登记第二域名 ${SITE_HOST_NATIVE}（非 Chromium 通道）" 200 \
  "$(sec_api_code POST "/api/v1/applications/$APP_ID/domains" /dev/stdin <<EOF
{"hostname":"$SITE_HOST_NATIVE","is_primary":false,"http_enabled":false,"https_enabled":true,"https_port":$SITE_HTTPS_PORT,"redirect_http_to_https":false}
EOF
)"
sec_api POST "/api/v1/applications/$APP_ID/upstreams" /dev/stdin > /dev/null <<'EOF'
{"name":"testorigin","scheme":"http","host":"testorigin","port":8081,"weight":1,"priority":1,"health_check_enabled":false,"health_check_path":"/health","health_check_method":"GET","health_check_interval_seconds":10,"health_check_timeout_seconds":3,"expected_status_codes":"200","connect_timeout_ms":3000,"response_header_timeout_ms":10000,"tls_server_name":"","tls_verify":false}
EOF
expect_code "绑定证书到应用" 200 \
  "$(sec_api_code POST "/api/v1/applications/$APP_ID/certificate" /dev/stdin <<EOF
{"certificate_id":"$CERT_ID"}
EOF
)"
sec_api POST "/api/v1/applications/$APP_ID/enable" > /dev/null
echo "[setup] app=$APP_ID hosts=$SITE_HOST,$SITE_HOST_NATIVE cert=$CERT_ID"

# ---- 身份指纹盐播种（identity_behavior 依赖；与 run.sh 同口径 psql 夹具通道）----
docker exec -i jiuzhang-stage5-postgres psql -U "$PG_USER" -d "$PG_DB" -v ON_ERROR_STOP=1 >/dev/null <<SQL
INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, description)
VALUES ('gateway_runtime','identity_salt','"$IDENTITY_SALT"','string','bot-browsers：身份指纹盐（随机，仅本轮栈）')
ON CONFLICT (setting_group, setting_key) DO UPDATE
SET setting_value = EXCLUDED.setting_value, updated_at = now(), version = system_settings.version + 1;
SQL
record "身份指纹盐（identity_salt）播种" 1

# ---- Bot 签名密钥播种（同 run.sh：psql + AES-256-GCM 现场加密，退出即清理）----
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
print("VALUES ('gateway_runtime','bot_signing_keys','\"%s\"','string','bot-browsers：Bot签名密钥（随机，仅本轮栈）')" % cipher)
print("ON CONFLICT (setting_group, setting_key) DO UPDATE")
print("SET setting_value = EXCLUDED.setting_value, updated_at = now(), version = system_settings.version + 1;")
PY
docker exec -i jiuzhang-stage5-postgres psql -U "$PG_USER" -d "$PG_DB" -v ON_ERROR_STOP=1 \
  < "$WORK_DIR/seed-keys.sql" >/dev/null
record "Bot 签名密钥（bot_signing_keys 密文）播种" 1

# ---- 启用身份行为观测（Bot 行为信号数据源；GLOBAL 策略）----
sec_api GET /api/v1/security/behavior-policy > "$WORK_DIR/behavior-policy.json"
python3 - "$WORK_DIR/behavior-policy.json" > "$WORK_DIR/behavior-policy-on.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))["data"]["policy"]
d["enabled"] = True
for k in ("id", "updated_by", "updated_at", "created_at"):
    d.pop(k, None)
print(json.dumps(d))
PY
expect_code "启用身份行为观测（behavior-policy enabled=true）" 200 \
  "$(sec_api_code PUT /api/v1/security/behavior-policy "$WORK_DIR/behavior-policy-on.json")"

# ---- Bot 策略 PROTECT 草稿（与 run.sh 同一可复算口径）----
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
    "reason": "bot-browsers: BOT-004/006 多浏览器与无障碍补证 PROTECT 草稿",
}))
PY
expect_code "保存 Bot 策略 PROTECT 草稿（乐观锁 v0）" 200 \
  "$(sec_api_code PUT "/api/v1/applications/$APP_ID/bot-policy" "$WORK_DIR/bot-policy.json")"

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
  sec_api GET "/api/v1/publish-tasks?page=1&page_size=3" \
    > "$EVIDENCE_DIR/publish-tasks.json" 2>/dev/null || true
fi
[ "$PUB" = "PUBLISH_OK" ] && record "PROTECT 配置发布成功（门禁通过）" 1 \
  || { record "PROTECT 配置发布成功（门禁通过）" 0 "$PUB"; echo ABORT; exit 1; }
wait_gateway_app 90 || { record "发布生效后网关 HTTPS 可达" 0 "超时"; echo ABORT; exit 1; }
record "发布生效后网关 HTTPS 可达" 1

# 双域名网关应答实证（第二域名不经 --resolve，系统解析器原生解析）
native_code="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 "$SITE_URL_NATIVE/" 2>/dev/null || echo 000)"
case "$native_code" in
  200|403) record "第二域名 $SITE_HOST_NATIVE 系统解析器原生解析并经网关应答（status=${native_code}）" 1 ;;
  *) record "第二域名 $SITE_HOST_NATIVE 系统解析器原生解析并经网关应答" 0 "status=${native_code}" ;;
esac

echo "============================================================"
echo "BOT-004 多浏览器通道（@browser 跨 projects）+ BOT-006 @a11y"
echo "============================================================"
# Playwright 可用性预检（浏览器二进制缺失时对应通道如实 BLOCKED）。
ln -sfn ../../../web/node_modules "$REPO_ROOT/test/e2e/bot-challenge/node_modules"
PW_CHANNELS=(chromium firefox webkit mobile-safari mobile-chrome)
declare -a CH_OK=()
PW_ANY=0
for ch in "${PW_CHANNELS[@]}"; do
  engine="$ch"
  case "$ch" in mobile-safari) engine=webkit ;; mobile-chrome) engine=chromium ;; esac
  bin="$(cd web && node -e "try{console.log(require('playwright-core').${engine}.executablePath())}catch(e){process.exit(1)}" 2>/dev/null || true)"
  if [ -n "$bin" ] && [ -x "$bin" ]; then CH_OK+=("$ch"); PW_ANY=1
  else blocked "BOT-004 通道 $ch" "Playwright $engine 浏览器二进制不可用（ENVIRONMENT_UNAVAILABLE；可 cd web && npx playwright install $engine 后重跑）"; fi
done

if [ "$PW_ANY" != "1" ]; then
  blocked "BOT-006 @a11y 组" "Playwright/Chromium 不可用（ENVIRONMENT_UNAVAILABLE）"
else
  export BOT_BENCH_SITE_URL="$SITE_URL"
  export BOT_BENCH_SITE_HOST="$SITE_HOST"
  export BOT_BENCH_SITE_URL_NATIVE="$SITE_URL_NATIVE"
  export BOT_BENCH_REPORT_DIR="$REPO_ROOT/$EVIDENCE_DIR"
  for ch in "${CH_OK[@]}"; do
    echo "[pw] BOT-004 通道：$ch"
    set +e
    (cd web && npx playwright test \
      --config ../test/e2e/bot-challenge/playwright.config.ts \
      --project="$ch" \
      --grep "@browser" \
      --reporter=json > "$REPO_ROOT/$EVIDENCE_DIR/group-browser.$ch.playwright.json" 2>&1)
    pw_rc=$?
    set -e
    echo "[pw] 通道 $ch 退出码=${pw_rc}（报告 $EVIDENCE_DIR/group-browser.$ch.playwright.json）"
    if [ "$pw_rc" = "0" ]; then
      record "BOT-004 通道 ${ch}：挑战→verify 204→clearance→REACHED_ORIGIN 全链路通过" 1
    else
      record "BOT-004 通道 ${ch}：挑战→verify 204→clearance→REACHED_ORIGIN 全链路通过" 0 "退出码=${pw_rc}，详见 group-browser.$ch.playwright.json"
    fi
  done

  # BOT-006 @a11y 组（固定 chromium 通道；chromium 不可用时上面已 BLOCKED 该通道）
  if printf '%s\n' "${CH_OK[@]}" | grep -qx chromium; then
    echo "[pw] BOT-006 @a11y 组（chromium）"
    set +e
    (cd web && npx playwright test \
      --config ../test/e2e/bot-challenge/playwright.config.ts \
      --project=chromium \
      --grep "@a11y" \
      --reporter=json > "$REPO_ROOT/$EVIDENCE_DIR/group-a11y.chromium.playwright.json" 2>&1)
    pw_rc=$?
    set -e
    echo "[pw] @a11y 组退出码=${pw_rc}"
    if [ "$pw_rc" = "0" ]; then
      record "BOT-006 慢设备（CPU 6x 节流）求解无长阻塞并通行" 1
      record "BOT-006 键盘导航：失败态可读、仅键盘重试并通行、焦点可见" 1
    else
      record "BOT-006 @a11y 组（慢设备 + 键盘导航）" 0 "退出码=${pw_rc}，详见 group-a11y.chromium.playwright.json"
    fi
  else
    blocked "BOT-006 @a11y 组" "Playwright Chromium 不可用（ENVIRONMENT_UNAVAILABLE）"
  fi
fi

# ---- 通道汇总（从各通道 result.json 提取关键指标，便于复核）----
python3 - "$EVIDENCE_DIR" <<'PY' > "$EVIDENCE_DIR/channels-summary.json"
import glob, json, os, sys
ev = sys.argv[1]
rows = []
for f in sorted(glob.glob(os.path.join(ev, "group-browser.*.result.json"))):
    rows.append(json.load(open(f)))
print(json.dumps({"channels": rows}, ensure_ascii=False, indent=2))
PY

# ---- 汇总与证据落盘 ----
echo "============================================================"
echo "P1-02 BOT-004/006 补证汇总: 总项 $TOTAL 通过 $PASS 失败 $FAIL 阻塞 $BLOCKED"
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
    "task": "P1-02 BOT-004 多浏览器通道 + BOT-006 慢设备/键盘导航补证",
    "finished_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "totals": {"total": total, "pass": passed, "fail": failed, "blocked": blocked_n},
    "groups": {
        "browser-channels": {"evidence": "group-browser.<channel>.playwright.json / group-browser.<channel>.result.json", "channels": ["chromium", "firefox", "webkit", "mobile-safari", "mobile-chrome"]},
        "a11y": {"evidence": "group-a11y.chromium.playwright.json / group-a11y-*.result.json / group-a11y-keyboard.aria-snapshot.yml"},
        "summary": {"evidence": "channels-summary.json"},
    },
    "verdict": "FAIL" if failed > 0 else ("PASS" if blocked_n == 0 else "PASS_WITH_BLOCKED"),
}
with open(os.path.join(ev, "status.json"), "w") as f:
    json.dump(status, f, ensure_ascii=False, indent=2)
PY

SCRIPT_DONE=1
[ "$FAIL" -eq 0 ]
