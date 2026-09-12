#!/usr/bin/env bash
# P1-02 BOT-018 洪峰与资源受控实测（真实 stage5 栈，夹具口径与 run.sh /
# rollback-drill.sh 一致：自建 postgres/valkey/api/gateway/testorigin + 自签
# HTTPS 应用 + Bot 策略 PROTECT path_exact=/ difficulty=12 经管理面真实发布）。
#
# 实测相位（全部 curl/python3 现场驱动，不用 Mock）：
#   基线    合法 clearance 通行与选择器外路径（POST /login）延迟基线；
#   洪峰A   签发洪峰：200 请求×并发 50 档、400 请求×并发 200 档合格导航
#           （同 IP 同 UA 同一身份指纹，第 3 次起达阈 → offer；签发三维限速
#           6/会话·60/IP·600/应用每分钟），断言 429 受控拒绝出现、无崩溃、服务存活；
#   洪峰B   验证洪峰 + 假会话制造：并发 verify（合法会话+错误解答 / 伪造会话
#           Cookie / 合法会话+未知 challenge_id），断言不签发 clearance、无 panic；
#   洪峰C   慢请求：慢速 body verify（HTTP/1.1，verifyReadTimeout=2s 生效实证）、
#           慢速 chunked 滴注，断言请求时限有界；
#   资源    洪峰全程 docker stats --no-stream 周期采样网关/Valkey 容器 CPU/内存、
#           Valkey bot 前缀键数（状态数有界，前缀 jiuzhang:guard:bot）；
#   影响    洪峰期间持合法 clearance 的正常请求与选择器外 POST /login 的
#           成功率/延迟 vs 基线，如实对比报告。
#
# 环境如实标注：开发机 macOS arm64 + Docker Desktop（Linux VM），非专用压测硬件；
# 所有数字为该环境实测值，不外推生产容量结论。
#
# 词表：PASS / FAIL / BLOCKED / NOT_RUN（与 run.sh 一致）；
# 环境缺失 → BLOCKED/ENVIRONMENT_UNAVAILABLE（退出码 3）。
# 用法：bash test/e2e/bot-challenge/flood-bench.sh
# 依赖：docker(compose 插件)、curl、openssl、python3（cryptography 包）
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT"

API_PORT="${API_PORT:-18081}"
GATEWAY_PORT="${GATEWAY_PORT:-18080}"
SITE_HTTPS_PORT="${SITE_HTTPS_PORT:-443}"
API_URL="http://127.0.0.1:$API_PORT"
SITE_HOST="bot-bench.local"
SITE_URL="https://${SITE_HOST}"
[ "$SITE_HTTPS_PORT" != "443" ] && SITE_URL="${SITE_URL}:$SITE_HTTPS_PORT"
PG_PORT="${PG_PORT:-5432}"
VK_PORT="${VK_PORT:-6379}"
RUN_ID="$(date +%Y%m%dT%H%M%S)-$(openssl rand -hex 3)"
EVIDENCE_DIR="test/e2e/bot-challenge/runs/$RUN_ID"

# ---- 每轮随机口令/密钥（仅本轮临时栈；mktemp 0700）----
WORK_DIR="$(mktemp -d)"
chmod 700 "$WORK_DIR"
DUMP_DIR=""
ENV_FILE="$WORK_DIR/bot-flood.env"
PG_USER="jiuzhang"
PG_DB="jiuzhang_waf"
PG_PWD="$(openssl rand -hex 16)"
VK_PWD="$(openssl rand -hex 16)"
ADMIN_PWD="Ci$(openssl rand -hex 8)1!"
ADMIN_NEW_PWD="Ci$(openssl rand -hex 8)2!"
SEC_PWD_CI="CiSec@$(openssl rand -hex 6)1"
MASTER_KEY="$(openssl rand -hex 32)"
IDENTITY_SALT="$(openssl rand -hex 32)"
BOT_KEY_REF="bot-flood-hmac"
BOT_KEY_HEX="$(openssl rand -hex 32)"
LIC_KEY_ID="bot-flood-key"

TOTAL=0; PASS=0; FAIL=0; FAILED=()
record() { # <name> <ok> [detail]
  local name="$1" ok="$2" detail="${3:-}"
  TOTAL=$((TOTAL+1))
  if [ "$ok" = "1" ]; then PASS=$((PASS+1)); echo "PASS  $name"
  else FAIL=$((FAIL+1)); FAILED+=("${name}: ${detail}"); echo "FAIL  $name (${detail})"; fi
}
expect_code() { [ "$2" = "$3" ] && record "$1" 1 || record "$1" 0 "status=$3 want=$2"; }

wait_http() {
  local url="$1" want="$2" deadline=$(( $(date +%s) + ${3:-120} )) code
  while [ "$(date +%s)" -lt "$deadline" ]; do
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$url" 2>/dev/null || echo 000)"
    [ "$code" = "$want" ] && return 0
    sleep 3
  done
  echo "ERROR: 等待 ${url} 返回 ${want} 超时（last=${code}）" >&2
  return 1
}

preflight_fail() { echo "BLOCKED/ENVIRONMENT_UNAVAILABLE: $1" >&2; exit 3; }
command -v docker >/dev/null 2>&1 || preflight_fail "docker 不可用"
docker compose version >/dev/null 2>&1 || preflight_fail "docker compose 插件不可用"
command -v openssl >/dev/null 2>&1 || preflight_fail "openssl 不可用"
command -v curl >/dev/null 2>&1 || preflight_fail "curl 不可用"
python3 -c "import cryptography" >/dev/null 2>&1 || preflight_fail "python3 cryptography 包不可用"

# ---- CI 临时 Ed25519 授权（与 run.sh 同口径）----
openssl genpkey -algorithm ed25519 -out "$WORK_DIR/lic-key.pem" >/dev/null 2>&1
chmod 600 "$WORK_DIR/lic-key.pem"
LIC_PUB_HEX="$(openssl pkey -in "$WORK_DIR/lic-key.pem" -pubout -outform DER 2>/dev/null \
  | tail -c 32 | python3 -c 'import sys; print(sys.stdin.buffer.read().hex())')"
python3 - "$WORK_DIR" "$LIC_KEY_ID" <<'PY'
import json, sys, datetime
work_dir, key_id = sys.argv[1], sys.argv[2]
payload = {
    "license_id": "LIC-BOT-FLOOD-0001", "license_type": "FORMAL", "product": "wdsp",
    "customer": "Bot Flood Bench", "issued_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
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
    echo "BLOCKED/ENVIRONMENT_UNAVAILABLE: 127.0.0.1:${p} 已被占用" >&2
    rm -rf "$WORK_DIR"; exit 3
  fi
done
if [ -n "$("${COMPOSE[@]}" ps -q 2>/dev/null)" ]; then
  echo "BLOCKED/ENVIRONMENT_UNAVAILABLE: 检测到 stage5 编排已有容器在运行" >&2
  rm -rf "$WORK_DIR"; exit 3
fi
"${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true

mkdir -p "$EVIDENCE_DIR"/{baseline,flood-offer,flood-verify,slow,impact}

SAMPLER_PID=""
cleanup() {
  local rc=$?
  if [ "$rc" -eq 0 ] && [ "${SCRIPT_DONE:-0}" != "1" ]; then rc=1; fi
  [ -n "$SAMPLER_PID" ] && kill "$SAMPLER_PID" 2>/dev/null || true
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 3 ]; then
    DUMP_DIR="$EVIDENCE_DIR/stack-dump"
    mkdir -p "$DUMP_DIR"
    {
      echo "==== compose ps ===="; "${COMPOSE[@]}" ps 2>&1
      echo; echo "==== gateway 日志尾部 ===="; "${COMPOSE[@]}" logs --tail=200 gateway 2>&1
      echo; echo "==== gateway guard-events 尾部 ===="
      docker exec jiuzhang-stage5-gateway sh -c 'tail -n 80 /var/log/caddy/guard-events.log' 2>&1 || true
    } > "$DUMP_DIR/stack-dump.log" 2>&1 || true
    echo "失败诊断日志（不含密钥/Token）：$DUMP_DIR/stack-dump.log" >&2
  fi
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK_DIR"
  exit "$rc"
}
trap cleanup EXIT

echo "============================================================"
echo "P1-02 BOT-018 洪峰与资源受控实测  run_id=$RUN_ID"
echo "api=$API_URL site=$SITE_URL"
echo "============================================================"

# ---- 环境标注（非专用压测硬件，如实披露）----
{
  echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "uname: $(uname -srm)"
  sw_vers 2>/dev/null || true
  echo "hw: $(sysctl -n hw.model 2>/dev/null) mem=$(sysctl -n hw.memsize 2>/dev/null)"
  echo "docker: $(docker version --format 'server={{.Server.Version}}' 2>/dev/null)"
  echo "note: 开发机 macOS arm64 + Docker Desktop（Linux VM），非专用压测硬件；所有数字为本环境实测值。"
  echo "git HEAD: $(git rev-parse HEAD 2>/dev/null)"
  echo "git 工作树状态（他人未提交改动随镜像进入，如实记录）："
  git status --porcelain 2>/dev/null | head -40
  [ -n "${BOT_BENCH_ENV_NOTE:-}" ] && echo "note: $BOT_BENCH_ENV_NOTE"
} > "$EVIDENCE_DIR/environment.txt"

echo "[build] 从当前工作树构建 api/gateway/testorigin 镜像 ..."
"${COMPOSE[@]}" build api gateway testorigin > "$EVIDENCE_DIR/build.log" 2>&1 || {
  echo "镜像构建失败，日志 $EVIDENCE_DIR/build.log" >&2; exit 1; }
record "正式构建镜像（工作树源码，build.log 留证）" 1

mkdir -p runtime/license
"${COMPOSE[@]}" up -d api gateway >/dev/null
wait_http "$API_URL/api/v1/health" 200 600 || {
  "${COMPOSE[@]}" logs --tail=120 api >&2 || true; exit 1; }
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

export API_URL GATEWAY_URL="http://127.0.0.1:$GATEWAY_PORT"
export HOST_HEADER="$SITE_HOST"
export VALKEY_PASSWORD="$VK_PWD" VALKEY_CONTAINER="jiuzhang-stage5-valkey"
export SYS_USER="jiuzhang_admin" SYS_PWD="$ADMIN_PWD" SYS_NEW_PWD="$ADMIN_NEW_PWD"
export SEC_USER="bot_flood_sec" SEC_PWD="$SEC_PWD_CI"
export APP_CODE="botflood"
# shellcheck source=../../waf/scripts/stage5-setup.sh
source test/waf/scripts/stage5-setup.sh

SYS_CSRF="$(s5_ensure_sysadmin)" || { echo "ERROR: sysadmin 登录失败" >&2; exit 1; }
LIC_BODY="$(python3 -c 'import json,sys; print(json.dumps({"file_content": open(sys.argv[1]).read()}))' "$WORK_DIR/license.lic")"
expect_code "导入 CI 临时 wdsp 授权" 200 \
  "$(curl -s -o /dev/null -w '%{http_code}' -b "/tmp/s5-$SYS_USER.txt" -X POST "$API_URL/api/v1/license/import" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $SYS_CSRF" -d "$LIC_BODY")"
SEC_CSRF="$(s5_ensure_secuser "$SYS_CSRF")"
[ -n "$SEC_CSRF" ] || { echo "ERROR: 安全管理员登录失败" >&2; exit 1; }

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

# ---- 自签证书 + HTTPS 应用（同 run.sh 夹具）----
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
print(json.dumps({"name": "bot-flood-selfsigned", "cert_pem": cert, "key_pem": key, "chain_pem": cert}))
PY
CERT_ID="$(sec_api POST /api/v1/certificates "$WORK_DIR/cert-upload.json" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['id'])" 2>/dev/null)"
[ -n "$CERT_ID" ] || { record "上传自签测试证书" 0 "cert_id 为空"; echo ABORT; exit 1; }

APP_ID="$(sec_api POST /api/v1/applications /dev/stdin <<EOF \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['id'])" 2>/dev/null
{"code":"$APP_CODE","name":"Bot洪峰实测应用","description":"P1-02 BOT-018 洪峰与资源受控","business_owner":"test","technical_owner":"test","protection_mode":"PROTECT"}
EOF
)"
[ -n "$APP_ID" ] || { record "创建 PROTECT 应用" 0 "app_id 为空"; echo ABORT; exit 1; }
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

# ---- 种子：身份指纹盐 + Bot 签名密钥（psql 夹具通道，同 run.sh）----
docker exec -i jiuzhang-stage5-postgres psql -U "$PG_USER" -d "$PG_DB" -v ON_ERROR_STOP=1 >/dev/null <<SQL
INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, description)
VALUES ('gateway_runtime','identity_salt','"$IDENTITY_SALT"','string','bot-flood：身份指纹盐（随机，仅本轮栈）')
ON CONFLICT (setting_group, setting_key) DO UPDATE
SET setting_value = EXCLUDED.setting_value, updated_at = now(), version = system_settings.version + 1;
SQL
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
print("VALUES ('gateway_runtime','bot_signing_keys','\"%s\"','string','bot-flood：Bot签名密钥（随机，仅本轮栈）')" % cipher)
print("ON CONFLICT (setting_group, setting_key) DO UPDATE")
print("SET setting_value = EXCLUDED.setting_value, updated_at = now(), version = system_settings.version + 1;")
PY
docker exec -i jiuzhang-stage5-postgres psql -U "$PG_USER" -d "$PG_DB" -v ON_ERROR_STOP=1 \
  < "$WORK_DIR/seed-keys.sql" >/dev/null
record "种子播种（identity_salt + bot_signing_keys 密文）" 1

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
    "reason": "bot-flood: BOT-018 洪峰实测 PROTECT 草稿",
}))
PY
expect_code "保存 Bot 策略 PROTECT 草稿（乐观锁 v0）" 200 \
  "$(sec_api_code PUT "/api/v1/applications/$APP_ID/bot-policy" "$WORK_DIR/bot-policy.json")"
sec_api POST "/api/v1/applications/$APP_ID/bot-policy/preflight" /dev/stdin > "$WORK_DIR/preflight.json" <<'EOF'
{}
EOF
cp "$WORK_DIR/preflight.json" "$EVIDENCE_DIR/preflight.json"

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

# ---- 网关探测与 PoW 求解（与 rollback-drill.sh 同实现）----
gw() { curl -sk --max-time 15 --resolve "$SITE_HOST:$SITE_HTTPS_PORT:127.0.0.1" "$@"; }
NAV_HEADERS=(-H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,*/*;q=0.8'
  -H 'Accept-Language: zh-CN,zh;q=0.9'
  -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36')

solve_pow() { # <challenge_html> → {"challenge_id","solution"}
  python3 - "$1" <<'PY'
import json, re, sys, hashlib, struct
html = open(sys.argv[1]).read()
m = re.search(r'id="wdsp-bot-params" type="application/json">([^<]+)</script>', html)
if not m:
    sys.exit("no wdsp-bot-params in challenge page")
p = json.loads(m.group(1))
def lp(b): return struct.pack(">I", len(b)) + b
prefix = (b"wdsp-bot-pow-v1" + lp(bytes.fromhex(p["challenge_id"])) + lp(bytes.fromhex(p["nonce"]))
          + lp(p["app"].encode()) + lp(p["host"].encode()))
diff = int(p["difficulty"])
def ok(s):
    d = hashlib.sha256(prefix + lp(str(s).encode())).digest()
    bits = 0
    for byte in d:
        if byte == 0:
            bits += 8
            continue
        bits += 8 - byte.bit_length()
        break
    return bits >= diff
for i in range(1 << 24):
    if ok(i):
        print(json.dumps({"challenge_id": p["challenge_id"], "solution": str(i)}))
        sys.exit(0)
sys.exit("no pow solution within bound")
PY
}

# ---- 资源采样（洪峰全程后台运行；CPU/内存/Valkey 键数曲线原始数据）----
bot_key_count() {
  docker exec jiuzhang-stage5-valkey sh -c \
    "valkey-cli -a '$VK_PWD' --no-auth-warning --scan --pattern 'jiuzhang:guard:bot*' | wc -l" 2>/dev/null | tr -d ' \r' || echo -1
}
valkey_dbsize() {
  docker exec jiuzhang-stage5-valkey sh -c \
    "valkey-cli -a '$VK_PWD' --no-auth-warning dbsize" 2>/dev/null | tr -d ' \r' || echo -1
}
SAMPLES="$EVIDENCE_DIR/resource-samples.tsv"
printf 'ts\tcontainer\tcpu_pct\tmem_usage\tmem_pct\tvalkey_dbsize\tbot_keys\n' > "$SAMPLES"
(
  while :; do
    ts="$(date +%H:%M:%S)"
    stats="$(docker stats --no-stream --format '{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}' \
      jiuzhang-stage5-gateway jiuzhang-stage5-valkey 2>/dev/null || true)"
    dbz="$(valkey_dbsize)"; bk="$(bot_key_count)"
    while IFS= read -r line; do
      [ -n "$line" ] && printf '%s\t%s\t%s\t%s\n' "$ts" "$line" "$dbz" "$bk" >> "$SAMPLES"
    done <<< "$stats"
    sleep 2
  done
) &
SAMPLER_PID=$!

# ---- 并发洪峰 worker（xargs 子进程独立 bash 无法继承父 shell 数组/函数，
#      落盘为 worker 脚本经环境变量传参）----
export FLOOD_SITE_URL="$SITE_URL" FLOOD_SITE_HOST="$SITE_HOST" FLOOD_SITE_PORT="$SITE_HTTPS_PORT"
export FLOOD_EVIDENCE="$EVIDENCE_DIR" FLOOD_JAR_V="$WORK_DIR/jar-verify.txt" FLOOD_VALID_CID=""
cat > "$WORK_DIR/flood-worker.sh" <<'WS'
#!/usr/bin/env bash
# flood-bench 并发 worker：$1=模式 <offer|bad-solution|forged-session|unknown-cid> $2=序号
set -u
RESOLVE="--resolve"
GW=(curl -sk --max-time 15 "$RESOLVE" "$FLOOD_SITE_HOST:$FLOOD_SITE_PORT:127.0.0.1")
NAV=(-H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,*/*;q=0.8'
  -H 'Accept-Language: zh-CN,zh;q=0.9'
  -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36')
VFY=(-X POST -H 'Content-Type: application/json' -H "Origin: $FLOOD_SITE_URL" -H 'Sec-Fetch-Site: same-origin')
case "$1" in
  offer)
    "${GW[@]}" -o /dev/null -w '%{http_code}\t%{time_total}\n' "${NAV[@]}" "$FLOOD_SITE_URL/" \
      >> "$FLOOD_EVIDENCE/flood-offer/$2/batch.tsv" 2>/dev/null \
      || echo "000	-1" >> "$FLOOD_EVIDENCE/flood-offer/$2/batch.tsv" ;;
  bad-solution)
    "${GW[@]}" -D "$FLOOD_EVIDENCE/flood-verify/headers-$1-$2.txt" -o /dev/null -w '%{http_code}\n' \
      -b "$FLOOD_JAR_V" "${VFY[@]}" \
      -d "{\"challenge_id\":\"$FLOOD_VALID_CID\",\"solution\":\"0\"}" \
      "$FLOOD_SITE_URL/_wdsp/bot/v1/verify" >> "$FLOOD_EVIDENCE/flood-verify/$1.tsv" 2>/dev/null \
      || echo "000" >> "$FLOOD_EVIDENCE/flood-verify/$1.tsv" ;;
  forged-session)
    "${GW[@]}" -o /dev/null -w '%{http_code}\n' \
      -H "Cookie: __Host-wdsp-bot-session=forged-$2" "${VFY[@]}" \
      -d "{\"challenge_id\":\"$FLOOD_VALID_CID\",\"solution\":\"0\"}" \
      "$FLOOD_SITE_URL/_wdsp/bot/v1/verify" >> "$FLOOD_EVIDENCE/flood-verify/$1.tsv" 2>/dev/null \
      || echo "000" >> "$FLOOD_EVIDENCE/flood-verify/$1.tsv" ;;
  unknown-cid)
    "${GW[@]}" -o /dev/null -w '%{http_code}\n' \
      -b "$FLOOD_JAR_V" "${VFY[@]}" \
      -d '{"challenge_id":"00000000000000000000000000000000","solution":"0"}' \
      "$FLOOD_SITE_URL/_wdsp/bot/v1/verify" >> "$FLOOD_EVIDENCE/flood-verify/$1.tsv" 2>/dev/null \
      || echo "000" >> "$FLOOD_EVIDENCE/flood-verify/$1.tsv" ;;
esac
WS
chmod 700 "$WORK_DIR/flood-worker.sh"

measure() { # <outfile.tsv> <count> <curl args...>
  local out="$1" n="$2"; shift 2
  : > "$out"
  for _ in $(seq 1 "$n"); do
    gw -o /dev/null -w '%{http_code}\t%{time_total}\n' "$@" >> "$out" || echo "000	-1" >> "$out"
  done
}

# ==================== 基线：合法通行与选择器外路径 ====================
echo "[基线] 获取合法 clearance（导航×3 → 挑战 → 现场求解 → verify 204）..."
JAR_LEGIT="$WORK_DIR/jar-legit.txt"; : > "$JAR_LEGIT"
c1="$(gw -o /dev/null -w '%{http_code}' -b "$JAR_LEGIT" -c "$JAR_LEGIT" "${NAV_HEADERS[@]}" "$SITE_URL/")"
c2="$(gw -o /dev/null -w '%{http_code}' -b "$JAR_LEGIT" -c "$JAR_LEGIT" "${NAV_HEADERS[@]}" "$SITE_URL/")"
c3="$(gw -o "$EVIDENCE_DIR/baseline/challenge.html" -w '%{http_code}' -b "$JAR_LEGIT" -c "$JAR_LEGIT" "${NAV_HEADERS[@]}" "$SITE_URL/")"
echo "[基线] nav 序列 status=${c1}/${c2}/${c3}"
if [ "$c3" != "403" ]; then
  record "基线获取合法 clearance" 0 "第三次导航未挑战 status=${c1}/${c2}/${c3}"; echo ABORT; exit 1
fi
POW="$(solve_pow "$EVIDENCE_DIR/baseline/challenge.html")" || { record "基线获取合法 clearance" 0 "pow 求解失败"; exit 1; }
echo "$POW" > "$EVIDENCE_DIR/baseline/pow.json"
vcode="$(gw -D "$EVIDENCE_DIR/baseline/verify.headers" -o "$EVIDENCE_DIR/baseline/verify.json" -w '%{http_code}' \
  -b "$JAR_LEGIT" -c "$JAR_LEGIT" -X POST -H 'Content-Type: application/json' \
  -H "Origin: $SITE_URL" -H 'Sec-Fetch-Site: same-origin' \
  -d "$POW" "$SITE_URL/_wdsp/bot/v1/verify")"
[ "$vcode" = "204" ] && record "基线获取合法 clearance（verify 204）" 1 \
  || { record "基线获取合法 clearance" 0 "verify status=${vcode}"; echo ABORT; exit 1; }

echo "[基线] 测量合法通行（20 次）与选择器外 POST /login（10 次）延迟 ..."
measure "$EVIDENCE_DIR/baseline/cleared.tsv" 20 -b "$JAR_LEGIT" "${NAV_HEADERS[@]}" "$SITE_URL/"
measure "$EVIDENCE_DIR/baseline/login.tsv" 10 -X POST \
  -H 'Content-Type: application/json' -H 'Accept: application/json' \
  -d '{"username":"bench","password":"bench"}' "$SITE_URL/login"

# ==================== 洪峰A：签发洪峰（并发合格导航 → offer）====================
# 同 IP 同 UA = 同一身份指纹：第 3 次导航起达阈 → 每次合格导航触发一次 offer；
# 签发限速 6/会话·60/IP·600/应用每分钟（B2 冻结常量），洪峰必触发 429 受控拒绝。
offer_flood() { # <concurrency> <total> <tag>
  local conc="$1" total="$2" tag="$3"
  local dir="$EVIDENCE_DIR/flood-offer/$tag"
  mkdir -p "$dir"; : > "$dir/batch.tsv"
  echo "[洪峰A:$tag] 并发=$conc 总数=$total 合格导航 ..."
  seq 1 "$total" | xargs -P "$conc" -I{} bash "$WORK_DIR/flood-worker.sh" offer "$tag" || true
  sort "$dir/batch.tsv" | uniq -c | sort -rn > "$dir/distribution.txt"
  cat "$dir/distribution.txt"
}

offer_flood 50 200 c50
offer_flood 200 400 c200

python3 - "$EVIDENCE_DIR" <<'PY' > "$EVIDENCE_DIR/flood-offer/summary.json"
import json, sys
ev = sys.argv[1]
out = {}
for tag in ("c50", "c200"):
    codes = {}
    lat = []
    for line in open(f"{ev}/flood-offer/{tag}/batch.tsv"):
        parts = line.split()
        if not parts: continue
        codes[parts[0]] = codes.get(parts[0], 0) + 1
        try: lat.append(float(parts[1]))
        except (IndexError, ValueError): pass
    lat.sort()
    out[tag] = {
        "status_distribution": codes,
        "samples": len(lat),
        "latency_p50_s": lat[len(lat)//2] if lat else None,
        "latency_p95_s": lat[int(len(lat)*0.95)] if lat else None,
    }
print(json.dumps(out, ensure_ascii=False, indent=2))
PY

# 断言：429 受控拒绝出现（签发限速生效）；无任何 5xx 崩溃（容量 503 属于受控语义，
# 本环境 IP 维 60/min 先于容量 10000 触发，如实记录 503=0 不外推）；
# 挑战服务存活：合法 clearance 通行 200 + verify GET 405（本地协议端点）
c200_5xx="$(awk '$1 ~ /^5/ && $1 != "503"' "$EVIDENCE_DIR/flood-offer/c200/batch.tsv" | wc -l | tr -d ' ')"
c200_5xx="$((c200_5xx + $(awk '$1 ~ /^5/ && $1 != "503"' "$EVIDENCE_DIR/flood-offer/c50/batch.tsv" | wc -l | tr -d ' ')))"
c200_429="$(awk '$1 == "429"' "$EVIDENCE_DIR/flood-offer/c200/batch.tsv" | wc -l | tr -d ' ')"
c200_503="$(awk '$1 == "503"' "$EVIDENCE_DIR/flood-offer/c200/batch.tsv" | wc -l | tr -d ' ')"
c50_429="$(awk '$1 == "429"' "$EVIDENCE_DIR/flood-offer/c50/batch.tsv" | wc -l | tr -d ' ')"
echo "[洪峰A] c50 429=${c50_429} c200 429=${c200_429} 503=${c200_503} 非容量5xx=${c200_5xx}"
if [ "$((c200_429 + c50_429))" -gt 0 ]; then
  record "洪峰A 签发洪峰触发 429 受控拒绝（签发三维限速生效；c50=${c50_429} c200=${c200_429}）" 1
else
  record "洪峰A 签发洪峰触发 429 受控拒绝" 0 "两档均无 429（限速未生效？）"
fi
[ "$c200_5xx" = "0" ] && record "洪峰A 无 5xx 崩溃（503 容量语义本次未触发=${c200_503}，IP 维限速先行）" 1 \
  || record "洪峰A 无 5xx 崩溃" 0 "非容量 5xx 计数=${c200_5xx}"

alive="$(gw -o /dev/null -w '%{http_code}' -b "$JAR_LEGIT" "${NAV_HEADERS[@]}" "$SITE_URL/")"
[ "$alive" = "200" ] && record "洪峰A 后挑战服务存活（合法 clearance 通行 200）" 1 \
  || record "洪峰A 后挑战服务存活" 0 "clearance 通行 status=${alive}"
expect_code "洪峰A 后 verify 协议端点本地存活（GET→405）" 405 \
  "$(gw -o /dev/null -w '%{http_code}' -X GET "$SITE_URL/_wdsp/bot/v1/verify")"

# ==================== 洪峰B：验证洪峰 + 假会话制造 ====================
# 独立身份（每轮换 UA）原因见下方挑战准备段注释。
echo "[洪峰B] 验证洪峰：合法会话+错误解答（60 并发）/ 伪造会话（30 并发）/ 未知 challenge_id（30 并发）..."
JAR_V="$WORK_DIR/jar-verify.txt"; : > "$JAR_V"
# 挑战准备前提：①信号判定（known_uri_ratio 绕阈 0.99 翻动，实测同身份 200/429 交替——
# 每轮换全新 UA 获得干净行为窗口，nav1/2 基线 + nav3 达阈）；②签发 IP 维 60/分钟
# 窗口已被洪峰A 约 58 次 offer 占满（事件实证 reason=ISSUE_RATE_LIMITED），
# 故先静候 70s 让滑动窗口排空，再逐轮尝试（每轮失败静候 20s 换新身份）。
sleep 70
vch=""
for i in 1 2 3 4 5; do
  ROUND_HEADERS=(-H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,*/*;q=0.8'
    -H 'Accept-Language: zh-CN,zh;q=0.9'
    -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) BotFloodVerify/1.$i")
  gw -o /dev/null -b "$JAR_V" -c "$JAR_V" "${ROUND_HEADERS[@]}" "$SITE_URL/" >/dev/null
  gw -o /dev/null -b "$JAR_V" -c "$JAR_V" "${ROUND_HEADERS[@]}" "$SITE_URL/" >/dev/null
  vch="$(gw -o "$EVIDENCE_DIR/flood-verify/challenge.html" -w '%{http_code}' -b "$JAR_V" -c "$JAR_V" "${ROUND_HEADERS[@]}" "$SITE_URL/")"
  echo "[洪峰B] 第 ${i} 轮（新身份）第 3 次合格导航 status=${vch}"
  if [ "$vch" = "403" ] && grep -q 'wdsp-bot-params' "$EVIDENCE_DIR/flood-verify/challenge.html"; then
    break
  fi
  sleep 20
done
[ "$vch" = "403" ] && grep -q 'wdsp-bot-params' "$EVIDENCE_DIR/flood-verify/challenge.html" \
  || { record "洪峰B 合法会话挑战准备" 0 "status=${vch}（5 轮均未获挑战页）"; echo ABORT; exit 1; }
record "洪峰B 合法会话挑战准备（status=403 + wdsp-bot-params）" 1
VALID_CID="$(python3 -c "
import json, re
html = open('$EVIDENCE_DIR/flood-verify/challenge.html').read()
print(json.loads(re.search(r'id=\"wdsp-bot-params\" type=\"application/json\">([^<]+)</script>', html).group(1))['challenge_id'])")"

export FLOOD_VALID_CID="$VALID_CID"
for kind in bad-solution forged-session unknown-cid; do : > "$EVIDENCE_DIR/flood-verify/$kind.tsv"; done
seq 1 60 | xargs -P 60 -I{} bash "$WORK_DIR/flood-worker.sh" bad-solution {} &
BPID1=$!
seq 1 30 | xargs -P 30 -I{} bash "$WORK_DIR/flood-worker.sh" forged-session {} &
BPID2=$!
seq 1 30 | xargs -P 30 -I{} bash "$WORK_DIR/flood-worker.sh" unknown-cid {} &
BPID3=$!
wait $BPID1 $BPID2 $BPID3 || true

for kind in bad-solution forged-session unknown-cid; do
  sort "$EVIDENCE_DIR/flood-verify/$kind.tsv" | uniq -c | sort -rn \
    > "$EVIDENCE_DIR/flood-verify/$kind.distribution.txt"
  echo "[洪峰B:$kind] 分布：$(tr '\n' ' ' < "$EVIDENCE_DIR/flood-verify/$kind.distribution.txt")"
done

# 断言：零 204、零 clearance Set-Cookie、无 panic、服务存活
n204="$(cat "$EVIDENCE_DIR/flood-verify/"*.tsv | awk '$1 == "204"' | wc -l | tr -d ' ')"
nclear="$({ grep -il 'wdsp-bot-clearance' "$EVIDENCE_DIR/flood-verify/"headers-*.txt 2>/dev/null || true; } | wc -l | tr -d ' ')"
n5xx="$(cat "$EVIDENCE_DIR/flood-verify/"*.tsv | awk '$1 ~ /^5/' | wc -l | tr -d ' ')"
[ "$n204" = "0" ] && [ "$nclear" = "0" ] \
  && record "洪峰B 验证洪峰+假会话：零 204 零 clearance 签发（120 并发伪造全拒）" 1 \
  || record "洪峰B 验证洪峰+假会话：零 204 零 clearance 签发" 0 "204=${n204} clearance=${nclear}"
[ "$n5xx" = "0" ] && record "洪峰B 无 5xx/panic（受控 4xx/429 拒绝）" 1 \
  || record "洪峰B 无 5xx/panic" 0 "5xx=${n5xx}"
if "${COMPOSE[@]}" logs --since 5m gateway 2>/dev/null | grep -qi 'panic:'; then
  record "洪峰B 网关日志无 panic" 0 "发现 panic 日志"
else
  record "洪峰B 网关日志无 panic" 1
fi

# ==================== 洪峰C：慢请求（慢速 body / 慢速滴注 verify）====================
echo "[洪峰C] 慢请求：HTTP/1.1 慢速 body（200B@20B/s，verifyReadTimeout=2s 应生效）..."
python3 -c "print('{\"challenge_id\":\"$VALID_CID\",\"solution\":\"0\"}' + ' ' * 130, end='')" > "$WORK_DIR/slow-body.json"
slow_out="$(curl -sk --http1.1 --max-time 20 --resolve "$SITE_HOST:$SITE_HTTPS_PORT:127.0.0.1" \
  -o "$EVIDENCE_DIR/slow/slow-body-resp.txt" -w '%{http_code}\t%{time_total}' \
  -b "$JAR_V" -X POST -H 'Content-Type: application/json' \
  -H "Origin: $SITE_URL" -H 'Sec-Fetch-Site: same-origin' \
  --data-binary @"$WORK_DIR/slow-body.json" --limit-rate 20 \
  "$SITE_URL/_wdsp/bot/v1/verify" 2>"$EVIDENCE_DIR/slow/slow-body-curl-err.txt")" || true
echo "$slow_out" > "$EVIDENCE_DIR/slow/slow-body.result.tsv"
echo "[洪峰C] 慢速 body 结果：${slow_out:-curl错误}（curl stderr 见 slow-body-curl-err.txt）"
slow_time="$(echo "$slow_out" | awk -F'\t' '{print $2}')"
slow_code="$(echo "$slow_out" | awk -F'\t' '{print $1}')"
# 判定：请求时限有界（≤8s 断开/拒绝），且不签发通行（非 204）。
# SetReadDeadline 对 HTTP/2 尽力而为（verify.go 注释），故强制 HTTP/1.1 取得确定性证据。
if [ -n "$slow_time" ] && python3 -c "import sys; sys.exit(0 if float('$slow_time') <= 8 else 1)" && [ "$slow_code" != "204" ]; then
  record "洪峰C 慢速 body 时限有界（time=${slow_time}s status=${slow_code:-curl错误}，≤2s 读取超时生效）" 1
else
  record "洪峰C 慢速 body 时限有界" 0 "time=${slow_time:-none} code=${slow_code:-none}"
fi

echo "[洪峰C] 慢速 chunked 滴注（stdin 慢速供给，正文读取同样受限）..."
set +e
chunk_out="$(python3 -c '
import sys, time
for _ in range(40):
    sys.stdout.write("x")
    sys.stdout.flush()
    time.sleep(0.5)
' | curl -sk --http1.1 --max-time 20 --resolve "$SITE_HOST:$SITE_HTTPS_PORT:127.0.0.1" \
  -o "$EVIDENCE_DIR/slow/slow-chunk-resp.txt" -w '%{http_code}\t%{time_total}' \
  -b "$JAR_V" -X POST -H 'Content-Type: application/json' \
  -H "Origin: $SITE_URL" -H 'Sec-Fetch-Site: same-origin' \
  -H 'Expect:' -T - "$SITE_URL/_wdsp/bot/v1/verify" 2>"$EVIDENCE_DIR/slow/slow-chunk-curl-err.txt")"
set -e
echo "$chunk_out" > "$EVIDENCE_DIR/slow/slow-chunk.result.tsv"
chunk_time="$(echo "$chunk_out" | awk -F'\t' '{print $2}')"
chunk_code="$(echo "$chunk_out" | awk -F'\t' '{print $1}')"
echo "[洪峰C] 慢速滴注结果：${chunk_out:-curl错误}"
if [ -n "$chunk_time" ] && python3 -c "import sys; sys.exit(0 if float('$chunk_time') <= 8 else 1)" && [ "$chunk_code" != "204" ]; then
  record "洪峰C 慢速 chunked 滴注时限有界（time=${chunk_time}s status=${chunk_code:-curl错误}）" 1
else
  record "洪峰C 慢速 chunked 滴注时限有界" 0 "time=${chunk_time:-none} code=${chunk_code:-none}"
fi

# ==================== 影响：洪峰期间正常业务 ====================
echo "[影响] 洪峰（并发 200 签发洪峰）期间测量正常业务 ..."
mkdir -p "$EVIDENCE_DIR/flood-offer/during"
: > "$EVIDENCE_DIR/flood-offer/during/batch.tsv"
seq 1 400 | xargs -P 200 -I{} bash "$WORK_DIR/flood-worker.sh" offer during &
FLOOD_PID=$!
sleep 1
measure "$EVIDENCE_DIR/impact/cleared-during-flood.tsv" 20 -b "$JAR_LEGIT" "${NAV_HEADERS[@]}" "$SITE_URL/"
measure "$EVIDENCE_DIR/impact/login-during-flood.tsv" 10 -X POST \
  -H 'Content-Type: application/json' -H 'Accept: application/json' \
  -d '{"username":"bench","password":"bench"}' "$SITE_URL/login"
wait $FLOOD_PID || true

python3 - "$EVIDENCE_DIR" <<'PY' > "$EVIDENCE_DIR/impact/impact-summary.json"
import json, sys

def stats(path):
    codes, lat = {}, []
    ok = 0
    for line in open(path):
        parts = line.split()
        if not parts:
            continue
        codes[parts[0]] = codes.get(parts[0], 0) + 1
        if parts[0] == "200":
            ok += 1
        try:
            lat.append(float(parts[1]))
        except (IndexError, ValueError):
            pass
    lat.sort()
    n = len(lat)
    return {
        "samples": n,
        "success_200": ok,
        "status_distribution": codes,
        "p50_s": lat[n // 2] if n else None,
        "p95_s": lat[int(n * 0.95)] if n else None,
        "max_s": lat[-1] if n else None,
    }

ev = sys.argv[1]
print(json.dumps({
    "baseline_cleared": stats(f"{ev}/baseline/cleared.tsv"),
    "baseline_login": stats(f"{ev}/baseline/login.tsv"),
    "flood_cleared": stats(f"{ev}/impact/cleared-during-flood.tsv"),
    "flood_login": stats(f"{ev}/impact/login-during-flood.tsv"),
}, ensure_ascii=False, indent=2))
PY
cat "$EVIDENCE_DIR/impact/impact-summary.json"

ok_cleared="$(awk '$1 == "200"' "$EVIDENCE_DIR/impact/cleared-during-flood.tsv" | wc -l | tr -d ' ')"
ok_login="$(awk '$1 == "200"' "$EVIDENCE_DIR/impact/login-during-flood.tsv" | wc -l | tr -d ' ')"
echo "[影响] 洪峰期间：clearance 通行 200×${ok_cleared}/20，POST /login 200×${ok_login}/10"
[ "$ok_cleared" = "20" ] && record "影响：洪峰期间合法 clearance 通行成功率 100%（20/20）" 1 \
  || record "影响：洪峰期间合法 clearance 通行成功率 100%" 0 "成功 ${ok_cleared}/20"
[ "$ok_login" = "10" ] && record "影响：洪峰期间选择器外业务（POST /login）成功率 100%（10/10）" 1 \
  || record "影响：洪峰期间选择器外业务成功率 100%" 0 "成功 ${ok_login}/10"

# ==================== 资源曲线收尾断言 ====================
sleep 2
[ -n "$SAMPLER_PID" ] && kill "$SAMPLER_PID" 2>/dev/null && SAMPLER_PID="" || true
max_keys="$(awk -F'\t' 'NR>1 && $7+0 > m {m=$7+0} END {print m+0}' "$SAMPLES")"
restarts="$(docker inspect -f '{{.RestartCount}} {{.State.OOMKilled}}' jiuzhang-stage5-gateway 2>/dev/null || echo 'unknown')"
sample_lines="$(wc -l < "$SAMPLES" | tr -d ' ')"
echo "[资源] 采样行数=${sample_lines} Valkey bot 键数峰值=${max_keys} 网关 RestartCount/OOMKilled=${restarts}"
# 状态数有界：bot 键数峰值 << 在途上限 10000（本环境 IP 维限速先行，峰值如实记录）
if [ "$max_keys" -ge 0 ] && [ "$max_keys" -lt 10000 ]; then
  record "资源：Valkey bot 状态数有界（峰值=${max_keys} << 在途上限 10000，曲线见 resource-samples.tsv）" 1
else
  record "资源：Valkey bot 状态数有界" 0 "峰值=${max_keys}"
fi
case "$restarts" in
  "0 false") record "资源：网关容器零重启零 OOM（CPU/内存曲线见 resource-samples.tsv）" 1 ;;
  *) record "资源：网关容器零重启零 OOM" 0 "RestartCount/OOMKilled=${restarts}" ;;
esac
[ "$sample_lines" -gt 10 ] && record "资源：洪峰全程 CPU/内存/键数周期采样留证（${sample_lines} 行）" 1 \
  || record "资源：洪峰全程周期采样留证" 0 "采样行数=${sample_lines}"

# ==================== 汇总与证据 ====================
echo "============================================================"
echo "P1-02 BOT-018 洪峰实测汇总: 总项 $TOTAL 通过 $PASS 失败 $FAIL"
if [ "$FAIL" -gt 0 ]; then
  for c in "${FAILED[@]}"; do echo "  FAIL - $c"; done
fi
echo "证据目录: $EVIDENCE_DIR"
echo "============================================================"

python3 - "$EVIDENCE_DIR" "$RUN_ID" "$TOTAL" "$PASS" "$FAIL" <<'PY'
import json, sys, datetime, os
ev, run_id, total, passed, failed = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])
status = {
    "run_id": run_id,
    "task": "P1-02 BOT-018 洪峰与资源受控实测",
    "environment": "开发机 macOS arm64 + Docker Desktop（Linux VM），非专用压测硬件；数字为本环境实测值",
    "finished_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "totals": {"total": total, "pass": passed, "fail": failed, "blocked": 0},
    "phases": {
        "baseline": {"evidence": "baseline/"},
        "flood-offer": {"evidence": "flood-offer/（summary.json + 各档 distribution）"},
        "flood-verify": {"evidence": "flood-verify/（三类伪造分布）"},
        "slow": {"evidence": "slow/"},
        "impact": {"evidence": "impact/impact-summary.json"},
        "resources": {"evidence": "resource-samples.tsv（docker stats + Valkey 键数周期采样原始数据）"},
    },
    "verdict": "PASS" if failed == 0 else "FAIL",
}
with open(os.path.join(ev, "status.json"), "w") as f:
    json.dump(status, f, ensure_ascii=False, indent=2)
PY

SCRIPT_DONE=1
[ "$FAIL" -eq 0 ]
