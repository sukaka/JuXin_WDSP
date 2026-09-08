#!/usr/bin/env bash
# P1-04 R2 回归专用 stage5 隔离栈拉起（真实栈回放环境）：
# 栈：deployment/docker-compose.stage5.yml + docker-compose.wdsp.yml + test-license，
# 双 HTTPS 应用（OBSERVE=DetectionOnly / PROTECT=On，均回 testorigin）、
# Bot 策略（OBSERVE/PROTECT 各一，选择器 path_exact=/，行为双信号组）、
# 5 条自定义规则（webshell/cloud_abuse/ssti/xxe/double-encode，7100001-7100005）。
# 口令/密钥每轮随机（mktemp 0700），退出不下栈（供多次 regression/compare 运行），
# 清理用同目录 stack-down.sh。
#
# 用法：bash test/regression/p1/stage5/stack-up.sh <descriptor-out-path>
#   成功写出环境描述符 JSON（0600，含管理面只读 Cookie——敏感，禁止入证据/git），
#   stdout 打印描述符路径；失败非零退出并下栈。
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
cd "$REPO_ROOT"

DESC_OUT="${1:?用法: stack-up.sh <descriptor-out-path>}"

API_PORT="${API_PORT:-18081}"
GATEWAY_PORT="${GATEWAY_PORT:-18080}"
SITE_HTTPS_PORT="${SITE_HTTPS_PORT:-443}"
API_URL="http://127.0.0.1:$API_PORT"
PG_PORT="${PG_PORT:-5432}"
VK_PORT="${VK_PORT:-6379}"
STACK_ID="$(date +%Y%m%dT%H%M%S)-$(openssl rand -hex 3)"

OBS_HOST="p1reg-observe.local"
PROT_HOST="p1reg-protect.local"

WORK_DIR="$(mktemp -d)"
chmod 700 "$WORK_DIR"
ENV_FILE="$WORK_DIR/p1reg-stack.env"
PG_USER="jiuzhang"
PG_DB="jiuzhang_waf"
PG_PWD="$(openssl rand -hex 16)"
VK_PWD="$(openssl rand -hex 16)"
ADMIN_PWD="Ci$(openssl rand -hex 8)1!"
ADMIN_NEW_PWD="Ci$(openssl rand -hex 8)2!"
SEC_PWD_CI="CiSec@$(openssl rand -hex 6)1"
MASTER_KEY="$(openssl rand -hex 32)"
IDENTITY_SALT="$(openssl rand -hex 32)"
BOT_KEY_REF="p1reg-bot-hmac"
BOT_KEY_HEX="$(openssl rand -hex 32)"
LIC_KEY_ID="p1reg-stack-key"

log() { printf '[p1reg-stack %s] %s\n' "$(date '+%H:%M:%S')" "$*"; }
fail() { echo "ERROR: $*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || fail "docker 不可用"
docker compose version >/dev/null 2>&1 || fail "docker compose 插件不可用"
python3 -c "import cryptography" >/dev/null 2>&1 || fail "python3 cryptography 包不可用"

# ---- CI 临时 Ed25519 授权（与 bot-challenge 同口径）----
openssl genpkey -algorithm ed25519 -out "$WORK_DIR/lic-key.pem" >/dev/null 2>&1
chmod 600 "$WORK_DIR/lic-key.pem"
LIC_PUB_HEX="$(openssl pkey -in "$WORK_DIR/lic-key.pem" -pubout -outform DER 2>/dev/null \
  | tail -c 32 | python3 -c 'import sys; print(sys.stdin.buffer.read().hex())')"
python3 - "$WORK_DIR" "$LIC_KEY_ID" <<'PY'
import json, sys, datetime
work_dir, key_id = sys.argv[1], sys.argv[2]
payload = {
    "license_id": "LIC-P1REG-STACK-0001", "license_type": "FORMAL", "product": "wdsp",
    "customer": "P1 Regression", "issued_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
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
payload = json.load(open(work_dir + "/lic-payload.bin"))
json.dump({"payload": payload, "signature": sig}, open(work_dir + "/license.lic", "w"))
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
  port_free "$p" || fail "127.0.0.1:$p 已被占用"
done
[ -z "$("${COMPOSE[@]}" ps -q 2>/dev/null)" ] || fail "检测到 stage5 编排已有容器在运行"
"${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true

cleanup_on_error() {
  local rc=$?
  if [ "$rc" -ne 0 ]; then
    "${COMPOSE[@]}" logs --tail=80 api gateway 2>&1 | tail -40 >&2 || true
    "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
    rm -rf "$WORK_DIR"
  fi
  exit "$rc"
}
trap cleanup_on_error EXIT

log "构建 api/gateway/testorigin 镜像（当前工作树）..."
"${COMPOSE[@]}" build api gateway testorigin >/dev/null
mkdir -p runtime/license
log "启动栈 ..."
"${COMPOSE[@]}" up -d api gateway >/dev/null

# GeoIP mmdb 注入：api 的 /app/runtime 是命名卷（不带仓库 runtime/geoip 内容），
# 缺失时 apigeo Sweeper 每周期 nil 指针 panic 导致 API 周期性崩溃重启（实测复现）。
# 产品缺陷（Sweeper 未对缺失 mmdb 降级）不在本任务修复范围；环境侧注入仓库自带的
# country.mmdb 并重启 api 使其启动期加载（与生产交付含 geoip 的口径一致）。
GEOIP_MMDB="runtime/geoip/country.mmdb"
[ -f "$GEOIP_MMDB" ] || fail "GeoIP mmdb 缺失: $GEOIP_MMDB"
deadline=$(( $(date +%s) + 120 ))
until docker exec jiuzhang-stage5-api true >/dev/null 2>&1; do
  [ "$(date +%s)" -lt "$deadline" ] || fail "api 容器未就绪（无法注入 geoip）"
  sleep 2
done
docker exec jiuzhang-stage5-api mkdir -p /app/runtime/geoip
docker cp "$GEOIP_MMDB" jiuzhang-stage5-api:/app/runtime/geoip/country.mmdb
docker restart jiuzhang-stage5-api >/dev/null
log "GeoIP mmdb 已注入并重启 api"

deadline=$(( $(date +%s) + 600 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$API_URL/api/v1/health" 2>/dev/null || echo 000)"
  [ "$code" = "200" ] && break
  sleep 3
done
[ "$code" = "200" ] || fail "API 健康检查超时（last=${code}）"
log "API 健康"

# ---- 登录/用户 复用阶段5公共函数 ----
export API_URL GATEWAY_URL="http://127.0.0.1:$GATEWAY_PORT"
export HOST_HEADER="$PROT_HOST"
export VALKEY_PASSWORD="$VK_PWD" VALKEY_CONTAINER="jiuzhang-stage5-valkey"
export SYS_USER="jiuzhang_admin" SYS_PWD="$ADMIN_PWD" SYS_NEW_PWD="$ADMIN_NEW_PWD"
export SEC_USER="p1reg_sec" SEC_PWD="$SEC_PWD_CI"
export APP_CODE="p1regprot"
# shellcheck source=../../../waf/scripts/stage5-setup.sh
source test/waf/scripts/stage5-setup.sh

SYS_CSRF="$(s5_ensure_sysadmin)" || fail "sysadmin 登录失败"
LIC_BODY="$(python3 -c 'import json,sys; print(json.dumps({"file_content": open(sys.argv[1]).read()}))' "$WORK_DIR/license.lic")"
lic_code="$(curl -s -o /dev/null -w '%{http_code}' -b "/tmp/s5-$SYS_USER.txt" -X POST "$API_URL/api/v1/license/import" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $SYS_CSRF" -d "$LIC_BODY")"
[ "$lic_code" = "200" ] || fail "授权导入失败 status=$lic_code"
SEC_CSRF="$(s5_ensure_secuser "$SYS_CSRF")"
[ -n "$SEC_CSRF" ] || fail "安全管理员登录失败"

sec_api() { # <method> <path> [bodyfile]
  local m="$1" p="$2" bf="${3:-}"
  local args=(-s -b "/tmp/s5-$SEC_USER.txt" -X "$m" "$API_URL$p"
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF")
  [ -n "$bf" ] && args+=(--data-binary "@$bf")
  curl "${args[@]}"
}

# ---- 双自签证书 + 双应用 ----
mk_cert() { # <host> <name> → cert_id
  local host="$1" name="$2"
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$WORK_DIR/$name-key.pem" -out "$WORK_DIR/$name-cert.pem" \
    -days 2 -subj "/CN=$host" -addext "subjectAltName=DNS:$host" >/dev/null 2>&1
  chmod 600 "$WORK_DIR/$name-key.pem"
  python3 - "$WORK_DIR" "$name" > "$WORK_DIR/$name-upload.json" <<'PY'
import json, sys
w, name = sys.argv[1], sys.argv[2]
cert = open(f"{w}/{name}-cert.pem").read()
key = open(f"{w}/{name}-key.pem").read()
print(json.dumps({"name": name, "cert_pem": cert, "key_pem": key, "chain_pem": cert}))
PY
  sec_api POST /api/v1/certificates "$WORK_DIR/$name-upload.json" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['id'])"
}

mk_app() { # <code> <mode> <host> <cert_id> → app_id
  local code="$1" mode="$2" host="$3" cert="$4"
  local appid
  appid="$(sec_api POST /api/v1/applications /dev/stdin <<EOF \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['id'])"
{"code":"$code","name":"P1回归应用-$code","description":"P1-04 R2 真实栈回放","business_owner":"test","technical_owner":"test","protection_mode":"$mode"}
EOF
)"
  [ -n "$appid" ] || { echo ""; return 1; }
  sec_api POST "/api/v1/applications/$appid/domains" /dev/stdin >/dev/null <<EOF
{"hostname":"$host","is_primary":true,"http_enabled":false,"https_enabled":true,"https_port":$SITE_HTTPS_PORT,"redirect_http_to_https":false}
EOF
  sec_api POST "/api/v1/applications/$appid/upstreams" /dev/stdin >/dev/null <<'EOF'
{"name":"testorigin","scheme":"http","host":"testorigin","port":8081,"weight":1,"priority":1,"health_check_enabled":false,"health_check_path":"/health","health_check_method":"GET","health_check_interval_seconds":10,"health_check_timeout_seconds":3,"expected_status_codes":"200","connect_timeout_ms":3000,"response_header_timeout_ms":10000,"tls_server_name":"","tls_verify":false}
EOF
  sec_api POST "/api/v1/applications/$appid/certificate" /dev/stdin >/dev/null <<EOF
{"certificate_id":"$cert"}
EOF
  sec_api POST "/api/v1/applications/$appid/enable" >/dev/null
  echo "$appid"
}

OBS_CERT="$(mk_cert "$OBS_HOST" p1reg-observe)" || fail "OBSERVE 证书上传失败"
PROT_CERT="$(mk_cert "$PROT_HOST" p1reg-protect)" || fail "PROTECT 证书上传失败"
OBS_APP="$(mk_app p1regobs OBSERVE "$OBS_HOST" "$OBS_CERT")" || fail "OBSERVE 应用创建失败"
PROT_APP="$(mk_app p1regprot PROTECT "$PROT_HOST" "$PROT_CERT")" || fail "PROTECT 应用创建失败"
log "应用就绪 obs=$OBS_APP prot=$PROT_APP"

# ---- 身份盐 + Bot 签名密钥播种（psql 夹具通道，与 bot-challenge 同口径）----
docker exec -i jiuzhang-stage5-postgres psql -U "$PG_USER" -d "$PG_DB" -v ON_ERROR_STOP=1 >/dev/null <<SQL
INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, description)
VALUES ('gateway_runtime','identity_salt','"$IDENTITY_SALT"','string','p1reg：身份指纹盐（随机，仅本轮栈）')
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
print("VALUES ('gateway_runtime','bot_signing_keys','\"%s\"','string','p1reg：Bot签名密钥（随机，仅本轮栈）')" % cipher)
print("ON CONFLICT (setting_group, setting_key) DO UPDATE")
print("SET setting_value = EXCLUDED.setting_value, updated_at = now(), version = system_settings.version + 1;")
PY
docker exec -i jiuzhang-stage5-postgres psql -U "$PG_USER" -d "$PG_DB" -v ON_ERROR_STOP=1 \
  < "$WORK_DIR/seed-keys.sql" >/dev/null
log "身份盐与 Bot 密钥已播种"

# ---- 启用身份行为观测 ----
sec_api GET /api/v1/security/behavior-policy > "$WORK_DIR/behavior-policy.json"
python3 - "$WORK_DIR/behavior-policy.json" > "$WORK_DIR/behavior-policy-on.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))["data"]["policy"]
d["enabled"] = True
for k in ("id", "updated_by", "updated_at", "created_at"):
    d.pop(k, None)
print(json.dumps(d))
PY
bp_code="$(curl -s -o /dev/null -w '%{http_code}' -b "/tmp/s5-$SEC_USER.txt" -X PUT \
  "$API_URL/api/v1/security/behavior-policy" -H 'Content-Type: application/json' \
  -H "X-CSRF-Token: $SEC_CSRF" --data-binary "@$WORK_DIR/behavior-policy-on.json")"
[ "$bp_code" = "200" ] || fail "behavior-policy 启用失败 status=$bp_code"

# ---- 自定义规则（CUSTOM_PACK 语料真值载体；family 映射入描述符）----
# 注意：服务端 escapeSecLangArg 会把 \ 转义为 \\（Coraza 不解回），正则须用
# 无反斜杠写法（[[:space:]]/[.]/{[}] 等 POSIX 与字面类），实测反斜杠写法不命中。
mk_rule() { # <rule_id> <name> <family> <phase> <variables-json> <operator> <value>
  python3 - "$1" "$2" "$3" "$4" "$5" "$6" "$7" > "$WORK_DIR/rule-$1.json" <<'PY'
import json, sys
rid, name, family, phase, variables, op, value = sys.argv[1:8]
print(json.dumps({
    "rule_id": int(rid), "name": name, "description": "P1-04 R2 回归自定义规则",
    "attack_type": "OTHER", "severity": "CRITICAL", "phase": int(phase),
    "operator": op, "operator_value": value,
    "target_variables": json.loads(variables), "action": "BLOCK",
    "tags": ["p1reg", "family:" + family],
}))
PY
  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' -b "/tmp/s5-$SEC_USER.txt" -X POST \
    "$API_URL/api/v1/custom-rules" -H 'Content-Type: application/json' \
    -H "X-CSRF-Token: $SEC_CSRF" --data-binary "@$WORK_DIR/rule-$1.json")"
  [ "$code" = "200" ] || { echo "ERROR: 自定义规则 $1($2) 创建失败 status=$code" >&2; return 1; }
}
mk_rule 7100001 "p1reg-webshell-uploads" "webshell_uploads" 2 '["REQUEST_BODY","ARGS","REQUEST_FILENAME"]' rx '(?i)<%(=|[[:space:]]).*request' || exit 1
mk_rule 7100002 "p1reg-cloud-abuse" "cloud_abuse" 2 '["REQUEST_BODY","ARGS"]' rx '169[.]254[.]169[.]254' || exit 1
mk_rule 7100003 "p1reg-ssti-injection" "ssti_injection" 2 '["REQUEST_BODY","ARGS"]' rx '[{][{][^}]+[}][}]' || exit 1
mk_rule 7100004 "p1reg-xxe-lfi" "xxe_lfi_variants" 2 '["REQUEST_BODY","ARGS"]' rx '(?i)<!ENTITY[[:space:]]+[A-Za-z0-9_]+[[:space:]]+SYSTEM' || exit 1
mk_rule 7100005 "p1reg-double-encode-evasion" "attack_variants_evasion" 1 '["QUERY_STRING","REQUEST_URI"]' rx '%252e' || exit 1
log "自定义规则 7100001-7100005 已创建"

# ---- Bot 策略（双应用；选择器 path_exact=/，行为双信号组，第三次导航评估达阈）----
mk_bot_policy() { # <app_id> <mode>
  local appid="$1" mode="$2"
  python3 - "$BOT_KEY_REF" "$mode" > "$WORK_DIR/bot-policy-$mode.json" <<'PY'
import json, sys
key_ref, mode = sys.argv[1], sys.argv[2]
print(json.dumps({
    "mode": mode,
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
    "reason": "p1reg: R2 真实栈回放 Bot 策略",
}))
PY
  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' -b "/tmp/s5-$SEC_USER.txt" -X PUT \
    "$API_URL/api/v1/applications/$appid/bot-policy" -H 'Content-Type: application/json' \
    -H "X-CSRF-Token: $SEC_CSRF" --data-binary "@$WORK_DIR/bot-policy-$mode.json")"
  [ "$code" = "200" ] || { echo "ERROR: bot-policy $mode 保存失败 status=$code" >&2; return 1; }
  sec_api POST "/api/v1/applications/$appid/bot-policy/preflight" /dev/stdin <<'EOF' \
    | python3 -c "import json,sys; d=json.load(sys.stdin)['data']; assert d.get('publishable') is True, d; print('preflight-ok')"
{}
EOF
}
mk_bot_policy "$OBS_APP" OBSERVE || exit 1
mk_bot_policy "$PROT_APP" PROTECT || exit 1
log "Bot 策略草稿与预检通过"

PUB="$(s5_publish "$SEC_CSRF" || true)"
[ "$PUB" = "PUBLISH_OK" ] || fail "配置发布失败: $PUB"
log "发布成功"

# ---- 网关可达冒烟（双 Host；JSON 客户端不受挑战，直达源站）----
gw_code() { # <host> <path>
  curl -sk -o /dev/null -w '%{http_code}' --max-time 10 \
    --resolve "$1:$SITE_HTTPS_PORT:127.0.0.1" -H 'Accept: application/json' \
    "https://$1${SITE_HTTPS_PORT:+:$SITE_HTTPS_PORT}$2" 2>/dev/null || echo 000
}
deadline=$(( $(date +%s) + 90 ))
while :; do
  c1="$(gw_code "$OBS_HOST" /)"
  c2="$(gw_code "$PROT_HOST" /)"
  [ "$c1" = "200" ] && [ "$c2" = "200" ] && break
  [ "$(date +%s)" -ge "$deadline" ] && fail "网关冒烟超时 obs=$c1 prot=$c2"
  sleep 2
done
mark="$(curl -sk --max-time 10 --resolve "$PROT_HOST:$SITE_HTTPS_PORT:127.0.0.1" \
  -H 'Accept: application/json' "https://$PROT_HOST/" \
  | python3 -c "import json,sys; print(json.load(sys.stdin).get('upstream_mark',''))" 2>/dev/null || true)"
[ "$mark" = "REACHED_ORIGIN" ] || fail "源站标记缺失（testorigin 未回写 upstream_mark）"
log "网关冒烟通过（双 Host 200 + 源站标记）"

# ---- 写环境描述符（0600；含管理面只读 Cookie——敏感，禁止入证据/git）----
SEC_COOKIE="$(python3 - "/tmp/s5-$SEC_USER.txt" <<'PY'
import sys
pairs = []
for line in open(sys.argv[1], encoding="utf-8"):
    line = line.strip()
    if not line:
        continue
    if line.startswith("#HttpOnly_"):
        line = line[len("#HttpOnly_"):]
    elif line.startswith("#"):
        continue
    parts = line.split("\t")
    if len(parts) >= 7:
        pairs.append(f"{parts[5]}={parts[6]}")
print("; ".join(pairs))
PY
)"
[ -n "$SEC_COOKIE" ] || fail "无法从 cookie jar 提取会话"
python3 - "$DESC_OUT" "$API_URL" "$OBS_HOST" "$OBS_APP" "$PROT_HOST" "$PROT_APP" \
  "$SEC_COOKIE" "$STACK_ID" "$SITE_HTTPS_PORT" <<'PY'
import json, os, sys
(out, api_url, obs_host, obs_app, prot_host, prot_app,
 cookie, stack_id, port) = sys.argv[1:10]
desc = {
    "kind": "p1reg_stage5_env",
    "api_url": api_url,
    "sec_cookie": cookie,
    "origin_mark": "jiuzhang-test-origin",
    "resolve_to": "127.0.0.1",
    "gateway_scheme": "https",
    "profiles": {
        "OBSERVE": {"host": obs_host, "app_id": obs_app, "app_code": "p1regobs"},
        "PROTECT": {"host": prot_host, "app_id": prot_app, "app_code": "p1regprot"},
    },
    "custom_rule_families": {
        "7100001": "webshell_uploads",
        "7100002": "cloud_abuse",
        "7100003": "ssti_injection",
        "7100004": "xxe_lfi_variants",
        "7100005": "attack_variants_evasion",
    },
    "allowed_targets": [obs_host, prot_host],
    "stack": {
        "stack_id": stack_id,
        "compose_project": "jiuzhang-stage5",
        "site_https_port": int(port),
        "note": "口令/密钥每轮随机存于 mktemp（已随描述符同目录保留至 stack-down）",
    },
}
fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as fh:
    json.dump(desc, fh, ensure_ascii=False, indent=2)
    fh.write("\n")
PY
echo "$WORK_DIR" > "$DESC_OUT.workdir"
chmod 600 "$DESC_OUT.workdir"
trap - EXIT
log "环境描述符: ${DESC_OUT} （栈保持运行；清理: stack-down.sh ${DESC_OUT}）"
echo "$DESC_OUT"
