#!/usr/bin/env bash
# run-stage5.sh NG-ID G1 批次 C stage5 联调驱动（机器身份 HTTP Message Signatures：
# I01~I05 + 能力门三态 + C01/C04 + 越权审计）。
# 前置：stage5 全栈在跑且 api/gateway 为当前工作树镜像（迁移 ≥000184，
# 网关自报 detectors.machineid=mid/1）：
#   docker compose --env-file .env -f deployment/docker-compose.stage5.yml \
#     -f deployment/docker-compose.wdsp.yml up -d --build --force-recreate api gateway
# 用法：test/waf/mid-e2e/run-stage5.sh [setup|i01|i02|i03|i05|i04|c04|c01|acl|capgate|all]
# 证据落 output/evidence/mid-g1-<ts>/（客户端 VERDICT 原样/事件断言/发布任务/autosave 快照）。
# 客户端：test/waf/mid-e2e（Go stdlib 三算法签名器，零第三方依赖）；禁 curl 冒充签名请求。
set -euo pipefail
cd "$(dirname "$0")/../../.."

PHASE="${1:-all}"
EVID="output/evidence/mid-g1-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVID"
echo "$EVID" > /tmp/mid-g1-evid-latest

# shellcheck source=../scripts/stage5-setup.sh
source test/waf/scripts/stage5-setup.sh
export VALKEY_PASSWORD="$(grep -m1 '^VALKEY_PASSWORD=' .env | cut -d= -f2-)"
MASTER_KEY="$(grep -m1 '^JIUZHANG_MASTER_KEY=' .env | cut -d= -f2-)"

HOST_P="mid-protect.local"
HOST_O="mid-observe.local"
APP_CODE_P="mids5p"; APP_CODE_O="mids5o"
ISSUER="https://idp.mid-s5.local"
AUD="mid-pay"
BOT_KEY_REF="mid-g1-bot"
E2E=/tmp/mid-e2e
KEYS=/tmp/mid-g1-keys
GW_A_URL="http://127.0.0.1:18080"
GW_B_URL="http://127.0.0.1:${GATEWAY_B_PORT:-18083}"
GW_TLS_URL="https://127.0.0.1:443"
PG="docker exec jiuzhang-stage5-postgres psql -U jiuzhang -d jiuzhang_waf"
GWA="docker exec jiuzhang-stage5-gateway"
GWB="docker exec jiuzhang-stage5-gateway-b"
COMPOSE="docker compose --env-file .env -f deployment/docker-compose.stage5.yml -f deployment/docker-compose.wdsp.yml -f deployment/docker-compose.stage5-mid.yml"

record() { echo "[$PHASE] $*" | tee -a "$EVID/records.log"; }
pass() { record "PASS $*"; }
fail() { record "FAIL $*"; echo "FAIL: $*" >&2; exit 1; }

# publish_patient 发布等待（机器身份写操作（身份/键/绑定每次变更）各自触发自动发布，
# 与显式发布竞态 LOCK_BUSY——更长退避窗口吸纳自动发布排水；mcp 同纪律）。
publish_patient() {
  local task attempt code st
  for attempt in $(seq 1 20); do
    task=$(curl -s -b "/tmp/s5-$SEC_USER.txt" -X POST "$API_URL/api/v1/gateway-config/publish" \
      -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" \
      -d "{\"idempotency_key\":\"mid-g1-$(date +%s)-$RANDOM\"}" \
      | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['id'])" 2>/dev/null)
    for _ in $(seq 1 40); do
      st=$(curl -s -b "/tmp/s5-$SEC_USER.txt" "$API_URL/api/v1/publish-tasks/$task" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['status'])" 2>/dev/null)
      case "$st" in
        SUCCESS) echo "PUBLISH_OK"; return 0;;
        FAILED)
          code=$(curl -s -b "/tmp/s5-$SEC_USER.txt" "$API_URL/api/v1/publish-tasks/$task" | python3 -c "import json,sys; print(json.load(sys.stdin)['data'].get('failure_code') or '')" 2>/dev/null)
          if [ "$code" = "LOCK_BUSY" ]; then sleep 4; break; fi
          echo "PUBLISH_FAILED:$code"; return 1;;
      esac
      sleep 1
    done
    [ "$st" = "FAILED" ] && [ "$code" = "LOCK_BUSY" ] && continue
    echo "PUBLISH_TIMEOUT"; return 1
  done
  echo "PUBLISH_FAILED"; return 1
}

# login_patient 登录等待+会话缓存（限流周期吸纳；mcp 同纪律）。
login_patient() {
  local cache=/tmp/mid-g1-session.env
  # cookie jar 被外部登录刷新时缓存 CSRF 即失效（token 绑定会话）——jar 新于缓存则弃缓存
  if [ -f "$cache" ] && [ "/tmp/s5-$SEC_USER.txt" -nt "$cache" ]; then rm -f "$cache"; fi
  if [ -f "$cache" ]; then
    local saved_csrf
    saved_csrf=$(grep '^SEC_CSRF=' "$cache" | cut -d= -f2-)
    if [ -n "$saved_csrf" ] && curl -s -o /dev/null -w '%{http_code}' -b "/tmp/s5-$SEC_USER.txt" \
        "$API_URL/api/v1/applications?page_size=1" | grep -q '^200$'; then
      SEC_CSRF="$saved_csrf"
      return 0
    fi
  fi
  SEC_CSRF=""
  for _ in $(seq 1 10); do
    SEC_CSRF=$(s5_login "$SEC_USER" "$SEC_PWD" 2>/dev/null || true)
    [ -n "$SEC_CSRF" ] && { echo "SEC_CSRF=$SEC_CSRF" > "$cache"; return 0; }
    sleep 10
  done
  fail "sec 登录（重试 10 次仍失败/限流）"
}

sec_get() { curl -s -b "/tmp/s5-$SEC_USER.txt" "$API_URL$1"; }
sec_put() { curl -s -o /dev/null -w '%{http_code}' -b "/tmp/s5-$SEC_USER.txt" -X PUT "$API_URL$1" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" -d "$2"; }
sec_post_code() { curl -s -o /dev/null -w '%{http_code}' -b "/tmp/s5-$SEC_USER.txt" -X POST "$API_URL$1" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" -d "${2:-}"; }
sec_post() { curl -s -b "/tmp/s5-$SEC_USER.txt" -X POST "$API_URL$1" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" -d "${2:-}"; }

# ---------- 客户端与 VERDICT 辅助 ----------

ensure_client() {
  if [ ! -x "$E2E" ]; then
    (cd test/waf/mid-e2e && go build -o "$E2E" .) || fail "参照客户端构建失败"
  fi
  "$E2E" keygen -dir "$KEYS" > /dev/null
  record "参照客户端就绪（${E2E}）+固定键集幂等（${KEYS}）"
}

# S <label> <send args...>：发送并留证，标准输出最后一行 VERDICT。
S() {
  local label="$1"; shift
  local out
  out=$("$E2E" send -label "$label" "$@" 2>&1 || true)
  { echo "== $label =="; echo "$out"; } >> "$EVID/client.log"
  echo "$out" | tail -1
}
v_status() { echo "$1" | grep -oE 'status=[0-9]+' | head -1 | cut -d= -f2; }
v_origin() { echo "$1" | grep -oE 'origin=(true|false)' | head -1 | cut -d= -f2; }
v_rid() { echo "$1" | grep -oE 'rid=[^ ]*' | head -1 | cut -d= -f2; }

assert_status() { # <verdict> <期望状态码集合（|分隔）> <说明>
  local st; st=$(v_status "$1")
  if echo "$2" | grep -qw "$st"; then pass "${3}（status=${st}）"; else fail "${3}：status=${st} 期望 $2 — $1"; fi
}

# ev_mid <container> <rid> → "<event_type> <reason_code> <detail>"（guard-events.log 精确 rid 行）。
ev_mid() { # <container> <rid> [event_type 过滤 regex——同 rid 多事件（VERIFIED+BOT_EXEMPT 并存）按类型择行]
  docker exec "$1" sh -c "grep '\"request_id\":\"$2\"' /var/log/caddy/guard-events.log 2>/dev/null | grep -E '\"event_type\":\"(${3:-.})\"' | tail -1" \
    | python3 -c "
import json,sys
line=sys.stdin.read().strip()
if not line:
    print('NONE - -'); sys.exit(0)
try:
    d=json.loads(line)
except Exception:
    print('PARSE_FAIL - -'); sys.exit(0)
m=d.get('machine_id') or {}
print(d.get('event_type','?'), m.get('reason_code','-'), (m.get('detail') or '-'))
" 2>/dev/null || echo "PARSE_FAIL - -"
}

assert_ev() { # <container> <rid> <event_type regex> <reason_code regex（- 表示不查）> <说明>
  local ev; ev=$(ev_mid "$1" "$2" "$3")
  echo "$(date +%T) rid=$2 ev=[$ev]" >> "$EVID/events-assert.log"
  local et rc; et=$(echo "$ev" | cut -d' ' -f1); rc=$(echo "$ev" | cut -d' ' -f2)
  echo "$et" | grep -qE "$3" || fail "${5}：事件类型 $et 不符 ${3}（rid=${2}）"
  if [ "$4" != "-" ]; then
    echo "$rc" | grep -qE "$4" || fail "${5}：reason $rc 不符 ${4}（rid=${2}）"
  fi
  pass "${5}（event=$et reason=${rc}）"
}

# ---------- 管理面资源辅助 ----------

ensure_app_mid() { # <code> <host> <protection_mode> <https:0|1> -> app_id
  local code="$1" host="$2" pmode="$3" https="$4" appid
  appid=$(sec_get "/api/v1/applications?keyword=$code" | python3 -c "
import json,sys
items=json.load(sys.stdin)['data']['items'] or []
print(next((i['id'] for i in items if i['code']=='$code'),''))" 2>/dev/null)
  if [ -n "$appid" ]; then echo "$appid"; return 0; fi
  appid=$(sec_post /api/v1/applications \
    "{\"code\":\"$code\",\"name\":\"MID联调应用-$code\",\"description\":\"NG-ID G1 批次 C\",\"business_owner\":\"test\",\"technical_owner\":\"test\",\"protection_mode\":\"$pmode\"}" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['id'])" 2>/dev/null)
  [ -n "$appid" ] || return 1
  if [ "$https" = "1" ]; then
    sec_post "/api/v1/applications/$appid/domains" \
      "{\"hostname\":\"$host\",\"is_primary\":true,\"http_enabled\":true,\"https_enabled\":true,\"http_port\":8080,\"https_port\":443,\"redirect_http_to_https\":false}" > /dev/null
  else
    sec_post "/api/v1/applications/$appid/domains" \
      "{\"hostname\":\"$host\",\"is_primary\":true,\"http_enabled\":true,\"https_enabled\":false,\"http_port\":8080,\"redirect_http_to_https\":false}" > /dev/null
  fi
  sec_post "/api/v1/applications/$appid/upstreams" \
    '{"name":"testorigin","scheme":"http","host":"testorigin","port":8081,"weight":1,"priority":1,"health_check_enabled":false,"health_check_path":"/health","health_check_method":"GET","health_check_interval_seconds":10,"health_check_timeout_seconds":3,"expected_status_codes":"200","connect_timeout_ms":3000,"response_header_timeout_ms":10000,"tls_server_name":"","tls_verify":false}' > /dev/null
  sec_post "/api/v1/applications/$appid/enable" > /dev/null
  echo "$appid"
}

# ensure_app_mode <appid> <mode>：防护模式校正（词表 OFF/OBSERVE/PROTECT/BYPASS——
# 已存在应用 ensure_app_mid 早退不重建，模式须显式 PUT 对齐；custom-pack 同形态）
ensure_app_mode() {
  local appid="$1" mode="$2" cur body rc
  cur=$(sec_get "/api/v1/applications/$appid" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['protection_mode'])" 2>/dev/null)
  [ "$cur" = "$mode" ] && return 0
  body=$(sec_get "/api/v1/applications/$appid" | python3 -c "
import json,sys
d=json.load(sys.stdin)['data']
print(json.dumps({'name':d['name'],'description':d.get('description') or '',
 'business_owner':d.get('business_owner') or '','technical_owner':d.get('technical_owner') or '',
 'protection_mode':'$mode','version':d['version']}))" 2>/dev/null)
  rc=$(sec_put "/api/v1/applications/$appid" "$body")
  [ "$rc" = "200" ] || fail "应用模式校正 rc=$rc（$appid → $mode）"
}

ensure_cert_bound() { # <appid> <hostname>：自签证书（仅联调栈）上传+绑定（幂等）
  local appid="$1" host="$2" certid
  certid=$(sec_get "/api/v1/certificates?name=mid-g1-selfsigned" | python3 -c "
import json,sys
items=json.load(sys.stdin)['data']['items'] or []
print(next((i['id'] for i in items if i.get('name')=='mid-g1-selfsigned'),''))" 2>/dev/null)
  if [ -z "$certid" ]; then
    if [ ! -f "$KEYS/site-cert.pem" ]; then
      openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$KEYS/site-key.pem" -out "$KEYS/site-cert.pem" \
        -days 30 -subj "/CN=$host" -addext "subjectAltName=DNS:$host" >/dev/null 2>&1
      chmod 600 "$KEYS/site-key.pem"
    fi
    python3 - "$KEYS" > "$EVID/cert-upload.json" <<'PY'
import json, sys
w = sys.argv[1]
cert = open(w + "/site-cert.pem").read()
key = open(w + "/site-key.pem").read()
print(json.dumps({"name": "mid-g1-selfsigned", "cert_pem": cert, "key_pem": key, "chain_pem": cert}))
PY
    certid=$(curl -s -b "/tmp/s5-$SEC_USER.txt" -X POST "$API_URL/api/v1/certificates" \
      -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" -d @"$EVID/cert-upload.json" \
      | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['id'])" 2>/dev/null)
  fi
  [ -n "$certid" ] || return 1
  sec_post_code "/api/v1/applications/$appid/certificate" "{\"certificate_id\":\"$certid\"}" > /dev/null
  echo "$certid"
}

put_jwt_policy() { # <appid>：OBSERVE token_required=false 全覆盖（principal_binding 组合前提）
  local appid="$1" ver
  ver=$(sec_get "/api/v1/applications/$appid/jwt-trust-policy" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['policy']['version'])" 2>/dev/null)
  local body
  body=$(python3 - "$EVID/jwks.json" "$ISSUER" "$AUD" "${ver:-0}" <<'PY'
import json, sys
jwks = open(sys.argv[1]).read()
iss, aud, ev = sys.argv[2], sys.argv[3], int(sys.argv[4])
print(json.dumps({
    "mode": "OBSERVE", "expected_version": ev,
    "selectors": [{"methods": ["GET", "POST"], "path_prefix": "/", "token_required": False}],
    "issuers": [{"issuer": iss, "audiences": [aud], "algorithms": ["RS256"],
                 "key_source": {"type": "STATIC_JWKS", "jwks": jwks},
                 "clock_skew_seconds": 30, "role_claims": ["roles"]}],
    "reason": "mid-g1 batch C: OBSERVE 全覆盖（principal_binding 组合前提）",
}))
PY
)
  sec_put "/api/v1/applications/$appid/jwt-trust-policy" "$body"
}

put_bot_tombstone() { # <appid>（CC 探针兼容——S5 同环境适配，mcp 同纪律）
  local appid="$1" ver
  ver=$(sec_get "/api/v1/applications/$appid/bot-policy" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['policy']['version'])" 2>/dev/null)
  sec_put "/api/v1/applications/$appid/bot-policy" \
    "{\"mode\":\"OFF\",\"expected_version\":${ver:-0},\"selectors\":[],\"route_reservation\":{\"state\":\"RESERVED_TOMBSTONE\",\"namespace\":\"/_wdsp/bot/v1/\"},\"reason\":\"mid-g1 batch C: CC 探针兼容墓碑\"}"
}

put_bot_protect() { # <appid>：PROTECT 挑战策略（selector /articles；bot-bench 同阈）
  local appid="$1" ver
  ver=$(sec_get "/api/v1/applications/$appid/bot-policy" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['policy']['version'])" 2>/dev/null)
  local body
  body=$(python3 - "$BOT_KEY_REF" "${ver:-0}" <<'PY'
import json, sys
key_ref, ev = sys.argv[1], int(sys.argv[2])
print(json.dumps({
    "mode": "PROTECT",
    "expected_version": ev,
    "selectors": [{"path_prefix": "/articles"}],
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
    "reason": "mid-g1 batch C: I05 Bot 组合 PROTECT",
}))
PY
)
  sec_put "/api/v1/applications/$appid/bot-policy" "$body"
}

seed_bot_signing_keys() {
  # gateway_runtime:bot_signing_keys 密文 JSON（AES-256-GCM/JIUZHANG_MASTER_KEY；
  # bot-bench 同夹具通道——管理面写入入口属 B5）
  # 加解密 python 需 cryptography 包（宿主默认 python3 为 Xcode 3.9 无此包——
  # 按序探测候选解释器，联调实证适配）
  local pyc=""
  for p in python3 python3.12 /opt/homebrew/bin/python3.12 /usr/local/bin/python3.12; do
    command -v "$p" >/dev/null 2>&1 && "$p" -c "import cryptography" >/dev/null 2>&1 && { pyc="$p"; break; }
  done
  [ -n "$pyc" ] || fail "无含 cryptography 的 python（bot_signing_keys 播种需要）"
  local key_hex cipher
  key_hex=$(openssl rand -hex 32)
  cipher=$("$pyc" - "$MASTER_KEY" "$BOT_KEY_REF" "$key_hex" <<'PY'
import sys, json, base64, os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
master_hex, key_ref, key_hex = sys.argv[1], sys.argv[2], sys.argv[3]
key = bytes.fromhex(master_hex)
nonce = os.urandom(12)
ct = AESGCM(key).encrypt(nonce, json.dumps({key_ref: key_hex}).encode(), None)
print(base64.b64encode(nonce + ct).decode())
PY
)
  echo "$cipher" | python3 -c "
import sys
cipher = sys.stdin.read().strip()
print(\"INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, description)\")
print(\"VALUES ('gateway_runtime','bot_signing_keys','\\\"%s\\\"','string','mid-g1：Bot签名密钥（随机，仅本轮栈）')\" % cipher)
print(\"ON CONFLICT (setting_group, setting_key) DO UPDATE\")
print(\"SET setting_value = EXCLUDED.setting_value, updated_at = now(), version = system_settings.version + 1;\")
" | docker exec -i jiuzhang-stage5-postgres psql -U jiuzhang -d jiuzhang_waf -v ON_ERROR_STOP=1 > /dev/null
  record "Bot 签名密钥播种（key_ref=${BOT_KEY_REF}，密文入库）"
}

# ---------- 机器身份管理面 ----------

mid_find_identity() { # <name> -> id（空=不存在）
  sec_get "/api/v1/api-security/machine-identities" | python3 -c "
import json,sys
items=json.load(sys.stdin)['data']['items'] or []
print(next((i['id'] for i in items if i['identity_name']=='$1'),''))" 2>/dev/null
}

mid_key_alg() { python3 -c "import json; print(json.load(open('$KEYS/manifest.json'))['$1'])"; }

mid_import_key() { # <identity_id> <kid>（幂等：已存在跳过）
  local iid="$1" kid="$2"
  local exists
  exists=$(sec_get "/api/v1/api-security/machine-identities/$iid" | python3 -c "
import json,sys
keys=json.load(sys.stdin)['data'].get('keys') or []
print('1' if any(k['kid']=='$kid' for k in keys) else '')" 2>/dev/null)
  [ -n "$exists" ] && return 0
  local body rc
  body=$(python3 - "$KEYS" "$kid" <<'PY'
import json, sys
d, kid = sys.argv[1], sys.argv[2]
alg = json.load(open(d + "/manifest.json"))[kid]
pem = open(d + "/" + kid + ".pub.pem").read().strip()
print(json.dumps({"kid": kid, "alg": alg, "public_key_pem": pem}))
PY
)
  rc=$(sec_post_code "/api/v1/api-security/machine-identities/$iid/keys" "$body")
  [ "$rc" = "200" ] || [ "$rc" = "409" ] || fail "导入键 $kid rc=$rc"
}

ensure_identity() { # <name> <status> <exempt:true|false> <kid 列表（空格分隔）> -> id
  local name="$1" status="$2" exempt="$3" kids="$4" iid
  iid=$(mid_find_identity "$name")
  if [ -z "$iid" ]; then
    iid=$(sec_post /api/v1/api-security/machine-identities \
      "{\"identity_name\":\"$name\",\"status\":\"$status\",\"bot_challenge_exempt\":$exempt}" \
      | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['identity']['id'])" 2>/dev/null)
  fi
  [ -n "$iid" ] || fail "身份 $name 创建失败"
  local kid
  for kid in $kids; do mid_import_key "$iid" "$kid"; done
  echo "$iid"
}

ensure_binding() { # <appid> <path_prefix> <mode> <proof_required:true|false>
  local appid="$1" prefix="$2" mode="$3" proof="$4" existing
  existing=$(sec_get "/api/v1/api-security/machine-identity-bindings?application_id=$appid" | python3 -c "
import json,sys
items=json.load(sys.stdin)['data']['items'] or []
print(len([i for i in items if i['path_prefix']=='$prefix']))" 2>/dev/null)
  if [ "${existing:-0}" != "0" ]; then return 0; fi
  local rc
  rc=$(sec_post_code /api/v1/api-security/machine-identity-bindings \
    "{\"application_id\":\"$appid\",\"path_prefix\":\"$prefix\",\"mode\":\"$mode\",\"proof_required\":$proof}")
  [ "$rc" = "200" ] || [ "$rc" = "409" ] || fail "绑定 $prefix 创建 rc=$rc"
}

mid_key_row() { # <identity_id> <kid> -> "<row_id> <status>"
  sec_get "/api/v1/api-security/machine-identities/$1" | python3 -c "
import json,sys
keys=json.load(sys.stdin)['data'].get('keys') or []
k=next((k for k in keys if k['kid']=='$2'), None)
print(k['id'], k['status']) if k else print('')" 2>/dev/null
}

# ---------- 阶段 ----------

do_setup() {
  login_patient
  record "sec_admin 登录 ok"
  # 前置断言：迁移 ≥000184 + 端点在册 + 网关自报 mid/1（镜像须为当前工作树构建）
  local mig
  mig=$($PG -tAc "select max(version) from schema_migrations" 2>/dev/null | tr -d '[:space:]')
  [ "${mig:-0}" -ge 184 ] || fail "schema_migrations=${mig}（<184）——先重建 api/gateway 镜像"
  local rc
  rc=$(curl -s -o /dev/null -w '%{http_code}' -b "/tmp/s5-$SEC_USER.txt" "$API_URL/api/v1/api-security/machine-identities")
  [ "$rc" = "200" ] || fail "machine-identities 端点 rc=${rc}（B1 未生效）"
  $GWA sh -c "grep -o 'machineid' /var/run/caddy/sidecars/capability.json" > /dev/null 2>&1 \
    || fail "网关清单无 machineid（B2 未生效——重建 gateway 镜像）"
  record "前置断言：迁移=${mig}、端点 200、网关自报 machineid"

  # API 管线须 PROTECT（引擎闸；stage5 现状不改动只断言）
  local mode
  mode=$(sec_get "/api/v1/api-security/policy" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['mode'])" 2>/dev/null)
  [ "$mode" = "PROTECT" ] || fail "API 管线非 PROTECT（mode=${mode}）"
  record "API 管线 PROTECT"

  ensure_client
  "$E2E" jwks -dir "$KEYS" > "$EVID/jwks.json"
  record "JWT JWKS（jwt-k1 RS256）导出"

  # identity_salt 以发布面线值为准（裁决 3 换算盐同快照）
  SALT=$($GWA sh -c "grep -o '\"identity_salt\":\"[^\"]*\"' /config/caddy/autosave.json | head -1 | cut -d'\"' -f4" 2>/dev/null)
  [ -n "$SALT" ] || fail "autosave 无 identity_salt"
  export SALT
  record "identity_salt 线值读取（${SALT:0:4}…）"

  APP_ID_P=$(ensure_app_mid "$APP_CODE_P" "$HOST_P" PROTECT 1)
  APP_ID_O=$(ensure_app_mid "$APP_CODE_O" "$HOST_O" OFF 0)
  [ -n "$APP_ID_P" ] && [ -n "$APP_ID_O" ] || fail "应用创建失败"
  export APP_ID_P APP_ID_O
  CERT_ID=$(ensure_cert_bound "$APP_ID_P" "$HOST_P")
  ensure_app_mode "$APP_ID_P" PROTECT
  record "两应用就绪 protect=$APP_ID_P observe=$APP_ID_O cert=${CERT_ID}（protect 模式 PROTECT+HTTPS 443）"

  rc=$(put_jwt_policy "$APP_ID_P")
  [ "$rc" = "200" ] || fail "jwt 策略保存 rc=$rc"
  record "protect 应用 jwt_trust OBSERVE（selector / GET,POST token_required=false，iss=$ISSUER aud=${AUD}）"

  seed_bot_signing_keys
  rc=$(put_bot_protect "$APP_ID_P")
  [ "$rc" = "200" ] || fail "bot PROTECT 策略保存 rc=$rc"
  rc=$(put_bot_tombstone "$APP_ID_O")
  [ "$rc" = "200" ] || fail "observe 应用 bot 墓碑 rc=$rc"
  record "bot 策略：protect=PROTECT（/articles，key_ref=${BOT_KEY_REF}） observe=OFF 墓碑"

  # 身份六条+键（幂等）
  ID_A=$(ensure_identity mid-svc-a ENABLED false "k-ed k-ec k-rsa")
  ID_B=$(ensure_identity mid-svc-b ENABLED false "k-b")
  ID_OFF=$(ensure_identity mid-svc-off DISABLED false "k-dis")
  ID_P=$(ensure_identity mid-svc-p ENABLED false "k-p")
  ID_BOT=$(ensure_identity mid-bot ENABLED false "k-bot")
  ID_BX=$(ensure_identity mid-bot-exempt ENABLED true "k-bx")
  export ID_A ID_B ID_OFF ID_P ID_BOT ID_BX
  record "六身份就绪 svc-a=$ID_A svc-b=$ID_B off=$ID_OFF svc-p=$ID_P bot=$ID_BOT bot-exempt=$ID_BX"

  # 绑定（源站 echo 路径锚定——/ping /search /submit /articles /download 均为
  # testorigin 注册回显路径（X-Wdsp-Origin-Mark 到达对账）；绑定 selector 逐字对齐）
  ensure_binding "$APP_ID_P" /ping PROTECT true
  ensure_binding "$APP_ID_P" /search PROTECT true
  ensure_binding "$APP_ID_P" /submit PROTECT true
  ensure_binding "$APP_ID_P" /articles PROTECT true
  ensure_binding "$APP_ID_P" /download PROTECT true
  ensure_binding "$APP_ID_O" /ping OBSERVE false
  record "六绑定就绪（protect 五路径 PROTECT+proof_required；observe /ping OBSERVE）"

  PUB=$(publish_patient); case "$PUB" in PUBLISH_OK) ;; *) fail "发布 $PUB";; esac
  record "发布成功（含 PROTECT 绑定——能力门 mid/1 自报满足）"

  echo "APP_ID_P=$APP_ID_P APP_ID_O=$APP_ID_O SALT=$SALT" > "$EVID/ids.env"
  echo "ID_A=$ID_A ID_B=$ID_B ID_OFF=$ID_OFF ID_P=$ID_P ID_BOT=$ID_BOT ID_BX=$ID_BX" >> "$EVID/ids.env"
}

load_ids() {
  login_patient
  ensure_client
  if [ -f "$EVID/ids.env" ]; then
    # shellcheck disable=SC1090
    source "$EVID/ids.env"
  elif [ -f "$(cat /tmp/mid-g1-evid-latest 2>/dev/null)/ids.env" ]; then
    # shellcheck disable=SC1090
    source "$(cat /tmp/mid-g1-evid-latest)/ids.env"
  fi
  if [ -z "${APP_ID_P:-}" ]; then
    APP_ID_P=$(ensure_app_mid "$APP_CODE_P" "$HOST_P" PROTECT 1)
    APP_ID_O=$(ensure_app_mid "$APP_CODE_O" "$HOST_O" OFF 0)
  fi
  if [ -z "${SALT:-}" ]; then
    SALT=$($GWA sh -c "grep -o '\"identity_salt\":\"[^\"]*\"' /config/caddy/autosave.json | head -1 | cut -d'\"' -f4" 2>/dev/null)
  fi
  if [ -z "${ID_A:-}" ]; then
    ID_A=$(mid_find_identity mid-svc-a); ID_B=$(mid_find_identity mid-svc-b)
    ID_OFF=$(mid_find_identity mid-svc-off); ID_P=$(mid_find_identity mid-svc-p)
    ID_BOT=$(mid_find_identity mid-bot); ID_BX=$(mid_find_identity mid-bot-exempt)
  fi
  export APP_ID_P APP_ID_O SALT ID_A ID_B ID_OFF ID_P ID_BOT ID_BX
  "$E2E" jwks -dir "$KEYS" > "$EVID/jwks.json" 2>/dev/null || true
}

# I01 有效签名三算法 + 篡改/畸形/覆盖/时效矩阵 + OBSERVE 对照
do_i01() {
  load_ids
  local V rid
  V=$(S i01-valid-ed -gw "$GW_A_URL" -host "$HOST_P" -path /ping -dir "$KEYS" -kid k-ed)
  assert_status "$V" 200 "I01 ed25519 有效签名"
  [ "$(v_origin "$V")" = "true" ] && pass "I01 ed25519 源站到达（X-Wdsp-Origin-Mark）" || fail "I01 ed25519 未到源站: $V"
  assert_ev jiuzhang-stage5-gateway "$(v_rid "$V")" MID_VERIFIED - "I01 MID_VERIFIED 事件在册"

  V=$(S i01-valid-ec-query -gw "$GW_A_URL" -host "$HOST_P" -path /ping -query "a=1&b=%2F" -dir "$KEYS" -kid k-ec)
  assert_status "$V" 200 "I01 ecdsa-p256-sha256 有效签名（含 @query 覆盖）"
  [ "$(v_origin "$V")" = "true" ] || fail "I01 ecdsa 未到源站: $V"

  V=$(S i01-valid-rsa-body -gw "$GW_A_URL" -host "$HOST_P" -path /ping -method POST -body '{"m":1}' -dir "$KEYS" -kid k-rsa)
  assert_status "$V" 200 "I01 rsa-pss-sha512 有效签名（含 content-digest 覆盖）"
  [ "$(v_origin "$V")" = "true" ] || fail "I01 rsa 未到源站: $V"

  # 篡改矩阵（裁决 1：密码学不可区分的两类按词表集合判定）
  for t in method path; do
    V=$(S i01-tamper-$t -gw "$GW_A_URL" -host "$HOST_P" -path /ping -dir "$KEYS" -kid k-ed -tamper "$t")
    assert_status "$V" 401 "I01 篡改 $t 拒绝"
    rid=$(v_rid "$V")
    assert_ev jiuzhang-stage5-gateway "$rid" MID_AUTH_FAILED "MID-TARGET-MISMATCH|MID-SIGNATURE-INVALID" "I01 篡改 $t 事件词表"
  done
  V=$(S i01-tamper-query -gw "$GW_A_URL" -host "$HOST_P" -path /ping -query "a=1" -dir "$KEYS" -kid k-ed -tamper query)
  assert_status "$V" 401 "I01 篡改 query 拒绝"
  assert_ev jiuzhang-stage5-gateway "$(v_rid "$V")" MID_AUTH_FAILED "MID-TARGET-MISMATCH|MID-SIGNATURE-INVALID" "I01 篡改 query 事件词表"

  V=$(S i01-tamper-body -gw "$GW_A_URL" -host "$HOST_P" -path /ping -method POST -body '{"m":1}' -dir "$KEYS" -kid k-rsa -tamper body)
  assert_status "$V" 401 "I01 篡改 body 拒绝"
  assert_ev jiuzhang-stage5-gateway "$(v_rid "$V")" MID_AUTH_FAILED MID-DIGEST-MISMATCH "I01 篡改 body 事件词表"

  # 多标签（Signature-Input 多成员——畸形）
  V=$(S i01-multilabel -gw "$GW_A_URL" -host "$HOST_P" -path /ping -dir "$KEYS" \
    -raw-input 'sig1=("@method" "@authority" "@path");created=1690000000;expires=1690000060;nonce="qvo5JVPy2CHqtD9CvpnqBQ";keyid="k-ed";alg="ed25519", sig2=("@method");created=1690000000' \
    -raw-sig 'sig1=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==:, sig2=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==:')
  assert_status "$V" 401 "I01 多标签拒绝"
  assert_ev jiuzhang-stage5-gateway "$(v_rid "$V")" MID_AUTH_FAILED MID-SIGNATURE-MALFORMED "I01 多标签事件词表"

  # 未签名（proof_required=true 准入拒绝——网关门禁语义：signature_absent 归入
  # MID-SIGNATURE-MALFORMED 形态族（准入策略判定非 UNKNOWN，机器身份无 401 专属
  # reason；MID-NA-UNSIGNED-001 是 proof_required=false 的覆盖观测 NA 规则号））
  V=$(S i01-unsigned -gw "$GW_A_URL" -host "$HOST_P" -path /ping -unsigned)
  assert_status "$V" 401 "I01 未签名拒绝（proof_required）"
  assert_ev jiuzhang-stage5-gateway "$(v_rid "$V")" MID_AUTH_FAILED MID-SIGNATURE-MALFORMED "I01 未签名事件词表"

  # OBSERVE 对照（proof_required=false）：未签名按普通流量放行 + 覆盖观测
  # NOT_APPLICABLE/MID-NA-UNSIGNED-001 在册（零 MID 事件——NOT_PRESENT 不产生事件）
  V=$(S i01-observe-unsigned -gw "$GW_A_URL" -host "$HOST_O" -path /ping -unsigned)
  assert_status "$V" 200 "I01 OBSERVE 未签名放行"
  [ "$(v_origin "$V")" = "true" ] || fail "I01 OBSERVE 未签名未到源站: $V"
  rid=$(v_rid "$V")
  # 覆盖观测异步落盘（响应返回后写入）——短轮询吸纳写入竞态
  local covtry
  for covtry in $(seq 1 10); do
    $GWA sh -c "grep '$rid' /var/log/caddy/coverage-observations.jsonl 2>/dev/null | grep '\"detector\":\"machineid\"' | tail -1" > "$EVID/i01-na-coverage.json"
    [ -s "$EVID/i01-na-coverage.json" ] && break
    sleep 1
  done
  python3 - "$EVID/i01-na-coverage.json" <<'PY' || fail "I01 未签名覆盖观测不符"
import json, sys
d = json.load(open(sys.argv[1]))
assert d["detector"] == "machineid", d["detector"]
assert d["status"] == "NOT_APPLICABLE", d["status"]
assert d.get("na_rule_id") == "MID-NA-UNSIGNED-001", d.get("na_rule_id")
print("I01 NA 覆盖观测 ok：NOT_APPLICABLE/MID-NA-UNSIGNED-001")
PY
  pass "I01 OBSERVE 未签名覆盖观测（NOT_APPLICABLE/MID-NA-UNSIGNED-001）"

  # 覆盖不足（省略 @path）
  V=$(S i01-omit-path -gw "$GW_A_URL" -host "$HOST_P" -path /ping -dir "$KEYS" -kid k-ed -omit "@path")
  assert_status "$V" 401 "I01 覆盖不足拒绝"
  assert_ev jiuzhang-stage5-gateway "$(v_rid "$V")" MID_AUTH_FAILED MID-COVERAGE-INSUFFICIENT "I01 覆盖不足事件词表"

  # keyid URL 形态（未登记——不抓取）
  V=$(S i01-kid-url -gw "$GW_A_URL" -host "$HOST_P" -path /ping -dir "$KEYS" -kid k-ed -kid-claim "https://evil.example/k.pem")
  assert_status "$V" 401 "I01 keyid URL 形态拒绝（不抓取）"
  assert_ev jiuzhang-stage5-gateway "$(v_rid "$V")" MID_AUTH_FAILED MID-KEY-UNKNOWN "I01 keyid URL 事件词表"

  # 时效：过期/未来 created/寿命超限
  local now; now=$(date +%s)
  V=$(S i01-expired -gw "$GW_A_URL" -host "$HOST_P" -path /ping -dir "$KEYS" -kid k-ed -created-at $((now-300)) -expires-at $((now-240)))
  assert_status "$V" 401 "I01 过期证明拒绝"
  assert_ev jiuzhang-stage5-gateway "$(v_rid "$V")" MID_AUTH_FAILED MID-PROOF-EXPIRED "I01 过期事件词表"
  V=$(S i01-clock -gw "$GW_A_URL" -host "$HOST_P" -path /ping -dir "$KEYS" -kid k-ed -created-at $((now+300)) -expires-at $((now+360)))
  assert_status "$V" 401 "I01 未来 created 拒绝"
  assert_ev jiuzhang-stage5-gateway "$(v_rid "$V")" MID_AUTH_FAILED MID-CLOCK-SKEW "I01 时钟偏移事件词表"
  V=$(S i01-lifetime -gw "$GW_A_URL" -host "$HOST_P" -path /ping -dir "$KEYS" -kid k-ed -lifetime 3600)
  assert_status "$V" 401 "I01 寿命超限拒绝"
  assert_ev jiuzhang-stage5-gateway "$(v_rid "$V")" MID_AUTH_FAILED MID-PROOF-EXPIRED "I01 寿命超限事件词表"

  # OBSERVE 对照：同篡改放行到源站 + MID_OBSERVED 在册（篡改 method——echo 全方法
  # 注册仍可 200 到达对账；path 篡改会落源站 404 干扰状态断言）
  V=$(S i01-observe-tamper -gw "$GW_A_URL" -host "$HOST_O" -path /ping -dir "$KEYS" -kid k-b -tamper method)
  assert_status "$V" 200 "I01 OBSERVE 篡改放行"
  [ "$(v_origin "$V")" = "true" ] || fail "I01 OBSERVE 未到源站: $V"
  assert_ev jiuzhang-stage5-gateway "$(v_rid "$V")" MID_OBSERVED "MID-TARGET-MISMATCH|MID-SIGNATURE-INVALID" "I01 OBSERVE 事件在册"
}

# I02 principal_binding 组合 + 未登记/DISABLED 键 + 算法不符
do_i02() {
  load_ids
  local FP_ALICE ver rc V
  FP_ALICE=$("$E2E" principalfp -salt "$SALT" -app "$APP_ID_P" -iss "$ISSUER" -sub alice)
  record "I02 VerifiedPrincipalID(alice)=$FP_ALICE"
  ver=$(sec_get "/api/v1/api-security/machine-identities/$ID_P" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['identity']['version'])" 2>/dev/null)
  rc=$(sec_put "/api/v1/api-security/machine-identities/$ID_P" \
    "{\"identity_name\":\"mid-svc-p\",\"principal_binding\":\"$FP_ALICE\",\"status\":\"ENABLED\",\"bot_challenge_exempt\":false,\"version\":$ver}")
  [ "$rc" = "200" ] || fail "principal_binding 录入 rc=$rc"
  PUB=$(publish_patient); case "$PUB" in PUBLISH_OK) ;; *) fail "发布 $PUB";; esac
  record "I02 principal_binding 录入+发布成功"

  # 裁决 3 线值实证：autosave（jiuzhang_guard 处理器段嵌套）的
  # principal_binding == HMAC(salt,"jwt-principal:"+录入值)
  $GWA sh -c "cat /config/caddy/autosave.json" > "$EVID/autosave-i02.json"
  python3 - "$EVID/autosave-i02.json" "$SALT" "$FP_ALICE" <<'PY' || fail "裁决3 线值不符（见 autosave-i02.json）"
import json, sys, hmac, hashlib
d = json.load(open(sys.argv[1]))
salt, entered = sys.argv[2], sys.argv[3]
expect = hmac.new(salt.encode(), ("jwt-principal:" + entered).encode(), hashlib.sha256).hexdigest()[:32]
# GuardConfig 嵌套于 Caddy 配置 apps.http.servers.*.routes.*.handle[handler=jiuzhang_guard]
def find_guard(o):
    if isinstance(o, dict):
        if o.get("handler") == "jiuzhang_guard":
            return o
        for v in o.values():
            r = find_guard(v)
            if r is not None:
                return r
    if isinstance(o, list):
        for v in o:
            r = find_guard(v)
            if r is not None:
                return r
    return None
g = find_guard(d)
assert g is not None, "autosave 无 jiuzhang_guard 处理器"
assert g.get("identity_salt") == salt, "autosave identity_salt 与读取盐不符"
ids = g.get("api_machine_identities") or []
row = next((i for i in ids if i.get("identity_name") == "mid-svc-p"), None)
assert row is not None, "autosave 无 mid-svc-p"
got = row.get("principal_binding")
assert got == expect, f"线值不符: got={got} expect={expect}"
print("裁决3 线值实证 ok：principal_binding 已换算至网关比对域", got)
PY
  pass "裁决3 发布域换算线值实证（autosave principal_binding==HMAC 第二层指纹）"

  local JWT_A JWT_B
  JWT_A=$("$E2E" mintjwt -dir "$KEYS" -iss "$ISSUER" -aud "$AUD" -sub alice)
  JWT_B=$("$E2E" mintjwt -dir "$KEYS" -iss "$ISSUER" -aud "$AUD" -sub bob)

  V=$(S i02-alice -gw "$GW_A_URL" -host "$HOST_P" -path /ping -dir "$KEYS" -kid k-p -jwt "$JWT_A")
  assert_status "$V" 200 "I02 绑定主体 alice 放行"
  [ "$(v_origin "$V")" = "true" ] || fail "I02 alice 未到源站: $V"

  V=$(S i02-bob -gw "$GW_A_URL" -host "$HOST_P" -path /ping -dir "$KEYS" -kid k-p -jwt "$JWT_B")
  assert_status "$V" 401 "I02 非绑定主体 bob 拒绝"
  assert_ev jiuzhang-stage5-gateway "$(v_rid "$V")" MID_AUTH_FAILED MID-PRINCIPAL-MISMATCH "I02 bob 事件词表"

  V=$(S i02-nojwt -gw "$GW_A_URL" -host "$HOST_P" -path /ping -dir "$KEYS" -kid k-p)
  assert_status "$V" 200 "I02 无 JWT 签名独立成立放行"

  V=$(S i02-kid-ghost -gw "$GW_A_URL" -host "$HOST_P" -path /ping -dir "$KEYS" -kid k-p -kid-claim k-ghost)
  assert_status "$V" 401 "I02 未登记 keyid 拒绝"
  assert_ev jiuzhang-stage5-gateway "$(v_rid "$V")" MID_AUTH_FAILED MID-KEY-UNKNOWN "I02 未登记 keyid 事件词表"

  V=$(S i02-disabled -gw "$GW_A_URL" -host "$HOST_P" -path /ping -dir "$KEYS" -kid k-dis)
  assert_status "$V" 401 "I02 DISABLED 身份键拒绝（不下发）"
  assert_ev jiuzhang-stage5-gateway "$(v_rid "$V")" MID_AUTH_FAILED MID-KEY-UNKNOWN "I02 DISABLED 键事件词表"

  V=$(S i02-alg-mismatch -gw "$GW_A_URL" -host "$HOST_P" -path /ping -dir "$KEYS" -kid k-p -alg-claim rsa-pss-sha512)
  assert_status "$V" 401 "I02 算法与登记不符拒绝"
  assert_ev jiuzhang-stage5-gateway "$(v_rid "$V")" MID_AUTH_FAILED MID-ALG-REJECTED "I02 算法不符事件词表"
  V=$(S i02-alg-hmac -gw "$GW_A_URL" -host "$HOST_P" -path /ping -dir "$KEYS" -kid k-p -alg-claim hmac-sha256)
  assert_status "$V" 401 "I02 词表外算法拒绝"
  assert_ev jiuzhang-stage5-gateway "$(v_rid "$V")" MID_AUTH_FAILED MID-ALG-REJECTED "I02 词表外算法事件词表"
}

# I03 双节点重放 + Valkey 依赖中断两态
do_i03() {
  load_ids
  # 第二节点：overlay up + restart 重 resume 收敛共享 autosave
  $COMPOSE up -d gateway-b > /dev/null 2>&1 || fail "gateway-b 启动失败"
  docker restart jiuzhang-stage5-gateway-b > /dev/null
  local V ok=""
  for _ in $(seq 1 30); do
    V=$(S i03-b-ready -gw "$GW_B_URL" -host "$HOST_P" -path /ping -dir "$KEYS" -kid k-ed)
    [ "$(v_status "$V")" = "200" ] && { ok=1; break; }
    sleep 2
  done
  [ -n "$ok" ] || fail "gateway-b 收敛超时（30 次探测未 200）：$V"
  pass "I03 gateway-b 配置收敛（共享 autosave resume 后签名探针 200）"

  # 固定 nonce 三发跨节点重放
  local NONCE="midg1fx$(date +%s)"
  V=$(S i03-replay-a1 -gw "$GW_A_URL" -host "$HOST_P" -path /ping -dir "$KEYS" -kid k-ed -nonce "$NONCE")
  assert_status "$V" 200 "I03 首次 nonce 放行（A）"
  V=$(S i03-replay-b -gw "$GW_B_URL" -host "$HOST_P" -path /ping -dir "$KEYS" -kid k-ed -nonce "$NONCE")
  assert_status "$V" 401 "I03 同 nonce 跨节点重放拒绝（B）"
  assert_ev jiuzhang-stage5-gateway-b "$(v_rid "$V")" MID_AUTH_FAILED MID-REPLAY-DETECTED "I03 B 节点重放事件"
  V=$(S i03-replay-a2 -gw "$GW_A_URL" -host "$HOST_P" -path /ping -dir "$KEYS" -kid k-ed -nonce "$NONCE")
  assert_status "$V" 401 "I03 同 nonce 回本节点重放拒绝（A）"
  assert_ev jiuzhang-stage5-gateway "$(v_rid "$V")" MID_AUTH_FAILED MID-REPLAY-DETECTED "I03 A 节点重放事件"

  # Valkey 原子存储键直查（跨节点互认证据）
  local NKEY NEX
  NKEY=$("$E2E" noncekey -salt "$SALT" -identity mid-svc-a -nonce "$NONCE")
  NEX=$(docker exec jiuzhang-stage5-valkey valkey-cli -a "$VALKEY_PASSWORD" --no-auth-warning EXISTS "$NKEY" 2>/dev/null | tr -d '[:space:]')
  echo "nonce_key=$NKEY exists=$NEX" > "$EVID/i03-nonce-key.txt"
  [ "$NEX" = "1" ] && pass "I03 Valkey 重放存储键在册（EXISTS=1）" || fail "I03 Valkey 键缺席: $NKEY"

  # 依赖中断：PROTECT 503（双节点）/OBSERVE 放行披露
  docker stop jiuzhang-stage5-valkey > /dev/null
  sleep 3
  V=$(S i03-valkey-down-a -gw "$GW_A_URL" -host "$HOST_P" -path /ping -dir "$KEYS" -kid k-ed)
  assert_status "$V" 503 "I03 Valkey 中断 A 节点 PROTECT 503"
  assert_ev jiuzhang-stage5-gateway "$(v_rid "$V")" MID_UNAVAILABLE - "I03 A 节点 MID_UNAVAILABLE 事件"
  V=$(S i03-valkey-down-b -gw "$GW_B_URL" -host "$HOST_P" -path /ping -dir "$KEYS" -kid k-ed)
  assert_status "$V" 503 "I03 Valkey 中断 B 节点 PROTECT 503"
  V=$(S i03-valkey-down-observe -gw "$GW_A_URL" -host "$HOST_O" -path /ping -dir "$KEYS" -kid k-b)
  assert_status "$V" 200 "I03 Valkey 中断 OBSERVE 放行"
  assert_ev jiuzhang-stage5-gateway "$(v_rid "$V")" MID_OBSERVED - "I03 OBSERVE 披露事件"
  docker start jiuzhang-stage5-valkey > /dev/null
  for _ in $(seq 1 30); do
    docker exec jiuzhang-stage5-valkey valkey-cli -a "$VALKEY_PASSWORD" --no-auth-warning ping 2>/dev/null | grep -q PONG && break
    sleep 2
  done
  sleep 3
  V=$(S i03-valkey-back-a -gw "$GW_A_URL" -host "$HOST_P" -path /ping -dir "$KEYS" -kid k-ed)
  [ "$(v_status "$V")" = "200" ] || { docker restart jiuzhang-stage5-gateway jiuzhang-stage5-gateway-b > /dev/null; sleep 8; V=$(S i03-valkey-back-a2 -gw "$GW_A_URL" -host "$HOST_P" -path /ping -dir "$KEYS" -kid k-ed); }
  assert_status "$V" 200 "I03 Valkey 恢复 A 节点放行"
  V=$(S i03-valkey-back-b -gw "$GW_B_URL" -host "$HOST_P" -path /ping -dir "$KEYS" -kid k-ed)
  assert_status "$V" 200 "I03 Valkey 恢复 B 节点放行"
}

# I05 既有防线组合：WAF / CC / Bot 挑战（机器身份不绕过）
do_i05() {
  load_ids
  local V MARK
  # WAF：有效签名 SQLi → 机器身份 VERIFIED 在册 + Coraza 403 阻断（不绕过）
  MARK="i05$(date +%s)"
  V=$(S i05-waf-sqli -gw "$GW_A_URL" -host "$HOST_P" -path /search -query "id=1%27%20OR%20%271%27%3D%271&midmark=$MARK" -dir "$KEYS" -kid k-ed)
  assert_status "$V" 403 "I05 WAF SQLi 阻断（签名有效不豁免 WAF）"
  assert_ev jiuzhang-stage5-gateway "$(v_rid "$V")" MID_VERIFIED - "I05 WAF 请求机器身份 VERIFIED 在册"
  $GWA sh -c "grep '$MARK' /var/log/caddy/coraza-audit.log 2>/dev/null | tail -2" > "$EVID/i05-coraza-audit.log"
  [ -s "$EVID/i05-coraza-audit.log" ] && pass "I05 Coraza 审计在册（midmark=${MARK}）" || fail "I05 coraza-audit.log 未见攻击事务"

  # CC：/submit limit 3/60s burst 3 REJECT → 5 签名请求前 3 放行后 429（不绕过）
  local ccid
  ccid=$(sec_get "/api/v1/rate-limit-policies?keyword=cc-mid-g1" | python3 -c "import json,sys; items=json.load(sys.stdin)['data']['items'] or []; print(next((i['id'] for i in items if i['name']=='cc-mid-g1'),''))" 2>/dev/null)
  [ -n "$ccid" ] && sec_post_code "/api/v1/rate-limit-policies/$ccid/disable" > /dev/null && \
    curl -s -o /dev/null -b "/tmp/s5-$SEC_USER.txt" -X DELETE "$API_URL/api/v1/rate-limit-policies/$ccid" -H "X-CSRF-Token: $SEC_CSRF"
  sec_post_code /api/v1/rate-limit-policies \
    "{\"name\":\"cc-mid-g1\",\"scope_type\":\"APPLICATION\",\"application_id\":\"$APP_ID_P\",\"uri_match_type\":\"PREFIX\",\"uri_pattern\":\"/submit\",\"dimension\":\"CLIENT_IP\",\"algorithm\":\"TOKEN_BUCKET\",\"requests_limit\":3,\"window_seconds\":60,\"burst_capacity\":3,\"action\":\"REJECT\",\"priority\":100}" > /dev/null
  PUB=$(publish_patient); case "$PUB" in PUBLISH_OK) ;; *) fail "发布 $PUB";; esac
  local i st43="" st429=""
  for i in 1 2 3 4 5; do
    V=$(S i05-cc-$i -gw "$GW_A_URL" -host "$HOST_P" -path /submit -method POST -body "x=$i" -dir "$KEYS" -kid k-ed)
    case "$i" in
      1|2|3) [ "$(v_status "$V")" = "200" ] && st43="$st43$i" || fail "I05 CC 第 $i 请求未放行: $V";;
      *) [ "$(v_status "$V")" = "429" ] && st429="$st429$i" || fail "I05 CC 第 $i 请求未 429: $V";;
    esac
  done
  pass "I05 CC REJECT 生效（前 3 放行后 2×429——签名有效不豁免 CC）"
  ccid=$(sec_get "/api/v1/rate-limit-policies?keyword=cc-mid-g1" | python3 -c "import json,sys; items=json.load(sys.stdin)['data']['items'] or []; print(next((i['id'] for i in items if i['name']=='cc-mid-g1'),''))" 2>/dev/null)
  [ -n "$ccid" ] && curl -s -o /dev/null -b "/tmp/s5-$SEC_USER.txt" -X DELETE "$API_URL/api/v1/rate-limit-policies/$ccid" -H "X-CSRF-Token: $SEC_CSRF"
  PUB=$(publish_patient); case "$PUB" in PUBLISH_OK) ;; *) fail "CC 清理发布 $PUB";; esac
  record "I05 CC 策略清理+发布"

  # Bot：合格 HTTPS 浏览器文档导航连发（k-bot 未豁免 → 挑战；k-bx 豁免 → 直通）
  local challenged="" i2
  for i2 in 1 2 3 4 5 6 7 8; do
    V=$(S i05-bot-$i2 -gw "$GW_TLS_URL" -tls -browser -host "$HOST_P" -path /articles -dir "$KEYS" -kid k-bot)
    [ "$(v_status "$V")" = "403" ] && { challenged=1; break; }
    sleep 1
  done
  [ -n "$challenged" ] || fail "I05 Bot 8 次导航未挑战（信号阈未达）"
  pass "I05 Bot 挑战触发（k-bot 第 $i2 次导航 403）"
  $GWA sh -c "grep 'BOT_CHALLENGE_OFFERED' /var/log/caddy/guard-events.log 2>/dev/null | tail -3" > "$EVID/i05-bot-offered.log"
  grep -q "$HOST_P" "$EVID/i05-bot-offered.log" && pass "I05 BOT_CHALLENGE_OFFERED 事件在册" || fail "I05 缺 BOT_CHALLENGE_OFFERED"
  for i2 in 1 2 3; do
    V=$(S i05-bot-exempt-$i2 -gw "$GW_TLS_URL" -tls -browser -host "$HOST_P" -path /articles -dir "$KEYS" -kid k-bx)
    assert_status "$V" 200 "I05 Bot 豁免直通（k-bx #${i2}）"
  done
  assert_ev jiuzhang-stage5-gateway "$(v_rid "$V")" MID_BOT_EXEMPT - "I05 MID_BOT_EXEMPT 事件在册"
}

# I04 轮换/撤销/回滚水位回归（在 i01/i03/i05 后——前置用例依赖 ACTIVE 键）
do_i04() {
  load_ids
  local V row kid_rsa kid_ed did_revoke=""
  # V0=当前生效版本（水位 0 快照——回滚目标）
  V0=$(sec_get "/api/v1/config-versions?page_size=20" | python3 -c "
import json,sys
items=json.load(sys.stdin)['data']['items'] or []
cur=next((i for i in items if i.get('is_current')), items[0] if items else None)
print(cur['id'] if cur else '')" 2>/dev/null)
  [ -n "$V0" ] || fail "I04 无当前配置版本"
  record "I04 回滚目标 V0=$V0"

  # 撤销 k-rsa（幂等：已 REVOKED 跳过——重跑安全）
  row=$(mid_key_row "$ID_A" k-rsa); kid_rsa=$(echo "$row" | cut -d' ' -f1)
  if [ "$(echo "$row" | cut -d' ' -f2)" != "REVOKED" ]; then
    sec_post_code "/api/v1/api-security/machine-identities/$ID_A/keys/$kid_rsa/revoke" '{}' > /dev/null
    did_revoke=1
    PUB=$(publish_patient); case "$PUB" in PUBLISH_OK) ;; *) fail "撤销发布 $PUB";; esac
    record "I04 k-rsa 撤销+发布"
  else
    record "I04 k-rsa 已 REVOKED（重跑跳过撤销）"
  fi
  V=$(S i04-revoked-rsa -gw "$GW_A_URL" -host "$HOST_P" -path /ping -dir "$KEYS" -kid k-rsa)
  assert_status "$V" 401 "I04 已撤销键拒绝"
  assert_ev jiuzhang-stage5-gateway "$(v_rid "$V")" MID_AUTH_FAILED MID-KEY-REVOKED "I04 撤销事件词表"

  # 轮换 k-ed→k-ed2（幂等：k-ed 已 RETIRED 跳过）
  row=$(mid_key_row "$ID_A" k-ed); kid_ed=$(echo "$row" | cut -d' ' -f1)
  if [ "$(echo "$row" | cut -d' ' -f2)" = "ACTIVE" ]; then
    local body
    body=$(python3 - "$KEYS" <<'PY'
import json, sys
d = sys.argv[1]
pem = open(d + "/k-ed2.pub.pem").read().strip()
print(json.dumps({"kid": "k-ed2", "alg": "ed25519", "public_key_pem": pem}))
PY
)
    sec_post "/api/v1/api-security/machine-identities/$ID_A/keys/$kid_ed/rotate" "$body" > "$EVID/i04-rotate.json"
    PUB=$(publish_patient); case "$PUB" in PUBLISH_OK) ;; *) fail "轮换发布 $PUB";; esac
    record "I04 k-ed→k-ed2 轮换+发布"
  else
    record "I04 k-ed 已 RETIRED（重跑跳过轮换）"
  fi
  # 窗口内新旧均放行
  V=$(S i04-retired-old -gw "$GW_A_URL" -host "$HOST_P" -path /ping -dir "$KEYS" -kid k-ed)
  assert_status "$V" 200 "I04 RETIRED 窗口内旧键放行"
  V=$(S i04-active-new -gw "$GW_A_URL" -host "$HOST_P" -path /ping -dir "$KEYS" -kid k-ed2)
  assert_status "$V" 200 "I04 轮换新键放行"
  record "I04 登记偏差承接：RETIRED 窗口内放行但事件无 RETIRED 标注（B2 遗留——管理面读回 status/retire_overlap_until 承载）"
  # 管理面读回状态机
  sec_get "/api/v1/api-security/machine-identities/$ID_A" > "$EVID/i04-identity.json"
  python3 - "$EVID/i04-identity.json" <<'PY' || fail "I04 管理面状态机不符"
import json, sys
d = json.load(open(sys.argv[1]))["data"]
keys = {k["kid"]: k for k in d["keys"]}
assert keys["k-rsa"]["status"] == "REVOKED", "k-rsa 应 REVOKED"
assert (keys["k-rsa"].get("revoked_seq") or 0) >= 1, "k-rsa revoked_seq 应 ≥1"
assert keys["k-ed"]["status"] == "RETIRED", "k-ed 应 RETIRED"
assert keys["k-ed"].get("retire_overlap_until"), "k-ed 应有 retire_overlap_until"
assert keys["k-ed2"]["status"] == "ACTIVE", "k-ed2 应 ACTIVE"
print("I04 管理面状态机 ok：REVOKED+seq / RETIRED+窗口 / ACTIVE")
PY
  pass "I04 管理面状态机（REVOKED+revoked_seq/RETIRED+窗口/ACTIVE）"

  # 回滚 V0 → 水位回归 fail-closed（仅本轮真实推进水位时断言；重跑跳过）
  if [ -n "$did_revoke" ]; then
    local task st fcode
    task=$(sec_post "/api/v1/config-versions/$V0/rollback" '{}' | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['id'])" 2>/dev/null)
    for _ in $(seq 1 40); do
      st=$(sec_get "/api/v1/publish-tasks/$task" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['status'])" 2>/dev/null)
      [ "$st" = "SUCCESS" ] || [ "$st" = "FAILED" ] && break
      sleep 1
    done
    sec_get "/api/v1/publish-tasks/$task" > "$EVID/i04-rollback-task.json"
    fcode=$(python3 -c "import json; print(json.load(open('$EVID/i04-rollback-task.json'))['data'].get('failure_code') or '')" 2>/dev/null)
    [ "$st" = "FAILED" ] || fail "I04 回滚未失败（st=${st}）——水位回归门未闭合"
    $GWA sh -c "grep 'MID_WATERMARK_REGRESSION' /var/log/caddy/caddy.log 2>/dev/null | tail -2" > "$EVID/i04-watermark.log"
    [ -s "$EVID/i04-watermark.log" ] || fail "I04 网关日志缺 MID_WATERMARK_REGRESSION（task failure_code=${fcode}）"
    pass "I04 回滚水位回归 fail-closed（task FAILED($fcode)+网关 MID_WATERMARK_REGRESSION）"
    V=$(S i04-after-rollback -gw "$GW_A_URL" -host "$HOST_P" -path /ping -dir "$KEYS" -kid k-rsa)
    assert_status "$V" 401 "I04 回滚被拒后 k-rsa 仍拒（网关保留现行配置）"
  else
    record "I04 重跑：水位已在高位，回滚回归断言跳过（首轮已实证）"
  fi
}

# C04 白名单/CC 与机器身份顺序：CC 先行计数、白名单跳过 CC 但不绕过机器身份
do_c04() {
  load_ids
  local rid ccid V
  rid=$(sec_get "/api/v1/access-rules?keyword=mid-c04-allow" | python3 -c "import json,sys; items=json.load(sys.stdin)['data']['items'] or []; print(next((i['id'] for i in items if i['name']=='mid-c04-allow'),''))" 2>/dev/null)
  [ -z "$rid" ] && sec_post /api/v1/access-rules "{\"name\":\"mid-c04-allow\",\"rule_type\":\"ALLOW\",\"scope_type\":\"APPLICATION\",\"application_id\":\"$APP_ID_P\",\"address\":\"198.51.100.77\",\"priority\":100,\"validity_type\":\"PERMANENT\"}" > /dev/null
  sec_post_code /api/v1/rate-limit-policies \
    "{\"name\":\"cc-mid-c04\",\"scope_type\":\"APPLICATION\",\"application_id\":\"$APP_ID_P\",\"uri_match_type\":\"PREFIX\",\"uri_pattern\":\"/download\",\"dimension\":\"CLIENT_IP\",\"algorithm\":\"TOKEN_BUCKET\",\"requests_limit\":1,\"window_seconds\":60,\"burst_capacity\":1,\"action\":\"REJECT\",\"priority\":100}" > /dev/null
  PUB=$(publish_patient); case "$PUB" in PUBLISH_OK) ;; *) fail "发布 $PUB";; esac
  record "C04 ALLOW 198.51.100.77 + CC /download limit 1/60s 发布"

  V=$(S c04-unsigned-1 -gw "$GW_A_URL" -host "$HOST_P" -path /download -unsigned -xff 203.0.113.9)
  assert_status "$V" 401 "C04 未签名首发 401（CC 计数后机器身份拒绝）"
  assert_ev jiuzhang-stage5-gateway "$(v_rid "$V")" MID_AUTH_FAILED "MID-SIGNATURE-MALFORMED" "C04 首发事件词表"
  V=$(S c04-unsigned-2 -gw "$GW_A_URL" -host "$HOST_P" -path /download -unsigned -xff 203.0.113.9)
  assert_status "$V" 429 "C04 未签名再发 429（CC 先于机器身份饱和实证）"
  V=$(S c04-whitelist -gw "$GW_A_URL" -host "$HOST_P" -path /download -unsigned -xff 198.51.100.77)
  assert_status "$V" 401 "C04 白名单未签名仍 401（跳过 CC 不绕过机器身份）"
  assert_ev jiuzhang-stage5-gateway "$(v_rid "$V")" MID_AUTH_FAILED "MID-SIGNATURE-MALFORMED" "C04 白名单事件词表"

  # 清理
  rid=$(sec_get "/api/v1/access-rules?keyword=mid-c04-allow" | python3 -c "import json,sys; items=json.load(sys.stdin)['data']['items'] or []; print(next((i['id'] for i in items if i['name']=='mid-c04-allow'),''))" 2>/dev/null)
  [ -n "$rid" ] && curl -s -o /dev/null -b "/tmp/s5-$SEC_USER.txt" -X DELETE "$API_URL/api/v1/access-rules/$rid" -H "X-CSRF-Token: $SEC_CSRF"
  ccid=$(sec_get "/api/v1/rate-limit-policies?keyword=cc-mid-c04" | python3 -c "import json,sys; items=json.load(sys.stdin)['data']['items'] or []; print(next((i['id'] for i in items if i['name']=='cc-mid-c04'),''))" 2>/dev/null)
  [ -n "$ccid" ] && curl -s -o /dev/null -b "/tmp/s5-$SEC_USER.txt" -X DELETE "$API_URL/api/v1/rate-limit-policies/$ccid" -H "X-CSRF-Token: $SEC_CSRF"
  PUB=$(publish_patient); case "$PUB" in PUBLISH_OK) ;; *) fail "C04 清理发布 $PUB";; esac
  record "C04 清理+发布"
}

# C01 无绑定应用零行为
do_c01() {
  load_ids
  local V rid
  V=$(S c01-no-binding -gw "$GW_A_URL" -host waf-s5.local -path /ping -unsigned)
  local st; st=$(v_status "$V")
  [ "$st" != "401" ] && ! echo "$V" | grep -q 'machine_identity' || fail "C01 无绑定应用被机器身份干预: $V"
  rid=$(v_rid "$V")
  local ev; ev=$(ev_mid jiuzhang-stage5-gateway "$rid")
  [ "${ev%% *}" = "NONE" ] && pass "C01 无绑定应用机器身份零行为（status=${st}，无 MID 事件）" \
    || fail "C01 出现 MID 事件: $ev"
}

# 越权与审计：jiuzhang_admin 无权（403），sec_admin 在册；写操作 HIGH 审计
do_acl() {
  load_ids
  # 系统管理员登录（限流重试；先旧密码后新密码——s5_ensure_sysadmin 改密先例）
  local sys_csrf=""
  for _ in $(seq 1 6); do
    sys_csrf=$(s5_login "$SYS_USER" "$SYS_PWD" 2>/dev/null || true)
    [ -z "$sys_csrf" ] && sys_csrf=$(s5_login "$SYS_USER" "$SYS_NEW_PWD" 2>/dev/null || true)
    [ -n "$sys_csrf" ] && break
    sleep 10
  done
  [ -n "$sys_csrf" ] || fail "jiuzhang_admin 登录失败"
  local rc
  # 授权口径（000126 种子+机器身份端点复用 jwt_trust.read/manage）：只读三角色
  # 全授（SYSTEM_ADMIN/SECURITY_ADMIN/AUDIT_ADMIN），manage 仅前两者——
  # SYSTEM_ADMIN 读=200 为合规正向；越权负向由未认证 401 与 AUDIT_ADMIN 写 403 承载。
  rc=$(curl -s -o /dev/null -w '%{http_code}' "$API_URL/api/v1/api-security/machine-identities")
  [ "$rc" = "401" ] && pass "未认证 GET machine-identities 401" || fail "未认证 GET rc=${rc}（期望 401）"
  rc=$(curl -s -o /dev/null -w '%{http_code}' -b "/tmp/s5-$SYS_USER.txt" "$API_URL/api/v1/api-security/machine-identities")
  [ "$rc" = "200" ] && pass "SYSTEM_ADMIN GET machine-identities 200（jwt_trust.read 种子已授）" || fail "sysadmin GET rc=${rc}（期望 200）"

  # 一次性 AUDIT_ADMIN 探针用户（有 read 无 manage——读 200 / 写 403 粒度实证）。
  # 用户名带时间戳：用户删除为软删（status=DELETED 仍占用户名唯一约束），
  # 复用同名会撞 RESOURCE_CONFLICT——每轮新名天然幂等， remnants 隐藏于 List。
  local au_id au_pw au au_csrf au_name
  au_name="mid_acl_$(date +%s)"
  au=$(curl -s -b "/tmp/s5-$SYS_USER.txt" -X POST "$API_URL/api/v1/users" -H 'Content-Type: application/json' -H "X-CSRF-Token: $sys_csrf" \
    -d "{\"username\":\"$au_name\",\"display_name\":\"MID联调审计探针\",\"role_code\":\"AUDIT_ADMIN\"}")
  au_id=$(echo "$au" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['user']['id'])" 2>/dev/null)
  au_pw=$(echo "$au" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['temporary_password'])" 2>/dev/null)
  [ -n "$au_id" ] && [ -n "$au_pw" ] || fail "审计探针用户创建失败: ${au}"
  au_csrf=$(s5_login "$au_name" "$au_pw" 2>/dev/null || true)
  [ -n "$au_csrf" ] || fail "审计探针登录失败"
  # 首登强制改密（MustChangePassword——s5_ensure_sysadmin 同形）
  curl -s -o /dev/null -b "/tmp/s5-$au_name.txt" -X POST "$API_URL/api/v1/auth/change-password" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $au_csrf" \
    -d "{\"old_password\":\"$au_pw\",\"new_password\":\"MidAcl!S5audit2026\"}"
  au_csrf=$(s5_login "$au_name" "MidAcl!S5audit2026" 2>/dev/null || true)
  [ -n "$au_csrf" ] || fail "审计探针改密后登录失败"
  rc=$(curl -s -o /dev/null -w '%{http_code}' -b "/tmp/s5-$au_name.txt" "$API_URL/api/v1/api-security/machine-identities")
  [ "$rc" = "200" ] && pass "AUDIT_ADMIN GET machine-identities 200（只读授权）" || fail "audit GET rc=${rc}（期望 200）"
  rc=$(curl -s -o /dev/null -w '%{http_code}' -b "/tmp/s5-$au_name.txt" -X POST "$API_URL/api/v1/api-security/machine-identities" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $au_csrf" \
    -d '{"identity_name":"mid-acl-probe","status":"ENABLED","bot_challenge_exempt":false}')
  [ "$rc" = "403" ] && pass "越权 AUDIT_ADMIN POST machine-identities 403（无 manage）" || fail "越权 POST rc=${rc}（期望 403）"
  # 写操作审计读回（audits.read 属 AUDIT_ADMIN——趁探针会话在册；sec_admin 无此权限）
  curl -s -b "/tmp/s5-$au_name.txt" "$API_URL/api/v1/audits?module=api_security&page_size=50" > "$EVID/audits.json"
  python3 - "$EVID/audits.json" <<'PY' || fail "越权审计：缺 machine_identity HIGH 审计"
import json, sys
items = json.load(open(sys.argv[1]))["data"]["items"] or []
hits = [i for i in items if (i.get("object_type") or "").startswith("machine_identity") and i.get("risk_level") == "HIGH"]
assert hits, "无 machine_identity* HIGH 审计"
print("越权审计 ok：machine_identity* HIGH 审计", len(hits), "条（示例 action=%s）" % hits[0]["action"])
PY
  pass "写操作 HIGH 审计在册（module=api_security）"
  # 探针用户清理（SYSTEM_ADMIN 删除——软删；失败不阻断——审计在册即可）
  curl -s -o /dev/null -b "/tmp/s5-$SYS_USER.txt" -X DELETE "$API_URL/api/v1/users/$au_id" -H "X-CSRF-Token: $sys_csrf"
  rm -f "/tmp/s5-$au_name.txt"
  record "ACL 探针用户已清理（${au_name} id=${au_id}）"

  rc=$(curl -s -o /dev/null -w '%{http_code}' -b "/tmp/s5-$SEC_USER.txt" "$API_URL/api/v1/api-security/machine-identities")
  [ "$rc" = "200" ] && pass "sec_admin GET machine-identities 200" || fail "sec GET rc=$rc"
}

# 能力门三态：A 真实清单收载 / B 无 machineid 旧清单 fail-closed / C 全 OBSERVE 零需求
do_capgate() {
  load_ids
  # 真实清单入口一次快照（恢复源；注入纪律照 S6——exec 覆写保 jiuzhang 属主）
  $GWA sh -c "cat /var/run/caddy/sidecars/capability.json" > "$EVID/capability-real.json"
  python3 - "$EVID/capability-real.json" <<'PY' > "$EVID/capability-old.json"
import json, sys, datetime
d = json.load(open(sys.argv[1]))
d["detectors"] = [x for x in d["detectors"] if x["name"] != "machineid"]
d["generated_at"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
print(json.dumps(d))
PY
  # 状态 B：旧清单在位 + 含 PROTECT 绑定 → 发布必拒
  docker exec -i jiuzhang-stage5-api sh -c 'cat > /var/run/caddy/sidecars/capability.json' < "$EVID/capability-old.json"
  local task st fcode fmsg
  task=$(sec_post /api/v1/gateway-config/publish "{\"idempotency_key\":\"mid-gate-old-$(date +%s)\"}" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['id'])" 2>/dev/null)
  for _ in $(seq 1 30); do
    st=$(sec_get "/api/v1/publish-tasks/$task" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['status'])" 2>/dev/null)
    [ "$st" = "SUCCESS" ] || [ "$st" = "FAILED" ] && break
    sleep 1
  done
  sec_get "/api/v1/publish-tasks/$task" > "$EVID/capgate-old-task.json"
  fcode=$(python3 -c "import json; print(json.load(open('$EVID/capgate-old-task.json'))['data'].get('failure_code') or '')" 2>/dev/null)
  fmsg=$(python3 -c "import json; print(json.load(open('$EVID/capgate-old-task.json'))['data'].get('failure_message') or '')" 2>/dev/null)
  if [ "$st" = "FAILED" ] && [ "$fcode" = "CAPABILITY_MISSING" ] && echo "$fmsg" | grep -q "CAP_MISSING:detectors.machineid"; then
    pass "能力门 B：无 machineid 旧清单 fail-closed（CAP_MISSING:detectors.machineid）"
  else
    fail "能力门 B 未 fail-closed: st=$st code=$fcode msg=$fmsg"
  fi

  # 状态 C：绑定全改 OBSERVE（零需求）→ 旧清单在位发布仍 SUCCESS（滚动升级可行）
  local bindings
  bindings=$(sec_get "/api/v1/api-security/machine-identity-bindings?application_id=$APP_ID_P" | python3 -c "
import json,sys
for i in json.load(sys.stdin)['data']['items']: print(i['id'], i['version'])")
  local bid bver
  echo "$bindings" | while read -r bid bver; do
    [ -n "$bid" ] && sec_put "/api/v1/api-security/machine-identity-bindings/$bid" "{\"mode\":\"OBSERVE\",\"proof_required\":false,\"version\":$bver}" > /dev/null
  done
  # 旧清单重写（防 janitor 回写真实清单导致状态 C 失真）
  docker exec -i jiuzhang-stage5-api sh -c 'cat > /var/run/caddy/sidecars/capability.json' < "$EVID/capability-old.json"
  PUB=$(publish_patient)
  [ "$PUB" = "PUBLISH_OK" ] && pass "能力门 C：全 OBSERVE 零需求（旧清单在位发布 SUCCESS）" \
    || fail "能力门 C 发布失败: $PUB"

  # 状态 A：恢复真实清单 + 绑定回 PROTECT → 发布 SUCCESS
  docker exec -i jiuzhang-stage5-api sh -c 'cat > /var/run/caddy/sidecars/capability.json' < "$EVID/capability-real.json"
  bindings=$(sec_get "/api/v1/api-security/machine-identity-bindings?application_id=$APP_ID_P" | python3 -c "
import json,sys
for i in json.load(sys.stdin)['data']['items']: print(i['id'], i['version'])")
  echo "$bindings" | while read -r bid bver; do
    [ -n "$bid" ] && sec_put "/api/v1/api-security/machine-identity-bindings/$bid" "{\"mode\":\"PROTECT\",\"proof_required\":true,\"version\":$bver}" > /dev/null
  done
  PUB=$(publish_patient)
  [ "$PUB" = "PUBLISH_OK" ] && pass "能力门 A：真实清单+PROTECT 绑定收载（发布 SUCCESS）" \
    || fail "能力门 A 恢复发布失败: $PUB"
  record "capgate 完成（环境已恢复 PROTECT 绑定+真实清单）"
}

case "$PHASE" in
  setup) do_setup ;;
  i01) do_i01 ;;
  i02) do_i02 ;;
  i03) do_i03 ;;
  i05) do_i05 ;;
  i04) do_i04 ;;
  c04) do_c04 ;;
  c01) do_c01 ;;
  acl) do_acl ;;
  capgate) do_capgate ;;
  all)
    do_setup; do_i01; do_i02; do_i03; do_i05; do_i04; do_c04; do_c01; do_acl; do_capgate
    record "ALL PHASES DONE evid=$EVID"
    ;;
  *) echo "unknown phase: $PHASE" >&2; exit 2 ;;
esac
