#!/usr/bin/env bash
# P1-02 B5 BOT-024 升级/关闭/回退演练（真实 stage5 栈，与 run.sh 同夹具口径）：
#   相位 A 升级    当前工作树正式构建镜像（compose build）并升级栈（相当于 1.0.0→候选），
#                  镜像 ID/健康状态留证
#   相位 B 基线    Bot PROTECT 发布生效中：真实业务流量触发挑战（第 3 次合格导航 403），
#                  curl + python3 现场求解 PoW → verify 204 → clearance 通行 200
#   相位 C 关闭    发布 bot OFF（RESERVED_TOMBSTONE 墓碑）→ 再放真实业务流量：
#                  合格导航直达源站 200（挑战主动行为停止）；verify POST→404 / GET→405 /
#                  未知子路径→404（墓碑语义，均本地不转发）；SQLi 仍被 CRS 403（其余防护
#                  继续）；历史 BOT 事件在事件中心 API 可读
#   相位 D 回退    回滚到 PROTECT 版本重新发布 → 挑战恢复；旧 clearance（policy_epoch=1）
#                  按代次撤销不复活（持旧双 Cookie 仍被重新挑战）；新挑战可完整求解通行
#   相位 E 记录    每次发布的任务状态/节点结果 JSON 与 BOT 事件列表全量留证
#
# 词表：PASS / FAIL / BLOCKED（与 p0bench/run.sh 一致）；环境缺失 → BLOCKED 退出码 3。
# 用法：bash test/e2e/bot-challenge/rollback-drill.sh
# 依赖：docker(compose 插件)、curl、openssl、python3（cryptography 包）
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

# ---- 每轮随机口令/密钥（仅本轮临时栈；mktemp 0700）----
WORK_DIR="$(mktemp -d)"
chmod 700 "$WORK_DIR"
DUMP_DIR=""
ENV_FILE="$WORK_DIR/bot-drill.env"
PG_USER="jiuzhang"
PG_DB="jiuzhang_waf"
PG_PWD="$(openssl rand -hex 16)"
VK_PWD="$(openssl rand -hex 16)"
ADMIN_PWD="Ci$(openssl rand -hex 8)1!"
ADMIN_NEW_PWD="Ci$(openssl rand -hex 8)2!"
SEC_PWD_CI="CiSec@$(openssl rand -hex 6)1"
MASTER_KEY="$(openssl rand -hex 32)"
IDENTITY_SALT="$(openssl rand -hex 32)"
BOT_KEY_REF="bot-drill-hmac"
BOT_KEY_HEX="$(openssl rand -hex 32)"
LIC_KEY_ID="bot-drill-key"

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
    "license_id": "LIC-BOT-DRILL-0001", "license_type": "FORMAL", "product": "wdsp",
    "customer": "Bot Rollback Drill", "issued_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
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

mkdir -p "$EVIDENCE_DIR"/phase-{a-upgrade,b-protect,c-off,d-rollback}

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
echo "P1-02 B5 BOT-024 升级/关闭/回退演练  run_id=$RUN_ID"
echo "api=$API_URL site=$SITE_URL"
echo "============================================================"

# ==================== 相位 A：正式构建升级 ====================
echo "[A] 从当前工作树构建 api/gateway/testorigin 镜像（升级路径：工作树=候选版本）..."
"${COMPOSE[@]}" build api gateway testorigin > "$EVIDENCE_DIR/phase-a-upgrade/build.log" 2>&1 || {
  echo "镜像构建失败，日志 $EVIDENCE_DIR/phase-a-upgrade/build.log" >&2; exit 1; }
record "A 正式构建镜像（工作树源码，build.log 留证）" 1

mkdir -p runtime/license
"${COMPOSE[@]}" up -d api gateway >/dev/null
"${COMPOSE[@]}" images > "$EVIDENCE_DIR/phase-a-upgrade/images.txt" 2>&1 || true
docker version --format 'server={{.Server.Version}}' > "$EVIDENCE_DIR/phase-a-upgrade/docker-version.txt" 2>/dev/null || true

wait_http "$API_URL/api/v1/health" 200 600 || {
  "${COMPOSE[@]}" logs --tail=120 api >&2 || true; exit 1; }
curl -s "$API_URL/api/v1/health" > "$EVIDENCE_DIR/phase-a-upgrade/health.json"
record "A 升级后 api 健康检查通过" 1

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
export SEC_USER="bot_drill_sec" SEC_PWD="$SEC_PWD_CI"
export APP_CODE="botdrill"
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
print(json.dumps({"name": "bot-drill-selfsigned", "cert_pem": cert, "key_pem": key, "chain_pem": cert}))
PY
CERT_ID="$(sec_api POST /api/v1/certificates "$WORK_DIR/cert-upload.json" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['id'])" 2>/dev/null)"
[ -n "$CERT_ID" ] || { record "上传自签测试证书" 0 "cert_id 为空"; echo ABORT; exit 1; }

APP_ID="$(sec_api POST /api/v1/applications /dev/stdin <<EOF \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['id'])" 2>/dev/null
{"code":"$APP_CODE","name":"Bot回退演练应用","description":"P1-02 B5 BOT-024 升级/关闭/回退","business_owner":"test","technical_owner":"test","protection_mode":"PROTECT"}
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
VALUES ('gateway_runtime','identity_salt','"$IDENTITY_SALT"','string','bot-drill：身份指纹盐（随机，仅本轮栈）')
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
print("VALUES ('gateway_runtime','bot_signing_keys','\"%s\"','string','bot-drill：Bot签名密钥（随机，仅本轮栈）')" % cipher)
print("ON CONFLICT (setting_group, setting_key) DO UPDATE")
print("SET setting_value = EXCLUDED.setting_value, updated_at = now(), version = system_settings.version + 1;")
PY
docker exec -i jiuzhang-stage5-postgres psql -U "$PG_USER" -d "$PG_DB" -v ON_ERROR_STOP=1 \
  < "$WORK_DIR/seed-keys.sql" >/dev/null
record "种子播种（identity_salt + bot_signing_keys 密文）" 1

# ---- 启用身份行为观测（Bot 行为信号数据源）----
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

# ---- Bot 策略文档生成（PROTECT / OFF 两版；expected_version 调用点注入）----
mk_bot_policy() { # <PROTECT|OFF> <expected_version> <outfile>
  python3 - "$BOT_KEY_REF" "$1" "$2" <<'PY' > "$3"
import json, sys
key_ref, mode, ev = sys.argv[1], sys.argv[2], int(sys.argv[3])
if mode == "PROTECT":
    print(json.dumps({
        "mode": "PROTECT", "expected_version": ev,
        "selectors": [{"path_exact": "/"}],
        "signal_rules": {
            "min_independent_groups": 2, "require_behavior_group": True,
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
        "reason": "bot-drill: PROTECT（演练策略）",
    }))
else:
    # 从已启用状态关闭：RESERVED_TOMBSTONE 保留本地 404/405 墓碑（旧挑战提交不落入源站）
    print(json.dumps({
        "mode": "OFF", "expected_version": ev,
        "route_reservation": {"state": "RESERVED_TOMBSTONE", "namespace": "/_wdsp/bot/v1/"},
        "reason": "bot-drill: 关闭 Bot（OFF + 墓碑保留）",
    }))
PY
}

# ---- 发布并留证（任务状态/节点结果全量 JSON）----
publish_evidence() { # <phase-tag>
  local tag="$1" pub
  pub="$(s5_publish "$SEC_CSRF" || true)"
  echo "[publish:${tag}] result=$pub"
  sec_api GET "/api/v1/publish-tasks?page=1&page_size=1" \
    > "$EVIDENCE_DIR/publish-${tag}-list.json" 2>/dev/null || true
  local tid
  tid="$(python3 -c "import json,sys; d=json.load(open('$EVIDENCE_DIR/publish-${tag}-list.json'))['data']; items=d.get('items') or d.get('list') or []; print(items[0]['id'] if items else '')" 2>/dev/null || true)"
  if [ -n "$tid" ]; then
    sec_api GET "/api/v1/publish-tasks/$tid" > "$EVIDENCE_DIR/publish-${tag}-task.json" 2>/dev/null || true
  fi
  [ "$pub" = "PUBLISH_OK" ]
}

# ---- 网关探测与 PoW 求解 ----
gw() { curl -sk --max-time 15 --resolve "$SITE_HOST:$SITE_HTTPS_PORT:127.0.0.1" "$@"; }
NAV_HEADERS=(-H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,*/*;q=0.8'
  -H 'Accept-Language: zh-CN,zh;q=0.9'
  -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36')

solve_pow() { # <challenge_html> → {"challenge_id","solution"}（与页内 JS/Go botchallenge.Solve 同一构造）
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

# solve_and_pass <jar> <dir> <tag>：挑战页求解 → verify 204 → 带双 Cookie 直达 200
solve_and_pass() {
  local jar="$1" dir="$2" tag="$3" body
  body="$(solve_pow "$dir/challenge-${tag}.html")" || { echo "pow 求解失败"; return 1; }
  echo "$body" > "$dir/pow-${tag}.json"
  local vcode
  vcode="$(gw -D "$dir/verify-${tag}.headers" -o "$dir/verify-${tag}.json" -w '%{http_code}' \
    -b "$jar" -c "$jar" -X POST -H 'Content-Type: application/json' \
    -H "Origin: $SITE_URL" -H 'Sec-Fetch-Site: same-origin' \
    -d "$body" "$SITE_URL/_wdsp/bot/v1/verify")"
  [ "$vcode" = "204" ] || { echo "verify status=${vcode}"; return 1; }
  grep -qi '^set-cookie:.*__Host-wdsp-bot-clearance' "$dir/verify-${tag}.headers" || {
    echo "verify 未签发 clearance"; return 1; }
  local pcode
  pcode="$(gw -o "$dir/pass-${tag}.txt" -w '%{http_code}' -b "$jar" -c "$jar" \
    "${NAV_HEADERS[@]}" "$SITE_URL/")"
  [ "$pcode" = "200" ] || { echo "clearance 通行 status=${pcode}"; return 1; }
  return 0
}

# ==================== 相位 B：PROTECT 基线（挑战生效 + 完整通行链）====================
echo "[B] PUT Bot PROTECT（v1）并发布 ..."
mk_bot_policy PROTECT 0 "$WORK_DIR/bot-protect.json"
expect_code "B PUT Bot PROTECT 草稿（v0→v1）" 200 \
  "$(sec_api_code PUT "/api/v1/applications/$APP_ID/bot-policy" "$WORK_DIR/bot-protect.json")"
sec_api POST "/api/v1/applications/$APP_ID/bot-policy/preflight" /dev/stdin <<'EOF' \
  > "$EVIDENCE_DIR/phase-b-protect/preflight.json"
{}
EOF
publish_evidence "b-protect" && record "B PROTECT 发布成功（publish-b-protect-task.json 留证）" 1 \
  || { record "B PROTECT 发布成功" 0 "见 publish-b-protect-*.json"; echo ABORT; exit 1; }
wait_gateway_app 90 || { record "B 发布生效后网关 HTTPS 可达" 0 "超时"; echo ABORT; exit 1; }

JAR_B="$WORK_DIR/jar-b.txt"; : > "$JAR_B"
code1="$(gw -o "$EVIDENCE_DIR/phase-b-protect/nav-1.html" -w '%{http_code}' -b "$JAR_B" -c "$JAR_B" "${NAV_HEADERS[@]}" "$SITE_URL/")"
code2="$(gw -o "$EVIDENCE_DIR/phase-b-protect/nav-2.html" -w '%{http_code}' -b "$JAR_B" -c "$JAR_B" "${NAV_HEADERS[@]}" "$SITE_URL/")"
code3="$(gw -D "$EVIDENCE_DIR/phase-b-protect/nav-3.headers" -o "$EVIDENCE_DIR/phase-b-protect/challenge-b.html" -w '%{http_code}' -b "$JAR_B" -c "$JAR_B" "${NAV_HEADERS[@]}" "$SITE_URL/")"
echo "[B] nav 序列 status=${code1}/${code2}/${code3}"
if [ "$code1" = "200" ] && [ "$code2" = "200" ] && [ "$code3" = "403" ] \
  && grep -q '安全验证' "$EVIDENCE_DIR/phase-b-protect/challenge-b.html"; then
  record "B PROTECT 基线：第 3 次合格导航被挑战 403" 1
else
  record "B PROTECT 基线：第 3 次合格导航被挑战 403" 0 "status=${code1}/${code2}/${code3}"
fi
if [ "$code3" = "403" ] && solve_and_pass "$JAR_B" "$EVIDENCE_DIR/phase-b-protect" "b"; then
  record "B PoW 求解 → verify 204 → clearance 通行 200（epoch=1 通行签发）" 1
else
  record "B PoW 求解 → verify 204 → clearance 通行 200" 0 "见 phase-b-protect/verify-b.json"
fi

# ==================== 相位 C：发布 OFF（墓碑）→ 真实业务流量 ====================
echo "[C] PUT Bot OFF（RESERVED_TOMBSTONE，v1→v2）并发布 ..."
mk_bot_policy OFF 1 "$WORK_DIR/bot-off.json"
expect_code "C PUT Bot OFF 草稿（v1→v2）" 200 \
  "$(sec_api_code PUT "/api/v1/applications/$APP_ID/bot-policy" "$WORK_DIR/bot-off.json")"
publish_evidence "c-off" && record "C OFF 发布成功（publish-c-off-task.json 留证）" 1 \
  || { record "C OFF 发布成功" 0 "见 publish-c-off-*.json"; echo ABORT; exit 1; }
wait_gateway_app 90 || { record "C 发布生效后网关 HTTPS 可达" 0 "超时"; echo ABORT; exit 1; }

# 挑战主动行为停止：连续合格导航全部直达源站 200（行为计数仍在累积，若 OFF 生效必无挑战）
JAR_C="$WORK_DIR/jar-c.txt"; : > "$JAR_C"
off_all200=1
for i in 1 2 3 4; do
  c="$(gw -o "$EVIDENCE_DIR/phase-c-off/nav-${i}.html" -w '%{http_code}' -b "$JAR_C" -c "$JAR_C" "${NAV_HEADERS[@]}" "$SITE_URL/")"
  echo "[C] OFF 后第 ${i} 次合格导航 status=${c}"
  if [ "$c" != "200" ] || grep -q '安全验证' "$EVIDENCE_DIR/phase-c-off/nav-${i}.html" 2>/dev/null; then
    off_all200=0
  fi
done
[ "$off_all200" = "1" ] && record "C 关闭后挑战主动行为停止（4 次合格导航全 200 直达源站）" 1 \
  || record "C 关闭后挑战主动行为停止" 0 "见 phase-c-off/nav-*.html"

# 墓碑语义：verify POST→404、GET→405、未知子路径→404（本地，不转发源站）
tpost="$(gw -o "$EVIDENCE_DIR/phase-c-off/verify-post.json" -w '%{http_code}' \
  -b "$JAR_B" -X POST -H 'Content-Type: application/json' -H "Origin: $SITE_URL" \
  -d '{"challenge_id":"00000000000000000000000000000000","solution":"0"}' \
  "$SITE_URL/_wdsp/bot/v1/verify")"
expect_code "C OFF 墓碑：verify POST → 404" 404 "$tpost"
tget="$(gw -o /dev/null -w '%{http_code}' -X GET "$SITE_URL/_wdsp/bot/v1/verify")"
expect_code "C OFF 墓碑：verify GET → 405" 405 "$tget"
tunk="$(gw -o /dev/null -w '%{http_code}' "${NAV_HEADERS[@]}" "$SITE_URL/_wdsp/bot/v1/unknown")"
expect_code "C OFF 墓碑：未知子路径 → 404" 404 "$tunk"

# 其余防护继续：SQLi 仍被 CRS 403（且非挑战页）
scode="$(gw -o "$EVIDENCE_DIR/phase-c-off/sqli.html" -w '%{http_code}' \
  "${NAV_HEADERS[@]}" "$SITE_URL/?id=1%27%20OR%20%271%27=%271")"
if [ "$scode" = "403" ] && ! grep -q '安全验证' "$EVIDENCE_DIR/phase-c-off/sqli.html"; then
  record "C 其余防护继续：SQLi 仍被 WAF/CRS 403（非挑战页）" 1
else
  record "C 其余防护继续：SQLi 仍被 WAF/CRS 403" 0 "status=${scode}"
fi

# 历史 BOT 事件在事件中心 API 可读
bot_ev_total="$(s5_event_count "BOT_CHALLENGE_OFFERED")"
sec_api GET "/api/v1/access-control-events?event_type=BOT_CHALLENGE_OFFERED&page=1&page_size=5" \
  > "$EVIDENCE_DIR/phase-c-off/events-bot-offered.json" 2>/dev/null || true
if [ "${bot_ev_total:-0}" -ge 1 ] 2>/dev/null; then
  record "C 历史 BOT 事件在事件中心 API 可读（BOT_CHALLENGE_OFFERED total=${bot_ev_total}）" 1
else
  record "C 历史 BOT 事件在事件中心 API 可读" 0 "total=${bot_ev_total:-查询失败}"
fi

# ==================== 相位 D：回退到 PROTECT（v2→v3）====================
echo "[D] 回退：PUT Bot PROTECT（v2→v3）并发布 ..."
mk_bot_policy PROTECT 2 "$WORK_DIR/bot-protect-v3.json"
expect_code "D PUT Bot PROTECT 回退草稿（v2→v3）" 200 \
  "$(sec_api_code PUT "/api/v1/applications/$APP_ID/bot-policy" "$WORK_DIR/bot-protect-v3.json")"
publish_evidence "d-rollback" && record "D 回退 PROTECT 发布成功（publish-d-rollback-task.json 留证）" 1 \
  || { record "D 回退 PROTECT 发布成功" 0 "见 publish-d-rollback-*.json"; echo ABORT; exit 1; }
wait_gateway_app 90 || { record "D 发布生效后网关 HTTPS 可达" 0 "超时"; echo ABORT; exit 1; }

# 挑战恢复：OFF 期间行为计数持续累积，达阈后挑战应在 ≤5 次导航内复现
JAR_D="$WORK_DIR/jar-d.txt"; : > "$JAR_D"
d_challenge=""
for i in 1 2 3 4 5; do
  c="$(gw -D "$EVIDENCE_DIR/phase-d-rollback/nav-${i}.headers" -o "$EVIDENCE_DIR/phase-d-rollback/nav-${i}.html" -w '%{http_code}' -b "$JAR_D" -c "$JAR_D" "${NAV_HEADERS[@]}" "$SITE_URL/")"
  echo "[D] 回退后第 ${i} 次合格导航 status=${c}"
  if [ "$c" = "403" ] && grep -q '安全验证' "$EVIDENCE_DIR/phase-d-rollback/nav-${i}.html"; then
    cp "$EVIDENCE_DIR/phase-d-rollback/nav-${i}.html" "$EVIDENCE_DIR/phase-d-rollback/challenge-d.html"
    d_challenge="yes"; break
  fi
done
[ -n "$d_challenge" ] && record "D 回退后挑战恢复（≤5 次导航内复现 403 挑战页）" 1 \
  || record "D 回退后挑战恢复" 0 "5 次导航均未挑战（见 phase-d-rollback/nav-*.html）"

# 旧 clearance（epoch=1）按代次撤销不复活：持相位 B 的双 Cookie 仍被重新挑战
old_code="$(gw -o "$EVIDENCE_DIR/phase-d-rollback/old-clearance.html" -w '%{http_code}' \
  -b "$JAR_B" "${NAV_HEADERS[@]}" "$SITE_URL/")"
if [ "$old_code" = "403" ] && grep -q '安全验证' "$EVIDENCE_DIR/phase-d-rollback/old-clearance.html"; then
  record "D 旧 clearance 按 policy_epoch 代次撤销不复活（持旧双 Cookie 重新挑战 403）" 1
else
  record "D 旧 clearance 按 policy_epoch 代次撤销不复活" 0 "status=${old_code}"
fi

# 新挑战可完整求解通行（回退后链路无损）
if [ -n "$d_challenge" ] && solve_and_pass "$JAR_D" "$EVIDENCE_DIR/phase-d-rollback" "d"; then
  record "D 回退后 PoW 求解 → verify 204 → 新 clearance 通行 200" 1
else
  record "D 回退后 PoW 求解 → verify 204 → 新 clearance 通行 200" 0 "见 phase-d-rollback/verify-d.json"
fi

# ==================== 相位 E：汇总与证据 ====================
echo "============================================================"
echo "P1-02 B5 BOT-024 演练汇总: 总项 $TOTAL 通过 $PASS 失败 $FAIL"
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
    "task": "P1-02 B5 BOT-024 升级/关闭/回退演练",
    "finished_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "totals": {"total": total, "pass": passed, "fail": failed, "blocked": 0},
    "phases": {
        "a-upgrade": {"evidence": "phase-a-upgrade/"},
        "b-protect-baseline": {"evidence": "phase-b-protect/"},
        "c-off-tombstone": {"evidence": "phase-c-off/"},
        "d-rollback-protect": {"evidence": "phase-d-rollback/"},
        "publish-evidence": {"evidence": "publish-*.json"},
    },
    "verdict": "PASS" if failed == 0 else "FAIL",
}
with open(os.path.join(ev, "status.json"), "w") as f:
    json.dump(status, f, ensure_ascii=False, indent=2)
PY

SCRIPT_DONE=1
[ "$FAIL" -eq 0 ]
