#!/usr/bin/env bash
# P1-04 R4a 安全回归管理界面 E2E（真实 stage5 栈，不 mock）：
#   栈：deployment/docker-compose.stage5.yml + docker-compose.wdsp.yml（与 bot-challenge 同口径）；
#   真实证据：tools/regsign genkey/canonicalize/sign 生成 Ed25519 签名的回归报告，
#             受信公钥经 psql 播种 system_settings security_regression:trusted_verify_keys，
#             证据对象经 POST /security/regression-objects 上传、imports API 登记（服务端真实核验）；
#   界面链路：vite dev（5173，/api/v1 代理到 18081）+ Playwright Chromium：
#             列表 → 详情（gate_assessment）→ 用例差异（分类/纯文本）→ 配置发布页门禁状态
#             → ENFORCE 后真实发布被 REGRESSION_GATE_REJECTED → 缺失项展示 + 深链跳转。
#
# 词表：PASS / FAIL / BLOCKED / NOT_RUN（与 bot-challenge 一致）；环境缺失 → BLOCKED/ENVIRONMENT_UNAVAILABLE。
# 用法：bash test/e2e/security-regression/run.sh
# 依赖：docker(compose 插件)、curl、openssl、python3、node/npx（web/ 的 Playwright 与 vite）、
#       tools/regsign（预编译二进制或本机 go 工具链兜底）
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT"

API_PORT="${API_PORT:-18081}"
GATEWAY_PORT="${GATEWAY_PORT:-18080}"
WEB_PORT="${WEB_PORT:-5173}"
API_URL="http://127.0.0.1:$API_PORT"
WEB_URL="http://127.0.0.1:$WEB_PORT"
PG_PORT="${PG_PORT:-5432}"
VK_PORT="${VK_PORT:-6379}"
RUN_ID="$(date +%Y%m%dT%H%M%S)-$(openssl rand -hex 3)"
EVIDENCE_DIR="test/e2e/security-regression/runs/$RUN_ID"

# ---- 每轮随机口令/密钥（仅本轮临时栈使用；mktemp 目录权限 0700）----
WORK_DIR="$(mktemp -d)"
chmod 700 "$WORK_DIR"
DUMP_DIR=""
ENV_FILE="$WORK_DIR/reg-e2e.env"
PG_USER="jiuzhang"
PG_DB="jiuzhang_waf"
PG_PWD="$(openssl rand -hex 16)"
VK_PWD="$(openssl rand -hex 16)"
ADMIN_PWD="Ci$(openssl rand -hex 8)1!"
ADMIN_NEW_PWD="Ci$(openssl rand -hex 8)2!"
SEC_PWD_CI="CiSec@$(openssl rand -hex 6)1"
MASTER_KEY="$(openssl rand -hex 32)"
LIC_KEY_ID="reg-e2e-key"
REG_KEY_ID="e2e-verifier-$(date +%Y%m%d)-$(openssl rand -hex 2)"

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
command -v python3 >/dev/null 2>&1 || preflight_fail "python3 不可用"

# regsign：优先预编译二进制；不可用则 go run 兜底；两者皆缺 → BLOCKED
REGSIGN=()
if [ -x tools/regsign/regsign ]; then
  REGSIGN=(tools/regsign/regsign)
elif command -v go >/dev/null 2>&1; then
  REGSIGN=(go -C tools/regsign run .)
else
  preflight_fail "tools/regsign 不可用（无预编译二进制且无 go 工具链）"
fi

# ---- CI 临时 Ed25519 授权（与 bot-challenge 同口径，解锁授权门控）----
openssl genpkey -algorithm ed25519 -out "$WORK_DIR/lic-key.pem" >/dev/null 2>&1
chmod 600 "$WORK_DIR/lic-key.pem"
LIC_PUB_HEX="$(openssl pkey -in "$WORK_DIR/lic-key.pem" -pubout -outform DER 2>/dev/null \
  | tail -c 32 | python3 -c 'import sys; print(sys.stdin.buffer.read().hex())')"
python3 - "$WORK_DIR" "$LIC_KEY_ID" <<'PY'
import json, sys, datetime
work_dir, key_id = sys.argv[1], sys.argv[2]
payload = {
    "license_id": "LIC-REG-E2E-0001", "license_type": "FORMAL", "product": "wdsp",
    "customer": "Regression E2E", "issued_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
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
for p in "$PG_PORT" "$VK_PORT" "$API_PORT" "$GATEWAY_PORT" "$WEB_PORT"; do
  if ! port_free "$p"; then
    echo "BLOCKED/ENVIRONMENT_UNAVAILABLE: 127.0.0.1:$p 已被占用" >&2
    rm -rf "$WORK_DIR"; exit 3
  fi
done
if [ -n "$("${COMPOSE[@]}" ps -q 2>/dev/null)" ]; then
  echo "BLOCKED/ENVIRONMENT_UNAVAILABLE: 检测到 stage5 编排已有容器在运行" >&2
  rm -rf "$WORK_DIR"; exit 3
fi
# 防御性清卷：口令每轮随机，残留卷会让 api 起不来
"${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true

mkdir -p "$EVIDENCE_DIR"

WEB_PID=""
cleanup() {
  local rc=$?
  if [ "$rc" -eq 0 ] && [ "${SCRIPT_DONE:-0}" != "1" ]; then rc=1; fi
  if [ -n "$WEB_PID" ]; then kill "$WEB_PID" >/dev/null 2>&1 || true; fi
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 3 ]; then
    DUMP_DIR="$EVIDENCE_DIR/stack-dump"
    mkdir -p "$DUMP_DIR"
    {
      echo "==== compose ps ===="; "${COMPOSE[@]}" ps 2>&1
      echo; echo "==== api 日志尾部 ===="; "${COMPOSE[@]}" logs --tail=200 api 2>&1
      echo; echo "==== vite dev 日志尾部 ===="; tail -n 60 "$EVIDENCE_DIR/vite-dev.log" 2>&1 || true
    } > "$DUMP_DIR/stack-dump.log" 2>&1 || true
    echo "失败诊断日志（不含密钥/Token）：$DUMP_DIR/stack-dump.log" >&2
  fi
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK_DIR"
  exit "$rc"
}
trap cleanup EXIT

echo "============================================================"
echo "P1-04 R4a 安全回归管理界面 E2E  run_id=$RUN_ID"
echo "api=$API_URL web=$WEB_URL"
echo "============================================================"

# ---- 镜像：api 含 R3 回归域代码，必须从当前工作树重建 ----
echo "[build] 从当前工作树构建 api/gateway 镜像 ..."
"${COMPOSE[@]}" build api gateway

echo "[up] 启动 postgres/valkey/gateway/api ..."
"${COMPOSE[@]}" up -d api gateway

wait_http "$API_URL/api/v1/health" 200 600 || {
  echo "==== api 容器状态与日志尾部 ====" >&2
  "${COMPOSE[@]}" ps api >&2 || true
  "${COMPOSE[@]}" logs --tail=120 api >&2 || true
  exit 1
}
record "api 健康检查通过" 1

# ---- 登录/用户/发布 复用阶段5公共函数 ----
export API_URL GATEWAY_URL="http://127.0.0.1:$GATEWAY_PORT"
export HOST_HEADER="reg-e2e.local"
export VALKEY_PASSWORD="$VK_PWD" VALKEY_CONTAINER="jiuzhang-stage5-valkey"
export SYS_USER="jiuzhang_admin" SYS_PWD="$ADMIN_PWD" SYS_NEW_PWD="$ADMIN_NEW_PWD"
export SEC_USER="reg_e2e_sec" SEC_PWD="$SEC_PWD_CI"
export APP_CODE="rege2e"
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
record "安全管理员就绪（SECURITY_ADMIN 含 security_regression.* 种子权限）" 1

sec_api() { # <method> <path> [bodyfile]
  local m="$1" p="$2" bf="${3:-}"
  local args=(-s -b "/tmp/s5-$SEC_USER.txt" -X "$m" "$API_URL$p"
    -H "X-CSRF-Token: $SEC_CSRF")
  [ -n "$bf" ] && args+=(-H 'Content-Type: application/json' --data-binary "@$bf")
  curl "${args[@]}"
}
sec_api_code() { # <method> <path> [bodyfile] → http code
  local m="$1" p="$2" bf="${3:-}"
  local args=(-s -o /dev/null -w '%{http_code}' -b "/tmp/s5-$SEC_USER.txt" -X "$m" "$API_URL$p"
    -H "X-CSRF-Token: $SEC_CSRF")
  [ -n "$bf" ] && args+=(-H 'Content-Type: application/json' --data-binary "@$bf")
  curl "${args[@]}"
}

# ---- 回归验签密钥：regsign genkey，私钥只在 mktemp，公钥经 psql 播种受信登记 ----
"${REGSIGN[@]}" genkey -key-id "$REG_KEY_ID" -out "$WORK_DIR/verifier.key" \
  > "$WORK_DIR/verifier.pub.json" 2>"$WORK_DIR/verifier.genkey.log"
python3 - "$WORK_DIR/verifier.pub.json" > "$WORK_DIR/seed-trusted-keys.sql" <<'PY'
import json, sys
entry = json.load(open(sys.argv[1]))
assert entry["algorithm"] == "ed25519" and entry["status"] == "ACTIVE"
# system_settings.setting_value 为 JSON 值；GetString 期望 JSON 字符串，
# 其内容再按 []TrustedKey 解析（与 LoadTrustedKeys 口径一致）→ 双重编码
inner = json.dumps([entry], ensure_ascii=False)
setting = json.dumps(inner, ensure_ascii=False)
print("INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, description)")
print("VALUES ('security_regression','trusted_verify_keys','%s','string','reg-e2e：回归验签受信公钥（随机，仅本轮栈）')" % setting)
print("ON CONFLICT (setting_group, setting_key) DO UPDATE")
print("SET setting_value = EXCLUDED.setting_value, updated_at = now(), version = system_settings.version + 1;")
PY
docker exec -i jiuzhang-stage5-postgres psql -U "$PG_USER" -d "$PG_DB" -v ON_ERROR_STOP=1 \
  < "$WORK_DIR/seed-trusted-keys.sql" >/dev/null
record "回归验签受信公钥（trusted_verify_keys）播种" 1

# ---- 构造两份真实回归证据（规范形 + Ed25519 签名 + 受控对象上传 + imports 登记）----
# run1：全过（FULL/PASS，门禁评估可用）；run2：声明 FAIL 且强制用例失败（门禁评估不可用，
# 用例差异含恶意 HTML 串样本，供界面纯文本断言）。
python3 - "$WORK_DIR" "$RUN_ID" <<'PY'
import json, sys, hashlib, datetime
work_dir, run_id = sys.argv[1], sys.argv[2]
now = datetime.datetime.now(datetime.timezone.utc)
ts = lambda d: d.strftime("%Y-%m-%dT%H:%M:%SZ")
fp = lambda seed: "cfgfpv1:" + hashlib.sha256(("cfg-" + seed).encode()).hexdigest()
h64 = lambda seed: hashlib.sha256(seed.encode()).hexdigest()

runs = [
    {
        "dir": "run1", "run_id": "e2e-reg-%s-pass" % run_id, "level": "FULL",
        "declared_status": "PASS",
        "cases": [
            {"case_id": "sqli-001", "case_version": 3, "family": "sqli", "truth": "ATTACK",
             "criticality": "MANDATORY", "status": "PASS",
             "expected_action": "BLOCK", "observed_action": "BLOCK"},
            {"case_id": "xss-009", "case_version": 1, "family": "xss", "truth": "ATTACK",
             "criticality": "MANDATORY", "status": "PASS",
             "expected_action": "BLOCK", "observed_action": "BLOCK"},
            {"case_id": "benign-017", "case_version": 2, "family": "benign", "truth": "BENIGN",
             "criticality": "MANDATORY", "status": "PASS",
             "expected_action": "ALLOW", "observed_action": "ALLOW"},
            {"case_id": "rce-201", "case_version": 1, "family": "rce", "truth": "ATTACK",
             "criticality": "OPTIONAL", "status": "PASS",
             "expected_action": "BLOCK", "observed_action": "BLOCK"},
        ],
        "counts": {"planned": 4, "executed": 4, "skipped": 0, "blocked": 0, "not_run": 0,
                   "passed": 4, "failed": 0, "mandatory_total": 3, "mandatory_failed": 0},
    },
    {
        "dir": "run2", "run_id": "e2e-reg-%s-diff" % run_id, "level": "FULL",
        "declared_status": "FAIL",
        "cases": [
            {"case_id": "sqli-002", "case_version": 1, "family": "sqli", "truth": "ATTACK",
             "criticality": "MANDATORY", "status": "FAIL",
             "expected_action": "BLOCK", "observed_action": "ALLOW",
             "diff": {"expected_action": "BLOCK", "observed_action": "ALLOW",
                      "observed_payload_sample": "<img src=x onerror=alert(1)><script>alert(2)</script>"}},
            {"case_id": "benign-042", "case_version": 1, "family": "benign", "truth": "BENIGN",
             "criticality": "OPTIONAL", "status": "FAIL",
             "expected_action": "ALLOW", "observed_action": "BLOCK",
             "diff": {"expected_action": "ALLOW", "observed_action": "BLOCK",
                      "rule_hit": "942100"}},
            {"case_id": "xss-009", "case_version": 1, "family": "xss", "truth": "ATTACK",
             "criticality": "OPTIONAL", "status": "PASS",
             "expected_action": "BLOCK", "observed_action": "BLOCK"},
            {"case_id": "ratelimit-88", "case_version": 1, "family": "ratelimit", "truth": "UNKNOWN",
             "criticality": "OPTIONAL", "status": "SKIP"},
        ],
        "counts": {"planned": 4, "executed": 3, "skipped": 1, "blocked": 0, "not_run": 0,
                   "passed": 1, "failed": 2, "mandatory_total": 1, "mandatory_failed": 1},
    },
]
for r in runs:
    d = work_dir + "/" + r["dir"]
    import os
    os.makedirs(d, exist_ok=True)
    chunk = {"schema_version": 1, "run_id": r["run_id"], "cases": r["cases"]}
    with open(d + "/cases-0001.json", "w") as f:
        json.dump(chunk, f, ensure_ascii=False, indent=2)
    manifest = {
        "schema_version": 1,
        "run_id": r["run_id"],
        "level": r["level"],
        "created_at": ts(now),
        "run_started_at": ts(now - datetime.timedelta(minutes=5)),
        "run_finished_at": ts(now - datetime.timedelta(minutes=2)),
        "declared_status": r["declared_status"],
        "candidate": {
            "config_fingerprint": fp(r["run_id"]),
            "build_digest": "sha256:" + h64("build-" + r["run_id"]),
            "compiler": "regc-e2e-1.0.0",
            "corpus_id": "corpus-e2e",
            "corpus_version": 1,
            "corpus_sha256": h64("corpus-" + r["run_id"]),
            "plan_sha256": h64("plan-" + r["run_id"]),
        },
        "counts": r["counts"],
        # files 占位：sha256/size 待对象上传后以服务端计算值回填（调用方无法声明）
        "files": [{"role": "CASES_CHUNK", "name": "cases-0001.json",
                   "sha256": "0" * 64, "size_bytes": 0}],
    }
    with open(d + "/manifest.raw.json", "w") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
print("prepared")
PY
record "两份回归证据素材生成（chunk + manifest 草稿）" 1

# import_one_run <dir> → 打印 run UUID；失败返回空
import_one_run() {
  local d="$1"
  # 1) 用例分块 canonicalize（服务端 ParseCasesChunk 要求规范形字节）后上传，
  #    sha256/size 以服务端计算值为准（调用方无法声明）
  "${REGSIGN[@]}" canonicalize -in "$WORK_DIR/$d/cases-0001.json" \
    -out "$WORK_DIR/$d/cases-0001.canon.json" 2>/dev/null
  local obj_resp obj_id obj_sha obj_size
  obj_resp="$(curl -s -b "/tmp/s5-$SEC_USER.txt" -X POST \
    "$API_URL/api/v1/security/regression-objects?kind=CASES_CHUNK" \
    -H "X-CSRF-Token: $SEC_CSRF" -H 'Content-Type: application/octet-stream' \
    --data-binary "@$WORK_DIR/$d/cases-0001.canon.json")"
  obj_id="$(python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["data"]["id"])' <<<"$obj_resp" 2>/dev/null)"
  obj_sha="$(python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["data"]["sha256"])' <<<"$obj_resp" 2>/dev/null)"
  obj_size="$(python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["data"]["size_bytes"])' <<<"$obj_resp" 2>/dev/null)"
  [ -n "$obj_id" ] && [ -n "$obj_sha" ] && [ -n "$obj_size" ] || { echo ""; return 1; }
  # 2) manifest 回填真实 sha256/size → canonicalize → sign
  python3 - "$WORK_DIR/$d" "$obj_sha" "$obj_size" <<'PY'
import json, sys
d, sha, size = sys.argv[1], sys.argv[2], int(sys.argv[3])
m = json.load(open(d + "/manifest.raw.json"))
m["files"][0]["sha256"] = sha
m["files"][0]["size_bytes"] = size
with open(d + "/manifest.filled.json", "w") as f:
    json.dump(m, f, ensure_ascii=False, indent=2)
PY
  "${REGSIGN[@]}" canonicalize -in "$WORK_DIR/$d/manifest.filled.json" -out "$WORK_DIR/$d/manifest.json" 2>/dev/null
  "${REGSIGN[@]}" sign -key "$WORK_DIR/verifier.key" -key-id "$REG_KEY_ID" \
    -manifest "$WORK_DIR/$d/manifest.json" > "$WORK_DIR/$d/signature.json" 2>/dev/null
  # 3) 上传 manifest 对象（kind=MANIFEST）
  local m_resp m_id
  m_resp="$(curl -s -b "/tmp/s5-$SEC_USER.txt" -X POST \
    "$API_URL/api/v1/security/regression-objects?kind=MANIFEST" \
    -H "X-CSRF-Token: $SEC_CSRF" -H 'Content-Type: application/octet-stream' \
    --data-binary "@$WORK_DIR/$d/manifest.json")"
  m_id="$(python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["data"]["id"])' <<<"$m_resp" 2>/dev/null)"
  [ -n "$m_id" ] || { echo ""; return 1; }
  # 4) imports 登记（签名封装原样引用 regsign 输出）
  python3 - "$WORK_DIR/$d" "$m_id" "$obj_id" > "$WORK_DIR/$d/import-req.json" <<'PY'
import json, sys
d, m_id, obj_id = sys.argv[1], sys.argv[2], sys.argv[3]
sig = json.load(open(d + "/signature.json"))
req = {"manifest_object_id": m_id, "signature": sig,
       "objects": [{"object_id": obj_id, "role": "CASES_CHUNK", "name": "cases-0001.json"}]}
print(json.dumps(req))
PY
  local imp_resp
  imp_resp="$(sec_api POST /api/v1/security/regressions/imports "$WORK_DIR/$d/import-req.json")"
  echo "$imp_resp" > "$WORK_DIR/$d/import-resp.json"
  python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["data"]["run"]["id"])' <<<"$imp_resp" 2>/dev/null || echo ""
}

RUN1_UUID="$(import_one_run run1)"
RUN2_UUID="$(import_one_run run2)"
cp "$WORK_DIR/run1/import-resp.json" "$EVIDENCE_DIR/run1-import-resp.json" 2>/dev/null || true
cp "$WORK_DIR/run2/import-resp.json" "$EVIDENCE_DIR/run2-import-resp.json" 2>/dev/null || true
if [ -n "$RUN1_UUID" ] && [ -n "$RUN2_UUID" ]; then
  record "两份签名回归报告经 imports API 登记（201，服务端真实验签）" 1
else
  record "两份签名回归报告经 imports API 登记" 0 "run1=${RUN1_UUID:-失败} run2=${RUN2_UUID:-失败}（详见 evidence import-resp.json）"
  echo ABORT; exit 1
fi
V1="$(python3 -c 'import json; print(json.load(open("'$WORK_DIR'/run1/import-resp.json"))["data"]["run"]["verification_status"])' 2>/dev/null)"
V2="$(python3 -c 'import json; print(json.load(open("'$WORK_DIR'/run2/import-resp.json"))["data"]["run"]["verification_status"])' 2>/dev/null)"
[ "$V1" = "PASSED" ] && [ "$V2" = "PASSED" ] \
  && record "服务端核验状态 PASSED（签名校验 + 计数对账）" 1 \
  || { record "服务端核验状态 PASSED" 0 "run1=$V1 run2=$V2"; echo ABORT; exit 1; }
RUN1_RID="$(python3 -c 'import json; print(json.load(open("'$WORK_DIR'/run1/import-resp.json"))["data"]["run"]["run_id"])')"
RUN2_RID="$(python3 -c 'import json; print(json.load(open("'$WORK_DIR'/run2/import-resp.json"))["data"]["run"]["run_id"])')"
echo "[setup] run1=$RUN1_RID ($RUN1_UUID) run2=$RUN2_RID ($RUN2_UUID)"

# ---- Web 控制台（vite dev，/api/v1 代理到本轮栈）----
echo "[web] 启动 vite dev（127.0.0.1:${WEB_PORT}，VITE_API_PROXY=${API_URL}）..."
VITE_API_PROXY="$API_URL" npm --prefix web run dev -- --host 127.0.0.1 --port "$WEB_PORT" --strictPort \
  > "$EVIDENCE_DIR/vite-dev.log" 2>&1 &
WEB_PID=$!
wait_http "$WEB_URL/login" 200 120 || { record "vite dev 启动" 0 "超时"; echo ABORT; exit 1; }
record "vite dev 启动（页面同域代理 API）" 1

# ---- Playwright 实跑（模块解析软链与 bot-challenge 同口径）----
ln -sfn ../../../web/node_modules "$REPO_ROOT/test/e2e/security-regression/node_modules"
PW_OK=0
if (cd web && npx playwright --version >/dev/null 2>&1); then
  CHROMIUM_BIN="$(cd web && node -e "try{console.log(require('playwright-core').chromium.executablePath())}catch(e){process.exit(1)}" 2>/dev/null || true)"
  if [ -n "$CHROMIUM_BIN" ] && [ -x "$CHROMIUM_BIN" ]; then
    PW_OK=1
  fi
fi
if [ "$PW_OK" != "1" ]; then
  blocked "回归控制台链路（列表→详情→用例差异→发布门禁）" "Playwright/Chromium 不可用（ENVIRONMENT_UNAVAILABLE；可 cd web && npx playwright install chromium 后重跑）"
else
  export E2E_BASE_URL="$WEB_URL"
  export VALKEY_PORT VALKEY_PASSWORD="$VK_PWD"
  export REG_E2E_SEC_USER="$SEC_USER" REG_E2E_SEC_PWD="$SEC_PWD_CI"
  export REG_E2E_RUN1_ID="$RUN1_RID" REG_E2E_RUN2_ID="$RUN2_RID"
  export REG_E2E_REPORT_DIR="$REPO_ROOT/$EVIDENCE_DIR"
  set +e
  (cd web && npx playwright test \
    --config ../test/e2e/security-regression/playwright.config.ts \
    --reporter=json > "$REPO_ROOT/$EVIDENCE_DIR/playwright.json" 2>&1)
  pw_rc=$?
  set -e
  echo "[pw] 退出码=${pw_rc}（报告 $EVIDENCE_DIR/playwright.json）"
  if [ "$pw_rc" = "0" ]; then
    record "回归控制台链路（列表→详情→用例差异→发布门禁状态）" 1
    record "ENFORCE 发布拒绝链路（REGRESSION_GATE_REJECTED 缺失项+深链）" 1
  else
    record "回归控制台链路（列表→详情→用例差异→发布门禁状态）" 0 "退出码=${pw_rc}，详见 playwright.json"
    record "ENFORCE 发布拒绝链路（REGRESSION_GATE_REJECTED 缺失项+深链）" 0 "同上"
  fi
fi

# ---- 汇总与证据落盘 ----
echo "============================================================"
echo "P1-04 R4a 安全回归管理界面 E2E 汇总: 总项 $TOTAL 通过 $PASS 失败 $FAIL 阻塞 $BLOCKED"
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
    "task": "P1-04 R4a 安全回归管理界面 + 发布门禁 E2E",
    "finished_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "totals": {"total": total, "pass": passed, "fail": failed, "blocked": blocked_n},
    "evidence": {"playwright": "playwright.json", "vite_log": "vite-dev.log",
                 "imports": ["run1-import-resp.json", "run2-import-resp.json"]},
    "verdict": "FAIL" if failed > 0 else ("PASS" if blocked_n == 0 else "PASS_WITH_BLOCKED"),
}
with open(os.path.join(ev, "status.json"), "w") as f:
    json.dump(status, f, ensure_ascii=False, indent=2)
PY

SCRIPT_DONE=1
[ "$FAIL" -eq 0 ]
