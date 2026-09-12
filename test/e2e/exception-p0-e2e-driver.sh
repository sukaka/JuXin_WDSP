#!/usr/bin/env bash
# EXC-14 E2E 驱动（WDSP P0-04 页面流）：stage5+wdsp 隔离栈 + CI 临时授权 +
# 用户 provision + 自有 vite(5199) + Playwright。
# 与 test/e2e/exception-p0-smoke.sh 同栈同授权口径；5173 被占用时不得 kill，
# 一律使用 5199（E2E_BASE_URL 覆盖，playwright webServer 自动跳过）。
#
# 用法：bash test/e2e/exception-p0-e2e-driver.sh [额外 playwright 参数...]
# 依赖：docker(compose 插件)、curl、openssl、python3、node/npm（web/ 依赖已装）
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

API_PORT="${API_PORT:-18081}"
GATEWAY_PORT="${GATEWAY_PORT:-18080}"
PG_PORT="${PG_PORT:-15432}"
VK_PORT="${VK_PORT:-16379}"
VITE_PORT="${VITE_PORT:-5199}"
API_URL="http://127.0.0.1:$API_PORT"
GATEWAY_URL="http://127.0.0.1:$GATEWAY_PORT"

# ---- 固定口令（spec 默认值口径：web/e2e/exception-p0.spec.ts）----
WORK_DIR="$(mktemp -d)"
chmod 700 "$WORK_DIR"
ENV_FILE="$WORK_DIR/exc-e2e.env"
PG_USER="jiuzhang"
PG_DB="jiuzhang_waf"
PG_PWD="$(openssl rand -hex 16)"
VK_PWD="$(openssl rand -hex 16)"
ADMIN_PWD="Ci$(openssl rand -hex 8)1!"
MASTER_KEY="$(openssl rand -hex 32)"
LIC_KEY_ID="exc-e2e-key"

# ---- CI 临时 Ed25519 授权（与 exception-p0-smoke.sh 同口径）----
openssl genpkey -algorithm ed25519 -out "$WORK_DIR/lic-key.pem" >/dev/null 2>&1
chmod 600 "$WORK_DIR/lic-key.pem"
LIC_PUB_HEX="$(openssl pkey -in "$WORK_DIR/lic-key.pem" -pubout -outform DER 2>/dev/null \
  | tail -c 32 | python3 -c 'import sys; print(sys.stdin.buffer.read().hex())')"
python3 - "$WORK_DIR" "$LIC_KEY_ID" <<'PY'
import json, sys, datetime
work_dir, key_id = sys.argv[1], sys.argv[2]
payload = {
    "license_id": "LIC-EXC-E2E-0001",
    "license_type": "FORMAL",
    "product": "wdsp",
    "customer": "Exception E2E",
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

COMPOSE=(docker compose --env-file "$ENV_FILE"
  -f deployment/docker-compose.stage5.yml -f deployment/docker-compose.wdsp.yml
  -f deployment/docker-compose.test-license.yml)

VITE_PID=""
cleanup() {
  local rc=$?
  if [ -n "$VITE_PID" ]; then
    kill "$VITE_PID" 2>/dev/null || true
    # 子壳被 kill 后 vite 进程可能存活（脱离进程组），按端口特征兜底清理
    pkill -f "vite --port $VITE_PORT" 2>/dev/null || true
  fi
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK_DIR"
  exit "$rc"
}
trap cleanup EXIT

port_free() { ! python3 -c "
import socket,sys
s=socket.socket(); s.settimeout(0.3)
sys.exit(0 if s.connect_ex(('127.0.0.1',$1))==0 else 1)"; }
for p in "$PG_PORT" "$VK_PORT" "$API_PORT" "$GATEWAY_PORT" "$VITE_PORT"; do
  if ! port_free "$p"; then
    echo "ERROR: 127.0.0.1:$p 已被占用，请先释放" >&2; exit 1
  fi
done
if [ -n "$("${COMPOSE[@]}" ps -q 2>/dev/null)" ]; then
  echo "ERROR: 检测到 stage5 编排已有容器在运行；请先停止" >&2; exit 1
fi

echo "[build] 从当前工作树构建 api/gateway/testorigin 镜像 ..."
"${COMPOSE[@]}" build api gateway testorigin
mkdir -p runtime/license
echo "[up] 启动栈 ..."
"${COMPOSE[@]}" up -d api gateway

code=""
for _ in $(seq 1 200); do
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$API_URL/api/v1/health" 2>/dev/null || echo 000)"
  [ "$code" = "200" ] && break
  sleep 3
done
[ "$code" = "200" ] || { "${COMPOSE[@]}" logs --tail=120 api >&2 || true; exit 1; }
echo "[ok] api 健康"

# ---- 用户 provision（复用阶段5公共函数；口令固定为 spec 默认值）----
export API_URL GATEWAY_URL
export HOST_HEADER="exc-e2e.local"
export VALKEY_PASSWORD="$VK_PWD" VALKEY_CONTAINER="jiuzhang-stage5-valkey"
export SYS_USER="jiuzhang_admin" SYS_PWD="$ADMIN_PWD" SYS_NEW_PWD="SysAdmin@S5!2026x"
export SEC_USER="sec_admin_s5" SEC_PWD='SecAdmin@S5!2026'
export APP_CODE="exce2e"
# shellcheck source=../waf/scripts/stage5-setup.sh
source test/waf/scripts/stage5-setup.sh

SYS_CSRF="$(s5_ensure_sysadmin)" || { echo "ERROR: sysadmin 登录失败" >&2; exit 1; }
echo "[ok] jiuzhang_admin 就绪（已改密为 spec 固定口令）"

LIC_BODY="$(python3 -c 'import json,sys; print(json.dumps({"file_content": open(sys.argv[1]).read()}))' "$WORK_DIR/license.lic")"
lic_code="$(curl -s -o /dev/null -w '%{http_code}' -b "/tmp/s5-$SYS_USER.txt" -X POST "$API_URL/api/v1/license/import" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $SYS_CSRF" -d "$LIC_BODY")"
[ "$lic_code" = "200" ] || { echo "ERROR: 授权导入失败 status=$lic_code" >&2; exit 1; }
echo "[ok] CI 临时 wdsp 授权已导入"

SEC_CSRF="$(s5_ensure_secuser "$SYS_CSRF")"
[ -n "$SEC_CSRF" ] || { echo "ERROR: 安全管理员 provision 失败" >&2; exit 1; }
echo "[ok] sec_admin_s5 就绪"

# ---- 自有 vite（5173 占用禁令；5199）----
echo "[vite] 启动 dev server :$VITE_PORT ..."
(cd web && npx vite --port "$VITE_PORT" --strictPort > "$WORK_DIR/vite.log" 2>&1) &
VITE_PID=$!
vcode=""
for _ in $(seq 1 40); do
  vcode="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:$VITE_PORT" 2>/dev/null || echo 000)"
  [ "$vcode" = "200" ] && break
  sleep 2
done
[ "$vcode" = "200" ] || { echo "ERROR: vite 未就绪" >&2; tail -30 "$WORK_DIR/vite.log" >&2; exit 1; }
echo "[ok] vite 就绪"

# ---- Playwright ----
echo "[e2e] 运行 exception-p0.spec.ts ..."
set +e
(cd web && \
  E2E_BASE_URL="http://localhost:$VITE_PORT" \
  E2E_GATEWAY_URL="$GATEWAY_URL" \
  VALKEY_HOST=127.0.0.1 VALKEY_PORT="$VK_PORT" VALKEY_PASSWORD="$VK_PWD" \
  npx playwright test e2e/exception-p0.spec.ts "$@")
RC=$?
set -e
echo "[done] playwright exit=$RC"
exit "$RC"
