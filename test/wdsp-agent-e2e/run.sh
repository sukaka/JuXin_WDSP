#!/usr/bin/env bash
# WDSP 分布式流量采集 Agent — Phase 1/2/2-B/3 端到端集成验收（设计 §60/§61/§73，契约见
# docs/agents/WDSP_AGENT_PHASE1_CONTRACT.md、WDSP_AGENT_PHASE2_CONTRACT.md、
# WDSP_AGENT_PHASE3_CONTRACT.md）。
# Phase 2-B 增量：机器身份证书三件套（§7/§12）、PoP 认证直接证据（§8，poptool 手工构造
# 三头：Bearer 回退 200 / 篡改签名 401 防降级 / 合法 PoP 200）、证书轮换（§9，仅 PoP 可调、
# 新指纹即时生效、旧指纹 24h 宽限）、disable 吊销即时生效（§11）、迁移 000111（§10）。
# Phase 3 增量：HTTP Sensor L2（脱敏 MASK/响应截断/content_type 跳过/gzip 解压，契约 §2-§6）、
# L1 等级（headers 有 body 无）、API 资产联动（§6）、迁移 000112/000113；
# 业务 HTTP 服务由 python http.server 升级为 business_server.py（/api/login、/big、/upload、/gz 端点）。
# Phase 4 增量（契约 docs/agents/WDSP_AGENT_PHASE4_CONTRACT.md）：11g 定向采集提升
# （uri_prefix override L0→L2 即时提升、未命中 URI 不提升、删除后回落）、11h 确定性采样
# （rate=0.01 上界断言）、11i 背压降级与恢复（backpressure_cap / DEGRADED→ONLINE）、迁移 000114；
# business_server.py 新增 /api/payment 端点。
#
# 拓扑（Docker Desktop on macOS）：
#   主机：管理后端 api 二进制（显式 go build -tags wdsp_testkeys）→ 127.0.0.1:18080
#   容器：PostgreSQL 16.4-alpine（55432）、Valkey 8.1.8-alpine（56379）
#   容器网络 wdsp-e2e-net：
#     wdsp-e2e-agent  —— Agent 宿主：python3 http.server(8000) + wdsp-agent（AF_PACKET 抓 eth0）
#     wdsp-e2e-client —— 流量发起方：curl 经 docker 网桥访问 agent 容器，产生真实 eth0 报文
#
# 说明：不修改 server/、wdsp-agent/、web/ 任何代码；所有产物（二进制/数据）在 $WORK（/tmp）
# 与 docker 容器层内，跑完清理。发现既有代码 bug 时如实报告，不绕过。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ---- 端口与命名（避开可能的本地开发环境） ----
API_PORT="${E2E_API_PORT:-28080}"
PG_PORT="${E2E_PG_PORT:-25432}"
VALKEY_PORT="${E2E_VALKEY_PORT:-26379}"
NET="wdsp-e2e-net"
C_PG="wdsp-e2e-pg"
C_VALKEY="wdsp-e2e-valkey"
C_AGENT="wdsp-e2e-agent"
C_CLIENT="wdsp-e2e-client"
IMAGE="wdsp-e2e-agent-host:local"
API_BASE="http://127.0.0.1:${API_PORT}"

PG_IMAGE="postgres:16.4-alpine@sha256:5660c2cbfea50c7a9127d17dc4e48543eedd3d7a41a595a2dfa572471e37e64c"
VALKEY_IMAGE="valkey/valkey:8.1.8-alpine@sha256:94365b275456ae14621001c03556c732b1d93a0cdeacc317d1bdd52eba680885"

WORK="$(mktemp -d /tmp/wdsp-agent-e2e.XXXXXX)"
SERVER_PID=""
FAILED=0
PASS_COUNT=0
FAIL_COUNT=0

log()  { printf '\n=== %s ===\n' "$*"; }
info() { printf '  %s\n' "$*"; }
ok()   { PASS_COUNT=$((PASS_COUNT+1)); printf '  [OK]   %s\n' "$*"; }
bad()  { FAIL_COUNT=$((FAIL_COUNT+1)); FAILED=1; printf '  [FAIL] %s\n' "$*" >&2; }

cleanup() {
  set +e
  echo
  log "清理"
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
  docker rm -f "$C_AGENT" "$C_CLIENT" "$C_PG" "$C_VALKEY" >/dev/null 2>&1
  docker network rm "$NET" >/dev/null 2>&1
  if [ "$FAILED" -eq 0 ] && [ "${KEEP_WORK:-0}" != "1" ]; then
    rm -rf "$WORK"
    info "临时目录已删除"
  else
    info "保留现场: $WORK （server.log / wdsp-agent 容器日志可经 KEEP_WORK=1 复现）"
  fi
}
trap cleanup EXIT

die() { echo "FATAL: $*" >&2; exit 1; }

# wait_for <描述> <超时秒> <条件命令...>：每 2s 重试直到成功或超时（超时返回 1）
wait_for() {
  local desc="$1" timeout="$2"; shift 2
  local deadline=$(( $(date +%s) + timeout ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 2
  done
  return 1
}

rand_hex() { openssl rand -hex "$1"; }

# ---- 0. 前置检查 ----
log "0. 前置检查"
for c in docker go jq curl openssl; do command -v "$c" >/dev/null || die "缺少依赖: $c"; done
docker info >/dev/null 2>&1 || die "Docker 不可用"
for p in "$API_PORT" "$PG_PORT" "$VALKEY_PORT"; do
  if curl -sf -o /dev/null "http://127.0.0.1:$p/" 2>/dev/null || nc -z 127.0.0.1 "$p" 2>/dev/null; then
    die "端口 $p 已被占用（可用 E2E_API_PORT/E2E_PG_PORT/E2E_VALKEY_PORT 覆盖）"
  fi
done
# 避免与上次异常退出的残留冲突
docker rm -f "$C_AGENT" "$C_CLIENT" "$C_PG" "$C_VALKEY" >/dev/null 2>&1 || true
docker network rm "$NET" >/dev/null 2>&1 || true
info "工作目录: $WORK"

DOCKER_ARCH="$(docker version -f '{{.Server.Arch}}')"
case "$DOCKER_ARCH" in
  amd64|x86_64) GOARCH=amd64 ;;
  aarch64|arm64) GOARCH=arm64 ;;
  *) die "未知 Docker 架构: $DOCKER_ARCH" ;;
esac
info "Docker 架构: $DOCKER_ARCH → GOARCH=$GOARCH"

# ---- 1. 编译（产物全部在 $WORK，不入仓库） ----
log "1. 编译 api 与 wdsp-agent（linux/${GOARCH}，CGO_ENABLED=0）"
# 源码快照到 $WORK/src（含未提交/未跟踪的 Phase 1 代码；不触碰工作树）。
# 原因：工作树存在与本验收无关的进行中修改（aiorchestrator 调用 ResolveContextualMessage
# 但实现缺失），直接在工作树 go build 会失败；在快照内隔离处置并如实记录。
SRC="$WORK/src"
mkdir -p "$SRC/gateway"
rsync -a "$REPO_ROOT/server/" "$SRC/server/"
rsync -a "$REPO_ROOT/gateway/dynamic_security/" "$SRC/gateway/dynamic_security/"
rsync -a "$REPO_ROOT/wdsp-agent/" "$SRC/wdsp-agent/"

build_api() { (cd "$SRC/server" && go build -tags wdsp_testkeys -o "$WORK/api" ./cmd/api); }
if ! build_api 2>"$WORK/build-api.log"; then
  if grep -q 'undefined: ResolveContextualMessage' "$WORK/build-api.log"; then
    cat >"$SRC/server/internal/aiorchestrator/resolve_contextual_e2e_shim.go" <<'EOF'
// resolve_contextual_e2e_shim.go —— 仅由 test/wdsp-agent-e2e/run.sh 生成于 /tmp 源码快照，
// 不进入仓库。工作树 orchestrator.go 存在与本验收无关的进行中修改（调用
// ResolveContextualMessage 但实现未提交），此处按 orchestrator_test.go 的语义契约
// 补齐最小实现使快照可编译；仓库内修复责任在工作树作者，本 shim 不构成对既有代码的改动。
package aiorchestrator

import "strings"

// ResolveContextualMessage 追问消歧：消息本身无独立意图（Classify 兜底 GENERAL_SECURITY_QA）
// 时，继承最近一条具备明确意图的用户消息作为上下文；具备独立意图时原样返回。
func ResolveContextualMessage(message string, recent []Message) string {
	trimmed := strings.TrimSpace(message)
	if trimmed == "" || Classify(trimmed).TaskType != TaskGeneralQA {
		return message
	}
	for i := len(recent) - 1; i >= 0; i-- {
		if recent[i].Role != "user" {
			continue
		}
		prev := strings.TrimSpace(recent[i].Content)
		if prev == "" || prev == trimmed || Classify(prev).TaskType == TaskGeneralQA {
			continue
		}
		return prev + "；" + trimmed
	}
	return message
}
EOF
    info "WARN: 工作树 aiorchestrator 存在无关 WIP（ResolveContextualMessage 未实现），已在快照内按测试语义补齐 shim（仓库未动）"
    build_api 2>>"$WORK/build-api.log" || { cat "$WORK/build-api.log" >&2; die "api 编译失败（快照含 shim 后仍失败，见上）"; }
  else
    cat "$WORK/build-api.log" >&2
    die "api 编译失败（非已知 WIP 问题，如实上报，见上）"
  fi
fi
(cd "$SRC/wdsp-agent" && CGO_ENABLED=0 GOOS=linux GOARCH="$GOARCH" go build -o "$WORK/wdsp-agent" ./cmd/agent)
# poptool：PoP 签名/CSR/指纹调试工具（Phase 2-B §7-§9 验收用，主机侧运行，仅标准库）
(cd "$SCRIPT_DIR/poptool" && go build -o "$WORK/poptool" .)
ok "编译完成"

# ---- 2. 依赖容器（版本锁定，禁 latest） ----
log "2. 启动 PostgreSQL / Valkey 容器"
PG_PASSWORD="$(rand_hex 16)"
VALKEY_PASSWORD="$(rand_hex 16)"
docker run -d --name "$C_PG" -p "127.0.0.1:${PG_PORT}:5432" \
  -e POSTGRES_USER=jiuzhang -e POSTGRES_PASSWORD="$PG_PASSWORD" -e POSTGRES_DB=jiuzhang_waf \
  "$PG_IMAGE" >/dev/null
docker run -d --name "$C_VALKEY" -p "127.0.0.1:${VALKEY_PORT}:6379" \
  "$VALKEY_IMAGE" valkey-server --requirepass "$VALKEY_PASSWORD" >/dev/null
wait_for "PostgreSQL ready" 60 docker exec "$C_PG" pg_isready -U jiuzhang -d jiuzhang_waf || die "PostgreSQL 未就绪"
wait_for "Valkey ready" 60 docker exec "$C_VALKEY" valkey-cli -a "$VALKEY_PASSWORD" --no-auth-warning ping || die "Valkey 未就绪"
ok "依赖容器就绪（postgres:16.4-alpine / valkey:8.1.8-alpine，digest 锁定）"

# ---- 3. 迁移 000001→000115 + 关闭图形验证码（验收脚本无法 OCR，属环境配置非代码改动） ----
log "3. 数据库迁移与验收环境设置"
export POSTGRES_HOST=127.0.0.1 POSTGRES_PORT="$PG_PORT" POSTGRES_DB=jiuzhang_waf \
       POSTGRES_USER=jiuzhang POSTGRES_PASSWORD="$PG_PASSWORD" POSTGRES_SSLMODE=disable \
       VALKEY_HOST=127.0.0.1 VALKEY_PORT="$VALKEY_PORT" VALKEY_PASSWORD="$VALKEY_PASSWORD" \
       MIGRATIONS_DIR="$REPO_ROOT/server/migrations"
"$WORK/api" migrate up | tee "$WORK/migrate.out"
grep -q 'applied migration 000111_traffic_agent_certs' "$WORK/migrate.out" \
  && ok "迁移 000111_traffic_agent_certs 已应用（Phase 2-B 机器身份证书，契约 §10）" \
  || bad "迁移日志未见 000111_traffic_agent_certs"
grep -q 'applied migration 000112_traffic_agent_http_events' "$WORK/migrate.out" \
  && grep -q 'applied migration 000113_traffic_agent_http_skipped_reason' "$WORK/migrate.out" \
  && ok "迁移 000112/000113 已应用（Phase 3 HTTP 事件表 + skipped_reason 增量，PHASE3 契约 §6）" \
  || bad "迁移日志未见 000112_traffic_agent_http_events / 000113_traffic_agent_http_skipped_reason"
grep -q 'applied migration 000114_traffic_agent_capture_overrides' "$WORK/migrate.out" \
  && ok "迁移 000114_traffic_agent_capture_overrides 已应用（Phase 4 定向采集规则表）" \
  || bad "迁移日志未见 000114_traffic_agent_capture_overrides"
grep -q 'applied migration 000115_traffic_agent_k8s_metadata' "$WORK/migrate.out" \
  && ok "迁移 000115_traffic_agent_k8s_metadata 已应用（Phase 5 Kubernetes 元数据）" \
  || bad "迁移日志未见 000115_traffic_agent_k8s_metadata"
docker exec "$C_PG" psql -U jiuzhang -d jiuzhang_waf -c \
  "UPDATE system_settings SET setting_value='false' WHERE setting_group='login' AND setting_key='captcha_enabled';" >/dev/null
# 验收库补授权（同验证码开关口径，非代码改动）：000100 权限重划后 api_asset.read 划归
# SECURITY_ADMIN，初始管理员（SYSTEM_ADMIN）查 /api-security/endpoints 默认 403；
# 补授该只读权限点使 11f 资产联动断言走真实管理面路由（登录在步骤 6，授权先生效）。
docker exec "$C_PG" psql -U jiuzhang -d jiuzhang_waf -c \
  "INSERT INTO role_permissions (role_id, permission_id)
   SELECT r.id, p.id FROM roles r, permissions p
   WHERE r.code='SYSTEM_ADMIN' AND p.code='api_asset.read'
   ON CONFLICT (role_id, permission_id) DO NOTHING;" >/dev/null
ok "迁移完成（000001→000115），登录验证码已关闭、api_asset.read 已补授 SYSTEM_ADMIN（均在验收库）"

# ---- 4. 临时授权（随机一次性密钥对；仅注入 wdsp_testkeys 测试进程） ----
log "4. 生成临时离线授权"
go run "$SCRIPT_DIR/genlicense.go" -lic-out "$WORK/license.lic" -env-out "$WORK/license.env"
LICENSE_VENDOR_PUBLIC_KEY="$(cut -d= -f2- "$WORK/license.env")"
ok "临时授权已生成（wdsp/永久/配额不限/不绑指纹；私钥不落盘）"

# ---- 5. 启动管理后端 ----
log "5. 启动管理后端（127.0.0.1:${API_PORT}）"
ADMIN_USER="jiuzhang_admin"
ADMIN_INIT_PW="Init@$(rand_hex 8)Z9"
mkdir -p "$WORK/home"
(
  cd "$WORK/home"
  # PRODUCT_EDITION=wdsp：/api/v1/api-security 命名空间按产品形态门控
  # （product.APIDynamicProtectionEnabled，waf 形态不注册→404，app.go 装配处）；
  # 本验收即 WDSP 产品线，管理后端以 wdsp 形态运行，11f 资产联动断言走真实管理面路由。
  env APP_ENV=dev SERVER_HOST=0.0.0.0 SERVER_PORT="$API_PORT" \
      PRODUCT_EDITION=wdsp \
      POSTGRES_HOST=127.0.0.1 POSTGRES_PORT="$PG_PORT" POSTGRES_DB=jiuzhang_waf \
      POSTGRES_USER=jiuzhang POSTGRES_PASSWORD="$PG_PASSWORD" POSTGRES_SSLMODE=disable \
      VALKEY_HOST=127.0.0.1 VALKEY_PORT="$VALKEY_PORT" VALKEY_PASSWORD="$VALKEY_PASSWORD" \
      JIUZHANG_MASTER_KEY="$(rand_hex 32)" \
      LICENSE_VENDOR_PUBLIC_KEY="$LICENSE_VENDOR_PUBLIC_KEY" \
      INITIAL_ADMIN_USERNAME="$ADMIN_USER" INITIAL_ADMIN_PASSWORD="$ADMIN_INIT_PW" \
      GATEWAY_DATA_DIR="$WORK/home/runtime" \
      "$WORK/api" >"$WORK/server.log" 2>&1 &
  echo $! >"$WORK/server.pid"
)
SERVER_PID="$(cat "$WORK/server.pid")"
wait_for "api health" 60 curl -sf "$API_BASE/api/v1/health" || { tail -50 "$WORK/server.log" >&2; die "管理后端未就绪"; }
ok "管理后端健康（pid ${SERVER_PID}）"

# ---- 6. 登录 → 首次改密 → 重新登录（MustChangePassword 豁免路径仅限改密） ----
log "6. 管理员登录/改密/导入授权/签发 Enrollment Token"
JAR="$WORK/cookies.txt"
NEW_PW="E2e@$(rand_hex 8)Qw"

login() { # login <username> <password> → 输出 csrf_token
  curl -sf -c "$JAR" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$1\",\"password\":\"$2\"}" \
    "$API_BASE/api/v1/auth/login" | jq -r '.data.csrf_token // empty'
}
CSRF="$(login "$ADMIN_USER" "$ADMIN_INIT_PW")"
[ -n "$CSRF" ] || { cat "$JAR" >&2; die "初始登录失败（见 server.log）"; }
HTTP_CODE="$(curl -s -o "$WORK/chpw.json" -w '%{http_code}' -b "$JAR" -H "X-CSRF-Token: $CSRF" \
  -H 'Content-Type: application/json' \
  -d "{\"old_password\":\"$ADMIN_INIT_PW\",\"new_password\":\"$NEW_PW\"}" \
  "$API_BASE/api/v1/auth/change-password")"
[ "$HTTP_CODE" = "200" ] || { cat "$WORK/chpw.json" >&2; die "首次改密失败: HTTP $HTTP_CODE"; }
CSRF="$(login "$ADMIN_USER" "$NEW_PW")"
[ -n "$CSRF" ] || die "改密后重新登录失败"
ok "管理员会话建立（含首次强制改密闭环）"

# 管理 API 辅助：mapi <METHOD> <PATH> [JSON_BODY]
mapi() {
  local method="$1" path="$2" body="${3:-}"
  local args=(-s -b "$JAR" -H "X-CSRF-Token: $CSRF" -X "$method")
  [ -n "$body" ] && args+=(-H 'Content-Type: application/json' -d "$body")
  curl "${args[@]}" "$API_BASE$path"
}

LIC_JSON="$(jq -Rs '{file_content: .}' <"$WORK/license.lic")"
mapi POST /api/v1/license/import "$LIC_JSON" | jq -e '.code == "SUCCESS"' >/dev/null \
  && ok "临时授权导入成功（管理面授权门控解锁）" || bad "授权导入失败"

TOKEN_RESP="$(mapi POST /api/v1/traffic/agents/enrollment-tokens '{"label":"e2e","ttl_minutes":60}')"
ENROLL_TOKEN="$(echo "$TOKEN_RESP" | jq -r '.data.token // empty')"
[ -n "$ENROLL_TOKEN" ] || { echo "$TOKEN_RESP" >&2; die "签发 Enrollment Token 失败"; }
ok "Enrollment Token 已签发（wdt_… 一次性，60 分钟）"

# ---- 7. Agent 宿主镜像与容器网络 ----
log "7. 构建 Agent 宿主镜像并启动容器"
mkdir -p "$WORK/imgctx"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj '/CN=127.0.0.1' -addext 'subjectAltName=IP:127.0.0.1' \
  -keyout "$WORK/imgctx/fake-kube.key" -out "$WORK/imgctx/fake-kube.crt" >/dev/null 2>&1
printf '%s' 'wdsp-e2e-service-account-token' >"$WORK/imgctx/kube-token"
cp "$WORK/wdsp-agent" "$SCRIPT_DIR/entrypoint.sh" "$SCRIPT_DIR/business_server.py" \
  "$SCRIPT_DIR/fake_kube_server.py" "$WORK/imgctx/"
docker build -q -t "$IMAGE" -f "$SCRIPT_DIR/Dockerfile.agent" "$WORK/imgctx" >/dev/null
docker network create "$NET" >/dev/null
docker run -d --name "$C_AGENT" --network "$NET" \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  -e KUBERNETES_SERVICE_HOST=127.0.0.1 -e KUBERNETES_SERVICE_PORT=8443 \
  -e NODE_NAME=e2e-node -e K8S_CLUSTER_NAME=wdsp-e2e \
  --add-host host.docker.internal:host-gateway \
  "$IMAGE" >/dev/null
docker run -d --name "$C_CLIENT" --network "$NET" --entrypoint sleep "$IMAGE" infinity >/dev/null
AGENT_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$C_AGENT")"
CLIENT_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$C_CLIENT")"
info "agent 容器 IP=$AGENT_IP  client 容器 IP=$CLIENT_IP"
# 说明：不在此处关闭 eth0 的 TSO/GSO/GRO——D-06（抓包缓冲=MTU 致超帧静默截断）已在 agent
# 侧修复（64KB 帧缓冲 + 截断检测快速失败），/big 的 TSO 超帧流量留作修复的真实验收（见 11d）。
wait_for "业务 HTTP 服务" 30 docker exec "$C_CLIENT" curl -sf "http://$C_AGENT:8000/" || die "业务 HTTP 服务未就绪"
wait_for "fake Kubernetes API" 30 docker exec "$C_AGENT" curl -skf \
  -H 'Authorization: Bearer wdsp-e2e-service-account-token' \
  'https://127.0.0.1:8443/api/v1/pods?limit=500&fieldSelector=spec.nodeName%3De2e-node%2Cstatus.phase%3DRunning' \
  || die "fake Kubernetes API 未就绪"
ok "容器拓扑就绪（业务流量 client→agent:8000；fake Kubernetes API TLS + ServiceAccount Token）"

# ---- 8. enroll + run ----
log "8. wdsp-agent enroll / run"
docker exec "$C_AGENT" wdsp-agent enroll \
  --server "http://host.docker.internal:${API_PORT}" --token "$ENROLL_TOKEN" \
  --config /etc/wdsp-agent/agent.json | tee "$WORK/enroll.out"
grep -q '注册成功' "$WORK/enroll.out" && ok "enroll 成功（agent_id 与 wda_ 凭据已下发）" || bad "enroll 失败"
docker exec -d "$C_AGENT" sh -c 'wdsp-agent run --debug >/var/log/wdsp-agent.log 2>&1'

AGENT_ID=""
wait_for "agent 注册可见" 30 sh -c "curl -sf -b '$JAR' '$API_BASE/api/v1/traffic/agents' | jq -e '.data.total >= 1' >/dev/null" \
  || die "管理面看不到任何 Agent"
AGENT_ID="$(mapi GET /api/v1/traffic/agents | jq -r '.data.items[0].agent_id')"
info "agent_id=$AGENT_ID"

agent_status() { mapi GET "/api/v1/traffic/agents/$AGENT_ID" | jq -r '.data.status // empty'; }
deadline=$(( $(date +%s) + 90 ))
while [ "$(agent_status)" != "ONLINE" ] && [ "$(date +%s)" -lt "$deadline" ]; do sleep 2; done
[ "$(agent_status)" = "ONLINE" ] && ok "管理面派生状态 ONLINE（心跳通道建立，契约 §5）" \
  || { bad "Agent 状态非 ONLINE: $(agent_status)"; docker exec "$C_AGENT" tail -20 /var/log/wdsp-agent.log >&2 || true; }

# ---- 8b. 机器身份证书三件套（Phase 2-B 契约 §7/§11/§12） ----
log "8b. 机器身份证书（agent.key/agent.crt/ca.crt + 管理端指纹字段）"
STATE_DIR=/var/lib/wdsp-agent
docker exec "$C_AGENT" grep -q '启用 PoP 认证' /var/log/wdsp-agent.log \
  && ok "Agent 日志「机器身份证书已加载，启用 PoP 认证」（run 进入 PoP 模式，契约 §8/§12）" \
  || bad "Agent 日志未见 PoP 模式启用记录"
KEY_MODE="$(docker exec "$C_AGENT" stat -c '%a' "$STATE_DIR/agent.key" 2>/dev/null || true)"
if [ "$KEY_MODE" = "600" ] \
  && docker exec "$C_AGENT" test -f "$STATE_DIR/agent.crt" \
  && docker exec "$C_AGENT" test -f "$STATE_DIR/ca.crt"; then
  ok "enroll 自动签发三件套：agent.key(0600)/agent.crt/ca.crt 齐备（契约 §7/§12）"
else
  bad "证书三件套缺失或权限错误（agent.key mode=${KEY_MODE:-missing}, want 600）"
fi
mapi GET "/api/v1/traffic/agents/$AGENT_ID" | jq -e \
  '.data.cert_fingerprint != null and .data.cert_not_after != null' >/dev/null \
  && ok "管理端详情含 cert_fingerprint/cert_not_after（非 null，契约 §11）" \
  || bad "管理端详情缺 cert_fingerprint/cert_not_after: $(mapi GET "/api/v1/traffic/agents/$AGENT_ID" | jq -c '.data | {cert_fingerprint, cert_not_after}')"

# ---- 8c. 显式 L0 策略（Phase 3 语义切换前置） ----
# Phase 3 起 agent 内置默认策略 capture_level=L1（wdsp-agent/internal/config DefaultPolicy），
# L1+ 会停发旧 event_type=request 事件（由 HTTP 记录替代，契约 §2 冻结语义，flow_end 保留）。
# 步骤 9 断言的是旧 request 事件通道，故先显式创建并绑定 L0 策略（L0 仅 flow 事件、
# 恢复 request 事件），等 ACK 闭环后再做旧通道回归；步骤 10 起再切换 L1/L2 验收新语义。
log "8c. 显式 L0 策略（保住旧 request 事件通道，契约 §2）"
POLICY_L0='{
  "name": "e2e-l0",
  "config": {
    "name": "e2e-l0",
    "capture": {"interfaces": ["eth0"], "direction": "both", "protocols": ["tcp"], "ports": [8000]},
    "capture_level": "L0",
    "output": {"mode": "FLOW"},
    "limits": {"max_body_size": 262144, "outbound_mbps": 100, "cpu_percent": 90, "memory_mb": 512},
    "sampling": {"enabled": false, "rate": 1.0},
    "buffer": {"enabled": true, "max_size_mb": 64, "max_age_minutes": 30}
  }
}'
POLICY_L0_ID="$(mapi POST /api/v1/traffic/policies "$POLICY_L0" | jq -r '.data.id // empty')"
[ -n "$POLICY_L0_ID" ] && ok "L0 策略已创建: $POLICY_L0_ID" || die "L0 策略创建失败"
mapi POST "/api/v1/traffic/agents/$AGENT_ID/policy" "{\"policy_id\":\"$POLICY_L0_ID\"}" >/dev/null
agent_versions() { mapi GET "/api/v1/traffic/agents/$AGENT_ID" | jq -r '"\(.data.config_version) \(.data.applied_config_version)"'; }
deadline=$(( $(date +%s) + 90 ))
APPLIED_OK=0
while [ "$(date +%s)" -lt "$deadline" ]; do
  read -r CV AV <<<"$(agent_versions)"
  [ "$AV" = "$CV" ] && [ "$CV" -gt 0 ] && { APPLIED_OK=1; break; }
  sleep 2
done
[ "$APPLIED_OK" = "1" ] && ok "L0 策略已应用（capture_level=L0，version ${CV}，ACK 闭环；默认 L1 抑制旧 request 事件，L0 恢复）" \
  || bad "L0 策略下发超时: config_version=$CV applied=$AV"

# ---- 9. 真实流量 + 事件断言（设计 §60） ----
log "9. 发起真实流量（client→agent:8000，含 POST /api/login JSON body）"
# curl 显式 Connection: close 短连接：请求完成后客户端主动 FIN，python http.server 随即 FIN，
# 双方 FIN 到齐应触发 Agent 立即发 flow_end（D-01 修复后的 FIN/RST 关闭路径）。
gen_traffic() {
  docker exec "$C_CLIENT" sh -c '
    curl -s -o /dev/null -H "Connection: close" http://wdsp-e2e-agent:8000/
    curl -s -o /dev/null -X POST http://wdsp-e2e-agent:8000/api/login \
      -H "Content-Type: application/json" -H "Connection: close" \
      -d "{\"username\":\"e2e\",\"password\":\"not-a-real-secret\"}"
    curl -s -o /dev/null -H "Connection: close" http://wdsp-e2e-agent:8000/index.html
  '
}
gen_traffic && ok "流量已发起（GET / ×2 + POST /api/login，Connection: close 短连接）" || bad "流量发起失败"
TRAFFIC_TS="$(date +%s)"

events_json() { mapi GET "/api/v1/traffic/agents/$AGENT_ID/events?page_size=100"; }
REQ_JQ='[.data.items[] | select(.event_type=="request" and .http_method=="POST" and .http_uri=="/api/login"
        and .tls_visibility=="PLAINTEXT" and .protocol=="tcp")] | .[0] // empty'
deadline=$(( $(date +%s) + 90 ))
REQ_EV=""
FLOW_ID=""
while [ -z "$REQ_EV" ] && [ "$(date +%s)" -lt "$deadline" ]; do
  REQ_EV="$(events_json | jq -c "$REQ_JQ")"
  [ -n "$REQ_EV" ] || sleep 2
done
if [ -n "$REQ_EV" ]; then
  ok "request 事件已入库（POST /api/login，PLAINTEXT）"
  echo "$REQ_EV" | jq -e --arg s "$CLIENT_IP" --arg d "$AGENT_IP" \
    '.src_ip==$s and .dst_ip==$d and .dst_port==8000 and (.src_port>0)' >/dev/null \
    && ok "五元组正确（src=$CLIENT_IP:* → dst=$AGENT_IP:8000/tcp，真实 AF_PACKET 抓包证据）" \
    || bad "五元组不符: $(echo "$REQ_EV" | jq -c '{src_ip,src_port,dst_ip,dst_port}')"
  echo "$REQ_EV" | jq -e '.http_host | test("wdsp-e2e-agent")' >/dev/null \
    && ok "http_host 嗅探正确: $(echo "$REQ_EV" | jq -r '.http_host')" \
    || bad "http_host 不符: $(echo "$REQ_EV" | jq -r '.http_host')"
  FLOW_ID="$(echo "$REQ_EV" | jq -r '.flow_id')"

  # flow_end 收紧断言（契约 §3.4「流关闭即报」；D-01 修复：双方 FIN 立即/RST 立即/
  # 半关闭 3s 宽限 + 2s 扫描，最坏约 5s）：连接关闭后 ≤30s 内必须可查且 bytes>0。
  deadline=$(( $(date +%s) + 30 ))
  FE_BYTES=""
  while [ -z "$FE_BYTES" ] && [ "$(date +%s)" -lt "$deadline" ]; do
    FE_BYTES="$(events_json | jq -r --arg f "$FLOW_ID" \
      '[.data.items[] | select(.event_type=="flow_end" and .flow_id==$f)] | .[0] // empty | "\(.bytes_in + .bytes_out)"')"
    [ -n "$FE_BYTES" ] || sleep 2
  done
  if [ -n "$FE_BYTES" ] && [ "$FE_BYTES" -gt 0 ] 2>/dev/null; then
    FE_DELAY=$(( $(date +%s) - TRAFFIC_TS ))
    ok "flow_end 事件字节数>0（bytes_in+bytes_out=${FE_BYTES}，关闭后约 ${FE_DELAY}s 可查，FIN/RST 路径生效）"
  else
    bad "flow_end 事件未在连接关闭后 30s 内出现或字节数为 0（flow_id=${FLOW_ID}，FIN/RST 路径未生效）"
  fi
else
  bad "request 事件未出现（POST /api/login）"
  docker exec "$C_AGENT" tail -30 /var/log/wdsp-agent.log >&2 || true
fi

# ---- 10. 策略创建→绑定→配置下发 ACK 闭环（契约 §3.3） ----
log "10. 策略下发与 ACK 闭环"
POLICY_FLOW='{
  "name": "e2e-flow",
  "config": {
    "name": "e2e-flow",
    "capture": {"interfaces": ["eth0"], "direction": "both", "protocols": ["tcp"], "ports": [8000]},
    "capture_level": "L1",
    "output": {"mode": "FLOW"},
    "limits": {"max_body_size": 262144, "outbound_mbps": 100, "cpu_percent": 90, "memory_mb": 512},
    "sampling": {"enabled": false, "rate": 1.0},
    "buffer": {"enabled": true, "max_size_mb": 64, "max_age_minutes": 30}
  }
}'
POLICY_ID="$(mapi POST /api/v1/traffic/policies "$POLICY_FLOW" | jq -r '.data.id // empty')"
[ -n "$POLICY_ID" ] && ok "策略已创建: $POLICY_ID" || die "策略创建失败"
mapi POST "/api/v1/traffic/agents/$AGENT_ID/policy" "{\"policy_id\":\"$POLICY_ID\"}" >/dev/null

agent_versions() { mapi GET "/api/v1/traffic/agents/$AGENT_ID" | jq -r '"\(.data.config_version) \(.data.applied_config_version)"'; }
read -r CV _ <<<"$(agent_versions)"
[ "$CV" -gt 0 ] 2>/dev/null && ok "绑定后 config_version=${CV}（>0）" || bad "config_version 未推进: $CV"
deadline=$(( $(date +%s) + 90 ))
APPLIED_OK=0
while [ "$(date +%s)" -lt "$deadline" ]; do
  read -r CV AV <<<"$(agent_versions)"
  [ "$AV" = "$CV" ] && [ "$CV" -gt 0 ] && { APPLIED_OK=1; break; }
  sleep 2
done
[ "$APPLIED_OK" = "1" ] && ok "applied_config_version=$AV == config_version=${CV}（下发+应用+ACK 闭环）" \
  || bad "ACK 闭环超时: config_version=$CV applied=$AV"

# ---- 11. FLOW_RAW → RAW 帧上报计数（契约 §3.5） ----
log "11. 切换 FLOW_RAW，验证 RAW 通道"
POLICY_RAW="$(echo "$POLICY_FLOW" | jq '.name="e2e-flow-raw" | .config.name="e2e-flow-raw" | .config.output.mode="FLOW_RAW"')"
mapi PUT "/api/v1/traffic/policies/$POLICY_ID" "$POLICY_RAW" >/dev/null
deadline=$(( $(date +%s) + 90 ))
APPLIED_OK=0
while [ "$(date +%s)" -lt "$deadline" ]; do
  read -r CV AV <<<"$(agent_versions)"
  [ "$AV" = "$CV" ] && { APPLIED_OK=1; break; }
  sleep 2
done
[ "$APPLIED_OK" = "1" ] && ok "FLOW_RAW 策略已应用（version ${CV}）" || bad "FLOW_RAW 下发超时"
gen_traffic
raw_frames() { mapi GET "/api/v1/traffic/agents/$AGENT_ID" | jq -r '.data.last_metrics.raw_frames_received // 0'; }
deadline=$(( $(date +%s) + 90 ))
while [ "$(raw_frames)" -le 0 ] 2>/dev/null && [ "$(date +%s)" -lt "$deadline" ]; do sleep 2; done
RF="$(raw_frames)"
[ "$RF" -gt 0 ] 2>/dev/null && ok "last_metrics.raw_frames_received=$RF > 0（WDP1 批量校验/计数/丢弃通道打通）" \
  || bad "raw_frames_received 未增长（=${RF}）"

# ---- 11b. PoP 认证直接证据（Phase 2-B 契约 §8；poptool 手工构造三头） ----
log "11b. PoP 认证直接证据（Bearer 回退 / 防降级负例 / 手工合法 PoP）"
mkdir -p "$WORK/pop"
docker cp "$C_AGENT:$STATE_DIR/agent.key" "$WORK/pop/agent.key" >/dev/null
docker cp "$C_AGENT:$STATE_DIR/agent.crt" "$WORK/pop/agent.crt" >/dev/null
CRED="$(docker exec "$C_AGENT" python3 -c 'import json; print(json.load(open("/etc/wdsp-agent/agent.json"))["credential"])')"
[ -n "$CRED" ] || die "无法从容器 agent.json 读取 credential"
HB_PATH="/api/v1/agents/$AGENT_ID/heartbeat"
printf '{"timestamp":%s,"status":"ONLINE"}' "$(date +%s)" >"$WORK/pop/hb.json"

# pop_curl <key> <cert> <method> <path> <body-file|-> <tamper|-> <out-file|-> [extra curl args...]
# → stdout=http_code。用 poptool 按契约 §8 构造 PoP 三头（签名串 "POP\nMETHOD\nPATH\nTS\nhex(SHA256(body))"）。
pop_curl() {
  local key="$1" cert="$2" method="$3" path="$4" body="$5" tamper="$6" out="$7"; shift 7
  local args=(headers -key "$key" -cert "$cert" -method "$method" -path "$path")
  [ "$body" != "-" ] && args+=(-body-file "$body")
  [ "$tamper" != "-" ] && args+=(-tamper "$tamper")
  local hdrs
  hdrs="$("$WORK/poptool" "${args[@]}")" || { echo "poptool headers 失败: $method $path" >&2; echo 000; return 0; }
  local curl_args=(-s -w '%{http_code}' -X "$method")
  local h
  while IFS= read -r h; do curl_args+=(-H "$h"); done <<< "$hdrs"
  [ "$body" != "-" ] && curl_args+=(-H 'Content-Type: application/json' --data-binary @"$body")
  if [ "$out" != "-" ]; then curl_args+=(-o "$out"); else curl_args+=(-o /dev/null); fi
  curl_args+=("$@")
  curl "${curl_args[@]}" "$API_BASE$path"
}

# a. 无 PoP 头 + 正确 Bearer → 200（过渡期回退通道存在）
CODE="$(curl -s -o /dev/null -w '%{http_code}' -X POST \
  -H "Authorization: Bearer $CRED" -H 'Content-Type: application/json' \
  --data-binary @"$WORK/pop/hb.json" "$API_BASE$HB_PATH")"
[ "$CODE" = "200" ] && ok "无 PoP 头 + 正确 Bearer 心跳 → 200（Bearer 回退通道存在，契约 §8）" \
  || bad "Bearer 回退心跳应 200，实际 HTTP $CODE"

# b. PoP 三头齐全但签名故意篡改 + 正确 Bearer → 401（防降级，关键安全断言）
CODE="$(pop_curl "$WORK/pop/agent.key" "$WORK/pop/agent.crt" POST "$HB_PATH" "$WORK/pop/hb.json" signature - \
  -H "Authorization: Bearer $CRED")"
[ "$CODE" = "401" ] && ok "PoP 头存在但签名被篡改 + 正确 Bearer → 401（防降级，绝不回退 Bearer，契约 §8）" \
  || bad "篡改签名应 401（防降级），实际 HTTP $CODE"

# c. 手工合法 PoP（不带 Bearer）→ 200（证明 PoP 路径独立真实可用，非 agent 自说自话）
CODE="$(pop_curl "$WORK/pop/agent.key" "$WORK/pop/agent.crt" POST "$HB_PATH" "$WORK/pop/hb.json" - -)"
[ "$CODE" = "200" ] && ok "手工构造合法 PoP（无 Bearer）心跳 → 200（PoP 路径独立可用，契约 §8）" \
  || bad "合法 PoP 心跳应 200，实际 HTTP $CODE"

# ---- 11c. 证书轮换（契约 §9：仅 PoP 可调，旧指纹 24h 宽限） ----
log "11c. 证书轮换（rotate-cert 仅 PoP / 新指纹生效 / 旧指纹宽限）"
ROT_PATH="/api/v1/agents/$AGENT_ID/rotate-cert"
"$WORK/poptool" csr -new-key-out "$WORK/pop/rotated.key" >"$WORK/pop/rotated.csr.pem" \
  || die "poptool csr 失败"
jq -Rs '{csr_pem: .}' <"$WORK/pop/rotated.csr.pem" >"$WORK/pop/rotate.json"

# 负例：仅 Bearer（无 PoP）调 rotate-cert → 401
CODE="$(curl -s -o /dev/null -w '%{http_code}' -X POST \
  -H "Authorization: Bearer $CRED" -H 'Content-Type: application/json' \
  --data-binary @"$WORK/pop/rotate.json" "$API_BASE$ROT_PATH")"
[ "$CODE" = "401" ] && ok "rotate-cert 仅 Bearer（无 PoP）→ 401（轮换仅接受 PoP 认证，契约 §9）" \
  || bad "Bearer 调 rotate-cert 应 401，实际 HTTP $CODE"

# 正例：旧证书 PoP 调 rotate-cert → 200 签发新证书
CODE="$(pop_curl "$WORK/pop/agent.key" "$WORK/pop/agent.crt" POST "$ROT_PATH" "$WORK/pop/rotate.json" - \
  "$WORK/pop/rotate_resp.json")"
if [ "$CODE" = "200" ] && jq -e '.agent_cert_pem != null and .ca_cert_pem != null and .cert_expires_at != null' \
    "$WORK/pop/rotate_resp.json" >/dev/null 2>&1; then
  ok "旧证书 PoP 调 rotate-cert → 200，签发新证书（agent_cert_pem/ca_cert_pem/cert_expires_at，契约 §9）"
else
  bad "rotate-cert PoP 调用失败: HTTP $CODE $(cat "$WORK/pop/rotate_resp.json" 2>/dev/null || true)"
fi
[ -s "$WORK/pop/rotate_resp.json" ] || die "rotate_resp.json 缺失（前述 rotate 失败，见上 FAIL）"
jq -r '.agent_cert_pem // empty' "$WORK/pop/rotate_resp.json" >"$WORK/pop/rotated.crt"

OLD_FP="$("$WORK/poptool" fingerprint -cert "$WORK/pop/agent.crt")"
NEW_FP="$("$WORK/poptool" fingerprint -cert "$WORK/pop/rotated.crt" 2>/dev/null || true)"
if [ -n "$NEW_FP" ] && [ "$OLD_FP" != "$NEW_FP" ] \
  && mapi GET "/api/v1/traffic/agents/$AGENT_ID" | jq -e --arg fp "$NEW_FP" '.data.cert_fingerprint == $fp' >/dev/null; then
  ok "管理端 cert_fingerprint 已切换到新指纹（${OLD_FP:0:12}… → ${NEW_FP:0:12}…）"
else
  bad "cert_fingerprint 未切换（old=$OLD_FP new=$NEW_FP）"
fi

# 新证书 PoP 心跳 → 200（新指纹即时生效）
CODE="$(pop_curl "$WORK/pop/rotated.key" "$WORK/pop/rotated.crt" POST "$HB_PATH" "$WORK/pop/hb.json" - -)"
[ "$CODE" = "200" ] && ok "新证书 PoP 心跳 → 200（新指纹即时生效）" \
  || bad "新证书 PoP 心跳应 200，实际 HTTP $CODE"

# 旧证书 PoP 心跳 → 200（24h 宽限期新旧并存；运行中的 agent 进程持旧证书亦赖此继续在线）
CODE="$(pop_curl "$WORK/pop/agent.key" "$WORK/pop/agent.crt" POST "$HB_PATH" "$WORK/pop/hb.json" - -)"
[ "$CODE" = "200" ] && ok "旧证书 PoP 心跳仍 200（24h 宽限期新旧并存，契约 §9）" \
  || bad "宽限期内旧证书 PoP 应 200，实际 HTTP $CODE"

# ---- 11d. HTTP Sensor L2 采集（PHASE3 契约 §2-§6：脱敏/截断/skipped/gzip） ----
log "11d. HTTP Sensor L2：脱敏 / 截断 / content_type 跳过 / gzip 解压"
# capture.backend=afpacket：eBPF 后端 snaplen 会截大帧，L2 验收用 AF_PACKET 保证重组完整
# （契约/设计允许按后端能力选择）；max_body_size=1024 用小上限便于触发截断。
POLICY_L2="$(echo "$POLICY_FLOW" | jq '
  .name="e2e-phase3-l2" | .config.name="e2e-phase3-l2" |
  .config.capture_level="L2" | .config.capture.backend="afpacket" |
  .config.limits.max_body_size=1024')"
mapi PUT "/api/v1/traffic/policies/$POLICY_ID" "$POLICY_L2" >/dev/null
deadline=$(( $(date +%s) + 90 ))
APPLIED_OK=0
while [ "$(date +%s)" -lt "$deadline" ]; do
  read -r CV AV <<<"$(agent_versions)"
  [ "$AV" = "$CV" ] && { APPLIED_OK=1; break; }
  sleep 2
done
[ "$APPLIED_OK" = "1" ] && ok "L2 策略已应用（capture_level=L2 backend=afpacket max_body_size=1024，version ${CV}，ACK 闭环）" \
  || bad "L2 策略下发超时: config_version=$CV applied=$AV"

http_events() { mapi GET "/api/v1/traffic/agents/$AGENT_ID/http-events?page_size=100"; }
http_detail() { mapi GET "/api/v1/traffic/agents/$AGENT_ID/http-events/$1"; }

# 记录当前最新事件 id 作为水位线，之后只对 id 更大的新记录断言
# （步骤 9/11 在既有 L1 策略下已产生 /api/login 等 HTTP 记录）。
MARK="$(http_events | jq -r '.data.items[0].id // 0')"
info "L2 断言水位线 MARK=$MARK"

OCTET='BINPAYLOAD0123456789'
gen_l2_traffic() {
  docker exec "$C_CLIENT" sh -c '
    curl -s -o /dev/null -X POST http://wdsp-e2e-agent:8000/api/login \
      -H "Content-Type: application/json" -H "Authorization: Bearer abc123secret" -H "Connection: close" \
      -d "{\"user\":\"alice\",\"password\":\"p@ssw0rd\"}"
    curl -s -o /dev/null -H "Connection: close" http://wdsp-e2e-agent:8000/big
    curl -s --compressed -o /dev/null -H "Connection: close" http://wdsp-e2e-agent:8000/gz
  '
  docker exec "$C_CLIENT" sh -c "
    curl -s -o /dev/null -X POST http://wdsp-e2e-agent:8000/upload \
      -H 'Content-Type: application/octet-stream' -H 'Connection: close' --data-binary '$OCTET'
  "
}
gen_l2_traffic && ok "L2 验收流量已发起（login 脱敏 / big 5050B / octet-stream ${#OCTET}B / gzip）" || bad "L2 流量发起失败"

# 等四条记录全部入库（Agent 按 1s 冲刷周期上报 POST /agents/{id}/http）
deadline=$(( $(date +%s) + 90 ))
EVS=""
N=0
while [ "$(date +%s)" -lt "$deadline" ]; do
  EVS="$(http_events)"
  N="$(echo "$EVS" | jq --argjson m "$MARK" \
    '[.data.items[] | select(.id > $m) | .request.uri] | map(select(. == "/api/login" or . == "/big" or . == "/upload" or . == "/gz")) | unique | length')"
  [ "$N" = "4" ] && break
  sleep 2
done
[ "$N" = "4" ] && ok "L2 四条 HTTP 记录全部入库（/api/login、/big、/upload、/gz，机器端点 /http 通道，契约 §3）" \
  || { bad "L2 HTTP 记录不齐（命中 $N/4）"; echo "$EVS" | jq -c --argjson m "$MARK" \
      '[.data.items[] | select(.id > $m) | {id, uri: .request.uri, status: (.response.status // null)}]' >&2; }

pick_id() { # pick_id <events_json> <mark> <uri> [method]
  echo "$1" | jq -r --argjson m "$2" --arg u "$3" --arg mt "${4:-}" \
    '[.data.items[] | select(.id > $m and .request.uri == $u and ($mt == "" or .request.method == $mt))] | .[0].id // empty'
}

# a. 脱敏（契约 §5：authorization MASK；JSON 一级 password MASK）
LOGIN_ID="$(pick_id "$EVS" "$MARK" "/api/login" "POST")"
[ -n "$LOGIN_ID" ] || die "缺 /api/login HTTP 记录（见前述 FAIL）"
LOGIN="$(http_detail "$LOGIN_ID")"
echo "$LOGIN" | jq -e '
  .data.tls_visibility == "PLAINTEXT" and
  ((.data.response.status // 0) == 200) and
  (.data.latency_ms != null) and
  ((.data.request.headers.authorization // "") == "********") and
  (.data.request.body | contains("p@ssw0rd") | not) and
  (.data.request.body | contains("********"))' >/dev/null \
  && ok "login 记录：status=200 / latency_ms 非空 / PLAINTEXT / authorization=******** / body 无 p@ssw0rd 原文（契约 §5 MASK 生效）" \
  || bad "login 记录断言失败: $(echo "$LOGIN" | jq -c '.data | {tls_visibility, latency_ms, auth: .request.headers.authorization, body: .request.body, status: (.response.status // null)}')"

echo "$LOGIN" | jq -e '
  .data.k8s.cluster == "wdsp-e2e" and
  .data.k8s.namespace == "wdsp-e2e" and
  .data.k8s.pod == "wdsp-e2e-agent-7d9f84c8bf-x7k2p" and
  .data.k8s.workload == "wdsp-e2e-agent" and
  .data.k8s.service == "wdsp-e2e-service" and
  .data.k8s.side == "dst"' >/dev/null \
  && ok "Phase 5 Kubernetes 元数据：cluster/namespace/pod/workload/service/side 经 Agent→入库→管理详情完整可见" \
  || bad "Kubernetes 元数据断言失败: $(echo "$LOGIN" | jq -c '.data.k8s // null')"

# flow_id 互查：http 记录与 flow 事件（flow_end）同源同流
FLOW_ID_H="$(echo "$LOGIN" | jq -r '.data.flow_id')"
events_json | jq -e --arg f "$FLOW_ID_H" '[.data.items[] | select(.flow_id == $f)] | length >= 1' >/dev/null \
  && ok "http 记录与 flow 事件 flow_id 互查命中（${FLOW_ID_H:0:18}…，同一流双通道）" \
  || bad "http 记录 flow_id=$FLOW_ID_H 在 flow 事件中无对应"

# b. 响应截断（契约 §4：>max_body_size → truncated + original_body_size）
# /big 在 TSO/GSO 全开下以超 MTU 帧到达抓包点（5050B 单写聚合，D-06 修复的真实验收）：
# response 必须非 null 且 status=200（响应完整接收，而非截断快速失败后的 response=null 补发）。
BIG_ID="$(pick_id "$EVS" "$MARK" "/big")"
[ -n "$BIG_ID" ] || die "缺 /big HTTP 记录（见前述 FAIL）"
BIG="$(http_detail "$BIG_ID")"
echo "$BIG" | jq -e '
  (.data.response != null) and
  (.data.response.status == 200) and
  .data.response.body_truncated == true and
  .data.response.original_body_size > 1024 and
  ((.data.response.body | length) <= 1024)' >/dev/null \
  && ok "big 响应截断：response 非 null / status=200 / body_truncated=true / original_body_size=$(echo "$BIG" | jq -r '.data.response.original_body_size')（>1024）/ body 长度≤1024（契约 §4 硬上限；TSO 超帧完整重组，D-06 修复生效）" \
  || bad "big 截断断言失败: $(echo "$BIG" | jq -c '.data.response | {status, body_truncated, original_body_size, body_len: (.body | length)}')"

# c. 内容类型白名单外 → body_skipped_reason=content_type（契约 §4）
UP_ID="$(pick_id "$EVS" "$MARK" "/upload" "POST")"
[ -n "$UP_ID" ] || die "缺 /upload HTTP 记录（见前述 FAIL）"
UP="$(http_detail "$UP_ID")"
echo "$UP" | jq -e --argjson n "${#OCTET}" '
  .data.request.body_skipped_reason == "content_type" and
  (.data.request.original_body_size == $n) and
  (.data.request.body | contains("BINPAYLOAD") | not)' >/dev/null \
  && ok "octet-stream 请求体按 content_type 跳过：skipped_reason=content_type / original_body_size=${#OCTET} / body 无原文（契约 §4 白名单）" \
  || bad "upload skipped 断言失败: $(echo "$UP" | jq -c '.data.request | {body_skipped_reason, original_body_size, body}')"

# d. gzip 响应解压采集（契约 §4 压缩处理）
GZ_ID="$(pick_id "$EVS" "$MARK" "/gz")"
[ -n "$GZ_ID" ] || die "缺 /gz HTTP 记录（见前述 FAIL）"
GZ="$(http_detail "$GZ_ID")"
echo "$GZ" | jq -e '
  .data.response.body_skipped_reason == "" and
  ((try (.data.response.body | fromjson | .msg) catch "") == "gzip-json")' >/dev/null \
  && ok "gzip 响应已解压采集：body 为合法 JSON（msg=gzip-json）且 skipped 为空（契约 §4 压缩处理）" \
  || bad "gzip 断言失败: $(echo "$GZ" | jq -c '.data.response | {body_skipped_reason, body: (.body | .[0:120])}')"

# e. 截断帧计数（D-06 修复验收）：/big 等 TSO 超帧流量后 last_metrics.truncated_frames
# 应为 0 或不存在（omitempty）——64KB 帧缓冲下无捕获截断；计数单调不减，记录入库即
# 保证对应心跳快照已覆盖采集窗口，直接读管理端详情即可。
TF="$(mapi GET "/api/v1/traffic/agents/$AGENT_ID" | jq -r '.data.last_metrics.truncated_frames // 0')"
[ "$TF" = "0" ] && ok "last_metrics.truncated_frames=${TF}（TSO/GSO 全开下零截断帧，D-06 修复生效）" \
  || bad "truncated_frames=${TF}（应 0 或缺省；仍有捕获截断帧，D-06 修复未完全生效）"

# ---- 11e. L1 采集等级（契约 §2：headers 有、body 无；仅对水位线后的新记录断言） ----
log "11e. L1 采集等级（headers 非空、body 为空串）"
POLICY_L1="$(echo "$POLICY_L2" | jq '.name="e2e-phase3-l1" | .config.name="e2e-phase3-l1" | .config.capture_level="L1"')"
mapi PUT "/api/v1/traffic/policies/$POLICY_ID" "$POLICY_L1" >/dev/null
deadline=$(( $(date +%s) + 90 ))
APPLIED_OK=0
while [ "$(date +%s)" -lt "$deadline" ]; do
  read -r CV AV <<<"$(agent_versions)"
  [ "$AV" = "$CV" ] && { APPLIED_OK=1; break; }
  sleep 2
done
[ "$APPLIED_OK" = "1" ] && ok "L1 策略已应用（capture_level=L1，version ${CV}，ACK 闭环）" \
  || bad "L1 策略下发超时: config_version=$CV applied=$AV"

MARK_L1="$(http_events | jq -r '.data.items[0].id // 0')"
docker exec "$C_CLIENT" sh -c 'curl -s -o /dev/null -H "Connection: close" http://wdsp-e2e-agent:8000/index.html' \
  && ok "L1 验收流量已发起（GET /index.html）" || bad "L1 流量发起失败"
deadline=$(( $(date +%s) + 60 ))
L1_ID=""
while [ -z "$L1_ID" ] && [ "$(date +%s)" -lt "$deadline" ]; do
  L1_ID="$(pick_id "$(http_events)" "$MARK_L1" "/index.html")"
  [ -n "$L1_ID" ] || sleep 2
done
[ -n "$L1_ID" ] || bad "L1 新记录（/index.html，id>$MARK_L1）未出现"
if [ -n "$L1_ID" ]; then
  L1D="$(http_detail "$L1_ID")"
  echo "$L1D" | jq -e '
    (.data.request.headers | length) > 0 and
    (((.data.response.headers // {}) | length) > 0) and
    .data.request.body == "" and
    (((.data.response.body // "") == ""))' >/dev/null \
    && ok "L1 记录：request/response headers 非空且 body 均为空串（契约 §2 L1 语义，仅断言 id>$MARK_L1 新记录）" \
    || bad "L1 断言失败: $(echo "$L1D" | jq -c '.data | {req_headers: (.request.headers | length), req_body: .request.body, resp_headers: ((.response.headers // {}) | length), resp_body: (.response.body // null)}')"
fi

# ---- 11f. API 资产联动（契约 §6：UpsertDiscovery 复用入口，URI 模板化） ----
log "11f. API 资产联动（api-security/endpoints 出现 POST /api/login）"
deadline=$(( $(date +%s) + 60 ))
ASSET_OK=0
while [ "$(date +%s)" -lt "$deadline" ]; do
  if mapi GET "/api/v1/api-security/endpoints?keyword=/api/login&page_size=50" | jq -e \
    '[.data.items[] | select(.http_method=="POST") | select((.normalized_path // "") | contains("/api/login")) | select(.hit_count >= 1)] | length >= 1' >/dev/null 2>&1; then
    ASSET_OK=1; break
  fi
  sleep 2
done
[ "$ASSET_OK" = "1" ] && ok "API 资产联动：POST /api/login 已 upsert 为 API 资产（hit_count≥1，契约 §6；host 归因偏离见 README）" \
  || bad "API 资产联动未见 POST /api/login（GET /api-security/endpoints?keyword=/api/login）"

# ---- 11g. 定向采集规则（Phase 4 契约 §2.3：uri_prefix override 即时提升 / 未命中不提升 / 删除回落） ----
log "11g. 定向采集规则（基线 L0 → /api/payment override 提升 L2 → 删除回落）"
# 基线策略回 L0（无 http 记录），验证 override 的即时提升语义：命中 URI 的流自请求行嗅探起
# 提升到 L2 采集，未命中 URI 保持 L0。
POLICY_P4_BASE="$(echo "$POLICY_L2" | jq '
  .name="e2e-phase4-base-l0" | .config.name="e2e-phase4-base-l0" | .config.capture_level="L0"')"
mapi PUT "/api/v1/traffic/policies/$POLICY_ID" "$POLICY_P4_BASE" >/dev/null
deadline=$(( $(date +%s) + 90 ))
APPLIED_OK=0
while [ "$(date +%s)" -lt "$deadline" ]; do
  read -r CV AV <<<"$(agent_versions)"
  [ "$AV" = "$CV" ] && { APPLIED_OK=1; break; }
  sleep 2
done
[ "$APPLIED_OK" = "1" ] && ok "11g 基线策略已应用（capture_level=L0，version ${CV}，ACK 闭环）" \
  || bad "11g 基线策略下发超时: config_version=$CV applied=$AV"

MARK_G="$(http_events | jq -r '.data.items[0].id // 0')"
info "11g 断言水位线 MARK_G=$MARK_G"

OV_RESP="$(mapi POST "/api/v1/traffic/agents/$AGENT_ID/overrides" \
  '{"match":{"uri_prefix":"/api/payment"},"capture_level":"L2","ttl_minutes":30,"note":"e2e-11g"}')"
OVERRIDE_ID="$(echo "$OV_RESP" | jq -r '.data.id // empty')"
[ -n "$OVERRIDE_ID" ] && ok "override 已创建（uri_prefix=/api/payment → L2，ttl=30min，201）" \
  || { bad "override 创建失败: $OV_RESP"; die "无法继续 11g"; }
mapi GET "/api/v1/traffic/agents/$AGENT_ID/overrides" | jq -e --arg id "$OVERRIDE_ID" \
  '[.data.items[] | select(.id==$id and .active==true and .capture_level=="L2" and .match.uri_prefix=="/api/payment")] | length == 1' >/dev/null \
  && ok "overrides 列表含该规则且 active=true（派生字段，契约 §2.3）" \
  || bad "overrides 列表未见 active 规则 $OVERRIDE_ID: $(mapi GET "/api/v1/traffic/agents/$AGENT_ID/overrides" | jq -c '.data')"
# 创建同事务 config_version+1 → agent 拉取生效 → ACK 闭环
deadline=$(( $(date +%s) + 90 ))
APPLIED_OK=0
while [ "$(date +%s)" -lt "$deadline" ]; do
  read -r CV AV <<<"$(agent_versions)"
  [ "$AV" = "$CV" ] && { APPLIED_OK=1; break; }
  sleep 2
done
[ "$APPLIED_OK" = "1" ] && ok "override 创建已联动 config_version 并 ACK（version ${CV}）" \
  || bad "override 创建下发超时: config_version=$CV applied=$AV"

docker exec "$C_CLIENT" sh -c '
  curl -s -o /dev/null -H "Connection: close" http://wdsp-e2e-agent:8000/api/payment
  curl -s -o /dev/null -X POST http://wdsp-e2e-agent:8000/api/login \
    -H "Content-Type: application/json" -H "Connection: close" \
    -d "{\"username\":\"e2e\",\"password\":\"x\"}"
' && ok "11g 验收流量已发起（GET /api/payment 命中规则 + POST /api/login 未命中）" || bad "11g 流量发起失败"

# a. 命中 URI：基线 L0 流被即时提升 L2 → http 记录存在且响应 body 完整（curl 单段请求头可完整
# 解析，响应自提升点起全采）
PAY_ID=""
deadline=$(( $(date +%s) + 60 ))
while [ -z "$PAY_ID" ] && [ "$(date +%s)" -lt "$deadline" ]; do
  PAY_ID="$(pick_id "$(http_events)" "$MARK_G" "/api/payment")"
  [ -n "$PAY_ID" ] || sleep 2
done
if [ -n "$PAY_ID" ]; then
  PAY="$(http_detail "$PAY_ID")"
  echo "$PAY" | jq -e '
    ((.data.response.status // 0) == 200) and
    ((.data.response.body // "") | contains("ord_e2e"))' >/dev/null \
    && ok "/api/payment 命中 override 即时提升 L2：http 记录入库且响应 body 完整（含 ord_e2e）" \
    || bad "/api/payment 记录断言失败: $(echo "$PAY" | jq -c '.data | {status: (.response.status // null), resp_body: (.response.body // null)}')"
else
  bad "/api/payment http 记录未出现（override 提升未生效）"
fi
# b. 未命中 URI：保持 L0 无 http 记录（L0 恢复的旧 request 事件走 events 端点，不影响本断言；
# 等一个冲刷周期再查，避免与 a 的等待提前退出造成竞态）
sleep 3
N_LOGIN="$(http_events | jq --argjson m "$MARK_G" \
  '[.data.items[] | select(.id > $m and .request.uri == "/api/login")] | length')"
[ "$N_LOGIN" = "0" ] && ok "/api/login 未命中 override 保持 L0：无新 http 记录（提升不泄漏到未命中 URI）" \
  || bad "/api/login 出现 $N_LOGIN 条新 http 记录（应 0，override 泄漏到未命中 URI）"

# d. 删除规则 → ACK → 再请求 /api/payment → 回落 L0 无新 http 记录
CODE="$(curl -s -o /dev/null -w '%{http_code}' -b "$JAR" -H "X-CSRF-Token: $CSRF" -X DELETE \
  "$API_BASE/api/v1/traffic/agents/$AGENT_ID/overrides/$OVERRIDE_ID")"
[ "$CODE" = "204" ] && ok "DELETE override → 204（契约 §2.3）" \
  || bad "DELETE override 应 204，实际 HTTP $CODE"
deadline=$(( $(date +%s) + 90 ))
APPLIED_OK=0
while [ "$(date +%s)" -lt "$deadline" ]; do
  read -r CV AV <<<"$(agent_versions)"
  [ "$AV" = "$CV" ] && { APPLIED_OK=1; break; }
  sleep 2
done
[ "$APPLIED_OK" = "1" ] && ok "override 删除已联动 config_version 并 ACK（version ${CV}）" \
  || bad "override 删除下发超时: config_version=$CV applied=$AV"
MARK_G2="$(http_events | jq -r '.data.items[0].id // 0')"
docker exec "$C_CLIENT" curl -s -o /dev/null -H "Connection: close" http://wdsp-e2e-agent:8000/api/payment
sleep 8
N_PAY2="$(http_events | jq --argjson m "$MARK_G2" \
  '[.data.items[] | select(.id > $m and .request.uri == "/api/payment")] | length')"
[ "$N_PAY2" = "0" ] && ok "override 删除后 /api/payment 回落 L0：无新 http 记录（删除经 ACK 闭环生效）" \
  || bad "override 删除后 /api/payment 仍有 $N_PAY2 条新 http 记录（应 0）"

# ---- 11h. 确定性采样（Phase 4 契约 §2.2：rate=0.01，http 记录宽松上界） ----
log "11h. 采样（sampling.rate=0.01，20 次请求新 http 记录 ≤2）"
POLICY_P4_SAMP="$(echo "$POLICY_L2" | jq '
  .name="e2e-phase4-sampling" | .config.name="e2e-phase4-sampling" |
  .config.capture_level="L2" | .config.sampling={"enabled":true,"rate":0.01}')"
mapi PUT "/api/v1/traffic/policies/$POLICY_ID" "$POLICY_P4_SAMP" >/dev/null
deadline=$(( $(date +%s) + 90 ))
APPLIED_OK=0
while [ "$(date +%s)" -lt "$deadline" ]; do
  read -r CV AV <<<"$(agent_versions)"
  [ "$AV" = "$CV" ] && { APPLIED_OK=1; break; }
  sleep 2
done
[ "$APPLIED_OK" = "1" ] && ok "采样策略已应用（sampling.enabled=true rate=0.01，version ${CV}，ACK 闭环）" \
  || bad "采样策略下发超时: config_version=$CV applied=$AV"

MARK_H="$(http_events | jq -r '.data.items[0].id // 0')"
docker exec "$C_CLIENT" sh -c '
  i=0
  while [ $i -lt 20 ]; do
    curl -s -o /dev/null -H "Connection: close" http://wdsp-e2e-agent:8000/index.html
    i=$((i+1))
  done
' && ok "采样验收流量已发起（20 × GET /index.html 独立短连接）" || bad "采样流量发起失败"
# 采样判定 SHA-256(flow_id) 前 8 字节/2^64 < rate：rate=0.01 下 20 流期望≈0.2 条，宽松上界 ≤2
# （确定性采样对固定 flow_id 结果确定，不同跑次 flow_id 随机故用统计上界而不断言 0）
sleep 8
N_SAMP="$(http_events | jq --argjson m "$MARK_H" '[.data.items[] | select(.id > $m)] | length')"
[ "$N_SAMP" -le 2 ] 2>/dev/null \
  && ok "采样上界：20 次请求新 http 记录 ${N_SAMP} 条 ≤2（rate=0.01 期望≈0.2，采样外 flow 仅 flow_end 计数、无 http 记录）" \
  || bad "采样后新 http 记录 ${N_SAMP} 条 >2（rate=0.01 上界被突破）"

# 恢复全量采集（capture_level 保持 L2，供 11i 背压产生 http 记录积压）
POLICY_P4_RESTORE="$(echo "$POLICY_P4_SAMP" | jq '
  .name="e2e-phase4-sampling-off" | .config.name="e2e-phase4-sampling-off" | .config.sampling={"enabled":false,"rate":1.0}')"
mapi PUT "/api/v1/traffic/policies/$POLICY_ID" "$POLICY_P4_RESTORE" >/dev/null
deadline=$(( $(date +%s) + 90 ))
APPLIED_OK=0
while [ "$(date +%s)" -lt "$deadline" ]; do
  read -r CV AV <<<"$(agent_versions)"
  [ "$AV" = "$CV" ] && { APPLIED_OK=1; break; }
  sleep 2
done
[ "$APPLIED_OK" = "1" ] && ok "采样已关闭恢复全量（enabled=false rate=1.0，version ${CV}，ACK 闭环）" \
  || bad "采样恢复下发超时: config_version=$CV applied=$AV"

# ---- 11i. 背压降级与恢复（Phase 4 契约 §2.5：出站限速 → DEGRADED + backpressure_cap → 恢复 ONLINE） ----
log "11i. 背压（outbound_mbps=0.05 触发降级，恢复带宽后回 ONLINE）"
POLICY_P4_BP="$(echo "$POLICY_P4_RESTORE" | jq '
  .name="e2e-phase4-backpressure" | .config.name="e2e-phase4-backpressure" | .config.limits.outbound_mbps=0.05')"
mapi PUT "/api/v1/traffic/policies/$POLICY_ID" "$POLICY_P4_BP" >/dev/null
deadline=$(( $(date +%s) + 90 ))
APPLIED_OK=0
while [ "$(date +%s)" -lt "$deadline" ]; do
  read -r CV AV <<<"$(agent_versions)"
  [ "$AV" = "$CV" ] && { APPLIED_OK=1; break; }
  sleep 2
done
[ "$APPLIED_OK" = "1" ] && ok "背压策略已应用（outbound_mbps=0.05，version ${CV}，ACK 闭环）" \
  || bad "背压策略下发超时: config_version=$CV applied=$AV"

# 持续大流量（/big 5050B 响应 ×100，L2 全采）使出站桶持续拒绝：DenialStreak≥5s → 水位 1.0
# → 采集帽自 L3 逐级下降（≥70% 时每 10s 最多一级），帽 <L3 即心跳 status=DEGRADED +
# metrics.backpressure_cap。后台发流，前台并发轮询管理端详情。
bp_cap() { mapi GET "/api/v1/traffic/agents/$AGENT_ID" | jq -r '"\(.data.status) \(.data.last_metrics.backpressure_cap // "")"'; }
docker exec "$C_CLIENT" sh -c '
  i=0
  while [ $i -lt 100 ]; do
    curl -s -o /dev/null -H "Connection: close" http://wdsp-e2e-agent:8000/big
    i=$((i+1))
  done
' >/dev/null 2>&1 &
BP_TRAFFIC_PID=$!
deadline=$(( $(date +%s) + 90 ))
BP_OK=0
while [ "$(date +%s)" -lt "$deadline" ]; do
  read -r ST CAP <<<"$(bp_cap)"
  if [ "$ST" = "DEGRADED" ] && [ -n "$CAP" ]; then BP_OK=1; break; fi
  sleep 2
done
wait "$BP_TRAFFIC_PID" 2>/dev/null || true
[ "$BP_OK" = "1" ] && ok "背压降级生效：status=DEGRADED 且 last_metrics.backpressure_cap=${CAP}（出站桶持续拒绝 → 采集帽 <L3，契约 §2.5）" \
  || bad "90s 内未见 DEGRADED + backpressure_cap（当前: $(bp_cap)）"

# 恢复带宽：帽按迟滞逐级回升（水位 <50% 持续 30s 升一级），180s 上限应足够回 L3/ONLINE
POLICY_P4_BP_RESTORE="$(echo "$POLICY_P4_BP" | jq '
  .name="e2e-phase4-bp-restore" | .config.name="e2e-phase4-bp-restore" | .config.limits.outbound_mbps=100')"
mapi PUT "/api/v1/traffic/policies/$POLICY_ID" "$POLICY_P4_BP_RESTORE" >/dev/null
deadline=$(( $(date +%s) + 90 ))
APPLIED_OK=0
while [ "$(date +%s)" -lt "$deadline" ]; do
  read -r CV AV <<<"$(agent_versions)"
  [ "$AV" = "$CV" ] && { APPLIED_OK=1; break; }
  sleep 2
done
[ "$APPLIED_OK" = "1" ] && ok "带宽已恢复（outbound_mbps=100，version ${CV}，ACK 闭环）" \
  || bad "带宽恢复下发超时: config_version=$CV applied=$AV"
deadline=$(( $(date +%s) + 180 ))
REC_OK=0
while [ "$(date +%s)" -lt "$deadline" ]; do
  read -r ST CAP <<<"$(bp_cap)"
  if [ "$ST" = "ONLINE" ] && [ -z "$CAP" ]; then REC_OK=1; break; fi
  sleep 3
done
[ "$REC_OK" = "1" ] && ok "背压恢复：backpressure_cap 消失且状态回 ONLINE（迟滞回升完成，契约 §2.5）" \
  || bad "180s 内未恢复 ONLINE（当前: $(bp_cap)；迟滞 30s×降级级数，若偶发超时按 README 观察项记录）"

# ---- 12. 禁用（契约 §3.2 desired_state=DISABLED） ----
log "12. 禁用 Agent（停抓保心跳）"
mapi POST "/api/v1/traffic/agents/$AGENT_ID/disable" >/dev/null
deadline=$(( $(date +%s) + 90 ))
while ! docker exec "$C_AGENT" grep -q '停止抓包' /var/log/wdsp-agent.log 2>/dev/null \
  && [ "$(date +%s)" -lt "$deadline" ]; do sleep 2; done
docker exec "$C_AGENT" grep -q '停止抓包' /var/log/wdsp-agent.log 2>/dev/null \
  && ok "Agent 日志出现「服务端禁用 Agent，停止抓包（心跳继续）」（收到 DISABLED 并处置）" \
  || bad "Agent 日志未见停止抓包记录"
[ "$(agent_status)" = "DISABLED" ] && ok "管理面派生状态 DISABLED（心跳仍在线，契约 §5）" \
  || bad "禁用后状态异常: $(agent_status)"

# disable 立即撤销当前指纹（契约 §11）：重放当前（轮换后新）证书 PoP → 401
CODE="$(pop_curl "$WORK/pop/rotated.key" "$WORK/pop/rotated.crt" POST "$HB_PATH" "$WORK/pop/hb.json" - -)"
[ "$CODE" = "401" ] && ok "disable 后重放当前证书 PoP → 401（吊销即时生效，契约 §11）" \
  || bad "disable 后当前证书 PoP 应 401（吊销未生效），实际 HTTP $CODE"

# ---- 13. 停管理后端 → 业务不受影响 + 断线重连退避（设计 §61 WDSP Shutdown） ----
log "13. 停掉管理后端（WDSP Shutdown 故障验收）"
kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""
sleep 3
docker exec "$C_CLIENT" curl -sf "http://$C_AGENT:8000/" | grep -q 'business ok' \
  && ok "管理后端停止后业务 HTTP 服务正常（Fail-Open 红线）" \
  || bad "管理后端停止后业务异常"
deadline=$(( $(date +%s) + 90 ))
while ! docker exec "$C_AGENT" grep -q '心跳失败，退避重连' /var/log/wdsp-agent.log 2>/dev/null \
  && [ "$(date +%s)" -lt "$deadline" ]; do sleep 2; done
docker exec "$C_AGENT" grep -q '心跳失败，退避重连' /var/log/wdsp-agent.log 2>/dev/null \
  && ok "Agent 进入断线重连指数退避（设计 §61 / 契约 §6：1s→60s）" \
  || bad "Agent 日志未见断线退避"

# ---- 14. kill -9 agent → 业务仍正常（设计 §61 Agent Kill，Fail-Open 红线） ----
log "14. kill -9 wdsp-agent（Agent Kill 故障验收）"
docker exec "$C_AGENT" sh -c 'kill -9 $(pidof wdsp-agent)' 2>/dev/null || true
sleep 2
if docker exec "$C_AGENT" pidof wdsp-agent >/dev/null 2>&1; then
  bad "wdsp-agent 进程未能 kill -9"
else
  ok "wdsp-agent 进程已被 kill -9"
fi
docker exec "$C_CLIENT" sh -c 'curl -sf http://wdsp-e2e-agent:8000/ && curl -s -o /dev/null -X POST http://wdsp-e2e-agent:8000/api/login' \
  | grep -q 'business ok' \
  && ok "Agent 进程被杀后业务 HTTP 服务完全正常（旁路只读 Fail-Open，设计 §61 红线）" \
  || bad "Agent 被杀后业务异常"

# ---- 汇总 ----
echo
log "结果汇总"
info "通过 $PASS_COUNT 项，失败 $FAIL_COUNT 项"
if [ "$FAIL_COUNT" -eq 0 ]; then
  echo "WDSP AGENT E2E: PASS"
  exit 0
else
  echo "WDSP AGENT E2E: FAIL"
  exit 1
fi
