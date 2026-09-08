#!/usr/bin/env bash
# P1-03 G3 真实 Envoy 取证：TLS 终止 + tap 管理流 → tapsrc 适配器。
#
# 场景（对应任务书 AGT-005/006/007/008/009/010/011 的 G3 部分）：
#   S1  HTTP/2 单连接多路复用（6 流交错）：请求/响应按流配对（X-Rid 回显
#       校验），observed=2 / DECRYPTED / COMPLETE；query token 脱敏
#   S2  gRPC unary 成功：service/method、grpc_status=0、CLOSED、HTTP 200
#   S3  gRPC unary 非零状态：grpc_status=3 与 HTTP 200 分列；trailer 脱敏
#   S4  gRPC server streaming 成功（3 消息）：CLOSED/0
#   S5  gRPC streaming 客户端取消：不伪造 grpc_status=0（UNKNOWN/部分如实）
#   S6  gRPC streaming 截止时间：不伪造成功；客户端 DEADLINE_EXCEEDED
#   S7  WebSocket 握手成功：101 握手视图可见，帧内容不驻留（相位 B）
#   S8  WebSocket 握手失败（403）：如实记录（相位 B）
#   S9  Envoy 进程重启：tap 管理流中断重连（disconnect/reconnect 计数），
#       重启后重新提交 tap 配置、采集恢复
#   S10 适配器故障：杀死后业务照常 200（采集故障不影响转发），守护拉起后
#        采集恢复
#   S11 脱敏：header/query/body/trailer 合成敏感标记在 records.jsonl 无明文
#   S12 正文超 Envoy 缓冲上限截断：truncated=true + original_total_size=null
#       （契约 V1.1：截断但总大小未知）
#   全局：records.jsonl 无任何合成敏感标记明文（脱敏在出主机前）
#
# 相位（Envoy v1.35.3 实测：Admin 同时只允许一条已挂接 tap 流）：
#   相位 A：envoy-h2.yaml（8443 TLS/h2 挂 tap，断言 observed=2/DECRYPTED），跑 S1-S6/S9-S12；
#   相位 B：换入 envoy-h1.yaml（8080 明文挂 tap，断言 observed=1.1/PLAINTEXT），跑 S7/S8。
#
# 隔离铁律（仿 mirror/run.sh）：
#   - 每次运行唯一 run_id；容器命名 wdsp-envoytap-e2e-<run_id> 并打
#     wdsp.envoytap.run_id 标签；删除前双校验（名称+标签）；
#   - 禁止全局 prune，不操作任何非本 run 资源；容器不发布任何端口到宿主机
#     （客户端全部 docker exec 在容器内回环执行）；
#   - 基础镜像 tag+digest 双锁（见 Dockerfile 与 BASE_IMAGE）。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
RUNS_ROOT="${SCRIPT_DIR}/runs"
BASE_IMAGE="envoyproxy/envoy:v1.35.3@sha256:4d496918618a7ebd6c71ae8285e31ebff092f3a0a5ad642d50decf4a54eb2456"
TEST_IMAGE="wdsp-envoytap-e2e:g3"

RUN_ID="$(date '+%Y%m%dT%H%M%S')-$(head -c 3 /dev/urandom | od -An -tx1 | tr -d ' \n')"
RUN_DIR="${RUNS_ROOT}/${RUN_ID}"
CONTAINER="wdsp-envoytap-e2e-$(printf '%s' "${RUN_ID}" | tr 'A-Z' 'a-z' | tr -d '.')"
EVIDENCE="${RUN_DIR}/evidence"
START_TS="$(date +%s)"

PASS_COUNT=0
FAIL_COUNT=0

log()  { printf '[envoytap-e2e %s] %s\n' "$(date '+%H:%M:%S')" "$*"; }
ok()   { PASS_COUNT=$((PASS_COUNT+1)); printf '  [OK]   %s\n' "$*"; }
bad()  { FAIL_COUNT=$((FAIL_COUNT+1)); printf '  [FAIL] %s\n' "$*" >&2; }

cleanup() {
  set +e
  local owned
  owned="$(docker ps -aq --filter "name=^${CONTAINER}$" \
      --filter "label=wdsp.envoytap.run_id=${RUN_ID}" 2>/dev/null)"
  if [ -n "${owned}" ]; then
    docker rm -f "${CONTAINER}" >/dev/null 2>&1
  fi
  rm -f "${RUN_DIR}/tls/tls.key" 2>/dev/null
  log "清理完成（容器已删；证据保留于 ${RUN_DIR}）"
}
trap cleanup EXIT

die() { echo "FATAL: $*" >&2; exit 1; }

exec_client() { # 容器内回环执行取证客户端
  docker exec "${CONTAINER}" /usr/local/bin/tace2e "$@"
}

# ── 预检 ─────────────────────────────────────────────────
preflight() {
  command -v docker >/dev/null || die "docker 不可用"
  docker info >/dev/null 2>&1 || die "docker daemon 不可达"
  for c in openssl python3 go; do
    command -v "${c}" >/dev/null || die "${c} 不可用"
  done
  [ -f "${REPO_ROOT}/wdsp-agent/go.mod" ] || die "wdsp-agent 模块缺失"
  [ -f "${SCRIPT_DIR}/harness/go.mod" ] || die "取证 harness 模块缺失"
  grep -q "FROM ${BASE_IMAGE}" "${SCRIPT_DIR}/Dockerfile" \
    || die "Dockerfile 基础镜像未按 ${BASE_IMAGE} 锁定"
  docker image inspect "${BASE_IMAGE}" >/dev/null 2>&1 \
    || die "基础镜像未拉取：docker pull ${BASE_IMAGE}"
  if docker ps -a --filter "name=^${CONTAINER}$" -q | grep -q .; then
    die "容器名冲突（run_id 碰撞），拒绝复用"
  fi
  log "预检通过"
}

# ── 构建与启动 ────────────────────────────────────────────
build_and_start() {
  mkdir -p "${EVIDENCE}" "${RUN_DIR}/tls"
  umask 077

  openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj "/CN=envoy-tap-e2e.local" \
    -keyout "${RUN_DIR}/tls/tls.key" -out "${RUN_DIR}/tls/tls.crt" >/dev/null 2>&1 \
    || die "自签证书生成失败"
  chmod 0600 "${RUN_DIR}/tls/tls.key"

  local goarch
  case "$(docker info -f '{{.Architecture}}')" in
    aarch64) goarch=arm64 ;;
    x86_64)  goarch=amd64 ;;
    *)       die "未知 docker 架构: $(docker info -f '{{.Architecture}}')" ;;
  esac
  (cd "${REPO_ROOT}/wdsp-agent" && \
    GOOS=linux GOARCH="${goarch}" CGO_ENABLED=0 go build -o "${RUN_DIR}/tapharness" ./cmd/tapharness) \
    || die "tapharness 构建失败"
  (cd "${SCRIPT_DIR}/harness" && \
    GOOS=linux GOARCH="${goarch}" CGO_ENABLED=0 go build -o "${RUN_DIR}/tace2e" .) \
    || die "tace2e 构建失败"

  local ctx="${RUN_DIR}/buildctx"
  mkdir -p "${ctx}"
  cp "${SCRIPT_DIR}/Dockerfile" "${SCRIPT_DIR}/envoy-h2.yaml" "${SCRIPT_DIR}/envoy-h1.yaml" "${SCRIPT_DIR}/entrypoint.sh" "${ctx}/"
  cp "${RUN_DIR}/tapharness" "${RUN_DIR}/tace2e" "${ctx}/"
  docker build -q -t "${TEST_IMAGE}" "${ctx}" >/dev/null || die "取证镜像构建失败"
  rm -rf "${ctx}" "${RUN_DIR}/tapharness" "${RUN_DIR}/tace2e"
  docker image inspect "${TEST_IMAGE}" --format '{{.Id}}' > "${RUN_DIR}/image-id.txt"

  docker run -d --name "${CONTAINER}" \
    --label "wdsp.envoytap.run_id=${RUN_ID}" \
    -e "TAP_INSTANCE=envoy-e2e" -e "TAP_BODY=1" \
    -v "${RUN_DIR}/tls:/etc/envoy/tls:ro" \
    -v "${EVIDENCE}:/evidence" \
    "${TEST_IMAGE}" >/dev/null || die "容器启动失败"

  # 业务就绪（有界等待；Envoy/源站/适配器守护循环自拉起）
  local deadline=$(( $(date +%s) + 90 ))
  while :; do
    if exec_client httpget -url http://127.0.0.1:8080/healthz -rid ready 2>/dev/null | grep -q 'status=200'; then
      break
    fi
    [ "$(date +%s)" -ge "${deadline}" ] && die "栈健康等待超时"
    sleep 2
  done
  log "栈就绪（容器 ${CONTAINER}，无端口发布）"
  # 等待 tap 会话建立（适配器重试提交 tap 配置）
  sleep 5
}

# ── 场景 ─────────────────────────────────────────────────
scenario_traffic() {
  log "S1 HTTP/2 多路复用（6 流交错，X-Rid 回显配对校验）"
  exec_client h2client -base https://envoy-tap-e2e.local:8443 -dial 127.0.0.1:8443 -n 6

  log "S2 gRPC unary 成功"
  exec_client grpcclient -addr 127.0.0.1:8443 -mode unary -rid grpc-s2

  log "S3 gRPC unary 非零状态（INVALID_ARGUMENT=3）"
  exec_client grpcclient -addr 127.0.0.1:8443 -mode fail -rid grpc-s3

  log "S4 gRPC server streaming 成功（3 消息）"
  exec_client grpcclient -addr 127.0.0.1:8443 -mode stream -rid grpc-s4

  log "S5 gRPC streaming 客户端取消（首消息后 cancel）"
  exec_client grpcclient -addr 127.0.0.1:8443 -mode cancel -rid grpc-s5

  log "S6 gRPC streaming 截止时间（300ms deadline，服务端 2s/条）"
  exec_client grpcclient -addr 127.0.0.1:8443 -mode deadline -rid grpc-s6

  log "S12 正文超 Envoy 缓冲上限（8KB > 4KB 截断）"
  exec_client h2client -base https://envoy-tap-e2e.local:8443 -dial 127.0.0.1:8443 -n 1 -body-bytes 8192 -rid s12

  log "S9 Envoy 进程重启（tap 流中断 → 适配器重连重新提交）"
  docker exec "${CONTAINER}" pkill -x envoy || die "杀死 envoy 失败"
  sleep 8  # 守护 3s 重启 + 适配器退避重连
  exec_client h2client -base https://envoy-tap-e2e.local:8443 -dial 127.0.0.1:8443 -n 1 -rid s9-after

  log "S10 适配器故障（杀死后业务照常；守护拉起恢复采集）"
  docker exec "${CONTAINER}" pkill -x tapharness || die "杀死适配器失败"
  sleep 1
  local i
  for i in 1 2 3; do
    exec_client h2client -base https://envoy-tap-e2e.local:8443 -dial 127.0.0.1:8443 -n 1 -rid "s10-down-${i}"
  done
  sleep 6  # 守护 3s 拉起 + tap 重连
  exec_client h2client -base https://envoy-tap-e2e.local:8443 -dial 127.0.0.1:8443 -n 1 -rid s10-after

  log "S11 脱敏标记流量（header/query/body/trailer 合成敏感标记）"
  exec_client h2client -base https://envoy-tap-e2e.local:8443 -dial 127.0.0.1:8443 -n 1 -rid s11

  # ── 相位 B：切到 h1 明文监听挂 tap（单管理流约束，须换配置重启两者）──
  log "相位切换：envoy-h1.yaml（8080 明文挂 tap）+ 断言 observed=1.1/PLAINTEXT"
  docker cp "${SCRIPT_DIR}/envoy-h1.yaml" "${CONTAINER}:/etc/envoy/envoy.yaml" || die "相位 B 配置换入失败"
  docker exec "${CONTAINER}" sh -c 'echo "-observed 1.1" > /run/wdsp/tap-flags' || die "相位 B flags 注入失败"
  docker exec "${CONTAINER}" pkill -x envoy || die "相位 B 重启 envoy 失败"
  docker exec "${CONTAINER}" pkill -x tapharness || die "相位 B 重启适配器失败"
  sleep 8  # 守护 3s 重启 ×2 + tap 重连

  log "S7 WebSocket 握手成功 + 单帧 echo（帧内容含合成敏感标记）"
  exec_client wsclient -addr 127.0.0.1:8080 -path /ws -rid ws-s7 -frame "ws-frame-secret-s7"

  log "S8 WebSocket 握手失败（/ws-deny → 403）"
  exec_client wsclient -addr 127.0.0.1:8080 -path /ws-deny -rid ws-s8

  docker logs "${CONTAINER}" > "${EVIDENCE}/stack.log" 2>&1 || true
}

# ── 断言 ─────────────────────────────────────────────────
verify() {
  log "断言（有界等待 records.jsonl 产出）"
  local deadline=$(( $(date +%s) + 40 ))
  while :; do
    [ -s "${EVIDENCE}/records.jsonl" ] && break
    [ "$(date +%s)" -ge "${deadline}" ] && break
    sleep 1
  done
  sleep 4  # WS 追踪在连接关闭时冲刷 + 收尾等待

  python3 - "${EVIDENCE}" <<'PYEOF'
import json, os, sys

evidence = sys.argv[1]
records = []
with open(os.path.join(evidence, "records.jsonl"), encoding="utf-8") as fh:
    for line in fh:
        line = line.strip()
        if line:
            records.append(json.loads(line))
raw = open(os.path.join(evidence, "records.jsonl"), encoding="utf-8").read()
results = []

def check(name, cond, detail=""):
    results.append((name, bool(cond), detail))

def find(rid):
    out = []
    for r in records:
        req = r.get("request", {})
        uri = req.get("uri") or ""
        hdrs = req.get("headers") or {}
        if f"rid={rid}" in uri or f"rid={rid}&" in uri \
           or rid in (hdrs.get("x-rid") or []) \
           or (r.get("grpc") or {}).get("service", "").endswith(rid):
            out.append(r)
    return out

def single(rid):
    rs = find(rid)
    return rs[0] if rs else None

# S1：H2 多路复用配对
h2ok = 0
for i in range(6):
    r = single(f"h2-{i}")
    if r and r.get("response") and (r["response"].get("headers") or {}).get("x-rid") == [f"h2-{i}"] \
       and f"rid=h2-{i}" in r["request"].get("uri", ""):
        h2ok += 1
check("S1 6 条 H2 流全部按流配对（X-Rid 回显一致，不串流）", h2ok == 6, f"paired={h2ok}/6")
r0 = single("h2-0")
if r0:
    check("S1 来源/协议/TLS 口径", r0.get("source_type") == "ENVOY_TAP"
          and r0.get("source_instance") == "envoy-e2e"
          and r0.get("source_capabilities_version") == "envoy-tap/1"
          and r0.get("observed_http_version") == "2"
          and r0.get("original_http_version") == "2"
          and r0.get("tls_visibility") == "DECRYPTED"
          and r0.get("association_state") == "COMPLETE",
          json.dumps({k: r0.get(k) for k in ("source_type","observed_http_version","original_http_version","tls_visibility","association_state")}))
    check("S1 capture_stream_id 为 null（tap 缓冲输出无流 ID，不造假）",
          r0.get("capture_stream_id") is None)
    check("S1 query token 脱敏", "token=********" in r0["request"].get("uri", "")
          and "plain-h2tok" not in r0["request"].get("uri", ""), r0["request"].get("uri"))
    check("S1 五元组占位（tap 不含地址，不伪造）", r0.get("src_ip") == "127.0.0.1" and r0.get("src_port") == 0)
    check("S1 tap 时戳口径（latency 恒 0 不表达业务延迟）", r0.get("latency_ms") == 0)

# S2：gRPC unary 成功
r = None
for x in records:
    g = x.get("grpc") or {}
    hdrs = x.get("request", {}).get("headers") or {}
    if g.get("service") == "test.Echo" and g.get("method") == "Unary" and "grpc-s2" in (hdrs.get("x-rid") or []):
        r = x
check("S2 gRPC unary 记录存在", r is not None)
if r:
    g = r["grpc"]
    check("S2 service/method 解析", g.get("service") == "test.Echo" and g.get("method") == "Unary")
    check("S2 grpc_status=0 + CLOSED", g.get("grpc_status") == 0 and g.get("stream_state") == "CLOSED",
          json.dumps(g))
    check("S2 HTTP 200 与 RPC 状态分列", r["response"]["status"] == 200)
    check("S2 gRPC 正文不采集", r["request"].get("body") == ""
          and r["request"].get("body_quality", {}).get("skipped_reason") == "content_type")
    check("S2 响应 trailers 可见", "grpc-status" in (r["response"].get("trailers") or {}))

# S3：非零 grpc-status（HTTP 200 ≠ RPC 成功）
r = None
for x in records:
    hdrs = x.get("request", {}).get("headers") or {}
    if "grpc-s3" in (hdrs.get("x-rid") or []):
        r = x
check("S3 记录存在", r is not None)
if r:
    g = r.get("grpc") or {}
    check("S3 grpc_status=3（HTTP 200 ≠ RPC 成功）",
          r["response"]["status"] == 200 and g.get("grpc_status") == 3, json.dumps(g))
    # trailers-only 响应：set-cookie 并入响应 headers（Envoy 实测呈现形态）
    resp = r["response"]
    sc = (resp.get("trailers") or {}).get("set-cookie") or (resp.get("headers") or {}).get("set-cookie") or []
    check("S3 trailer 敏感标记脱敏（set-cookie）",
          sc == ["********"] and "plain-trailer-secret-s3" not in json.dumps(resp),
          json.dumps({"trailers": resp.get("trailers"), "set-cookie": sc}))

# S4：streaming 成功
r = None
for x in records:
    hdrs = x.get("request", {}).get("headers") or {}
    if "grpc-s4" in (hdrs.get("x-rid") or []):
        r = x
check("S4 streaming 成功记录（CLOSED/0）",
      r is not None and (r.get("grpc") or {}).get("grpc_status") == 0
      and (r.get("grpc") or {}).get("stream_state") == "CLOSED",
      json.dumps((r or {}).get("grpc")))

# S5/S6：取消/截止——不伪造 grpc_status=0
for rid, tag in (("grpc-s5", "S5 取消"), ("grpc-s6", "S6 截止")):
    rs = [x for x in records if rid in (x.get("request", {}).get("headers") or {}).get("x-rid", [])]
    forged = [x for x in rs if (x.get("grpc") or {}).get("grpc_status") == 0
              and (x.get("grpc") or {}).get("stream_state") == "CLOSED"]
    check(f"{tag} 不伪造成功（grpc_status≠0 或 UNKNOWN/REQUEST_ONLY）",
          len(forged) == 0,
          f"records={len(rs)} shapes=" + json.dumps(
              [{"assoc": x.get("association_state"), "grpc": x.get("grpc")} for x in rs]))

# S7：WS 握手成功（101 视图；帧不驻留）
r = None
for x in records:
    hdrs = x.get("request", {}).get("headers") or {}
    if "ws-s7" in (hdrs.get("x-rid") or []):
        r = x
check("S7 WS 握手记录存在", r is not None)
if r:
    check("S7 握手视图 101 + COMPLETE", r.get("response", {}).get("status") == 101
          and r.get("association_state") == "COMPLETE",
          json.dumps({"status": (r.get("response") or {}).get("status"), "assoc": r.get("association_state")}))
    check("S7 握手请求头可见（upgrade/sec-websocket-key）",
          "websocket" in ((r["request"].get("headers") or {}).get("upgrade") or [""])[0])
    check("S7 相位 B 协议断言（observed=1.1 / PLAINTEXT）",
          r.get("observed_http_version") == "1.1" and r.get("tls_visibility") == "PLAINTEXT",
          json.dumps({"observed": r.get("observed_http_version"), "tls": r.get("tls_visibility")}))
    check("S7 帧内容不驻留（正文为空）",
          r["request"].get("body", "") == "" and (r.get("response") or {}).get("body", "") == "")

# S8：WS 握手失败
r = None
for x in records:
    hdrs = x.get("request", {}).get("headers") or {}
    if "ws-s8" in (hdrs.get("x-rid") or []):
        r = x
check("S8 WS 握手失败记录（403）", r is not None and r.get("response", {}).get("status") == 403)

# S9：重启后采集恢复
check("S9 Envoy 重启后采集恢复（s9-after 记录存在）", single("s9-after") is not None)

# S10：适配器恢复后采集恢复
check("S10 适配器恢复后采集恢复（s10-after 记录存在）", single("s10-after") is not None)

# S12：正文截断口径（契约 V1.1）
r = single("s12")
check("S12 记录存在", r is not None)
if r:
    bq = r["request"].get("body_quality") or {}
    check("S12 truncated=true 且 original_total_size=null（截断但总大小未知）",
          bq.get("truncated") is True and bq.get("original_total_size") is None,
          json.dumps(bq))

# 适配器计数
stats = {}
sp = os.path.join(evidence, "adapter-stats.json")
if os.path.exists(sp):
    stats = json.load(open(sp))
check("适配器断连/重连计数（S9 生效）",
      stats.get("disconnects", 0) >= 1 and stats.get("reconnects", 0) >= 1, json.dumps(stats))
check("适配器无解析错误/超限丢弃", stats.get("parse_errors", 1) == 0 and stats.get("oversize_drops", 1) == 0,
      json.dumps(stats))

# 全局：无明文泄漏（脱敏在出主机前）
for marker in ("plain-h2tok", "plain-ws-secret", "plain-trailer-secret-s3", "ws-frame-secret-s7"):
    check(f"全局 无明文泄漏 {marker[:16]}…", marker not in raw)

failed = [n for n, ok_, d in results if not ok_]
for n, ok_, d in results:
    print(f"  [{'OK' if ok_ else 'FAIL'}] {n}" + ("" if ok_ else f"  -- {d[:240]}"))
report = os.path.join(evidence, "verify-report.md")
with open(report, "w", encoding="utf-8") as fh:
    fh.write("# P1-03 G3 Envoy tap 取证断言\n\n")
    fh.write(f"记录总数：{len(records)}\n\n")
    fh.write("## 取消/截止场景实际到达形态（如实记录）\n\n")
    for rid in ("grpc-s5", "grpc-s6"):
        rs = [x for x in records if rid in (x.get("request", {}).get("headers") or {}).get("x-rid", [])]
        fh.write(f"- {rid}: {len(rs)} 条 " +
                 json.dumps([{"assoc": x.get("association_state"),
                              "reason": x.get("association_reason"),
                              "grpc": x.get("grpc")} for x in rs], ensure_ascii=False) + "\n")
    fh.write("\n## 断言\n\n")
    for n, ok_, d in results:
        fh.write(f"- [{'PASS' if ok_ else 'FAIL'}] {n}" + ("" if ok_ else f"：{d}") + "\n")
sys.exit(1 if failed else 0)
PYEOF
}

# ── 清单 ─────────────────────────────────────────────────
write_manifest() {
  python3 - "${RUN_DIR}/manifest.json" "${RUN_ID}" "${REPO_ROOT}" "${BASE_IMAGE}" <<'PYEOF'
import json, platform, subprocess, sys
out, run_id, repo_root, base = sys.argv[1:5]
def safe(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=20).stdout.strip()
    except Exception:
        return "unavailable"
doc = {
    "run_id": run_id,
    "base_image": base,
    "base_image_id": safe(["docker", "image", "inspect", base, "--format", "{{.Id}}"]),
    "envoy_version": safe(["docker", "run", "--rm", "--entrypoint", "envoy", base, "--version"]),
    "host": {"os": platform.platform(), "machine": platform.machine()},
    "git_commit": safe(["git", "-C", repo_root, "rev-parse", "HEAD"]),
    "docker_version": safe(["docker", "version", "--format", "{{.Server.Version}}"]),
    "go_version": safe(["go", "version"]),
    "s0_lock": {
        "envoy": "v1.35.3",
        "tap_output": "streaming_admin / JSON_BODY_AS_BYTES",
        "note": "streaming_admin+PROTO_BINARY_LENGTH_DELIMITED 在 v1.35.3 实测使 Envoy 崩溃（SIGTRAP），禁用二进制路径；不写 tap 文件，无需 ADR"
    },
}
with open(out, "w", encoding="utf-8") as fh:
    json.dump(doc, fh, ensure_ascii=False, indent=2, sort_keys=True)
    fh.write("\n")
PYEOF
}

# ── 主流程 ────────────────────────────────────────────────
preflight
log "run_id=${RUN_ID}"
build_and_start
write_manifest

scenario_traffic 2>&1 | tee "${EVIDENCE}/traffic.log"

# 业务连续性断言（traffic.log 中的客户端输出）
for rid in grpc-s2 grpc-s4 s9-after s10-after; do
  if grep -q "rid=${rid}" "${EVIDENCE}/traffic.log"; then
    ok "${rid} 业务客户端输出存在"
  else
    bad "${rid} 业务客户端无输出（见 traffic.log）"
  fi
done
if grep -q 'rid=grpc-s3 rpc_error code=3' "${EVIDENCE}/traffic.log"; then
  ok "grpc-s3 业务侧如实 INVALID_ARGUMENT"
else
  bad "grpc-s3 业务侧状态异常"
fi
if grep -q 'rid=grpc-s6 stream end recv=.* err_code=4' "${EVIDENCE}/traffic.log"; then
  ok "grpc-s6 业务侧 DEADLINE_EXCEEDED"
else
  bad "grpc-s6 业务侧未按预期截止"
fi
if grep -q 'rid=ws-s7 handshake_status=101' "${EVIDENCE}/traffic.log" \
   && grep -q 'rid=ws-s7 echoed="ws-frame-secret-s7"' "${EVIDENCE}/traffic.log"; then
  ok "ws-s7 握手 101 且帧 echo 成功（业务链路完整）"
else
  bad "ws-s7 业务链路异常"
fi
if grep -q 'rid=ws-s8 handshake_status=403' "${EVIDENCE}/traffic.log"; then
  ok "ws-s8 握手 403（业务侧如实）"
else
  bad "ws-s8 握手失败场景异常"
fi
down_count="$(grep -c 'rid=s10-down-.* status=200' "${EVIDENCE}/traffic.log" || true)"
if [ "${down_count}" = "3" ]; then
  ok "S10 适配器故障期间业务 3/3 200（采集故障不影响转发）"
else
  bad "S10 适配器故障影响业务（见 traffic.log）"
fi
h2_count="$(grep -c 'rid=h2-.* status=200' "${EVIDENCE}/traffic.log" || true)"
if [ "${h2_count}" = "6" ]; then
  ok "S1 业务侧 6/6 200"
else
  bad "S1 业务侧非 6/6 200（见 traffic.log）"
fi

if verify; then
  ok "记录断言全部通过（${EVIDENCE}/verify-report.md）"
else
  bad "记录断言存在 FAIL（${EVIDENCE}/verify-report.md）"
fi

ELAPSED=$(( $(date +%s) - START_TS ))
cat > "${RUN_DIR}/status.json" <<EOF
{"run_id":"${RUN_ID}","pass":${PASS_COUNT},"fail":${FAIL_COUNT},"elapsed_sec":${ELAPSED}}
EOF
echo
if [ "${FAIL_COUNT}" -eq 0 ]; then
  log "全部通过（PASS=${PASS_COUNT}，${ELAPSED}s）证据：${RUN_DIR}"
  exit 0
fi
log "存在 FAIL（PASS=${PASS_COUNT} FAIL=${FAIL_COUNT}）证据：${RUN_DIR}"
exit 1
