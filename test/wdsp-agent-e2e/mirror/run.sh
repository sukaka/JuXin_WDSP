#!/usr/bin/env bash
# P1-03 G2 真实 Nginx 取证：TLS 终止 + mirror → mirrorsrc 适配器（Unix Socket）。
#
# 场景（对应任务书 AGT-002/003/004/010/011/018 的 G2 部分）：
#   S1  GET 元数据镜像：方法/Host/路径/允许 Header 采集正确；query/Header 脱敏；
#       伪造 X-Forwarded-For 被 Nginx 覆盖且不被采信；x-wdsp-* 控制头剥离；
#       response/response_ts/latency_ms 恒 null（SOURCE_REQUEST_ONLY）
#   S2  POST JSON 正文镜像：一级字段脱敏，无明文泄漏
#   S3  源站返回 500：记录仍 response=null（镜像接收器状态/业务状态互不回填）
#   S4  大上传（8MB）：正文按上限截断、original_total_size=CL；源站收全量（业务无损）
#   S5  慢上传：业务完成，镜像记录产出
#   S6  客户端取消：适配器不崩溃，后续采集正常
#   S7  适配器故障：杀死后业务照常 200，自拉起后恢复采集
#   S8  伪造写入方：直连 socket 无/错/多令牌一律 403，不产生记录
#   S9  socket 权限与属组（0660 nginx）
#   S10 默认仅元数据路径：正文不驻留，original_total_size 照记，源站收全量
#   全局：records.jsonl 无任何合成敏感标记明文（脱敏在出主机前）
#
# 隔离铁律（仿 test/security-apm-demo/run.sh）：
#   - 每次运行唯一 run_id；容器命名 wdsp-mirror-e2e-<run_id> 并打
#     wdsp.mirror.run_id 标签；删除前双校验（名称+标签）；
#   - 禁止全局 prune，不操作任何非本 run 资源；
#   - 镜像令牌随机生成，仅存 run 目录 env（0600），运行结束删除；证据文件不回显令牌；
#   - 基础镜像 tag+digest 双锁（见 Dockerfile）。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
RUNS_ROOT="${SCRIPT_DIR}/runs"
BASE_IMAGE="nginx:1.28.0-alpine@sha256:30f1c0d78e0ad60901648be663a710bdadf19e4c10ac6782c235200619158284"
TEST_IMAGE="wdsp-mirror-e2e:g2"

RUN_ID="$(date '+%Y%m%dT%H%M%S')-$(head -c 3 /dev/urandom | od -An -tx1 | tr -d ' \n')"
RUN_DIR="${RUNS_ROOT}/${RUN_ID}"
CONTAINER="wdsp-mirror-e2e-$(printf '%s' "${RUN_ID}" | tr 'A-Z' 'a-z' | tr -d '.')"
EVIDENCE="${RUN_DIR}/evidence"
MIRROR_TOKEN="$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
PORT=""
START_TS="$(date +%s)"

PASS_COUNT=0
FAIL_COUNT=0

log()  { printf '[mirror-e2e %s] %s\n' "$(date '+%H:%M:%S')" "$*"; }
ok()   { PASS_COUNT=$((PASS_COUNT+1)); printf '  [OK]   %s\n' "$*"; }
bad()  { FAIL_COUNT=$((FAIL_COUNT+1)); printf '  [FAIL] %s\n' "$*" >&2; }

cleanup() {
  set +e
  # 双校验：名称 + run_id 标签，不触碰任何其他资源
  local owned
  owned="$(docker ps -aq --filter "name=^${CONTAINER}$" \
      --filter "label=wdsp.mirror.run_id=${RUN_ID}" 2>/dev/null)"
  if [ -n "${owned}" ]; then
    docker rm -f "${CONTAINER}" >/dev/null 2>&1
  fi
  rm -f "${RUN_DIR}/env" "${RUN_DIR}/tls/tls.key" 2>/dev/null
  log "清理完成（容器已删；证据保留于 ${RUN_DIR}）"
}
trap cleanup EXIT

die() { echo "FATAL: $*" >&2; exit 1; }

pick_free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
}

# curl_https <path> [额外 curl 参数...]：经 TLS 到本 run Nginx（Host/SNI=mirror-e2e.local）
curl_https() {
  local path="$1"; shift
  curl -ksS --resolve "mirror-e2e.local:${PORT}:127.0.0.1" "$@" \
    "https://mirror-e2e.local:${PORT}${path}"
}

# ── 预检 ─────────────────────────────────────────────────
preflight() {
  command -v docker >/dev/null || die "docker 不可用"
  docker info >/dev/null 2>&1 || die "docker daemon 不可达"
  for c in curl openssl python3 go; do
    command -v "${c}" >/dev/null || die "${c} 不可用"
  done
  [ -f "${REPO_ROOT}/wdsp-agent/go.mod" ] || die "wdsp-agent 模块缺失"
  # 镜像锁定复核：Dockerfile FROM 必须 tag+digest 双锁且与本脚本一致
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
  printf 'MIRROR_TOKEN=%s\n' "${MIRROR_TOKEN}" > "${RUN_DIR}/env"
  chmod 0600 "${RUN_DIR}/env"

  # TLS 终止证书（本 run 自签，仅容器内使用；私钥 0600，cleanup 删除）
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj "/CN=mirror-e2e.local" \
    -keyout "${RUN_DIR}/tls/tls.key" -out "${RUN_DIR}/tls/tls.crt" >/dev/null 2>&1 \
    || die "自签证书生成失败"
  chmod 0600 "${RUN_DIR}/tls/tls.key"

  # 构建 harness（目标架构随 docker daemon）
  local goarch
  case "$(docker info -f '{{.Architecture}}')" in
    aarch64) goarch=arm64 ;;
    x86_64)  goarch=amd64 ;;
    *)       die "未知 docker 架构: $(docker info -f '{{.Architecture}}')" ;;
  esac
  (cd "${REPO_ROOT}/wdsp-agent" && \
    GOOS=linux GOARCH="${goarch}" CGO_ENABLED=0 go build -o "${RUN_DIR}/mirrorharness" ./cmd/mirrorharness) \
    || die "mirrorharness 构建失败"

  # 独立构建上下文（不污染仓库树）
  local ctx="${RUN_DIR}/buildctx"
  mkdir -p "${ctx}"
  cp "${SCRIPT_DIR}/Dockerfile" "${SCRIPT_DIR}/nginx.conf" "${SCRIPT_DIR}/entrypoint.sh" "${ctx}/"
  cp "${RUN_DIR}/mirrorharness" "${ctx}/mirrorharness"
  # 令牌注入（构建上下文在 run 目录内，镜像层不含令牌——令牌经运行时 env 注入；
  # nginx.conf 中的 __MIRROR_TOKEN__ 由启动前容器内 entrypoint 不处理，
  # 改由本脚本生成渲染后的 conf 挂载——见下）
  python3 - "${ctx}/nginx.conf" "${MIRROR_TOKEN}" <<'PYEOF' || die "令牌渲染失败"
import sys
path, token = sys.argv[1], sys.argv[2]
with open(path, encoding="utf-8") as fh:
    doc = fh.read()
assert "__MIRROR_TOKEN__" in doc
with open(path, "w", encoding="utf-8") as fh:
    fh.write(doc.replace("__MIRROR_TOKEN__", token))
PYEOF

  docker build -q -t "${TEST_IMAGE}" "${ctx}" >/dev/null || die "取证镜像构建失败"
  rm -rf "${ctx}" "${RUN_DIR}/mirrorharness"   # 构建后即删（含令牌的 conf 不进镜像层之外的持久物）
  docker image inspect "${TEST_IMAGE}" --format '{{.Id}}' > "${RUN_DIR}/image-id.txt"

  PORT="$(pick_free_port)"
  docker run -d --name "${CONTAINER}" \
    --label "wdsp.mirror.run_id=${RUN_ID}" \
    -e "MIRROR_TOKEN=${MIRROR_TOKEN}" \
    -e "MIRROR_INSTANCE=nginx-e2e" \
    -v "${RUN_DIR}/tls:/etc/nginx/tls:ro" \
    -v "${EVIDENCE}:/evidence" \
    -p "127.0.0.1:${PORT}:8443" \
    "${TEST_IMAGE}" >/dev/null || die "容器启动失败"

  # 业务就绪（有界等待）
  local deadline=$(( $(date +%s) + 60 ))
  while :; do
    if [ "$(curl_https /healthz -o /dev/null -w '%{http_code}' 2>/dev/null || echo 000)" = "200" ]; then
      break
    fi
    [ "$(date +%s)" -ge "${deadline}" ] && die "栈健康等待超时"
    sleep 1
  done
  log "栈就绪：https://mirror-e2e.local:${PORT}（容器 ${CONTAINER}）"
}

# ── 场景 ─────────────────────────────────────────────────
scenario_traffic() {
  log "S1 GET 元数据镜像（伪造头覆盖检查）"
  curl_https "/get?rid=s1&token=tok-plain-s1&ok=1" -o /dev/null -w 's1 business=%{http_code}\n' \
    -H 'Authorization: Bearer plain-secret-s1' \
    -H 'Cookie: sid=plain-cookie-s1' \
    -H 'X-Forwarded-For: 9.9.9.9' \
    -H 'X-Wdsp-Mirror-Instance: forged-by-client' \
    -H 'X-Request-Id: rid-s1'

  log "S2 POST JSON 正文镜像（脱敏）"
  curl_https "/api/login?rid=s2" -o /dev/null -w 's2 business=%{http_code}\n' \
    -H 'Content-Type: application/json' \
    -d '{"user":"u","password":"plain-secret-s2"}'

  log "S3 源站 500（镜像状态互不回填）"
  curl_https "/api/fail?rid=s3" -o /dev/null -w 's3 business=%{http_code}\n' \
    -H 'X-Origin-Status: 500'

  log "S4 大上传 8MB（正文截断 + 业务无损；text/plain 在脱敏白名单内以走截断路径）"
  head -c $((8*1024*1024)) /dev/urandom > "${RUN_DIR}/upload-8m.bin"
  curl_https "/upload?rid=s4" -o /dev/null -w 's4 business=%{http_code}\n' \
    -H 'Content-Type: text/plain' \
    --data-binary @"${RUN_DIR}/upload-8m.bin"
  rm -f "${RUN_DIR}/upload-8m.bin"

  log "S5 慢上传 200KB @ 20KB/s"
  head -c $((200*1024)) /dev/urandom > "${RUN_DIR}/upload-slow.bin"
  curl_https "/upload?rid=s5" -o /dev/null -w 's5 business=%{http_code}\n' \
    -H 'Content-Type: application/octet-stream' \
    --limit-rate 20k --max-time 30 \
    --data-binary @"${RUN_DIR}/upload-slow.bin"
  rm -f "${RUN_DIR}/upload-slow.bin"

  log "S6 客户端取消（50MB 上传限速 1MB/s，2s 后中断）"
  head -c $((50*1024*1024)) /dev/zero > "${RUN_DIR}/upload-cancel.bin"
  curl_https "/upload?rid=s6" -o /dev/null -w 's6 business=%{http_code}\n' \
    -H 'Content-Type: application/octet-stream' \
    --limit-rate 1m --max-time 2 --data-binary @"${RUN_DIR}/upload-cancel.bin" || true
  rm -f "${RUN_DIR}/upload-cancel.bin"
  sleep 2
  curl_https "/get?rid=s6-after" -o /dev/null -w 's6-after business=%{http_code}\n'

  log "S7 适配器故障（杀死后业务照常；自拉起恢复采集）"
  docker exec "${CONTAINER}" pkill -f 'mirrorharness adapter' || die "杀死适配器失败"
  sleep 1  # 适配器停机窗口内
  local i
  for i in 1 2 3; do
    curl_https "/get?rid=s7-down-${i}" -o /dev/null -w "s7-down-${i} business=%{http_code}\n"
  done
  sleep 5  # 守护循环 3s 后自拉起
  curl_https "/get?rid=s7-after" -o /dev/null -w 's7-after business=%{http_code}\n'

  log "S8 伪造写入方（直连 socket：无/错/多令牌）"
  docker exec "${CONTAINER}" /usr/local/bin/mirrorharness probe \
    -socket /run/wdsp/mirror.sock > "${EVIDENCE}/probe-no-token.txt" || true
  docker exec "${CONTAINER}" /usr/local/bin/mirrorharness probe \
    -socket /run/wdsp/mirror.sock -token wrong-token > "${EVIDENCE}/probe-wrong-token.txt" || true
  docker exec "${CONTAINER}" /usr/local/bin/mirrorharness probe \
    -socket /run/wdsp/mirror.sock -token "${MIRROR_TOKEN}" -token-count 2 \
    > "${EVIDENCE}/probe-multi-token.txt" || true

  log "S9 socket 权限与属组"
  docker exec "${CONTAINER}" ls -l /run/wdsp/mirror.sock > "${EVIDENCE}/socket-perms.txt"

  log "S10 默认仅元数据路径（正文不驻留）"
  curl_https "/form?rid=s10" -o /dev/null -w 's10 business=%{http_code}\n' \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -d 'password=plain-secret-s10&ok=1'

  # Nginx 容器日志落证据（mirror 子请求故障排查原始材料）
  docker logs "${CONTAINER}" > "${EVIDENCE}/nginx.log" 2>&1 || true
}

# ── 断言 ─────────────────────────────────────────────────
verify() {
  log "断言（有界等待 records.jsonl 产出）"
  local deadline=$(( $(date +%s) + 30 ))
  while :; do
    [ -s "${EVIDENCE}/records.jsonl" ] && break
    [ "$(date +%s)" -ge "${deadline}" ] && break
    sleep 1
  done
  sleep 2  # 收尾冲刷

  python3 - "${EVIDENCE}" "${MIRROR_TOKEN}" "${REPO_ROOT}" <<'PYEOF'
import json, os, sys

evidence, token, repo_root = sys.argv[1], sys.argv[2], sys.argv[3]
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
    return [r for r in records if f"rid={rid}" in (r.get("request", {}).get("uri") or "")]

def single(rid):
    rs = find(rid)
    return rs[0] if len(rs) >= 1 else None

# S1
r = single("s1")
check("S1 记录存在", r is not None)
if r:
    req = r["request"]
    check("S1 方法/Host/路径", req.get("method") == "GET"
          and req.get("host") == "mirror-e2e.local"
          and req.get("uri", "").startswith("/get?"), json.dumps(req.get("uri")))
    check("S1 query token 脱敏", "token=********" in req.get("uri", "")
          and "tok-plain-s1" not in req.get("uri", ""), req.get("uri"))
    hdrs = req.get("headers") or {}
    check("S1 authorization/cookie 脱敏",
          hdrs.get("authorization") == ["********"] and hdrs.get("cookie") == ["********"],
          json.dumps({k: hdrs.get(k) for k in ("authorization", "cookie")}))
    check("S1 允许的普通头保留", hdrs.get("x-request-id") == ["rid-s1"])
    xff = (hdrs.get("x-forwarded-for") or [""])[0]
    check("S1 伪造 X-Forwarded-For 被 Nginx 覆盖", xff != "9.9.9.9", xff)
    check("S1 五元组不采信外部头", r.get("src_ip") not in ("9.9.9.9",), r.get("src_ip"))
    check("S1 x-wdsp-* 控制头剥离",
          not any(k.startswith("x-wdsp-") for k in hdrs), json.dumps(sorted(hdrs)))
    check("S1 单向源口径",
          r.get("response") is None and r.get("response_ts") is None
          and r.get("latency_ms") is None
          and r.get("association_state") == "REQUEST_ONLY"
          and r.get("association_reason") == "SOURCE_REQUEST_ONLY",
          f"{r.get('association_state')}/{r.get('association_reason')}")
    check("S1 来源标识", r.get("source_type") == "NGINX_MIRROR"
          and r.get("source_instance") == "nginx-e2e"
          and isinstance(r.get("source_epoch"), int) and r.get("source_epoch") > 0
          and r.get("source_capabilities_version") == "nginx-mirror/1")
    check("S1 TLS 可见性 DECRYPTED（可信终止点拓扑断言）",
          r.get("tls_visibility") == "DECRYPTED", r.get("tls_visibility"))
    check("S1 观测/原协议", r.get("observed_http_version") == "1.1"
          and r.get("original_http_version") is None,
          f"{r.get('observed_http_version')}/{r.get('original_http_version')}")
    check("S1 event_id 稳定形态", str(r.get("event_id", "")).startswith("ev-"))

# S2
r = single("s2")
check("S2 记录存在", r is not None)
if r:
    body = r["request"].get("body", "")
    check("S2 JSON 一级字段脱敏", "plain-secret-s2" not in body and "********" in body, body)

# S3：源站 500 而记录 response 恒 null
r = single("s3")
check("S3 源站 500 请求已镜像", r is not None)
if r:
    check("S3 response 仍恒 null（源站状态不回填）", r.get("response") is None
          and r.get("association_reason") == "SOURCE_REQUEST_ONLY")

# S4：8MB 上传
r = single("s4")
check("S4 记录存在", r is not None)
if r:
    bq = r["request"].get("body_quality") or {}
    check("S4 正文截断且原始总大小=CL",
          bq.get("truncated") is True
          and bq.get("original_total_size") == 8 * 1024 * 1024
          and bq.get("captured_bytes", 1 << 30) <= 4096, json.dumps(bq))

# S5
check("S5 慢上传记录存在", single("s5") is not None)

# S6：取消后适配器仍工作
check("S6 取消后采集正常", single("s6-after") is not None)

# S7：适配器故障期间业务无损，恢复后采集继续
check("S7 适配器恢复后采集正常", single("s7-after") is not None)

# S8：伪造写入方
def probe(name):
    p = os.path.join(evidence, name)
    return open(p).read().strip() if os.path.exists(p) else "missing"
check("S8 无令牌 403", probe("probe-no-token.txt") == "403", probe("probe-no-token.txt"))
check("S8 错令牌 403", probe("probe-wrong-token.txt") == "403", probe("probe-wrong-token.txt"))
check("S8 多令牌 403", probe("probe-multi-token.txt") == "403", probe("probe-multi-token.txt"))
stats = {}
sp = os.path.join(evidence, "adapter-stats.json")
if os.path.exists(sp):
    stats = json.load(open(sp))
check("S8 forbidden 计数 ≥3", stats.get("forbidden", 0) >= 3, json.dumps(stats))

# S9：socket 权限
perms = probe("socket-perms.txt")
check("S9 socket 0660 属组 nginx", perms.startswith("srw-rw----") and " nginx" in perms, perms)

# S10：默认仅元数据
r = single("s10")
check("S10 记录存在", r is not None)
if r:
    bq = r["request"].get("body_quality") or {}
    check("S10 正文不驻留且原始大小照记",
          r["request"].get("body") == ""
          and bq.get("captured_bytes") == 0
          and bq.get("original_total_size") == len("password=plain-secret-s10&ok=1"),
          json.dumps(bq))

# 全局：无明文泄漏（脱敏在出主机前；含镜像令牌本身）
for marker in ("tok-plain-s1", "plain-secret-s1", "plain-cookie-s1",
               "plain-secret-s2", "plain-secret-s10", token):
    check(f"全局 无明文泄漏 {marker[:12]}…", marker not in raw)

# 业务侧：origin 收到全量上传（8MB 与 200KB 完整到达，业务与镜像隔离）
ostats = {}
op = os.path.join(evidence, "origin-stats.json")
if os.path.exists(op):
    ostats = json.load(open(op))
check("业务 源站收全量上传（≥8MB+200KB）",
      ostats.get("upload_bytes", 0) >= 8 * 1024 * 1024 + 200 * 1024,
      json.dumps(ostats.get("upload_bytes")))

failed = [n for n, ok_, d in results if not ok_]
for n, ok_, d in results:
    print(f"  [{'OK' if ok_ else 'FAIL'}] {n}" + ("" if ok_ else f"  -- {d[:200]}"))
report = os.path.join(evidence, "verify-report.md")
with open(report, "w", encoding="utf-8") as fh:
    fh.write("# P1-03 G2 Nginx mirror 取证断言\n\n")
    fh.write(f"记录总数：{len(records)}\n\n")
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
        return subprocess.run(cmd, capture_output=True, text=True, timeout=15).stdout.strip()
    except Exception:
        return "unavailable"
doc = {
    "run_id": run_id,
    "base_image": base,
    "base_image_id": safe(["docker", "image", "inspect", base, "--format", "{{.Id}}"]),
    "nginx_version": safe(["docker", "run", "--rm", base, "nginx", "-v"]),
    "host": {"os": platform.platform(), "machine": platform.machine()},
    "git_commit": safe(["git", "-C", repo_root, "rev-parse", "HEAD"]),
    "docker_version": safe(["docker", "version", "--format", "{{.Server.Version}}"]),
    "go_version": safe(["go", "version"]),
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

# 流量（场景内业务状态码落到 evidence/traffic.log）
scenario_traffic 2>&1 | tee "${EVIDENCE}/traffic.log"

# S7 业务无损断言（故障窗口内 3 个请求全 200）
if grep -c 's7-down-.* business=200' "${EVIDENCE}/traffic.log" | grep -q '^3$'; then
  ok "S7 适配器故障期间业务 3/3 200"
else
  bad "S7 适配器故障影响业务（见 traffic.log）"
fi
for s in s1 s2 s4 s5 s6-after s7-after s10; do
  if grep -q "${s} business=200\|${s}.* business=200" "${EVIDENCE}/traffic.log" \
     && grep "${s}" "${EVIDENCE}/traffic.log" | grep -q "business=200"; then
    ok "${s} 业务 200"
  else
    case "${s}" in
      s3) : ;;  # S3 业务应为 500，下方单独断言
      *) bad "${s} 业务状态非 200（见 traffic.log）" ;;
    esac
  fi
done
if grep -q 's3 business=500' "${EVIDENCE}/traffic.log"; then
  ok "s3 业务 500（源站状态独立于镜像）"
else
  bad "s3 业务应为 500（见 traffic.log）"
fi
if grep -q 's6 business=000\|s6 business=28' "${EVIDENCE}/traffic.log" \
   || ! grep -q 's6 business=200' "${EVIDENCE}/traffic.log"; then
  ok "s6 取消按预期中断（business 非 200/连接中止）"
else
  bad "s6 取消未生效"
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
