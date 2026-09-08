#!/usr/bin/env bash
# P1-01 A1+A4 安全与 APM 标准演示 —— 场景驱动脚本（bash 3.2 兼容，macOS / Linux）
#
# 子命令：
#   preflight                       环境与静态预检（不起栈）：工具链、引用资产、镜像锁定、端口
#   startup   [--sampling MODE] [--with-product]
#                                   起独立演示栈（每次运行唯一 run_id / compose project / 数据卷）；
#                                   --with-product 叠加真实产品栈（管理 server + 网关 + 管理 PG +
#                                   Valkey，复用演示 Collector/ClickHouse 作 APM 数据面）并经真实
#                                   管理 API 完成接入（授权导入/访问日志开启/建应用/发布/traceparent
#                                   注入开启），不用 SQL 直接插库
#   traffic   [--run-id ID] [--normal-count N] [--wave NAME]
#                                   造流：正常 / 慢查询 / 异常 / 攻击（攻击需网关；
#                                   产品栈存在时自动指向本 run 网关）。wave=main（默认，A1 口径）；
#                                   wave=protect（阻断波次，含源站计数前后快照）；
#                                   wave=gwonly（仅网关观测波次）
#   verify    [--run-id ID]         证据断言：A1-01~07 + A4-01~04（管理 API 对账：
#                                   trace-search availability/correlation、安全事件、access_logs）；
#                                   无数据如实 FAIL/BLOCKED
#   mode      [--run-id ID] observe|protect
#                                   经管理 API 切换演示应用防护模式并重发布（仅 --with-product run）
#   instrumentation [--run-id ID] on|off
#                                   重建 service-a/b 开/关应用遥测（OTEL_SDK_DISABLED），
#                                   用于场景 7「仅网关观测」（仅 --with-product run）
#   cleanup   [--run-id ID]         清理本 run 资源（仅本 compose project，清理前双标签归属校验）
#
# 隔离铁律（仿 test/performance/p0/run.sh）：
#   - 每次运行唯一 run_id 与 compose project（apmdemo-<run_id>）；
#   - 停止/删除前必须同时校验 project 标签与 apmdemo.run_id 标签；
#   - 禁止全局 prune、禁止操作任何非本 project 资源（不碰共享 stage 栈）；
#   - 密码/管理凭据经本 run 环境文件注入（0600），运行结束删除；任何输出与证据文件
#     不回显密码、Token、Cookie、CSRF、授权签名私钥；
#   - A1 口径下本脚本从不调用管理面 API；--with-product 口径下的管理面操作对象仅限
#     本 run 自建的产品栈实例，不触碰任何既有部署。
#
# 已知环境约束：macOS /bin/bash 3.2 + UTF-8 locale 下 `$VAR` 后紧跟全角字符会越界
# （WORKLOG S1 记录），本脚本一律用 ${VAR} 界定。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.security-apm-demo.yml"
PRODUCT_COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.product-stack.yml"
RUNS_ROOT="${SCRIPT_DIR}/runs"
HEALTH_TIMEOUT_S=300
CH_WAIT_S=90
COLLECTOR_WAIT_S=60
API_WAIT_S=300            # 管理 server 迁移（90+ 个迁移文件）+ 启动的有界等待
VERIFY_POLL_S=45          # 单次断言的有界等待上限（不入库则 FAIL，不永久轮询）

RUN_ID=""
PROJECT=""
RUN_DIR=""
ENV_FILE=""
PORTS_FILE=""
PRODUCT_META=""           # product.env（APP_ID/APP_MODE 等非敏感元数据）
SAMPLING="keep-all"       # startup --sampling keep-all|sampled
NORMAL_COUNT=5            # traffic --normal-count
WAVE="main"               # traffic --wave main|protect|gwonly
WITH_PRODUCT=0            # startup --with-product
COMPOSE_PRODUCT=0         # 本 run 是否叠加产品栈（startup 由参数决定，其余子命令由 env 文件识别）
STACK_UP=0

log()  { printf '[apmdemo %s] %s\n' "$(date '+%H:%M:%S')" "$*"; }
die()  { echo "ERROR: $*" >&2; exit 1; }

usage() {
  cat <<'EOF'
用法: bash test/security-apm-demo/run.sh <子命令> [选项]

子命令:
  preflight    环境与静态预检（不起栈）：
               docker/compose/curl/python3、引用资产存在性、镜像 tag+digest 锁定、端口占用
  startup      起独立演示栈：--sampling keep-all（默认，正常全保留）| sampled（正常基线 0%，
               用于「显式不采样」证据）；现场生成 run_id 与全部密码（0600 env 文件）
               --with-product 叠加真实产品栈（管理 server + 网关 + 管理 PG + Valkey，
               APM 数据面指向本 run 演示 ClickHouse），并经真实管理 API 完成接入：
               授权导入（每轮随机 Ed25519 测试密钥）→ 开启全量访问日志 → 建安全管理员 →
               建应用（OBSERVE，上游=service-a）→ 配置发布 → 网关 trace_inject_upstream
               显式开启（adminpatch）→ 网关自检
  traffic      造流：--normal-count N（默认 5）；--wave main（默认，A1 全类别）|
               protect（阻断波次：网关正常×2 + 攻击×3 + 服务A计数前后快照）|
               gwonly（仅网关观测波次：网关正常×2，配合 instrumentation off 使用）。
               产品栈存在时自动指向本 run 网关；否则攻击/网关联调需运行时环境变量：
                 GATEWAY_BASE_URL  既有部署网关地址（如 http://127.0.0.1:8081）
                 GATEWAY_HOST      演示应用在网关注册的 Host（可选，按需透传）
               未提供网关时攻击/网关联调类如实记 SKIP，不伪造
  verify       证据断言（有界等待，不永久轮询）：
               A1-01~07（栈健康/Trace 层次/慢 SQL/异常/脱敏/采样决策/网关联调）
               + A4-01~04（产品栈管理 API 对账：OBSERVE 命中关联 MATCHED、PROTECT 阻断
               NOT_EXPECTED+源站计数不变、并存可区分、仅网关观测如实显示）；
               结果写 verify-report.md 与 status.json
  mode         observe|protect：经管理 API 切换演示应用防护模式并重发布+adminpatch
  instrumentation on|off：重建 service-a/b 开/关应用遥测（场景 7）
  cleanup      清理本 run 资源（双标签归属校验后 compose down -v；证据目录保留，
               含密码的 env 文件与授权私钥/Cookie 删除）

公共选项:
  --run-id ID  指定 run（traffic/verify/cleanup/mode/instrumentation；缺省取 runs/latest）
  -h, --help   本帮助

退出码: 0=全部执行项 PASS；1=存在 FAIL；2=用法/预检拒绝；3=存在 BLOCKED/SKIP（未完成项）。
EOF
}

gen_run_id() {
  local rand
  rand="$(head -c 3 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  printf '%s-%s' "$(date '+%Y%m%dT%H%M%S')" "${rand}"
}

compose_cmd() {
  if [ "${COMPOSE_PRODUCT}" = "1" ]; then
    docker compose -p "${PROJECT}" -f "${COMPOSE_FILE}" -f "${PRODUCT_COMPOSE_FILE}" \
      --env-file "${ENV_FILE}" "$@"
  else
    docker compose -p "${PROJECT}" -f "${COMPOSE_FILE}" --env-file "${ENV_FILE}" "$@"
  fi
}

# ---------- 归属与隔离 ----------
assert_project_absent() {
  if docker ps -a --filter "label=com.docker.compose.project=${PROJECT}" -q | grep -q .; then
    die "compose project ${PROJECT} 已存在（run_id 冲突），拒绝复用"
  fi
}

assert_ownership() { # 成功返回 0；失败打印原因并返回 1（由调用方决定 die 或降级）
  # 容器：仅取名称+标签（不输出完整 inspect）。
  # 注意分隔符差异：docker ps --format '{{.Labels}}' 输出 k=v 逗号串；
  # docker volume inspect -f '{{.Labels}}' 输出 Go map 形态 map[k:v ...]，两种都认。
  docker ps -a --filter "label=com.docker.compose.project=${PROJECT}" \
      --format '{{.Names}}\t{{.Labels}}' \
    | python3 -c '
import sys
run_id = sys.argv[1]
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    name, _, labels = line.partition("\t")
    if f"apmdemo.run_id={run_id}" not in labels and f"apmdemo.run_id:{run_id}" not in labels:
        print(f"NOT_OWNED container: {name}", file=sys.stderr)
        sys.exit(1)
' "${RUN_ID}" >/dev/null \
    || { echo "归属校验失败：${PROJECT} 存在不属于本 run_id 的容器，禁止操作" >&2; return 1; }
  # 卷：逐个取标签行（仅 .Labels）
  local vol
  while read -r vol; do
    [ -z "${vol}" ] && continue
    printf '%s\t%s\n' "${vol}" "$(docker volume inspect -f '{{.Labels}}' "${vol}")"
  done < <(docker volume ls --filter "label=com.docker.compose.project=${PROJECT}" --format '{{.Name}}') \
    | python3 -c '
import sys
run_id = sys.argv[1]
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    name = line.split("\t", 1)[0]
    if f"apmdemo.run_id={run_id}" not in line and f"apmdemo.run_id:{run_id}" not in line:
        print(f"NOT_OWNED volume: {name}", file=sys.stderr)
        sys.exit(1)
' "${RUN_ID}" \
    || { echo "归属校验失败：${PROJECT} 存在不属于本 run_id 的卷，禁止操作" >&2; return 1; }
  return 0
}

# ---------- run 生命周期 ----------
pick_free_port() { # 从内核借一个回环空闲端口（释放后使用；本地演示可接受的竞态窗口）
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
}

new_run() {
  RUN_ID="$(gen_run_id)"
  # compose project 名只允许小写（run_id 含大写 T 分隔符，证据目录沿用原样）
  PROJECT="apmdemo-$(printf '%s' "${RUN_ID}" | tr 'A-Z' 'a-z')"
  RUN_DIR="${RUNS_ROOT}/${RUN_ID}"
  PORTS_FILE="${RUN_DIR}/ports.env"
  PRODUCT_META="${RUN_DIR}/product.env"
  mkdir -p "${RUN_DIR}"
  ENV_FILE="${RUN_DIR}/env"
  local rand_db rand_ch rand_wr
  rand_db="$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  rand_ch="$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  rand_wr="$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  umask 077
  cat > "${ENV_FILE}" <<EOF
DEMO_RUN_ID=${RUN_ID}
DEMO_DB_PASSWORD=${rand_db}
DEMO_CH_ADMIN_USER=default
DEMO_CH_ADMIN_PASSWORD=${rand_ch}
DEMO_CH_WRITER_USER=apm_writer
DEMO_CH_WRITER_PASSWORD=${rand_wr}
DEMO_COLLECTOR_CONFIG=demo-${SAMPLING}.yaml
EOF
  if [ "${WITH_PRODUCT}" = "1" ]; then
    gen_product_secrets
  fi
  # 端口分配：Docker Desktop（compose v2.38 实测）对 "127.0.0.1::<port>" 空宿主端口
  # 不会分配随机端口而是不发布（:0），故由本脚本显式分配——用户已设置的
  # DEMO_*_PORT（shell 环境，preflight 已校验占用）优先，缺省自动取回环空闲端口。
  local var p
  for var in DEMO_SERVICE_A_PORT DEMO_SERVICE_B_PORT DEMO_DB_PORT DEMO_CH_HTTP_PORT \
             DEMO_COLLECTOR_METRICS_PORT DEMO_COLLECTOR_HEALTH_PORT; do
    p="${!var:-}"
    [ -z "${p}" ] && p="$(pick_free_port)"
    printf '%s=%s\n' "${var}" "${p}" >> "${ENV_FILE}"
  done
  if [ "${WITH_PRODUCT}" = "1" ]; then
    for var in DEMO_API_PORT DEMO_GATEWAY_PORT; do
      p="${!var:-}"
      [ -z "${p}" ] && p="$(pick_free_port)"
      printf '%s=%s\n' "${var}" "${p}" >> "${ENV_FILE}"
    done
  fi
  chmod 0600 "${ENV_FILE}"
  printf '%s\n' "${RUN_ID}" > "${RUNS_ROOT}/latest"
  log "run_id=${RUN_ID} project=${PROJECT} run_dir=${RUN_DIR} sampling=${SAMPLING} with_product=${WITH_PRODUCT}"
}

# gen_product_secrets 生成产品栈全部运行时凭据（管理 PG/Valkey/master key/初始管理员/安全
# 管理员口令 + 每轮随机 Ed25519 授权验签密钥对）。私钥与 env 均 0600，cleanup 删除；
# 公钥经 env 注入 api 容器（wdsp_testkeys 测试构建才读取，同 test-license 口径）。
gen_product_secrets() {
  COMPOSE_PRODUCT=1
  local rand_pg rand_vk rand_mk rand_adm rand_adm2 rand_sec
  rand_pg="$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  rand_vk="$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  rand_mk="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  # 口令复杂度：大小写+数字+特殊字符（与 ci-edition-smoke 同形态）
  rand_adm="Dm$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')1!"
  rand_adm2="Dm$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')2!"
  rand_sec="DmSec@$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')1"
  cat >> "${ENV_FILE}" <<EOF
DEMO_PRODUCT_STACK=1
DEMO_MGMT_PG_PASSWORD=${rand_pg}
DEMO_MGMT_VALKEY_PASSWORD=${rand_vk}
DEMO_MGMT_MASTER_KEY=${rand_mk}
DEMO_ADMIN_USER=jiuzhang_admin
DEMO_ADMIN_PASSWORD=${rand_adm}
DEMO_ADMIN_PASSWORD2=${rand_adm2}
DEMO_SEC_USER=sec_admin_apmdemo
DEMO_SEC_PASSWORD=${rand_sec}
EOF
  # 授权验签密钥对（Ed25519；私钥只用于 startup 现场签发 .lic，cleanup 删除）
  openssl genpkey -algorithm ed25519 -out "${RUN_DIR}/lic-key.pem" >/dev/null 2>&1 \
    || die "openssl 生成授权密钥失败"
  chmod 0600 "${RUN_DIR}/lic-key.pem"
  local pub_hex
  pub_hex="$(openssl pkey -in "${RUN_DIR}/lic-key.pem" -pubout -outform DER 2>/dev/null \
    | tail -c 32 | python3 -c 'import sys; print(sys.stdin.buffer.read().hex())')" \
    || die "导出授权公钥失败"
  printf 'LICENSE_VENDOR_PUBLIC_KEY=apmdemo-key:%s\n' "${pub_hex}" >> "${ENV_FILE}"
}

resolve_run() {
  if [ -z "${RUN_ID}" ]; then
    [ -f "${RUNS_ROOT}/latest" ] || die "未指定 --run-id 且无最近运行记录（runs/latest）"
    RUN_ID="$(tr -d ' \n' < "${RUNS_ROOT}/latest")"
  fi
  case "${RUN_ID}" in
    *[!A-Za-z0-9-]*|"") die "非法 run_id 形态: ${RUN_ID}" ;;
  esac
  PROJECT="apmdemo-$(printf '%s' "${RUN_ID}" | tr 'A-Z' 'a-z')"
  RUN_DIR="${RUNS_ROOT}/${RUN_ID}"
  ENV_FILE="${RUN_DIR}/env"
  PORTS_FILE="${RUN_DIR}/ports.env"
  PRODUCT_META="${RUN_DIR}/product.env"
  [ -d "${RUN_DIR}" ] || die "run 目录不存在: ${RUN_DIR}"
}

load_env() { # 读取本 run 的密码（0600 env 文件；值为本脚本生成的 hex，来源可信）
  [ -f "${ENV_FILE}" ] || die "env 文件缺失: ${ENV_FILE}（已 cleanup？密码文件运行结束即删）"
  set -a
  # shellcheck disable=SC1090
  . "${ENV_FILE}"
  set +a
  [ "${DEMO_PRODUCT_STACK:-0}" = "1" ] && COMPOSE_PRODUCT=1
}

load_ports() {
  [ -f "${PORTS_FILE}" ] || die "端口记录缺失: ${PORTS_FILE}（先运行 startup）"
  set -a
  # shellcheck disable=SC1090
  . "${PORTS_FILE}"
  set +a
}

write_manifest() {
  python3 - "${RUN_DIR}/manifest.json" "${RUN_ID}" "${PROJECT}" "${REPO_ROOT}" "${SAMPLING}" <<'PYEOF'
import json, platform, subprocess, sys
out, run_id, project, repo_root, sampling = sys.argv[1:6]
def safe(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=15).stdout.strip()
    except Exception:
        return "unavailable"
doc = {
    "run_id": run_id,
    "compose_project": project,
    "sampling_profile": sampling,
    "host": {"os": platform.platform(), "machine": platform.machine()},
    "git_commit": safe(["git", "-C", repo_root, "rev-parse", "HEAD"]),
    "docker_version": safe(["docker", "version", "--format", "{{.Server.Version}}"]),
    "compose_version": safe(["docker", "compose", "version", "--short"]),
    "go_version": safe(["go", "version"]),
}
with open(out, "w", encoding="utf-8") as fh:
    json.dump(doc, fh, ensure_ascii=False, indent=2, sort_keys=True)
    fh.write("\n")
PYEOF
}

write_ports() {
  local svc port_var addr
  : > "${PORTS_FILE}"
  for spec in "service-a 8080 SERVICE_A_ADDR" "service-b 8080 SERVICE_B_ADDR" \
              "db 5432 DB_ADDR" "clickhouse 8123 CH_HTTP_ADDR" \
              "collector 8888 COLLECTOR_METRICS_ADDR" "collector 13133 COLLECTOR_HEALTH_ADDR"; do
    set -- ${spec}
    addr="$(compose_cmd port "$1" "$2" 2>/dev/null | head -1)" \
      || die "无法取得 $1 的发布端口"
    [ -n "${addr}" ] || die "服务 $1 无发布端口（${spec}）"
    printf '%s=%s\n' "$3" "${addr}" >> "${PORTS_FILE}"
  done
  if [ "${COMPOSE_PRODUCT}" = "1" ]; then
    # 产品服务可能在 write_ports 首调（业务栈就绪时）尚未启动；仅记录已启动者，
    # 产品栈端口由 product_stack_up 在 api/gateway 就绪后再次调用本函数补齐
    for spec in "api 8080 API_ADDR" "gateway 8080 GATEWAY_ADDR"; do
      set -- ${spec}
      [ -n "$(compose_cmd ps -q "$1" 2>/dev/null | head -1)" ] || continue
      addr="$(compose_cmd port "$1" "$2" 2>/dev/null | head -1)" \
        || die "无法取得 $1 的发布端口"
      [ -n "${addr}" ] || die "服务 $1 无发布端口（${spec}）"
      printf '%s=%s\n' "$3" "${addr}" >> "${PORTS_FILE}"
    done
  fi
  chmod 0644 "${PORTS_FILE}"
  log "端口已记录: ${PORTS_FILE}"
}

# ---------- 预检 ----------
preflight_checks() {
  log "预检开始"
  command -v docker >/dev/null || die "docker 不可用"
  docker compose version >/dev/null 2>&1 || die "docker compose v2 不可用"
  command -v curl >/dev/null || die "curl 不可用"
  command -v python3 >/dev/null || die "python3 不可用"
  docker info >/dev/null 2>&1 || die "docker daemon 不可达"

  # 引用资产存在性（引用而非复制的纪律：缺失即拒绝，不静默复制）
  local f
  for f in \
    "${REPO_ROOT}/deployment/docker-compose.apm.yml" \
    "${REPO_ROOT}/deployment/apm/clickhouse/001_otel_traces.sql" \
    "${REPO_ROOT}/deployment/apm/clickhouse/002_aggregates.sql" \
    "${REPO_ROOT}/deployment/apm/clickhouse/003_metrics.sql" \
    "${REPO_ROOT}/deployment/apm/collector/central-gateway.yaml" \
    "${SCRIPT_DIR}/collector/demo-keep-all.yaml" \
    "${SCRIPT_DIR}/collector/demo-sampled.yaml" \
    "${SCRIPT_DIR}/db-init/001_demo_schema.sql"; do
    [ -f "${f}" ] || die "引用资产缺失: ${f}"
  done
  log "引用资产齐备（deployment/apm 镜像与 schema、collector 双配置、db-init）"

  # 产品栈叠加编排（A4）：引用资产与镜像锁定同样复核（不作为既有部署的副本，
  # 服务组成口径复刻 deployment/docker-compose.stage5.yml，见文件头注释）
  for f in \
    "${PRODUCT_COMPOSE_FILE}" \
    "${REPO_ROOT}/server/Dockerfile" \
    "${REPO_ROOT}/gateway/Dockerfile" \
    "${REPO_ROOT}/gateway/configs/Caddyfile" \
    "${REPO_ROOT}/gateway/configs/blockpage.html" \
    "${REPO_ROOT}/gateway/rules/coraza.conf" \
    "${REPO_ROOT}/THIRD_PARTY_NOTICES.md" \
    "${SCRIPT_DIR}/services/cmd/adminpatch/main.go"; do
    [ -f "${f}" ] || die "产品栈引用资产缺失: ${f}"
  done
  command -v openssl >/dev/null || die "openssl 不可用（--with-product 授权密钥生成需要）"

  # 镜像锁定复核：本编排内全部第三方镜像必须 tag+digest 双锁；禁止 latest/裸 tag
  python3 - "${COMPOSE_FILE}" "${PRODUCT_COMPOSE_FILE}" "${SCRIPT_DIR}/services/Dockerfile" <<'PYEOF' \
    || die "镜像锁定复核失败（禁止 latest 或未锁 digest 的镜像）"
import re, sys
bad = []
for path in sys.argv[1:3]:
    compose = open(path, encoding="utf-8").read()
    for m in re.finditer(r'^\s*image:\s*(\S+)\s*$', compose, re.M):
        ref = m.group(1)
        if ref.startswith("jiuzhang-apmdemo-"):   # 本地构建产物（固定 tag，非 latest）
            continue
        if "@sha256:" not in ref or ":latest" in ref:
            bad.append(f"{path}: {ref}")
df = open(sys.argv[3], encoding="utf-8").read()
for m in re.finditer(r'^FROM\s+(?:--platform=\S+\s+)?(\S+)', df, re.M):
    ref = m.group(1)
    if ref == "builder":
        continue
    # FROM 引用 ARG digest 的锁定形态：name:tag${ARG:+@$ARG}
    if "${" in ref:
        continue
    if "@sha256:" not in ref or ":latest" in ref:
        bad.append(ref)
if bad:
    for ref in bad:
        print(f"UNLOCKED image: {ref}", file=sys.stderr)
    sys.exit(1)
PYEOF

  # 显式端口占用检查（缺省为随机端口无冲突面）
  local var port
  for var in DEMO_SERVICE_A_PORT DEMO_SERVICE_B_PORT DEMO_DB_PORT DEMO_CH_HTTP_PORT \
             DEMO_COLLECTOR_METRICS_PORT DEMO_COLLECTOR_HEALTH_PORT \
             DEMO_API_PORT DEMO_GATEWAY_PORT; do
    port="${!var:-}"
    [ -z "${port}" ] && continue
    if ! python3 -c '
import socket, sys
s = socket.socket()
try:
    s.bind(("127.0.0.1", int(sys.argv[1])))
except OSError:
    sys.exit(1)
finally:
    s.close()
' "${port}"; then
      die "端口 ${port}（${var}）已被占用，停止"
    fi
  done

  # Go 工具链（静态构建验证用；起栈构建在容器内进行，不强制本机 Go）
  if command -v go >/dev/null; then
    log "go: $(go version)"
  else
    log "WARN: 本机无 go 工具链（跳过 go build/vet 自检；容器内构建不受影响）"
  fi

  # compose 静态校验（不 up 栈）
  docker compose -f "${COMPOSE_FILE}" config --quiet >/dev/null \
    || die "compose 文件静态校验失败"
  docker compose -f "${COMPOSE_FILE}" -f "${PRODUCT_COMPOSE_FILE}" config --quiet >/dev/null \
    || die "产品栈叠加 compose 静态校验失败"
  log "预检通过"
}

# ---------- 栈生命周期 ----------
wait_services_healthy() { # $1 = 等待的服务列表（空格分隔）
  local deadline bad
  deadline=$(( $(date +%s) + HEALTH_TIMEOUT_S ))
  while :; do
    bad="$(compose_cmd ps --format json 2>/dev/null | python3 -c '
import json, sys
bad = 0
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        row = json.loads(line)
    except json.JSONDecodeError:
        continue
    st = (row.get("Health") or row.get("State") or "").lower()
    if st not in ("healthy", "running"):
        bad += 1
print(bad)' 2>/dev/null || echo 99)"
    [ "${bad}" = "0" ] && break
    [ "$(date +%s)" -ge "${deadline}" ] && return 1
    sleep 3
  done
  return 0
}

ch_admin_query() { # $1 = SQL（admin 账号；密码只经 HTTP 头，不回显日志）
  curl -sS -m 15 "http://${CH_HTTP_ADDR}/" \
    -H "X-ClickHouse-User: ${DEMO_CH_ADMIN_USER}" \
    -H "X-ClickHouse-Key: ${DEMO_CH_ADMIN_PASSWORD}" \
    --data-binary "$1"
}

create_ch_writer() {
  # 等 schema 初始化完成（initdb 在首启执行 001/002/003）再建最小权限写入账号
  local deadline
  deadline=$(( $(date +%s) + CH_WAIT_S ))
  while :; do
    if [ "$(ch_admin_query "SELECT count() FROM system.tables WHERE database='apm' AND name='otel_traces'" 2>/dev/null | tr -d ' \n')" = "1" ]; then
      break
    fi
    [ "$(date +%s)" -ge "${deadline}" ] && startup_die "ClickHouse schema 初始化等待超时（${CH_WAIT_S}s）"
    sleep 2
  done
  ch_admin_query "CREATE USER IF NOT EXISTS ${DEMO_CH_WRITER_USER} IDENTIFIED WITH sha256_password BY '${DEMO_CH_WRITER_PASSWORD}'" >/dev/null \
    || startup_die "创建 apm_writer 账号失败"
  # 向带物化视图的基表 INSERT 时，CH 以插入者身份对 MV 源表执行 SELECT（INVOKER 语义，
  # 实测 clickhouse 25.8：缺 SELECT 授权时基表插入成功但 MV 推送报 code 497，exporter
  # 重试造成基表重复行后丢数据）。MV 链为两级级联：otel_traces → 分钟表 → 小时/天表
  # （002_aggregates.sql），中间表均为下游 MV 的源表，故按库级 SELECT 授权（独立实例、
  # 随机密码、用完即毁，授权面可控）；schema 新增级联层时无需改此处。
  ch_admin_query "GRANT INSERT ON apm.otel_traces TO ${DEMO_CH_WRITER_USER}" >/dev/null \
    || startup_die "apm_writer INSERT 授权失败"
  ch_admin_query "GRANT SELECT ON apm.* TO ${DEMO_CH_WRITER_USER}" >/dev/null \
    || startup_die "apm_writer 库级 SELECT 授权失败"
  log "ClickHouse schema 就绪，apm_writer（INSERT otel_traces + SELECT apm.*）已创建"
}

# startup_die 启动失败专用：清理本 run 半成品资源（归属校验后仅本 project），
# 删除含密码 env 文件；不触碰任何既有部署资源（本脚本从不调用管理面 API）。
startup_die() {
  echo "ERROR: $*" >&2
  if [ "${STACK_UP}" = "1" ] && [ -n "${PROJECT}" ] && [ -n "${ENV_FILE}" ] && [ -f "${ENV_FILE}" ]; then
    if assert_ownership; then
      log "启动失败回扫：仅清理 project=${PROJECT}（归属已校验）"
      compose_cmd down -v --remove-orphans >/dev/null 2>&1 || true
    else
      log "WARN: 启动失败回扫时归属校验未过，跳过清理；请人工核查 project=${PROJECT}"
    fi
  fi
  [ -n "${ENV_FILE}" ] && rm -f "${ENV_FILE}"
  exit 1
}

stack_up() {
  new_run
  write_manifest
  assert_project_absent
  log "构建演示业务镜像（固定 tag jiuzhang-apmdemo-service-{a,b}:a1，锁定基础镜像 digest）"
  compose_cmd build --quiet >/dev/null || startup_die "镜像构建失败（栈未启动，既有部署不受影响）"
  log "启动 db + clickhouse"
  compose_cmd up -d db clickhouse >/dev/null || startup_die "db/clickhouse 启动失败"
  STACK_UP=1
  wait_services_healthy || startup_die "db/clickhouse 健康等待超时（${HEALTH_TIMEOUT_S}s）"
  # CH 发布端口需在建号前解析（up 后即固定）
  local ch_addr
  ch_addr="$(compose_cmd port clickhouse 8123 2>/dev/null | head -1)" || startup_die "无法取得 ClickHouse 端口"
  [ -n "${ch_addr}" ] || startup_die "ClickHouse 无发布端口"
  set -a; . "${ENV_FILE}"; set +a
  CH_HTTP_ADDR="${ch_addr}"
  create_ch_writer
  log "启动 collector（配置 $(grep '^DEMO_COLLECTOR_CONFIG=' "${ENV_FILE}" | cut -d= -f2)）"
  compose_cmd up -d collector >/dev/null || startup_die "collector 启动失败"
  local deadline health_addr
  health_addr="$(compose_cmd port collector 13133 2>/dev/null | head -1 || true)"
  [ -n "${health_addr}" ] || startup_die "collector 无健康端口发布"
  deadline=$(( $(date +%s) + COLLECTOR_WAIT_S ))
  while :; do
    if curl -sS -m 3 "http://${health_addr}/" >/dev/null 2>&1; then
      break
    fi
    [ "$(date +%s)" -ge "${deadline}" ] && startup_die "collector 健康等待超时（${COLLECTOR_WAIT_S}s）"
    sleep 2
  done
  log "启动 service-b + service-a"
  if [ "${COMPOSE_PRODUCT}" = "1" ]; then
    compose_cmd up -d service-b service-a >/dev/null || startup_die "业务服务启动失败"
  else
    compose_cmd up -d >/dev/null || startup_die "业务服务启动失败"
  fi
  wait_services_healthy || startup_die "业务服务健康等待超时（${HEALTH_TIMEOUT_S}s）"
  write_ports
  load_ports
  # 起栈自检：直连服务 A 健康端点（不经过网关，不触碰既有部署）
  local code
  code="$(curl -sS -m 5 -o /dev/null -w '%{http_code}' "http://${SERVICE_A_ADDR}/healthz")" \
    || startup_die "服务 A 健康自检失败"
  [ "${code}" = "200" ] || startup_die "服务 A /healthz 返回 ${code}"
  # 写入通路 canary：一条慢场景请求（trace 时长>2s，两种采样形态下均被 slow-keep-all
  # 保留），有界等待其入库且 exporter 零失败重试——实测 clickhouse 25.8 下 MV 级联
  # 以插入者身份读源表（INVOKER），授权缺失表现为"基表插入成功+MV 推送 497+重试叠加
  # 重复行"，必须在 startup 阶段 fail-fast，不能留到 verify 才显形。
  local canary_tid
  canary_tid="$(curl -sS -m 30 -o /dev/null -D - \
      -H 'X-Demo-Scenario: slow-sql' \
      "http://${SERVICE_A_ADDR}/demo/order?id=1" 2>/dev/null \
    | grep -i '^X-Demo-Trace-Id:' | tr -d '\r' | awk '{print $2}' || true)"
  [ -n "${canary_tid}" ] || startup_die "写入通路 canary 请求失败（无 trace 响应头）"
  local canary_deadline xfail canary_in
  canary_deadline=$(( $(date +%s) + 60 ))
  while :; do
    xfail="$(curl -sS -m 5 "http://${COLLECTOR_METRICS_ADDR}/metrics" 2>/dev/null \
      | grep '^otelcol_exporter_send_failed_spans' | awk '{s+=$NF} END {print s+0}' || true)"
    [ "${xfail:-0}" -gt 0 ] 2>/dev/null \
      && startup_die "写入通路故障：exporter send_failed_spans=${xfail}（疑 CH 授权/连通性，查 collector 日志）"
    canary_in="$(ch_select "SELECT count() FROM apm.otel_traces WHERE TraceId='${canary_tid}'" 2>/dev/null | tr -d ' \n')"
    case "${canary_in}" in ''|*[!0-9]*) canary_in=0 ;; esac
    [ "${canary_in}" -ge 1 ] && break
    [ "$(date +%s)" -ge "${canary_deadline}" ] \
      && startup_die "写入通路 canary 60s 未入库（trace=${canary_tid}；查 collector 日志）"
    sleep 3
  done
  log "写入通路自检通过（canary trace=${canary_tid} 已入库，exporter 零失败重试）"
  if [ "${COMPOSE_PRODUCT}" = "1" ]; then
    product_stack_up
  fi
  log "演示栈就绪。服务 A（直连）: http://${SERVICE_A_ADDR}/demo/order?id=1"
  if [ "${COMPOSE_PRODUCT}" = "1" ]; then
    log "产品栈就绪。管理 API: http://${API_ADDR}  网关: http://${GATEWAY_ADDR}（Host: ${DEMO_GW_HOSTNAME}）"
  fi
  log "下一步：bash ${SCRIPT_DIR}/run.sh traffic --run-id ${RUN_ID}"
}

# ---------- 产品栈（A4：--with-product） ----------
# 以下函数只操作本 run 自建的产品栈容器，全部管理面操作走真实 HTTP 管理 API
# （不直连数据库插值）。会话 Cookie/CSRF 为运行时凭据：仅存 run 目录 0600 文件，
# 不写入任何证据文件，cleanup 删除。

product_stack_up() {
  log "启动产品栈：mgmt-postgres + mgmt-valkey"
  compose_cmd up -d mgmt-postgres mgmt-valkey >/dev/null || startup_die "管理 PG/Valkey 启动失败"
  log "启动产品栈：gateway + api（api 首启执行全部迁移，等待上限 ${API_WAIT_S}s）"
  compose_cmd up -d gateway api >/dev/null || startup_die "gateway/api 启动失败"
  wait_services_healthy || startup_die "产品栈健康等待超时（${HEALTH_TIMEOUT_S}s）"
  write_ports
  load_ports
  # 管理 API 健康有界等待（健康检查有 start_period，容器 healthy 前 8080 可能已可答）
  local deadline code
  deadline=$(( $(date +%s) + API_WAIT_S ))
  while :; do
    code="$(curl -sS -m 5 -o /dev/null -w '%{http_code}' "http://${API_ADDR}/api/v1/health" 2>/dev/null || echo 000)"
    [ "${code}" = "200" ] && break
    [ "$(date +%s)" -ge "${deadline}" ] && startup_die "管理 API 健康等待超时（${API_WAIT_S}s，last=${code}）"
    sleep 5
  done
  log "管理 API 健康（http://${API_ADDR}）"
  product_onboard
}

# product_onboard 真实管理 API 接入序列：授权导入 → 全量访问日志开启 → 安全管理员 →
# 建应用（OBSERVE）→ 发布 → adminpatch → 网关自检。任何一步失败即启动失败回滚。
product_onboard() {
  # 1) 系统管理员登录（验证码从本 run Valkey 读取；首登强制改密）
  local sys_csrf
  sys_csrf="$(api_login "${DEMO_ADMIN_USER}" "${DEMO_ADMIN_PASSWORD}")" \
    || startup_die "系统管理员登录失败"
  local must
  must="$(api_get "${DEMO_ADMIN_USER}" "/api/v1/auth/me" | python3 -c \
    'import json,sys; print(json.load(sys.stdin)["data"].get("user",{}).get("must_change_password", False))' 2>/dev/null || echo False)"
  if [ "${must}" = "True" ]; then
    sys_csrf="$(api_login "${DEMO_ADMIN_USER}" "${DEMO_ADMIN_PASSWORD}")" || startup_die "系统管理员重登录失败"
    api_post_expect "${DEMO_ADMIN_USER}" "${sys_csrf}" "/api/v1/auth/change-password" \
      "{\"old_password\":\"${DEMO_ADMIN_PASSWORD}\",\"new_password\":\"${DEMO_ADMIN_PASSWORD2}\"}" 200 \
      || startup_die "初始管理员强制改密失败"
    sys_csrf="$(api_login "${DEMO_ADMIN_USER}" "${DEMO_ADMIN_PASSWORD2}")" || startup_die "改密后登录失败"
  fi
  log "系统管理员登录完成"

  # 2) 签发并导入本 run 临时 wdsp 授权（.lic 语义与 ci-edition-smoke 一致：
  #    payload 键字典序紧凑 JSON → Ed25519 签名；永久、不限额、不绑指纹）
  python3 - "${RUN_DIR}" <<'PYEOF' || startup_die "签发授权 payload 失败"
import datetime, json, sys
payload = {
    "license_id": "LIC-APMDEMO-0001",
    "license_type": "FORMAL",
    "product": "wdsp",
    "customer": "APM Demo",
    "issued_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "expires_at": None,
    "perpetual": True,
    "machine_fingerprint": None,
    "quotas": {"max_applications": 0, "max_api_endpoints": 0, "max_qps": 0},
    "features": ["api", "waf"],
    "version": 1,
    "key_id": "apmdemo-key",
}
canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
with open(sys.argv[1] + "/lic-payload.bin", "w") as fh:
    fh.write(canonical)
PYEOF
  chmod 0600 "${RUN_DIR}/lic-payload.bin"
  openssl pkeyutl -sign -rawin -inkey "${RUN_DIR}/lic-key.pem" \
    -in "${RUN_DIR}/lic-payload.bin" -out "${RUN_DIR}/lic-sig.bin" 2>/dev/null \
    || startup_die "授权签名失败"
  python3 - "${RUN_DIR}" <<'PYEOF' || startup_die "组装 .lic 失败"
import json, sys
with open(sys.argv[1] + "/lic-payload.bin") as fh:
    payload = json.load(fh)
with open(sys.argv[1] + "/lic-sig.bin", "rb") as fh:
    sig = fh.read().hex()
with open(sys.argv[1] + "/license.lic", "w") as fh:
    json.dump({"payload": payload, "signature": sig}, fh)
PYEOF
  chmod 0600 "${RUN_DIR}/license.lic"
  local lic_body
  lic_body="$(python3 -c 'import json,sys; print(json.dumps({"file_content": open(sys.argv[1]).read()}))' "${RUN_DIR}/license.lic")"
  api_post_expect "${DEMO_ADMIN_USER}" "${sys_csrf}" "/api/v1/license/import" "${lic_body}" 200 \
    || startup_die "导入临时授权失败"
  rm -f "${RUN_DIR}/lic-payload.bin" "${RUN_DIR}/lic-sig.bin"
  local edition_ok
  edition_ok="$(api_get "${DEMO_ADMIN_USER}" "/api/v1/product/edition" | python3 -c '
import json,sys
d=json.load(sys.stdin)["data"]
print("OK" if d.get("edition")=="wdsp" and d.get("license_valid") is True else "BAD")' 2>/dev/null || echo BAD)"
  [ "${edition_ok}" = "OK" ] || startup_die "授权导入后 product/edition 校验失败（${edition_ok}）"
  log "临时 wdsp 授权已导入并生效"

  # 3) 开启全量访问日志（request_id → trace_id 关联链的 PG 证据来源）
  enable_access_log_setting "${sys_csrf}"

  # 4) 安全管理员用户（临时口令登录后改为本 run 随机口令）
  local tmp_pwd sec_csrf
  tmp_pwd="$(api_post "${DEMO_ADMIN_USER}" "${sys_csrf}" "/api/v1/users" \
    "{\"username\":\"${DEMO_SEC_USER}\",\"display_name\":\"安全管理员APM演示\",\"role_code\":\"SECURITY_ADMIN\"}" \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("data",{}).get("temporary_password","") if d.get("code")=="SUCCESS" else "")' 2>/dev/null)"
  [ -n "${tmp_pwd}" ] || startup_die "创建安全管理员失败"
  sec_csrf="$(api_login "${DEMO_SEC_USER}" "${tmp_pwd}")" || startup_die "安全管理员首登失败"
  api_post_expect "${DEMO_SEC_USER}" "${sec_csrf}" "/api/v1/auth/change-password" \
    "{\"old_password\":\"${tmp_pwd}\",\"new_password\":\"${DEMO_SEC_PASSWORD}\"}" 200 \
    || startup_die "安全管理员改密失败"
  sec_csrf="$(api_login "${DEMO_SEC_USER}" "${DEMO_SEC_PASSWORD}")" || startup_die "安全管理员改密后登录失败"
  log "安全管理员就绪（${DEMO_SEC_USER}）"

  # 5) 建演示应用（OBSERVE）+ 域名 + 上游（service-a，compose 内网）+ 启用
  DEMO_GW_HOSTNAME="apmdemo-$(printf '%s' "${RUN_ID}" | tr 'A-Z' 'a-z').test"
  local app_code="apmdemo$(printf '%s' "${RUN_ID}" | tail -c 7 | tr -d '-')"
  local app_id
  app_id="$(api_post "${DEMO_SEC_USER}" "${sec_csrf}" "/api/v1/applications" \
    "{\"code\":\"${app_code}\",\"name\":\"APM演示应用-${RUN_ID}\",\"description\":\"P1-01 A4 网关联动演示\",\"business_owner\":\"demo\",\"technical_owner\":\"demo\",\"protection_mode\":\"OBSERVE\"}" \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("data",{}).get("id","") if d.get("code")=="SUCCESS" else "")' 2>/dev/null)"
  [ -n "${app_id}" ] || startup_die "创建演示应用失败"
  api_post_expect "${DEMO_SEC_USER}" "${sec_csrf}" "/api/v1/applications/${app_id}/domains" \
    "{\"hostname\":\"${DEMO_GW_HOSTNAME}\",\"is_primary\":true,\"http_enabled\":true,\"https_enabled\":false,\"http_port\":8080,\"redirect_http_to_https\":false}" 200 \
    || startup_die "应用域名配置失败"
  api_post_expect "${DEMO_SEC_USER}" "${sec_csrf}" "/api/v1/applications/${app_id}/upstreams" \
    '{"name":"service-a","scheme":"http","host":"service-a","port":8080,"weight":1,"priority":1,"health_check_enabled":false,"health_check_path":"/healthz","health_check_method":"GET","health_check_interval_seconds":10,"health_check_timeout_seconds":3,"expected_status_codes":"200","connect_timeout_ms":3000,"response_header_timeout_ms":10000,"tls_server_name":"","tls_verify":false}' 200 \
    || startup_die "应用上游配置失败"
  api_post_expect "${DEMO_SEC_USER}" "${sec_csrf}" "/api/v1/applications/${app_id}/enable" '{}' 200 \
    || startup_die "应用启用失败"
  log "演示应用已创建（id=${app_id} code=${app_code} host=${DEMO_GW_HOSTNAME} mode=OBSERVE）"

  # 6) 发布 → adminpatch（每次发布后补丁即被覆盖，必须重打）→ 网关自检
  api_publish "${DEMO_SEC_USER}" "${sec_csrf}" || startup_die "配置发布失败"
  api_adminpatch || startup_die "trace_inject_upstream 开启失败"
  cat > "${PRODUCT_META}" <<EOF
APP_ID=${app_id}
APP_CODE=${app_code}
GW_HOSTNAME=${DEMO_GW_HOSTNAME}
APP_MODE=OBSERVE
INSTRUMENTATION=on
EOF
  chmod 0644 "${PRODUCT_META}"
  local gw_code
  gw_code="$(curl -sS -m 10 -o /dev/null -w '%{http_code}' -H "Host: ${DEMO_GW_HOSTNAME}" \
    "http://${GATEWAY_ADDR}/demo/order?id=1" 2>/dev/null || echo 000)"
  [ "${gw_code}" = "200" ] || startup_die "网关自检失败：经网关访问演示应用返回 ${gw_code}（期望 200）"
  log "网关自检通过（经网关 200 到达演示业务，traceparent 注入已开启）"
}

# enable_access_log_setting PUT system-settings logging.access_log_enabled=true
# （先读当前 version，乐观锁冲突时重读重试一次）
enable_access_log_setting() {
  local csrf="$1" ver
  ver="$(api_get "${DEMO_ADMIN_USER}" "/api/v1/system-settings?group=logging" | python3 -c '
import json,sys
items=json.load(sys.stdin)["data"]["items"]
print(next((i["version"] for i in items if i["setting_key"]=="access_log_enabled"), ""))' 2>/dev/null)"
  [ -n "${ver}" ] || startup_die "读取 logging.access_log_enabled 设置失败"
  api_put_expect "${DEMO_ADMIN_USER}" "${csrf}" "/api/v1/system-settings" \
    "{\"setting_group\":\"logging\",\"setting_key\":\"access_log_enabled\",\"setting_value\":true,\"version\":${ver}}" 200 \
    || startup_die "开启全量访问日志设置失败"
  log "全量访问日志已开启（logging.access_log_enabled=true）"
}

# api_login <user> <pass>：验证码从本 run Valkey 读取（不落证据）；Cookie jar 0600；
# 输出 CSRF token 到 stdout（登录响应不落盘——含会话凭据）。
api_login() {
  local user="$1" pass="$2" capid capcode csrf
  capid="$(curl -sS -m 10 "http://${API_ADDR}/api/v1/auth/captcha" 2>/dev/null \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["captcha_id"])' 2>/dev/null)"
  [ -n "${capid}" ] || return 1
  capcode="$(compose_cmd exec -T mgmt-valkey valkey-cli -a "${DEMO_MGMT_VALKEY_PASSWORD}" \
      --no-auth-warning GET "jiuzhang:captcha:${capid}" 2>/dev/null | tr -d '\r')"
  [ -n "${capcode}" ] || return 1
  csrf="$(curl -sS -m 10 -c "${RUN_DIR}/cookies-${user}.txt" -X POST \
      "http://${API_ADDR}/api/v1/auth/login" -H 'Content-Type: application/json' \
      -d "{\"username\":\"${user}\",\"password\":\"${pass}\",\"captcha_id\":\"${capid}\",\"captcha_code\":\"${capcode}\"}" 2>/dev/null \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["csrf_token"])' 2>/dev/null)"
  chmod 0600 "${RUN_DIR}/cookies-${user}.txt" 2>/dev/null || true
  [ -n "${csrf}" ] || return 1
  printf '%s' "${csrf}"
}

api_get() { # api_get <user> <path>：GET 管理 API（输出响应体到 stdout，调用方决定落盘）
  curl -sS -m 20 -b "${RUN_DIR}/cookies-$1.txt" "http://${API_ADDR}$2" 2>/dev/null
}

api_post() { # api_post <user> <csrf> <path> <body>
  curl -sS -m 30 -b "${RUN_DIR}/cookies-$1.txt" -X POST "http://${API_ADDR}$3" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $2" -d "$4" 2>/dev/null
}

api_put() { # api_put <user> <csrf> <path> <body>
  curl -sS -m 30 -b "${RUN_DIR}/cookies-$1.txt" -X PUT "http://${API_ADDR}$3" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $2" -d "$4" 2>/dev/null
}

api_post_expect() { # api_post_expect <user> <csrf> <path> <body> <want_code>
  local code
  code="$(curl -sS -m 30 -o /dev/null -w '%{http_code}' -b "${RUN_DIR}/cookies-$1.txt" \
    -X POST "http://${API_ADDR}$3" -H 'Content-Type: application/json' -H "X-CSRF-Token: $2" \
    -d "$4" 2>/dev/null || echo 000)"
  [ "${code}" = "$5" ]
}

api_put_expect() { # api_put_expect <user> <csrf> <path> <body> <want_code>
  local code
  code="$(curl -sS -m 30 -o /dev/null -w '%{http_code}' -b "${RUN_DIR}/cookies-$1.txt" \
    -X PUT "http://${API_ADDR}$3" -H 'Content-Type: application/json' -H "X-CSRF-Token: $2" \
    -d "$4" 2>/dev/null || echo 000)"
  [ "${code}" = "$5" ]
}

# api_publish <user> <csrf>：发布并等待终态（≤90s）；成功返回 0
api_publish() {
  local task st i
  task="$(api_post "$1" "$2" "/api/v1/gateway-config/publish" \
      "{\"idempotency_key\":\"apmdemo-${RUN_ID}-$(date +%s)\"}" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin).get("data",{}).get("id",""))' 2>/dev/null)"
  [ -n "${task}" ] || return 1
  i=0
  while [ "${i}" -lt 45 ]; do
    st="$(api_get "$1" "/api/v1/publish-tasks/${task}" \
      | python3 -c 'import json,sys; print(json.load(sys.stdin).get("data",{}).get("status",""))' 2>/dev/null)"
    case "${st}" in
      SUCCESS) log "发布成功（task=${task}）"; return 0 ;;
      FAILED) echo "发布失败（task=${task}）" >&2; return 1 ;;
    esac
    sleep 2; i=$(( i + 1 ))
  done
  echo "发布超时（task=${task}）" >&2
  return 1
}

# api_adminpatch：经一次性容器为活跃配置的全部 jiuzhang_guard 处理器开启
# trace_inject_upstream（发布侧取值接线未落地，见 adminpatch main.go 头注释）。
api_adminpatch() {
  local out
  out="$(compose_cmd run --rm -T adminpatch 2>/dev/null)" || {
    echo "adminpatch 执行失败" >&2; return 1; }
  log "trace_inject_upstream 已开启（${out}）"
}

load_product_meta() { # 读取 product.env（非敏感元数据：APP_ID/APP_MODE/INSTRUMENTATION）
  [ "${COMPOSE_PRODUCT}" = "1" ] || die "本 run 未叠加产品栈（startup 未带 --with-product）"
  [ -f "${PRODUCT_META}" ] || die "产品接入元数据缺失: ${PRODUCT_META}（startup 未完成接入？）"
  set -a
  # shellcheck disable=SC1090
  . "${PRODUCT_META}"
  set +a
}

product_meta_set() { # product_meta_set KEY VALUE：就地更新 product.env 单键
  python3 - "${PRODUCT_META}" "$1" "$2" <<'PYEOF'
import sys
path, key, val = sys.argv[1:4]
lines = []
found = False
with open(path, encoding="utf-8") as fh:
    for line in fh:
        if line.startswith(key + "="):
            lines.append(f"{key}={val}\n")
            found = True
        else:
            lines.append(line)
if not found:
    lines.append(f"{key}={val}\n")
with open(path, "w", encoding="utf-8") as fh:
    fh.writelines(lines)
PYEOF
}

# cmd_mode observe|protect：经真实管理 API 切换演示应用防护模式（更新应用 → 发布 →
# adminpatch 重打——发布会覆盖运行态补丁），并记录模式到 product.env 供 verify 对账。
cmd_mode() {
  local mode="${MODE_ARG:-}"
  case "${mode}" in observe|protect) ;; *) die "mode 仅接受 observe|protect" ;; esac
  resolve_run
  load_env
  load_ports
  load_product_meta
  local want
  want="$(printf '%s' "${mode}" | tr 'a-z' 'A-Z')"
  if [ "${APP_MODE}" = "${want}" ]; then
    log "应用已处于 ${want}，无需切换"
    return 0
  fi
  local sec_csrf
  sec_csrf="$(api_login "${DEMO_SEC_USER}" "${DEMO_SEC_PASSWORD}")" || die "安全管理员登录失败"
  # 更新应用模式（PUT 乐观锁需携带 version；名称一并从 GET 读回）
  local app_name app_ver
  app_name="$(api_get "${DEMO_SEC_USER}" "/api/v1/applications/${APP_ID}" | python3 -c \
    'import json,sys; d=json.load(sys.stdin)["data"]; print(d["name"]); print(d["version"])' 2>/dev/null)"
  app_ver="$(printf '%s\n' "${app_name}" | sed -n '2p')"
  app_name="$(printf '%s\n' "${app_name}" | sed -n '1p')"
  [ -n "${app_name}" ] && [ -n "${app_ver}" ] || die "读取应用详情失败（app=${APP_ID}）"
  local code
  code="$(curl -sS -m 30 -o /dev/null -w '%{http_code}' -b "${RUN_DIR}/cookies-${DEMO_SEC_USER}.txt" \
    -X PUT "http://${API_ADDR}/api/v1/applications/${APP_ID}" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: ${sec_csrf}" \
    -d "{\"name\":\"${app_name}\",\"protection_mode\":\"${want}\",\"version\":${app_ver}}" 2>/dev/null || echo 000)"
  [ "${code}" = "200" ] || die "切换防护模式失败（HTTP ${code}）"
  api_publish "${DEMO_SEC_USER}" "${sec_csrf}" || die "模式切换后发布失败"
  api_adminpatch || die "模式切换后 adminpatch 失败"
  product_meta_set APP_MODE "${want}"
  log "防护模式已切换为 ${want} 并发布生效"
}

# cmd_instrumentation on|off：重建 service-a/b 开/关应用遥测（OTEL_SDK_DISABLED）。
# 场景 7「仅网关观测」：off 后业务照常运行但不产生 Span，网关侧数据照常。
cmd_instrumentation() {
  local want="${MODE_ARG:-}"
  case "${want}" in on|off) ;; *) die "instrumentation 仅接受 on|off" ;; esac
  resolve_run
  load_env
  load_ports
  load_product_meta
  local flag=false
  [ "${want}" = "off" ] && flag=true
  log "重建 service-a/b（OTEL_SDK_DISABLED=${flag}）"
  OTEL_SDK_DISABLED="${flag}" compose_cmd up -d --force-recreate service-a service-b >/dev/null \
    || die "重建 service-a/b 失败"
  wait_services_healthy || die "service-a/b 重建后健康等待超时"
  local code
  code="$(curl -sS -m 5 -o /dev/null -w '%{http_code}' "http://${SERVICE_A_ADDR}/healthz" 2>/dev/null || echo 000)"
  [ "${code}" = "200" ] || die "service-a 重建后健康自检失败（${code}）"
  product_meta_set INSTRUMENTATION "${want}"
  log "应用遥测已${want}（INSTRUMENTATION=${want}）"
}

# ---------- 造流 ----------
# attack 语料（固定合成探针，仅发往经授权的演示应用；不接受外部输入）
ATTACK_PROBES='sqli|/demo/order?id=1&q=1%27%20OR%20%271%27%3D%271
lfi|/demo/order?id=1&p=..%2F..%2F..%2Fetc%2Fpasswd
xss|/demo/order?id=1&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E'

validate_gateway_url() { # $1 = GATEWAY_BASE_URL；防 SSRF/凭据泄露的形态校验
  python3 - "$1" <<'PYEOF'
import sys
from urllib.parse import urlsplit
u = sys.argv[1]
try:
    p = urlsplit(u)
except Exception:
    sys.exit(1)
if p.scheme not in ("http", "https") or not p.hostname:
    sys.exit(1)
if p.username or p.password or "@" in (p.netloc or ""):
    sys.exit(1)   # URL 不得内嵌凭据
if p.path not in ("", "/") or p.query or p.fragment:
    sys.exit(1)
PYEOF
}

# demo_req <class> <seq> <base_url> <path> [scenario] [via] [extra_curl_args...]
# 记录一行 JSONL：class/demo_request_id/via/status/latency/trace_id/jiuzhang_request_id/scenario_applied
demo_req() {
  local class="$1" seq="$2" base="$3" path="$4" scenario="${5:-}" via="${6:-direct}"
  shift $(( $# > 6 ? 6 : $# ))
  local reqid out status ttotal trace_id jrid applied
  local -a hdrs=()
  [ -n "${scenario}" ] && hdrs+=(-H "X-Demo-Scenario: ${scenario}")
  [ -n "${GATEWAY_HOST:-}" ] && hdrs+=(-H "Host: ${GATEWAY_HOST}")
  reqid="d-${RUN_ID}-${WAVE}-${class}-${seq}"
  out="$(curl -sS -m 30 -o /dev/null --path-as-is \
      -w '%{http_code}\t%{time_total}' \
      -H "X-Demo-Request-Id: ${reqid}" \
      ${hdrs[@]+"${hdrs[@]}"} \
      "$@" \
      -D "${RUN_DIR}/.headers.tmp" \
      "${base}${path}")" || out=$'000\t0'
  status="${out%%	*}"
  ttotal="${out##*	}"
  trace_id="$(grep -i '^X-Demo-Trace-Id:' "${RUN_DIR}/.headers.tmp" 2>/dev/null | tr -d '\r' | awk '{print $2}' || true)"
  jrid="$(grep -i '^X-Jiuzhang-Request-ID:' "${RUN_DIR}/.headers.tmp" 2>/dev/null | tr -d '\r' | awk '{print $2}' || true)"
  applied="$(grep -i '^X-Demo-Scenario-Applied:' "${RUN_DIR}/.headers.tmp" 2>/dev/null | tr -d '\r' | awk '{print $2}' || true)"
  rm -f "${RUN_DIR}/.headers.tmp"
  python3 - "${TRAFFIC_FILE}" "${class}" "${reqid}" "${via}" "${status}" "${ttotal}" \
      "${trace_id:-}" "${jrid:-}" "${applied:-}" <<'PYEOF'
import json, sys
path, cls, reqid, via, status, ttotal, trace_id, jrid, applied = sys.argv[1:10]
rec = {"class": cls, "demo_request_id": reqid, "via": via,
       "status": None if status in ("000", "") else int(status),
       "latency_ms": round(float(ttotal or 0) * 1000, 1),
       "trace_id": trace_id or None,
       "jiuzhang_request_id": jrid or None,
       "scenario_applied": applied or None}
with open(path, "a", encoding="utf-8") as fh:
    fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
PYEOF
}

cmd_traffic() {
  resolve_run
  load_env
  load_ports
  # 产品栈存在时网关自动指向本 run（仍可被运行时环境变量覆盖）；GATEWAY_HOST 取接入域名
  if [ "${COMPOSE_PRODUCT}" = "1" ] && [ -f "${PRODUCT_META}" ]; then
    set -a; . "${PRODUCT_META}"; set +a
    GATEWAY_BASE_URL="${GATEWAY_BASE_URL:-http://${GATEWAY_ADDR}}"
    GATEWAY_HOST="${GATEWAY_HOST:-${GW_HOSTNAME}}"
  fi
  case "${WAVE}" in
    main) TRAFFIC_FILE="${RUN_DIR}/traffic.jsonl" ;;
    protect|gwonly) TRAFFIC_FILE="${RUN_DIR}/traffic-${WAVE}.jsonl" ;;
    *) die "--wave 仅接受 main|protect|gwonly" ;;
  esac
  : > "${TRAFFIC_FILE}"
  local base="http://${SERVICE_A_ADDR}" i

  if [ "${WAVE}" = "gwonly" ]; then
    # 场景 7 波次：仅经网关发正常请求（应用遥测已由 instrumentation off 关闭）
    [ -n "${GATEWAY_BASE_URL:-}" ] || die "gwonly 波次需要网关（--with-product 或 GATEWAY_BASE_URL）"
    validate_gateway_url "${GATEWAY_BASE_URL}" || die "GATEWAY_BASE_URL 形态非法"
    log "造流：仅网关观测波次 网关正常 ×2（${GATEWAY_BASE_URL}，Host=${GATEWAY_HOST:-默认}）"
    demo_req gwonly-normal 1 "${GATEWAY_BASE_URL}" "/demo/order?id=7" "" gateway
    demo_req gwonly-normal 2 "${GATEWAY_BASE_URL}" "/demo/order?id=8" "" gateway
    write_wave_meta
    log "造流完成，记录: ${TRAFFIC_FILE}"
    return 0
  fi

  if [ "${WAVE}" = "protect" ]; then
    # 场景 3 波次：源站计数前后快照 + 网关正常 + 攻击（应用须已 mode protect）
    [ -n "${GATEWAY_BASE_URL:-}" ] || die "protect 波次需要网关（--with-product 或 GATEWAY_BASE_URL）"
    validate_gateway_url "${GATEWAY_BASE_URL}" || die "GATEWAY_BASE_URL 形态非法"
    local stats_before stats_after
    stats_before="$(curl -sS -m 5 "http://${SERVICE_A_ADDR}/demo/stats" 2>/dev/null \
      | python3 -c 'import json,sys; print(json.load(sys.stdin)["order_requests_total"])' 2>/dev/null || echo '')"
    [ -n "${stats_before}" ] || die "读取服务 A 计数端点失败（/demo/stats）"
    log "造流：阻断波次（源站计数前置快照=${stats_before}）"
    demo_req gw-normal 1 "${GATEWAY_BASE_URL}" "/demo/order?id=5" "" gateway
    demo_req gw-normal 2 "${GATEWAY_BASE_URL}" "/demo/order?id=6" "" gateway
    local name path
    printf '%s\n' "${ATTACK_PROBES}" | while IFS='|' read -r name path; do
      [ -z "${name}" ] && continue
      demo_req "attack-${name}" 1 "${GATEWAY_BASE_URL}" "${path}" "" gateway
    done
    stats_after="$(curl -sS -m 5 "http://${SERVICE_A_ADDR}/demo/stats" 2>/dev/null \
      | python3 -c 'import json,sys; print(json.load(sys.stdin)["order_requests_total"])' 2>/dev/null || echo '')"
    python3 - "${RUN_DIR}/protect-stats.json" "${stats_before}" "${stats_after}" <<'PYEOF'
import json, sys
doc = {"order_requests_total_before": int(sys.argv[2]),
       "order_requests_total_after": int(sys.argv[3]),
       "note": "protect 波次含 2 条网关正常透传（计入 after）；攻击请求若被网关阻断则不计入"}
with open(sys.argv[1], "w", encoding="utf-8") as fh:
    json.dump(doc, fh, ensure_ascii=False, indent=2)
    fh.write("\n")
PYEOF
    write_wave_meta
    log "造流完成（源站计数后置快照=${stats_after}），记录: ${TRAFFIC_FILE} + protect-stats.json"
    return 0
  fi

  log "造流：正常 ×${NORMAL_COUNT}（直连服务 A）"
  i=1
  while [ "${i}" -le "${NORMAL_COUNT}" ]; do
    demo_req normal "${i}" "${base}" "/demo/order?id=$(( (i % 100) + 1 ))"
    i=$(( i + 1 ))
  done

  log "造流：慢 SQL ×1（场景 slow-sql，库内有界延迟 2.5s→clamp≤3s）"
  demo_req slow 1 "${base}" "/demo/order?id=2" slow-sql

  log "造流：异常 ×1（场景 exception，库内固定合成错误）"
  demo_req exception 1 "${base}" "/demo/order?id=3" exception

  log "造流：脱敏护栏 ×1（携带合成 Authorization/Cookie 头，断言不落 CH）"
  demo_req redact 1 "${base}" "/demo/order?id=4" "" direct \
    -H "Authorization: Bearer demo-not-a-real-token-p1-01" -H "Cookie: demo=redact-check"

  if [ -n "${GATEWAY_BASE_URL:-}" ]; then
    validate_gateway_url "${GATEWAY_BASE_URL}" \
      || die "GATEWAY_BASE_URL 形态非法（需 http(s)://host[:port]，无内嵌凭据/路径）"
    log "造流：网关正常透传 ×2（${GATEWAY_BASE_URL}）"
    demo_req gw-normal 1 "${GATEWAY_BASE_URL}" "/demo/order?id=5" "" gateway
    demo_req gw-normal 2 "${GATEWAY_BASE_URL}" "/demo/order?id=6" "" gateway
    log "造流：攻击 ×3（固定合成探针，经网关；OBSERVE/PROTECT 由演示应用策略决定）"
    local name path
    printf '%s\n' "${ATTACK_PROBES}" | while IFS='|' read -r name path; do
      [ -z "${name}" ] && continue
      demo_req "attack-${name}" 1 "${GATEWAY_BASE_URL}" "${path}" "" gateway
    done
  else
    log "GATEWAY_BASE_URL 未提供：攻击与网关联调类记 SKIP（不伪造网关证据）"
    python3 - "${TRAFFIC_FILE}" <<'PYEOF'
import json, sys
rec = {"class": "attack", "demo_request_id": None, "via": "gateway",
       "status": None, "skipped": True, "reason": "GATEWAY_NOT_CONFIGURED"}
with open(sys.argv[1], "a", encoding="utf-8") as fh:
    fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
PYEOF
  fi
  write_wave_meta
  log "造流完成，记录: ${TRAFFIC_FILE}"
  log "下一步：bash ${SCRIPT_DIR}/run.sh verify --run-id ${RUN_ID}"
}

# write_wave_meta 记录本波次的防护模式/遥测状态/时间窗起点（verify 对账依据；无凭据）
write_wave_meta() {
  local app_mode="" instr=""
  if [ -f "${PRODUCT_META}" ]; then
    app_mode="$(grep '^APP_MODE=' "${PRODUCT_META}" | cut -d= -f2)"
    instr="$(grep '^INSTRUMENTATION=' "${PRODUCT_META}" | cut -d= -f2)"
  fi
  python3 - "${TRAFFIC_FILE}" "${WAVE}" "${app_mode}" "${instr}" <<'PYEOF'
import datetime, json, sys
path, wave, mode, instr = sys.argv[1:5]
meta = {"wave": wave, "app_mode": mode or None, "instrumentation": instr or None,
        "started_at_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
with open(path.replace(".jsonl", "") + ".meta.json", "w", encoding="utf-8") as fh:
    json.dump(meta, fh, ensure_ascii=False, indent=2)
    fh.write("\n")
PYEOF
}

# ---------- A4 断言（产品栈管理 API 对账；仅 --with-product run 执行） ----------
# 证据纪律：全部 API 响应原样落盘 runs/<run_id>/evidence-a4/（查询响应不含凭据）；
# 会话 Cookie 只经 jar 文件（0600）传递；断言失败如实 FAIL，外部条件缺失如实 SKIP/BLOCKED。
verify_a4() {
  # 安全管理员会话（GET 只需 Cookie；CSRF 不涉及）
  if ! api_login "${DEMO_SEC_USER}" "${DEMO_SEC_PASSWORD}" >/dev/null; then
    add_result A4-01-observe-correlation BLOCKED "安全管理员登录失败，无法执行管理 API 对账"
    add_result A4-02-protect-block BLOCKED "同上"
    add_result A4-03-coexist-distinct BLOCKED "同上"
    add_result A4-04-gateway-only BLOCKED "同上"
    return
  fi
  mkdir -p "${RUN_DIR}/evidence-a4"
  # 凭据（CH 账号）经环境继承，Cookie 经 jar 文件；均不上 python 命令行。
  # 结果行先捕获到变量再在主 shell 循环 add_result（管道子 shell 会丢 VERIFY_RESULTS）
  local a4_out
  a4_out="$(python3 - "${RUN_DIR}" "${API_ADDR}" "${DEMO_SEC_USER}" "${VERIFY_POLL_S}" "${CH_HTTP_ADDR}" <<'PYEOF' || true
import datetime, hashlib, http.cookiejar, json, os, subprocess, sys, time
import urllib.request, urllib.parse, urllib.error

run_dir, api_addr, sec_user, poll_s, ch_addr = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5]
evdir = os.path.join(run_dir, "evidence-a4")
api_base = "http://" + api_addr
ch_user = os.environ["DEMO_CH_ADMIN_USER"]
ch_key = os.environ["DEMO_CH_ADMIN_PASSWORD"]

jar = http.cookiejar.MozillaCookieJar(os.path.join(run_dir, f"cookies-{sec_user}.txt"))
jar.load(ignore_discard=True, ignore_expires=True)

def log(msg):
    print(f"[a4-verify] {msg}", file=sys.stderr)

def api_get(path, params=None, timeout=25):
    url = api_base + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url)
    for c in jar:
        req.add_header("Cookie", f"{c.name}={c.value}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")[:500]
        return e.code, {"_http_error": e.code, "_body": body}
    except Exception as e:
        return 0, {"_error": str(e)}

def window():
    now = datetime.datetime.now(datetime.timezone.utc)
    start = now - datetime.timedelta(minutes=30)
    return (start.strftime("%Y-%m-%dT%H:%M:%SZ"), now.strftime("%Y-%m-%dT%H:%M:%SZ"))

def save(name, obj):
    with open(os.path.join(evdir, name), "w", encoding="utf-8") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=2)
        fh.write("\n")

def load_wave(name):
    path = os.path.join(run_dir, name)
    if not os.path.exists(path):
        return None
    return [json.loads(x) for x in open(path, encoding="utf-8") if x.strip()]

def load_meta(wavefile):
    path = os.path.join(run_dir, wavefile.replace(".jsonl", "") + ".meta.json")
    if not os.path.exists(path):
        return {}
    return json.load(open(path, encoding="utf-8"))

def ch_scalar(sql):
    out = subprocess.run(["curl", "-sS", "-m", "20", f"http://{ch_addr}/",
                          "-H", f"X-ClickHouse-User: {ch_user}",
                          "-H", f"X-ClickHouse-Key: {ch_key}",
                          "--data-binary", sql],
                         capture_output=True, text=True).stdout.strip()
    return out

def trace_search(jrid):
    st, body = api_get("/api/v1/apm/trace-search",
                       {"request_id": jrid, "start_time": window()[0], "end_time": window()[1]})
    return st, body

def emit(aid, status, reason):
    print(f"{aid}\t{status}\t{reason}")

# ---------- A4-01 场景2「命中但观察」：OBSERVE 攻击的请求 ↔ 事件 ↔ 上游 Trace 相互定位 ----------
main = load_wave("traffic.jsonl")
meta_main = load_meta("traffic.jsonl")
attacks = [r for r in (main or []) if (r.get("class") or "").startswith("attack-")
           and r.get("via") == "gateway" and not r.get("skipped")
           and r.get("jiuzhang_request_id") and r.get("status") not in (None, 403)]
if main is None or not attacks:
    emit("A4-01-observe-correlation", "SKIP",
         "主波次无 OBSERVE 透传攻击记录（无网关/未造流/波次非 OBSERVE），不伪造关联证据")
else:
    fails, oks = [], []
    for rec in attacks:
        jrid = rec["jiuzhang_request_id"]
        tag = rec["class"]
        st, ev = api_get("/api/v1/security-events",
                         {"request_id": jrid, "start_time": window()[0], "end_time": window()[1]})
        save(f"A4-01-{tag}-security-events.json", ev)
        if st == 403 or st == 401:
            fails.append(f"{tag}: 安全事件查询 {st}（权限/会话问题）")
            continue
        ev_total = (ev.get("data") or {}).get("total", 0)
        ev_items = (ev.get("data") or {}).get("items") or []
        ev_action = ev_items[0].get("action") if ev_items else None
        if ev_total < 1:
            fails.append(f"{tag}: 安全事件缺失（request_id={jrid}）")
            continue
        if ev_action == "BLOCK":
            fails.append(f"{tag}: OBSERVE 波次事件 action=BLOCK（与波次模式 {meta_main.get('app_mode')} 矛盾）")
            continue
        # 关联检索：有界轮询直到 MATCHED（PENDING 允许短暂等待，不永久轮询）
        deadline = time.time() + poll_s
        ts = None
        while True:
            st, ts = trace_search(jrid)
            if st in (401, 403):
                break
            corr = ((ts or {}).get("data") or {}).get("correlation") or {}
            if corr.get("state") == "MATCHED" or time.time() >= deadline:
                break
            time.sleep(5)
        save(f"A4-01-{tag}-trace-search.json", ts)
        data = (ts or {}).get("data") or {}
        corr = data.get("correlation") or {}
        items = data.get("list") or []
        if st in (401, 403):
            fails.append(f"{tag}: trace-search {st}（权限缺失？）")
            continue
        if corr.get("state") != "MATCHED":
            fails.append(f"{tag}: correlation.state={corr.get('state')}（{corr.get('reason','')}）")
            continue
        found = [i for i in items if i.get("trace_id") == rec.get("trace_id")]
        if not found:
            fails.append(f"{tag}: MATCHED 但列表不含造流记录 trace_id={rec.get('trace_id')}（列表 {[i.get('trace_id') for i in items]}）")
            continue
        # Trace 详情：同 request_id 的安全事件与上游 Trace 可相互定位
        st, tv = api_get(f"/api/v1/apm/traces/{rec['trace_id']}")
        save(f"A4-01-{tag}-trace-view.json", tv)
        tvd = (tv or {}).get("data") or {}
        svcs = {s.get("service_name") for s in (tvd.get("otel_spans") or [])}
        srcs = set(((tvd.get("availability") or {}).get("observed_sources")) or [])
        if not ({"demo-service-a", "demo-service-b"} <= svcs):
            fails.append(f"{tag}: trace 详情缺演示服务 Span（services={sorted(svcs)}）")
            continue
        if "GATEWAY" not in srcs or "OTEL" not in srcs:
            fails.append(f"{tag}: trace availability.observed_sources={sorted(srcs)}（应含 GATEWAY+OTEL）")
            continue
        oks.append(f"{tag}: request_id={jrid} ↔ trace={rec['trace_id']}（事件 action={ev_action}）")
    if fails:
        emit("A4-01-observe-correlation", "FAIL", "；".join(fails))
    else:
        emit("A4-01-observe-correlation", "PASS",
             f"{len(oks)} 条 OBSERVE 攻击：安全事件（action≠BLOCK）↔ 同 request_id 上游 Trace 相互定位（MATCHED，trace_id 与造流记录一致，详情含 demo-service-a/b 且双数据源）。证据 evidence-a4/A4-01-*")

# ---------- A4-02 场景3「网关阻断」：PROTECT 阻断 + 源站计数不变 + NOT_EXPECTED ----------
protect = load_wave("traffic-protect.jsonl")
if not protect:
    emit("A4-02-protect-block", "SKIP", "无 protect 波次（先 mode protect 再 traffic --wave protect）")
else:
    fails = []
    patks = [r for r in protect if (r.get("class") or "").startswith("attack-") and r.get("jiuzhang_request_id")]
    if not patks:
        fails.append("protect 波次无攻击记录")
    for rec in patks:
        if rec.get("status") != 403:
            fails.append(f"{rec['class']}: 状态={rec.get('status')}（PROTECT 下攻击应 403）")
    # 源站调用计数：delta 必须等于波次内 200 透传请求数（攻击未计入）
    stats_path = os.path.join(run_dir, "protect-stats.json")
    if not os.path.exists(stats_path):
        fails.append("protect-stats.json 缺失（源站计数证据缺失）")
    else:
        st_doc = json.load(open(stats_path, encoding="utf-8"))
        save("A4-02-protect-stats.json", st_doc)
        expect_delta = sum(1 for r in protect if r.get("via") == "gateway" and r.get("status") == 200)
        delta = st_doc["order_requests_total_after"] - st_doc["order_requests_total_before"]
        if delta != expect_delta:
            fails.append(f"源站计数 delta={delta} ≠ 透传请求数={expect_delta}（攻击可能到达了源站）")
    # 数据级证据：CH 无这些 request 的应用 Span
    for rec in patks:
        n = ch_scalar("SELECT count() FROM apm.otel_traces WHERE SpanAttributes['demo.request_id'] = "
                      f"'{rec['demo_request_id']}'")
        if n != "0":
            fails.append(f"{rec['class']}: 阻断请求存在应用 Span {n} 条")
    # 管理 API：事件 BLOCK + 访问记录 BLOCK + correlation NOT_EXPECTED（有界轮询）
    for rec in patks:
        jrid = rec["jiuzhang_request_id"]
        tag = rec["class"]
        st, ev = api_get("/api/v1/security-events", {"request_id": jrid})
        save(f"A4-02-{tag}-security-events.json", ev)
        ev_items = ((ev or {}).get("data") or {}).get("items") or []
        if not any(i.get("action") == "BLOCK" for i in ev_items):
            fails.append(f"{tag}: 无 action=BLOCK 安全事件（request_id={jrid}）")
        st, al = api_get("/api/v1/access-logs", {"request_id": jrid})
        save(f"A4-02-{tag}-access-logs.json", al)
        al_items = ((al or {}).get("data") or {}).get("items") or []
        if al_items and not any((i.get("waf_action") or "ALLOW") == "BLOCK" for i in al_items):
            fails.append(f"{tag}: 访问记录 waf_action 非 BLOCK（{[i.get('waf_action') for i in al_items]}）")
        deadline = time.time() + poll_s
        ts = None
        while True:
            st, ts = trace_search(jrid)
            corr = ((ts or {}).get("data") or {}).get("correlation") or {}
            if corr.get("state") in ("NOT_EXPECTED", "MATCHED") or time.time() >= deadline:
                break
            time.sleep(5)
        save(f"A4-02-{tag}-trace-search.json", ts)
        corr = ((ts or {}).get("data") or {}).get("correlation") or {}
        if corr.get("state") != "NOT_EXPECTED":
            fails.append(f"{tag}: correlation.state={corr.get('state')}（期望 NOT_EXPECTED：{corr.get('reason','')}）")
    if fails:
        emit("A4-02-protect-block", "FAIL", "；".join(fails))
    else:
        emit("A4-02-protect-block", "PASS",
             f"{len(patks)} 条攻击全部 403；源站计数 delta 仅含透传请求；CH 无应用 Span；事件/访问记录 BLOCK；trace-search correlation=NOT_EXPECTED。证据 evidence-a4/A4-02-*")

# ---------- A4-03 场景6「同时但无关」：攻击与慢 SQL 按 ID 可区分，无交叉链接 ----------
slow = [r for r in (main or []) if r.get("class") == "slow" and r.get("trace_id")]
if not main or not attacks or not slow:
    emit("A4-03-coexist-distinct", "SKIP", "主波次缺攻击或慢查询记录（需同波次并存）")
else:
    fails = []
    slow_tid = slow[0]["trace_id"]
    atk_tids = {r.get("trace_id") for r in attacks}
    atk_jrids = {r.get("jiuzhang_request_id") for r in attacks}
    if slow_tid in atk_tids:
        fails.append("慢查询 trace_id 与攻击 trace_id 相同（ID 冲突）")
    if len(atk_jrids) != len(attacks) or None in atk_jrids:
        fails.append("攻击请求内部 request_id 缺失或不唯一")
    # 攻击 Trace 不得包含慢 SQL 指纹；慢 Trace 必须包含。瀑布属性按产品数据最小化口径
    # 不含原始 db.statement（§11.1），交叉判定走 SQL 诊断页 trace 级定位：指纹=hex(MD5(常量语句))。
    slow_fp = hashlib.md5(b"SELECT demo_sleep_bounded($1)").hexdigest().upper()  # CH hex() 大写口径
    atk_tid = attacks[0].get("trace_id")
    st, tv = api_get(f"/api/v1/apm/traces/{atk_tid}")
    save("A4-03-attack-trace-view.json", tv)
    st, aq = api_get("/api/v1/apm/sql", {"trace_id": atk_tid,
                                         "start_time": window()[0], "end_time": window()[1]})
    save("A4-03-attack-sql.json", aq)
    a_fps = [i.get("sql_fingerprint") for i in (((aq or {}).get("data") or {}).get("list") or [])]
    if slow_fp in a_fps:
        fails.append("攻击 Trace 的 SQL 指纹列表出现慢 SQL 指纹（不应存在的交叉）")
    st, sv = api_get(f"/api/v1/apm/traces/{slow_tid}")
    save("A4-03-slow-trace-view.json", sv)
    st, sq = api_get("/api/v1/apm/sql", {"trace_id": slow_tid,
                                         "start_time": window()[0], "end_time": window()[1]})
    save("A4-03-slow-sql.json", sq)
    s_fps = [i.get("sql_fingerprint") for i in (((sq or {}).get("data") or {}).get("list") or [])]
    if slow_fp not in s_fps:
        fails.append(f"慢查询 Trace 的 SQL 指纹列表缺 demo_sleep_bounded 指纹（实际 {s_fps}）")
    # 事件侧：攻击事件的 request_id 与慢查询无任何共享标识
    if fails:
        emit("A4-03-coexist-distinct", "FAIL", "；".join(fails))
    else:
        emit("A4-03-coexist-distinct", "PASS",
             f"并存可区分：攻击 request_id/trace_id（{sorted(atk_jrids)}）与慢查询 trace={slow_tid} 互不交叉；攻击 Trace 的 SQL 指纹列表无慢 SQL 指纹，慢 Trace 有（SQL 诊断页 trace 级定位）。本断言只证「可区分」，不断言因果。证据 evidence-a4/A4-03-*")

# ---------- A4-04 场景7「仅网关观测」：遥测关闭后仅网关侧数据可用 ----------
gwonly = load_wave("traffic-gwonly.jsonl")
meta_gw = load_meta("traffic-gwonly.jsonl")
if not gwonly:
    emit("A4-04-gateway-only", "SKIP", "无 gwonly 波次（先 instrumentation off 再 traffic --wave gwonly）")
elif meta_gw.get("instrumentation") != "off":
    emit("A4-04-gateway-only", "FAIL", f"gwonly 波次元数据 instrumentation={meta_gw.get('instrumentation')}（须先 instrumentation off）")
else:
    fails, checked = [], 0
    for rec in gwonly:
        if rec.get("status") != 200 or not rec.get("jiuzhang_request_id"):
            fails.append(f"{rec.get('class')}: 状态={rec.get('status')}（遥测关闭不影响业务，应 200）")
            continue
        checked += 1
        jrid = rec["jiuzhang_request_id"]
        tag = rec["class"] + "-" + str(checked)
        st, al = api_get("/api/v1/access-logs", {"request_id": jrid})
        save(f"A4-04-{tag}-access-logs.json", al)
        al_items = ((al or {}).get("data") or {}).get("items") or []
        if not al_items:
            fails.append(f"{tag}: 网关访问记录缺失（request_id={jrid}）")
            continue
        # trace-search：不得 MATCHED；PENDING 有界等待后须落 NOT_FOUND/UNKNOWN。
        # 产品口径 correlationPendingMargin=5min（availability.go：发生时间距 now <5min 允许 PENDING），
        # 故等待上限 = 波次结束时刻 + 5min + 30s 余量（封顶 now+390s，不永久轮询）。
        try:
            wave_end = datetime.datetime.strptime(meta_gw.get("started_at_utc") or "",
                                                  "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc).timestamp()
        except Exception:
            wave_end = time.time()
        deadline = min(max(time.time() + poll_s, wave_end + 5*60 + 30), time.time() + 390)
        ts = None
        while True:
            st, ts = trace_search(jrid)
            corr = ((ts or {}).get("data") or {}).get("correlation") or {}
            if corr.get("state") != "PENDING" or time.time() >= deadline:
                break
            time.sleep(15)
        save(f"A4-04-{tag}-trace-search.json", ts)
        tsd = (ts or {}).get("data") or {}
        corr = tsd.get("correlation") or {}
        if corr.get("state") == "MATCHED" or (tsd.get("list") or []):
            fails.append(f"{tag}: 遥测关闭却检索到 Trace（state={corr.get('state')}）——疑似伪造/串请求")
            continue
        if corr.get("state") not in ("NOT_FOUND", "UNKNOWN"):
            fails.append(f"{tag}: correlation.state={corr.get('state')}（期望 NOT_FOUND/UNKNOWN）")
            continue
        # trace 详情（候选 trace_id 来自 access_logs 解析）：仅 GATEWAY 源，无 Span
        cands = corr.get("candidates") or []
        tid = cands[0].get("trace_id") if cands else None
        if not tid:
            fails.append(f"{tag}: 无 access_logs 解析候选 trace_id（网关侧 trace 上下文缺失）")
            continue
        st, tv = api_get(f"/api/v1/apm/traces/{tid}")
        save(f"A4-04-{tag}-trace-view.json", tv)
        tvd = (tv or {}).get("data") or {}
        srcs = set(((tvd.get("availability") or {}).get("observed_sources")) or [])
        spans = tvd.get("otel_spans") or []
        if "OTEL" in srcs or spans:
            fails.append(f"{tag}: trace 详情出现 OTEL 数据（sources={sorted(srcs)} spans={len(spans)}）")
            continue
        if "GATEWAY" not in srcs:
            fails.append(f"{tag}: trace 详情缺 GATEWAY 源（sources={sorted(srcs)}）")
            continue
        # SQL 页 trace 级定位：空列表 + 不伪造
        st, sq = api_get("/api/v1/apm/sql", {"trace_id": tid,
                                             "start_time": window()[0], "end_time": window()[1]})
        save(f"A4-04-{tag}-sql.json", sq)
        sq_items = ((sq or {}).get("data") or {}).get("list") or []
        if sq_items:
            fails.append(f"{tag}: 无应用采集却返回 SQL 指纹 {len(sq_items)} 条")
            continue
        # CH 地面真值：该 trace_id 无任何 Span
        n = ch_scalar(f"SELECT count() FROM apm.otel_traces WHERE TraceId='{tid}'")
        if n != "0":
            fails.append(f"{tag}: CH 存在该 trace Span {n} 条（遥测未真正关闭？）")
            continue
    if fails:
        emit("A4-04-gateway-only", "FAIL", "；".join(fails))
    elif checked == 0:
        emit("A4-04-gateway-only", "FAIL", "gwonly 波次无 200 记录可核对")
    else:
        emit("A4-04-gateway-only", "PASS",
             f"{checked} 条请求：业务 200（遥测关闭不影响业务）；访问记录可用；trace-search 无 MATCHED；trace 详情仅 GATEWAY 源无 Span；SQL trace 级定位为空；CH 地面真值零 Span。SQL/代码级不可用如实呈现。证据 evidence-a4/A4-04-*")
PYEOF
)"
  # 主 shell 内逐行登记（进程替换避免管道子 shell 丢状态）
  while IFS='	' read -r a4id a4st a4reason; do
    [ -z "${a4id}" ] && continue
    add_result "${a4id}" "${a4st}" "${a4reason}"
  done < <(printf '%s\n' "${a4_out}")
}

# ---------- 断言 ----------
# status.json 词表与 p0bench/p1reg 一致：PASS / FAIL / SKIP / BLOCKED
VERIFY_RESULTS=""   # 逐行 "id<TAB>status<TAB>reason"

add_result() { # add_result <id> <status> <reason>
  VERIFY_RESULTS="${VERIFY_RESULTS}$1	$2	$3
"
  log "断言 $1: $2 — $3"
}

ch_select() { # $1 = SQL（SELECT ... FORMAT JSONEachRow）；admin 账号只读本 run 演示 CH
  curl -sS -m 20 "http://${CH_HTTP_ADDR}/" \
    -H "X-ClickHouse-User: ${DEMO_CH_ADMIN_USER}" \
    -H "X-ClickHouse-Key: ${DEMO_CH_ADMIN_PASSWORD}" \
    --data-binary "$1"
}

# wait_spans <trace_id> <min_count>：有界轮询 CH（批次+尾采样决策+异步插入延迟）
wait_spans() {
  local tid="$1" want="$2" deadline got
  deadline=$(( $(date +%s) + VERIFY_POLL_S ))
  while :; do
    got="$(ch_select "SELECT count() FROM apm.otel_traces WHERE TraceId='${tid}'" 2>/dev/null | tr -d ' \n')"
    case "${got}" in ''|*[!0-9]*) got=0 ;; esac
    [ "${got}" -ge "${want}" ] && return 0
    [ "$(date +%s)" -ge "${deadline}" ] && return 1
    sleep 3
  done
}

fetch_spans() { # $1=trace_id $2=outfile（JSONEachRow 原始证据保留）
  ch_select "SELECT ServiceName, SpanName, SpanKind, SpanId, ParentSpanId, Duration, StatusCode, SpanAttributes, Events.Name AS EventNames FROM apm.otel_traces WHERE TraceId='$1' ORDER BY Timestamp FORMAT JSONEachRow" \
    > "$2"
}

cmd_verify() {
  resolve_run
  load_env
  load_ports
  TRAFFIC_FILE="${RUN_DIR}/traffic.jsonl"
  [ -f "${TRAFFIC_FILE}" ] || die "造流记录缺失: ${TRAFFIC_FILE}（先运行 traffic）"
  local report="${RUN_DIR}/verify-report.md"

  # A1-01 栈健康（本 run 全部容器）
  if wait_services_healthy; then
    add_result A1-01-stack-health PASS "本 run 全部容器 running/healthy（project=${PROJECT}）"
  else
    add_result A1-01-stack-health BLOCKED "栈不健康或已清理；后续断言依赖栈，终止"
    write_verify_outputs "${report}"
    return
  fi

  # 采样形态（keep-all / sampled）决定 A1-02/A1-05 的可核对性：sampled 形态下
  # 正常流量（含脱敏护栏请求）按 tail_sampling 设计被丢弃，CH 里查无是预期而非缺陷。
  local sampling_cfg
  sampling_cfg="$(grep '^DEMO_COLLECTOR_CONFIG=' "${ENV_FILE}" | cut -d= -f2)"

  # A1-02 正常调用：真实 Trace 与调用层次（直连正常流量逐条核对）
  if [ "${sampling_cfg}" = "demo-sampled.yaml" ]; then
    add_result A1-02-normal-trace SKIP "sampled 形态：正常流量按 tail_sampling 设计丢弃（丢弃证据见 A1-06），链路层次核对以 keep-all 形态为准"
  else
  local fails=0 checked=0 line tid sfile
  while read -r line; do
    checked=$(( checked + 1 ))
    tid="$(printf '%s' "${line}" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("trace_id") or "")')"
    [ -z "${tid}" ] && { fails=$(( fails + 1 )); continue; }
    sfile="${RUN_DIR}/spans-${tid}.jsonl"
    if ! wait_spans "${tid}" 4; then
      fails=$(( fails + 1 )); continue
    fi
    fetch_spans "${tid}" "${sfile}"
    python3 - "${sfile}" <<'PYEOF' || fails=$(( fails + 1 ))
import json, sys
spans = [json.loads(x) for x in open(sys.argv[1], encoding="utf-8") if x.strip()]
ids = [s["SpanId"] for s in spans]
if len(ids) != len(set(ids)):
    print("Span 重复入库（导出重试叠加/授权异常）: " + json.dumps(ids), file=sys.stderr)
    sys.exit(1)
def find(pred):
    return [s for s in spans if pred(s)]
a_srv = find(lambda s: s["ServiceName"] == "demo-service-a" and s["SpanKind"] == "Server")
a_cli = find(lambda s: s["ServiceName"] == "demo-service-a" and s["SpanKind"] == "Client")
b_srv = find(lambda s: s["ServiceName"] == "demo-service-b" and s["SpanKind"] == "Server")
b_db  = find(lambda s: s["ServiceName"] == "demo-service-b" and s["SpanKind"] == "Client"
                       and s["SpanAttributes"].get("db.statement"))
ok = (a_srv and a_cli and b_srv and b_db
      and a_cli[0]["ParentSpanId"] == a_srv[0]["SpanId"]
      and b_srv[0]["ParentSpanId"] == a_cli[0]["SpanId"]
      and b_db[0]["ParentSpanId"] == b_srv[0]["SpanId"])
if not ok:
    print("层次/父子链不符: " + json.dumps(
        [{k: s[k] for k in ("ServiceName", "SpanKind", "SpanId", "ParentSpanId")} for s in spans],
        ensure_ascii=False), file=sys.stderr)
    sys.exit(1)
PYEOF
  done < <(python3 -c '
import json, sys
for line in open(sys.argv[1], encoding="utf-8"):
    r = json.loads(line)
    if r.get("class") == "normal" and r.get("via") == "direct":
        print(json.dumps(r))
' "${TRAFFIC_FILE}")
  if [ "${checked}" = "0" ]; then
    add_result A1-02-normal-trace FAIL "无直连正常流量记录可核对（不允许伪造 Trace）"
  elif [ "${fails}" = "0" ]; then
    add_result A1-02-normal-trace PASS "${checked} 条正常 Trace 四层 Span（a→b→db）与父子链全部命中且无重复入库"
  else
    add_result A1-02-normal-trace FAIL "${checked} 条中 ${fails} 条未命中完整层次（见 spans-*.jsonl 原始证据）"
  fi
  fi

  # A1-03 慢 SQL：目标 Trace 内真实 DB Span 与 SQL 指纹来源
  tid="$(python3 -c '
import json, sys
for line in open(sys.argv[1], encoding="utf-8"):
    r = json.loads(line)
    if r.get("class") == "slow":
        print(r.get("trace_id") or ""); break
' "${TRAFFIC_FILE}")"
  if [ -z "${tid}" ]; then
    add_result A1-03-slow-sql FAIL "慢查询流量无 trace_id（遥测降级？不允许取其他请求替代）"
  elif wait_spans "${tid}" 4; then
    sfile="${RUN_DIR}/spans-${tid}.jsonl"
    fetch_spans "${tid}" "${sfile}"
    if python3 - "${sfile}" <<'PYEOF'
import json, sys
spans = [json.loads(x) for x in open(sys.argv[1], encoding="utf-8") if x.strip()]
delay = [s for s in spans
         if s["SpanAttributes"].get("db.statement") == "SELECT demo_sleep_bounded($1)"]
item = [s for s in spans
        if s["SpanAttributes"].get("db.statement") == "SELECT id, name, price_cents FROM demo_items WHERE id = $1"]
ok = (delay and item
      and 2_000_000_000 <= delay[0]["Duration"] <= 4_000_000_000)
sys.exit(0 if ok else 1)
PYEOF
    then
      add_result A1-03-slow-sql PASS "慢 SQL Trace=${tid}：demo_sleep_bounded DB Span 时长落在 [2s,4s] 有界区间，语句指纹来源为常量"
    else
      add_result A1-03-slow-sql FAIL "慢 SQL Span 缺失/时长越界（证据 ${sfile}）"
    fi
  else
    add_result A1-03-slow-sql FAIL "慢查询 Trace 未入库（${VERIFY_POLL_S}s 有界等待后无数据）"
  fi

  # A1-04 应用异常：异常 Span 与目标 Trace 对应（非 WAF 403 冒充）
  tid="$(python3 -c '
import json, sys
for line in open(sys.argv[1], encoding="utf-8"):
    r = json.loads(line)
    if r.get("class") == "exception":
        print(r.get("trace_id") or ""); break
' "${TRAFFIC_FILE}")"
  local exc_status
  exc_status="$(python3 -c '
import json, sys
for line in open(sys.argv[1], encoding="utf-8"):
    r = json.loads(line)
    if r.get("class") == "exception":
        print(r.get("status") or ""); break
' "${TRAFFIC_FILE}")"
  if [ -z "${tid}" ]; then
    add_result A1-04-exception FAIL "异常流量无 trace_id（不允许伪造异常关联）"
  elif [ "${exc_status}" != "500" ]; then
    add_result A1-04-exception FAIL "异常场景响应码=${exc_status}（期望 500 合成响应；非 403 冒充）"
  elif wait_spans "${tid}" 4; then
    sfile="${RUN_DIR}/spans-${tid}.jsonl"
    fetch_spans "${tid}" "${sfile}"
    if python3 - "${sfile}" <<'PYEOF'
import json, sys
spans = [json.loads(x) for x in open(sys.argv[1], encoding="utf-8") if x.strip()]
err = [s for s in spans if s["StatusCode"] == "Error"]
exc = [s for s in spans if "exception" in (s.get("EventNames") or [])]
sys.exit(0 if (err and exc) else 1)
PYEOF
    then
      add_result A1-04-exception PASS "异常 Trace=${tid}：存在 Error Span 与 exception 事件（合成固定错误）"
    else
      add_result A1-04-exception FAIL "异常 Span/事件缺失（证据 ${sfile}）"
    fi
  else
    add_result A1-04-exception FAIL "异常 Trace 未入库（${VERIFY_POLL_S}s 有界等待后无数据）"
  fi

  # A1-05 脱敏护栏：合成 Bearer/Cookie 值不得出现在任何 Span 属性中
  if [ "${sampling_cfg}" = "demo-sampled.yaml" ]; then
    add_result A1-05-redaction SKIP "sampled 形态：脱敏护栏请求为正常流量按设计丢弃，CH 无可核对对象；脱敏核对以 keep-all 形态为准"
  else
  tid="$(python3 -c '
import json, sys
for line in open(sys.argv[1], encoding="utf-8"):
    r = json.loads(line)
    if r.get("class") == "redact":
        print(r.get("trace_id") or ""); break
' "${TRAFFIC_FILE}")"
  if [ -z "${tid}" ]; then
    add_result A1-05-redaction FAIL "脱敏护栏流量无 trace_id"
  elif wait_spans "${tid}" 4; then
    sfile="${RUN_DIR}/spans-${tid}.jsonl"
    fetch_spans "${tid}" "${sfile}"
    if grep -q 'demo-not-a-real-token-p1-01\|demo=redact-check' "${sfile}"; then
      add_result A1-05-redaction FAIL "敏感合成值出现在 Span 证据中（${sfile}）"
    else
      add_result A1-05-redaction PASS "合成 Authorization/Cookie 值未进入任何 Span 属性/事件"
    fi
  else
    add_result A1-05-redaction FAIL "脱敏护栏 Trace 未入库（无法完成核对，不臆断通过）"
  fi
  fi

  # A1-06 采样决策证据（仅 sampled 形态）：tail_sampling 决策计数器（v0.154.0 实测输出，
  # Development 稳定性）+ CH 地面真值。注意：exporter sent/failed 计数器在本版本与
  # clickhouse exporter 实际入库行为可能脱节（重试语义），仅作诊断不作判据。
  if [ "${sampling_cfg}" != "demo-sampled.yaml" ]; then
    add_result A1-06-not-sampled SKIP "当前采样配置为 ${sampling_cfg}（keep-all）；以 --sampling sampled 重启栈后执行"
  else
    local mfile="${RUN_DIR}/collector-metrics-snapshot.txt"
    curl -sS -m 10 "http://${COLLECTOR_METRICS_ADDR}/metrics" > "${mfile}" 2>/dev/null || true
    if [ ! -s "${mfile}" ]; then
      add_result A1-06-not-sampled BLOCKED "Collector 自监控不可达（${COLLECTOR_METRICS_ADDR}），无采样决策证据"
    else
      local received n_sampled n_dropped xfail
      received="$(grep '^otelcol_processor_tail_sampling_new_trace_id_received' "${mfile}" | awk '{s+=$NF} END {print s+0}' || true)"
      n_sampled="$(grep '^otelcol_processor_tail_sampling_global_count_traces_sampled{decision="sampled"' "${mfile}" | awk '{s+=$NF} END {print s+0}' || true)"
      n_dropped="$(grep '^otelcol_processor_tail_sampling_global_count_traces_sampled{decision="not_sampled"' "${mfile}" | awk '{s+=$NF} END {print s+0}' || true)"
      xfail="$(grep '^otelcol_exporter_send_failed_spans' "${mfile}" | awk '{s+=$NF} END {print s+0}' || true)"
      # 找一条正常 trace：应在 receiver 被接收但确定性不入库
      tid="$(python3 -c '
import json, sys
for line in open(sys.argv[1], encoding="utf-8"):
    r = json.loads(line)
    if r.get("class") == "normal" and r.get("via") == "direct":
        print(r.get("trace_id") or ""); break
' "${TRAFFIC_FILE}")"
      # 决策窗口：decision_wait 5s + batch 5s + 余量
      sleep 15
      local inch
      inch="$(ch_select "SELECT count() FROM apm.otel_traces WHERE TraceId='${tid}'" 2>/dev/null | tr -d ' \n')"
      if [ "${inch:-0}" != "0" ]; then
        add_result A1-06-not-sampled FAIL "sampled 形态下正常 Trace 竟入库（trace=${tid}），采样配置未生效？"
      elif [ -n "${tid}" ] && [ "${received:-0}" -gt 0 ] && [ "${n_dropped:-0}" -gt 0 ] && [ "${n_sampled:-0}" -gt 0 ]; then
        add_result A1-06-not-sampled PASS "NOT_SAMPLED_CONFIRMED：tail_sampling 决策计数 received=${received} / sampled=${n_sampled}（慢+异常保留）/ not_sampled=${n_dropped}，正常 Trace ${tid} 经决策窗口后 CH 查无（原始指标 ${mfile}）"
      else
        add_result A1-06-not-sampled BLOCKED "采样决策证据不足（received=${received:-?} sampled=${n_sampled:-?} not_sampled=${n_dropped:-?} trace=${tid:-none} ch_count=${inch:-?} send_failed=${xfail:-?}），如实标 UNKNOWN"
      fi
    fi
  fi

  # A1-07 网关联调（需 traffic 时提供 GATEWAY_BASE_URL）
  local gw_count
  gw_count="$(python3 -c '
import json, sys
n = 0
for line in open(sys.argv[1], encoding="utf-8"):
    r = json.loads(line)
    if r.get("via") == "gateway" and not r.get("skipped"):
        n += 1
print(n)
' "${TRAFFIC_FILE}")"
  if [ "${gw_count}" = "0" ]; then
    add_result A1-07-gateway SKIP "GATEWAY_NOT_CONFIGURED：traffic 未提供 GATEWAY_BASE_URL，攻击/网关联调未执行"
  else
    # 被阻断（403）请求不得产生应用 Span = 未到达源站的数据级证据；
    # 非 403（OBSERVE 透传）请求应能找到对应应用 Trace（同一 demo_request_id）
    # 凭据经环境继承（load_env 已 set -a 导出），不上 python 命令行
    if python3 - "${TRAFFIC_FILE}" "${CH_HTTP_ADDR}" "${VERIFY_POLL_S}" <<'PYEOF'
import json, os, subprocess, sys, time
traffic_path, ch_addr, poll_s = sys.argv[1], sys.argv[2], int(sys.argv[3])
ch_user = os.environ["DEMO_CH_ADMIN_USER"]
ch_key = os.environ["DEMO_CH_ADMIN_PASSWORD"]
def ch_count(reqid):
    q = ("SELECT count() FROM apm.otel_traces "
         f"WHERE SpanAttributes['demo.request_id'] = '{reqid}'")
    out = subprocess.run(["curl", "-sS", "-m", "20", f"http://{ch_addr}/",
                          "-H", f"X-ClickHouse-User: {ch_user}",
                          "-H", f"X-ClickHouse-Key: {ch_key}",
                          "--data-binary", q],
                         capture_output=True, text=True).stdout.strip()
    return int(out) if out.isdigit() else -1
fails = []
deadline = time.time() + poll_s
for line in open(traffic_path, encoding="utf-8"):
    r = json.loads(line)
    if r.get("via") != "gateway" or r.get("skipped") or not r.get("demo_request_id"):
        continue
    reqid, status = r["demo_request_id"], r.get("status")
    while True:
        n = ch_count(reqid)
        if status == 403:
            # 阻断：有界等待后仍为 0 才算「未到达源站」成立
            if n == 0:
                if time.time() >= deadline:
                    break
                time.sleep(3)
                continue
            fails.append(f"{reqid}: 403 阻断却存在应用 Span（{n} 条）")
            break
        else:
            # 透传（OBSERVE 命中或正常）：应出现应用 Span
            if n > 0:
                break
            if time.time() >= deadline:
                fails.append(f"{reqid}: status={status} 透传但无应用 Span")
                break
            time.sleep(3)
            continue
if fails:
    print("; ".join(fails), file=sys.stderr)
    sys.exit(1)
PYEOF
    then
      add_result A1-07-gateway PASS "网关流量 ${gw_count} 条核对一致：阻断无应用 Span（未达源站）、透传有可定位 Trace"
    else
      add_result A1-07-gateway FAIL "网关联调核对不一致（见上方明细；不伪造因果）"
    fi
  fi

  # A4-01~04 产品栈管理 API 对账（仅 --with-product run；A1 形态不涉及管理面）
  if [ "${COMPOSE_PRODUCT}" = "1" ]; then
    verify_a4
  fi

  # 尾声护栏：导出健康（startup canary 之后的 traffic 阶段若发生导出失败重试，
  # 基表可能重复/丢数，以上 PASS 可信度受损——必须显形，不臆断）
  local mfile_tail="${RUN_DIR}/collector-metrics-final.txt"
  curl -sS -m 10 "http://${COLLECTOR_METRICS_ADDR}/metrics" > "${mfile_tail}" 2>/dev/null || true
  if [ ! -s "${mfile_tail}" ]; then
    add_result A1-export-health BLOCKED "Collector 自监控不可达，导出健康无法核对"
  else
    local xfail_tail
    xfail_tail="$(grep '^otelcol_exporter_send_failed_spans' "${mfile_tail}" | awk '{s+=$NF} END {print s+0}' || true)"
    if [ "${xfail_tail:-0}" -gt 0 ] 2>/dev/null; then
      add_result A1-export-health FAIL "exporter send_failed_spans=${xfail_tail}（导出失败重试，基表可能重复/丢数；查 collector 日志与 ${mfile_tail}）"
    else
      add_result A1-export-health PASS "exporter 零失败重试（send_failed_spans=0，原始指标 ${mfile_tail}）"
    fi
  fi

  write_verify_outputs "${report}"
}

write_verify_outputs() { # $1 = report 路径；status.json + 中文报告；退出码汇总
  local report="$1" fails blocked
  printf '%s' "${VERIFY_RESULTS}" > "${RUN_DIR}/.status-rows.tmp"
  python3 - "${RUN_DIR}/status.json" "${RUN_DIR}/.status-rows.tmp" <<'PYEOF'
import json, os, sys
rows = []
with open(sys.argv[2], encoding="utf-8") as fh:
    for line in fh:
        line = line.rstrip("\n")
        if not line:
            continue
        tid, st, reason = line.split("\t", 2)
        rows.append({"id": tid, "status": st, "reason": reason})
doc = {"run_dir": sys.argv[1].rsplit("/", 1)[0], "results": rows}
with open(sys.argv[1], "w", encoding="utf-8") as fh:
    json.dump(doc, fh, ensure_ascii=False, indent=2)
    fh.write("\n")
os.remove(sys.argv[2])
PYEOF
  {
    echo "# P1-01 A1 演示断言报告"
    echo
    echo "- run_id: ${RUN_ID}"
    echo "- compose project: ${PROJECT}"
    echo "- 时间: $(date '+%Y-%m-%d %H:%M:%S %z')"
    echo
    echo "| 断言 | 状态 | 说明 |"
    echo "|---|---|---|"
    printf '%s' "${VERIFY_RESULTS}" | while IFS='	' read -r tid st reason; do
      [ -z "${tid}" ] && continue
      echo "| ${tid} | ${st} | ${reason} |"
    done
    echo
    echo "原始证据：traffic.jsonl、spans-<trace_id>.jsonl、collector-metrics-snapshot.txt（如有）、status.json。"
  } > "${report}"
  fails="$(printf '%s' "${VERIFY_RESULTS}" | awk -F'\t' '$2=="FAIL"{n++} END {print n+0}')"
  blocked="$(printf '%s' "${VERIFY_RESULTS}" | awk -F'\t' '$2=="BLOCKED"||$2=="SKIP"{n++} END {print n+0}')"
  log "断言完成：报告 ${report}"
  if [ "${fails}" -gt 0 ]; then
    exit 1
  elif [ "${blocked}" -gt 0 ]; then
    exit 3
  fi
  exit 0
}

# ---------- 清理 ----------
cmd_cleanup() {
  resolve_run
  log "清理本 run 资源（仅 project=${PROJECT}，清理前双标签归属校验）"
  if docker ps -a --filter "label=com.docker.compose.project=${PROJECT}" -q | grep -q .; then
    load_env
    if assert_ownership; then
      compose_cmd down -v --remove-orphans >/dev/null 2>&1 \
        || log "WARN: compose down 返回非零，证据目录保留: ${RUN_DIR}"
    else
      die "归属校验失败，拒绝清理；请人工核查 project=${PROJECT}"
    fi
  else
    log "project ${PROJECT} 无存活容器（可能已清理）"
  fi
  # 密码文件运行结束即删（证据不含凭据）；证据目录（traffic/verify/原始 Span）保留
  [ -f "${RUN_DIR}/env" ] && rm -f "${RUN_DIR}/env"
  # 授权私钥 / .lic / 会话 Cookie 同属运行时凭据，一并删除（含密码以外的会话材料）
  rm -f "${RUN_DIR}/lic-key.pem" "${RUN_DIR}/license.lic" \
        "${RUN_DIR}/lic-payload.bin" "${RUN_DIR}/lic-sig.bin" \
        "${RUN_DIR}"/cookies-*.txt 2>/dev/null || true
  [ -f "${RUNS_ROOT}/latest" ] && [ "$(cat "${RUNS_ROOT}/latest")" = "${RUN_ID}" ] && rm -f "${RUNS_ROOT}/latest"
  log "清理完成：容器/网络/卷已删除；证据目录保留 ${RUN_DIR}（env 密码文件/授权私钥/Cookie 已删）"
}

# ---------- 入口 ----------
cmd_preflight() {
  preflight_checks
}

cmd_startup() {
  preflight_checks
  stack_up
}

MODE_ARG=""   # mode / instrumentation 的位置参数

main() {
  local cmd="${1:-}"
  case "${cmd}" in
    preflight|startup|traffic|verify|cleanup|mode|instrumentation) ;;
    -h|--help|"") usage; [ -n "${cmd}" ] && exit 0 || exit 2 ;;
    *) echo "未知子命令: ${cmd}" >&2; usage >&2; exit 2 ;;
  esac
  shift
  while [ $# -gt 0 ]; do
    case "$1" in
      --run-id) RUN_ID="${2:?--run-id 需要参数}"; shift 2 ;;
      --sampling)
        [ "${2:-}" = "keep-all" ] || [ "${2:-}" = "sampled" ] \
          || die "--sampling 仅接受 keep-all|sampled"
        SAMPLING="$2"; shift 2 ;;
      --normal-count)
        case "${2:-}" in ''|*[!0-9]*) die "--normal-count 需为正整数" ;; esac
        NORMAL_COUNT="$2"; shift 2 ;;
      --with-product)
        [ "${cmd}" = "startup" ] || die "--with-product 仅对 startup 有意义"
        WITH_PRODUCT=1; shift ;;
      --wave)
        [ "${cmd}" = "traffic" ] || die "--wave 仅对 traffic 有意义"
        case "${2:-}" in main|protect|gwonly) ;; *) die "--wave 仅接受 main|protect|gwonly" ;; esac
        WAVE="$2"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      -*)
        die "未知参数: $1" ;;
      *)
        # mode / instrumentation 的位置参数
        if [ "${cmd}" = "mode" ] || [ "${cmd}" = "instrumentation" ]; then
          [ -z "${MODE_ARG}" ] || die "多余的位置参数: $1"
          MODE_ARG="$1"; shift
        else
          die "未知参数: $1"
        fi ;;
    esac
  done
  case "${cmd}" in
    startup)
      # startup 总是新建 run；--sampling 仅对 startup 有意义
      [ -z "${RUN_ID}" ] || die "startup 不接受 --run-id（每次运行生成唯一 run_id）"
      ;;
    preflight)
      [ "${SAMPLING}" = "keep-all" ] || die "preflight 不接受 --sampling"
      [ "${WITH_PRODUCT}" = "0" ] || die "preflight 不接受 --with-product"
      ;;
    traffic|verify|cleanup)
      [ "${SAMPLING}" = "keep-all" ] || die "${cmd} 不接受 --sampling（采样形态在 startup 时冻结于 env 文件）"
      ;;
    mode|instrumentation)
      [ -n "${MODE_ARG}" ] || die "${cmd} 需要位置参数（见 -h）"
      ;;
  esac
  "cmd_${cmd}"
}

main "$@"
