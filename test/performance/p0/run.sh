#!/usr/bin/env bash
# P0-02 同配置安全与性能基准运行器（S2 新增）
#
# 子命令（任务书 §8）：
#   preflight   --plan F   隔离与预检（§3.1），不起栈
#   smoke       --plan F   短时运行，只证明工具可运行，不产生容量结论
#   correctness --plan F   语料回放 + 逐样本真值（§5）
#   matrix      --plan F   七模式 × 负载阶梯 × 重复（§4/§6.1）
#   soak        --plan F   七模式稳定性 + combined_protect 72h 长稳（§6.3）
#   recovery    --plan F   故障注入与恢复时限核验（§6.3）
#   regression  --plan F   P1-04 规则/模型回归。plan 登记
#                          environment.stage5_env_descriptor 时真实栈回放
#                          （R2）；未登记时执行层明确 BLOCKED/
#                          ENVIRONMENT_UNAVAILABLE 并非零退出，不假执行
#   compare     --baseline R --candidate R   P1-04 前后版本逐例比较（只读
#                          两个已完成证据目录，不重新执行、不猜测期望）
#
# 隔离铁律（§3.1 / §10）：
#   - 每次运行唯一 run_id 与 compose project（p0bench-<run_id>）；
#   - 停止/删除/重建/故障注入前必须同时校验 project 标签与 run_id 标签；
#   - 禁止全局 prune、禁止操作任何非本 project 资源；
#   - trap 清理仅限本 run_id 资源，清理前校验归属；证据目录保留；
#   - 密码经本 run 环境文件注入（0600），任何输出不含环境变量全集、
#     原始 Authorization 或完整 docker inspect 数据。
#
# JWT-18 配对实验（S3 起接线，计划声明 config.jwt_pair 时启用）：
#   - 配对 profile jwt_off / jwt_protect：同构建同基础配置（waf=Off、
#     api_mode=OFF），仅 JWT 信任链 OFF vs PROTECT（静态 JWKS）；不混入
#     七模式主基线，主基线切换时同步把 JWT 压回 OFF 防配对残留污染；
#   - RSA 测试密钥由本运行现场生成到 $RUN_DIR/jwt/（0600，openssl），不入库
#     不入 git；Token 现场签发并经 0600 临时头文件以 curl -H @file 注入，
#     不上命令行；运行结束删除私钥与头文件（证据不含密钥材料），公钥 JWKS
#     保留供审计；
#   - 前置条件：基准应用（config.jwt_pair.app_code）已在基准栈接入；找不到
#     即该轮 BLOCKED（BENCH-04 纪律），不伪造结果。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/deployment/docker-compose.p0-benchmark.yml"
EVIDENCE_ROOT="${P0B_EVIDENCE_ROOT:-$REPO_ROOT/docs/evidence/benchmarks}"
# P1-04 回归（严格增量）：工具与语料位于 test/regression/p1，证据根独立
REG_DIR="$REPO_ROOT/test/regression/p1"
REG_PROFILES_DIR="$REG_DIR/profiles"
REG_EVIDENCE_ROOT="$REPO_ROOT/docs/evidence/regressions"
HEALTH_TIMEOUT_S=300

RUN_ID=""
PROJECT=""
RUN_DIR=""
ENV_FILE=""
PLAN_FILE=""
BASELINE_ID=""
CANDIDATE_ID=""
STACK_UP=0

log()  { printf '[p0bench %s] %s\n' "$(date '+%H:%M:%S')" "$*"; }
die()  { echo "ERROR: $*" >&2; exit 1; }

p0b() { PYTHONPATH="$SCRIPT_DIR" python3 -m p0bench.cli "$@"; }

# p1reg CLI（P1-04 R1）：PYTHONPATH 同时挂 P1 与 P0 工具目录（复用 isolation/词表）
p1reg() { PYTHONPATH="$REG_DIR:$SCRIPT_DIR" python3 -m p1reg.cli "$@"; }

json_get() { # json_get <file> <dotted.path>
  python3 - "$1" "$2" <<'PYEOF'
import json, sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
cur = doc
for part in sys.argv[2].split("."):
    if isinstance(cur, dict) and part in cur:
        cur = cur[part]
    else:
        sys.exit(3)
if isinstance(cur, (dict, list)):
    print(json.dumps(cur, ensure_ascii=False))
elif isinstance(cur, bool):
    print("true" if cur else "false")
else:
    print(cur)
PYEOF
}

usage() {
  cat <<'EOF'
用法: bash test/performance/p0/run.sh <子命令> --plan <run-plan.json>

子命令:
  preflight    隔离与预检（§3.1）：计划结构、语料哈希、环境标识、端口、时钟、工具链
  smoke        短时 smoke：只证明工具可运行，结果只能标记 smoke
  correctness  语料回放与逐样本真值（§5），需完整 run-plan（§7）
  matrix       七模式 × 负载阶梯 × ≥3 重复（§4/§6.1），需完整 run-plan
  soak         七模式稳定性 + combined_protect 72 小时长稳（§6.3），需完整 run-plan
  recovery     故障注入与恢复时限核验（§6.3），需完整 run-plan
  regression   P1-04 规则/模型回归（--plan 为 kind=p1_regression_run_plan 的计划）：
               语料 schema v1 校验 + 内容哈希自校验 + 确定性回放计划 + 证据骨架。
               R1/S1 为工具层：隔离栈未接线前执行层一律
               status=BLOCKED/reason=ENVIRONMENT_UNAVAILABLE 并非零退出，不假执行
  compare      P1-04 前后版本逐例比较：--baseline <run-id> --candidate <run-id>
               只读 docs/evidence/regressions/ 下两个已完成证据目录配对，
               不重新执行、不猜测期望；结果写入新的 compare-<run-id> 目录；
               FAIL/NOT_PASSED/证据校验失败均非零退出

公共选项:
  --plan FILE      预登记计划（P0 见 run-plan.example.json；P1 回归见
                   test/regression/p1/run-plan.example.json）
  --baseline ID    compare 专用：baseline 证据目录 run-id
  --candidate ID   compare 专用：candidate 证据目录 run-id
  -h, --help       本帮助

说明: correctness/matrix/soak/recovery 在计划缺必填字段时拒绝启动；
      smoke 可带缺字段计划运行，但报告只能标记 smoke。
      matrix/soak/recovery 还要求 P0B_FORMAL_ENVIRONMENT_READY=1 且
      P0B_FORMAL_ENV_ID 与冻结计划 environment.environment_id 一致；否则
      生成 BLOCKED/ENVIRONMENT_UNAVAILABLE 证据并返回 3，不启动 Docker 栈。
      计划声明 config.jwt_pair 时，correctness/matrix/soak 在七模式主基线之外
      追加 JWT-18 配对 profile（jwt_off/jwt_protect，静态 JWKS + 运行期测试密钥）。
EOF
}

gen_run_id() {
  local rand
  rand="$(head -c 3 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  printf '%s-%s' "$(date '+%Y%m%dT%H%M%S')" "$rand"
}

machine_id() {
  if [ -r /etc/machine-id ]; then
    head -c 64 /etc/machine-id
  elif command -v ioreg >/dev/null 2>&1; then
    ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null \
      | awk -F'"' '/IOPlatformUUID/{print $4}' | head -1
  else
    hostname
  fi
}

new_run() {
  RUN_ID="$(gen_run_id)"
  PROJECT="p0bench-$RUN_ID"
  RUN_DIR="$EVIDENCE_ROOT/$RUN_ID"
  mkdir -p "$RUN_DIR"
  ENV_FILE="$RUN_DIR/env"
  # 冻结计划副本（只读），防止运行后被原地修改（§7）
  cp "$PLAN_FILE" "$RUN_DIR/plan.json"
  chmod 0444 "$RUN_DIR/plan.json"
  log "run_id=$RUN_ID project=$PROJECT run_dir=$RUN_DIR"
}

write_manifest() {
  python3 - "$RUN_DIR/manifest.json" "$RUN_ID" "$PROJECT" "$PLAN_FILE" "$REPO_ROOT" <<'PYEOF'
import json, platform, subprocess, sys
out, run_id, project, plan_path, repo_root = sys.argv[1:6]
def safe(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=15).stdout.strip()
    except Exception:
        return "unavailable"
doc = {
    "run_id": run_id,
    "compose_project": project,
    "plan_file": plan_path,
    "host": {"os": platform.platform(), "machine": platform.machine()},
    "git_commit": safe(["git", "-C", repo_root, "rev-parse", "HEAD"]),
    "docker_version": safe(["docker", "version", "--format", "{{.Server.Version}}"]),
    "compose_version": safe(["docker", "compose", "version", "--short"]),
    "loadgen_versions": {},
}
with open(out, "w", encoding="utf-8") as fh:
    json.dump(doc, fh, ensure_ascii=False, indent=2, sort_keys=True)
    fh.write("\n")
PYEOF
}

set_status() { # set_status <id> <status> [reason] [--optional]
  local tid="$1" st="$2" reason="${3:-}" opt=""
  [ "${4:-}" = "--optional" ] && opt="--optional"
  p0b set-status --run-dir "$RUN_DIR" --test-id "$tid" --status "$st" \
      --reason "$reason" --evidence "$RUN_DIR" $opt >/dev/null
}

formal_environment_gate() { # $1 = mandatory status id, $2 = command scope
  local tid="$1" scope="${2:-}" rc=0
  p0b formal-gate --plan "$RUN_DIR/plan.json" \
      --ready "${P0B_FORMAL_ENVIRONMENT_READY:-0}" \
      --environment-id "${P0B_FORMAL_ENV_ID:-}" \
      --evidence "$RUN_DIR/formal-environment.json" || rc=$?
  case "$rc" in
    0)
      log "正式环境门禁通过（环境 ID 与冻结计划一致）"
      ;;
    3)
    set_status "$tid" BLOCKED \
        "ENVIRONMENT_UNAVAILABLE：缺少正式隔离环境的显式就绪声明或环境 ID 不匹配"
      if [ -n "$scope" ]; then
        set_status "${scope}:formal_environment" BLOCKED \
          "ENVIRONMENT_UNAVAILABLE：缺少正式隔离环境的显式就绪声明或环境 ID 不匹配"
      fi
      PYTHONPATH="$SCRIPT_DIR" python3 "$SCRIPT_DIR/report.py" --run-dir "$RUN_DIR" >/dev/null || true
      log "正式环境门禁阻断；未启动 Docker 栈，证据: $RUN_DIR"
      exit 3
      ;;
    *)
      die "正式环境门禁执行失败（退出码 $rc）"
      ;;
  esac
}

make_env_file() {
  local rand24 rand32
  rand24="$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  rand32="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  umask 077
  cat > "$ENV_FILE" <<EOF
P0B_RUN_ID=$RUN_ID
POSTGRES_PASSWORD=$rand24
VALKEY_PASSWORD=$rand24
INITIAL_ADMIN_PASSWORD=Bench-$rand24
JIUZHANG_MASTER_KEY=$rand32
EOF
  chmod 0600 "$ENV_FILE"
}

compose_cmd() {
  docker compose -p "$PROJECT" -f "$COMPOSE_FILE" --env-file "$ENV_FILE" "$@"
}

assert_project_absent() {
  if docker ps -a --filter "label=com.docker.compose.project=$PROJECT" -q | grep -q .; then
    die "compose project $PROJECT 已存在（run_id 冲突），拒绝复用"
  fi
}

assert_ownership() {
  # 容器：ps --format 仅取名称+标签（不输出完整 inspect）
  docker ps -a --filter "label=com.docker.compose.project=$PROJECT" \
      --format '{{.Names}}	{{.Labels}}' | p0b owns --run-id "$RUN_ID" >/dev/null \
    || die "归属校验失败：$PROJECT 存在不属于本 run_id 的容器，禁止操作"
  # 卷：逐个取标签行（仅 .Labels，不输出 inspect 全量）
  local vol
  while read -r vol; do
    [ -z "$vol" ] && continue
    printf '%s\t%s\n' "$vol" "$(docker volume inspect -f '{{.Labels}}' "$vol")" 
  done < <(docker volume ls --filter "label=com.docker.compose.project=$PROJECT" --format '{{.Name}}') \
    | python3 - "$RUN_ID" <<'PYEOF'
import re, sys
run_id = sys.argv[1]
ok_any = False
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    ok_any = True
    # docker volume inspect -f '{{.Labels}}' 输出形如 map[k:v ...]
    if f"p0bench.run_id:{run_id}" not in line:
        print(f"NOT_OWNED volume: {line.split(chr(9))[0]}", file=sys.stderr)
        sys.exit(1)
sys.exit(0)
PYEOF
}

cleanup() {
  set +e
  if [ "$STACK_UP" = "1" ] && [ -n "$PROJECT" ]; then
    log "清理本 run 资源（仅 project=${PROJECT}，清理前校验归属）"
    if assert_ownership; then
      compose_cmd down -v --remove-orphans >/dev/null 2>&1 \
        || log "WARN: compose down 返回非零，证据目录保留: $RUN_DIR"
    else
      log "WARN: 归属校验失败，跳过清理；请人工核查 project=$PROJECT"
    fi
  fi
  # 证据目录一律保留；环境文件含密码，运行结束删除（证据不含凭据）
  [ -n "$ENV_FILE" ] && rm -f "$ENV_FILE"
  # JWT 测试私钥与已签发 Token 头文件含密钥材料，运行结束删除；
  # 公钥 JWKS（jwt/jwks.json）非秘密，保留供审计/溯源
  if [ -n "$RUN_DIR" ] && [ -d "$RUN_DIR/jwt" ]; then
    rm -f "$RUN_DIR/jwt/key.pem" "$RUN_DIR/jwt/authorization.header" \
        "$RUN_DIR/jwt/authorization-tampered.header"
  fi
}

# ---------- 预检（§3.1） ----------
preflight_checks() { # $1 = strict|lenient
  local mode="$1" failed=0
  log "预检开始（mode=${mode}）"

  if ! p0b validate-plan --plan "$RUN_DIR/plan.json"; then
    if [ "$mode" = strict ]; then
      die "run-plan 不满足 §7 预登记契约，拒绝启动"
    fi
    log "WARN: run-plan 不完整（smoke 模式允许，结果只能标记 smoke）"
  fi

  # 语料哈希
  local corpus_path corpus_want corpus_actual
  corpus_path="$(json_get "$RUN_DIR/plan.json" corpus.manifest_path || true)"
  corpus_want="$(json_get "$RUN_DIR/plan.json" corpus.manifest_sha256 || true)"
  if [ -n "$corpus_path" ] && [ -f "$REPO_ROOT/$corpus_path" ]; then
    corpus_actual="$(p0b corpus-hash --manifest "$REPO_ROOT/$corpus_path")"
    if [ "$corpus_actual" != "$corpus_want" ]; then
      die "语料哈希不匹配（登记 ${corpus_want}，实际 ${corpus_actual}），运行无效"
    fi
    log "语料哈希一致: ${corpus_actual:0:16}…"
  else
    [ "$mode" = strict ] && die "语料文件缺失或 plan 未登记语料"
    log "WARN: 语料缺失（smoke 继续）"
  fi

  # 工具链与版本采集（压测器版本必须进入 manifest）
  local tool
  tool="$(json_get "$RUN_DIR/plan.json" load.loadgen.tool 2>/dev/null || echo ab)"
  command -v docker >/dev/null || die "docker 不可用"
  docker compose version >/dev/null 2>&1 || die "docker compose v2 不可用"
  command -v python3 >/dev/null || die "python3 不可用"
  command -v curl >/dev/null || die "curl 不可用"
  # JWT-18 配对实验（计划声明 config.jwt_pair）：密钥生成/RS256 签名依赖 openssl
  if json_get "$RUN_DIR/plan.json" config.jwt_pair.app_code >/dev/null 2>&1; then
    if ! command -v openssl >/dev/null; then
      [ "$mode" = strict ] && die "计划声明 JWT 配对实验但 openssl 不可用（密钥生成/签名需要）"
      log "WARN: openssl 不可用，JWT 配对 profile 将 BLOCKED（smoke 继续）"
    else
      log "JWT 配对实验已声明（app_code=$(json_get "$RUN_DIR/plan.json" config.jwt_pair.app_code)），openssl 可用"
    fi
  fi
  case "$tool" in
    ab)  command -v ab  >/dev/null || die "计划登记的压测器 ab 不可用" ;;
    wrk) command -v wrk >/dev/null || die "计划登记的压测器 wrk 不可用" ;;
    k6)  command -v k6  >/dev/null || die "计划登记的压测器 k6 不可用" ;;
  esac
  local ab_ver curl_ver
  ab_ver="$(ab -V 2>&1 | head -1 || true)"
  curl_ver="$(curl --version 2>/dev/null | head -1 || true)"
  PYTHONPATH="$SCRIPT_DIR" python3 "$SCRIPT_DIR/collect.py" versions --run-dir "$RUN_DIR" \
      --tool ab --version-text "$ab_ver" >/dev/null
  PYTHONPATH="$SCRIPT_DIR" python3 "$SCRIPT_DIR/collect.py" versions --run-dir "$RUN_DIR" \
      --tool curl --version-text "$curl_ver" >/dev/null
  log "压测器: plan=$tool; 已采集版本 ab/curl 入 manifest"

  # 环境唯一标识（§3.1.4）
  local eid actual_fp
  eid="$(json_get "$RUN_DIR/plan.json" environment.environment_id 2>/dev/null || true)"
  actual_fp="$(p0b env-fingerprint --machine-id "$(machine_id)" --hostname "$(hostname -s)")"
  if [ "$eid" != "$actual_fp" ]; then
    if [ "$mode" = strict ]; then
      die "环境唯一标识不符（登记=$eid 实际=${actual_fp}），拒绝在非登记环境运行正式测量"
    fi
    log "WARN: 环境标识不符（登记=$eid 实际=${actual_fp}），smoke 结果仅标记 smoke"
  else
    log "环境标识一致"
  fi

  # 端口占用（§3.1.6）：仅检查显式指定的 P0B_*_PORT；缺省为随机端口无冲突面
  local var port
  for var in P0B_POSTGRES_PORT P0B_VALKEY_PORT P0B_API_PORT P0B_GATEWAY_PORT P0B_SITE_HTTP_PORT P0B_SITE_HTTPS_PORT; do
    port="${!var:-}"
    [ -z "$port" ] && continue
    if ! PYTHONPATH="$SCRIPT_DIR" python3 -c \
        "import sys; from p0bench.isolation import is_port_free; sys.exit(0 if is_port_free(int(sys.argv[1])) else 1)" "$port"; then
      die "端口 $port（${var}）已被占用，停止并标记无效运行"
    fi
  done
  log "端口检查通过（未显式指定的端口由 Docker 随机分配于 127.0.0.1）"

  # 时钟（§3.1.6）：宿主机时钟来源记录；容器时钟偏差在起栈后核验
  date -u '+UTC %Y-%m-%dT%H:%M:%SZ' > "$RUN_DIR/clock-host.txt"
  log "宿主机时钟已记录；容器时钟偏差在起栈后核验"

  # 登记目标格式校验 + 逃逸检查演示：登记地址必须可解析且不带凭据
  local targets
  targets="$(json_get "$RUN_DIR/plan.json" environment.isolation.registered_targets 2>/dev/null || echo '[]')"
  python3 - "$targets" <<'PYEOF' || die "登记目标含非法项"
import json, sys
from urllib.parse import urlsplit
for t in json.loads(sys.argv[1]):
    if not isinstance(t, str) or "://" in t or "@" in t or not t.strip():
        print(f"非法登记目标: {t!r}", file=sys.stderr)
        sys.exit(1)
PYEOF

  [ "$failed" = "0" ] || die "预检失败"
  log "预检通过（mode=${mode}）"
}

# ---------- 栈生命周期 ----------
stack_up() {
  make_env_file
  assert_project_absent
  log "构建并启动隔离栈 project=$PROJECT"
  compose_cmd build --quiet >/dev/null
  compose_cmd up -d >/dev/null
  STACK_UP=1

  local deadline=$(( $(date +%s) + HEALTH_TIMEOUT_S ))
  while :; do
    local bad
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
    [ "$bad" = "0" ] && break
    [ "$(date +%s)" -ge "$deadline" ] && die "栈健康等待超时（${HEALTH_TIMEOUT_S}s）"
    sleep 3
  done
  log "栈已健康"

  # 起栈后时钟核验：网关容器与宿主机 epoch 偏差
  local max_skew host_ts gw_ts skew
  max_skew="$(json_get "$RUN_DIR/plan.json" environment.clock.max_skew_ms 2>/dev/null || echo 1000)"
  host_ts="$(date +%s)"
  gw_ts="$(compose_cmd exec -T gateway date +%s 2>/dev/null | tr -dc '0-9' || true)"
  if [ -n "$gw_ts" ]; then
    skew=$(( (host_ts - gw_ts) * 1000 )); [ $skew -lt 0 ] && skew=$(( -skew ))
    echo "$skew" > "$RUN_DIR/clock-skew-ms.txt"
    if [ "$skew" -gt "$max_skew" ]; then
      die "时钟偏差 ${skew}ms 超过 plan 冻结值 ${max_skew}ms，运行无效"
    fi
    log "时钟偏差 ${skew}ms ≤ ${max_skew}ms"
  fi
}

port_of() { compose_cmd port "$1" "$2" 2>/dev/null | head -1; }

allowed_targets() {
  # 本 project 的 127.0.0.1 发布端口 + 计划登记目标
  local out="" p
  for spec in "gateway 8080" "gateway 81" "api 8080"; do
    p="$(port_of $spec)" || true
    [ -n "$p" ] && out="$out --allow $p"
  done
  python3 - "$RUN_DIR/plan.json" <<'PYEOF'
import json, sys
try:
    plan = json.load(open(sys.argv[1], encoding="utf-8"))
    for t in plan["environment"]["isolation"]["registered_targets"]:
        print(f" --allow {t}", end="")
except Exception:
    pass
PYEOF
  echo "$out" | tr -s ' '
}

require_target_allowed() { # $1=url
  local allow
  allow="$(allowed_targets)"
  # shellcheck disable=SC2086
  p0b check-target --url "$1" $allow >/dev/null || die "目标被拒绝（§3.1）: $1"
}

# ---------- 管理面登录与模式切换 ----------
api_login() { # 打印 CSRF；cookie 存 $RUN_DIR/cookies.txt（0600）
  local api_port api_url capid capcode csrf
  api_port="$(port_of api 8080)" || die "无法取得 api 端口"
  api_url="http://$api_port"
  require_target_allowed "$api_url/api/v1/health"
  capid="$(curl -s "$api_url/api/v1/auth/captcha" \
      | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['captcha_id'])" 2>/dev/null)"
  [ -n "$capid" ] || die "captcha_id 获取失败"
  # 验证码仅从本 project 的 valkey 读取（归属已由 assert_ownership 保证）
  assert_ownership
  local vpw
  vpw="$(grep '^VALKEY_PASSWORD=' "$ENV_FILE" | cut -d= -f2)"
  capcode="$(compose_cmd exec -T valkey valkey-cli -a "$vpw" --no-auth-warning \
      GET "jiuzhang:captcha:$capid" 2>/dev/null | tr -d '\r')"
  [ -n "$capcode" ] || die "验证码读取失败"
  local apw
  apw="$(grep '^INITIAL_ADMIN_PASSWORD=' "$ENV_FILE" | cut -d= -f2)"
  umask 077
  csrf="$(curl -s -c "$RUN_DIR/cookies.txt" -X POST "$api_url/api/v1/auth/login" \
      -H 'Content-Type: application/json' \
      -d "{\"username\":\"jiuzhang_admin\",\"password\":\"$apw\",\"captcha_id\":\"$capid\",\"captcha_code\":\"$capcode\"}" \
      | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['csrf_token'])" 2>/dev/null)"
  [ -n "$csrf" ] || die "管理面登录失败"
  chmod 0600 "$RUN_DIR/cookies.txt"
  echo "$csrf"
}

# ---------- JWT-18 配对实验支撑（计划声明 config.jwt_pair 时启用） ----------
jwt_pair_declared() { json_get "$RUN_DIR/plan.json" config.jwt_pair.app_code >/dev/null 2>&1; }

jwt_pair_kid() { json_get "$RUN_DIR/plan.json" config.jwt_pair.kid 2>/dev/null || echo "p0bench-jwt-test-key"; }

jwt_setup_keys() {
  # 本 run 现场生成专用 RSA 测试密钥（0600，不入库不入 git）；公钥 JWKS 非秘密，保留供审计
  mkdir -p "$RUN_DIR/jwt"
  chmod 0700 "$RUN_DIR/jwt"
  if [ ! -f "$RUN_DIR/jwt/key.pem" ]; then
    umask 077
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
        -out "$RUN_DIR/jwt/key.pem" 2>/dev/null || return 1
    chmod 0600 "$RUN_DIR/jwt/key.pem"
    log "JWT 测试密钥已现场生成（run 目录 0600，运行结束即删）"
  fi
  p0b jwt-jwks --key "$RUN_DIR/jwt/key.pem" --kid "$(jwt_pair_kid)" \
      > "$RUN_DIR/jwt/jwks.json" || return 1
  chmod 0644 "$RUN_DIR/jwt/jwks.json"
}

jwt_mint_headers() {
  # 现场签发有效/篡改签名两份 Authorization 头文件（0600）；Token 不上命令行
  local iss aud ttl
  iss="$(json_get "$RUN_DIR/plan.json" config.jwt_pair.issuer)" || return 1
  aud="$(json_get "$RUN_DIR/plan.json" config.jwt_pair.audience)" || return 1
  ttl="$(json_get "$RUN_DIR/plan.json" config.jwt_pair.token_ttl_seconds 2>/dev/null || echo 3600)"
  p0b jwt-mint --key "$RUN_DIR/jwt/key.pem" --kid "$(jwt_pair_kid)" \
      --issuer "$iss" --audience "$aud" --subject "p0bench-user" --ttl "$ttl" \
      --out-header "$RUN_DIR/jwt/authorization.header" \
      --tamper-out-header "$RUN_DIR/jwt/authorization-tampered.header" >/dev/null || return 1
  chmod 0600 "$RUN_DIR/jwt/authorization.header" "$RUN_DIR/jwt/authorization-tampered.header"
}

jwt_resolve_app_id() { # 打印应用 ID（按 config.jwt_pair.app_code 精确匹配）；无匹配打印空串
  local api_port api_url code
  code="$(json_get "$RUN_DIR/plan.json" config.jwt_pair.app_code)" || return 1
  api_port="$(port_of api 8080)" || return 1
  api_url="http://$api_port"
  curl -s -b "$RUN_DIR/cookies.txt" "$api_url/api/v1/applications?keyword=$code" \
    | python3 -c "
import json, sys
items = (json.load(sys.stdin).get('data') or {}).get('items') or []
hit = [i for i in items if i.get('code') == sys.argv[1]]
print(hit[0]['id'] if hit else '')" "$code"
}

jwt_apply_mode() { # $1=OFF|PROTECT：PUT 草稿（乐观锁）+ 发布 + 生效核对；失败返回非零
  local mode="$1" api_port api_url csrf app_id cur_ver body cur_mode
  api_port="$(port_of api 8080)" || return 1
  api_url="http://$api_port"
  csrf="$(api_login)" || return 1
  app_id="$(jwt_resolve_app_id)" || return 1
  [ -n "$app_id" ] || {
    log "WARN: JWT 配对：未找到应用（config.jwt_pair.app_code）；请先完成基准站点接入"
    return 1
  }
  cur_ver="$(curl -s -b "$RUN_DIR/cookies.txt" \
      "$api_url/api/v1/applications/$app_id/jwt-trust-policy" \
      | python3 -c "import json,sys; print((json.load(sys.stdin).get('data',{}).get('policy') or {}).get('version',0))" 2>/dev/null)"
  [ -n "$cur_ver" ] || return 1
  if [ "$mode" = "PROTECT" ]; then
    body="$(python3 - "$RUN_DIR/plan.json" "$RUN_DIR/jwt/jwks.json" "$cur_ver" "$RUN_ID" <<'PYEOF'
import json, sys
plan_path, jwks_path, cur_ver, run_id = sys.argv[1:5]
pair = (json.load(open(plan_path, encoding="utf-8")).get("config") or {}).get("jwt_pair") or {}
sel = pair.get("selector") or {}
jwks = open(jwks_path, encoding="utf-8").read().strip()
body = {
    "mode": "PROTECT",
    "expected_version": int(cur_ver),
    "selectors": [{
        "methods": sel.get("methods") or ["GET", "POST"],
        "path_exact": sel.get("path_exact") or "",
        "path_prefix": sel.get("path_prefix") or "/",
        "token_required": False,
    }],
    "issuers": [{
        "issuer": pair["issuer"],
        "audiences": [pair["audience"]],
        "algorithms": ["RS256"],
        "key_source": {"type": "STATIC_JWKS", "jwks": jwks},
        "clock_skew_seconds": 30,
        "tenant_claim": "",
    }],
    "reason": f"P0-02 JWT-18 配对实验（run_id={run_id}；运行期本地生成测试密钥）",
}
print(json.dumps(body, ensure_ascii=False))
PYEOF
)" || return 1
  else
    body="{\"mode\":\"OFF\",\"expected_version\":$cur_ver,\"selectors\":[],\"issuers\":[],\"reason\":\"P0-02 JWT-18 配对实验 jwt_off/基线归位（run_id=$RUN_ID）\"}"
  fi
  curl -s -o /dev/null -b "$RUN_DIR/cookies.txt" -X PUT \
      "$api_url/api/v1/applications/$app_id/jwt-trust-policy" \
      -H 'Content-Type: application/json' -H "X-CSRF-Token: $csrf" -d "$body" || return 1
  # 发布走既有 gateway-config 发布通道（同一发布入口，jwt_trust 段随整站配置下发）
  curl -s -o /dev/null -b "$RUN_DIR/cookies.txt" -X POST "$api_url/api/v1/api-security/policy/publish" \
      -H 'Content-Type: application/json' -H "X-CSRF-Token: $csrf" -d '{}' || return 1
  sleep 2
  cur_mode="$(curl -s -b "$RUN_DIR/cookies.txt" \
      "$api_url/api/v1/applications/$app_id/jwt-trust-policy" \
      | python3 -c "import json,sys; print((json.load(sys.stdin).get('data',{}).get('policy') or {}).get('mode',''))" 2>/dev/null)"
  [ "$cur_mode" = "$mode" ] || { log "WARN: jwt_trust 未生效（期望=$mode 实际=${cur_mode}）"; return 1; }
  # 有效配置差异快照（仅存哈希；公钥非秘密，Token/私钥不出现）
  curl -s -b "$RUN_DIR/cookies.txt" "$api_url/api/v1/applications/$app_id/jwt-trust-policy" \
      | python3 -c "import hashlib,sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())" \
      > "$RUN_DIR/config-diff-jwt-$mode.sha256"
  log "jwt_trust=$mode 已发布并验证生效（app_id=$app_id）"
}

switch_profile() { # $1=profile_id；失败即返回非零（BENCH-04：该轮无效）
  local profile="$1" waf api_mode jwt_mode=""
  case "$profile" in
    proxy)             waf=Off;            api_mode=OFF ;;
    waf_observe)       waf=DetectionOnly;  api_mode=OFF ;;
    waf_protect)       waf=On;             api_mode=OFF ;;
    api_observe)       waf=Off;            api_mode=OBSERVE ;;
    api_protect)       waf=Off;            api_mode=PROTECT ;;
    combined_observe)  waf=DetectionOnly;  api_mode=OBSERVE ;;
    combined_protect)  waf=On;             api_mode=PROTECT ;;
    # JWT-18 配对：同构建同基础配置，仅 JWT 信任链 OFF vs PROTECT（静态 JWKS）
    jwt_off)           waf=Off;            api_mode=OFF; jwt_mode=OFF ;;
    jwt_protect)       waf=Off;            api_mode=OFF; jwt_mode=PROTECT ;;
    *) return 1 ;;
  esac
  # 声明 JWT 配对后，七模式主基线切换同步把 JWT 信任链压回 OFF：
  # 主基线不混入 JWT（§4），防止配对 PROTECT 残留污染后续基线轮次
  if [ -z "$jwt_mode" ] && jwt_pair_declared; then jwt_mode=OFF; fi
  # 配对 profile 先备好密钥/Token 头文件（签发失败即该轮无效，不进入回放）
  case "$profile" in
    jwt_off|jwt_protect)
      jwt_setup_keys || { log "WARN: profile=$profile JWT 密钥准备失败"; return 1; }
      jwt_mint_headers || { log "WARN: profile=$profile JWT Token 签发失败"; return 1; }
      ;;
  esac
  # WAF 模式：重建本网关容器（env 切换），仅作用本 project
  assert_ownership || return 1
  P0B_SEC_RULE_ENGINE="$waf" compose_cmd up -d --no-deps --force-recreate gateway >/dev/null || return 1
  # API 模式：管理面策略 PUT + 发布，并核对生效值（节点回执前不算切换完成）
  local api_port api_url csrf cur
  api_port="$(port_of api 8080)" || return 1
  api_url="http://$api_port"
  csrf="$(api_login)" || return 1
  curl -s -o /dev/null -b "$RUN_DIR/cookies.txt" -X PUT "$api_url/api/v1/api-security/policy" \
      -H 'Content-Type: application/json' -H "X-CSRF-Token: $csrf" \
      -d "{\"mode\":\"$api_mode\"}" || return 1
  curl -s -o /dev/null -b "$RUN_DIR/cookies.txt" -X POST "$api_url/api/v1/api-security/policy/publish" \
      -H 'Content-Type: application/json' -H "X-CSRF-Token: $csrf" -d '{}' || return 1
  sleep 2
  cur="$(curl -s -b "$RUN_DIR/cookies.txt" "$api_url/api/v1/api-security/policy" \
      | python3 -c "import json,sys; print(json.load(sys.stdin)['data'].get('mode',''))" 2>/dev/null)"
  [ "$cur" = "$api_mode" ] || { log "WARN: profile=$profile API 模式未生效（期望=$api_mode 实际=${cur}）"; return 1; }
  # JWT 信任链模式：PUT jwt-trust-policy + 发布 + 生效核对（仅声明配对时）。
  # 配对 profile 失败即该轮无效；基线 profile 的 OFF 归位失败仅告警——
  # 应用不存在时不可能有已发布 PROTECT 策略，JWT 本就关闭，不阻断基线轮次。
  if [ -n "$jwt_mode" ]; then
    if ! jwt_apply_mode "$jwt_mode"; then
      case "$profile" in
        jwt_off|jwt_protect)
          log "WARN: profile=$profile jwt_trust 切换失败"
          return 1
          ;;
        *)
          log "WARN: profile=$profile 基线 JWT 归位（OFF）失败；若无历史 PROTECT 策略则 JWT 本就关闭，继续"
          ;;
      esac
    fi
  fi
  # 有效配置差异快照（规范化）：保存策略文本哈希而非明文全量
  curl -s -b "$RUN_DIR/cookies.txt" "$api_url/api/v1/api-security/policy" \
      | python3 -c "import hashlib,sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())" \
      > "$RUN_DIR/config-diff-$profile.sha256"
  log "profile=$profile 切换并验证生效（waf=$waf api=${api_mode}${jwt_mode:+ jwt=$jwt_mode}）"
}

# ---------- 语料回放 ----------
replay_corpus() { # $1=profile
  local profile="$1" gw_port base raw i n
  gw_port="$(port_of gateway 81)" || die "无法取得网关站点端口"
  base="http://$gw_port"
  require_target_allowed "$base/"
  raw="$RUN_DIR/truth-raw-$profile.jsonl"
  : > "$raw"
  local corpus_path
  corpus_path="$(json_get "$RUN_DIR/plan.json" corpus.manifest_path)"
  n=0
  while read -r req; do
    n=$((n + 1))
    python3 - "$req" "$base" "$raw" "$profile" "$RUN_DIR/jwt" <<'PYEOF'
import json, os, subprocess, sys, urllib.parse
req, base, raw, profile, jwt_dir = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
r = json.loads(req)
url = base + r["path"]
if r.get("query"):
    url += "?" + urllib.parse.urlencode({"q": r["query"][2:]}) if r["query"].startswith("q=") else "?" + r["query"]
cmd = ["curl", "-sS", "-o", "/dev/null", "--max-time", "30",
       "-w", "%{http_code}\t%{time_total}",
       "-X", r["method"], "-H", f"X-Request-Id: {r['request_id']}"]
for k, v in (r.get("headers") or {}).items():
    if k.lower() == "authorization":
        continue  # 不在命令行回显/传递 Authorization；JWT 样本经临时头文件注入
    cmd += ["-H", f"{k}: {v}"]
# JWT 配对 profile（jwt_off/jwt_protect）：语料声明 jwt_inject 的样本从 run 目录
# 0600 临时头文件注入 Bearer Token（curl -H @file；Token 不上命令行、不入输出）。
# 七模式主基线不注入（JWT 关闭语义）；头文件由 switch_profile 现场签发。
inject = r.get("jwt_inject") if profile in ("jwt_off", "jwt_protect") else None
if inject:
    name = "authorization-tampered.header" if inject == "tampered" else "authorization.header"
    header_file = os.path.join(jwt_dir, name)
    # 缺失时如实让 curl 报错（status 记 None/000），不伪造响应；正常流程已被 profile 切换拦截
    cmd += ["-H", "@" + header_file]
if r.get("body") is not None:
    cmd += ["--data-binary", "@-"]
p = subprocess.run(cmd, input=(r.get("body") or "").encode(), capture_output=True, text=False)
code, _, ttotal = p.stdout.decode().partition("\t")
status = None if code in ("000", "") else int(code)
# origin 可达性由后续对账（源站 echo 的 upstream_mark）确认；此处先记响应
rec = {"request_id": r["request_id"], "case_id": r["case_id"],
       "status": status, "latency_ms": float(ttotal or 0) * 1000,
       "origin_reached": status is not None and 200 <= status < 400}
with open(raw, "a", encoding="utf-8") as fh:
    fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
PYEOF
  done < <(p0b gen-requests --manifest "$REPO_ROOT/$corpus_path" --profile "$profile")
  log "profile=$profile 回放 $n 条语料"
  PYTHONPATH="$SCRIPT_DIR" python3 "$SCRIPT_DIR/collect.py" truthbuild --run-dir "$RUN_DIR" \
      --profile "$profile" --raw "$raw" --corpus "$REPO_ROOT/$corpus_path" \
      ${DETECTED_IDS:+--detected "$DETECTED_IDS"} >/dev/null
}

# ---------- 子命令 ----------
cmd_preflight() {
  new_run; write_manifest
  preflight_checks lenient
  set_status preflight PASS "隔离与预检通过" --optional
  PYTHONPATH="$SCRIPT_DIR" python3 "$SCRIPT_DIR/report.py" --run-dir "$RUN_DIR" >/dev/null || true
  log "preflight 完成，证据: $RUN_DIR"
}

# JWT-18 配对循环：七模式主基线之外追加 jwt_off/jwt_protect（计划声明 config.jwt_pair 时）。
# $1=correctness|matrix|soak；各模式执行逻辑与主基线一致，仅 profile 序列不同。
run_jwt_pair_loop() {
  jwt_pair_declared || return 0
  local what="$1" profile
  log "JWT-18 配对实验（$what）：jwt_off vs jwt_protect（同构建同基础配置，静态 JWKS）"
  while read -r profile; do
    [ -z "$profile" ] && continue
    case "$what" in
      correctness)
        if ! switch_profile "$profile"; then
          set_status "correctness:$profile" BLOCKED "JWT 配对模式切换/生效验证失败（BENCH-04 纪律：该轮无效）"
          continue
        fi
        replay_corpus "$profile"
        set_status "correctness:$profile" PASS "JWT 配对语料回放完成，逐样本真值见 truth/$profile.json"
        ;;
      matrix)
        if ! switch_profile "$profile"; then
          set_status "matrix:$profile" BLOCKED "JWT 配对模式切换/生效验证失败（该轮无效）"
          continue
        fi
        if matrix_ladder "$profile"; then
          set_status "matrix:$profile" PASS "JWT 配对矩阵完成（ab 闭环并发不带 Token；带 Token 逐请求延迟见 correctness 回放）"
        else
          set_status "matrix:$profile" BLOCKED "负载点执行或吞吐证据不完整，未生成 PASS 结论"
        fi
        ;;
      soak)
        if ! switch_profile "$profile"; then
          set_status "soak:$profile" BLOCKED "JWT 配对模式切换失败"
          continue
        fi
        soak_profile "$profile"
        ;;
    esac
  done < <(p0b shuffle-profiles --seed "$(json_get "$RUN_DIR/plan.json" corpus.seed)" --jwt-pair)
}

cmd_smoke() {
  new_run; write_manifest
  preflight_checks lenient
  stack_up
  local dur rps gw_port url i tsv
  dur="$(json_get "$RUN_DIR/plan.json" load.smoke.duration_seconds 2>/dev/null || echo 10)"
  rps="$(json_get "$RUN_DIR/plan.json" load.smoke.rps 2>/dev/null || echo 5)"
  gw_port="$(port_of gateway 81)" || die "无法取得网关站点端口"
  url="http://$gw_port/"
  require_target_allowed "$url"
  tsv="$RUN_DIR/smoke.tsv"
  : > "$tsv"
  local n=$(( dur * rps )) delay
  delay="$(python3 -c "print(1.0/max(1,$rps))")"
  log "smoke: ${n} 请求（${rps}/s × ${dur}s），只证明工具可运行"
  for i in $(seq 1 "$n"); do
    curl -s -o /dev/null --max-time 10 \
        -w "smoke-$i\t%{http_code}\t%{time_total}\t%{remote_ip}\n" "$url" >> "$tsv" || true
    sleep "$delay"
  done
  PYTHONPATH="$SCRIPT_DIR" python3 "$SCRIPT_DIR/collect.py" curltsv --run-dir "$RUN_DIR" \
      --profile smoke --name smoke --file "$tsv" >/dev/null
  set_status smoke PASS "工具链路可运行；不产生容量结论" --optional
  for tid in BENCH-11 BENCH-12; do
    set_status "$tid" NOT_RUN "smoke 不覆盖；真实环境最终验收"
  done
  PYTHONPATH="$SCRIPT_DIR" python3 "$SCRIPT_DIR/report.py" --run-dir "$RUN_DIR" >/dev/null
  log "smoke 完成，证据: $RUN_DIR（报告标记 smoke）"
}

cmd_correctness() {
  new_run; write_manifest
  preflight_checks strict
  stack_up
  local profile
  while read -r profile; do
    if ! switch_profile "$profile"; then
      set_status "correctness:$profile" BLOCKED "模式切换/生效验证失败（BENCH-04 纪律：该轮无效）"
      continue
    fi
    replay_corpus "$profile"
    set_status "correctness:$profile" PASS "语料回放完成，逐样本真值见 truth/$profile.json"
  done < <(p0b shuffle-profiles --seed "$(json_get "$RUN_DIR/plan.json" corpus.seed)")
  run_jwt_pair_loop correctness
  PYTHONPATH="$SCRIPT_DIR" python3 "$SCRIPT_DIR/report.py" --run-dir "$RUN_DIR" >/dev/null
  log "correctness 完成，证据: $RUN_DIR"
}

matrix_ladder() { # $1=profile：负载阶梯 × 重复（ab 闭环并发，如实记录模型限制）
  local profile="$1" rps repeat out
  for rps in $(json_get "$RUN_DIR/plan.json" load.rps_ladder | python3 -c "import json,sys; print(' '.join(map(str, json.load(sys.stdin))))"); do
    for repeat in $(seq 1 "$(json_get "$RUN_DIR/plan.json" load.repeats)"); do
      out="$RUN_DIR/ab-$profile-r$repeat-$rps.txt"
      log "matrix: profile=$profile rps=$rps repeat=$repeat"
      # ab 闭环并发：并发数≈目标 rps × 预估延迟，如实记录模型限制
      if ! ab -k -c "$rps" -t "$(json_get "$RUN_DIR/plan.json" load.steady_point_seconds)" \
         "http://$(port_of gateway 81)/" > "$out" 2>&1; then
        log "matrix: profile=$profile rps=$rps repeat=$repeat 压测器失败，拒绝生成 PASS 证据"
        return 1
      fi
      PYTHONPATH="$SCRIPT_DIR" python3 "$SCRIPT_DIR/collect.py" loadgen --run-dir "$RUN_DIR" \
          --profile "$profile" --repeat "$repeat" --point "$rps" --tool ab --file "$out" >/dev/null || {
        log "matrix: profile=$profile rps=$rps repeat=$repeat 吞吐输出不可解析，拒绝生成 PASS 证据"
        return 1
      }
    done
  done
}

cmd_matrix() {
  new_run; write_manifest
  formal_environment_gate BENCH-11 matrix
  preflight_checks strict
  stack_up
  local model tool
  model="$(json_get "$RUN_DIR/plan.json" load.model)"
  tool="$(json_get "$RUN_DIR/plan.json" load.loadgen.tool)"
  if [ "$model" = "open_fixed_rate" ] && [ "$tool" = "ab" ]; then
    die "ab 为闭环并发，不能伪称固定到达率；请改用 wrk/k6 或调整 plan.load.model"
  fi
  local profile order
  order="$(p0b shuffle-profiles --seed "$(json_get "$RUN_DIR/plan.json" corpus.seed)")"
  while read -r profile; do
    [ -z "$profile" ] && continue
    if ! switch_profile "$profile"; then
      set_status "matrix:$profile" BLOCKED "模式切换/生效验证失败（该轮无效）"
      continue
    fi
    if matrix_ladder "$profile"; then
      set_status "matrix:$profile" PASS "矩阵完成（闭环并发，ab 版本见 manifest）"
    else
      set_status "matrix:$profile" BLOCKED "负载点执行或吞吐证据不完整，未生成 PASS 结论"
    fi
  done <<< "$order"
  run_jwt_pair_loop matrix
  PYTHONPATH="$SCRIPT_DIR" python3 "$SCRIPT_DIR/report.py" --run-dir "$RUN_DIR" >/dev/null
  log "matrix 完成，证据: $RUN_DIR"
}

soak_profile() { # $1=profile：单 profile 稳定性采集（仅本 project 容器）
  local profile="$1" minutes end stats rss_file started_at ended_at gateway_id rss_kib
  minutes="$(json_get "$RUN_DIR/plan.json" load.soak.per_profile_minutes)"
  end=$(( $(date +%s) + minutes * 60 ))
  stats="$RUN_DIR/stats-$profile.jsonl"
  rss_file="$RUN_DIR/rss-$profile.jsonl"
  started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  while [ "$(date +%s)" -lt "$end" ]; do
    # 仅采集本 project 容器（--filter 限定），不输出完整 inspect
    gateway_id="$(docker ps --filter "label=com.docker.compose.project=$PROJECT" \
      --filter "label=com.docker.compose.service=gateway" -q | head -1)"
    if [ -n "$gateway_id" ]; then
      docker stats --no-stream --format json "$gateway_id" >> "$stats" 2>/dev/null || true
      # Linux containers expose process RSS; this is intentionally a separate
      # evidence stream because docker stats is container memory, not RSS.
      rss_kib="$(docker exec "$gateway_id" sh -c \
        "grep '^VmRSS:' /proc/1/status 2>/dev/null | tr -s ' ' | cut -d ' ' -f2" \
        2>/dev/null || true)"
      case "$rss_kib" in
        ''|*[!0-9]*) ;;
        *) printf '{"container":"%s","pid":1,"rss_kib":%s}\n' \
             "$gateway_id" "$rss_kib" >> "$rss_file" ;;
      esac
    fi
    sleep 30
  done
  ended_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  if [ ! -s "$stats" ]; then
    set_status "soak:$profile" BLOCKED "容器内存样本缺失（无 docker stats 快照）"
    python3 - "$RUN_DIR/soak/$profile.json" "$minutes" "$started_at" "$ended_at" \
      "容器内存样本缺失（无 docker stats 快照）" <<'PYEOF'
import json, sys
out, minutes, started, ended, reason = sys.argv[1:]
with open(out, "w", encoding="utf-8") as fh:
    json.dump({"status": "BLOCKED", "reason": reason, "duration_minutes": int(minutes),
               "started_at": started, "ended_at": ended}, fh, ensure_ascii=False, indent=2)
    fh.write("\n")
PYEOF
    return 0
  fi
  if ! PYTHONPATH="$SCRIPT_DIR" python3 "$SCRIPT_DIR/collect.py" resources --run-dir "$RUN_DIR" \
      --name "$profile" --file "$stats" >/dev/null; then
    set_status "soak:$profile" BLOCKED "RSS/容器内存采集失败"
    python3 - "$RUN_DIR/soak/$profile.json" "$minutes" "$started_at" "$ended_at" \
      "容器内存采集失败" <<'PYEOF'
import json, sys
out, minutes, started, ended, reason = sys.argv[1:]
with open(out, "w", encoding="utf-8") as fh:
    json.dump({"status": "BLOCKED", "reason": reason, "duration_minutes": int(minutes),
               "started_at": started, "ended_at": ended}, fh, ensure_ascii=False, indent=2)
    fh.write("\n")
PYEOF
    return 0
  fi
  if [ ! -s "$rss_file" ] || ! PYTHONPATH="$SCRIPT_DIR" python3 "$SCRIPT_DIR/collect.py" resources \
      --run-dir "$RUN_DIR" --name "${profile}-rss" --source proc_rss --file "$rss_file" >/dev/null; then
    set_status "soak:$profile" BLOCKED "进程 RSS 样本缺失（Linux /proc VmRSS 不可用）"
    python3 - "$RUN_DIR/soak/$profile.json" "$minutes" "$started_at" "$ended_at" \
      "进程 RSS 样本缺失（Linux /proc VmRSS 不可用）" <<'PYEOF'
import json, sys
out, minutes, started, ended, reason = sys.argv[1:]
with open(out, "w", encoding="utf-8") as fh:
    json.dump({"status": "BLOCKED", "reason": reason, "duration_minutes": int(minutes),
               "started_at": started, "ended_at": ended}, fh, ensure_ascii=False, indent=2)
    fh.write("\n")
PYEOF
    return 0
  fi
  python3 - "$RUN_DIR/soak/$profile.json" "$minutes" "$started_at" "$ended_at" <<'PYEOF'
import json, sys
out, minutes, started, ended = sys.argv[1:]
with open(out, "w", encoding="utf-8") as fh:
    json.dump({"status": "PASS", "duration_minutes": int(minutes),
               "started_at": started, "ended_at": ended}, fh, ensure_ascii=False, indent=2)
    fh.write("\n")
PYEOF
  set_status "soak:$profile" PASS "稳定运行 ${minutes}min"
}

cmd_soak() {
  new_run; write_manifest
  formal_environment_gate BENCH-11 soak
  preflight_checks strict
  stack_up
  log "soak：长稳运行（七模式 ≥30min + combined_protect ≥72h），故障与恢复见 recovery"
  local profile
  while read -r profile; do
    [ -z "$profile" ] && continue
    switch_profile "$profile" || { set_status "soak:$profile" BLOCKED "模式切换失败"; continue; }
    soak_profile "$profile"
  done < <(p0b shuffle-profiles --seed "$(json_get "$RUN_DIR/plan.json" corpus.seed)")
  run_jwt_pair_loop soak
  PYTHONPATH="$SCRIPT_DIR" python3 "$SCRIPT_DIR/report.py" --run-dir "$RUN_DIR" >/dev/null
  log "soak 完成，证据: $RUN_DIR"
}

cmd_recovery() {
  new_run; write_manifest
  formal_environment_gate BENCH-09 recovery
  preflight_checks strict
  stack_up
  local limit
  limit="$(json_get "$RUN_DIR/plan.json" thresholds.recovery_time_seconds_max)"
  log "recovery：故障注入仅限本 project=${PROJECT}，恢复时限 ${limit}s（plan 冻结值）"
  assert_ownership
  local t0 t1 fault_injected_at gateway_healthy_at catchup_verified=0 healthy=0
  t0="$(date +%s)"
  fault_injected_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  compose_cmd stop gateway >/dev/null
  compose_cmd start gateway >/dev/null
  # 等待健康
  local deadline=$(( $(date +%s) + limit ))
  while :; do
    if compose_cmd ps gateway --format json 2>/dev/null | grep -q '"Healthy": *true\|healthy'; then
      healthy=1
      gateway_healthy_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      break
    fi
    [ "$(date +%s)" -ge "$deadline" ] && break
    sleep 2
  done
  t1="$(date +%s)"
  local elapsed=$(( t1 - t0 ))
  if [ "${P0B_RECOVERY_CATCHUP_VERIFIED:-0}" = "1" ]; then
    catchup_verified=1
  fi
  python3 - "$RUN_DIR/recovery.json" "$elapsed" "$limit" "$fault_injected_at" \
      "${gateway_healthy_at:-}" "$healthy" "$catchup_verified" <<'PYEOF'
import json, sys
out, elapsed, limit, fault_at, healthy_at, healthy, catchup = sys.argv[1:]
elapsed, limit = int(elapsed), int(limit)
healthy, catchup = int(healthy), int(catchup)
status = "PASS" if healthy and catchup and elapsed <= limit else "BLOCKED" if healthy else "FAIL"
reason = "" if status == "PASS" else (
    "EVENT_CATCHUP_UNVERIFIED" if healthy and not catchup else "GATEWAY_HEALTHCHECK_TIMEOUT"
)
doc = {"scenario": "gateway_restart", "recovery_time_seconds": elapsed,
       "limit_seconds": limit,
       "fault_injected_at": fault_at,
       "gateway_healthy_at": healthy_at or None,
       "catchup_verified": bool(catchup),
       "evidence_scope": "gateway_health_plus_operator_catchup_assertion",
       "status": status, "reason": reason}
with open(out, "w", encoding="utf-8") as fh:
    json.dump(doc, fh, ensure_ascii=False, indent=2, sort_keys=True)
    fh.write("\n")
PYEOF
  if [ "$healthy" -eq 1 ] && [ "$catchup_verified" -eq 1 ] && [ "$elapsed" -le "$limit" ]; then
    set_status BENCH-09 PASS "网关重启恢复 ${elapsed}s ≤ ${limit}s"
  elif [ "$healthy" -eq 1 ]; then
    set_status BENCH-09 BLOCKED "网关已恢复但事件追平未获得显式证据（设置 P0B_RECOVERY_CATCHUP_VERIFIED=1 后重跑）"
  else
    set_status BENCH-09 FAIL "网关重启恢复 ${elapsed}s > ${limit}s"
  fi
  PYTHONPATH="$SCRIPT_DIR" python3 "$SCRIPT_DIR/report.py" --run-dir "$RUN_DIR" >/dev/null
  log "recovery 完成，证据: $RUN_DIR"
}

# ---------- P1-04 规则/模型回归（严格增量；工具与语料在 test/regression/p1） ----------
# 证据纪律沿用 benchmarks：plan.json 0444 冻结、manifest.json、status.json、
# replay-plan.json（0444）、cases.jsonl、corpus-validation.txt、report.md 只读生成。
# 本阶段（R1/S1）不连接真实网关：执行层在隔离栈接线前一律 BLOCKED/
# ENVIRONMENT_UNAVAILABLE 并非零退出，绝不伪造回放结果。

write_manifest_regression() {
  python3 - "$RUN_DIR/manifest.json" "$RUN_ID" "$PLAN_FILE" "$REPO_ROOT" <<'PYEOF'
import json, platform, subprocess, sys
out, run_id, plan_path, repo_root = sys.argv[1:5]
def safe(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=15).stdout.strip()
    except Exception:
        return "unavailable"
doc = {
    "run_id": run_id,
    "kind": "p1_regression",
    "plan_file": plan_path,
    "host": {"os": platform.platform(), "machine": platform.machine()},
    "git_commit": safe(["git", "-C", repo_root, "rev-parse", "HEAD"]),
    "python_version": platform.python_version(),
}
with open(out, "w", encoding="utf-8") as fh:
    json.dump(doc, fh, ensure_ascii=False, indent=2, sort_keys=True)
    fh.write("\n")
PYEOF
}

new_regression_run() {
  RUN_ID="$(gen_run_id)"
  RUN_DIR="$REG_EVIDENCE_ROOT/$RUN_ID"
  mkdir -p "$RUN_DIR"
  cp "$PLAN_FILE" "$RUN_DIR/plan.json"
  chmod 0444 "$RUN_DIR/plan.json"
  log "regression run_id=$RUN_ID run_dir=$RUN_DIR"
}

regression_finish() { # $1=退出码；统一落报告并以非零结束（除非调用方给 0）
  local rc="$1"
  p1reg write-report --run-dir "$RUN_DIR" >/dev/null || true
  log "regression 结束（rc=${rc}），证据: $RUN_DIR"
  exit "$rc"
}

cmd_regression() {
  [ -d "$REG_DIR" ] || die "P1 回归工具目录缺失: $REG_DIR"
  new_regression_run
  write_manifest_regression

  # 1) 回归 run-plan 结构校验（kind=p1_regression_run_plan，与 P0 计划区分）
  if ! p1reg validate-run-plan --plan "$RUN_DIR/plan.json" --profiles-dir "$REG_PROFILES_DIR"; then
    set_status regression-plan FAIL "回归 run-plan 不满足契约，拒绝启动"
    regression_finish 3
  fi
  set_status regression-plan PASS "回归 run-plan 结构校验通过"

  # 2) 语料 schema v1 校验（含逐用例内容哈希自校验、路径越界与断言解析拒绝）
  local corpus_path corpus_want corpus_actual
  corpus_path="$(json_get "$RUN_DIR/plan.json" corpus.manifest_path)" || {
    set_status corpus-validation FAIL "plan 缺 corpus.manifest_path"
    regression_finish 3
  }
  corpus_want="$(json_get "$RUN_DIR/plan.json" corpus.manifest_sha256)"
  if [ ! -f "$REPO_ROOT/$corpus_path" ]; then
    set_status corpus-validation FAIL "语料 manifest 缺失: $corpus_path"
    regression_finish 3
  fi
  if ! p1reg validate-corpus --manifest "$REPO_ROOT/$corpus_path" \
        --profiles-dir "$REG_PROFILES_DIR" > "$RUN_DIR/corpus-validation.txt" 2>&1; then
    set_status corpus-validation FAIL "语料校验失败，明细见 corpus-validation.txt"
    regression_finish 3
  fi
  corpus_actual="$(p1reg corpus-hash --manifest "$REPO_ROOT/$corpus_path")"
  if [ "$corpus_actual" != "$corpus_want" ]; then
    set_status corpus-validation FAIL "语料哈希不匹配（登记 ${corpus_want}，实际 ${corpus_actual}），运行无效"
    regression_finish 3
  fi
  set_status corpus-validation PASS "语料 schema v1 与内容哈希一致: ${corpus_actual:0:16}…"

  # 3) 确定性回放计划（seed 驱动，绑定 run_id 与语料哈希；0444 冻结）
  p1reg gen-plan --manifest "$REPO_ROOT/$corpus_path" --profiles-dir "$REG_PROFILES_DIR" \
      --seed "$(json_get "$RUN_DIR/plan.json" corpus.seed)" --run-id "$RUN_ID" \
      > "$RUN_DIR/replay-plan.json" || {
    set_status replay-plan FAIL "回放计划生成失败"
    regression_finish 3
  }
  chmod 0444 "$RUN_DIR/replay-plan.json"
  # 逐例骨架：全部 NOT_RUN（执行层填充前的诚实初始态）
  p1reg init-cases --replay-plan "$RUN_DIR/replay-plan.json" > "$RUN_DIR/cases.jsonl" || {
    set_status replay-plan FAIL "cases.jsonl 骨架生成失败"
    regression_finish 3
  }
  local planned
  planned="$(wc -l < "$RUN_DIR/cases.jsonl" | tr -d ' ')"
  set_status replay-plan PASS "确定性回放计划已生成（计划样本数 ${planned}）"

  # 4) 执行层：plan 登记 environment.stage5_env_descriptor（R2 真实隔离栈
  #    描述符，0600）时走真实回放→对账→判定；未登记时保持 R1/S1 语义——
  #    明确 BLOCKED，不发起任何请求，不产生任何假 PASS。
  local env_desc=""
  env_desc="$(json_get "$RUN_DIR/plan.json" environment.stage5_env_descriptor 2>/dev/null || true)"
  if [ -z "$env_desc" ]; then
    set_status regression-execution BLOCKED \
      "ENVIRONMENT_UNAVAILABLE：S1 工具层交付，真实网关执行待隔离环境接线（P1-04 R2）；未执行任何请求（0/${planned}），不做假 PASS"
    log "regression: 执行层 BLOCKED（ENVIRONMENT_UNAVAILABLE），计划 $planned 条均未执行"
    regression_finish 3
  fi
  if [ ! -f "$env_desc" ]; then
    set_status regression-execution FAIL "环境描述符不存在: $env_desc"
    regression_finish 3
  fi
  log "regression: 真实栈执行（描述符 ${env_desc}），计划 ${planned} 条"
  local exec_rc=0
  p1reg execute --replay-plan "$RUN_DIR/replay-plan.json" \
    --manifest "$REPO_ROOT/$corpus_path" --profiles-dir "$REG_PROFILES_DIR" \
    --env "$env_desc" --run-dir "$RUN_DIR" --run-id "$RUN_ID" || exec_rc=$?
  case "$exec_rc" in
    0)
      set_status regression-execution PASS "真实栈回放完成：全部执行且无 FAIL（明细 cases.jsonl / perf.jsonl）"
      regression_finish 0
      ;;
    1)
      set_status regression-execution FAIL "真实栈回放存在 FAIL 用例（明细 cases.jsonl / report.md）"
      regression_finish 1
      ;;
    2)
      set_status regression-execution FAIL "执行层结构错误（描述符/计划/语料不符）"
      regression_finish 3
      ;;
    *)
      set_status regression-execution BLOCKED "执行不完整（存在 BLOCKED/NOT_RUN/执行无效），不授予完整通过"
      regression_finish 3
      ;;
  esac
}

cmd_compare() {
  [ -d "$REG_DIR" ] || die "P1 回归工具目录缺失: $REG_DIR"
  p1reg validate-run-id --run-id "$BASELINE_ID" >/dev/null \
    || die "非法 baseline run_id（必须为 YYYYMMDDTHHMMSS-xxxxxx）: $BASELINE_ID"
  p1reg validate-run-id --run-id "$CANDIDATE_ID" >/dev/null \
    || die "非法 candidate run_id（必须为 YYYYMMDDTHHMMSS-xxxxxx）: $CANDIDATE_ID"
  local bdir="$REG_EVIDENCE_ROOT/$BASELINE_ID" cdir="$REG_EVIDENCE_ROOT/$CANDIDATE_ID"
  [ -d "$bdir" ] || die "baseline 证据目录不存在: $bdir"
  [ -d "$cdir" ] || die "candidate 证据目录不存在: $cdir"
  local outdir="$REG_EVIDENCE_ROOT/compare-$(gen_run_id)"
  mkdir -p "$outdir"
  # compare 只读两个已完成证据目录；输出写入新的 compare-<run-id> 目录，
  # 不改动输入证据；退出码：PASS=0，FAIL/NOT_PASSED=1，结构错误=2
  local rc=0
  p1reg compare --baseline "$bdir" --candidate "$cdir" --out "$outdir" || rc=$?
  log "compare 结果目录: ${outdir}（退出码 ${rc}）"
  exit "$rc"
}

# ---------- 入口 ----------
main() {
  local cmd="${1:-}"
  case "$cmd" in
    preflight|smoke|correctness|matrix|soak|recovery|regression|compare) ;;
    -h|--help|"") usage; [ -n "$cmd" ] && exit 0 || exit 2 ;;
    *) echo "未知子命令: $cmd" >&2; usage >&2; exit 2 ;;
  esac
  shift
  while [ $# -gt 0 ]; do
    case "$1" in
      --plan) PLAN_FILE="${2:?--plan 需要参数}"; shift 2 ;;
      --baseline) BASELINE_ID="${2:?--baseline 需要参数}"; shift 2 ;;
      --candidate) CANDIDATE_ID="${2:?--candidate 需要参数}"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) die "未知参数: $1" ;;
    esac
  done
  if [ "$cmd" = "compare" ]; then
    # compare 只读两个已完成证据目录，不需要 --plan
    [ -n "$BASELINE_ID" ] || die "缺 --baseline <run-id>"
    [ -n "$CANDIDATE_ID" ] || die "缺 --candidate <run-id>"
  else
    [ -n "$PLAN_FILE" ] || die "缺 --plan <run-plan.json>"
    [ -f "$PLAN_FILE" ] || die "plan 不存在: $PLAN_FILE"
    PLAN_FILE="$(cd "$(dirname "$PLAN_FILE")" && pwd)/$(basename "$PLAN_FILE")"
  fi
  [ -f "$COMPOSE_FILE" ] || die "编排文件缺失: $COMPOSE_FILE"

  trap cleanup EXIT INT TERM
  "cmd_$cmd"
}

main "$@"
