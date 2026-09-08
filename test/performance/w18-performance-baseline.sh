#!/usr/bin/env bash
# 九章 API 安全补全 W18-PERF：性能基线实测（任务书 §202-203 形态的最小矩阵）。
#   矩阵两档（同一 URL 集，变量只有 API 动态防护开关）：
#     - Baseline Proxy：api_dynamic_protection=false（发布 JSON 与纯 WAF 完全一致，
#       网关 serveNext 直接放行，不进入 API 管线）；
#     - Full API Security：wdsp 形态 + 策略 OBSERVE（解析→分类→归一化→全检测器→
#       事件输出→采集入库全链路）。
#   指标：QPS / P50 / P95 / P99 / max 延迟 / 失败数 + 压测期间 gateway/api/postgres/valkey
#   的 CPU 与内存（docker stats 周期采样）。
#
# 与实现对齐的关键事实（先读后改结论）：
#   - 策略 mode=OFF 只在 decision 层强制 ALLOW，管线工作不减少（decision/engine.go:36），
#     不能充当 Baseline；真基线只能关掉 api_dynamic_protection；
#   - 该开关由管理后端 API_DYNAMIC_PROTECTION_ENABLED 环境变量决定（guardconfig/provider.go:353），
#     无运行期开关，因此 Baseline 臂需用「不带 wdsp 覆盖」重建 api 容器，测完立即恢复；
#   - 压测 URL 为读方法 GET（写方法有 60/min 进程内限速，见 detectors/ratelimit.go），不会 429；
#   - 每臂使用本次运行唯一路径前缀，事件按 endpoint_key 精确计数，避免与历史/并行分片串扰；
#   - ab -k 长连接：避免 macOS 短时高端口耗尽（ ephemeral 端口 ~1.6 万个），同时两臂一致可比；
#   - 事件计数校验：Baseline 臂前缀事件必须为 0（证明真绕过了管线），Full 臂事件应 ≈ 请求数。
#
# 依赖已在运行的 stage5 编排（stage5 + wdsp 覆盖）。用法（仓库根目录）：
#   bash test/performance/w18-performance-baseline.sh
# 结果写入 test/performance/w18-performance-baseline-result.txt；原始数据保留在 /tmp/w18-perf-<TS>/。
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SCRIPT_DIR/../waf/scripts/stage5-setup.sh"

TS=$(date +%s)
PFX="w18p$TS"                       # 本次运行唯一前缀
URL_BASE="$GATEWAY_URL/v1/$PFX-base/1"
URL_FULL="$GATEWAY_URL/v1/$PFX-full/1"
EK_BASE="GET /v1/$PFX-base/{id}"
EK_FULL="GET /v1/$PFX-full/{id}"
WORK="/tmp/w18-perf-$TS"
mkdir -p "$WORK"

CONC=20                             # 压测并发（适度：共享开发机 + Docker Desktop）
DUR=30                              # 每臂计量时长（秒）
WARM=5                              # 每臂预热时长（秒，丢弃）
AB_N=5000000                        # -n 上限（远大于可达量，实际由 -t 限时）

REPORT="$SCRIPT_DIR/w18-performance-baseline-result.txt"
: > "$REPORT"
log() { echo "$@" | tee -a "$REPORT"; }

# 运行中的 stage5 栈为避让本机其他项目使用了非默认宿主端口（postgres 15432 / valkey 16379 /
# ollama 21434；gateway 18080 / api 18081 为默认）。compose 重建 api 时必须带上相同端口覆盖，
# 否则 compose 会按默认端口重建 postgres/valkey——端口被占直接失败（本分片已踩过并恢复）。
# shell 环境变量优先于 --env-file .env，此处仅覆盖端口，不读取任何凭据。
export POSTGRES_PORT="${POSTGRES_PORT:-15432}"
export VALKEY_PORT="${VALKEY_PORT:-16379}"
export OLLAMA_PORT="${OLLAMA_PORT:-21434}"

# compose 重建 api 的统一入口：--no-deps 保证只动 api 一个容器，绝不波及数据容器
compose_api() {                     # $@=额外的 -f 覆盖文件参数
  (cd "$REPO_ROOT" && docker compose --env-file .env \
    -f deployment/docker-compose.stage5.yml "$@" up -d --no-deps api)
}

# 预检：dry-run 展开同一命令，任何非 api 容器出现 Recreate 即中止（宁缺毋滥）
preflight_only_api_changes() {      # $@=额外的 -f 覆盖文件参数
  local dry
  dry=$(cd "$REPO_ROOT" && docker compose --env-file .env \
    -f deployment/docker-compose.stage5.yml "$@" up -d --no-deps --dry-run api 2>&1)
  if echo "$dry" | grep -E 'stage5-(postgres|valkey|gateway|testorigin|ollama)' | grep -q 'Recreate'; then
    echo "$dry" | tee -a "$REPORT"
    return 1
  fi
  return 0
}

RESTORE_PENDING=0
# 任何退出路径都尽力恢复 wdsp 形态（共享环境，恢复原状是硬要求）：
# 重建 api 容器 + 健康等待 + 重新登录 + 发布（让网关配置也回到 wdsp 口径）
restore_env() {
  [ "$RESTORE_PENDING" = "1" ] || return 0
  echo "[restore] 恢复 api 容器为 wdsp 形态并重新发布…" | tee -a "$REPORT"
  compose_api -f deployment/docker-compose.wdsp.yml >> "$WORK/compose-restore.log" 2>&1
  wait_api || return 0
  local csrf
  csrf=$(s5_login "$SEC_USER" "$SEC_PWD")
  [ -n "$csrf" ] && s5_publish "$csrf" >> "$WORK/compose-restore.log" 2>&1
  return 0
}
trap restore_env EXIT

api_env_flag() {                    # $1=期望的 API_DYNAMIC_PROTECTION_ENABLED 值 → 校验容器实际环境
  docker inspect jiuzhang-stage5-api --format '{{range .Config.Env}}{{println .}}{{end}}' \
    | grep -q "^API_DYNAMIC_PROTECTION_ENABLED=$1$"
}

wait_api() {                        # 等待管理面健康（postgres+valkey 均 true）
  for _ in $(seq 1 45); do
    local h
    h=$(curl -s --max-time 3 "$API_URL/api/v1/health" 2>/dev/null)
    case "$h" in *'"postgres":true'*'"valkey":true'*) return 0;; esac
    sleep 2
  done
  echo "ERROR: api health timeout" | tee -a "$REPORT"; return 1
}

ev_total() {                        # $1=endpoint_key → 主事件总数（wdsp 形态下可用）
  curl -s -b "/tmp/s5-$SEC_USER.txt" -G "$API_URL/api/v1/api-security/runtime/events" \
    --data-urlencode "endpoint_key=$1" --data-urlencode "page_size=1" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['data'].get('total', 0))" 2>/dev/null
}

# 资源采样：计量窗口内周期 docker stats（含时间戳）
sample_stats() {                    # $1=输出文件 $2=时长秒
  local end=$(( $(date +%s) + $2 ))
  while [ "$(date +%s)" -lt "$end" ]; do
    echo "ts=$(date +%s)" >> "$1"
    docker stats --no-stream --format '{{.Name}} cpu={{.CPUPerc}} mem={{.MemUsage}}' \
      jiuzhang-stage5-gateway jiuzhang-stage5-api jiuzhang-stage5-postgres jiuzhang-stage5-valkey \
      >> "$1" 2>/dev/null
    sleep 1
  done
}

stats_summary() {                   # $1=采样文件 → 每容器 均值/峰值 CPU 与峰值内存
  awk '/^ts=/ {next}
    { name=$1; cpu=$2; sub("cpu=","",cpu); sub("%","",cpu); cpu+=0
      mem=$3; sub("mem=","",mem); split(mem,a,"MiB"); mib=a[1]+0
      sum[name]+=cpu; n[name]++
      if (cpu>max[name]) max[name]=cpu
      if (mib>mmax[name]) mmax[name]=mib }
    END { for (k in n) printf "%s avg_cpu=%.2f%% max_cpu=%.2f%% max_mem=%.1fMiB samples=%d\n", \
          k, sum[k]/n[k], max[k], mmax[k], n[k] }' "$1" | sort
}

ab_field() { grep -E "^$2:" "$1" | head -1 | awk -F: '{print $2}' | awk '{print $1}'; }
ab_pct()   { awk -v p="$2" '$1==p {print $2}' "$1"; }   # 百分位表 " 95%    38" → 38

run_arm() {                         # $1=臂名 $2=URL $3=输出前缀；写 ab 原文与 stats
  local name="$1" url="$2" out="$3"
  # 预热（丢弃）：消除首连建立/懒初始化/Caddy 重载后的抖动
  /usr/sbin/ab -k -r -c 5 -t "$WARM" -n "$AB_N" -H "Host: $HOST_HEADER" "$url" \
      > "$out-warmup.txt" 2>/dev/null
  sample_stats "$out-stats.txt" "$DUR" &
  local sampler=$!
  /usr/sbin/ab -k -r -c "$CONC" -t "$DUR" -n "$AB_N" -H "Host: $HOST_HEADER" "$url" \
      > "$out-ab.txt" 2>/dev/null
  wait "$sampler"
  log "[$name] complete=$(ab_field "$out-ab.txt" 'Complete requests') failed=$(ab_field "$out-ab.txt" 'Failed requests') non2xx=$(ab_field "$out-ab.txt" 'Non-2xx responses') qps=$(ab_field "$out-ab.txt" 'Requests per second') mean_ms=$(ab_field "$out-ab.txt" 'Time per request') p50=$(ab_pct "$out-ab.txt" '50%') p95=$(ab_pct "$out-ab.txt" '95%') p99=$(ab_pct "$out-ab.txt" '99%') max=$(ab_pct "$out-ab.txt" '100%')"
}

log "============================================================"
log "九章 W18-PERF 性能基线实测  $(date '+%Y-%m-%d %H:%M:%S')（UTC $(date -u '+%H:%M:%S')）"
log "环境: $(uname -srm)  gateway=$GATEWAY_URL api=$API_URL"
log "参数: 并发=$CONC 计量=${DUR}s/臂 预热=${WARM}s ab=-k（长连接） 单URL读方法GET"
log "镜像: api=$(docker inspect jiuzhang-stage5-api --format '{{.Image}}' | cut -c1-19) gateway=$(docker inspect jiuzhang-stage5-gateway --format '{{.Image}}' | cut -c1-19)"
log "原始数据目录: $WORK"
log "============================================================"

# ---------- 前置：登录 / 应用 / 发布 / 记录策略形态 ----------
SYS_CSRF=$(s5_ensure_sysadmin) || { echo "ABORT: sysadmin login"; exit 1; }
SEC_CSRF=$(s5_ensure_secuser "$SYS_CSRF")
[ -z "$SEC_CSRF" ] && { echo "ABORT: sec login"; exit 1; }
APP_ID=$(s5_ensure_app "$SEC_CSRF")
log "[setup] app=$APP_ID"
POL_BEFORE=$(curl -s -b "/tmp/s5-$SEC_USER.txt" "$API_URL/api/v1/api-security/policy")
log "[setup] 策略现状: $(echo "$POL_BEFORE" | python3 -c "import json,sys; d=json.load(sys.stdin)['data']; print(d['edition'], d['api_dynamic_protection'], d['mode'], d['mode_source'])" 2>/dev/null)"

# 空闲资源参照（未压测）
sample_stats "$WORK/idle-stats.txt" 6
log "[idle] $(stats_summary "$WORK/idle-stats.txt" | tr '\n' ' | ')"

# ---------- 臂1 Baseline Proxy：去 wdsp 覆盖重建 api（api_dynamic_protection=false） ----------
log "[baseline] 重建 api 容器（不带 wdsp 覆盖 → API_DYNAMIC_PROTECTION_ENABLED=false）"
preflight_only_api_changes || { log "ABORT: 预检发现非 api 容器将被重建"; exit 1; }
RESTORE_PENDING=1
compose_api > "$WORK/compose-baseline.log" 2>&1 \
  || { log "ABORT: compose baseline 失败（见 $WORK/compose-baseline.log）"; exit 1; }
wait_api || exit 1
# 防呆：容器环境必须是 false，否则「基线臂」实际仍开着管线，两臂对比将失真
api_env_flag "false" || { log "ABORT: 基线臂 api 容器 API_DYNAMIC_PROTECTION_ENABLED 非 false（.env 可能显式覆盖）"; exit 1; }
log "[baseline] 容器环境校验 API_DYNAMIC_PROTECTION_ENABLED=false 通过"
# 基线臂也需发布一次：把「不含 api_dynamic_protection」的配置推到网关
SEC_CSRF=$(s5_login "$SEC_USER" "$SEC_PWD")
PUB=$(s5_publish "$SEC_CSRF")
[ "$PUB" = "PUBLISH_OK" ] || { log "ABORT: 基线发布 $PUB"; exit 1; }
CODE=$(s5_req "/")
log "[baseline] 发布完成，网关代理自检 GET / -> $CODE"
seq 1 20 | while read -r _; do s5_req "/v1/$PFX-base/0" > /dev/null; done   # 基线零事件探针（数字段，命中 {id} 模板）
run_arm "baseline" "$URL_BASE" "$WORK/baseline"

# ---------- 臂2 Full API Security：恢复 wdsp 覆盖（OBSERVE 全管线） ----------
log "[full] 恢复 api 容器为 wdsp 形态（API_DYNAMIC_PROTECTION_ENABLED=true）"
preflight_only_api_changes -f deployment/docker-compose.wdsp.yml || { log "ABORT: 预检发现非 api 容器将被重建"; exit 1; }
compose_api -f deployment/docker-compose.wdsp.yml > "$WORK/compose-full.log" 2>&1 \
  || { log "ABORT: compose full 失败（见 $WORK/compose-full.log）"; exit 1; }
wait_api || exit 1
api_env_flag "true" || { log "ABORT: full 臂 api 容器 API_DYNAMIC_PROTECTION_ENABLED 非 true"; exit 1; }
SEC_CSRF=$(s5_login "$SEC_USER" "$SEC_PWD")
PUB=$(s5_publish "$SEC_CSRF")
[ "$PUB" = "PUBLISH_OK" ] || { log "ABORT: full 发布 $PUB"; exit 1; }
RESTORE_PENDING=0
POL_AFTER=$(curl -s -b "/tmp/s5-$SEC_USER.txt" "$API_URL/api/v1/api-security/policy")
log "[full] 策略确认: $(echo "$POL_AFTER" | python3 -c "import json,sys; d=json.load(sys.stdin)['data']; print(d['edition'], d['api_dynamic_protection'], d['mode'], d['mode_source'])" 2>/dev/null)"
# 管线活性探针：20 个请求须产出主事件（证明全链路在跑，再开始计量）。
# 探针路径用数字段 /0：归一化命中 {id} 模板且无凭据 → resource.unauthenticated_object_access
# 观察事件（此前用 probeN 非数字段不归一化、无对象标识、不产事件，探针假阴性）。
seq 1 20 | while read -r _; do s5_req "/v1/$PFX-full/0" > /dev/null; done
PROBE_EV=0
for _ in $(seq 1 10); do PROBE_EV=$(ev_total "$EK_FULL"); [ "${PROBE_EV:-0}" -gt 0 ] && break; sleep 2; done
log "[full] 管线活性探针事件数=${PROBE_EV:-0}（>0 才计量）"
[ "${PROBE_EV:-0}" -gt 0 ] || { log "ABORT: full 臂管线无事件"; exit 1; }
run_arm "full" "$URL_FULL" "$WORK/full"

# ---------- 事件计数校验（两臂都在 wdsp 形态下查询） ----------
# 注意：10 万级事件洪峰下采集器入库需数分钟追平（逐条 UPSERT + 多条副作用，实测 ~300-1900 条/s
# 爬升），本处 60s 轮询窗口在高 QPS run 会显著低报——仅作即时参考；最终总量以事后复查为准
# （实测见 docs/evidence/api-security-performance-baseline.md §5：114651/114651 零丢失）。
FULL_REQ=$(ab_field "$WORK/full-ab.txt" 'Complete requests')
EV_FULL=0
for _ in $(seq 1 30); do
  EV_FULL=$(ev_total "$EK_FULL")
  [ "${EV_FULL:-0}" -ge $(( FULL_REQ * 9 / 10 )) ] && break
  sleep 2
done
EV_BASE=$(ev_total "$EK_BASE")
log "[verify] full 臂事件=${EV_FULL:-0}/${FULL_REQ}（含探针20，阈值≥90%）  baseline 臂事件=${EV_BASE:-0}（必须=0）"

# ---------- 汇总 ----------
log "============================================================"
log "资源消耗（压测窗口 docker stats 采样汇总）"
log "[idle]     $(stats_summary "$WORK/idle-stats.txt" | tr '\n' ';')"
log "[baseline] $(stats_summary "$WORK/baseline-stats.txt" | tr '\n' ';')"
log "[full]     $(stats_summary "$WORK/full-stats.txt" | tr '\n' ';')"
BQ=$(ab_field "$WORK/baseline-ab.txt" 'Requests per second'); FQ=$(ab_field "$WORK/full-ab.txt" 'Requests per second')
BP95=$(ab_pct "$WORK/baseline-ab.txt" '95%'); FP95=$(ab_pct "$WORK/full-ab.txt" '95%')
python3 - "$BQ" "$FQ" "$BP95" "$FP95" <<'EOF' | tee -a "$REPORT"
import sys
bq, fq = float(sys.argv[1]), float(sys.argv[2])
bp, fp = int(sys.argv[3]), int(sys.argv[4])
print(f"[delta] QPS: baseline={bq} full={fq} 开销={(bq-fq)/bq*100:.1f}%  p95: baseline={bp}ms full={fp}ms 增量={fp-bp}ms")
EOF
log "============================================================"
log "完成。原始 ab 输出与 stats 采样保留于 $WORK"
