#!/usr/bin/env bash
# 九章 API 安全 §202 性能扩展矩阵（W18-PERF 两档基线的扩展分片，口径与 W18 完全一致：c=20×30s + 5s 预热）。
#   四臂（每臂唯一路径前缀防串扰）：
#     1) baseline   ：api_dynamic_protection=false（重建 api 去 wdsp 覆盖，同 W18 臂1）；
#     2) observe    ：wdsp + 策略 OBSERVE（同 W18 臂2，作为本矩阵参照臂）；
#     3) protect    ：策略切 PROTECT（PUT /api/v1/api-security/policy + 发布，settings 表覆盖），
#                     流量形态 GET /v1/<pfx>-prot/1?password=perfprobe —— query 键名命中内置敏感词表
#                     → sensitive.in_query BLOCK/HIGH（detectors/sensitive.go:151-163）→ PROTECT 真实 403 阻断，
#                     测的是真实阻断路径开销（解析→分类→全检测器→决策→403 短路，不转发源站）；
#                     附带 protect-pass 子测量：同 PROTECT 模式下干净 URL（无敏感参数）透传流量，
#                     隔离「模式本身」与「阻断动作」两份开销；
#     4) body       ：OBSERVE 下 POST JSON 体 1KiB vs 64KiB 对比（max_body_parse_bytes=1MiB，64KiB 完整解析）。
#                     写方法有 60/min/端点进程内限速（detectors/ratelimit.go，OBSERVE 也定案 429，已实测验证），
#                     故本臂前经 system_settings 注入 gateway_runtime/api_write_rate_per_minute=200000000 并发布，
#                     测完删除该行并再发布——插入/删除同一行，精确可逆，不动其他任何设置。
#
# §202 矩阵中当前架构无法单独分档的项（诚实声明，不造假分档）：
#   API Discovery/Schema/Auth/AuthZ/Response Parse/Sensitive Data/Behavior 各检测器无独立开关——
#   管线为整体（pipeline.go 顺序执行，配置项只能整体开/关 api_dynamic_protection 与 mode），
#   检测器级开销只能用「有无触发形态」对比近似（如本矩阵 body 两臂隔离解析成本），不能单独关闭。
#
# 共享环境铁律（与 W18 相同并扩展）：
#   - compose 只重建 api（--no-deps + dry-run 预检），数据容器严禁重建；端口覆盖同 W18；
#   - 任何退出路径经 EXIT trap 恢复：api 回 wdsp 形态、策略回 OBSERVE、删临时限速行、重新发布；
#   - 终态核验打印在报告尾部（容器健康/镜像/策略/设置行/网关自检/数据抽查）。
#
# 用法（仓库根目录）：bash test/performance/w18-performance-matrix.sh
# 结果写入 test/performance/w18-performance-matrix-result.txt；原始数据保留在 /tmp/w18-matrix-<TS>/。
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SCRIPT_DIR/../waf/scripts/stage5-setup.sh"

TS=$(date +%s)
PFX="w18m$TS"
URL_BASE="$GATEWAY_URL/v1/$PFX-base/1"
URL_OBS="$GATEWAY_URL/v1/$PFX-obs/1"
URL_PROT="$GATEWAY_URL/v1/$PFX-prot/1?password=perfprobe"     # 敏感 query 键名 → PROTECT 下 403
URL_PROTOK="$GATEWAY_URL/v1/$PFX-protok/1"                    # PROTECT 下干净透传（子测量）
URL_BODY="$GATEWAY_URL/v1/$PFX-body/1"
EK_BASE="GET /v1/$PFX-base/{id}"
EK_OBS="GET /v1/$PFX-obs/{id}"
EK_PROT="GET /v1/$PFX-prot/{id}"
EK_PROTOK="GET /v1/$PFX-protok/{id}"
EK_BODY="POST /v1/$PFX-body/{id}"
WORK="/tmp/w18-matrix-$TS"
mkdir -p "$WORK"

CONC=20; DUR=30; WARM=5; AB_N=5000000                        # 与 W18 同口径

REPORT="$SCRIPT_DIR/w18-performance-matrix-result.txt"
: > "$REPORT"
log() { echo "$@" | tee -a "$REPORT"; }

export POSTGRES_PORT="${POSTGRES_PORT:-15432}"
export VALKEY_PORT="${VALKEY_PORT:-16379}"
export OLLAMA_PORT="${OLLAMA_PORT:-21434}"

compose_api() {                     # $@=额外的 -f 覆盖文件参数（--no-deps 只动 api）
  (cd "$REPO_ROOT" && docker compose --env-file .env \
    -f deployment/docker-compose.stage5.yml "$@" up -d --no-deps api)
}

preflight_only_api_changes() {      # $@=额外的 -f 覆盖文件参数；非 api 容器 Recreate 即中止
  local dry
  dry=$(cd "$REPO_ROOT" && docker compose --env-file .env \
    -f deployment/docker-compose.stage5.yml "$@" up -d --no-deps --dry-run api 2>&1)
  if echo "$dry" | grep -E 'stage5-(postgres|valkey|gateway|testorigin|ollama)' | grep -q 'Recreate'; then
    echo "$dry" | tee -a "$REPORT"
    return 1
  fi
  return 0
}

psql_s5() { docker exec jiuzhang-stage5-postgres psql -U jiuzhang -d jiuzhang_waf -At -c "$1"; }

RATE_KEY_WHERE="setting_group='gateway_runtime' AND setting_key='api_write_rate_per_minute'"
rate_setting_exists() { [ "$(psql_s5 "SELECT count(*) FROM system_settings WHERE $RATE_KEY_WHERE")" = "1" ]; }
rate_setting_insert() { # $1=每分钟上限（字符串落 jsonb）
  psql_s5 "INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, description) \
VALUES ('gateway_runtime','api_write_rate_per_minute','\"$1\"'::jsonb,'string',\
'W18-PERF 扩展矩阵临时提升写限速（测完即删，勿手工保留）')" > /dev/null
}
rate_setting_delete() { psql_s5 "DELETE FROM system_settings WHERE $RATE_KEY_WHERE" > /dev/null; }

set_policy_mode() {                 # $1=OFF/OBSERVE/PROTECT $2=csrf → 打印生效 mode
  curl -s -b "/tmp/s5-$SEC_USER.txt" -X PUT "$API_URL/api/v1/api-security/policy" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $2" -d "{\"mode\":\"$1\"}" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['policy']['mode'])" 2>/dev/null
}

RESTORE_API=0; RESTORE_POLICY=0; RESTORE_RATE=0
# 任何退出路径都尽力恢复终态（wdsp + OBSERVE + 无临时限速行 + 重新发布）——共享环境硬要求
restore_env() {
  local need_pub=0 csrf
  if [ "$RESTORE_API" = "1" ]; then
    echo "[restore] 恢复 api 容器为 wdsp 形态…" | tee -a "$REPORT"
    compose_api -f deployment/docker-compose.wdsp.yml >> "$WORK/compose-restore.log" 2>&1
    wait_api || true
  fi
  if [ "$RESTORE_API" = "1" ] || [ "$RESTORE_POLICY" = "1" ] || [ "$RESTORE_RATE" = "1" ]; then need_pub=1; fi
  [ "$need_pub" = "1" ] || return 0
  csrf=$(s5_login "$SEC_USER" "$SEC_PWD")
  if [ "$RESTORE_POLICY" = "1" ] && [ -n "$csrf" ]; then
    echo "[restore] 策略回 OBSERVE（当前: $(set_policy_mode OBSERVE "$csrf")）" | tee -a "$REPORT"
  fi
  if [ "$RESTORE_RATE" = "1" ]; then
    echo "[restore] 删除临时写限速设置行…" | tee -a "$REPORT"
    rate_setting_delete
  fi
  [ -n "$csrf" ] && s5_publish "$csrf" >> "$WORK/compose-restore.log" 2>&1
  return 0
}
trap restore_env EXIT

api_env_flag() {
  docker inspect jiuzhang-stage5-api --format '{{range .Config.Env}}{{println .}}{{end}}' \
    | grep -q "^API_DYNAMIC_PROTECTION_ENABLED=$1$"
}

wait_api() {
  for _ in $(seq 1 45); do
    local h
    h=$(curl -s --max-time 3 "$API_URL/api/v1/health" 2>/dev/null)
    case "$h" in *'"postgres":true'*'"valkey":true'*) return 0;; esac
    sleep 2
  done
  echo "ERROR: api health timeout" | tee -a "$REPORT"; return 1
}

ev_total() {                        # $1=endpoint_key [$2=final_action] → 主事件总数（采集入库侧，backlog 下滞后）
  local extra=""
  [ -n "${2:-}" ] && extra="--data-urlencode final_action=$2"
  curl -s -b "/tmp/s5-$SEC_USER.txt" -G "$API_URL/api/v1/api-security/runtime/events" \
    --data-urlencode "endpoint_key=$1" --data-urlencode "page_size=1" $extra \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['data'].get('total', 0))" 2>/dev/null
}

# 网关侧事件日志精确计数（/var/log/caddy/api-runtime-events.log 每请求一行，含 warmup/探针）。
# 管线活性判据用网关侧而非入库侧：事件风暴后采集器 backlog 可达十分钟级（W18 §5 实测），
# 入库计数在探针窗口内可能为 0 造成假阴性（本脚本首轮回踩过：探针 20 事件网关侧齐、入库侧 0）。
gw_ev_count() {                     # $1=路径前缀子串 → 行数（grep -c 无匹配时输出 0 返回 1，属正常）
  docker exec jiuzhang-stage5-gateway sh -c \
    "grep -c '$1' /var/log/caddy/api-runtime-events.log" 2>/dev/null
}
gw_ev_count_action() {              # $1=路径前缀子串 $2=final_action → 行数
  docker exec jiuzhang-stage5-gateway sh -c \
    "grep '$1' /var/log/caddy/api-runtime-events.log | grep -c '\"final_action\":\"$2\"'" 2>/dev/null
}

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

stats_summary() {
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
ab_pct()   { awk -v p="$2" '$1==p {print $2}' "$1"; }

run_arm() {                         # $1=臂名 $2=URL $3=输出前缀；剩余参数=额外 ab 参数（如 -p/-T）
  local name="$1" url="$2" out="$3"; shift 3
  /usr/sbin/ab -k -r -c 5 -t "$WARM" -n "$AB_N" -H "Host: $HOST_HEADER" "$@" "$url" \
      > "$out-warmup.txt" 2>/dev/null
  sample_stats "$out-stats.txt" "$DUR" &
  local sampler=$!
  /usr/sbin/ab -k -r -c "$CONC" -t "$DUR" -n "$AB_N" -H "Host: $HOST_HEADER" "$@" "$url" \
      > "$out-ab.txt" 2>/dev/null
  wait "$sampler"
  log "[$name] complete=$(ab_field "$out-ab.txt" 'Complete requests') failed=$(ab_field "$out-ab.txt" 'Failed requests') non2xx=$(ab_field "$out-ab.txt" 'Non-2xx responses') qps=$(ab_field "$out-ab.txt" 'Requests per second') mean_ms=$(ab_field "$out-ab.txt" 'Time per request') p50=$(ab_pct "$out-ab.txt" '50%') p95=$(ab_pct "$out-ab.txt" '95%') p99=$(ab_pct "$out-ab.txt" '99%') max=$(ab_pct "$out-ab.txt" '100%')"
}

ev_wait() {                         # $1=endpoint_key $2=阈值 $3=final_action(可空) → 60s 轮询（参考值，backlog 下低报）
  local ev=0 _
  for _ in $(seq 1 30); do
    ev=$(ev_total "$1" "${3:-}")
    [ "${ev:-0}" -ge "$2" ] && break
    sleep 2
  done
  echo "${ev:-0}"
}

log "============================================================"
log "九章 §202 性能扩展矩阵实测  $(date '+%Y-%m-%d %H:%M:%S')（UTC $(date -u '+%H:%M:%S')）"
log "环境: $(uname -srm)  gateway=$GATEWAY_URL api=$API_URL"
log "参数: 并发=$CONC 计量=${DUR}s/臂 预热=${WARM}s ab=-k（长连接） 口径与 W18 一致"
log "镜像: api=$(docker inspect jiuzhang-stage5-api --format '{{.Image}}' | cut -c1-19) gateway=$(docker inspect jiuzhang-stage5-gateway --format '{{.Image}}' | cut -c1-19)"
log "原始数据目录: $WORK"
log "============================================================"

# ---------- 前置：登录 / 应用 / 策略现状 / 限速行前置检查 / 压测体生成 ----------
SYS_CSRF=$(s5_ensure_sysadmin) || { echo "ABORT: sysadmin login"; exit 1; }
SEC_CSRF=$(s5_ensure_secuser "$SYS_CSRF")
[ -z "$SEC_CSRF" ] && { echo "ABORT: sec login"; exit 1; }
APP_ID=$(s5_ensure_app "$SEC_CSRF")
log "[setup] app=$APP_ID"
POL_BEFORE=$(curl -s -b "/tmp/s5-$SEC_USER.txt" "$API_URL/api/v1/api-security/policy")
log "[setup] 策略现状: $(echo "$POL_BEFORE" | python3 -c "import json,sys; d=json.load(sys.stdin)['data']; print(d['edition'], d['api_dynamic_protection'], d['mode'], d['mode_source'])" 2>/dev/null)"
if rate_setting_exists; then
  log "ABORT: gateway_runtime/api_write_rate_per_minute 已存在（非本脚本所建则不覆盖）: $(psql_s5 "SELECT setting_value FROM system_settings WHERE $RATE_KEY_WHERE")"
  exit 1
fi
python3 - "$WORK" <<'EOF'
import json, sys
work = sys.argv[1]
def pad(target):
    body = {"order_id": 12345, "channel": "perf", "note": ""}
    base = len(json.dumps(body, separators=(",", ":")))
    body["note"] = "x" * (target - base)
    return json.dumps(body, separators=(",", ":"))
for name, size in (("body-1k.json", 1024), ("body-64k.json", 65536)):
    with open(f"{work}/{name}", "w") as f:
        f.write(pad(size))
EOF
log "[setup] 压测体: $(wc -c < "$WORK/body-1k.json" | tr -d ' ')B / $(wc -c < "$WORK/body-64k.json" | tr -d ' ')B（合法 JSON，字段数 3，长字符串填充）"

sample_stats "$WORK/idle-stats.txt" 6
log "[idle] $(stats_summary "$WORK/idle-stats.txt" | tr '\n' ' | ')"

# ---------- 臂1 baseline：去 wdsp 覆盖重建 api ----------
log "[baseline] 重建 api 容器（不带 wdsp 覆盖 → API_DYNAMIC_PROTECTION_ENABLED=false）"
preflight_only_api_changes || { log "ABORT: 预检发现非 api 容器将被重建"; exit 1; }
RESTORE_API=1
compose_api > "$WORK/compose-baseline.log" 2>&1 || { log "ABORT: compose baseline 失败"; exit 1; }
wait_api || exit 1
api_env_flag "false" || { log "ABORT: 基线臂 api 容器 API_DYNAMIC_PROTECTION_ENABLED 非 false"; exit 1; }
SEC_CSRF=$(s5_login "$SEC_USER" "$SEC_PWD")
PUB=$(s5_publish "$SEC_CSRF"); [ "$PUB" = "PUBLISH_OK" ] || { log "ABORT: 基线发布 $PUB"; exit 1; }
log "[baseline] 发布完成，网关代理自检 GET / -> $(s5_req "/")"
seq 1 20 | while read -r _; do s5_req "/v1/$PFX-base/0" > /dev/null; done
run_arm "baseline" "$URL_BASE" "$WORK/baseline"

# ---------- 臂2 observe：恢复 wdsp（OBSERVE 全管线，同 W18 full 臂） ----------
log "[observe] 恢复 api 容器为 wdsp 形态（API_DYNAMIC_PROTECTION_ENABLED=true）"
preflight_only_api_changes -f deployment/docker-compose.wdsp.yml || { log "ABORT: 预检发现非 api 容器将被重建"; exit 1; }
compose_api -f deployment/docker-compose.wdsp.yml > "$WORK/compose-observe.log" 2>&1 || { log "ABORT: compose observe 失败"; exit 1; }
wait_api || exit 1
api_env_flag "true" || { log "ABORT: observe 臂 api 容器 API_DYNAMIC_PROTECTION_ENABLED 非 true"; exit 1; }
SEC_CSRF=$(s5_login "$SEC_USER" "$SEC_PWD")
PUB=$(s5_publish "$SEC_CSRF"); [ "$PUB" = "PUBLISH_OK" ] || { log "ABORT: observe 发布 $PUB"; exit 1; }
RESTORE_API=0
seq 1 20 | while read -r _; do s5_req "/v1/$PFX-obs/0" > /dev/null; done
PROBE_EV=0
for _ in $(seq 1 10); do PROBE_EV=$(gw_ev_count "$PFX-obs"); [ "${PROBE_EV:-0}" -gt 0 ] && break; sleep 2; done
log "[observe] 管线活性探针网关侧事件数=${PROBE_EV:-0}（>0 才计量）"
[ "${PROBE_EV:-0}" -gt 0 ] || { log "ABORT: observe 臂管线无事件"; exit 1; }
run_arm "observe" "$URL_OBS" "$WORK/observe"

# ---------- 臂3 protect：策略切 PROTECT（敏感 query 真实 403 阻断 + 干净透传子测量） ----------
MODE=$(set_policy_mode PROTECT "$SEC_CSRF")
[ "$MODE" = "PROTECT" ] || { log "ABORT: 策略切换 PROTECT 失败（got '$MODE'）"; exit 1; }
RESTORE_POLICY=1
PUB=$(s5_publish "$SEC_CSRF"); [ "$PUB" = "PUBLISH_OK" ] || { log "ABORT: protect 发布 $PUB"; exit 1; }
log "[protect] 策略已切 PROTECT 并发布（db 覆盖，settings version=$(psql_s5 "SELECT version FROM system_settings WHERE setting_group='api_protection' AND setting_key='mode'")）"
# 行为断言：敏感 query URL 必须 403（真实阻断），干净 URL 必须透传（404 来自源站）
CODE_PROT=$(s5_req "/v1/$PFX-prot/1?password=perfprobe")
CODE_PROTOK=$(s5_req "/v1/$PFX-protok/1")
log "[protect] 阻断探针 GET prot?password=… -> ${CODE_PROT}（期望403）；透传探针 GET protok -> ${CODE_PROTOK}（期望404）"
[ "$CODE_PROT" = "403" ] || { log "ABORT: PROTECT 下敏感 query 未阻断（got ${CODE_PROT}）"; exit 1; }
[ "$CODE_PROTOK" = "404" ] || { log "ABORT: PROTECT 下干净 URL 未透传（got ${CODE_PROTOK}）"; exit 1; }
seq 1 20 | while read -r _; do s5_req "/v1/$PFX-prot/0?password=perfprobe" > /dev/null; done
run_arm "protect-block" "$URL_PROT" "$WORK/protect"
run_arm "protect-pass" "$URL_PROTOK" "$WORK/protect-pass"
# 臂3收尾：策略回 OBSERVE；与臂4的限速注入合并为一次发布
MODE=$(set_policy_mode OBSERVE "$SEC_CSRF")
[ "$MODE" = "OBSERVE" ] || { log "ABORT: 策略恢复 OBSERVE 失败（got '$MODE'）"; exit 1; }
RESTORE_POLICY=0
log "[protect] 策略已回 OBSERVE（待与臂4限速注入一同发布）"

# ---------- 臂4 body：临时提写限速 → POST 1KiB vs 64KiB JSON（OBSERVE） ----------
rate_setting_insert 200000000
RESTORE_RATE=1
log "[body] 临时写限速已注入（gateway_runtime/api_write_rate_per_minute=200000000，仅此一行）"
PUB=$(s5_publish "$SEC_CSRF"); [ "$PUB" = "PUBLISH_OK" ] || { log "ABORT: body 发布 $PUB"; exit 1; }
# 行为断言：100 个快速 POST 不得出现 429（限速已提）；OBSERVE 下透传为 404
RATE_PROBE=$(seq 1 100 | while read -r _; do curl -s -o /dev/null -w "%{http_code}\n" -H "Host: $HOST_HEADER" \
  -H 'Content-Type: application/json' -X POST --data '{"a":1}' "$GATEWAY_URL/v1/$PFX-body/1"; done | sort | uniq -c | tr '\n' ' ')
log "[body] 100×POST 探针响应分布: ${RATE_PROBE}（期望全 404，无 429）"
echo "$RATE_PROBE" | grep -q 429 && { log "ABORT: 提限速后仍现 429"; exit 1; }
run_arm "body-1k" "$URL_BODY" "$WORK/body1k" -p "$WORK/body-1k.json" -T application/json
run_arm "body-64k" "$URL_BODY" "$WORK/body64k" -p "$WORK/body-64k.json" -T application/json
# 臂4收尾：删临时限速行 + 发布（回到终态 wdsp + OBSERVE + 默认限速）
rate_setting_delete
RESTORE_RATE=0
PUB=$(s5_publish "$SEC_CSRF"); [ "$PUB" = "PUBLISH_OK" ] || { log "ABORT: 终态发布 $PUB"; exit 1; }
log "[body] 临时限速行已删除并发布（终态：wdsp + OBSERVE + 默认 60/min 写限速）"

# ---------- 事件计数校验（网关侧日志为精确口径；入库侧 60s 窗口在 backlog 下低报，仅参考，见 W18 §5） ----------
REQ_OBS=$(ab_field "$WORK/observe-ab.txt" 'Complete requests')
REQ_PROT=$(ab_field "$WORK/protect-ab.txt" 'Complete requests')
REQ_B1=$(ab_field "$WORK/body1k-ab.txt" 'Complete requests')
REQ_B64=$(ab_field "$WORK/body64k-ab.txt" 'Complete requests')
GEV_BASE=$(gw_ev_count "$PFX-base")
GEV_OBS=$(gw_ev_count "$PFX-obs")
GEV_PROT=$(gw_ev_count_action "$PFX-prot" "BLOCK")
GEV_PROTOK=$(gw_ev_count "$PFX-protok")
GEV_BODY=$(gw_ev_count "$PFX-body")
log "[verify-gw] 网关事件日志精确计数（含预热与探针，下限=计量+探针）: baseline=${GEV_BASE:-0}（必须=0） observe=${GEV_OBS:-0}/≥$((REQ_OBS+20)) protect-block=${GEV_PROT:-0}/≥$((REQ_PROT+20)) protect-pass=${GEV_PROTOK:-0} body=${GEV_BODY:-0}/≥$((REQ_B1+REQ_B64+100))"
EV_OBS=$(ev_wait "$EK_OBS" $(( REQ_OBS * 9 / 10 )))
EV_PROT=$(ev_wait "$EK_PROT" $(( REQ_PROT * 9 / 10 )) "BLOCK")
EV_BODY=$(ev_wait "$EK_BODY" $(( (REQ_B1 + REQ_B64) * 9 / 10 )))
EV_BASE=$(ev_total "$EK_BASE")
log "[verify-db] 采集入库计数（参考）: observe=${EV_OBS}/${REQ_OBS} protect BLOCK=${EV_PROT}/${REQ_PROT} body=${EV_BODY}/$(( REQ_B1 + REQ_B64 )) baseline=${EV_BASE:-0}（必须=0）"

# ---------- 汇总 ----------
log "============================================================"
log "资源消耗（压测窗口 docker stats 采样汇总）"
for a in idle baseline observe protect protect-pass body1k body64k; do
  f="$WORK/$a-stats.txt"; [ -f "$f" ] || continue
  log "[$a] $(stats_summary "$f" | tr '\n' ';')"
done
python3 - "$WORK" <<'EOF' | tee -a "$REPORT"
import re, sys
work = sys.argv[1]
def qps(name):
    t = open(f"{work}/{name}-ab.txt").read()
    return float(re.search(r"Requests per second:\s+([\d.]+)", t).group(1))
def pct(name, p):
    m = re.search(rf"^\s*{p}%\s+(\d+)", open(f"{work}/{name}-ab.txt").read(), re.M)
    return int(m.group(1))
b, o = qps("baseline"), qps("observe")
pb, pk = qps("protect"), qps("protect-pass")
b1, b64 = qps("body1k"), qps("body64k")
print(f"[delta] observe vs baseline   : {b:.2f} -> {o:.2f} QPS  开销={(b-o)/b*100:.1f}%  p95 {pct('baseline',95)}ms -> {pct('observe',95)}ms")
print(f"[delta] protect-block vs pass : {pk:.2f} -> {pb:.2f} QPS  差={(pk-pb)/pk*100:+.1f}%（负值=阻断短路省源站往返反而更快） p95 {pct('protect-pass',95)}ms -> {pct('protect',95)}ms")
print(f"[delta] protect-pass vs obs   : {o:.2f} -> {pk:.2f} QPS  模式本身开销={(o-pk)/o*100:+.1f}%  p95 {pct('observe',95)}ms -> {pct('protect-pass',95)}ms")
print(f"[delta] body 64KiB vs 1KiB    : {b1:.2f} -> {b64:.2f} QPS  大body开销={(b1-b64)/b1*100:.1f}%  p95 {pct('body1k',95)}ms -> {pct('body64k',95)}ms")
EOF

# ---------- 终态核验（共享环境恢复原状的证据，必须全部通过） ----------
log "============================================================"
log "终态核验:"
log "  容器: $(docker ps --format '{{.Names}}={{.Status}}' | grep stage5 | tr '\n' ' ')"
api_env_flag "true" && log "  api 容器环境: API_DYNAMIC_PROTECTION_ENABLED=true ✓" || log "  api 容器环境: ✗✗✗ 非 true"
SEC_CSRF=$(s5_login "$SEC_USER" "$SEC_PWD")
POL_FINAL=$(curl -s -b "/tmp/s5-$SEC_USER.txt" "$API_URL/api/v1/api-security/policy")
log "  策略: $(echo "$POL_FINAL" | python3 -c "import json,sys; d=json.load(sys.stdin)['data']; print(d['edition'], d['api_dynamic_protection'], d['mode'], d['mode_source'])" 2>/dev/null)（期望 wdsp True OBSERVE db）"
log "  临时限速行残留: $(psql_s5 "SELECT count(*) FROM system_settings WHERE $RATE_KEY_WHERE")（期望0）  api_protection.mode=$(psql_s5 "SELECT setting_value FROM system_settings WHERE setting_group='api_protection' AND setting_key='mode'")"
log "  网关自检: GET / -> $(s5_req "/")  GET obs -> $(s5_req "/v1/$PFX-obs/1")（期望404透传）  GET prot?password=… -> $(s5_req "/v1/$PFX-prot/1?password=perfprobe")（OBSERVE 下期望404不再403）"
log "  数据抽查: applications=$(psql_s5 "SELECT count(*) FROM applications") api_endpoints=$(psql_s5 "SELECT count(*) FROM api_endpoints") api_runtime_events=$(psql_s5 "SELECT count(*) FROM api_runtime_events") users=$(psql_s5 "SELECT count(*) FROM users")"
log "============================================================"
log "完成。原始 ab 输出与 stats 采样保留于 $WORK"
