#!/usr/bin/env bash
# 九章 §202 性能追补矩阵（W18 两档 / §10 四臂之后剩余缺口分片，口径与前两轮完全一致：c=20×30s + 5s 预热）。
#   六测量（每臂唯一路径前缀防串扰）：
#     1) baseline    ：wdsp off + 应用 OFF（纯反代参照，本轮复测）；
#     2) waf-only    ：wdsp off + 应用 protection_mode=OBSERVE（SecRuleEngine DetectionOnly，全量 CRS PL1
#                       评估不阻断）——回答「WAF(Coraza) 本身开销 vs API 动态防护开销」；
#                       切换经管理面 PUT /api/v1/applications/{id}（GET 全量回传仅改 mode+version，
#                       乐观锁），测完同路径回 OFF；s5app 无策略绑定（application_policies 0 行，
#                       publisher.go:631 的覆盖不生效），应用字段直达发布；
#     3) observe-api ：wdsp on + 策略 OBSERVE + 应用 OFF（API 防护开销参照，本轮复测）；
#     4) mp-512k     ：OBSERVE 下 POST multipart/form-data 单文件 512KiB（体 ~512.2KiB <
#                       max_body_parse_bytes=1MiB，完整流式解析，BodyTruncated=false）；
#     5) mp-1m       ：同形态 POST 1MiB 文件（体 ~1.0002MiB > 1MiB → 解析至上限截断，
#                       BodyTruncated=true）——隔离「完整解析 vs 截断」与体长成本；
#                       【harness 修正】multipart 两臂统一打 testorigin /upload 固定路由
#                       （buildEcho 完整读取 ≤1MiB body 回 200）：首版打未知路径（404）时
#                       源站早期响应截断上传（Go net/http 未读 body >256KB 即关连接），
#                       1MiB 臂 ab 写错误早退不可测（见 matrix2b 注释与 §11 过程发现）；
#     6) conc100     ：OBSERVE GET c=100 × 15s 短促观察臂（错误率/p99 拐点；防压垮共享环境不做长时高压）。
#
# 与实现对齐的关键事实（先读后改结论）：
#   - 应用 OFF → SecRuleEngine Off（generator.go:16-20 modeToRuleEngine），规则加载但不评估；
#     OBSERVE → DetectionOnly（全量评估不阻断），coraza-audit.log（SecAuditEngine On）下
#     engine Off 的条目 uri/args 为空、DetectionOnly 条目含完整请求与命中消息——
#     用 run 唯一 marker 探针 grep 审计日志即可双侧证明臂2真评估、臂1真跳过；
#   - multipart 走流式解析（parser/parse_multipart.go）：逐 part 记录元数据，内容经
#     io.Discard 丢弃但 TeeReader 同步逐字节 FNV-1a 计数（hashCounter.Write 为逐字节循环），
#     体长成本主要来自传输+逐字节哈希；总字节超 MaxBodyParseBytes 置 BodyTruncated；
#   - 写方法 60/min/端点限速沿用 W19 手法：system_settings 注入
#     gateway_runtime/api_write_rate_per_minute=200000000（仅此一行），测完删行再发布，精确可逆；
#   - 采集器入库在事件风暴后 backlog 分钟级（W18 §5）：observe-api 臂后排空等待（drain，轮询
#     入库计数 vs 网关侧日志计数，上限 10min）再测 multipart，降低臂间噪声；conc100 前短 drain。
#
# 共享环境铁律（与前两轮相同并扩展）：
#   - compose 只重建 api（--no-deps + dry-run 预检），数据容器严禁重建；端口覆盖同 W18；
#   - 任何退出路径经 EXIT trap 恢复：api 回 wdsp 形态、应用回 OFF、删临时限速行、重新发布；
#   - 策略全程 OBSERVE 不动（本矩阵无需切 PROTECT）；终态核验打印在报告尾部。
#
# 用法（仓库根目录）：bash test/performance/w18-performance-matrix2.sh
# 结果写入 test/performance/w18-performance-matrix2-result.txt；原始数据保留在 /tmp/w18-matrix2-<TS>/。
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SCRIPT_DIR/../waf/scripts/stage5-setup.sh"

TS=$(date +%s)
PFX="w18x$TS"
URL_BASE="$GATEWAY_URL/v1/$PFX-base/1"
URL_WAF="$GATEWAY_URL/v1/$PFX-waf/1"
URL_OBS="$GATEWAY_URL/v1/$PFX-obs/1"
URL_CONC="$GATEWAY_URL/v1/$PFX-conc/1"
EK_OBS="GET /v1/$PFX-obs/{id}"
URL_UP="$GATEWAY_URL/upload"                 # multipart 两臂统一打 /upload（源站读 body，见文件头注释）
EK_UP="POST /upload"                         # multipart 两臂共用固定路由（源站消费 body）
MK="w18mk$TS"                                # Coraza 审计日志探针 marker（run 唯一，纯字母数字）
WORK="/tmp/w18-matrix2-$TS"
mkdir -p "$WORK"

CONC=20; DUR=30; WARM=5; AB_N=5000000        # 与前两轮同口径（conc100 臂单独传参）

REPORT="$SCRIPT_DIR/w18-performance-matrix2-result.txt"
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
rate_setting_insert() {
  psql_s5 "INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, description) \
VALUES ('gateway_runtime','api_write_rate_per_minute','\"$1\"'::jsonb,'string',\
'W18-PERF 追补矩阵临时提升写限速（测完即删，勿手工保留）')" > /dev/null
}
rate_setting_delete() { psql_s5 "DELETE FROM system_settings WHERE $RATE_KEY_WHERE" > /dev/null; }

app_mode_get() {                    # 打印 s5app 当前 protection_mode
  curl -s -b "/tmp/s5-$SEC_USER.txt" "$API_URL/api/v1/applications/$APP_ID" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['protection_mode'])" 2>/dev/null
}

set_app_mode() {                    # $1=mode $2=csrf → GET 全量回传仅改 mode（乐观锁带 version），打印生效 mode
  local app body
  app=$(curl -s -b "/tmp/s5-$SEC_USER.txt" "$API_URL/api/v1/applications/$APP_ID")
  body=$(echo "$app" | MODE="$1" python3 -c "
import json, os, sys
a = json.load(sys.stdin)['data']
print(json.dumps({'name': a['name'], 'description': a.get('description', ''),
  'business_owner': a.get('business_owner', ''), 'technical_owner': a.get('technical_owner', ''),
  'protection_mode': os.environ['MODE'], 'version': a['version']}))")
  curl -s -b "/tmp/s5-$SEC_USER.txt" -X PUT "$API_URL/api/v1/applications/$APP_ID" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $2" -d "$body" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['protection_mode'])" 2>/dev/null
}

RESTORE_API=0; RESTORE_APPMODE=0; RESTORE_RATE=0
# 任何退出路径都尽力恢复终态（api 回 wdsp + 应用回 OFF + 无临时限速行 + 重新发布）——共享环境硬要求
restore_env() {
  local csrf
  if [ "$RESTORE_API" = "1" ]; then
    echo "[restore] 恢复 api 容器为 wdsp 形态…" | tee -a "$REPORT"
    compose_api -f deployment/docker-compose.wdsp.yml >> "$WORK/compose-restore.log" 2>&1
    wait_api || true
  fi
  [ "$RESTORE_API" = "1" ] || [ "$RESTORE_APPMODE" = "1" ] || [ "$RESTORE_RATE" = "1" ] || return 0
  csrf=$(s5_login "$SEC_USER" "$SEC_PWD")
  if [ "$RESTORE_APPMODE" = "1" ] && [ -n "$csrf" ]; then
    echo "[restore] 应用回 OFF（当前: $(set_app_mode OFF "$csrf")）" | tee -a "$REPORT"
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

ev_total() {                        # $1=endpoint_key → 主事件入库总数（backlog 下滞后，仅 drain/参考用）
  curl -s -b "/tmp/s5-$SEC_USER.txt" -G "$API_URL/api/v1/api-security/runtime/events" \
    --data-urlencode "endpoint_key=$1" --data-urlencode "page_size=1" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['data'].get('total', 0))" 2>/dev/null
}

gw_ev_count() {                     # $1=路径前缀子串 → 网关事件日志行数（精确口径，不受 backlog 影响）
  docker exec jiuzhang-stage5-gateway sh -c \
    "grep -c '$1' /var/log/caddy/api-runtime-events.log" 2>/dev/null
}

# 网关事件日志时间窗计数：$1=窗口起点 ISO 秒 $2=raw_path 子串（multipart 臂共用 /upload 固定路由，
# 无 run 唯一路径，按 occurred_at ≥ 起点过滤；occurred_at 为变长小数，须 datetime 比较而非字典序）
gw_ev_count_since() {
  docker exec jiuzhang-stage5-gateway sh -c \
    "grep '\"raw_path\":\"$2\"' /var/log/caddy/api-runtime-events.log" 2>/dev/null \
    | python3 -c "
import json, sys
from datetime import datetime, timezone
since = datetime.fromisoformat('$1').replace(tzinfo=timezone.utc)
n = 0
for line in sys.stdin:
    try:
        ts = datetime.fromisoformat(json.loads(line)['occurred_at']).replace(tzinfo=timezone.utc)
        if ts >= since:
            n += 1
    except Exception:
        pass
print(n)"
}

audit_count() {                     # $1=子串 → coraza-audit.log 匹配行数（marker run 唯一，全文件 grep 安全）
  docker exec jiuzhang-stage5-gateway sh -c \
    "grep -c '$1' /var/log/caddy/coraza-audit.log" 2>/dev/null
}
audit_count_field() {               # $1=子串 $2=二级子串 → 双条件行数
  docker exec jiuzhang-stage5-gateway sh -c \
    "grep '$1' /var/log/caddy/coraza-audit.log | grep -c '$2'" 2>/dev/null
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

run_arm() {                         # $1=臂名 $2=URL $3=输出前缀 $4=并发 $5=计量秒；剩余=额外 ab 参数
  local name="$1" url="$2" out="$3" conc="$4" dur="$5"; shift 5
  /usr/sbin/ab -k -r -c 5 -t "$WARM" -n "$AB_N" -H "Host: $HOST_HEADER" "$@" "$url" \
      > "$out-warmup.txt" 2>/dev/null
  sample_stats "$out-stats.txt" "$dur" &
  local sampler=$!
  /usr/sbin/ab -k -r -c "$conc" -t "$dur" -n "$AB_N" -H "Host: $HOST_HEADER" "$@" "$url" \
      > "$out-ab.txt" 2>/dev/null
  wait "$sampler"
  log "[$name] complete=$(ab_field "$out-ab.txt" 'Complete requests') failed=$(ab_field "$out-ab.txt" 'Failed requests') non2xx=$(ab_field "$out-ab.txt" 'Non-2xx responses') qps=$(ab_field "$out-ab.txt" 'Requests per second') mean_ms=$(ab_field "$out-ab.txt" 'Time per request') p50=$(ab_pct "$out-ab.txt" '50%') p95=$(ab_pct "$out-ab.txt" '95%') p99=$(ab_pct "$out-ab.txt" '99%') max=$(ab_pct "$out-ab.txt" '100%')"
}

drain_wait() {                      # $1=endpoint_key $2=目标入库数 $3=上限轮数(30s/轮) → 打印追平情况
  local i ev=0
  for i in $(seq 1 "$3"); do
    ev=$(ev_total "$1")
    [ "${ev:-0}" -ge "$2" ] && { echo "${ev:-0} (iter=$i)"; return 0; }
    sleep 30
  done
  echo "${ev:-0} (DRAIN_TIMEOUT)"
}

log "============================================================"
log "九章 §202 性能追补矩阵实测  $(date '+%Y-%m-%d %H:%M:%S')（UTC $(date -u '+%H:%M:%S')）"
log "环境: $(uname -srm)  gateway=$GATEWAY_URL api=$API_URL"
log "参数: 并发=$CONC 计量=${DUR}s/臂 预热=${WARM}s ab=-k（长连接） 口径与 W18/§10 一致；conc100 臂 c=100×15s"
log "镜像: api=$(docker inspect jiuzhang-stage5-api --format '{{.Image}}' | cut -c1-19) gateway=$(docker inspect jiuzhang-stage5-gateway --format '{{.Image}}' | cut -c1-19)"
log "原始数据目录: $WORK"
log "============================================================"

# ---------- 前置：登录 / 应用 / 策略与应用现状 / 限速行前置检查 / multipart 压测体生成 ----------
SYS_CSRF=$(s5_ensure_sysadmin) || { echo "ABORT: sysadmin login"; exit 1; }
SEC_CSRF=$(s5_ensure_secuser "$SYS_CSRF")
[ -z "$SEC_CSRF" ] && { echo "ABORT: sec login"; exit 1; }
APP_ID=$(s5_ensure_app "$SEC_CSRF")
log "[setup] app=$APP_ID"
POL_BEFORE=$(curl -s -b "/tmp/s5-$SEC_USER.txt" "$API_URL/api/v1/api-security/policy")
log "[setup] 策略现状: $(echo "$POL_BEFORE" | python3 -c "import json,sys; d=json.load(sys.stdin)['data']; print(d['edition'], d['api_dynamic_protection'], d['mode'], d['mode_source'])" 2>/dev/null)"
echo "$POL_BEFORE" | grep -q '"mode":"OBSERVE"' || { log "ABORT: 策略非 OBSERVE，本矩阵不接管他人状态"; exit 1; }
APP_MODE_BEFORE=$(app_mode_get)
log "[setup] 应用 protection_mode=${APP_MODE_BEFORE}（期望 OFF，否则不接管）"
[ "$APP_MODE_BEFORE" = "OFF" ] || { log "ABORT: 应用 protection_mode 非 OFF（=${APP_MODE_BEFORE}），不覆盖他人状态"; exit 1; }
if rate_setting_exists; then
  log "ABORT: gateway_runtime/api_write_rate_per_minute 已存在（非本脚本所建则不覆盖）"
  exit 1
fi
BOUNDARY="W18MPBOUNDARY$TS"
python3 - "$WORK" "$BOUNDARY" <<'EOF'
import sys
work, boundary = sys.argv[1], sys.argv[2]
cell = bytes((i * 37 + 11) % 256 for i in range(4096))
def mp(path, payload_size, fname):
    head = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; "
            f"filename=\"{fname}\"\r\nContent-Type: application/octet-stream\r\n\r\n").encode()
    tail = f"\r\n--{boundary}--\r\n".encode()
    payload = cell * (payload_size // 4096)
    with open(path, "wb") as f:
        f.write(head + payload + tail)
    return len(head) + len(payload) + len(tail)
n1 = mp(f"{work}/mp-512k.bin", 524288, "perf-512k.bin")
n2 = mp(f"{work}/mp-1m.bin", 1048576, "perf-1m.bin")
print(f"mp-512k body={n1}B (< 1MiB 解析上限, 完整解析)  mp-1m body={n2}B (> 1MiB, 截断)", flush=True)
EOF
log "[setup] multipart 压测体: $(wc -c < "$WORK/mp-512k.bin" | tr -d ' ')B / $(wc -c < "$WORK/mp-1m.bin" | tr -d ' ')B（单文件 part，boundary=${BOUNDARY}）"

sample_stats "$WORK/idle-stats.txt" 6
log "[idle] $(stats_summary "$WORK/idle-stats.txt" | tr '\n' ' | ')"

# ---------- 臂1 baseline：去 wdsp 覆盖重建 api + 应用 OFF（纯反代，本轮复测） ----------
log "[baseline] 重建 api 容器（不带 wdsp 覆盖 → API_DYNAMIC_PROTECTION_ENABLED=false）"
preflight_only_api_changes || { log "ABORT: 预检发现非 api 容器将被重建"; exit 1; }
RESTORE_API=1
compose_api > "$WORK/compose-baseline.log" 2>&1 || { log "ABORT: compose baseline 失败"; exit 1; }
wait_api || exit 1
api_env_flag "false" || { log "ABORT: 基线臂 api 容器 API_DYNAMIC_PROTECTION_ENABLED 非 false"; exit 1; }
SEC_CSRF=$(s5_login "$SEC_USER" "$SEC_PWD")
PUB=$(s5_publish "$SEC_CSRF"); [ "$PUB" = "PUBLISH_OK" ] || { log "ABORT: 基线发布 $PUB"; exit 1; }
log "[baseline] 发布完成，网关代理自检 GET / -> $(s5_req "/")"
# Coraza 未评估对照探针：engine Off 时审计条目 uri/args 为空，marker 必须 0 命中
seq 1 5 | while read -r _; do
  curl -s -o /dev/null -G -H "Host: $HOST_HEADER" --data-urlencode "$MK=<script>alert(1)</script>" \
    "$GATEWAY_URL/v1/$PFX-base/1" > /dev/null
done
sleep 1
AUD_BASE=$(audit_count "$MK")
log "[baseline] Coraza 对照探针 marker 命中审计日志=${AUD_BASE:-0}（期望 0 = engine Off 真跳过）"
[ "${AUD_BASE:-0}" = "0" ] || log "WARN: 基线臂 marker 命中非 0，Coraza Off 断言存疑（如实记录继续）"
run_arm "baseline" "$URL_BASE" "$WORK/baseline" "$CONC" "$DUR"

# ---------- 臂2 waf-only：wdsp off + 应用 OBSERVE（Coraza DetectionOnly 全量 CRS） ----------
MODE=$(set_app_mode OBSERVE "$SEC_CSRF")
[ "$MODE" = "OBSERVE" ] || { log "ABORT: 应用切 OBSERVE 失败（got '$MODE'）"; exit 1; }
RESTORE_APPMODE=1
PUB=$(s5_publish "$SEC_CSRF"); [ "$PUB" = "PUBLISH_OK" ] || { log "ABORT: waf-only 发布 $PUB"; exit 1; }
log "[waf-only] 应用已切 OBSERVE（SecRuleEngine DetectionOnly）并发布"
# Coraza 活性断言：marker 必须命中审计日志且条目为 DetectionOnly；干净 GET 必须透传（DetectionOnly 不阻断）
seq 1 5 | while read -r _; do
  curl -s -o /dev/null -G -H "Host: $HOST_HEADER" --data-urlencode "$MK=<script>alert(1)</script>" \
    "$GATEWAY_URL/v1/$PFX-waf/1" > /dev/null
done
sleep 1
AUD_WAF=$(audit_count "$MK")
AUD_WAF_DET=$(audit_count_field "$MK" "DetectionOnly")
AUD_WAF_XSS=$(audit_count_field "$MK" "XSS")
CODE_WAF=$(s5_req "/v1/$PFX-waf/1")
log "[waf-only] 探针: marker 命中=${AUD_WAF:-0}（DetectionOnly 条目=${AUD_WAF_DET:-0}，含 XSS 命中消息=${AUD_WAF_XSS:-0}）；干净 GET -> ${CODE_WAF}（期望404透传）"
[ "${AUD_WAF_DET:-0}" -gt 0 ] || { log "ABORT: Coraza DetectionOnly 未评估（审计日志无 marker）"; exit 1; }
[ "$CODE_WAF" = "404" ] || { log "ABORT: DetectionOnly 下干净 GET 未透传（got ${CODE_WAF}）"; exit 1; }
run_arm "waf-only" "$URL_WAF" "$WORK/wafonly" "$CONC" "$DUR"
# 臂2收尾：应用回 OFF（待与臂3的 wdsp 重建合并为一次发布）
MODE=$(set_app_mode OFF "$SEC_CSRF")
[ "$MODE" = "OFF" ] || { log "ABORT: 应用恢复 OFF 失败（got '$MODE'）"; exit 1; }
RESTORE_APPMODE=0
log "[waf-only] 应用已回 OFF（待与 wdsp 重建一同发布）"

# ---------- 臂3 observe-api：恢复 wdsp（OBSERVE 全管线 + 应用 OFF，本轮复测参照） ----------
log "[observe-api] 恢复 api 容器为 wdsp 形态（API_DYNAMIC_PROTECTION_ENABLED=true）"
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
log "[observe-api] 管线活性探针网关侧事件数=${PROBE_EV:-0}（>0 才计量）"
[ "${PROBE_EV:-0}" -gt 0 ] || { log "ABORT: observe 臂管线无事件"; exit 1; }
run_arm "observe-api" "$URL_OBS" "$WORK/observe" "$CONC" "$DUR"

# ---------- drain：等采集器追平 observe-api 事件（上限 10min），降低后续臂噪声 ----------
OBS_GW=$(gw_ev_count "$PFX-obs")
log "[drain] observe-api 网关侧事件=${OBS_GW:-0}，等待入库追平至 ≥90%（30s 轮询，上限 20 轮）…"
DRAIN_OBS=$(drain_wait "$EK_OBS" $(( ${OBS_GW:-0} * 9 / 10 )) 20)
log "[drain] observe-api 入库追平: $DRAIN_OBS / 网关侧 ${OBS_GW:-0}"

# ---------- 臂4/5 multipart：临时提写限速 → POST 512KiB vs 1MiB 文件到 /upload（OBSERVE） ----------
rate_setting_insert 200000000
RESTORE_RATE=1
log "[multipart] 临时写限速已注入（gateway_runtime/api_write_rate_per_minute=200000000，仅此一行）"
PUB=$(s5_publish "$SEC_CSRF"); [ "$PUB" = "PUBLISH_OK" ] || { log "ABORT: multipart 发布 $PUB"; exit 1; }
RATE_PROBE=$(seq 1 100 | while read -r _; do curl -s -o /dev/null -w "%{http_code}\n" -H "Host: $HOST_HEADER" \
  -H 'Content-Type: application/json' -X POST --data '{"a":1}' "$URL_UP"; done | sort | uniq -c | tr '\n' ' ')
log "[multipart] 100×POST /upload 探针响应分布: ${RATE_PROBE}（期望全 200，无 429）"
echo "$RATE_PROBE" | grep -q 429 && { log "ABORT: 提限速后仍现 429"; exit 1; }
WIN_MP=$(date -u '+%Y-%m-%dT%H:%M:%S')       # /upload 时间窗计数起点（两臂共用）
run_arm "mp-512k" "$URL_UP" "$WORK/mp512" "$CONC" "$DUR" \
  -p "$WORK/mp-512k.bin" -T "multipart/form-data; boundary=$BOUNDARY"
run_arm "mp-1m" "$URL_UP" "$WORK/mp1m" "$CONC" "$DUR" \
  -p "$WORK/mp-1m.bin" -T "multipart/form-data; boundary=$BOUNDARY"
# 臂4/5收尾：删临时限速行 + 发布（回终态默认限速）
rate_setting_delete
RESTORE_RATE=0
PUB=$(s5_publish "$SEC_CSRF"); [ "$PUB" = "PUBLISH_OK" ] || { log "ABORT: 删限速行后发布 $PUB"; exit 1; }
log "[multipart] 临时限速行已删除并发布（终态：默认 60/min 写限速）"

# ---------- drain（短）：multipart 事件量小，上限 3min，再测 conc100 ----------
MP_GW=$(gw_ev_count_since "$WIN_MP" "/upload")
DRAIN_MP=$(drain_wait "$EK_UP" $(( ${MP_GW:-0} * 9 / 10 )) 6)
log "[drain] multipart 入库追平: ${DRAIN_MP} / 网关侧时间窗 ${MP_GW:-0}（自 ${WIN_MP}）"

# ---------- 臂6 conc100：c=100 × 15s 短促观察（错误率与 p99 拐点；最后测，噪声不影响他臂） ----------
run_arm "conc100" "$URL_CONC" "$WORK/conc100" 100 15

# ---------- 事件计数校验（网关侧日志精确口径） ----------
REQ_OBS=$(ab_field "$WORK/observe-ab.txt" 'Complete requests')
REQ_MP512=$(ab_field "$WORK/mp512-ab.txt" 'Complete requests')
REQ_MP1M=$(ab_field "$WORK/mp1m-ab.txt" 'Complete requests')
REQ_CONC=$(ab_field "$WORK/conc100-ab.txt" 'Complete requests')
GEV_BASE=$(gw_ev_count "$PFX-base")
GEV_WAF=$(gw_ev_count "$PFX-waf")
GEV_OBS=$(gw_ev_count "$PFX-obs")
GEV_MP=$(gw_ev_count_since "$WIN_MP" "/upload")
GEV_CONC=$(gw_ev_count "$PFX-conc")
log "[verify-gw] 网关事件日志精确计数（含预热与探针）: baseline=${GEV_BASE:-0}（必须=0） waf-only=${GEV_WAF:-0}（必须=0，Coraza 不产 API 事件） observe-api=${GEV_OBS:-0}/≥$((REQ_OBS+20)) multipart窗口=${GEV_MP:-0}/≥$((REQ_MP512+REQ_MP1M+100))（自 ${WIN_MP}） conc100=${GEV_CONC:-0}/≥${REQ_CONC}"

# ---------- 汇总 ----------
log "============================================================"
log "资源消耗（压测窗口 docker stats 采样汇总）"
for a in idle baseline wafonly observe mp512 mp1m conc100; do
  f="$WORK/$a-stats.txt"; [ -f "$f" ] || continue
  log "[$a] $(stats_summary "$f" | tr '\n' ';')"
done
python3 - "$WORK" <<'EOF' | tee -a "$REPORT"
import re, sys
work = sys.argv[1]
def qps(name):
    try:
        t = open(f"{work}/{name}-ab.txt").read()
    except OSError:
        return None
    m = re.search(r"Requests per second:\s+([\d.]+)", t)
    return float(m.group(1)) if m else None
def pct(name, p):
    try:
        t = open(f"{work}/{name}-ab.txt").read()
    except OSError:
        return None
    m = re.search(rf"^\s*{p}%\s+(\d+)", t, re.M)
    return int(m.group(1)) if m else None
def delta(label, hi, lo, note):
    a, b = qps(hi), qps(lo)
    if a and b:
        print(f"[delta] {label}: {a:.2f} -> {b:.2f} QPS  {note}={(a-b)/a*100:.1f}%  p95 {pct(hi,95)}ms -> {pct(lo,95)}ms")
    else:
        print(f"[delta] {label}: 缺臂数据，跳过（如实记录）")
delta("waf-only vs baseline   ", "baseline", "wafonly", "WAF(Coraza)开销")
delta("observe-api vs baseline", "baseline", "observe", "API防护开销")
delta("mp-1m vs mp-512k       ", "mp512", "mp1m", "体长翻倍开销")
EOF

# ---------- 终态核验（共享环境恢复原状的证据，必须全部通过） ----------
log "============================================================"
log "终态核验:"
log "  容器: $(docker ps --format '{{.Names}}={{.Status}}' | grep stage5 | tr '\n' ' ')"
api_env_flag "true" && log "  api 容器环境: API_DYNAMIC_PROTECTION_ENABLED=true ✓" || log "  api 容器环境: ✗✗✗ 非 true"
SEC_CSRF=$(s5_login "$SEC_USER" "$SEC_PWD")
POL_FINAL=$(curl -s -b "/tmp/s5-$SEC_USER.txt" "$API_URL/api/v1/api-security/policy")
log "  策略: $(echo "$POL_FINAL" | python3 -c "import json,sys; d=json.load(sys.stdin)['data']; print(d['edition'], d['api_dynamic_protection'], d['mode'], d['mode_source'])" 2>/dev/null)（期望 wdsp True OBSERVE db）"
log "  应用 protection_mode=$(app_mode_get)（期望 OFF）  临时限速行残留: $(psql_s5 "SELECT count(*) FROM system_settings WHERE $RATE_KEY_WHERE")（期望0）"
log "  网关自检: GET / -> $(s5_req "/")  GET obs -> $(s5_req "/v1/$PFX-obs/1")（期望404透传）"
# 写限速复核：默认 60/min 精确生效应为 60×200+10×429；若首轮未见 429（发布热更新瞬态曾观测到
# 全放行，60s 后复核精确生效），等待窗口滑过后复核一次再记录
probe_rate() { seq 1 70 | while read -r _; do curl -s -o /dev/null -w "%{http_code}\n" -H "Host: $HOST_HEADER" \
  -H 'Content-Type: application/json' -X POST --data '{"a":1}' "$URL_UP"; done | sort | uniq -c | tr '\n' ' '; }
RATE_FINAL=$(probe_rate)
echo "$RATE_FINAL" | grep -q 429 || { log "  写限速复核首轮无 429（=${RATE_FINAL}），65s 后复核…"; sleep 65; RATE_FINAL=$(probe_rate); }
log "  写限速复核: 70×POST /upload 分布 ${RATE_FINAL}（期望 60×200+10×429 = 默认 60/min）"
log "  数据抽查: applications=$(psql_s5 "SELECT count(*) FROM applications") api_endpoints=$(psql_s5 "SELECT count(*) FROM api_endpoints") api_runtime_events=$(psql_s5 "SELECT count(*) FROM api_runtime_events") users=$(psql_s5 "SELECT count(*) FROM users")"
log "============================================================"
log "完成。原始 ab 输出与 stats 采样保留于 $WORK"
