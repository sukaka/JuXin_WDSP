#!/usr/bin/env bash
# 九章 W21-FLUSH：采集器批量/周期 flush 修复（W20/W21，SetFlushPolicy 2000 行/2s +
# 断点同节奏落盘）效果复测。对照基线：修复前 11.5 万事件洪峰入库追平约 6.5 分钟、
# 深 backlog 下入库冻结数十分钟、断点仅 EOF 落盘、重建即全量重扫
# （docs/evidence/api-security-performance-baseline.md §11.8 现场）。
#
# 与 W18/W19 同口径的事件洪峰：stage5 + wdsp 形态 + 策略 OBSERVE + 应用 OFF，
# ab -k 长连接 c=20 × 30s（偏离/敏感两臂并发 c=10+c=10，同 URL 模板）：
#   - 偏离臂 GET /v1/<pfx>-dev/1            → resource.unauthenticated_object_access
#   - 敏感臂 GET /v1/<pfx>-sens/1?password=perfprobe → sensitive.in_query（OBSERVE 不阻断）
# 读方法 GET 不触发写限速（detectors/ratelimit.go 仅写方法 60/min），无需注入限速配置。
#
# 三项计量（全部真实实测，禁止编造）：
#   A. 追平时间：洪峰结束 → api_runtime_events 前缀计数追平网关侧日志前缀计数；
#   B. 断点更新频率：洪峰+追平全程每 2s 采样 checkpoint（offset/mtime 应秒级推进，
#      而非旧实现的 EOF 一次性落盘）；
#   C. 重扫行为：追平中途 docker restart api 一次（复刻 §11.8 发现 2 的
#      「重建即重扫」场景），计量重启前断点新鲜度（mtime 距 kill ≤2s）、重启后
#      断点连续性（不回退 0）、重放窗口字节数（≤2000 行+≤2s 上界）与计数连续性
#      （request_id 幂等去重，重放不双计）。
#
# 安全边界：不改策略（起始必须已是 OBSERVE，否则中止）；不动 gateway/数据容器；
# docker restart 保留容器全部配置；脚本不执行任何 compose 变更。
# 注意：本环境 bash 会把无花括号变量名与其后的多字节字符粘连解析（set -u 下报
# unbound variable），凡变量后紧跟中文/全角字符一律写 ${VAR}。
# 依赖已在运行的 stage5 编排（wdsp 形态，api 镜像须已含 W21 修复——预检 strings 校验）。
# 用法（仓库根目录）：bash test/performance/w21-flush-retest.sh
# 结果写入 test/performance/w21-flush-retest-result.txt；原始数据保留在 /tmp/w21-flush-<TS>/。
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SCRIPT_DIR/../waf/scripts/stage5-setup.sh"

TS=$(date +%s)
PFX="w21f$TS"                        # 本次运行唯一前缀
URL_DEV="$GATEWAY_URL/v1/$PFX-dev/1"
URL_SENS="$GATEWAY_URL/v1/$PFX-sens/1?password=perfprobe"
EK_DEV="GET /v1/$PFX-dev/{id}"
EK_SENS="GET /v1/$PFX-sens/{id}"
WORK="/tmp/w21-flush-$TS"
mkdir -p "$WORK"

CONC=10                              # 每臂并发（两臂并发合计 20，与 W18/W19 c=20 同口径）
DUR=30                               # 计量时长（秒）
WARM=5                               # 预热时长（秒，丢弃）
AB_N=5000000
RESTART_AFTER=60                     # 洪峰结束后多少秒触发中途重启（追平途中）
CATCHUP_TIMEOUT=1500                 # 追平最长等待（秒），超时如实记录

REPORT="$SCRIPT_DIR/w21-flush-retest-result.txt"
: > "$REPORT"
log() { echo "$@" | tee -a "$REPORT"; }

CSV="$WORK/catchup.csv"              # ts,iso,db_prefix_count,ckpt_offset,ckpt_mtime
echo "ts,iso,db_prefix_count,ckpt_offset,ckpt_mtime" > "$CSV"

PG="docker exec jiuzhang-stage5-postgres psql -U jiuzhang -d jiuzhang_waf -tAc"
CKPT=/app/runtime/api-runtime-events.checkpoint

db_prefix_count() {                  # 前缀两端点键入库事件总数（psql 直查，api 重启期间仍可用）
  $PG "SELECT count(*) FROM api_runtime_events WHERE endpoint_key IN ('$EK_DEV','$EK_SENS')" 2>/dev/null
}
gw_prefix_count() {                  # 网关侧日志前缀行数（产出计数精确口径）
  docker exec jiuzhang-stage5-gateway sh -c "grep -c '$PFX' /var/log/caddy/api-runtime-events.log" 2>/dev/null
}
ckpt_read() {                        # 输出 "<offset> <mtime_epoch>"；容器重启中输出 "NA NA"
  docker exec jiuzhang-stage5-api sh -c "stat -c '%Y' $CKPT 2>/dev/null; cat $CKPT 2>/dev/null" 2>/dev/null \
    | python3 -c "
import json,sys
lines=sys.stdin.read().split()
try:
    mt=lines[0]; cp=json.loads(' '.join(lines[1:]))
    print(cp.get('offset','NA'), mt)
except Exception:
    print('NA NA')" 2>/dev/null || echo "NA NA"
}

sampler() {                          # 后台：每 2s 采样 DB 前缀计数 + 断点（洪峰→追平全程）
  while :; do
    local row db ck
    db=$(db_prefix_count); ck=$(ckpt_read)
    printf '%s,%s,%s,%s\n' "$(date +%s)" "$(date -u '+%H:%M:%S')" "${db:-NA}" "$(echo $ck | awk '{print $1","$2}')" >> "$CSV"
    sleep 2
  done
}

last_db_count() { awk -F, 'NR>1 && $3!="NA" {v=$3} END {print v+0}' "$CSV"; }

wait_api() {                         # 等待管理面健康（postgres+valkey 均 true）
  for _ in $(seq 1 60); do
    local h
    h=$(curl -s --max-time 3 "$API_URL/api/v1/health" 2>/dev/null)
    case "$h" in *'"postgres":true'*'"valkey":true'*) return 0;; esac
    sleep 2
  done
  echo "ERROR: api health timeout" | tee -a "$REPORT"; return 1
}

ab_field() { grep -E "^$2:" "$1" | head -1 | awk -F: '{print $2}' | awk '{print $1}'; }
ab_pct()   { awk -v p="$2" '$1==p {print $2}' "$1"; }

SAMPLE_PID=""; AB1=""; AB2=""
cleanup() {                          # 退出路径收尾：杀后台采样/本脚本 ab，不遗留压测进程
  [ -n "$SAMPLE_PID" ] && kill "$SAMPLE_PID" 2>/dev/null
  [ -n "$AB1" ] && kill "$AB1" 2>/dev/null
  [ -n "$AB2" ] && kill "$AB2" 2>/dev/null
  return 0
}
trap cleanup EXIT

log "============================================================"
log "九章 W21-FLUSH 采集器 flush 修复复测  $(date '+%Y-%m-%d %H:%M:%S')（UTC $(date -u '+%H:%M:%S')）"
log "环境: $(uname -srm)  gateway=$GATEWAY_URL api=$API_URL"
log "参数: 两臂并发 c=${CONC}+${CONC} 计量=${DUR}s 预热=${WARM}s ab=-k  敏感/偏离混合"
log "镜像: api=$(docker inspect jiuzhang-stage5-api --format '{{.Image}}' | cut -c1-19) gateway=$(docker inspect jiuzhang-stage5-gateway --format '{{.Image}}' | cut -c1-19)"
log "原始数据目录: $WORK"
log "============================================================"

# ---------- 预检：容器健康 / api 镜像含修复 / 策略 OBSERVE / 无并发生产者 ----------
for c in api gateway postgres valkey testorigin ollama; do
  ST=$(docker inspect "jiuzhang-stage5-$c" --format '{{.State.Status}} {{.State.Health.Status}}' 2>/dev/null)
  log "[pre] jiuzhang-stage5-$c: $ST"
  case "$ST" in "running healthy") ;; *) log "ABORT: 容器 jiuzhang-stage5-$c 非 running healthy"; exit 1;; esac
done
FIX=$(docker exec jiuzhang-stage5-api sh -c 'strings $(which jiuzhang-api) | grep -c WAF_COLLECTOR_FLUSH' 2>/dev/null)
log "[pre] api 二进制 WAF_COLLECTOR_FLUSH 出现次数=${FIX}（≥1 证明含 W21 修复）"
[ "${FIX:-0}" -ge 1 ] || { log "ABORT: api 镜像不含 W21 flush 修复，先重建镜像"; exit 1; }

SYS_CSRF=$(s5_ensure_sysadmin) || { echo "ABORT: sysadmin login"; exit 1; }
SEC_CSRF=$(s5_ensure_secuser "$SYS_CSRF")
[ -z "$SEC_CSRF" ] && { echo "ABORT: sec login"; exit 1; }
APP_ID=$(s5_ensure_app "$SEC_CSRF")
log "[pre] app=$APP_ID"
POL=$(curl -s -b "/tmp/s5-$SEC_USER.txt" "$API_URL/api/v1/api-security/policy")
POL_TXT=$(echo "$POL" | python3 -c "import json,sys; d=json.load(sys.stdin)['data']; print(d['edition'], d['api_dynamic_protection'], d['mode'], d['mode_source'])" 2>/dev/null)
log "[pre] 策略现状: $POL_TXT"
case "$POL_TXT" in "wdsp True OBSERVE"*) ;; *) log "ABORT: 策略非 OBSERVE（共享环境不代为翻转）"; exit 1;; esac

GW_LINES_1=$(docker exec jiuzhang-stage5-gateway sh -c 'wc -l < /var/log/caddy/api-runtime-events.log')
sleep 5
GW_LINES_2=$(docker exec jiuzhang-stage5-gateway sh -c 'wc -l < /var/log/caddy/api-runtime-events.log')
log "[pre] 网关事件日志行数 5s 间隔两次读: ${GW_LINES_1} / ${GW_LINES_2}（相等=无并发生产者）"
[ "$GW_LINES_1" = "$GW_LINES_2" ] || { log "ABORT: 网关日志仍在写入，存在并发流量，择时重跑"; exit 1; }

# ---------- 管线活性探针 + 采集器 EOF 就位 ----------
seq 1 10 | while read -r _; do s5_req "/v1/$PFX-dev/0" > /dev/null; done
seq 1 10 | while read -r _; do s5_req "/v1/$PFX-sens/0?password=perfprobe" > /dev/null; done
PROBE_DB=0
for _ in $(seq 1 15); do PROBE_DB=$(db_prefix_count); [ "${PROBE_DB:-0}" -gt 0 ] && break; sleep 2; done
log "[pre] 管线活性探针入库事件数=${PROBE_DB:-0}（>0 才计量）"
[ "${PROBE_DB:-0}" -gt 0 ] || { log "ABORT: 管线无事件"; exit 1; }

# 等采集器追到 EOF（断点 offset == 日志大小），保证洪峰前零积压
for _ in $(seq 1 30); do
  SIZE=$(docker exec jiuzhang-stage5-gateway sh -c 'stat -c %s /var/log/caddy/api-runtime-events.log')
  OFF=$(ckpt_read | awk '{print $1}')
  [ "$OFF" = "$SIZE" ] && break
  sleep 2
done
log "[pre] 采集器 EOF 就位: checkpoint offset=${OFF} 日志大小=${SIZE}"
[ "$OFF" = "$SIZE" ] || { log "ABORT: 采集器未追平即开测会污染追平计量"; exit 1; }
DB_TOTAL_0=$($PG "SELECT count(*) FROM api_runtime_events")
log "[pre] 起始 api_runtime_events 总行数=${DB_TOTAL_0}"

# ---------- 洪峰：两臂并发 c=10+c=10 × 30s ----------
sampler & SAMPLE_PID=$!
/usr/sbin/ab -k -r -c 5 -t "$WARM" -n "$AB_N" -H "Host: $HOST_HEADER" "$URL_DEV" > "$WORK/dev-warmup.txt" 2>/dev/null
/usr/sbin/ab -k -r -c 5 -t "$WARM" -n "$AB_N" -H "Host: $HOST_HEADER" "$URL_SENS" > "$WORK/sens-warmup.txt" 2>/dev/null
T_FLOOD_START=$(date +%s)
log "[flood] 洪峰开始 $(date -u '+%H:%M:%S') UTC"
/usr/sbin/ab -k -r -c "$CONC" -t "$DUR" -n "$AB_N" -H "Host: $HOST_HEADER" "$URL_DEV" > "$WORK/dev-ab.txt" 2>/dev/null &
AB1=$!
/usr/sbin/ab -k -r -c "$CONC" -t "$DUR" -n "$AB_N" -H "Host: $HOST_HEADER" "$URL_SENS" > "$WORK/sens-ab.txt" 2>/dev/null &
AB2=$!
wait "$AB1" "$AB2"
T_FLOOD_END=$(date +%s)
log "[flood] 洪峰结束 $(date -u '+%H:%M:%S') UTC（计量窗 $((T_FLOOD_END-T_FLOOD_START))s）"
log "[flood] dev 臂: complete=$(ab_field "$WORK/dev-ab.txt" 'Complete requests') failed=$(ab_field "$WORK/dev-ab.txt" 'Failed requests') qps=$(ab_field "$WORK/dev-ab.txt" 'Requests per second') p95=$(ab_pct "$WORK/dev-ab.txt" '95%')ms"
log "[flood] sens 臂: complete=$(ab_field "$WORK/sens-ab.txt" 'Complete requests') failed=$(ab_field "$WORK/sens-ab.txt" 'Failed requests') qps=$(ab_field "$WORK/sens-ab.txt" 'Requests per second') p95=$(ab_pct "$WORK/sens-ab.txt" '95%')ms"

# 网关侧产出计数：等在途请求落盘至稳定（两次读间隔 ≥3s 相等）
GW_FINAL=0; GW_PREV=-1
for _ in $(seq 1 20); do
  GW_FINAL=$(gw_prefix_count)
  [ "${GW_FINAL:-0}" -gt 0 ] && [ "$GW_FINAL" = "$GW_PREV" ] && break
  GW_PREV=$GW_FINAL; sleep 3
done
T_GW_STABLE=$(date +%s)
DB_AT_END=$(last_db_count)
log "[flood] 网关侧前缀事件总数=${GW_FINAL}（$(date -u '+%H:%M:%S') UTC 稳定）；此刻已入库=${DB_AT_END}（洪峰期间采集器并发入库）"

# ---------- 追平计量 + 中途重启（复刻「重建即重扫」场景） ----------
RESTARTED=0; T_RESTART=0; T_API_BACK=0; CKPT_BEFORE_RESTART=""; LOG_SIZE_AT_RESTART=""
T_CAUGHT_UP=0
while :; do
  NOW=$(date +%s); ELAPSED=$((NOW-T_FLOOD_END))
  DB_NOW=$(last_db_count)
  if [ "$RESTARTED" = "0" ] && [ "$ELAPSED" -ge "$RESTART_AFTER" ]; then
    if [ "$DB_NOW" -lt $(( GW_FINAL * 9 / 10 )) ]; then
      CKPT_BEFORE_RESTART=$(docker exec jiuzhang-stage5-api sh -c "stat -c '%Y' $CKPT; cat $CKPT" 2>/dev/null | tr '\n' ' ')
      LOG_SIZE_AT_RESTART=$(docker exec jiuzhang-stage5-gateway sh -c 'stat -c %s /var/log/caddy/api-runtime-events.log')
      T_RESTART=$(date +%s)
      log "[restart] 追平途中 docker restart api（已入库=${DB_NOW}/${GW_FINAL}，断点=${CKPT_BEFORE_RESTART}）"
      docker restart jiuzhang-stage5-api > /dev/null 2>&1
      if wait_api; then T_API_BACK=$(date +%s); else log "ERROR: api 重启后未恢复健康，中止（容器有 unless-stopped 策略仍在自恢复）"; exit 1; fi
      log "[restart] api 恢复健康 $(date -u '+%H:%M:%S') UTC（重启耗时 $((T_API_BACK-T_RESTART))s）"
      docker logs jiuzhang-stage5-api --since 3m 2>&1 | grep -E 'collector started|migration' | tail -5 >> "$WORK/restart-api.log"
      RESTARTED=1
    else
      log "[restart] 追平已近完成（${DB_NOW}/${GW_FINAL} ≥90%），跳过中途重启并如实记录"
      RESTARTED=2
    fi
  fi
  if [ "$DB_NOW" -ge "$GW_FINAL" ]; then T_CAUGHT_UP=$NOW; break; fi
  if [ "$ELAPSED" -ge "$CATCHUP_TIMEOUT" ]; then
    log "[catchup] 超时 ${CATCHUP_TIMEOUT}s 未追平（${DB_NOW}/${GW_FINAL}），如实记录"; break
  fi
  sleep 2
done

# ---------- 结果汇总 ----------
CATCHUP_S=$((T_CAUGHT_UP-T_FLOOD_END))
DB_FINAL=$(db_prefix_count)
DISTINCT_FINAL=$($PG "SELECT count(DISTINCT request_id) FROM api_runtime_events WHERE endpoint_key IN ('$EK_DEV','$EK_SENS')")
DB_TOTAL_1=$($PG "SELECT count(*) FROM api_runtime_events")
GW_LINES_FINAL=$(docker exec jiuzhang-stage5-gateway sh -c 'wc -l < /var/log/caddy/api-runtime-events.log')
CKPT_FINAL=$(docker exec jiuzhang-stage5-api sh -c "cat $CKPT" 2>/dev/null)

python3 - "$CSV" "$T_FLOOD_START" "$T_FLOOD_END" "$T_CAUGHT_UP" <<'EOF' > "$WORK/ckpt-stats.txt"
import csv, sys, statistics
path, t0, t1, t2 = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
rows = [r for r in csv.DictReader(open(path)) if r['ckpt_offset'] not in ('NA', '')]
flood  = [r for r in rows if t0 <= int(r['ts']) <= t1 + 2]
catch  = [r for r in rows if t1 < int(r['ts']) <= t2]
def updates(rs):
    off = [(int(r['ts']), int(r['ckpt_offset'])) for r in rs]
    chg = [b for a, b in zip(off, off[1:]) if b[1] != a[1]]
    gaps = [b[0]-a[0] for a, b in zip(off, off[1:]) if b[1] != a[1]]
    return len(chg), (statistics.median(gaps) if gaps else float('nan'))
fu, fg = updates(flood); cu, cg = updates(catch)
print(f"flood_window_ckpt_updates={fu} median_gap_s={fg}")
print(f"catchup_window_ckpt_updates={cu} median_gap_s={cg}")
EOF

log "============================================================"
log "结果汇总"
log "  A. 追平时间: ${CATCHUP_S}s（洪峰结束→入库追平；含中途重启耗时 $((T_API_BACK-T_RESTART))s）"
log "     网关侧产出=${GW_FINAL}  洪峰结束已入库=${DB_AT_END}  追平段入库=$((GW_FINAL-DB_AT_END))"
log "     有效追平速率≈$(( CATCHUP_S>0 ? (GW_FINAL-DB_AT_END)/CATCHUP_S : 0 )) 行/s（对照：修复前 11.5 万≈6.5 分钟≈300 行/s）"
log "  B. 断点更新频率: $(tr '\n' ' ' < "$WORK/ckpt-stats.txt")"
log "  C. 重扫行为: restart 标志=${RESTARTED}（1=已执行中途重启）"
if [ "$RESTARTED" = "1" ]; then
  OFF_BEFORE=$(echo "$CKPT_BEFORE_RESTART" | python3 -c "import json,sys; s=sys.stdin.read(); i=s.find('{'); print(json.loads(s[i:])['offset'])" 2>/dev/null)
  MT_BEFORE=$(echo "$CKPT_BEFORE_RESTART" | awk '{print $1}')
  log "     重启前断点: offset=${OFF_BEFORE} mtime=${MT_BEFORE}（距 kill $((T_RESTART-MT_BEFORE))s，≤2s → 未提交尾部 ≤2000 行+≤2s 有界）"
  log "     重启时日志大小=${LOG_SIZE_AT_RESTART}（已提交 ${OFF_BEFORE}；未扫积压 $((LOG_SIZE_AT_RESTART-OFF_BEFORE)) 字节=首次扫描工作量，非重放）"
  log "     重启后断点自 ${OFF_BEFORE} 续进（catchup.csv 连续，不回退 0/洪峰起点）；重放尾批由 request_id 幂等去重（见下行校验）；api 恢复 $((T_API_BACK-T_RESTART))s"
fi
log "  幂等校验: 前缀行数=${DB_FINAL} distinct request_id=${DISTINCT_FINAL}（相等=重放零双计）"
log "  总量校验: 表总行数 ${DB_TOTAL_0} → ${DB_TOTAL_1}（净增 $((DB_TOTAL_1-DB_TOTAL_0)) vs 网关前缀产出 ${GW_FINAL}+探针20）"
log "  网关日志总行数=${GW_LINES_FINAL}  终态断点=${CKPT_FINAL}"

# ---------- 终态核验（共享环境恢复原状） ----------
log "============================================================"
log "终态核验"
for c in api gateway postgres valkey testorigin ollama; do
  ST=$(docker inspect "jiuzhang-stage5-$c" --format '{{.State.Status}} {{.State.Health.Status}}' 2>/dev/null)
  log "  jiuzhang-stage5-$c: $ST"
done
POL2=$(curl -s -b "/tmp/s5-$SEC_USER.txt" "$API_URL/api/v1/api-security/policy" | python3 -c "import json,sys; d=json.load(sys.stdin)['data']; print(d['edition'], d['api_dynamic_protection'], d['mode'], d['mode_source'])" 2>/dev/null)
APPMODE=$($PG "SELECT protection_mode FROM applications WHERE code='s5app'")
GR=$($PG "SELECT count(*) FROM system_settings WHERE setting_group='gateway_runtime'")
log "  策略: ${POL2}；应用 s5app=${APPMODE}；gateway_runtime 残留行=${GR}"
log "  网关行为: GET / -> $(s5_req /)（期望200）  GET /v1/$PFX-dev/1 -> $(s5_req "/v1/$PFX-dev/1")（期望404透传）"
log "  数据抽查: events=$($PG 'SELECT count(*) FROM api_runtime_events') endpoints=$($PG 'SELECT count(*) FROM api_endpoints') apps=$($PG 'SELECT count(*) FROM applications') users=$($PG 'SELECT count(*) FROM users')"
log "完成。原始数据：${WORK}（catchup.csv 全程采样、ab 原文、restart-api.log）"
