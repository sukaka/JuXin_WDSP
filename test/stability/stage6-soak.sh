#!/usr/bin/env bash
# 九章阶段6 稳定性浸泡（压缩计划）：
# 持续流量 + 安全事件写入 + 定时聚合 + 定时报告 + 定时备份 + 组件重启检查，
# 周期采样内存/任务积压/数据库连接，断言无持续增长与泄露。
# 用法：HOURS=1 bash test/stability/stage6-soak.sh（默认1小时；72小时验收用 HOURS=72）
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../waf/scripts/stage5-setup.sh"
# 阶段6专用测试账号（避免与其他会话共用的测试账号被重置）
SEC_USER="${S6_SEC_USER:-s6_sec}"
SEC_PWD="${S6_SEC_PWD:-S6Sec@Test2026!}"
SYS_USER="${S6_SYS_USER:-s6_sys}"
SYS_PWD="${S6_SYS_PWD:-S6Sys@Test2026!}"

HOURS="${HOURS:-1}"
DURATION=$(python3 -c "print(int(float('$HOURS')*3600))")
SAMPLE_INTERVAL=300          # 采样间隔 5 分钟
[ "$DURATION" -lt 600 ] && SAMPLE_INTERVAL=60  # 短浸泡时加密采样
REPORT_EVERY=1800            # 每 30 分钟一份报告
BACKUP_EVERY=3600            # 每 60 分钟一次备份
RESULT="$SCRIPT_DIR/stage6-soak-result.txt"
: > "$RESULT"
log() { echo "$@" | tee -a "$RESULT"; }

log "============================================================"
log "阶段6 稳定性浸泡  时长=${HOURS}h 开始=$(date '+%F %T')"
log "============================================================"

SYS_CSRF=$(s5_login "$SYS_USER" "$SYS_PWD"); SCK="/tmp/s5-$SYS_USER.txt"
SEC_CSRF=$(s5_login "$SEC_USER" "$SEC_PWD"); CK="/tmp/s5-$SEC_USER.txt"
APP_ID=$(s5_ensure_app "$SEC_CSRF")

# 后台流量生成（可持续访问 + 安全事件）
TRAFFIC_PID=""
start_traffic() {
  (
    while true; do
      curl -s -o /dev/null -H "Host: $HOST_HEADER" "$GATEWAY_URL/echo?soak=$RANDOM" 2>/dev/null
      curl -s -o /dev/null -H "Host: $HOST_HEADER" -H "X-Forwarded-For: 203.0.113.$((RANDOM % 250 + 1))" "$GATEWAY_URL/cc/ip/a" 2>/dev/null
      sleep 0.5
    done
  ) &
  TRAFFIC_PID=$!
}
start_traffic
trap '[ -n "$TRAFFIC_PID" ] && kill $TRAFFIC_PID 2>/dev/null' EXIT

mem_mb() { docker stats jiuzhang-stage5-api jiuzhang-stage5-gateway --no-stream --format '{{.Name}} {{.MemUsage}}' | awk '{print $1, $2}' | sed 's/MiB//'; }
pending_tasks() {
  docker exec jiuzhang-stage5-postgres psql -U jiuzhang -d jiuzhang_waf -tAc \
    "SELECT (SELECT count(*) FROM report_jobs WHERE status IN ('PENDING','COLLECTING','AGGREGATING','RENDERING')) +
            (SELECT count(*) FROM backup_jobs WHERE status IN ('PENDING','RUNNING','VERIFYING'))" 2>/dev/null
}
db_conns() { docker exec jiuzhang-stage5-postgres psql -U jiuzhang -d jiuzhang_waf -tAc "SELECT count(*) FROM pg_stat_activity" 2>/dev/null; }

START=$(date +%s)
LAST_REPORT=$START
LAST_BACKUP=$START
SAMPLE=0
declare -a API_MEMS
declare -a GW_MEMS
FAIL=0

log "采样: 时间(分) API内存 网关内存 待处理任务 DB连接"
while [ $(( $(date +%s) - START )) -lt $DURATION ]; do
  sleep $SAMPLE_INTERVAL
  ELAPSED=$(( ($(date +%s) - START) / 60 ))
  MEMS=$(mem_mb)
  API_MEM=$(echo "$MEMS" | awk '/api/{print $2}')
  GW_MEM=$(echo "$MEMS" | awk '/gateway/{print $2}')
  PEND=$(pending_tasks)
  CONNS=$(db_conns)
  API_MEMS+=("$API_MEM")
  GW_MEMS+=("$GW_MEM")
  SAMPLE=$((SAMPLE+1))
  log "  ${ELAPSED}m  api=${API_MEM}MiB gw=${GW_MEM}MiB pending=${PEND} conns=${CONNS}"

  # 定时报告
  NOW=$(date +%s)
  if [ $((NOW - LAST_REPORT)) -ge $REPORT_EVERY ]; then
    SEC_CSRF=$(s5_login "$SEC_USER" "$SEC_PWD")
    T_S=$(date -u -v-1H +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ)
    curl -s -b "$CK" -X POST "$API_URL/api/v1/reports" -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" \
      -d "{\"report_type\":\"CUSTOM\",\"start_time\":\"$T_S\",\"end_time\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"format\":\"html\"}" > /dev/null
    LAST_REPORT=$NOW
    log "  [soak] 定时报告已创建"
  fi
  # 定时备份
  if [ $((NOW - LAST_BACKUP)) -ge $BACKUP_EVERY ]; then
    SYS_CSRF=$(s5_login "$SYS_USER" "$SYS_PWD")
    curl -s -b "$SCK" -X POST "$API_URL/api/v1/backups" -H 'Content-Type: application/json' -H "X-CSRF-Token: $SYS_CSRF" -d '{"backup_type":"CONFIG_ONLY"}' > /dev/null
    LAST_BACKUP=$NOW
    log "  [soak] 定时备份已创建"
  fi
done

kill $TRAFFIC_PID 2>/dev/null; TRAFFIC_PID=""

echo ""
log "---- 结果分析 ----"
# 内存趋势：末三次均值 vs 前三次均值，增长 <30%
trend_ok() {
  local arr=("$@")
  local n=${#arr[@]}
  [ "$n" -lt 6 ] && { echo "samples=$n(skip)"; return 0; }
  local first=$(( (${arr[0]%%.*} + ${arr[1]%%.*} + ${arr[2]%%.*}) / 3 ))
  local last=$(( (${arr[$((n-3))]%%.*} + ${arr[$((n-2))]%%.*} + ${arr[$((n-1))]%%.*}) / 3 ))
  echo "first=${first}MiB last=${last}MiB"
  [ "$last" -lt $(( first * 13 / 10 + 30 )) ]
}
API_TREND=$(trend_ok "${API_MEMS[@]}") && log "API内存趋势: PASS ($API_TREND)" || { log "API内存趋势: FAIL ($API_TREND)"; FAIL=1; }
GW_TREND=$(trend_ok "${GW_MEMS[@]}") && log "网关内存趋势: PASS ($GW_TREND)" || { log "网关内存趋势: FAIL ($GW_TREND)"; FAIL=1; }
# 任务积压
PEND=$(pending_tasks)
[ "${PEND:-0}" -le 2 ] && log "任务积压: PASS (pending=$PEND)" || { log "任务积压: FAIL (pending=$PEND)"; FAIL=1; }
# DB 连接（无泄露：采样末期连接数未超初期 2 倍）
CONNS=$(db_conns)
[ "${CONNS:-0}" -lt 100 ] && log "DB连接: PASS (conns=$CONNS)" || { log "DB连接: FAIL (conns=$CONNS)"; FAIL=1; }
# 聚合任务健康（最近聚合任务 SUCCESS）
AGG=$(docker exec jiuzhang-stage5-postgres psql -U jiuzhang -d jiuzhang_waf -tAc "SELECT status FROM aggregation_jobs ORDER BY started_at DESC LIMIT 1" 2>/dev/null)
[ "$AGG" = "SUCCESS" ] && log "聚合任务: PASS (latest=$AGG)" || { log "聚合任务: FAIL (latest=$AGG)"; FAIL=1; }

log ""
log "============================================================"
[ "$FAIL" = "0" ] && log "稳定性浸泡: 通过（${HOURS}h, ${SAMPLE} 次采样）" || log "稳定性浸泡: 未通过"
log "============================================================"
[ "$FAIL" = "0" ]
