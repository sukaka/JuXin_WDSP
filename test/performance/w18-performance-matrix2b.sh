#!/usr/bin/env bash
# 九章 §202 性能追补矩阵 · multipart 补测分片（w18-performance-matrix2.sh 的修正重测）。
#   背景：首轮 multipart 臂打未知路径（/v1/<pfx>-mp*/1），testorigin 对未知路径立即 404
#   且不读请求体（deployment/stage1/testorigin/main.go:121-125）；Go net/http 仅在剩余未读
#   body ≤256KB（maxPostHandlerReadBytes）时 Drain 保连，1MiB 上传被源站早期响应截断，
#   ab 写方向 socket 错误提前退出（264 字节输出仅「Total of 61 requests completed」）。
#   修正：改打 /upload（buildEcho 会完整读取 ≤1MiB 请求体并返回 200 JSON 回显），源站消费
#   body，连接健康，两臂（512KiB 完整解析 vs 1MiB 超 1MiB 解析上限截断）同口径可测。
#
#   口径与 matrix2 完全一致（c=20×30s + 5s 预热、ab -k、OBSERVE + 应用 OFF + 临时提写限速）。
#   事件校验改为时间窗计数：/upload 为固定路由（raw_path 无 run 唯一性），按 occurred_at ≥
#   臂起点过滤（共享环境当前无其他 /upload 流量，臂前以对照窗口验证）。
#
#   共享环境铁律同前：不动 api 容器（当前已是 wdsp 形态，本脚本不重建任何容器）、策略不动、
#   临时限速行插入/删除同一行精确可逆、EXIT trap 兜底恢复。
#
# 用法（仓库根目录）：bash test/performance/w18-performance-matrix2b.sh
# 结果写入 test/performance/w18-performance-matrix2b-result.txt；原始数据 /tmp/w18-matrix2b-<TS>/。
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../waf/scripts/stage5-setup.sh"

TS=$(date +%s)
PFX="w18y$TS"
URL_UP="$GATEWAY_URL/upload"
WORK="/tmp/w18-matrix2b-$TS"
mkdir -p "$WORK"

CONC=20; DUR=30; WARM=5; AB_N=5000000

REPORT="$SCRIPT_DIR/w18-performance-matrix2b-result.txt"
: > "$REPORT"
log() { echo "$@" | tee -a "$REPORT"; }

psql_s5() { docker exec jiuzhang-stage5-postgres psql -U jiuzhang -d jiuzhang_waf -At -c "$1"; }
RATE_KEY_WHERE="setting_group='gateway_runtime' AND setting_key='api_write_rate_per_minute'"
rate_setting_exists() { [ "$(psql_s5 "SELECT count(*) FROM system_settings WHERE $RATE_KEY_WHERE")" = "1" ]; }
rate_setting_insert() {
  psql_s5 "INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, description) \
VALUES ('gateway_runtime','api_write_rate_per_minute','\"$1\"'::jsonb,'string',\
'W18-PERF multipart 补测临时提升写限速（测完即删，勿手工保留）')" > /dev/null
}
rate_setting_delete() { psql_s5 "DELETE FROM system_settings WHERE $RATE_KEY_WHERE" > /dev/null; }

RESTORE_RATE=0
restore_env() {
  [ "$RESTORE_RATE" = "1" ] || return 0
  echo "[restore] 删除临时写限速设置行并重新发布…" | tee -a "$REPORT"
  rate_setting_delete
  local csrf
  csrf=$(s5_login "$SEC_USER" "$SEC_PWD")
  [ -n "$csrf" ] && s5_publish "$csrf" >> "$WORK/restore.log" 2>&1
  return 0
}
trap restore_env EXIT

api_env_flag() {
  docker inspect jiuzhang-stage5-api --format '{{range .Config.Env}}{{println .}}{{end}}' \
    | grep -q "^API_DYNAMIC_PROTECTION_ENABLED=$1$"
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

run_arm() {                         # $1=臂名 $2=输出前缀；剩余=额外 ab 参数
  local name="$1" out="$2"; shift 2
  /usr/sbin/ab -k -r -c 5 -t "$WARM" -n "$AB_N" -H "Host: $HOST_HEADER" "$@" "$URL_UP" \
      > "$out-warmup.txt" 2>/dev/null
  sample_stats "$out-stats.txt" "$DUR" &
  local sampler=$!
  /usr/sbin/ab -k -r -c "$CONC" -t "$DUR" -n "$AB_N" -H "Host: $HOST_HEADER" "$@" "$URL_UP" \
      > "$out-ab.txt" 2>/dev/null
  wait "$sampler"
  log "[$name] complete=$(ab_field "$out-ab.txt" 'Complete requests') failed=$(ab_field "$out-ab.txt" 'Failed requests') non2xx=$(ab_field "$out-ab.txt" 'Non-2xx responses') qps=$(ab_field "$out-ab.txt" 'Requests per second') mean_ms=$(ab_field "$out-ab.txt" 'Time per request') p50=$(ab_pct "$out-ab.txt" '50%') p95=$(ab_pct "$out-ab.txt" '95%') p99=$(ab_pct "$out-ab.txt" '99%') max=$(ab_pct "$out-ab.txt" '100%')"
}

# 网关事件日志时间窗计数：$1=臂起点 ISO 时间戳 $2=raw_path 子串
# （occurred_at 为 Go RFC3339Nano 变长小数，lexicographic 不可靠，用 python datetime 比较）
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

log "============================================================"
log "九章 §202 multipart 补测（/upload 源站消费 body 修正）  $(date '+%Y-%m-%d %H:%M:%S')（UTC $(date -u '+%H:%M:%S')）"
log "环境: $(uname -srm)  gateway=$GATEWAY_URL api=$API_URL"
log "参数: 并发=$CONC 计量=${DUR}s/臂 预热=${WARM}s ab=-k POST ${URL_UP}（testorigin /upload 读 ≤1MiB body 回 200）"
log "镜像: api=$(docker inspect jiuzhang-stage5-api --format '{{.Image}}' | cut -c1-19) gateway=$(docker inspect jiuzhang-stage5-gateway --format '{{.Image}}' | cut -c1-19)"
log "原始数据目录: $WORK"
log "============================================================"

# ---------- 前置：形态校验（本脚本不重建任何容器，形态不符即中止） + 登录 + 压测体 ----------
api_env_flag "true" || { log "ABORT: api 容器非 wdsp 形态（本脚本不执行重建）"; exit 1; }
SYS_CSRF=$(s5_ensure_sysadmin) || { echo "ABORT: sysadmin login"; exit 1; }
SEC_CSRF=$(s5_ensure_secuser "$SYS_CSRF")
[ -z "$SEC_CSRF" ] && { echo "ABORT: sec login"; exit 1; }
APP_ID=$(s5_ensure_app "$SEC_CSRF")
POL=$(curl -s -b "/tmp/s5-$SEC_USER.txt" "$API_URL/api/v1/api-security/policy")
log "[setup] app=$APP_ID 策略: $(echo "$POL" | python3 -c "import json,sys; d=json.load(sys.stdin)['data']; print(d['edition'], d['api_dynamic_protection'], d['mode'], d['mode_source'])" 2>/dev/null)"
echo "$POL" | grep -q '"mode":"OBSERVE"' || { log "ABORT: 策略非 OBSERVE"; exit 1; }
APP_MODE=$(curl -s -b "/tmp/s5-$SEC_USER.txt" "$API_URL/api/v1/applications/$APP_ID" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['protection_mode'])" 2>/dev/null)
log "[setup] 应用 protection_mode=${APP_MODE}（期望 OFF）"
[ "$APP_MODE" = "OFF" ] || { log "ABORT: 应用 protection_mode 非 OFF"; exit 1; }
if rate_setting_exists; then
  log "ABORT: gateway_runtime/api_write_rate_per_minute 已存在（非本脚本所建则不覆盖）"
  exit 1
fi
BOUNDARY="W18MPBOUNDARY$TS"
python3 - "$WORK" "$BOUNDARY" "$TS" <<'EOF'
import sys
work, boundary, ts = sys.argv[1], sys.argv[2], sys.argv[3]
cell = bytes((i * 37 + 11) % 256 for i in range(4096))
def mp(path, payload_size, fname):
    head = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; "
            f"filename=\"{fname}\"\r\nContent-Type: application/octet-stream\r\n\r\n").encode()
    tail = f"\r\n--{boundary}--\r\n".encode()
    with open(path, "wb") as f:
        f.write(head + cell * (payload_size // 4096) + tail)
mp(f"{work}/mp-512k.bin", 524288, f"perf-{ts}-512k.bin")
mp(f"{work}/mp-1m.bin", 1048576, f"perf-{ts}-1m.bin")
EOF
log "[setup] multipart 压测体: $(wc -c < "$WORK/mp-512k.bin" | tr -d ' ')B（<1MiB 完整解析） / $(wc -c < "$WORK/mp-1m.bin" | tr -d ' ')B（>1MiB 截断）"
# 对照窗口：确认共享环境当前无其他 /upload 流量（窗口计数口径可信）
CTRL_SINCE=$(date -u -v-1M '+%Y-%m-%dT%H:%M:%S' 2>/dev/null || date -u -d '-1 min' '+%Y-%m-%dT%H:%M:%S')
CTRL_N=$(gw_ev_count_since "$CTRL_SINCE" "/upload")
log "[setup] 对照窗口(近1min) /upload 事件数=${CTRL_N:-0}（期望 0 或极小，否则窗口计数受干扰如实记录）"

sample_stats "$WORK/idle-stats.txt" 6
log "[idle] $(stats_summary "$WORK/idle-stats.txt" | tr '\n' ' | ')"

# ---------- 临时提写限速 + 发布 + 探针 ----------
rate_setting_insert 200000000
RESTORE_RATE=1
log "[setup] 临时写限速已注入（仅此一行）"
PUB=$(s5_publish "$SEC_CSRF"); [ "$PUB" = "PUBLISH_OK" ] || { log "ABORT: 发布 $PUB"; exit 1; }
RATE_PROBE=$(seq 1 100 | while read -r _; do curl -s -o /dev/null -w "%{http_code}\n" -H "Host: $HOST_HEADER" \
  -H 'Content-Type: application/json' -X POST --data '{"a":1}' "$URL_UP"; done | sort | uniq -c | tr '\n' ' ')
log "[setup] 100×POST /upload 探针响应分布: ${RATE_PROBE}（期望全 200，无 429）"
echo "$RATE_PROBE" | grep -q 429 && { log "ABORT: 提限速后仍现 429"; exit 1; }

# ---------- 臂1 mp-512k-up：512KiB 文件（完整解析） ----------
WIN512=$(date -u '+%Y-%m-%dT%H:%M:%S')
run_arm "mp-512k-up" "$WORK/mp512up" -p "$WORK/mp-512k.bin" -T "multipart/form-data; boundary=$BOUNDARY"

# ---------- 臂2 mp-1m-up：1MiB 文件（超 1MiB 解析上限，截断） ----------
WIN1M=$(date -u '+%Y-%m-%dT%H:%M:%S')
run_arm "mp-1m-up" "$WORK/mp1mup" -p "$WORK/mp-1m.bin" -T "multipart/form-data; boundary=$BOUNDARY"

# ---------- 收尾：删临时限速行 + 发布 ----------
rate_setting_delete
RESTORE_RATE=0
PUB=$(s5_publish "$SEC_CSRF"); [ "$PUB" = "PUBLISH_OK" ] || { log "ABORT: 删限速行后发布 $PUB"; exit 1; }
log "[restore] 临时限速行已删除并发布（终态：默认 60/min 写限速）"

# ---------- 事件计数校验（时间窗，含预热与探针） ----------
REQ_512=$(ab_field "$WORK/mp512up-ab.txt" 'Complete requests')
REQ_1M=$(ab_field "$WORK/mp1mup-ab.txt" 'Complete requests')
EV_512=$(gw_ev_count_since "$WIN512" "/upload")
EV_1M=$(gw_ev_count_since "$WIN1M" "/upload")
log "[verify-gw] /upload 时间窗事件计数: mp-512k-up=${EV_512:-0}/≥${REQ_512}（自 ${WIN512}） mp-1m-up=${EV_1M:-0}/≥${REQ_1M}（自 ${WIN1M}）"

# ---------- 汇总 ----------
log "============================================================"
log "资源消耗（压测窗口 docker stats 采样汇总）"
for a in idle mp512up mp1mup; do
  f="$WORK/$a-stats.txt"; [ -f "$f" ] || continue
  log "[$a] $(stats_summary "$f" | tr '\n' ';')"
done
python3 - "$WORK" <<'EOF' | tee -a "$REPORT"
import re, sys
work = sys.argv[1]
def qps(name):
    t = open(f"{work}/{name}-ab.txt").read()
    m = re.search(r"Requests per second:\s+([\d.]+)", t)
    return float(m.group(1)) if m else None
def pct(name, p):
    t = open(f"{work}/{name}-ab.txt").read()
    m = re.search(rf"^\s*{p}%\s+(\d+)", t, re.M)
    return int(m.group(1)) if m else None
m5, m1 = qps("mp512up"), qps("mp1mup")
if m5 and m1:
    print(f"[delta] mp-1m-up vs mp-512k-up: {m5:.2f} -> {m1:.2f} QPS  体长翻倍开销={(m5-m1)/m5*100:.1f}%  p95 {pct('mp512up',95)}ms -> {pct('mp1mup',95)}ms")
else:
    print("[delta] 缺臂数据，跳过（如实记录）")
EOF

# ---------- 终态核验 ----------
log "============================================================"
log "终态核验:"
log "  容器: $(docker ps --format '{{.Names}}={{.Status}}' | grep stage5 | tr '\n' ' ')"
api_env_flag "true" && log "  api 容器环境: API_DYNAMIC_PROTECTION_ENABLED=true ✓" || log "  api 容器环境: ✗✗✗ 非 true"
SEC_CSRF=$(s5_login "$SEC_USER" "$SEC_PWD")
POL_FINAL=$(curl -s -b "/tmp/s5-$SEC_USER.txt" "$API_URL/api/v1/api-security/policy")
log "  策略: $(echo "$POL_FINAL" | python3 -c "import json,sys; d=json.load(sys.stdin)['data']; print(d['edition'], d['api_dynamic_protection'], d['mode'], d['mode_source'])" 2>/dev/null)（期望 wdsp True OBSERVE db）"
APP_MODE=$(curl -s -b "/tmp/s5-$SEC_USER.txt" "$API_URL/api/v1/applications/$APP_ID" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['protection_mode'])" 2>/dev/null)
log "  应用 protection_mode=${APP_MODE}（期望 OFF）  临时限速行残留: $(psql_s5 "SELECT count(*) FROM system_settings WHERE $RATE_KEY_WHERE")（期望0）"
RATE_FINAL=$(seq 1 70 | while read -r _; do curl -s -o /dev/null -w "%{http_code}\n" -H "Host: $HOST_HEADER" \
  -H 'Content-Type: application/json' -X POST --data '{"a":1}' "$URL_UP"; done | sort | uniq -c | tr '\n' ' ')
log "  写限速复核: 70×POST /upload 分布 ${RATE_FINAL}（期望 60×200+10×429 = 默认 60/min）"
log "  数据抽查: applications=$(psql_s5 "SELECT count(*) FROM applications") api_endpoints=$(psql_s5 "SELECT count(*) FROM api_endpoints") api_runtime_events=$(psql_s5 "SELECT count(*) FROM api_runtime_events") users=$(psql_s5 "SELECT count(*) FROM users")"
log "============================================================"
log "完成。原始 ab 输出与 stats 采样保留于 $WORK"
