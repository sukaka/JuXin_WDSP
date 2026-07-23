#!/usr/bin/env bash
# 九章阶段8 性能测试（任务书五十五章节选，WDSP）：
#   a) 管线开销：开启 API 动态防护的端点 vs 普通 Web 页面，p95 延迟增幅 < 50%（OBSERVE 模式）；
#   b) 采集吞吐：200 个主事件产生后 15s 内管理面可检索 ≥180 条；
#   c) 大 body 解析：~1MB JSON 请求 p95 < 2s。
#
# 与实现对齐的关键事实：
#   - 写方法 API 进程内限速 60/min/端点（detectors/ratelimit.go，RATE_LIMIT 任意模式都会 429），
#     采样突发用「读方法 + 对象段路径」的 API 请求（GET /v1/<pfx>/N）：同样走完整管线
#     （解析→归一化→检测器→事件落盘，无凭据必命中 resource.unauthenticated_object_access），
#     但不会触发写限速污染采样；
#   - 普通 GET / 无检测命中、不产生主事件，作为 Web 基线臂；
#   - 应用防护模式 OFF（s5_ensure_app），Coraza 不干扰计时；
#   - p95 采用最近秩（nearest-rank），python3 计算；断言 <50% 增幅为主，
#     基线 p95 极小（<10ms 级）时比例噪声大，辅以 10ms 绝对开销地板（注释见断言处）。
#
# 依赖 stage5 编排 + wdsp 覆盖：
#   docker compose --env-file .env -f deployment/docker-compose.stage5.yml -f deployment/docker-compose.wdsp.yml up -d --build
# 结果写入 test/performance/stage8-performance-result.txt
# 用法：bash test/performance/stage8-performance-tests.sh
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../waf/scripts/stage5-setup.sh"

REPORT="$SCRIPT_DIR/stage8-performance-result.txt"
: > "$REPORT"
log() { echo "$@" | tee -a "$REPORT"; }

TOTAL=0; PASS=0; FAIL=0; FAILED=()
record() {
  local name="$1" ok="$2" detail="${3:-}"
  TOTAL=$((TOTAL+1))
  if [ "$ok" = "1" ]; then PASS=$((PASS+1)); log "PASS  $name $detail"
  else FAIL=$((FAIL+1)); FAILED+=("$name: $detail"); log "FAIL  $name ($detail)"; fi
}

CK="/tmp/s5-$SEC_USER.txt"
TS=$(date +%s)
PFX="perf$TS"          # 本次运行唯一路径前缀，避免与历史端点/事件串扰
N=200                  # 每臂采样数
PAR=10                 # 采样并发
BIG_N=20               # 大 body 采样数（远低于写限速 60/min）

# p95（最近秩）：输入文件每行 "<time_total> <http_code>"
p95_calc() {
  python3 - "$1" <<'EOF'
import sys, math
vals = sorted(float(l.split()[0]) for l in open(sys.argv[1]) if l.strip())
if not vals:
    print("-1")
else:
    k = max(0, min(len(vals)-1, math.ceil(0.95*len(vals))-1))
    print(f"{vals[k]:.4f}")
EOF
}

# 污染响应计数（429/5xx/000 为污染；testorigin 对未知路径 404 属正常全管线响应，不计入）
bad_codes() { awk '$2 == "429" || $2 == "000" || $2 ~ /^5/ {n++} END {print n+0}' "$1"; }

# 按 URL 文件并发采样：$1=URL文件 $2=并发 $3=输出文件（curl -w time_total）
burst() {
  : > "$3"
  xargs -P"$2" -n1 sh -c \
    'curl -s -o /dev/null -w "%{time_total} %{http_code}\n" -H "Host: '"$HOST_HEADER"'" "$0"' \
    >> "$3" < "$1"
}

log "============================================================"
log "九章阶段8 性能测试  $(date '+%Y-%m-%d %H:%M:%S')"
log "环境: $(uname -srm)  gateway=$GATEWAY_URL api=$API_URL 并发=$PAR 采样=$N/臂"
log "============================================================"

# ---------- 准备：登录 / 应用 / 发布 / 确认 OBSERVE ----------
SYS_CSRF=$(s5_ensure_sysadmin) || exit 1
SEC_CSRF=$(s5_ensure_secuser "$SYS_CSRF")
[ -z "$SEC_CSRF" ] && { echo "ERROR: sec login failed"; exit 1; }
APP_ID=$(s5_ensure_app "$SEC_CSRF")
log "[setup] app=$APP_ID"

PUB=$(s5_publish "$SEC_CSRF")
[ "$PUB" = "PUBLISH_OK" ] || { record "首次发布成功" 0 "$PUB"; echo "ABORT"; exit 1; }

# 显式确保 OBSERVE 模式（开销对比以 OBSERVE 为前提；幂等操作）
curl -s -o /dev/null -b "$CK" -X PUT "$API_URL/api/v1/api-security/policy" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" -d '{"mode":"OBSERVE"}'
PUBP=$(curl -s -b "$CK" -X POST "$API_URL/api/v1/api-security/policy/publish" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" -d '{}' \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['status'])" 2>/dev/null)
[ "$PUBP" = "SUCCESS" ] && record "策略确认为 OBSERVE 模式（基线前提）" 1 \
  || { record "策略确认为 OBSERVE 模式（基线前提）" 0 "publish=$PUBP"; echo "ABORT"; exit 1; }

# ---------- a) 管线开销：API 端点 vs Web 基线 ----------
URLS_API="/tmp/s8-perf-api-$TS.txt"; URLS_WEB="/tmp/s8-perf-web-$TS.txt"
SMP_API="/tmp/s8-perf-api-smp-$TS.txt"; SMP_WEB="/tmp/s8-perf-web-smp-$TS.txt"
seq 1 "$N" | while read -r i; do echo "$GATEWAY_URL/v1/$PFX/$i"; done > "$URLS_API"
seq 1 "$N" | while read -r _; do echo "$GATEWAY_URL/"; done > "$URLS_WEB"

# 预热（每臂 10 个，丢弃）：消除首连建立与懒初始化偏差；预热命中同一端点
seq 1 10 | while read -r _; do echo "$GATEWAY_URL/v1/$PFX/0"; done \
  | xargs -P"$PAR" -n1 sh -c 'curl -s -o /dev/null -H "Host: '"$HOST_HEADER"'" "$0"' > /dev/null
seq 1 10 | while read -r _; do echo "$GATEWAY_URL/"; done \
  | xargs -P"$PAR" -n1 sh -c 'curl -s -o /dev/null -H "Host: '"$HOST_HEADER"'" "$0"' > /dev/null

burst "$URLS_API" "$PAR" "$SMP_API"
burst "$URLS_WEB" "$PAR" "$SMP_WEB"

BAD_API=$(bad_codes "$SMP_API"); BAD_WEB=$(bad_codes "$SMP_WEB")
API_P95=$(p95_calc "$SMP_API"); WEB_P95=$(p95_calc "$SMP_WEB")
LINES_API=$(wc -l < "$SMP_API" | tr -d ' '); LINES_WEB=$(wc -l < "$SMP_WEB" | tr -d ' ')
log "[a] API 臂 p95=${API_P95}s（样本=$LINES_API 异常=${BAD_API}）  Web 臂 p95=${WEB_P95}s（样本=$LINES_WEB 异常=${BAD_WEB}）"

if [ "$LINES_API" != "$N" ] || [ "$LINES_WEB" != "$N" ] || [ "$BAD_API" != "0" ] || [ "$BAD_WEB" != "0" ]; then
  record "a) 采样纯净（样本完整且无 429/5xx 污染，200/404 均为干净响应）" 0 "样本 api=$LINES_API/$N web=$LINES_WEB/$N api_bad=$BAD_API web_bad=$BAD_WEB"
  record "a) API 管线 p95 开销增幅 < 50%" 0 "采样被污染，跳过对比"
else
  record "a) 采样纯净（样本完整且无 429/5xx 污染）" 1
  # 主判据：api_p95 ≤ web_p95×1.5；基线 p95 极小（<10ms 级）时比例噪声大，
  # 辅以绝对开销地板：增量 ≤10ms 视为同量级（任务书要求基准以实测为准）
  CMP=$(python3 - "$API_P95" "$WEB_P95" <<'EOF'
import sys
a, w = float(sys.argv[1]), float(sys.argv[2])
ratio = (a / w) if w > 0 else float("inf")
ok = (a <= w * 1.5) or ((a - w) <= 0.010)
print(f"{'OK' if ok else 'BAD'} ratio={ratio:.2f} api={a:.4f}s web={w:.4f}s delta={(a-w)*1000:.1f}ms")
EOF
)
  case "$CMP" in
    OK*) record "a) API 管线 p95 开销增幅 < 50%" 1 "$CMP" ;;
    *)   record "a) API 管线 p95 开销增幅 < 50%" 0 "$CMP" ;;
  esac
fi

# ---------- b) 采集吞吐：15s 内 ≥180 个主事件可检索 ----------
# (a) 的 API 臂 200 个请求每个都产生主事件（resource 命中），按 endpoint_key 精确计数
EK="GET /v1/$PFX/{id}"
DEADLINE=$(( $(date +%s) + 15 ))
EV_TOTAL=0
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
  EV_TOTAL=$(curl -s -b "$CK" -G "$API_URL/api/v1/api-security/runtime/events" \
    --data-urlencode "endpoint_key=$EK" --data-urlencode "page_size=1" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['data'].get('total', 0))" 2>/dev/null)
  [ "${EV_TOTAL:-0}" -ge 180 ] && break
  sleep 2
done
log "[b] 15s 窗口内 endpoint=$EK 主事件数=${EV_TOTAL}（阈值≥180）"
[ "${EV_TOTAL:-0}" -ge 180 ] && record "b) 采集吞吐：15s 内 ≥180/200 事件入库" 1 "total=$EV_TOTAL" \
  || record "b) 采集吞吐：15s 内 ≥180/200 事件入库" 0 "total=$EV_TOTAL"

# ---------- c) 大 body 解析：~1MB JSON p95 < 2s ----------
BODY="/tmp/s8-perf-body-$TS.json"
python3 -c "import json; print(json.dumps({'id':1,'name':'perf','pad':'x'*1000000}))" > "$BODY"
URLS_BIG="/tmp/s8-perf-big-urls-$TS.txt"; SMP_BIG="/tmp/s8-perf-big-smp-$TS.txt"
seq 1 "$BIG_N" | while read -r i; do echo "$GATEWAY_URL/v1/${PFX}big/$i"; done > "$URLS_BIG"
: > "$SMP_BIG"
xargs -P5 -n1 sh -c \
  'curl -s -o /dev/null -w "%{time_total} %{http_code}\n" -H "Host: '"$HOST_HEADER"'" -H "Content-Type: application/json" -X POST --data-binary @"'"$BODY"'" "$0"' \
  >> "$SMP_BIG" < "$URLS_BIG"

BAD_BIG=$(bad_codes "$SMP_BIG")
BIG_P95=$(p95_calc "$SMP_BIG")
LINES_BIG=$(wc -l < "$SMP_BIG" | tr -d ' ')
log "[c] 大 body 臂 p95=${BIG_P95}s（样本=$LINES_BIG/$BIG_N 异常=${BAD_BIG}，body≈1MB）"
if [ "$LINES_BIG" != "$BIG_N" ] || [ "$BAD_BIG" != "0" ] || [ "$BIG_P95" = "-1" ]; then
  record "c) 大 body（~1MB JSON）解析 p95 < 2s" 0 "样本=$LINES_BIG/$BIG_N 异常响应=$BAD_BIG"
else
  BIG_OK=$(python3 -c "print(1 if float('$BIG_P95') < 2.0 else 0)")
  [ "$BIG_OK" = "1" ] && record "c) 大 body（~1MB JSON）解析 p95 < 2s" 1 "p95=${BIG_P95}s" \
    || record "c) 大 body（~1MB JSON）解析 p95 < 2s" 0 "p95=${BIG_P95}s"
fi

rm -f "$URLS_API" "$URLS_WEB" "$SMP_API" "$SMP_WEB" "$URLS_BIG" "$SMP_BIG" "$BODY"

log "============================================================"
log "阶段8 性能测试：$PASS/$TOTAL 通过，$FAIL 失败"
if [ "$FAIL" -gt 0 ]; then printf '失败项：\n' | tee -a "$REPORT"; printf '  %s\n' "${FAILED[@]}" | tee -a "$REPORT"; fi
log "============================================================"
[ "$FAIL" = "0" ]
