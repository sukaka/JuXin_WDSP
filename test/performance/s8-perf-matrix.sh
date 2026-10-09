#!/usr/bin/env bash
# S8 批次 B 性能档位矩阵采样驱动（测试基建，非生产代码）。
# 方法冻结见 docs/nextgen/s8/S8-PERFORMANCE-REPORT.md §1：
#   - curl+xargs 固定并发开环突发（沿用 stage8-performance-tests.sh 口径），PAR=10；
#   - 每臂 N=300/轮（A2 写臂 N=200 且逐请求独立前缀规避写限速 60/min/端点）；
#   - 样本落 <outdir>/<tier>/<arm>.smp（每行 "time_total http_code"），统计由
#     s8-perf-stats.py 最近秩计算；429/5xx 计入分布不剔除，000 单独计数。
# 用法：bash test/performance/s8-perf-matrix.sh <outdir> <tier> [round]
#   tier 仅为标签（t0/t1/t2a/...），档位切换（发布/env）由调用方在轮次间完成。
set -u
OUT="$1"; TIER="$2"; ROUND="${3:-r1}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../waf/scripts/stage5-setup.sh"

PAR=10
N=300
N_WRITE=200
DIR="$OUT/$TIER"
mkdir -p "$DIR"
TS=$(date +%s)
PFX="pm${TIER}${ROUND}${TS}"

burst() { # <smp-out> <url-file>
  : > "$1"
  xargs -P"$PAR" -n1 sh -c \
    'curl -s -o /dev/null -w "%{time_total} %{http_code}\n" -H "Host: '"$ARM_HOST"'" '"$EXTRA"' "$0"' \
    >> "$1" < "$2"
}

mkurls() { # <count> <path-template-with-%d> <out>
  seq 1 "$1" | while read -r i; do printf '%s\n' "$(printf "$2" "$i")"; done > "$3"
}

echo "[matrix] tier=$TIER round=$ROUND out=$DIR ts=$TS"

# ---- W0 普通 Web GET / ----
ARM_HOST=waf-s5.local; EXTRA=""
mkurls "$N" "$GATEWAY_URL/" "$DIR/w0.urls"
burst "$DIR/w0-$ROUND.smp" "$DIR/w0.urls"
echo "[matrix] w0 done"

# ---- A1 API 读 GET /v1/<pfx>/<n>（同端点归一，走完整管线，无写限速）----
ARM_HOST=waf-s5.local; EXTRA=""
mkurls "$N" "$GATEWAY_URL/v1/$PFX-a1/1" "$DIR/a1.urls"
burst "$DIR/a1-$ROUND.smp" "$DIR/a1.urls"
echo "[matrix] a1 done"

# ---- A2 API JSON 写 POST ≤2KiB（逐请求独立前缀规避写限速）----
BODY2K=/tmp/s8pm-body2k.json
python3 -c "import json;print(json.dumps({'id':1,'name':'perf','pad':'x'*1900}))" > "$BODY2K"
ARM_HOST=waf-s5.local
EXTRA="-H Content-Type:application/json -X POST --data-binary @$BODY2K"
: > "$DIR/a2.urls"
seq 1 "$N_WRITE" | while read -r i; do echo "$GATEWAY_URL/v1/${PFX}-w$((i % 20))/1"; done > "$DIR/a2.urls"
burst "$DIR/a2-$ROUND.smp" "$DIR/a2.urls"
echo "[matrix] a2 done"

# ---- A3 API JSON 写 POST ≤16KiB（同规避；体量上限档）----
BODY16K=/tmp/s8pm-body16k.json
python3 -c "import json;print(json.dumps({'id':1,'name':'perf','pad':'x'*15800}))" > "$BODY16K"
ARM_HOST=waf-s5.local
EXTRA="-H Content-Type:application/json -X POST --data-binary @$BODY16K"
: > "$DIR/a3.urls"
seq 1 "$N_WRITE" | while read -r i; do echo "$GATEWAY_URL/v1/${PFX}-x$((i % 20))/1"; done > "$DIR/a3.urls"
burst "$DIR/a3-$ROUND.smp" "$DIR/a3.urls"
echo "[matrix] a3 done"

# ---- G1 GraphQL POST /graphql ≤2KiB ----
GBODY=/tmp/s8pm-gql.json
python3 -c "
import json
q = 'query P { ' + ' '.join('f%d: field(name:\"n%d\") { id name }' % (i,i) for i in range(12)) + ' }'
open('$GBODY','w').write(json.dumps({'query': q, 'operationName': 'P'}))"
ARM_HOST=waf-s5.local
EXTRA="-H Content-Type:application/json -X POST --data-binary @$GBODY"
mkurls "$N" "$GATEWAY_URL/graphql" "$DIR/g1.urls"
burst "$DIR/g1-$ROUND.smp" "$DIR/g1.urls"
echo "[matrix] g1 done"

# ---- M1 MCP tools/call（mcp-observe.local OBSERVE 绑定；原始 JSON-RPC over HTTP）----
MBODY=/tmp/s8pm-mcp.json
python3 -c "import json;open('$MBODY','w').write(json.dumps({'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'echo','arguments':{'text':'perf-arm-m1'}}}))"
ARM_HOST=mcp-observe.local
EXTRA="-H Content-Type:application/json -H Accept:application/json,text/event-stream -X POST --data-binary @$MBODY"
mkurls "$N" "$GATEWAY_URL/mcp" "$DIR/m1.urls"
burst "$DIR/m1-$ROUND.smp" "$DIR/m1.urls"
echo "[matrix] m1 done"

echo "[matrix] tier=$TIER round=$ROUND curl arms done -> $DIR"
