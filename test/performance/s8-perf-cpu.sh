#!/usr/bin/env bash
# S8 批次 B CPU 采样辅助（测试基建）：后台对网关施加持续负载 22s，
# 同时 docker stats 每 2s 采网关容器 CPU%/MemUsage ×10，落 <out>.cpu。
# 用法：s8-perf-cpu.sh <out.cpu> <arm> [host] [n]
#   arm: a1|a2m|g1p|w0|mcp|grpc|grpc-nd|mid-sig|mid-uns|waf-ping
set -u
OUT="$1"; ARM="$2"; HOST="${3:-waf-s5.local}"; N="${4:-2000}"
source "$(dirname "${BASH_SOURCE[0]}")/../waf/scripts/stage5-setup.sh"

: > "$OUT"
( for i in $(seq 1 10); do
    docker stats --no-stream --format '{{.Name}} cpu={{.CPUPerc}} mem={{.MemUsage}}' jiuzhang-stage5-gateway >> "$OUT"
    sleep 2
  done ) &
STATPID=$!

case "$ARM" in
  grpc|grpc-nd)
    M=/echo.EchoService/Echo; [ "$ARM" = "grpc-nd" ] && M=/echo.OtherService/Ping
    AH=grpc2-s5.local; [ -n "${3:-}" ] && AH="$3"
    /tmp/grpcload -descriptor /tmp/echo.pb -authority "$AH" -method "$M" -n "$N" -warmup 20 -out /tmp/s8cpu-grpc.smp > /dev/null
    ;;
  mid-sig)
    /tmp/midload -host mid-observe.local -dir /tmp/mid-g1-keys -kid k-b -path /ping -n "$N" -warmup 20 -out /tmp/s8cpu-mid.smp > /dev/null
    ;;
  mid-uns)
    /tmp/midload -host mid-observe.local -unsigned -path /ping -n "$N" -warmup 20 -out /tmp/s8cpu-mid.smp > /dev/null
    ;;
  waf-ping)
    /tmp/midload -host sf-s5.local -unsigned -path /ping -n "$N" -warmup 20 -out /tmp/s8cpu-mid.smp > /dev/null
    ;;
  *)
    # curl 持续臂：22s 内循环突发
    case "$ARM" in
      a1)  URL="$GATEWAY_URL/v1/s8cpu-a1/1"; EXTRA="" ;;
      w0)  URL="$GATEWAY_URL/"; EXTRA="" ;;
      a2m) URL=""; EXTRA="-H Content-Type:application/json -X POST --data-binary @/tmp/s8pm-body2k.json" ;;
      g1p) URL="$GATEWAY_URL/graphql"; EXTRA="-H Content-Type:application/json -X POST --data-binary @/tmp/s8pm-gql.json" ;;
      mcp) URL="$GATEWAY_URL/mcp"; HOST=mcp-observe.local; EXTRA="-H Content-Type:application/json -H Accept:application/json,text/event-stream -X POST --data-binary @/tmp/s8pm-mcp.json" ;;
    esac
    END=$(( $(date +%s) + 22 ))
    if [ "$ARM" = "a2m" ]; then
      # 写限速规避：10 端点轮换（22s 内每端点远低于 60/min）
      seq 0 9 | while read -r i; do echo "$GATEWAY_URL/v1/s8t2a-w$i/1"; done > /tmp/s8cpu-a2m.urls
      while [ "$(date +%s)" -lt "$END" ]; do
        xargs -P10 -n1 sh -c \
          'curl -s -o /dev/null -H "Host: '"$HOST"'" '"$EXTRA"' "$0"' > /dev/null 2>&1 < /tmp/s8cpu-a2m.urls
      done
    else
      while [ "$(date +%s)" -lt "$END" ]; do
        seq 1 40 | xargs -P10 -n1 sh -c \
          'curl -s -o /dev/null -H "Host: '"$HOST"'" '"$EXTRA"' "$0"' > /dev/null 2>&1
      done
    fi
    ;;
esac
wait $STATPID
echo "[cpu] arm=$ARM host=$HOST -> $OUT"
