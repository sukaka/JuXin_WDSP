#!/bin/sh
# P1-03 G2 取证容器入口：origin（业务源站，loopback）+ adapter（mirrorsrc 接收器，
# 守护重启——适配器故障不影响业务的取证依赖其可被杀/自拉起）+ nginx（TLS 终止 + mirror）。
set -eu

EVIDENCE="${EVIDENCE_DIR:-/evidence}"
SOCK_DIR=/run/wdsp
mkdir -p "${SOCK_DIR}" "${EVIDENCE}"

# 业务源站（仅回环）
/usr/local/bin/mirrorharness origin -listen 127.0.0.1:18081 \
  -stats "${EVIDENCE}/origin-stats.json" >"${EVIDENCE}/origin.log" 2>&1 &

# 镜像接收器（守护循环：被杀后 3s 自拉起；unix socket 0660 属组 nginx——
# nginx worker 以 nginx 用户运行需写 socket）
(
  while true; do
    /usr/local/bin/mirrorharness adapter \
      -socket "${SOCK_DIR}/mirror.sock" \
      -instance "${MIRROR_INSTANCE:-nginx-e2e}" \
      -token "${MIRROR_TOKEN:?MIRROR_TOKEN 必填}" \
      -tls-terminated \
      -body -max-body 4096 \
      -mode 0660 -group nginx \
      -level L2 \
      -out "${EVIDENCE}/records.jsonl" \
      -stats "${EVIDENCE}/adapter-stats.json" >>"${EVIDENCE}/adapter.log" 2>&1
    echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') adapter exited, restarting in 3s" >>"${EVIDENCE}/adapter-restarts.log"
    sleep 3
  done
) &

# 等 socket 就绪（nginx 启动前必须存在，否则 mirror 子请求 502 噪声）
i=0
while [ ! -S "${SOCK_DIR}/mirror.sock" ]; do
  i=$((i+1)); [ "${i}" -gt 50 ] && { echo "adapter socket 未就绪" >&2; exit 1; }
  sleep 0.2
done

exec nginx -g 'daemon off;'
