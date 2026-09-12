#!/usr/bin/env bash
# P1-03 G3 取证容器入口：Envoy（守护重启）+ 业务源站 + tap 适配器（守护重启）。
#
# 单管理流约束（v1.35.3 实测：Admin 同时只允许一条已挂接 tap 流）：
# tap 断言经 /run/wdsp/tap-flags 注入；run.sh 分相位切换（相位 A：h2+TLS 断言；
# 相位 B：h1 明文断言），切换 = 换 envoy.yaml + 改 flags + 重启两者（守护拉起）。
set -u

log() { printf '[entrypoint] %s\n' "$*"; }

mkdir -p /run/wdsp
[ -f /run/wdsp/tap-flags ] || echo "-observed 2 -tls-terminated" > /run/wdsp/tap-flags

# Envoy 守护（进程重启后 tap 配置失效，适配器重连重新提交）
(
  while true; do
    envoy -c /etc/envoy/envoy.yaml --log-level warning
    log "envoy 退出（$?），3s 后重启"
    sleep 3
  done
) &

# 业务源站
/usr/local/bin/tace2e webserver -listen 127.0.0.1:18090 &
/usr/local/bin/tace2e grpcserver -listen 127.0.0.1:18091 &
/usr/local/bin/tace2e wsserver -listen 127.0.0.1:18092 &

# tap 适配器守护（被杀后业务不受影响，守护拉起恢复采集）
(
  while true; do
    FLAGS="$(cat /run/wdsp/tap-flags 2>/dev/null || echo '-observed UNKNOWN')"
    # shellcheck disable=SC2086
    /usr/local/bin/tapharness adapter \
      -admin 127.0.0.1:9901 \
      -instance "${TAP_INSTANCE:-envoy-e2e}" \
      -config-id wdsp_tap \
      ${FLAGS} \
      ${TAP_BODY:+-body -level L2} \
      -out /evidence/records.jsonl \
      -stats /evidence/adapter-stats.json
    log "tapharness 退出（$?），3s 后重启"
    sleep 3
  done
) &

log "全部组件已拉起"
wait
