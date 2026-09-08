#!/bin/sh
# Agent 宿主容器入口：起业务 HTTP 服务（business_server.py，8000 端口——Phase 3 起
# 替换原 python -m http.server，以提供 /api/login、/big、/upload、/gz 等验收端点，
# 首页仍返回 'wdsp-agent-e2e business ok' 保持既有断言），主进程保持存活。
# wdsp-agent 由 run.sh 通过 docker exec 按需 enroll/run，
# 以便验收脚本独立控制 agent 进程生命周期（kill -9 / 日志断言）。
set -e
mkdir -p /var/log
python3 /business_server.py >/var/log/business-http.log 2>&1 &
python3 /fake_kube_server.py >/var/log/fake-kube.log 2>&1 &
exec sleep infinity
