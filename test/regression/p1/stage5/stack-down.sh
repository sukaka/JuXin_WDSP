#!/usr/bin/env bash
# P1-04 R2 回归栈清理：down -v 本编排 + 删除环境描述符与其 mktemp 工作目录。
# 只作用于 jiuzhang-stage5 编排（stack-up 启动前已校验无既有容器），
# 不做任何全局 prune；描述符含会话凭据，必须随栈一并销毁。
# 用法：bash test/regression/p1/stage5/stack-down.sh <descriptor-path>
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
cd "$REPO_ROOT"

DESC="${1:?用法: stack-down.sh <descriptor-path>}"
[ -f "$DESC" ] || { echo "ERROR: 描述符不存在: $DESC" >&2; exit 1; }

WORK_DIR="$(cat "$DESC.workdir" 2>/dev/null || true)"
if [ -n "$WORK_DIR" ] && [ -f "$WORK_DIR/p1reg-stack.env" ]; then
  docker compose --env-file "$WORK_DIR/p1reg-stack.env" \
    -f deployment/docker-compose.stage5.yml -f deployment/docker-compose.wdsp.yml \
    -f deployment/docker-compose.test-license.yml down -v --remove-orphans >/dev/null 2>&1 || true
else
  # 描述符 workdir 丢失的兜底：按编排文件默认清理（不依赖环境文件）
  docker compose \
    -f deployment/docker-compose.stage5.yml -f deployment/docker-compose.wdsp.yml \
    -f deployment/docker-compose.test-license.yml down -v --remove-orphans >/dev/null 2>&1 || true
fi

case "$WORK_DIR" in
  /tmp/*|/var/folders/*) [ -n "$WORK_DIR" ] && rm -rf "$WORK_DIR" ;;
esac
rm -f "$DESC" "$DESC.workdir"
echo "stack-down 完成（编排已 down -v，描述符与工作目录已销毁）"
