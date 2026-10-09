#!/usr/bin/env bash
# 兼容旧命令；所有补丁与功能升级均由同一构建器处理。
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
printf '%s\n' 'build-patch.sh 已合并至 build-upgrade-pack.sh，使用统一签名升级包格式。' >&2
exec bash "$SCRIPT_DIR/build-upgrade-pack.sh" "$@"
