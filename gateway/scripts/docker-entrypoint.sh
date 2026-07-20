#!/bin/sh
# 九章防护网关容器入口
# umask 077：确保 Caddy 创建的 admin.sock 等文件权限为 0700，
# 仅网关运行用户可访问 Admin API。
set -e
umask 077
exec /usr/bin/caddy "$@"
