#!/bin/sh
# 九章管理前端容器入口：按控制台 HTTPS 证书是否存在选择 Caddy 配置。
# 证书由宿主机安装期 ops/install/console-cert.sh 生成（自签、100 年有效期），
# 只读挂载到 /etc/caddy/console-certs/；缺失时退化为仅 HTTP（既有部署不重建
# 证书时行为与旧版一致），HTTPS 入口不监听。
set -e

CERT_DIR=/etc/caddy/console-certs
CONFIG=/etc/caddy/Caddyfile
if [ ! -s "$CERT_DIR/console.crt" ] || [ ! -s "$CERT_DIR/console.key" ]; then
	echo "[jiuzhang-web] 控制台 HTTPS 证书缺失（$CERT_DIR/console.crt / console.key），本次以仅 HTTP 模式启动" >&2
	echo "[jiuzhang-web] 启用 HTTPS：在部署目录执行 bash ops/install/console-cert.sh，然后 docker compose up -d web" >&2
	CONFIG=/etc/caddy/Caddyfile.http-only
fi

exec caddy run --config "$CONFIG" --adapter caddyfile
