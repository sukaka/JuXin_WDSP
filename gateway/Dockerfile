# 九章防护网关自定义 Caddy 构建
# 构建: docker build -t jiuzhang-gateway:stage1 gateway/
# 所有组件版本在 docs/DEPENDENCIES.md 中锁定

# ---------- 构建阶段 ----------
FROM golang:1.25-alpine@sha256:56961d79ea8129efddcc0b8643fd8a5416b4e6228cfd477e3fd61deb2672c587 AS builder

ARG CADDY_VERSION=v2.11.4
ARG XCADDY_VERSION=v0.4.5
ARG CORAZA_CADDY_VERSION=v2.5.0
# Go 模块代理，默认使用 goproxy.cn 以保证国内可重复构建；可用 --build-arg 覆盖
ARG GOPROXY=https://goproxy.cn,direct
ENV GOPROXY=${GOPROXY}

# 安装 xcaddy（锁定版本）
RUN go install github.com/caddyserver/xcaddy/cmd/xcaddy@${XCADDY_VERSION}

# 使用 xcaddy 构建包含 Coraza 模块的自定义 Caddy
# CGO_ENABLED=0 生成静态二进制，运行阶段无需 libc
RUN CGO_ENABLED=0 xcaddy build ${CADDY_VERSION} \
    --with github.com/corazawaf/coraza-caddy/v2@${CORAZA_CADDY_VERSION} \
    --output /usr/bin/caddy

# ---------- 运行阶段 ----------
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

# 创建非 root 运行用户（固定 UID/GID 便于与配置控制器容器共享 Admin Socket 卷）
RUN addgroup -g 1000 -S caddy && adduser -u 1000 -S -G caddy -h /var/lib/caddy caddy \
    && mkdir -p /etc/caddy /var/log/caddy /var/run/caddy /var/lib/caddy /srv/jiuzhang /tmp/coraza \
    && chown -R caddy:caddy /var/log/caddy /var/run/caddy /var/lib/caddy /srv/jiuzhang /tmp/coraza

COPY --from=builder /usr/bin/caddy /usr/bin/caddy
COPY --chmod=0755 scripts/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# 默认以非 root 运行；POC 使用 8080 高端口，无需 NET_BIND_SERVICE
USER caddy

EXPOSE 8080

# 健康检查：校验当前配置可加载
HEALTHCHECK --interval=15s --timeout=5s --retries=3 \
    CMD ["/usr/bin/caddy", "validate", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
