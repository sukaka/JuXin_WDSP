# 九章管理前端镜像（阶段2）
# 多阶段：Node 构建静态产物 + Caddy 托管并反代 /api
# builder 固定使用构建机原生平台（$BUILDPLATFORM）：静态产物与架构无关，
# 避免多架构构建时在 QEMU 模拟下运行 Node 工具链（与 server/gateway Dockerfile 同一写法）
FROM --platform=$BUILDPLATFORM node:24-alpine@sha256:a0b9bf06e4e6193cf7a0f58816cc935ff8c2a908f81e6f1a95432d679c54fbfd AS builder

WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
# 构建后剥离静态 geo 目录：运行阶段由上下文单独前置拷贝，避免每次构建重写时间戳破坏跨版本层复用
RUN npm run build && rm -rf /build/dist/assets/geo

FROM caddy:2.11.4-alpine@sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648

# Web 只监听 8080/8443，移除基础镜像的文件能力，使 Caddy 能在 cap_drop: ALL 下启动。
RUN setcap -r /usr/bin/caddy

# 极少变动的大体积静态 GeoIP 数据与配置前置到独立层，供 Web 差量升级包（layer-delta）复用
COPY public/assets/geo /usr/share/caddy/assets/geo
COPY Caddyfile.docker /etc/caddy/Caddyfile
COPY Caddyfile.docker.http-only /etc/caddy/Caddyfile.http-only
COPY --chmod=0755 docker-entrypoint.web.sh /usr/local/bin/docker-entrypoint.web.sh
# 高频变动的前端 SPA 静态产物置顶层，差量升级仅需传输 ~1.5MB
COPY --from=builder /build/dist /usr/share/caddy

EXPOSE 8080 8443

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.web.sh"]
