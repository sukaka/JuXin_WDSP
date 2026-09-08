# 九章防护网关自定义 Caddy 构建
# 构建: docker build -t jiuzhang-gateway:stage1 gateway/
# 所有组件版本在 docs/DEPENDENCIES.md 中锁定
#
# 多架构构建（linux/amd64 + linux/arm64；海光 C86、兆芯 KX/KH 为 x86-64 兼容，直接使用 amd64 产物）：
#   docker buildx build --platform linux/amd64,linux/arm64 -t jiuzhang-gateway:2.0.0 gateway/
# 基础镜像锁定策略（遵循项目“禁止 latest、依赖必须锁定版本”规则）：
#   - 版本标签固定（golang:1.25-alpine、alpine:3.24），digest 通过 ARG 控制；
#   - 下方默认 digest 为 multi-arch index 摘要（含 amd64+arm64），普通 docker build
#     与 buildx 多架构构建均可使用；Docker 按构建机/目标平台选层；
#   - 若 digests 被改成单架构子摘要，多架构构建需 --build-arg GOLANG_IMAGE_DIGEST=
#     --build-arg ALPINE_IMAGE_DIGEST=（按标签解析 manifest list）。
#   查询：docker buildx imagetools inspect golang:1.25-alpine

# 基础镜像 digest（见文件头说明）；置空则仅按版本标签解析
ARG GOLANG_IMAGE_DIGEST=sha256:56961d79ea8129efddcc0b8643fd8a5416b4e6228cfd477e3fd61deb2672c587
ARG ALPINE_IMAGE_DIGEST=sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

# ---------- 构建阶段 ----------
# builder 固定使用构建机原生平台（$BUILDPLATFORM）：Go 交叉编译零成本，
# 避免多架构构建时在 QEMU 模拟下运行 Go 工具链；产物经 GOOS/GOARCH 指向目标平台
FROM --platform=$BUILDPLATFORM golang:1.25-alpine${GOLANG_IMAGE_DIGEST:+@$GOLANG_IMAGE_DIGEST} AS builder

# buildx 自动注入的目标平台参数（单架构 docker build 时默认为构建机平台）
ARG TARGETOS
ARG TARGETARCH

ARG CADDY_VERSION=v2.11.4
ARG XCADDY_VERSION=v0.4.5
ARG CORAZA_CADDY_VERSION=v2.5.0
# Go 模块代理，默认使用 goproxy.cn 以保证国内可重复构建；可用 --build-arg 覆盖
ARG GOPROXY=https://goproxy.cn,direct
ENV GOPROXY=${GOPROXY}

# 安装 xcaddy（锁定版本）
RUN go install github.com/caddyserver/xcaddy/cmd/xcaddy@${XCADDY_VERSION}

# 复制自主 jiuzhang_guard 模块源码（本地路径替换，版本随仓库锁定）
COPY modules /src/modules
# 复制统一动态安全引擎（jiuzhang_guard 依赖；xcaddy 主模块需经 --with 注入本地替换）
COPY dynamic_security /src/dynamic_security

# 使用 xcaddy 构建包含 Coraza 模块与九章自主模块的自定义 Caddy
# CGO_ENABLED=0 生成静态二进制，运行阶段无需 libc
# GOOS/GOARCH 显式指向目标平台（Go 交叉编译，xcaddy 将环境透传给底层 go build）
# GOAMD64=v1 锁定 x86-64 v1 基线：兼容兆芯 KH-40000/KX-6000（无 AVX2）等信创 CPU，
# 防止未来工具链默认值上移或误加优化参数导致信创平台非法指令
RUN CGO_ENABLED=0 GOAMD64=v1 GOOS=$TARGETOS GOARCH=$TARGETARCH xcaddy build ${CADDY_VERSION} \
    --with github.com/corazawaf/coraza-caddy/v2@${CORAZA_CADDY_VERSION} \
    --with github.com/jiuzhang-waf/gateway/dynamic_security=/src/dynamic_security \
    --with github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard=/src/modules/jiuzhang_guard \
    --output /usr/bin/caddy

# ---------- 运行阶段 ----------
# 运行阶段不加 --platform：buildx 默认即为目标平台（须运行目标架构的 caddy 二进制）
FROM alpine:3.24${ALPINE_IMAGE_DIGEST:+@$ALPINE_IMAGE_DIGEST}

# 创建非 root 运行用户（固定 UID/GID 便于与配置控制器容器共享 Admin Socket 卷）
RUN addgroup -g 1000 -S caddy && adduser -u 1000 -S -G caddy -h /var/lib/caddy caddy \
    && mkdir -p /etc/caddy/certs /var/log/caddy /var/run/caddy /var/lib/caddy /srv/jiuzhang /tmp/coraza /config /data \
    && chown -R caddy:caddy /etc/caddy/certs /var/log/caddy /var/run/caddy /var/lib/caddy /srv/jiuzhang /tmp/coraza /config /data

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
