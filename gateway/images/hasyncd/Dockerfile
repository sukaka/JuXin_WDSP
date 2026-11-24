# 九章 hasyncd 高可用节点协同代理交付镜像（HMAC + 防重放 + TLS，非 root 1000:1000）
# 构建（build context = gateway/ 根，compose build context 亦指向 gateway/）:
#   docker build -f gateway/images/hasyncd/Dockerfile -t jiuzhang-hasyncd:2.0.0 gateway/
# 多架构构建（linux/amd64 + linux/arm64）：
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     -f gateway/images/hasyncd/Dockerfile -t jiuzhang-hasyncd:2.0.0 gateway/
# 基础镜像锁定策略与 gateway/Dockerfile、gateway/images/netmgrd/Dockerfile 保持一致：
#   版本标签固定（golang:1.25-alpine、alpine:3.24），digest 通过 ARG 控制；
#   下方默认 digest 为 multi-arch index 摘要；置空则仅按版本标签解析。
#   查询：docker buildx imagetools inspect golang:1.25-alpine

# 基础镜像 digest（与 gateway/images/netmgrd/Dockerfile 头部同一默认值）；置空则仅按版本标签解析
ARG GOLANG_IMAGE_DIGEST=sha256:56961d79ea8129efddcc0b8643fd8a5416b4e6228cfd477e3fd61deb2672c587
ARG ALPINE_IMAGE_DIGEST=sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

# ---------- 构建阶段 ----------
# builder 固定使用构建机原生平台（$BUILDPLATFORM）：Go 交叉编译零成本
FROM --platform=$BUILDPLATFORM golang:1.25-alpine${GOLANG_IMAGE_DIGEST:+@$GOLANG_IMAGE_DIGEST} AS builder

# buildx 自动注入的目标平台参数（单架构 docker build 时默认为构建机平台）
ARG TARGETOS
ARG TARGETARCH

# Go 模块代理，默认使用 goproxy.cn 以保证国内可重复构建；可用 --build-arg 覆盖
ARG GOPROXY=https://goproxy.cn,direct
ENV GOPROXY=${GOPROXY}

WORKDIR /src

# 先拷贝 go.mod/go.sum 及本地 replace 模块的 go.mod（根 go.mod 经 replace 引用
# dynamic_security、pcapevidence 与 modules/jiuzhang_guard，加载模块图需要其 go.mod 存在；
# hasyncd 本身零第三方依赖，无需 go mod download 全量模块图）
COPY go.mod go.sum ./
COPY dynamic_security/go.mod dynamic_security/go.mod
COPY pcapevidence/go.mod pcapevidence/go.mod
COPY modules/jiuzhang_guard/go.mod modules/jiuzhang_guard/go.mod

# hasyncd 包自包含（仅标准库），cmd/hasyncd 仅依赖本包
COPY hasyncd ./hasyncd
COPY cmd/hasyncd ./cmd/hasyncd

# CGO_ENABLED=0 静态二进制；GOAMD64=v1 锁定 x86-64 v1 基线（信创 CPU 兼容，
# 与 gateway/Dockerfile、gateway/images/netmgrd/Dockerfile 同一约束）
RUN CGO_ENABLED=0 GOAMD64=v1 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -buildvcs=false -ldflags="-s -w" -o /hasyncd ./cmd/hasyncd

# ---------- 运行阶段 ----------
FROM alpine:3.24${ALPINE_IMAGE_DIGEST:+@$ALPINE_IMAGE_DIGEST}

# hasyncd 全程以非 root uid/gid 1000 (jiuzhang) 运行，零 Linux capability，不挂载 docker.sock
RUN addgroup -g 1000 -S jiuzhang \
    && adduser -u 1000 -S -G jiuzhang -H -h /var/lib/hasyncd jiuzhang \
    && mkdir -p /var/lib/hasyncd /var/run/caddy/sidecars /var/log/caddy /app/runtime/hostctl /app/runtime/upgrade-packages /app/runtime/upgrade-executor \
    && chown -R jiuzhang:jiuzhang /var/lib/hasyncd /var/run/caddy /var/log/caddy /app/runtime

COPY --from=builder /hasyncd /usr/local/bin/hasyncd

USER 1000:1000

HEALTHCHECK --interval=15s --timeout=5s --start-period=15s --retries=3 \
  CMD ["/usr/local/bin/hasyncd", "--healthcheck"]

ENTRYPOINT ["/usr/local/bin/hasyncd"]
