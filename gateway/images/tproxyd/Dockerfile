# 九章 tproxyd 透明串接前置牵引 sidecar 交付镜像
# 构建（build context = gateway/ 根，compose build context 亦指向 gateway/）:
#   docker build -f gateway/images/tproxyd/Dockerfile -t jiuzhang-tproxyd:2.0.0 gateway/
# 多架构构建（linux/amd64 + linux/arm64）：
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     -f gateway/images/tproxyd/Dockerfile -t jiuzhang-tproxyd:2.0.0 gateway/
# 基础镜像锁定策略与 gateway/Dockerfile、gateway/images/netmgrd/Dockerfile、gateway/images/mirrorcap/Dockerfile 保持一致：
#   版本标签固定（golang:1.25-alpine、alpine:3.24），digest 通过 ARG 控制。

ARG GOLANG_IMAGE_DIGEST=sha256:56961d79ea8129efddcc0b8643fd8a5416b4e6228cfd477e3fd61deb2672c587
ARG ALPINE_IMAGE_DIGEST=sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

# ---------- 构建阶段 ----------
# builder 固定使用构建机原生平台（$BUILDPLATFORM）：Go 交叉编译零成本
FROM --platform=$BUILDPLATFORM golang:1.25-alpine${GOLANG_IMAGE_DIGEST:+@$GOLANG_IMAGE_DIGEST} AS builder

ARG TARGETOS
ARG TARGETARCH
ARG GOPROXY=https://goproxy.cn,direct
ENV GOPROXY=${GOPROXY}

WORKDIR /src

# 先拷贝根模块清单及本地 replace 模块的 go.mod（保证模块图解析及缓存复用；
# tproxyd 仅使用标准库，无需下载第三方依赖）
COPY go.mod go.sum ./
COPY dynamic_security/go.mod ./dynamic_security/go.mod
COPY pcapevidence/go.mod ./pcapevidence/go.mod
COPY modules/jiuzhang_guard/go.mod ./modules/jiuzhang_guard/go.mod
COPY tproxyd/ ./tproxyd/
COPY cmd/tproxyd/ ./cmd/tproxyd/

# CGO_ENABLED=0 静态二进制；GOAMD64=v1 锁定 x86-64 v1 基线（信创 CPU 兼容）
RUN CGO_ENABLED=0 GOAMD64=v1 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/tproxyd ./cmd/tproxyd

# ---------- 运行阶段 ----------
FROM alpine:3.24${ALPINE_IMAGE_DIGEST:+@$ALPINE_IMAGE_DIGEST}

# tproxyd 仅使用 SO_ORIGINAL_DST（非特权端口 15000），全程以非 root 1000:1000 运行，零 Linux capability
RUN addgroup -g 1000 -S tproxyd \
    && adduser -u 1000 -S -G tproxyd -H -h /var/lib/tproxyd tproxyd \
    && mkdir -p /var/run/caddy/sidecars \
    && chown -R tproxyd:tproxyd /var/run/caddy

COPY --from=builder /out/tproxyd /usr/local/bin/tproxyd

USER 1000:1000

HEALTHCHECK --interval=15s --timeout=5s --start-period=15s --retries=3 \
  CMD ["/usr/local/bin/tproxyd", "--healthcheck"]

ENTRYPOINT ["/usr/local/bin/tproxyd"]
