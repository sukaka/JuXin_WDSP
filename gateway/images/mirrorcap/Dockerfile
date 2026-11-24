# 九章 mirrorcap 镜像旁路采集与站点资产发现 sidecar 交付镜像
# 构建（build context = gateway/ 根，compose build context 亦指向 gateway/）:
#   docker build -f gateway/images/mirrorcap/Dockerfile -t jiuzhang-mirrorcap:2.0.0 gateway/
# 多架构构建（linux/amd64 + linux/arm64）：
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     -f gateway/images/mirrorcap/Dockerfile -t jiuzhang-mirrorcap:2.0.0 gateway/
# 基础镜像锁定策略与 gateway/Dockerfile、gateway/images/netmgrd/Dockerfile 保持一致：
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

# 先拷贝模块清单与本地 replace 依赖，保证模块图解析及缓存复用
COPY go.mod go.sum ./
COPY dynamic_security/ ./dynamic_security/
COPY pcapevidence/go.mod pcapevidence/go.sum ./pcapevidence/
COPY modules/jiuzhang_guard/go.mod modules/jiuzhang_guard/go.sum ./modules/jiuzhang_guard/
COPY modules/jiuzhang_guard/apievents/ ./modules/jiuzhang_guard/apievents/
COPY modules/jiuzhang_guard/netif/ ./modules/jiuzhang_guard/netif/
COPY mirrorcap/ ./mirrorcap/
COPY cmd/mirrorcap/ ./cmd/mirrorcap/

RUN go mod download

# CGO_ENABLED=0 静态二进制；GOAMD64=v1 锁定 x86-64 v1 基线（信创 CPU 兼容）
RUN CGO_ENABLED=0 GOAMD64=v1 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/mirrorcap ./cmd/mirrorcap

# ---------- 运行阶段 ----------
FROM alpine:3.24${ALPINE_IMAGE_DIGEST:+@$ALPINE_IMAGE_DIGEST}

# ethtool：供 netif 采集器探测物理网卡介质（FIBER/COPPER）与链路速率
RUN apk add --no-cache ethtool \
    && addgroup -g 1000 -S mirrorcap \
    && adduser -u 1000 -S -G mirrorcap -H -h /var/lib/mirrorcap mirrorcap \
    && mkdir -p /var/log/caddy /var/run/caddy/sidecars /tmp/coraza \
    && chown -R mirrorcap:mirrorcap /var/log/caddy /var/run/caddy /tmp/coraza

COPY --from=builder /out/mirrorcap /usr/local/bin/mirrorcap

# 启动时经 MIRROR_DROP_PRIVS=1 由 root 立即降权为 1000:1000 并仅保留 ambient CAP_NET_RAW/CAP_NET_ADMIN
ENV MIRROR_DROP_PRIVS=1
USER 0:0

HEALTHCHECK --interval=15s --timeout=5s --start-period=15s --retries=3 \
  CMD ["/usr/local/bin/mirrorcap", "--healthcheck"]

ENTRYPOINT ["/usr/local/bin/mirrorcap"]
