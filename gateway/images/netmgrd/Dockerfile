# 九章 netmgrd 网络执行组件交付镜像（网桥/路由落地 + DNS/NTP 落地 + 网络诊断）
# 构建（build context = gateway/ 根，compose build context 亦指向 gateway/）:
#   docker build -f gateway/images/netmgrd/Dockerfile -t jiuzhang-netmgrd:2.0.0 gateway/
# 多架构构建（linux/amd64 + linux/arm64）：
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     -f gateway/images/netmgrd/Dockerfile -t jiuzhang-netmgrd:2.0.0 gateway/
# 基础镜像锁定策略与 gateway/Dockerfile 保持一致：
#   版本标签固定（golang:1.25-alpine、alpine:3.24），digest 通过 ARG 控制；
#   下方默认 digest 为 multi-arch index 摘要；置空则仅按版本标签解析。
#   查询：docker buildx imagetools inspect golang:1.25-alpine

# 基础镜像 digest（与 gateway/Dockerfile 头部同一默认值）；置空则仅按版本标签解析
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
# dynamic_security 与 modules/jiuzhang_guard，加载模块图需要其 go.mod 存在；
# netmgrd 本身零第三方依赖，无需 go mod download 全量模块图）
COPY go.mod go.sum ./
COPY dynamic_security/go.mod dynamic_security/go.mod
COPY modules/jiuzhang_guard/go.mod modules/jiuzhang_guard/go.mod

# netmgrd 包自包含（仅标准库），cmd/netmgrd 仅依赖本包
COPY netmgrd ./netmgrd
COPY cmd/netmgrd ./cmd/netmgrd

# CGO_ENABLED=0 静态二进制；GOAMD64=v1 锁定 x86-64 v1 基线（信创 CPU 兼容，
# 与 gateway/Dockerfile 同一约束）
RUN CGO_ENABLED=0 GOAMD64=v1 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /netmgrd ./cmd/netmgrd

# ---------- 运行阶段 ----------
FROM alpine:3.24${ALPINE_IMAGE_DIGEST:+@$ALPINE_IMAGE_DIGEST}

# 落地与诊断所需工具集：
#   iproute2   —— ip（网桥/路由/链路快照）
#   iputils    —— ping（diag ping 动作；tracepath 回退）
#   traceroute —— diag traceroute 动作
#   tcpdump    —— diag capture 动作
# netmgrd 需要 root（NET_ADMIN + 主机网络命名空间操作），不建非 root 用户
RUN apk add --no-cache iproute2 iputils tcpdump traceroute

COPY --from=builder /netmgrd /usr/local/bin/netmgrd

HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=3 \
  CMD ["/usr/local/bin/netmgrd", "--healthcheck"]

ENTRYPOINT ["/usr/local/bin/netmgrd"]
