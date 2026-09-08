# 九章 HA lab 节点身份补丁工具镜像（deployment/ha-lab 专用）
# 构建（经 compose）：docker compose -f deployment/ha-lab/docker-compose.ha-lab.yml --profile tools build
# 基础镜像锁定策略与 gateway/Dockerfile、server/Dockerfile 完全一致：
# 版本标签固定 + multi-arch index digest 经 ARG 锁定（默认值与两 Dockerfile 相同）。
ARG GOLANG_IMAGE_DIGEST=sha256:56961d79ea8129efddcc0b8643fd8a5416b4e6228cfd477e3fd61deb2672c587
ARG ALPINE_IMAGE_DIGEST=sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

FROM --platform=$BUILDPLATFORM golang:1.25-alpine${GOLANG_IMAGE_DIGEST:+@$GOLANG_IMAGE_DIGEST} AS builder
ARG TARGETOS
ARG TARGETARCH
WORKDIR /build
COPY main.go ./
# 仅标准库，无 go.mod 依赖拉取；CGO 关闭产静态二进制
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/nodepatch main.go

FROM alpine:3.24${ALPINE_IMAGE_DIGEST:+@$ALPINE_IMAGE_DIGEST}
# 与网关/api 容器同 UID（1000）：Admin Socket 由网关以 umask 077 创建（0700/caddy），
# 补丁工具须以同 UID 运行才能连接
RUN addgroup -g 1000 -S tools && adduser -u 1000 -S -G tools tools
COPY --from=builder /out/nodepatch /usr/local/bin/nodepatch
USER tools
ENTRYPOINT ["/usr/local/bin/nodepatch"]
