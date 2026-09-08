# P1-01 A1 演示合成业务镜像（service-a / service-b 共用；ARG SERVICE 选择入口）
# 构建（一般由 run.sh startup 经 compose 触发，不手工构建）：
#   docker build --build-arg SERVICE=service-a -t jiuzhang-apmdemo-service-a:a1 .
#
# 基础镜像锁定策略与 server/Dockerfile 一致（仓库纪律：禁 latest、tag+digest 双锁）：
#   - 版本标签固定（golang:1.25-alpine、alpine:3.24），digest 为 multi-arch index 摘要，
#     与 server/Dockerfile、gateway/Dockerfile 当前默认值保持同一锁定基线；
#   - digest 被改成单架构子摘要时，多架构构建需 --build-arg 置空对应 digest。

ARG GOLANG_IMAGE_DIGEST=sha256:56961d79ea8129efddcc0b8643fd8a5416b4e6228cfd477e3fd61deb2672c587
ARG ALPINE_IMAGE_DIGEST=sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

# builder 固定构建机原生平台：Go 交叉编译零成本，避免 QEMU 模拟工具链
FROM --platform=$BUILDPLATFORM golang:1.25-alpine${GOLANG_IMAGE_DIGEST:+@$GOLANG_IMAGE_DIGEST} AS builder

ARG TARGETOS
ARG TARGETARCH

ARG GOPROXY=https://goproxy.cn,direct
ENV GOPROXY=${GOPROXY}

WORKDIR /build
# 依赖层缓存：先拷 go.mod/go.sum（版本与 go.sum 哈希已锁定提交）
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal

ARG SERVICE
RUN test -n "$SERVICE" && CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags "-s -w" -o /out/service ./cmd/${SERVICE}

FROM alpine:3.24${ALPINE_IMAGE_DIGEST:+@$ALPINE_IMAGE_DIGEST}
RUN adduser -D -u 10001 demo
COPY --from=builder /out/service /app/service
USER 10001
EXPOSE 8080
# 无 shell 依赖的自健康检查：/app/service -healthcheck（compose healthcheck 调用）
ENTRYPOINT ["/app/service"]
