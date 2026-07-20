# 九章阶段1测试源站镜像（仅 POC 使用）
FROM golang:1.25-alpine@sha256:56961d79ea8129efddcc0b8643fd8a5416b4e6228cfd477e3fd61deb2672c587 AS builder

ARG GOPROXY=https://goproxy.cn,direct
ENV GOPROXY=${GOPROXY}

WORKDIR /build
COPY main.go go.mod ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/testorigin .

FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

RUN addgroup -S origin && adduser -S -G origin origin
COPY --from=builder /out/testorigin /usr/local/bin/testorigin

USER origin
EXPOSE 8081

HEALTHCHECK --interval=15s --timeout=3s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8081/health || exit 1

ENTRYPOINT ["/usr/local/bin/testorigin"]
