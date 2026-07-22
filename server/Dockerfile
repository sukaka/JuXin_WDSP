# 九章管理后端镜像（阶段2）
# 构建: docker build -t jiuzhang-server:stage2 server/
FROM golang:1.25-alpine@sha256:56961d79ea8129efddcc0b8643fd8a5416b4e6228cfd477e3fd61deb2672c587 AS builder

ARG GOPROXY=https://goproxy.cn,direct
ENV GOPROXY=${GOPROXY}

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/jiuzhang-api ./cmd/api

FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

RUN addgroup -g 1000 -S jiuzhang && adduser -u 1000 -S -G jiuzhang jiuzhang \
    && mkdir -p /app/migrations /app/runtime && chown -R jiuzhang:jiuzhang /app

COPY --from=builder /out/jiuzhang-api /usr/local/bin/jiuzhang-api
COPY --chown=jiuzhang:jiuzhang migrations/ /app/migrations/
# 报告 PDF 字体等资源（阶段6）
COPY --chown=jiuzhang:jiuzhang assets/ /app/assets/

USER jiuzhang
WORKDIR /app
ENV MIGRATIONS_DIR=/app/migrations

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8080/api/v1/health || exit 1

# 启动时先执行迁移再启动服务
ENTRYPOINT ["/bin/sh", "-c", "jiuzhang-api migrate up && exec jiuzhang-api"]
