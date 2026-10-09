# 九章 gRPC 测试源站镜像（NG-GRPC G1 批次 C 联调；与 testorigin 同族形态与锁定纪律）
FROM golang:1.25-alpine@sha256:56961d79ea8129efddcc0b8643fd8a5416b4e6228cfd477e3fd61deb2672c587 AS builder

ARG GOPROXY=https://goproxy.cn,direct
ENV GOPROXY=${GOPROXY}

WORKDIR /build
COPY main.go go.mod go.sum ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/grpc-testorigin .
# 构建期导出描述符集（仅 EchoService；OtherService 不入集——R03 语义承载）
RUN CGO_ENABLED=0 go run . -dump-descriptor /out/echo.pb

FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

RUN addgroup -S origin && adduser -S -G origin origin
COPY --from=builder /out/grpc-testorigin /usr/local/bin/grpc-testorigin
COPY --from=builder /out/echo.pb /usr/local/share/grpc-testorigin/echo.pb

USER origin
EXPOSE 18571
ENTRYPOINT ["grpc-testorigin"]
