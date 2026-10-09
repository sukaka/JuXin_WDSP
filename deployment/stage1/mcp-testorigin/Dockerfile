# 九章 MCP 测试源站镜像（NG-MCP G1 批次 C 联调；与 grpc-testorigin 同族形态与锁定纪律）
FROM golang:1.25-alpine@sha256:56961d79ea8129efddcc0b8643fd8a5416b4e6228cfd477e3fd61deb2672c587 AS builder

WORKDIR /build
COPY main.go go.mod ./
# 零第三方依赖（stdlib 手工最小 Streamable HTTP MCP server——方案选择理由见 main.go 头注）
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/mcp-testorigin .

FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

RUN addgroup -S origin && adduser -S -G origin origin
COPY --from=builder /out/mcp-testorigin /usr/local/bin/mcp-testorigin

USER origin
EXPOSE 18572
ENTRYPOINT ["mcp-testorigin"]
