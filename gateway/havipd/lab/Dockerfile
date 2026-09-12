# 九章 havipd 主备 VIP 组件 lab 镜像（privileged 容器内真实 keepalived 验证）
# 需先在宿主机产出 havipd 静态二进制（仓库根目录）：
#   cd gateway && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath \
#     -ldflags="-s -w" -o havipd/lab/bin/havipd ./cmd/havipd && cd ..
FROM alpine:3.21

RUN apk add --no-cache keepalived iproute2 bash curl

COPY bin/havipd /usr/local/bin/havipd
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && mkdir -p /var/run/caddy/sidecars/keepalived

ENTRYPOINT ["/entrypoint.sh"]
