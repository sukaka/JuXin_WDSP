# 九章管理前端镜像（阶段2）
# 多阶段：Node 构建静态产物 + Caddy 托管并反代 /api
FROM node:24-alpine@sha256:a0b9bf06e4e6193cf7a0f58816cc935ff8c2a908f81e6f1a95432d679c54fbfd AS builder

WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM caddy:2.11.4-alpine@sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648

COPY --from=builder /build/dist /usr/share/caddy
COPY Caddyfile.docker /etc/caddy/Caddyfile

EXPOSE 8080
