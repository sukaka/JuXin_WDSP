#!/usr/bin/env bash
# 真实 Caddy + Publisher 发布冒烟 E2E。仅在隔离 Docker 网络运行，不代表兆芯/openEuler 验收。
# Caddy Admin 仅使用共享命名卷中的 Unix Socket；所有容器、网络、卷与临时文件均清理。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
IMAGE="jiuzhang-gateway:publish-smoke-e2e"
POSTGRES_IMAGE="postgres:16.4-alpine@sha256:5660c2cbfea50c7a9127d17dc4e48543eedd3d7a41a595a2dfa572471e37e64c"
GO_IMAGE="golang:1.25-alpine@sha256:56961d79ea8129efddcc0b8643fd8a5416b4e6228cfd477e3fd61deb2672c587"
RUN_ID="$$-${RANDOM}"
NETWORK="jz-publish-smoke-net-${RUN_ID}"
ADMIN_VOLUME="jz-publish-smoke-admin-${RUN_ID}"
PG_CONTAINER="jz-publish-smoke-pg-${RUN_ID}"
CADDY_CONTAINER="jz-publish-smoke-caddy-${RUN_ID}"
TEST_CONTAINER="jz-publish-smoke-test-${RUN_ID}"
TMP_ROOT="$(mktemp -d "/tmp/jz-publish-smoke-e2e.XXXXXX")"

cleanup() {
  docker rm -fv "$TEST_CONTAINER" "$CADDY_CONTAINER" "$PG_CONTAINER" >/dev/null 2>&1 || true
  docker volume rm "$ADMIN_VOLUME" >/dev/null 2>&1 || true
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
  case "$TMP_ROOT" in
    /tmp/jz-publish-smoke-e2e.*) rm -rf "$TMP_ROOT" ;;
    *) printf '拒绝清理非测试目录\n' >&2 ;;
  esac
}
trap cleanup EXIT INT TERM HUP

for cmd in docker openssl; do
  command -v "$cmd" >/dev/null 2>&1 || { printf '缺少命令: %s\n' "$cmd" >&2; exit 1; }
done
docker info >/dev/null

printf '构建当前工作区真实 Caddy 镜像（含 jiuzhang_guard 新端点）\n'
docker build --file "$REPO_ROOT/gateway/Dockerfile" --tag "$IMAGE" "$REPO_ROOT/gateway"

cat >"$TMP_ROOT/initial.json" <<'JSON'
{"admin":{"listen":"unix//run/caddy/admin.sock"},"apps":{"http":{"servers":{}}}}
JSON
chmod 0644 "$TMP_ROOT/initial.json"
docker network create --driver bridge "$NETWORK" >/dev/null
docker volume create "$ADMIN_VOLUME" >/dev/null
# 命名卷保持 Linux 原生 Unix Socket 语义；先赋予生产启动器所使用的 UID/GID。
docker run --rm --volume "$ADMIN_VOLUME:/run/caddy" --entrypoint /bin/sh \
  "$IMAGE" -c 'chown 1000:1000 /run/caddy && chmod 0770 /run/caddy'

DB_PASSWORD="$(openssl rand -hex 32)"
printf '启动隔离 PostgreSQL 与真实 Caddy（HTTP :82 仅在测试网络内）\n'
docker run --detach --name "$PG_CONTAINER" --network "$NETWORK" \
  --env POSTGRES_USER=jiuzhang \
  --env POSTGRES_PASSWORD="$DB_PASSWORD" \
  --env POSTGRES_DB=jiuzhang \
  "$POSTGRES_IMAGE" >/dev/null

docker run --detach --name "$CADDY_CONTAINER" --network "$NETWORK" \
  --volume "$TMP_ROOT/initial.json:/etc/caddy/initial.json:ro" \
  --volume "$ADMIN_VOLUME:/run/caddy" \
  --volume "$REPO_ROOT/gateway/rules:/etc/caddy/rules:ro" \
  --volume "$REPO_ROOT/gateway/configs/blockpage.html:/srv/jiuzhang/blockpage.html:ro" \
  "$IMAGE" run --config /etc/caddy/initial.json >/dev/null

for _ in $(seq 1 90); do
  if docker exec "$PG_CONTAINER" pg_isready -U jiuzhang -d jiuzhang >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
docker exec "$PG_CONTAINER" pg_isready -U jiuzhang -d jiuzhang >/dev/null

for _ in $(seq 1 60); do
  if docker exec "$CADDY_CONTAINER" test -S /run/caddy/admin.sock >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
docker exec "$CADDY_CONTAINER" test -S /run/caddy/admin.sock >/dev/null

# DSN 只经测试容器环境传递，不打印、不写文件；密钥由 Publisher 每次发布随机生成。
# Go 测试在独立容器运行，与 Caddy 共用 Unix Socket；源站也监听该测试容器的动态端口。
docker run --rm --name "$TEST_CONTAINER" --network "$NETWORK" \
  --env GOPROXY="https://goproxy.cn,direct" \
  --env JIUZHANG_PUBLISH_SMOKE_E2E=1 \
  --env JIUZHANG_PUBLISH_SMOKE_E2E_POSTGRES_DSN="postgres://jiuzhang:${DB_PASSWORD}@${PG_CONTAINER}:5432/jiuzhang?sslmode=disable" \
  --env JIUZHANG_PUBLISH_SMOKE_E2E_CADDY_SOCKET=/run/caddy/admin.sock \
  --env JIUZHANG_PUBLISH_SMOKE_E2E_CADDY_ADDR="${CADDY_CONTAINER}:82" \
  --env JIUZHANG_PUBLISH_SMOKE_E2E_ORIGIN_HOST="$TEST_CONTAINER" \
  --volume "$REPO_ROOT:/src:ro" \
  --volume "$ADMIN_VOLUME:/run/caddy" \
  --workdir /src/server \
  --entrypoint go \
  "$GO_IMAGE" test ./internal/gatewayconfig \
  -run '^TestPublishSmokeRealCaddyE2E$' -count=1 -timeout=4m -v

printf '真实 Caddy/Publisher E2E 完成；容器、网络、卷与临时文件已自动清理\n'
