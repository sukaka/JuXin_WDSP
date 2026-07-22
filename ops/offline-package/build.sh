#!/usr/bin/env bash
# build.sh —— 构建离线交付包 dist/jiuzhang-offline-{version}.tar.gz。
# 内容：锁定镜像（docker save）+ 生产 compose 模板 + 配置模板 + ops 脚本 + licenses + SBOM + manifest.json。
# 安全约束：绝不打包 .env / 真实口令；manifest 记录全部文件哈希。
# 退出码：0=成功 1=失败 2=用法错误
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck source=../lib/common.sh
source "$SCRIPT_DIR/../lib/common.sh"

# 锁定镜像（与 docs/DEPENDENCIES.md 一致，禁止使用 latest）
POSTGRES_IMAGE="postgres:16.4-alpine@sha256:5660c2cbfea50c7a9127d17dc4e48543eedd3d7a41a595a2dfa572471e37e64c"
VALKEY_IMAGE="valkey/valkey:8.1.8-alpine@sha256:94365b275456ae14621001c03556c732b1d93a0cdeacc317d1bdd52eba680885"

usage() {
  cat <<'EOF'
用法: build.sh --version X.Y.Z [选项]

构建离线交付包 dist/jiuzhang-offline-{version}.tar.gz：
  images/      docker save 的 4 个锁定镜像（server/gateway/postgres/valkey）
  docker-compose.yml  生产编排模板（端口/口令经 .env 注入）
  .env.example        配置模板
  ops/         运维脚本（install/upgrade/backup/restore/healthcheck/diagnostics）
  licenses/    第三方许可证归档
  docs/SBOM.*  软件物料清单（若已由 scripts/generate-sbom.sh 生成）
  manifest.json 版本/镜像摘要/文件清单与总哈希

选项:
  -v, --version X.Y.Z    交付版本号（必填，须与 jiuzhang-server/gateway 镜像 tag 一致）
      --skip-images      跳过 docker save（仅打包文件清单，供无 docker 环境验证）
  -o, --output DIR       输出目录（默认 <仓库>/dist）
  -h, --help             显示帮助

前置条件:
  - 本机已构建 jiuzhang-server:{version} 与 jiuzhang-gateway:{version} 镜像
  - 已生成 docs/SBOM.spdx.json / docs/SBOM.cyclonedx.json（可选但建议）

退出码: 0=成功 1=失败 2=用法错误
EOF
}

VERSION=""
SKIP_IMAGES=false
OUT_DIR="$REPO_ROOT/dist"
while [[ $# -gt 0 ]]; do
  case "$1" in
    -v|--version)   VERSION="$2"; shift 2 ;;
    --skip-images)  SKIP_IMAGES=true; shift ;;
    -o|--output)    OUT_DIR="$2"; shift 2 ;;
    -h|--help)      usage; exit 0 ;;
    *) log_err "未知参数: $1"; usage; exit 2 ;;
  esac
done

[[ -n "$VERSION" ]] || { log_err "必须指定 --version"; usage; exit 2; }
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || { log_err "版本号须为 X.Y.Z 格式: $VERSION"; exit 2; }
require_cmd tar
require_cmd jq

SERVER_IMAGE="jiuzhang-server:$VERSION"
GATEWAY_IMAGE="jiuzhang-gateway:$VERSION"

if [[ "$SKIP_IMAGES" != "true" ]]; then
  require_cmd docker
  for img in "$SERVER_IMAGE" "$GATEWAY_IMAGE" "$POSTGRES_IMAGE" "$VALKEY_IMAGE"; do
    docker image inspect "$img" >/dev/null 2>&1 || die "镜像不存在: ${img}（请先构建/拉取锁定镜像）"
  done
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/jzpkg.XXXXXX")"
trap 'rm -rf "$work"' EXIT
pkg_dir="$work/jiuzhang-offline-$VERSION"
mkdir -p "$pkg_dir"/{images,ops,licenses,docs}
mkdir -p "$OUT_DIR"

# ---------- 1. 镜像 ----------
image_digests=()
if [[ "$SKIP_IMAGES" != "true" ]]; then
  log_info "导出镜像（docker save，可能需要数分钟）..."
  docker save "$SERVER_IMAGE" -o "$pkg_dir/images/jiuzhang-server.tar"
  docker save "$GATEWAY_IMAGE" -o "$pkg_dir/images/jiuzhang-gateway.tar"
  docker save "$POSTGRES_IMAGE" -o "$pkg_dir/images/postgres.tar"
  docker save "$VALKEY_IMAGE" -o "$pkg_dir/images/valkey.tar"
fi
for img in "$SERVER_IMAGE" "$GATEWAY_IMAGE" "$POSTGRES_IMAGE" "$VALKEY_IMAGE"; do
  if [[ "$SKIP_IMAGES" != "true" ]]; then
    digest="$(docker image inspect "$img" --format '{{.Id}}')"
  else
    digest="(skipped)"
  fi
  image_digests+=("$(jq -n --arg image "$img" --arg digest "$digest" '{image:$image, digest:$digest}')")
done

# ---------- 2. 生产 compose 模板 ----------
cat > "$pkg_dir/docker-compose.yml" <<EOF
# 九章 WAF 生产编排模板（离线交付包 v${VERSION}）
# 所有口令经 .env 注入（参考 .env.example；禁止在本文档写入口令）
name: jiuzhang-waf

services:
  postgres:
    image: $POSTGRES_IMAGE
    container_name: jiuzhang-postgres
    restart: unless-stopped
    environment:
      POSTGRES_DB: \${POSTGRES_DB:-jiuzhang_waf}
      POSTGRES_USER: \${POSTGRES_USER:-jiuzhang}
      POSTGRES_PASSWORD: \${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required}
      PGDATA: /var/lib/postgresql/data/pgdata
    volumes:
      - postgres-data:/var/lib/postgresql/data
    ports:
      - "127.0.0.1:\${POSTGRES_PORT:-5432}:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U \${POSTGRES_USER:-jiuzhang} -d \${POSTGRES_DB:-jiuzhang_waf}"]
      interval: 10s
      timeout: 5s
      retries: 5
    security_opt: [no-new-privileges:true]
    networks: [jiuzhang-internal]

  valkey:
    image: $VALKEY_IMAGE
    container_name: jiuzhang-valkey
    restart: unless-stopped
    command: ["valkey-server", "--requirepass", "\${VALKEY_PASSWORD:?VALKEY_PASSWORD is required}",
              "--appendonly", "yes", "--maxmemory", "256mb", "--maxmemory-policy", "allkeys-lru"]
    environment:
      # 健康检查在容器内展开 VALKEY_PASSWORD，必须显式传入
      VALKEY_PASSWORD: \${VALKEY_PASSWORD:?VALKEY_PASSWORD is required}
    volumes:
      - valkey-data:/data
    ports:
      - "127.0.0.1:\${VALKEY_PORT:-6379}:6379"
    healthcheck:
      test: ["CMD-SHELL", "valkey-cli -a \"\$\$VALKEY_PASSWORD\" --no-auth-warning ping | grep -q PONG"]
      interval: 10s
      timeout: 5s
      retries: 5
    security_opt: [no-new-privileges:true]
    networks: [jiuzhang-internal]

  api:
    image: $SERVER_IMAGE
    container_name: jiuzhang-api
    restart: unless-stopped
    environment:
      APP_ENV: \${APP_ENV:-prod}
      SERVER_HOST: 0.0.0.0
      SERVER_PORT: 8080
      POSTGRES_HOST: postgres
      POSTGRES_PORT: 5432
      POSTGRES_DB: \${POSTGRES_DB:-jiuzhang_waf}
      POSTGRES_USER: \${POSTGRES_USER:-jiuzhang}
      POSTGRES_PASSWORD: \${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required}
      VALKEY_HOST: valkey
      VALKEY_PORT: 6379
      VALKEY_PASSWORD: \${VALKEY_PASSWORD:?VALKEY_PASSWORD is required}
      COOKIE_SECURE: \${COOKIE_SECURE:-true}
      INITIAL_ADMIN_USERNAME: \${INITIAL_ADMIN_USERNAME:-jiuzhang_admin}
      INITIAL_ADMIN_PASSWORD: \${INITIAL_ADMIN_PASSWORD:-}
      JIUZHANG_MASTER_KEY: \${JIUZHANG_MASTER_KEY:?JIUZHANG_MASTER_KEY is required}
      CADDY_ADMIN_SOCKET: /var/run/caddy/admin.sock
      GATEWAY_DATA_DIR: /app/runtime
      MIGRATIONS_DIR: /app/migrations
    ports:
      - "127.0.0.1:\${API_PORT:-18081}:8080"
    volumes:
      - gateway-admin:/var/run/caddy
      - gateway-logs:/var/log/caddy-audit:ro
      - runtime-data:/app/runtime
    depends_on:
      postgres: {condition: service_healthy}
      valkey:   {condition: service_healthy}
      gateway:  {condition: service_started}
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://127.0.0.1:8080/api/v1/health"]
      interval: 15s
      timeout: 5s
      retries: 5
      start_period: 20s
    security_opt: [no-new-privileges:true]
    networks: [jiuzhang-internal]

  gateway:
    image: $GATEWAY_IMAGE
    container_name: jiuzhang-gateway
    restart: unless-stopped
    ports:
      - "\${GATEWAY_PORT:-80}:8080"
    volumes:
      - gateway-logs:/var/log/caddy
      - gateway-admin:/var/run/caddy
    security_opt: [no-new-privileges:true]
    networks: [jiuzhang-internal]

volumes:
  postgres-data: {driver: local}
  valkey-data: {driver: local}
  gateway-admin: {driver: local}
  gateway-logs: {driver: local}
  runtime-data: {driver: local}

networks:
  jiuzhang-internal: {driver: bridge}
EOF

# ---------- 3. 配置模板 / ops 脚本 / licenses / SBOM ----------
cp "$REPO_ROOT/.env.example" "$pkg_dir/.env.example"
cp -R "$SCRIPT_DIR/.." "$work/ops-copy"
# 清理运维脚本目录中的状态文件与临时产物
rm -f "$work/ops-copy/upgrade/.upgrade-state.env"
mkdir -p "$pkg_dir/ops"
cp -R "$work/ops-copy/." "$pkg_dir/ops/"
rm -rf "$work/ops-copy"
cp -R "$REPO_ROOT/licenses/." "$pkg_dir/licenses/"
for f in SBOM.spdx.json SBOM.cyclonedx.json; do
  if [[ -f "$REPO_ROOT/docs/$f" ]]; then
    cp "$REPO_ROOT/docs/$f" "$pkg_dir/docs/$f"
  else
    log_warn "docs/$f 不存在（建议先运行 scripts/generate-sbom.sh）"
  fi
done
cp "$REPO_ROOT/THIRD_PARTY_NOTICES.md" "$pkg_dir/docs/THIRD_PARTY_NOTICES.md"
[[ -f "$REPO_ROOT/docs/DEPENDENCIES.md" ]] && cp "$REPO_ROOT/docs/DEPENDENCIES.md" "$pkg_dir/docs/"

# ---------- 4. 安全检查：绝不打包 .env / 真实口令 ----------
if find "$pkg_dir" -name '.env' -print -quit | grep -q .; then
  die "安全检查失败：打包目录中混入 .env"
fi

# ---------- 5. manifest.json（文件清单 + 哈希） ----------
log_info "生成 manifest.json ..."
files_json="$(
  cd "$pkg_dir"
  find . -type f ! -name 'manifest.json' | LC_ALL=C sort | while IFS= read -r f; do
    rel="${f#./}"
    hash="$(shasum -a 256 "$rel" | awk '{print $1}')"
    size="$(stat -f%z "$rel" 2>/dev/null || stat -c%s "$rel")"
    jq -n --arg path "$rel" --arg sha256 "$hash" --argjson size "$size" \
      '{path:$path, sha256:$sha256, size:$size}'
  done | jq -s '.'
)"
images_json="$(printf '%s\n' "${image_digests[@]}" | jq -s '.')"
total_hash="$(printf '%s' "$files_json" | shasum -a 256 | awk '{print $1}')"
jq -n \
  --arg product "九章WEB应用智能防护系统V2.0" \
  --arg version "$VERSION" \
  --arg built_at "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
  --argjson images "$images_json" \
  --argjson files "$files_json" \
  --arg files_hash "$total_hash" \
  '{product:$product, version:$version, built_at:$built_at,
    images:$images, files:$files, files_manifest_sha256:$files_hash}' \
  > "$pkg_dir/manifest.json"

# ---------- 6. 打包 ----------
out="$OUT_DIR/jiuzhang-offline-$VERSION.tar.gz"
tar -czf "$out" -C "$work" "jiuzhang-offline-$VERSION"
size="$(stat -f%z "$out" 2>/dev/null || stat -c%s "$out")"
log_info "离线交付包已生成: ${out}（${size} 字节）"
log_info "安装: tar -xzf $(basename "$out") && cd jiuzhang-offline-$VERSION && bash ops/install/install.sh"
