#!/usr/bin/env bash
# build.sh —— 按产品线 + 架构构建离线交付包。
#
# 产品线（PRODUCT_EDITION，同一套镜像，靠配置区分交付形态）：
#   waf  — 纯 Web 应用防火墙（API 动态防护关闭）
#   wdsp — Web 动态防护 = WAF + API 动态防护
#   api  — 九章 API 安全系统 = 底座 + API 能力（Web 防护专属菜单关闭）
#
# 架构：
#   amd64 — x86-64（含 Intel/AMD；海光 C86、兆芯 KX/KH 兼容，别名 x86 / x86_64）
#   arm64 — ARM64（鲲鹏/飞腾/Apple Silicon 等）
#
# 产物：dist/jiuzhang-{product}-offline-{version}-{arch}.tar.gz（+ 旁车 .sha256 与 .sig）
# 内容：锁定镜像（含可选 APM 数据面镜像）+ 生产 compose（含 edition 环境变量）+ APM 数据面 compose
#       + .env.example + ops + licenses + SBOM + manifest.json
# 安全约束：绝不打包 .env / 真实口令；manifest 记录全部文件哈希；
#       配置 WDSP_SIGNING_KEY（Ed25519 私钥路径，绝不入库）时对整包与内嵌裸机网关包签名，
#       安装端以内置可信公钥验签（见 ops/lib/signing.sh 与 docs/DEPLOYMENT.md）；
#       正式构建必须签名；--development 仅用于本地开发自验，产物明确标记为 development。
# 退出码：0=成功 1=失败 2=用法错误
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# 追溯字段只记录公开的构建标识，不读取或写入任何凭据。
BUILD_COMMIT="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || true)"
[[ -n "$BUILD_COMMIT" ]] || BUILD_COMMIT="unknown"
RELEASE_KEY_ID="wdsp-release-ed25519-0db8c1fc0fe556fd"
# shellcheck source=../lib/common.sh
source "$SCRIPT_DIR/../lib/common.sh"
# shellcheck source=../lib/signing.sh
source "$SCRIPT_DIR/../lib/signing.sh"

# 交付清单与构建侧安全扫描器只服务于打包阶段，不复制进客户包。
ALLOWLIST_FILE="$SCRIPT_DIR/allowlist.v1"
SCANNER_FILE="$SCRIPT_DIR/scan.py"
# Full product images include reviewed data-plane layers larger than the unit
# test defaults. The package scanner remains bounded and fail-closed; these
# limits cover the largest pinned delivery component without treating it as a
# compression bomb solely because it is a production database image.
PACKAGE_SCAN_MAX_MEMBER_BYTES=1073741824
PACKAGE_SCAN_MAX_TOTAL_BYTES=8589934592
# Full-image recursive scanning is intentionally bounded but needs more than
# the unit-test default.  Five minutes still fails closed on a stalled scanner.
PACKAGE_SCAN_TIMEOUT_SECONDS=300

# 锁定镜像（与 docs/DEPENDENCIES.md 一致，禁止使用 latest）。
# 下列 digest 为多架构 index/manifest list 摘要（含 amd64+arm64），
# 配合 docker pull --platform linux/{arch} 拉取对应平台层。
POSTGRES_IMAGE_AMD64="${POSTGRES_IMAGE_AMD64:-postgres:16.4-alpine@sha256:5660c2cbfea50c7a9127d17dc4e48543eedd3d7a41a595a2dfa572471e37e64c}"
VALKEY_IMAGE_AMD64="${VALKEY_IMAGE_AMD64:-valkey/valkey:8.1.8-alpine@sha256:94365b275456ae14621001c03556c732b1d93a0cdeacc317d1bdd52eba680885}"
POSTGRES_IMAGE_ARM64="${POSTGRES_IMAGE_ARM64:-postgres:16.4-alpine@sha256:5660c2cbfea50c7a9127d17dc4e48543eedd3d7a41a595a2dfa572471e37e64c}"
VALKEY_IMAGE_ARM64="${VALKEY_IMAGE_ARM64:-valkey/valkey:8.1.8-alpine@sha256:94365b275456ae14621001c03556c732b1d93a0cdeacc317d1bdd52eba680885}"
# APM 数据面镜像（可选能力，默认关闭）：
#   管理面开关 —— .env 设 APM_ENABLED=true（默认 false，关闭时 /api/v1/apm/* 统一 503 降级），
#                 经包内 docker-compose.yml api 服务 environment 透传进容器；
#   数据面启用 —— 包内 docker-compose.apm.yml（独立于主栈的 compose 项目，profile central/local；
#                 需先填 CLICKHOUSE_* 口令并按 docs/APM_DATA_PLANE_DEPLOYMENT.md 配置 mTLS 证书）。
# digest 与 deployment/docker-compose.apm.yml / docs/DEPENDENCIES.md 一致的 multi-arch index 摘要
# （2026-08-30 经 docker buildx imagetools inspect 实测，子摘要见 DEPENDENCIES.md APM 小节）。
CLICKHOUSE_IMAGE_AMD64="${CLICKHOUSE_IMAGE_AMD64:-clickhouse/clickhouse-server:25.8-alpine@sha256:87e0a5b72f5465b18eacca7c76850e7ff551c9795c50e451f5646299e5e24146}"
OTEL_COLLECTOR_IMAGE_AMD64="${OTEL_COLLECTOR_IMAGE_AMD64:-otel/opentelemetry-collector-contrib:0.154.0@sha256:b3079f45e19bdb7326bf49cdddce6cf60dfd865138db39f2733ea48ab17bc4cb}"
CLICKHOUSE_IMAGE_ARM64="${CLICKHOUSE_IMAGE_ARM64:-clickhouse/clickhouse-server:25.8-alpine@sha256:87e0a5b72f5465b18eacca7c76850e7ff551c9795c50e451f5646299e5e24146}"
OTEL_COLLECTOR_IMAGE_ARM64="${OTEL_COLLECTOR_IMAGE_ARM64:-otel/opentelemetry-collector-contrib:0.154.0@sha256:b3079f45e19bdb7326bf49cdddce6cf60dfd865138db39f2733ea48ab17bc4cb}"

usage() {
  cat <<'EOF'
用法: build.sh --version X.Y.Z --product PRODUCT [选项]

按产品线与架构构建离线交付包：
  dist/jiuzhang-{product}-offline-{version}-{arch}.tar.gz

产品线（--product，必填）：
  waf     九章 WEB 应用智能防护（API 动态防护关闭）
  wdsp    九章 Web 动态防护系统（WAF + API 动态防护）
  api     九章 API 安全系统（底座 + API 能力；Web 防护专属关闭）

架构（--arch）：
  amd64   x86-64（默认别名：x86、x86_64；海光 C86、兆芯 KX/KH 使用本架构）
  arm64   ARM64

包内：
  images/             docker save 的 server/gateway/web/logrotator/netmgrd/containerops/pcapd/postgres/valkey
                      及 APM 数据面镜像 clickhouse/opentelemetry-collector-contrib（共 11 个）
  gateway-linux-<arch>.tar.gz  裸机网关包（caddy 二进制 + sha256sums + VERSION + rules +
                      blockpage + bootstrap + unit + 安装/验收脚本）
  gateway/            生产 compose gateway 服务挂载源（rules/bootstrap Caddyfile/blockpage）
  docker-compose.yml  生产编排（注入 PRODUCT_EDITION 等；api 透传 APM_ENABLED，默认 false）
  docker-compose.apm.yml  可选 APM 数据面编排（独立 compose 项目，profile central/local）
  apm/                APM 数据面挂载源（clickhouse schema / collector 配置 / pki 占位）
  .env.example        配置模板（含产品线默认值；APM_* 与 CLICKHOUSE_* 默认关/空）
  ops/                运维脚本（完整安装时自动安装宿主机升级执行器）
  licenses/           第三方许可证
  docs/               SBOM / 依赖说明
  manifest.json       版本/产品/架构/镜像/文件哈希/APM 启用说明

选项:
  -v, --version X.Y.Z    交付版本号（必填，须与 jiuzhang-server/gateway 镜像 tag 一致）
  -p, --product PRODUCT  产品线 waf|wdsp|api（必填）
  -a, --arch ARCH        目标架构 amd64|arm64|x86|x86_64（缺省取宿主机架构）
      --runtime-only     不携带产品文档、SBOM 与开发/测试资源（保留许可证）
      --skip-images      跳过 docker pull/save（仅打包文件清单，供无 docker 环境验证）
      --development      开发自验模式：允许未配置发布私钥，产物标记 delivery_mode=development；禁止用于正式交付
  -o, --output DIR       输出目录（默认 <仓库>/dist）
  -h, --help             显示帮助

环境变量:
  WDSP_AGENT_BINARY      可选，同架构 Linux Agent 发布二进制；随包复制至 agents/wdsp-agent。
  WDSP_SIGNING_KEY       发布签名 Ed25519 私钥路径（openssl genpkey -algorithm ED25519 生成，
                         绝不入库）。设置后对整包与内嵌裸机网关包产出旁车 .sig；
                         正式构建必需；未设置时必须显式加 --development。

示例:
  build.sh -v 2.0.0 -p waf  -a amd64   # WAF × x86-64 / 海光 C86 / 兆芯 KX/KH
  build.sh -v 2.0.0 -p wdsp -a amd64   # WDSP × amd64
  build.sh -v 2.0.0 -p api  -a arm64   # API  × ARM64
  build.sh -v 2.0.0 -p waf  -a x86     # x86 别名 → amd64

批量（3 产品 × 2 架构）请用：
  ops/offline-package/build-all.sh -v 2.0.0

前置条件:
  - 本机已按目标架构构建 jiuzhang-server/gateway/web/logrotator/netmgrd/containerops:{version}
    （docker buildx build --platform linux/{arch}；containerops 用 -f deployment/containerops/Dockerfile，上下文=仓库根）
  - 已生成 docs/SBOM.spdx.json / docs/SBOM.cyclonedx.json（可选但建议）

退出码: 0=成功 1=失败 2=用法错误
EOF
}

# product_defaults PRODUCT —— 输出: display_name|api_dyn|web_waf
product_defaults() {
  case "$1" in
    waf)  printf '%s\n' "九章WEB应用智能防护系统|false|true" ;;
    wdsp) printf '%s\n' "九章Web动态防护系统|true|true" ;;
    api)  printf '%s\n' "九章API安全系统|true|false" ;;
    *)    return 1 ;;
  esac
}

# normalize_arch RAW —— 归一化为 amd64|arm64（x86/x86_64 → amd64）
normalize_arch() {
  case "$1" in
    amd64|x86_64|x86) printf 'amd64\n' ;;
    arm64|aarch64)    printf 'arm64\n' ;;
    *) return 1 ;;
  esac
}

RUNTIME_ONLY=false
runtime_copy() {
  local src="$1" dst="$2"
  mkdir -p "$dst"
  if [[ "$RUNTIME_ONLY" == "true" ]]; then
    COPYFILE_DISABLE=1 tar --no-xattrs --exclude='*.md' --exclude='README*' --exclude='INSTALL' \
      --exclude='.git*' --exclude='test' --exclude='tests' --exclude='testdata' \
      --exclude='__tests__' --exclude='__pycache__' -cf - -C "$src" . | tar -xf - -C "$dst"
  else
    cp -R "$src/." "$dst/"
  fi
}
VERSION=""
PRODUCT=""
ARCH=""
SKIP_IMAGES=false
DEVELOPMENT=false
OUT_DIR="$REPO_ROOT/dist"
while [[ $# -gt 0 ]]; do
  case "$1" in
    -v|--version)   VERSION="$2"; shift 2 ;;
    -p|--product)   PRODUCT="$2"; shift 2 ;;
    -a|--arch)      ARCH="$2"; shift 2 ;;
    --runtime-only) RUNTIME_ONLY=true; shift ;;
    --skip-images)  SKIP_IMAGES=true; shift ;;
    --development)  DEVELOPMENT=true; shift ;;
    -o|--output)    OUT_DIR="$2"; shift 2 ;;
    -h|--help)      usage; exit 0 ;;
    *) log_err "未知参数: $1"; usage; exit 2 ;;
  esac
done

[[ -n "$VERSION" ]] || { log_err "必须指定 --version"; usage; exit 2; }
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || { log_err "版本号须为 X.Y.Z 格式: $VERSION"; exit 2; }

PRODUCT="$(printf '%s' "$PRODUCT" | tr '[:upper:]' '[:lower:]')"
[[ -n "$PRODUCT" ]] || { log_err "必须指定 --product waf|wdsp|api"; usage; exit 2; }
defaults="$(product_defaults "$PRODUCT")" || { log_err "--product 仅支持 waf|wdsp|api: $PRODUCT"; usage; exit 2; }
IFS='|' read -r PRODUCT_NAME API_DYNAMIC_DEFAULT WEB_WAF_DEFAULT <<<"$defaults"

if [[ -z "$ARCH" ]]; then
  case "$(uname -m)" in
    x86_64)        ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) die "无法识别宿主机架构（uname -m: $(uname -m)），请显式指定 --arch amd64|arm64" ;;
  esac
else
  ARCH="$(normalize_arch "$ARCH")" || { log_err "--arch 仅支持 amd64|arm64|x86|x86_64: $ARCH"; usage; exit 2; }
fi

require_cmd tar
require_cmd jq
require_cmd python3
[[ -f "$ALLOWLIST_FILE" ]] || die "交付 allowlist 不存在: $ALLOWLIST_FILE"
[[ -f "$SCANNER_FILE" ]] || die "离线包扫描器不存在: $SCANNER_FILE"

# ---------- 0. 发布签名密钥（WDSP_SIGNING_KEY） ----------
# 签名在打包前确定（manifest 需记录 signed 标记）；私钥绝不入库，仅由发布侧保管。
SIGNING_KEY="${WDSP_SIGNING_KEY:-}"
PKG_SIGNED=false
DELIVERY_MODE="production"
if [[ "$DEVELOPMENT" == "true" ]]; then
  DELIVERY_MODE="development"
fi
if [[ -n "$SIGNING_KEY" ]]; then
  [[ -f "$SIGNING_KEY" ]] || die "WDSP_SIGNING_KEY 指向的私钥不存在: $SIGNING_KEY"
  require_cmd openssl
  openssl pkey -in "$SIGNING_KEY" -noout >/dev/null 2>&1 \
    || die "WDSP_SIGNING_KEY 私钥无法解析（须为 Ed25519 私钥，openssl genpkey -algorithm ED25519 生成）: $SIGNING_KEY"
  TRUSTED_PUB="$SCRIPT_DIR/release-signing.pub"
  [[ -f "$TRUSTED_PUB" ]] || die "缺少固定发布公钥"
  expected_pub="$(openssl pkey -pubin -in "$TRUSTED_PUB" -outform DER 2>/dev/null | base64)" || die "发布公钥无效"
  actual_pub="$(openssl pkey -in "$SIGNING_KEY" -pubout -outform DER 2>/dev/null | base64)" || die "无法导出签名公钥"
  [[ "$actual_pub" == "$expected_pub" ]] || die "WDSP_SIGNING_KEY 与固定发布公钥不匹配，拒绝生成无法验证的正式包"
  PKG_SIGNED=true
  log_info "发布签名已启用：将对整包与内嵌裸机网关包产出旁车 .sig（Ed25519）"
else
  if [[ "$DEVELOPMENT" != "true" ]]; then
    die "正式离线包必须签名：请设置 WDSP_SIGNING_KEY；本地开发自验请显式使用 --development"
  fi
  log_warn "==================== 安全警告：开发包将不签名 ===================="
  log_warn "  未配置 WDSP_SIGNING_KEY，本次构建仅允许用于本地开发自验。"
  log_warn "  产物 manifest.delivery_mode=development，安装端必须显式 --allow-unsigned。"
  log_warn "=================================================================="
fi

# sha256_of [FILE...] —— 计算 SHA-256（GNU sha256sum 优先，BSD shasum 兜底；
# 与 ops/install/install-gateway-baremetal.sh 的 sha256_verify 校验端对齐；无参数时读 stdin）
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$@"
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$@"
  else
    die "缺少 sha256sum/shasum，无法计算 SHA-256"
  fi
}

SERVER_IMAGE="jiuzhang-server:$VERSION"
GATEWAY_IMAGE="jiuzhang-gateway:$VERSION"
# 管理前端（构建上下文 web/，Node 构建 SPA + Caddy 托管并反代 /api 到 api 服务）
WEB_IMAGE="jiuzhang-web:$VERSION"
# 日志轮转 sidecar（本地构建镜像，与 server/gateway 同风格按版本 tag 锁定；
# 构建上下文 gateway/images/logrotator，基础镜像 alpine:3.24 digest 在其 Dockerfile 内锁定）
LOGROTATOR_IMAGE="jiuzhang-logrotator:$VERSION"
NETMGRD_IMAGE="jiuzhang-netmgrd:$VERSION"
PCAPD_IMAGE="jiuzhang-pcapd:$VERSION"
# 容器运维 sidecar（本地构建镜像；唯一挂载 docker.sock 的组件，构建上下文=仓库根，
# Dockerfile 为 deployment/containerops/Dockerfile，基础镜像 digest 在其文件内锁定）
CONTAINEROPS_IMAGE="jiuzhang-containerops:$VERSION"

if [[ "$ARCH" == "amd64" ]]; then
  POSTGRES_IMAGE="$POSTGRES_IMAGE_AMD64"
  VALKEY_IMAGE="$VALKEY_IMAGE_AMD64"
  CLICKHOUSE_IMAGE="$CLICKHOUSE_IMAGE_AMD64"
  OTEL_COLLECTOR_IMAGE="$OTEL_COLLECTOR_IMAGE_AMD64"
else
  POSTGRES_IMAGE="$POSTGRES_IMAGE_ARM64"
  VALKEY_IMAGE="$VALKEY_IMAGE_ARM64"
  CLICKHOUSE_IMAGE="$CLICKHOUSE_IMAGE_ARM64"
  OTEL_COLLECTOR_IMAGE="$OTEL_COLLECTOR_IMAGE_ARM64"
fi
for img in "$POSTGRES_IMAGE" "$VALKEY_IMAGE" "$CLICKHOUSE_IMAGE" "$OTEL_COLLECTOR_IMAGE"; do
  if [[ "$img" != *@sha256:* ]]; then
    log_warn "第三方镜像 ${img} 使用标签而非 digest 锁定，请尽快回填 ${ARCH} 子摘要"
  fi
done

check_image_arch() {
  local img="$1" hint="$2" actual
  # containerd 镜像存储下同一 digest 可共存多架构变体，inspect 默认展示宿主架构变体，
  # 须显式按目标平台检查；老版本 docker（非 containerd 存储）不支持 --platform 时回退原行为
  if actual="$(docker image inspect --platform "linux/${ARCH}" "$img" --format '{{.Architecture}}' 2>/dev/null)" && [[ -n "$actual" ]]; then
    :
  else
    actual="$(docker image inspect "$img" --format '{{.Architecture}}')" || die "无法检查镜像: ${img}"
  fi
  [[ "$actual" == "$ARCH" ]] || die "镜像架构不匹配: ${img} 本地为 ${actual}，目标为 ${ARCH}（${hint}）"
}

if [[ "$SKIP_IMAGES" != "true" ]]; then
  require_cmd docker
  log_info "准备锁定的第三方镜像（linux/${ARCH}，同摘要本地缓存优先）..."
  for img in "$POSTGRES_IMAGE" "$VALKEY_IMAGE" "$CLICKHOUSE_IMAGE" "$OTEL_COLLECTOR_IMAGE"; do
    if [[ "$img" == *@sha256:* ]] && docker image inspect --platform "linux/${ARCH}" "$img" >/dev/null 2>&1; then
      log_info "复用已锁定镜像: $img"
    else
      docker pull --platform "linux/${ARCH}" "$img" || die "拉取失败: $img"
    fi
  done
  for img in "$SERVER_IMAGE" "$GATEWAY_IMAGE" "$WEB_IMAGE" "$LOGROTATOR_IMAGE" "$NETMGRD_IMAGE" "$PCAPD_IMAGE" "$CONTAINEROPS_IMAGE"; do
    docker image inspect "$img" >/dev/null 2>&1 \
      || die "镜像不存在: ${img}（请先用 docker buildx build --platform linux/${ARCH} 构建）"
  done
  check_image_arch "$POSTGRES_IMAGE" "请先 docker pull --platform linux/${ARCH} ${POSTGRES_IMAGE}"
  check_image_arch "$VALKEY_IMAGE" "请先 docker pull --platform linux/${ARCH} ${VALKEY_IMAGE}"
  check_image_arch "$CLICKHOUSE_IMAGE" "请先 docker pull --platform linux/${ARCH} ${CLICKHOUSE_IMAGE}"
  check_image_arch "$OTEL_COLLECTOR_IMAGE" "请先 docker pull --platform linux/${ARCH} ${OTEL_COLLECTOR_IMAGE}"
  check_image_arch "$SERVER_IMAGE" "请用 docker buildx build --platform linux/${ARCH} 重新构建"
  check_image_arch "$GATEWAY_IMAGE" "请用 docker buildx build --platform linux/${ARCH} 重新构建"
  check_image_arch "$WEB_IMAGE" "请用 docker buildx build --platform linux/${ARCH} -t ${WEB_IMAGE} web/ 重新构建"
  check_image_arch "$LOGROTATOR_IMAGE" "请用 docker buildx build --platform linux/${ARCH} -t ${LOGROTATOR_IMAGE} gateway/images/logrotator 重新构建"
  check_image_arch "$NETMGRD_IMAGE" "请构建 gateway/images/netmgrd/Dockerfile"
  check_image_arch "$PCAPD_IMAGE" "请构建 gateway/images/pcapd/Dockerfile"
  check_image_arch "$CONTAINEROPS_IMAGE" "请用 docker buildx build --platform linux/${ARCH} -f deployment/containerops/Dockerfile -t ${CONTAINEROPS_IMAGE} . 重新构建"
fi

PKG_BASENAME="jiuzhang-${PRODUCT}-offline-${VERSION}-${ARCH}"
RELEASE_ID="wdsp-${PRODUCT}-${VERSION}-${ARCH}-${BUILD_COMMIT:0:12}"
DELIVERY_ID="$PKG_BASENAME"
work="$(mktemp -d "${TMPDIR:-/tmp}/jzpkg.XXXXXX")"
trap 'rm -rf "$work"' EXIT
pkg_dir="$work/$PKG_BASENAME"
mkdir -p "$pkg_dir"/{images,ops,licenses}
mkdir -p "$OUT_DIR"

log_info "构建产品包: product=${PRODUCT} arch=${ARCH} version=${VERSION}"

# ---------- 1. 镜像 ----------
# save_image IMAGE OUT_TAR —— 仅导出目标架构变体（containerd 存储下本地可共存多架构；
# 老版本 docker 无 save --platform 时回退全量导出）
save_image() {
  local variable="$1" out="$2" img metadata
  img="${!variable}"
  if ! docker save --platform "linux/${ARCH}" "$img" -o "$out" 2>/dev/null; then
    rm -f "$out"
    docker save "$img" -o "$out"
  fi
  if [[ "$RUNTIME_ONLY" == "true" ]]; then
    metadata="$(python3 "$SCRIPT_DIR/runtime-image.py" "$out" "$out.runtime" \
      --repository "jiuzhang-runtime-$(basename "$out" .tar)" --source-ref "$img")"
    mv "$out.runtime" "$out"
    docker load -i "$out" >&2
    printf -v "$variable" '%s' "$(printf '%s' "$metadata" | jq -r .image)"
    image_digests+=("$metadata")
  fi
}
image_digests=()
if [[ "$SKIP_IMAGES" != "true" ]]; then
  log_info "导出镜像（docker save，linux/${ARCH}，可能需要数分钟）..."
  save_image SERVER_IMAGE "$pkg_dir/images/jiuzhang-server.tar"
  save_image GATEWAY_IMAGE "$pkg_dir/images/jiuzhang-gateway.tar"
  save_image WEB_IMAGE "$pkg_dir/images/jiuzhang-web.tar"
  save_image LOGROTATOR_IMAGE "$pkg_dir/images/jiuzhang-logrotator.tar"
  save_image NETMGRD_IMAGE "$pkg_dir/images/jiuzhang-netmgrd.tar"
  save_image PCAPD_IMAGE "$pkg_dir/images/jiuzhang-pcapd.tar"
  save_image CONTAINEROPS_IMAGE "$pkg_dir/images/jiuzhang-containerops.tar"
  save_image POSTGRES_IMAGE "$pkg_dir/images/postgres.tar"
  save_image VALKEY_IMAGE "$pkg_dir/images/valkey.tar"
  save_image CLICKHOUSE_IMAGE "$pkg_dir/images/clickhouse.tar"
  save_image OTEL_COLLECTOR_IMAGE "$pkg_dir/images/opentelemetry-collector-contrib.tar"
fi
if [[ "$RUNTIME_ONLY" != "true" || "$SKIP_IMAGES" == "true" ]]; then
for img in "$SERVER_IMAGE" "$GATEWAY_IMAGE" "$WEB_IMAGE" "$LOGROTATOR_IMAGE" "$NETMGRD_IMAGE" "$PCAPD_IMAGE" "$CONTAINEROPS_IMAGE" "$POSTGRES_IMAGE" "$VALKEY_IMAGE" "$CLICKHOUSE_IMAGE" "$OTEL_COLLECTOR_IMAGE"; do
  if [[ "$SKIP_IMAGES" != "true" ]]; then
    digest="$(docker image inspect --platform "linux/${ARCH}" "$img" --format '{{.Id}}' 2>/dev/null || docker image inspect "$img" --format '{{.Id}}')"
  else
    digest="(skipped)"
  fi
  image_digests+=("$(jq -n --arg image "$img" --arg digest "$digest" '{image:$image, digest:$digest}')")
done
fi

# ---------- 1b. 裸机网关包 gateway-linux-<arch>.tar.gz ----------
# 设计文档 4.2：从现有多架构网关镜像抽取 /usr/bin/caddy（CGO_ENABLED=0 静态编译，
# 构建流程零改动），附 sha256sums 与 VERSION，并携带 rules/blockpage/bootstrap/unit/
# 安装与验收脚本及 delivery_mode，供 ops/install/install-gateway-baremetal.sh --package 使用。
build_gateway_baremetal_pkg() {
  local out="$1" gtmp gdir cid
  gtmp="$(mktemp -d "${TMPDIR:-/tmp}/jzgwpkg.XXXXXX")"
  gdir="$gtmp/gateway-linux-${ARCH}"
  mkdir -p "$gdir"
  if [[ "$SKIP_IMAGES" != "true" ]]; then
    log_info "抽取裸机网关二进制（docker create + docker cp /usr/bin/caddy）..."
    cid="$(docker create "$GATEWAY_IMAGE")" || die "docker create 失败: $GATEWAY_IMAGE"
    if ! docker cp "$cid:/usr/bin/caddy" "$gdir/caddy"; then
      docker rm -f "$cid" >/dev/null 2>&1 || true
      die "docker cp 抽取 /usr/bin/caddy 失败: $GATEWAY_IMAGE"
    fi
    docker rm -f "$cid" >/dev/null
    cid="$(docker create "$PCAPD_IMAGE")" || die "docker create 失败: $PCAPD_IMAGE"
    if ! docker cp "$cid:/usr/local/bin/jiuzhang-pcapd" "$gdir/jiuzhang-pcapd"; then
      docker rm -f "$cid" >/dev/null 2>&1 || true
      die "docker cp 抽取 pcapd 失败: $PCAPD_IMAGE"
    fi
    docker rm -f "$cid" >/dev/null
    docker run --rm --entrypoint /usr/bin/caddy "$GATEWAY_IMAGE" version > "$gdir/VERSION" \
      || die "读取网关版本失败: $GATEWAY_IMAGE"
  else
    log_warn "--skip-images：裸机包不含 caddy 二进制（仅占位），不可用于实际安装"
    printf 'skipped by --skip-images\n' > "$gdir/VERSION"
  fi
  # delivery_mode 是安装端区分正式包与开发自验包的显式边界；一并纳入包内摘要。
  printf '%s\n' "$DELIVERY_MODE" > "$gdir/delivery_mode"
  runtime_copy "$REPO_ROOT/gateway/rules" "$gdir/rules"
  cp "$REPO_ROOT/gateway/configs/blockpage.html" "$gdir/blockpage.html"
  cp "$REPO_ROOT/deployment/baremetal/Caddyfile.bootstrap" "$gdir/Caddyfile.bootstrap"
  cp "$REPO_ROOT/deployment/systemd/jiuzhang-gateway.service" "$gdir/jiuzhang-gateway.service"
  cp "$REPO_ROOT/deployment/systemd/jiuzhang-pcapd.service" "$gdir/jiuzhang-pcapd.service"
  cp "$REPO_ROOT/ops/install/install-gateway-baremetal.sh" "$gdir/"
  cp "$REPO_ROOT/ops/install/install-pcapd.sh" "$gdir/"
  cp "$REPO_ROOT/ops/install/pcap.sh" "$gdir/"
  mkdir -p "$gdir/lib"
  cp "$REPO_ROOT/ops/lib/common.sh" "$REPO_ROOT/ops/lib/signing.sh" "$gdir/lib/"
  cp "$REPO_ROOT/ops/install/verify-gateway-baremetal.sh" "$gdir/"
  if [[ "$SKIP_IMAGES" == "true" ]]; then
    (cd "$gdir" && sha256_of delivery_mode VERSION > sha256sums)
  else
    (cd "$gdir" && sha256_of caddy jiuzhang-pcapd delivery_mode VERSION > sha256sums)
  fi
  COPYFILE_DISABLE=1 tar --no-xattrs -czf "$out" -C "$gtmp" "gateway-linux-${ARCH}"
  gateway_scan_report="$gtmp/gateway-scan.json"
  python3 "$SCANNER_FILE" \
    --root "$out" \
    --output "$gateway_scan_report" \
    --product "$PRODUCT" \
    --version "$VERSION" \
    --platform "$ARCH" \
    || die "裸机网关包扫描失败，拒绝签名"
  gateway_scanned_sha256="$(jq -r '.input.sha256 // empty' "$gateway_scan_report")"
  gateway_actual_sha256="$(sha256_of "$out" | awk '{print $1}')"
  [[ -n "$gateway_scanned_sha256" && "$gateway_scanned_sha256" == "$gateway_actual_sha256" ]] \
    || die "裸机网关包扫描摘要不匹配，拒绝签名"
  rm -rf "$gtmp"
  # 旁车整包哈希（与包同目录随附）：安装端 install-gateway-baremetal.sh 先校验后解压。
  (cd "$(dirname "$out")" && sha256_of "$(basename "$out")" > "$(basename "$out").sha256")
  # Ed25519 签名旁车（真实性锚定，安装端验签通过后才解压；.sha256 保留为纵深）
  if [[ "$PKG_SIGNED" == "true" ]]; then
    ed25519_sign_file "$SIGNING_KEY" "$out" "${out}.sig" \
      || die "裸机网关包签名失败: $out"
    log_info "裸机网关包已生成: ${out}（旁车 $(basename "$out").sha256 / .sig，已签名）"
  else
    log_warn "裸机网关包未签名（未配置 WDSP_SIGNING_KEY）: ${out}"
    log_info "裸机网关包已生成: ${out}（旁车 $(basename "$out").sha256，未签名）"
  fi
}
build_gateway_baremetal_pkg "$pkg_dir/gateway-linux-${ARCH}.tar.gz"

# ---------- 2. 生产 compose 模板（注入产品线环境变量） ----------
cat > "$pkg_dir/docker-compose.yml" <<EOF
# ${PRODUCT_NAME} 生产编排模板（离线交付包 v${VERSION} / ${PRODUCT} / ${ARCH}）
# 所有口令经 .env 注入（参考 .env.example；禁止在本文档写入口令）
name: jiuzhang-${PRODUCT}

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
      # 生产 gateway 使用 host 网络，guard 配置发布须连接宿主机发布的 Valkey 端口。
      GATEWAY_VALKEY_ADDR: 127.0.0.1:\${VALKEY_PORT:-6379}
      GATEWAY_NODE_NAME: \${GATEWAY_NODE_NAME:-gateway-poc-01}
      # API 容器经宿主网关访问 host 网络 Caddy；只给主机，端口按每个站点配置跟随。
      GATEWAY_PUBLISH_SMOKE_ADDR: \${GATEWAY_PUBLISH_SMOKE_ADDR:-host.docker.internal}
      VALKEY_PASSWORD: \${VALKEY_PASSWORD:?VALKEY_PASSWORD is required}
      COOKIE_SECURE: \${COOKIE_SECURE:-true}
      INITIAL_ADMIN_USERNAME: \${INITIAL_ADMIN_USERNAME:-jiuzhang_admin}
      INITIAL_ADMIN_PASSWORD: \${INITIAL_ADMIN_PASSWORD:-}
      JIUZHANG_MASTER_KEY: \${JIUZHANG_MASTER_KEY:?JIUZHANG_MASTER_KEY is required}
      # 离线授权：验签公钥随正式构建内嵌；这里只配置宿主机指纹文件路径（卷挂载见下）
      LICENSE_HOST_FINGERPRINT_FILE: \${LICENSE_HOST_FINGERPRINT_FILE:-/app/runtime/license/host_fingerprint}
      CADDY_ADMIN_SOCKET: /var/run/caddy/admin.sock
      GATEWAY_DATA_DIR: /app/runtime
      MIGRATIONS_DIR: /app/migrations
      # 产品线（由打包写入，安装时可被 .env 覆盖）
      PRODUCT_EDITION: \${PRODUCT_EDITION:-${PRODUCT}}
      API_DYNAMIC_PROTECTION_ENABLED: \${API_DYNAMIC_PROTECTION_ENABLED:-${API_DYNAMIC_DEFAULT}}
      WEB_WAF_ENABLED: \${WEB_WAF_ENABLED:-${WEB_WAF_DEFAULT}}
      API_PROTECTION_MODE: \${API_PROTECTION_MODE:-OBSERVE}
      # APM 业务性能监控（可选，默认关闭）：true 后 /api/v1/apm/* 生效，false 时统一 503 降级；
      # 数据面需另行启用包内 docker-compose.apm.yml（独立 compose 项目，启用步骤见该文件头注释）
      APM_ENABLED: \${APM_ENABLED:-false}
      APM_CLICKHOUSE_DSN: \${APM_CLICKHOUSE_DSN:-}
      # 日志采集（逐项对照 deployment/docker-compose.stage5.yml）：api 经只读卷
      # /var/log/caddy-audit 采集网关写入 /var/log/caddy 的日志；缺失时采集器回退到
      # 开发默认值 runtime/logs/*（容器内不存在），事件采集链路静默中断，必须显式下发。
      # GATEWAY_* 为下发给网关侧的日志输出路径。
      WAF_AUDIT_LOG: /var/log/caddy-audit/coraza-audit.log
      WAF_GUARD_EVENTS_LOG: /var/log/caddy-audit/guard-events.log
      GATEWAY_GUARD_EVENTS_LOG: /var/log/caddy/guard-events.log
      WAF_NODE_IFACES_LOG: /var/log/caddy-audit/node-interfaces.jsonl
      WAF_ACCESS_LOG: /var/log/caddy-audit/access.log
      WAF_API_EVENTS_LOG: /var/log/caddy-audit/api-runtime-events.log
      GATEWAY_API_EVENTS_LOG: /var/log/caddy/api-runtime-events.log
      WAF_SITE_DISCOVERY_LOG: /var/log/caddy-audit/site-discovery.jsonl
      WAF_ACCESS_FULL_LOG: /var/log/caddy-audit/access-full.jsonl
      GATEWAY_ACCESS_FULL_LOG: /var/log/caddy/access-full.jsonl
      # 采集器批量/周期 flush 旋钮（崩溃重扫量有界；默认值与 server config.go 一致，可经 .env 覆盖）
      WAF_COLLECTOR_FLUSH_BATCH: \${WAF_COLLECTOR_FLUSH_BATCH:-2000}
      WAF_COLLECTOR_FLUSH_INTERVAL: \${WAF_COLLECTOR_FLUSH_INTERVAL:-2s}
      # 请求PCAP默认关闭；安装器或系统管理员显式启用时才配置采集与存储。
      REQUEST_PCAP_CAPTURE_ENABLED: \${REQUEST_PCAP_CAPTURE_ENABLED:-}
      REQUEST_PCAP_HOT_DIR: \${PCAP_SERVER_HOT_DIR:-}
      REQUEST_PCAP_WARM_DIR: \${PCAP_SERVER_WARM_DIR:-}
      REQUEST_PCAP_KEY_FILE: \${PCAP_SERVER_KEY_FILE:-}
      REQUEST_PCAP_PUBLIC_DIR: /app/runtime/pcap-public
      REQUEST_PCAP_RETENTION: \${REQUEST_PCAP_RETENTION:-24h}
      REQUEST_PCAP_HOT_AGE: \${REQUEST_PCAP_HOT_AGE:-15m}
      REQUEST_PCAP_GRANT_TTL: \${REQUEST_PCAP_GRANT_TTL:-24h}
      REQUEST_PCAP_MIGRATE_BPS: \${REQUEST_PCAP_MIGRATE_BPS:-33554432}
      REQUEST_PCAP_MIN_FREE_PERCENT: \${REQUEST_PCAP_MIN_FREE_PERCENT:-10}
      # 容器运维通道：经共享卷上的 Unix Socket 访问 containerops sidecar（API 不直接持有 docker.sock）
      CONTAINEROPS_SOCKET: /app/runtime/containerops/containerops.sock
    extra_hosts:
      - "host.docker.internal:host-gateway"
    ports:
      - "127.0.0.1:\${API_PORT:-18081}:8080"
    volumes:
      - gateway-admin:/var/run/caddy
      - gateway-logs:/var/log/caddy-audit:ro
      - runtime-data:/app/runtime
      # 系统控制通道：API 写入的 hostctl 标志必须对宿主机 path 单元可见；
      # 在 runtime-data 挂载点下叠加嵌套 bind，保留其余 runtime 命名卷数据。
      - ./runtime/hostctl:/app/runtime/hostctl
      # 容器运维通道：与 containerops sidecar 共享的 Unix Socket 卷（API 仅见 socket 文件，
      # 不挂载 /var/run/docker.sock；嵌套在 runtime-data 挂载点之下）
      - containerops-data:/app/runtime/containerops
      # 离线授权：宿主机指纹文件（安装期 ops/install/install.sh 采集写入包根 runtime/license/）。
      # 取舍说明：命名卷 runtime-data 由 Docker 管理、无法直接承载安装目录下的宿主机文件，
      # 故在其挂载点 /app/runtime 之下叠加一个相对包根的 bind 只读挂载（Docker 支持嵌套挂载）；
      # 指纹文件不进命名卷，升级/换卷时不丢失，也避免改动既有 runtime-data 数据面。
      - ./runtime/license:/app/runtime/license:ro
      # 私有证据密钥仅API可见；pcapd只见独立的只读公钥目录。
      - ./runtime/pcap-private:/app/runtime/pcap-private
      - ./runtime/pcap-public:/app/runtime/pcap-public
      - \${REQUEST_PCAP_HOT_DIR:-./runtime/pcap-hot}:/app/runtime/pcap-hot
      - \${REQUEST_PCAP_WARM_DIR:-./runtime/pcap-warm}:/app/runtime/pcap-warm
    depends_on:
      postgres: {condition: service_healthy}
      valkey:   {condition: service_healthy}
      gateway:  {condition: service_started}
      containerops: {condition: service_started}
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://127.0.0.1:8080/api/v1/health"]
      interval: 15s
      timeout: 5s
      retries: 5
      start_period: 20s
    security_opt: [no-new-privileges:true]
    networks: [jiuzhang-internal]

  # 管理前端：Caddy 托管 SPA 并反代 /api 到 api 服务（web/Caddyfile.docker）
  web:
    image: $WEB_IMAGE
    container_name: jiuzhang-web
    restart: unless-stopped
    # 管理控制台入口；默认监听全部接口供管理员从内网工作站访问，
    # 如需仅本机访问改为 "127.0.0.1:\${WEB_PORT:-8080}:8080"
    # HTTPS 8443：证书由安装期 ops/install/console-cert.sh 生成（自签、100 年有效期），
    # 经只读卷挂载；证书缺失时 web 入口自动退化为仅 HTTP（docker-entrypoint.web.sh）
    ports:
      - "\${WEB_PORT:-8080}:8080"
      - "\${WEB_HTTPS_PORT:-8443}:8443"
    volumes:
      - ./runtime/certificates:/etc/caddy/console-certs:ro
    depends_on:
      api: {condition: service_healthy}
    security_opt: [no-new-privileges:true]
    networks: [jiuzhang-internal]

  gateway:
    image: $GATEWAY_IMAGE
    container_name: jiuzhang-gateway
    restart: unless-stopped
    user: "0:0"
    entrypoint: ["/usr/local/bin/wdsp-gateway-bind"]
    environment:
      HOME: /var/lib/caddy
      # autosave 落点持久化：配合 --resume，容器重建后自动恢复最近一次发布配置
      XDG_CONFIG_HOME: /config
      # Caddy 存储（实例 ID、证书缓存、锁文件）持久化
      XDG_DATA_HOME: /data
    command: ["run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile", "--resume"]
    # 生产网关直接监听宿主机端口，避免业务站点端口再做容器端口换算。
    network_mode: host
    volumes:
      - gateway-logs:/var/log/caddy
      - gateway-admin:/var/run/caddy
      # autosave 与 Caddy 存储持久化（对应 XDG_CONFIG_HOME=/config、XDG_DATA_HOME=/data）
      - gateway-config:/config
      - gateway-config:/data
      # 修复既有缺陷（设计文档「二、现状与关键事实」）：原生产模板缺少
      # rules/Caddyfile/blockpage 挂载，参照 deployment/docker-compose.stage5.yml 补齐。
      # 离线生产包统一从 bootstrap Caddyfile 启动，配置由 API 经 Unix Socket 发布。
      - ./gateway/Caddyfile:/etc/caddy/Caddyfile:ro
      - ./gateway/blockpage.html:/srv/jiuzhang/blockpage.html:ro
      - ./gateway/rules:/etc/caddy/rules:ro
    security_opt: [no-new-privileges:true]
    cap_drop: [ALL]
    cap_add: [NET_BIND_SERVICE, SETUID, SETGID, SETPCAP]

  # 日志轮转 sidecar：对网关日志卷中常驻 append 写入的日志做 copytruncate 轮转
  # （coraza-audit.log / api-runtime-events.log / guard-events.log / access-full.jsonl /
  #  site-discovery.jsonl；access.log 与 caddy.log 由 Caddy 自身轮转，不在此处理）
  netmgrd:
    image: $NETMGRD_IMAGE
    restart: unless-stopped
    network_mode: service:gateway
    cap_add: [NET_RAW, NET_ADMIN]
    environment:
      NODE_NAME: \${GATEWAY_NODE_NAME:-gateway-poc-01}
    volumes:
      - gateway-admin:/var/run/caddy
    depends_on:
      gateway: {condition: service_started}
    security_opt: [no-new-privileges:true]

  logrotator:
    image: $LOGROTATOR_IMAGE
    container_name: jiuzhang-logrotator
    restart: unless-stopped
    volumes:
      # 读写挂载网关日志卷（轮转需写入 .N.gz 并截断原文件）
      - gateway-logs:/var/log/caddy
    depends_on:
      gateway: {condition: service_started}
    security_opt: [no-new-privileges:true]
    networks: [jiuzhang-internal]

  # 请求PCAP为显式启用的独立组件；默认profile不会启动持续抓包。
  pcapd:
    image: $PCAPD_IMAGE
    container_name: jiuzhang-pcapd
    restart: unless-stopped
    profiles: ["request-pcap"]
    network_mode: host
    # 仅保留NET_RAW；启动后将文件系统身份收敛到证据目录UID 1000。
    user: "0:0"
    environment:
      GATEWAY_NODE_NAME: \${GATEWAY_NODE_NAME:-gateway-poc-01}
      REQUEST_PCAP_IFACE: \${REQUEST_PCAP_IFACE:-}
      REQUEST_PCAP_PORTS: \${REQUEST_PCAP_PORTS:-}
      REQUEST_PCAP_POLICY_VERSION: \${REQUEST_PCAP_POLICY_VERSION:-installer-approved-v1}
    command: ["--promiscuous=false"]
    volumes:
      - \${REQUEST_PCAP_HOT_DIR:-./runtime/pcap-hot}:/var/lib/jiuzhang/pcap-hot
      - ./runtime/pcap-public:/etc/jiuzhang:ro
    read_only: true
    cap_drop: [ALL]
    cap_add: [NET_RAW]
    security_opt: [no-new-privileges:true]
    tmpfs: ["/tmp:size=8m,mode=1777"]
    depends_on:
      api: {condition: service_healthy}

  # 容器运维 sidecar（containeropsd）：全栈唯一挂载 /var/run/docker.sock 的组件。
  # API 容器只挂载共享 Unix Socket 卷（containerops-data）发起受控运维请求；
  # sidecar 校验 compose 项目标签与服务白名单后才触碰 Docker API。
  # 不暴露任何 TCP 端口（network_mode: none）。设计与安全边界见 docs/CONTAINER_OPS_DESIGN.md。
  containerops:
    image: $CONTAINEROPS_IMAGE
    container_name: jiuzhang-containerops
    restart: unless-stopped
    environment:
      CONTAINEROPS_SOCKET: /run/containerops/containerops.sock
      DOCKER_HOST: unix:///var/run/docker.sock
      # 仅允许运维本 compose 项目内、且在白名单中的服务（双重校验，fail-closed）
      CONTAINEROPS_PROJECT: jiuzhang-${PRODUCT}
      CONTAINEROPS_ALLOWED_SERVICES: api,web,gateway,postgres,valkey,logrotator,netmgrd,pcapd
    volumes:
      # 全栈唯一 docker.sock 挂载点（安全底线；严禁复制到 api 或其他服务）
      - /var/run/docker.sock:/var/run/docker.sock
      - containerops-data:/run/containerops
    # docker.sock 属主组 gid 因宿主机而异，经 group_add 注入；
    # 安装期用 ops/install/prepare-containerops.sh 探测写入 .env（CONTAINEROPS_DOCKER_GID）。
    group_add: ["\${CONTAINEROPS_DOCKER_GID:-0}"]
    # 无任何 TCP 面：不接入 bridge 网络（请求只经 Unix Socket 卷进出）
    network_mode: none
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    tmpfs: ["/tmp:size=8m,mode=1777"]

volumes:
  postgres-data: {driver: local}
  valkey-data: {driver: local}
  gateway-admin: {driver: local}
  gateway-logs: {driver: local}
  gateway-config: {driver: local}
  runtime-data: {driver: local}
  containerops-data: {driver: local}

networks:
  jiuzhang-internal: {driver: bridge}
EOF

# ---------- 3. 配置模板 / ops / licenses / SBOM ----------
# 基于仓库 .env.example 生成产品线专用模板
{
  if [[ -f "$REPO_ROOT/.env.example" ]]; then
    # 去掉原 PRODUCT_* / APM_* 行后追加本包固定默认（避免键重复）
    grep -v -E '^(PRODUCT_EDITION|API_DYNAMIC_PROTECTION_ENABLED|WEB_WAF_ENABLED|API_PROTECTION_MODE|APM_ENABLED|APM_CLICKHOUSE_DSN)=' \
      "$REPO_ROOT/.env.example" || true
  fi
  cat <<EOF

# ---------- 产品线（本包固定默认：${PRODUCT}）----------
# waf=纯WAF；wdsp=WAF+API动态防护；api=API安全系统
PRODUCT_EDITION=${PRODUCT}
# 管理控制台 HTTPS 入口端口（容器内固定 8443；证书由安装期生成，
# 见 runtime/certificates/console.crt，自签、100 年有效期）
WEB_HTTPS_PORT=8443
# API 动态防护总开关（waf 包须为 false；wdsp/api 默认 true）
API_DYNAMIC_PROTECTION_ENABLED=${API_DYNAMIC_DEFAULT}
# Web 防护专属交付（策略/CC/访问控制菜单；api 包默认 false）
WEB_WAF_ENABLED=${WEB_WAF_DEFAULT}
# 网关侧 API 防护模式：OFF | OBSERVE | PROTECT
API_PROTECTION_MODE=OBSERVE

# ---------- APM 业务性能监控（可选能力，默认关闭）----------
# 管理面总开关：true 后 /api/v1/apm/* 生效；false（默认）时统一 503 降级
APM_ENABLED=false
# ClickHouse 查询连接串（trace 检索；空 = 未接入，检索降级为空数据而非报错）
APM_CLICKHOUSE_DSN=
# 数据面口令：仅启用包内 docker-compose.apm.yml（独立 compose 项目，--profile central）时需要；
# 安装时自行生成强口令填入 .env，禁止提交回仓库；mTLS 证书按 docs/APM_DATA_PLANE_DEPLOYMENT.md 放入 apm/pki/
CLICKHOUSE_ADMIN_PASSWORD=
CLICKHOUSE_APM_WRITER_PASSWORD=

# ---------- 容器运维通道（containerops sidecar）----------
# sidecar 访问 /var/run/docker.sock 所需的属组 gid（compose group_add 注入）；
# 安装期执行 bash ops/install/prepare-containerops.sh -e .env 自动探测写入，
# 缺省 0 适配 Docker Desktop / root-owned socket 场景
CONTAINEROPS_DOCKER_GID=0
EOF
} > "$pkg_dir/.env.example"

mkdir -p "$pkg_dir/ops"
allowlist_version=""
declare -a ops_allowlist=()
while IFS= read -r allowlist_line || [[ -n "$allowlist_line" ]]; do
  allowlist_line="${allowlist_line%%$'\r'}"
  case "$allowlist_line" in
    ''|'#'*) continue ;;
    version=*)
      [[ -z "$allowlist_version" ]] || die "allowlist 重复 version 声明"
      allowlist_version="${allowlist_line#version=}"
      ;;
    file=*)
      rel="${allowlist_line#file=}"
      [[ -n "$rel" && "$rel" != /* && "$rel" != *'..'* && "$rel" != *'*'* ]] \
        || die "allowlist 含非法路径: $rel"
      ops_allowlist+=("$rel")
      ;;
    *) die "allowlist 含未知语法: $allowlist_line" ;;
  esac
done < "$ALLOWLIST_FILE"
[[ "$allowlist_version" == "1" ]] || die "不支持的 allowlist 版本: ${allowlist_version:-<none>}"
for rel in "${ops_allowlist[@]}"; do
  src="$REPO_ROOT/ops/$rel"
  [[ -f "$src" && ! -L "$src" ]] || die "allowlist 文件不存在或为符号链接: ops/$rel"
  mkdir -p "$pkg_dir/ops/$(dirname "$rel")"
  cp -p "$src" "$pkg_dir/ops/$rel"
done
allowlist_sha256="$(sha256_of "$ALLOWLIST_FILE" | awk '{print $1}')"
# hostctl helper 在纯离线包内也需要这两份模板；与 allowlist 中的宿主脚本一并交付。
mkdir -p "$pkg_dir/deployment/systemd"
cp -p "$REPO_ROOT/deployment/systemd/jiuzhang-hostctl.path" \
  "$REPO_ROOT/deployment/systemd/jiuzhang-hostctl.service" \
  "$pkg_dir/deployment/systemd/"
cp -R "$REPO_ROOT/licenses/." "$pkg_dir/licenses/"
if [[ "$RUNTIME_ONLY" == "true" ]]; then
  # 保留许可归属信息，但不把 Markdown 文档作为交付内容。
  while IFS= read -r -d '' notice; do
    mv "$notice" "${notice%.md}.NOTICE"
  done < <(find "$pkg_dir/licenses" -type f -name '*.md' -print0)
fi
if [[ -n "${WDSP_AGENT_BINARY:-}" ]]; then
  [[ -f "$WDSP_AGENT_BINARY" && ! -L "$WDSP_AGENT_BINARY" ]] || die "Agent 二进制不存在或为符号链接"
  mkdir -p "$pkg_dir/agents"
  cp "$WDSP_AGENT_BINARY" "$pkg_dir/agents/wdsp-agent"
  chmod 0755 "$pkg_dir/agents/wdsp-agent"
fi
# 生产 compose 模板 gateway 服务的 ./gateway/* 挂载源（rules/bootstrap Caddyfile/blockpage）
mkdir -p "$pkg_dir/gateway"
cp "$REPO_ROOT/deployment/baremetal/Caddyfile.bootstrap" "$pkg_dir/gateway/Caddyfile"
cp "$REPO_ROOT/gateway/configs/blockpage.html" "$pkg_dir/gateway/blockpage.html"
runtime_copy "$REPO_ROOT/gateway/rules" "$pkg_dir/gateway/rules"
# APM 数据面（可选能力，默认关闭；启用见 .env.example APM 节与 docker-compose.apm.yml 头注释）：
# 独立 compose 项目（profile central/local），镜像已随 images/ 预置；apm/pki 为 mTLS 证书占位目录，
# 由部署侧私有 CA 签发后放入（docs/APM_DATA_PLANE_DEPLOYMENT.md），仓库与包内均不含真实证书/口令。
sed -e "s|image: clickhouse/clickhouse-server:.*|image: $CLICKHOUSE_IMAGE|" \
    -e "s|image: otel/opentelemetry-collector-contrib:.*|image: $OTEL_COLLECTOR_IMAGE|" \
    "$REPO_ROOT/deployment/docker-compose.apm.yml" > "$pkg_dir/docker-compose.apm.yml"
mkdir -p "$pkg_dir/apm"
runtime_copy "$REPO_ROOT/deployment/apm/clickhouse" "$pkg_dir/apm/clickhouse"
runtime_copy "$REPO_ROOT/deployment/apm/collector" "$pkg_dir/apm/collector"
mkdir -p "$pkg_dir/apm/pki"
if [[ "$RUNTIME_ONLY" == "true" ]]; then
  cp "$REPO_ROOT/THIRD_PARTY_NOTICES.md" "$pkg_dir/licenses/THIRD_PARTY_NOTICES"
else
mkdir -p "$pkg_dir/docs"
for f in SBOM.spdx.json SBOM.cyclonedx.json; do
  if [[ -f "$REPO_ROOT/docs/$f" ]]; then
    cp "$REPO_ROOT/docs/$f" "$pkg_dir/docs/$f"
  else
    log_warn "docs/$f 不存在（建议先运行 scripts/generate-sbom.sh）"
  fi
done
cp "$REPO_ROOT/THIRD_PARTY_NOTICES.md" "$pkg_dir/docs/THIRD_PARTY_NOTICES.md"
[[ -f "$REPO_ROOT/docs/DEPENDENCIES.md" ]] && cp "$REPO_ROOT/docs/DEPENDENCIES.md" "$pkg_dir/docs/"
[[ -f "$REPO_ROOT/docs/BRANCHING_AND_PRODUCT_LINES.md" ]] && cp "$REPO_ROOT/docs/BRANCHING_AND_PRODUCT_LINES.md" "$pkg_dir/docs/"
# APM 数据面部署手册（可选能力的启用指引，manifest apm.enable 与 .env.example 均引用本文档）
[[ -f "$REPO_ROOT/docs/APM_DATA_PLANE_DEPLOYMENT.md" ]] && cp "$REPO_ROOT/docs/APM_DATA_PLANE_DEPLOYMENT.md" "$pkg_dir/docs/"
fi

# 产品线说明
cat > "$pkg_dir/PRODUCT.txt" <<EOF
product=${PRODUCT}
product_name=${PRODUCT_NAME}
version=${VERSION}
arch=${ARCH}
api_dynamic_protection=${API_DYNAMIC_DEFAULT}
web_waf_enabled=${WEB_WAF_DEFAULT}
# APM 业务性能监控为可选能力：管理面 APM_ENABLED 默认 false（503 降级）；
# 数据面镜像已预置 images/，启用方式见 docker-compose.apm.yml 头注释与 .env.example APM 节
apm_enabled_default=false
EOF

# ---------- 4. 安全检查 ----------
if find "$pkg_dir" -name '.env' -print -quit | grep -q .; then
  die "安全检查失败：打包目录中混入 .env"
fi

# ---------- 5. manifest.json ----------
log_info "生成 manifest.json ..."
files_json="$(
  cd "$pkg_dir"
  find . -type f ! -name 'manifest.json' | LC_ALL=C sort | while IFS= read -r f; do
    rel="${f#./}"
    hash="$(sha256_of "$rel" | awk '{print $1}')"
    size="$(stat -f%z "$rel" 2>/dev/null || stat -c%s "$rel")"
    jq -n --arg path "$rel" --arg sha256 "$hash" --argjson size "$size" \
      '{path:$path, sha256:$sha256, size:$size}'
  done | jq -s '.'
)"
images_json="$(printf '%s\n' "${image_digests[@]}" | jq -s '.')"
total_hash="$(printf '%s' "$files_json" | sha256_of | awk '{print $1}')"
jq -n \
  --arg product "$PRODUCT_NAME" \
  --arg edition "$PRODUCT" \
  --arg version "$VERSION" \
  --arg arch "$ARCH" \
  --arg api_dynamic "$API_DYNAMIC_DEFAULT" \
  --arg web_waf "$WEB_WAF_DEFAULT" \
  --arg delivery_mode "$DELIVERY_MODE" \
  --arg built_at "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
  --arg ch_image "$CLICKHOUSE_IMAGE" \
  --arg otel_image "$OTEL_COLLECTOR_IMAGE" \
  --argjson signed "$PKG_SIGNED" \
  --argjson images "$images_json" \
  --argjson files "$files_json" \
  --arg files_hash "$total_hash" \
  --arg allowlist_version "$allowlist_version" \
  --arg allowlist_sha256 "$allowlist_sha256" \
  --arg release_id "$RELEASE_ID" \
  --arg build_commit "$BUILD_COMMIT" \
  --arg delivery_id "$DELIVERY_ID" \
  --arg signature_algorithm "Ed25519" \
  --arg signature_key_id "$RELEASE_KEY_ID" \
  '{product:$product, edition:$edition, version:$version, arch:$arch,
    delivery_mode:$delivery_mode,
    signed:$signed,
    api_dynamic_protection:($api_dynamic=="true"),
    web_waf_enabled:($web_waf=="true"),
    built_at:$built_at, images:$images, files:$files, files_manifest_sha256:$files_hash,
    delivery_allowlist:{version:($allowlist_version|tonumber), sha256:$allowlist_sha256,
                        path:"ops/offline-package/allowlist.v1"},
    traceability:{release_id:$release_id, product_line:$edition, build_commit:$build_commit,
                  delivery_id:$delivery_id, policy_version:"WDSP_IP-01/IP-02.v1",
                  protection_form:"STANDARD_OFFLINE", hardware_requirements:[],
                  digest_binding:{artifact_digest_scope:"external-final-archive",
                                  scan_report_digest_scope:"external-scan-report"},
                  signature:{algorithm:$signature_algorithm, key_id:$signature_key_id,
                             signed:$signed}},
    security_scan:{build_time_only:true, scanner_policy:"WDSP_IP-01/IP-02.v1"},
    upgrade_executor:{included:true,
                      auto_install:true,
                      installer:"ops/upgrade/install-executor.sh",
                      service:"jiuzhang-upgrade-executor.service",
                      path_unit:"jiuzhang-upgrade-executor.path"},
    apm:{enabled_default:false,
         compose_file:"docker-compose.apm.yml",
         images:[$ch_image, $otel_image],
         enable:"管理面 .env 设 APM_ENABLED=true（默认 false，关闭时 /api/v1/apm/* 503 降级）；数据面 docker compose -f docker-compose.apm.yml --profile central up -d（先填 CLICKHOUSE_* 口令并配置 apm/pki mTLS 证书，见 docs/APM_DATA_PLANE_DEPLOYMENT.md）"}}' \
  > "$pkg_dir/manifest.json"

# ---------- 6. allowlist / 内容扫描（签名之前，失败即拒绝） ----------
package_scan_report="$work/package-scan.json"
if ! python3 "$SCANNER_FILE" \
  --root "$pkg_dir" \
  --allowlist "$ALLOWLIST_FILE" \
  --output "$package_scan_report" \
  --product "$PRODUCT" \
  --version "$VERSION" \
  --platform "$ARCH" \
  --max-member-bytes "$PACKAGE_SCAN_MAX_MEMBER_BYTES" \
  --max-total-bytes "$PACKAGE_SCAN_MAX_TOTAL_BYTES" \
  --timeout-seconds "$PACKAGE_SCAN_TIMEOUT_SECONDS"; then
  # The package directory is removed by the exit trap. Preserve only the
  # scanner's metadata report so a rejected build remains diagnosable without
  # retaining its images, credentials, or other package payloads.
  rejection_report="$OUT_DIR/${PKG_BASENAME}.package-scan.reject.json"
  [[ -f "$package_scan_report" ]] \
    || die "离线包扫描失败且未生成诊断报告，拒绝继续打包"
  cp "$package_scan_report" "$rejection_report" \
    || die "离线包扫描失败且无法保留诊断报告，拒绝继续打包"
  die "离线包 allowlist/内容扫描失败，拒绝继续打包；诊断报告：$rejection_report"
fi
jq -e --arg allowlist_sha256 "$allowlist_sha256" \
  '.result == "PASS" and .scope.allowlist == "allowlist.v1" and
   .scope.allowlist_sha256 == $allowlist_sha256 and
   (.manifest.sha256 | type) == "string" and
   (.manifest.files_manifest_sha256 | type) == "string"' \
  "$package_scan_report" >/dev/null \
  || die "离线包扫描报告未通过 allowlist 门禁"
package_manifest_sha256="$(jq -r '.manifest.sha256 // empty' "$package_scan_report")"
package_files_manifest_sha256="$(jq -r '.manifest.files_manifest_sha256 // empty' "$package_scan_report")"

# ---------- 7. 打包 ----------
out="$OUT_DIR/${PKG_BASENAME}.tar.gz"
COPYFILE_DISABLE=1 tar --no-xattrs -czf "$out" -C "$work" "$PKG_BASENAME"

# 对最终归档再次递归扫描，覆盖镜像层/历史层和嵌套归档；报告中的摘要
# 是签名对象的摘要，任何扫描后修改都会在签名/交付前被拒绝。
scan_report="$OUT_DIR/${PKG_BASENAME}.scan.json"
python3 "$SCANNER_FILE" \
  --root "$out" \
  --allowlist "$ALLOWLIST_FILE" \
  --output "$scan_report" \
  --product "$PRODUCT" \
  --version "$VERSION" \
  --platform "$ARCH" \
  --max-member-bytes "$PACKAGE_SCAN_MAX_MEMBER_BYTES" \
  --max-total-bytes "$PACKAGE_SCAN_MAX_TOTAL_BYTES" \
  --timeout-seconds "$PACKAGE_SCAN_TIMEOUT_SECONDS" \
  || die "最终离线归档扫描失败，拒绝签名/交付"
jq -e --arg allowlist_sha256 "$allowlist_sha256" \
  --arg package_manifest_sha256 "$package_manifest_sha256" \
  --arg package_files_manifest_sha256 "$package_files_manifest_sha256" \
  '.result == "PASS" and .scope.allowlist == "allowlist.v1" and
   .scope.allowlist_sha256 == $allowlist_sha256 and
   .manifest.sha256 == $package_manifest_sha256 and
   .manifest.files_manifest_sha256 == $package_files_manifest_sha256' \
  "$scan_report" >/dev/null \
  || die "最终扫描报告与 allowlist/manifest 绑定不一致，拒绝签名/交付"
scanned_sha256="$(jq -r '.input.sha256 // empty' "$scan_report")"
actual_sha256="$(sha256_of "$out" | awk '{print $1}')"
[[ -n "$scanned_sha256" && "$scanned_sha256" == "$actual_sha256" ]] \
  || die "扫描后产物摘要不匹配，拒绝签名/交付"

# 旁车整包哈希（与包同目录随附交付）：安装端 ops/install/install.sh 安装前校验（纵深层）。
(cd "$OUT_DIR" && sha256_of "${PKG_BASENAME}.tar.gz" > "${PKG_BASENAME}.tar.gz.sha256")
# Ed25519 签名旁车（真实性锚定）：安装端验签通过后才继续；未配置私钥时醒目告警。
if [[ "$PKG_SIGNED" == "true" ]]; then
  ed25519_sign_file "$SIGNING_KEY" "$out" "${out}.sig" \
    || die "离线交付包签名失败: $out"
else
  log_warn "==================== 安全警告：离线交付包未签名 ===================="
  log_warn "  ${PKG_BASENAME}.tar.gz 无旁车 .sig，安装端默认拒绝安装；"
  log_warn "  正式交付请配置 WDSP_SIGNING_KEY 重新构建。"
  log_warn "=================================================================="
fi
# 签名函数不应改变输入；最后一次复核把签名对象、旁车摘要和扫描报告绑定。
final_sha256="$(sha256_of "$out" | awk '{print $1}')"
[[ "$final_sha256" == "$scanned_sha256" ]] \
  || die "签名/交付前检测到产物被修改，拒绝交付"
scan_report_sha256="$(sha256_of "$scan_report" | awk '{print $1}')"
traceability_report="$OUT_DIR/${PKG_BASENAME}.traceability.json"
jq -n \
  --arg release_id "$RELEASE_ID" \
  --arg product_line "$PRODUCT" \
  --arg version "$VERSION" \
  --arg arch "$ARCH" \
  --arg build_commit "$BUILD_COMMIT" \
  --arg artifact_digest "$final_sha256" \
  --arg scan_report_digest "$scan_report_sha256" \
  --arg manifest_sha256 "$package_manifest_sha256" \
  --arg files_manifest_sha256 "$package_files_manifest_sha256" \
  --arg policy_version "WDSP_IP-01/IP-02.v1" \
  --arg delivery_id "$DELIVERY_ID" \
  --arg signature_algorithm "Ed25519" \
  --arg signature_key_id "$RELEASE_KEY_ID" \
  --arg protection_form "STANDARD_OFFLINE" \
  --arg artifact "$(basename "$out")" \
  --arg scan_report "$(basename "$scan_report")" \
  --argjson hardware_requirements '[]' \
  --argjson signed "$PKG_SIGNED" \
  '{release_id:$release_id, product_line:$product_line, version:$version, arch:$arch,
    build_commit:$build_commit, artifact_digest:$artifact_digest,
    scan_report_digest:$scan_report_digest, manifest_sha256:$manifest_sha256,
    files_manifest_sha256:$files_manifest_sha256, policy_version:$policy_version,
    protection_form:$protection_form, hardware_requirements:$hardware_requirements,
    delivery_id:$delivery_id,
    signature:{algorithm:$signature_algorithm, key_id:$signature_key_id, signed:$signed},
    artifact:$artifact, scan_report:$scan_report}' \
  > "$traceability_report"
if [[ "$PKG_SIGNED" == "true" ]]; then
  ed25519_sign_file "$SIGNING_KEY" "$traceability_report" "${traceability_report}.sig" \
    || die "交付追溯记录签名失败: $traceability_report"
fi
size="$(stat -f%z "$out" 2>/dev/null || stat -c%s "$out")"
log_info "离线交付包已生成: ${out}（${size} 字节，旁车 ${PKG_BASENAME}.tar.gz.sha256$( [[ "$PKG_SIGNED" == "true" ]] && printf ' / .sig（已签名）' || printf '，未签名' )）"
log_info "交付追溯记录已生成: ${traceability_report}$( [[ "$PKG_SIGNED" == "true" ]] && printf '（已签名）' || printf '（开发包未签名）' )"
# 同一签名字节可同时用于原名与 update-full 别名；文件名不属于 Ed25519 签名对象。
# 不复制第二份大镜像归档，硬链接节省构建与交付磁盘；摘要旁车使用各自的交付文件名。
update_alias="$OUT_DIR/jiuzhang-${PRODUCT}-update-full-${VERSION}-${ARCH}.tar.gz"
[[ ! -e "$update_alias" && ! -e "${update_alias}.sha256" && ! -e "${update_alias}.sig" ]] \
  || die "完整升级交付别名已存在，拒绝覆盖"
ln "$out" "$update_alias" || die "无法创建完整升级交付别名"
(cd "$OUT_DIR" && sha256_of "$(basename "$update_alias")" > "$(basename "$update_alias").sha256")
sha256_check_sidecar "$update_alias" || die "完整升级别名 SHA-256 校验失败"
if [[ "$PKG_SIGNED" == "true" ]]; then
  cp "${out}.sig" "${update_alias}.sig"
  ed25519_verify_file "$SCRIPT_DIR/release-signing.pub" "$update_alias" "${update_alias}.sig" \
    || die "完整升级别名验签失败"
fi
log_info "完整升级交付入口: ${update_alias}"
# 独立入口内嵌公共函数与固定信任根；现场无需先解开未验签的归档寻找升级脚本。
update_launcher="$OUT_DIR/jiuzhang-${PRODUCT}-update-full-${VERSION}-${ARCH}.sh"
{
  tail -n +2 "$REPO_ROOT/ops/lib/common.sh"
  tail -n +2 "$REPO_ROOT/ops/lib/signing.sh"
  sed '/^source "\$SCRIPT_DIR\/\.\.\/lib\/common\.sh"$/d; /^source "\$SCRIPT_DIR\/\.\.\/lib\/signing\.sh"$/d' \
    "$REPO_ROOT/ops/upgrade/update-full.sh"
} > "$update_launcher"
chmod 0755 "$update_launcher"
bash -n "$update_launcher" || die "独立升级入口语法检查失败"
(cd "$OUT_DIR" && sha256_of "$(basename "$update_launcher")" > "$(basename "$update_launcher").sha256")
sha256_check_sidecar "$update_launcher" || die "独立升级入口摘要校验失败"
if [[ "$PKG_SIGNED" == "true" ]]; then
  ed25519_sign_file "$SIGNING_KEY" "$update_launcher" "${update_launcher}.sig" || die "独立升级入口签名失败"
  ed25519_verify_file "$SCRIPT_DIR/release-signing.pub" "$update_launcher" "${update_launcher}.sig" \
    || die "独立升级入口验签失败"
fi
bash "$update_launcher" --help >/dev/null || die "独立升级入口 --help 冒烟失败"
log_info "独立升级启动脚本: ${update_launcher}"
log_info "安装: tar -xzf $(basename "$out") && cd ${PKG_BASENAME} && sudo bash ops/install/install.sh（请保留 .tar.gz 与 .tar.gz.sha256$( [[ "$PKG_SIGNED" == "true" ]] && printf ' / .tar.gz.sig' ) 于解压目录同级，安装前将验签并校验整包哈希）"
log_info "已有完整安装的升级: bash ops/upgrade/update-full.sh --package ${update_alias:-<正式update-full包>} --current-release <当前release目录>"
