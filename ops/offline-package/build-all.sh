#!/usr/bin/env bash
# build-all.sh —— 批量构建 3 产品线 × 2 架构 离线包。
#
# 默认产物（6 个）：
#   dist/jiuzhang-waf-offline-{version}-amd64.tar.gz
#   dist/jiuzhang-waf-offline-{version}-arm64.tar.gz
#   dist/jiuzhang-wdsp-offline-{version}-amd64.tar.gz
#   dist/jiuzhang-wdsp-offline-{version}-arm64.tar.gz
#   dist/jiuzhang-api-offline-{version}-amd64.tar.gz
#   dist/jiuzhang-api-offline-{version}-arm64.tar.gz
#
# 说明：
#   - amd64 = x86-64（Intel/AMD；海光 C86、兆芯 KX/KH 使用 amd64 包）
#   - arm64 = ARM64
#   - 同一套 jiuzhang-server/gateway 镜像可复用；差异在 PRODUCT_EDITION 配置
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck source=../lib/common.sh
source "$SCRIPT_DIR/../lib/common.sh"

usage() {
  cat <<'EOF'
用法: build-all.sh --version X.Y.Z [选项]

批量构建产品线 × 架构离线包（默认 3×2=6 包）。

选项:
  -v, --version X.Y.Z     交付版本号（必填）
  -p, --products LIST     产品列表，逗号分隔（默认 waf,wdsp,api）
  -a, --arches LIST       架构列表，逗号分隔（默认 amd64,arm64；可用 x86 作 amd64 别名）
      --skip-images       透传给 build.sh（跳过 docker pull/save）
      --development       透传给 build.sh，允许无发布私钥的本地开发自验包
  -o, --output DIR        输出目录（默认 <仓库>/dist）
  -h, --help              显示帮助

示例:
  # 全量 6 包
  build-all.sh -v 2.0.0

  # 仅 x86-64（amd64，含海光 C86、兆芯 KX/KH）的三产品包
  build-all.sh -v 2.0.0 --arches amd64

  # 仅 WAF + WDSP 的 amd64
  build-all.sh -v 2.0.0 -p waf,wdsp -a amd64

前置：
  各架构的 jiuzhang-server:{version} / jiuzhang-gateway:{version} 镜像需已构建。
  例如：
    docker buildx build --platform linux/amd64 -t jiuzhang-server:2.0.0 -f server/Dockerfile --load .
    docker buildx build --platform linux/amd64 -t jiuzhang-gateway:2.0.0 -f gateway/Dockerfile --load gateway/
    docker buildx build --platform linux/arm64 -t jiuzhang-server:2.0.0 -f server/Dockerfile --load .
    docker buildx build --platform linux/arm64 -t jiuzhang-gateway:2.0.0 -f gateway/Dockerfile --load gateway/
  日志轮转 sidecar 镜像（compose 模板含 logrotator 服务，离线包随版本一同导出）：
    docker buildx build --platform linux/<arch> -t jiuzhang-logrotator:2.0.0 --load gateway/images/logrotator

注意：单机无法同时持有同名不同架构的 docker 镜像。
若本机要依次打 amd64 与 arm64，请在切换架构前重新 --load 对应平台镜像，
或使用 --skip-images 仅验证打包清单。

签名：设置环境变量 WDSP_SIGNING_KEY（Ed25519 私钥路径，绝不入库）后，
每个正式产物自动附带旁车 .sig（透传给 build.sh）。未设置时必须显式
使用 --development 生成仅供本地自验的 development 包。
EOF
}

VERSION=""
PRODUCTS="waf,wdsp,api"
ARCHES="amd64,arm64"
SKIP_IMAGES=false
DEVELOPMENT=false
OUT_DIR="$REPO_ROOT/dist"
EXTRA_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    -v|--version)   VERSION="$2"; shift 2 ;;
    -p|--products)  PRODUCTS="$2"; shift 2 ;;
    -a|--arches)    ARCHES="$2"; shift 2 ;;
    --skip-images)  SKIP_IMAGES=true; EXTRA_ARGS+=(--skip-images); shift ;;
    --development)  DEVELOPMENT=true; EXTRA_ARGS+=(--development); shift ;;
    -o|--output)    OUT_DIR="$2"; shift 2 ;;
    -h|--help)      usage; exit 0 ;;
    *) log_err "未知参数: $1"; usage; exit 2 ;;
  esac
done

[[ -n "$VERSION" ]] || { log_err "必须指定 --version"; usage; exit 2; }

if [[ -z "${WDSP_SIGNING_KEY:-}" ]]; then
  if [[ "$DEVELOPMENT" != "true" ]]; then
    die "正式批量构建必须设置 WDSP_SIGNING_KEY；本地开发自验请显式使用 --development"
  fi
  log_warn "未配置 WDSP_SIGNING_KEY：本批生成 development 包，仅用于本地开发自验"
else
  log_info "发布签名已启用（WDSP_SIGNING_KEY），各产物将附带旁车 .sig"
fi

BUILD_SH="$SCRIPT_DIR/build.sh"
[[ -x "$BUILD_SH" ]] || chmod +x "$BUILD_SH"

# 归一化列表
IFS=',' read -r -a product_arr <<<"$PRODUCTS"
IFS=',' read -r -a arch_arr <<<"$ARCHES"

ok=0
fail=0
results=()

for product in "${product_arr[@]}"; do
  product="$(printf '%s' "$product" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
  [[ -n "$product" ]] || continue
  for arch in "${arch_arr[@]}"; do
    arch="$(printf '%s' "$arch" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
    [[ -n "$arch" ]] || continue
    log_info "======== 开始: product=${product} arch=${arch} ========"
    if "$BUILD_SH" -v "$VERSION" -p "$product" -a "$arch" -o "$OUT_DIR" "${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}"; then
      ok=$((ok + 1))
      results+=("OK  jiuzhang-${product}-offline-${VERSION}-${arch}.tar.gz")
    else
      fail=$((fail + 1))
      results+=("FAIL jiuzhang-${product}-offline-${VERSION}-${arch}")
      log_err "构建失败: product=${product} arch=${arch}"
    fi
  done
done

echo
log_info "批量构建完成：成功 ${ok}，失败 ${fail}"
for line in "${results[@]}"; do
  printf '  %s\n' "$line"
done

[[ "$fail" -eq 0 ]] || exit 1
