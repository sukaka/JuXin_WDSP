#!/usr/bin/env bash
# 将 WDSP amd64 离线包封装为 openEuler / 兆芯自解压 .run 安装包。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
HEADER="$REPO_ROOT/ops/install/openeuler-zhaoxin-run-header.sh"
BASE_BUILDER="$SCRIPT_DIR/build.sh"
# shellcheck source=../lib/common.sh
source "$REPO_ROOT/ops/lib/common.sh"
# shellcheck source=../lib/signing.sh
source "$REPO_ROOT/ops/lib/signing.sh"

usage() {
  cat <<'EOF'
用法: build-openeuler-zhaoxin-run.sh --version X.Y.Z [选项]

构建：dist/jiuzhang-wdsp-openeuler-zhaoxin-X.Y.Z-amd64.run

选项:
  -v, --version X.Y.Z       版本号（必填）
      --offline-package F   使用已构建的 jiuzhang-wdsp-offline-*-amd64.tar.gz
      --rpm-dir DIR         随包附带 openEuler x86-64 依赖 RPM（可选）
      --development         允许构建未签名 development 包，仅用于测试
      --skip-images         新建基础离线包时跳过镜像，仅用于结构测试
  -o, --output DIR          输出目录（默认 <仓库>/dist）
  -h, --help                显示帮助

正式构建要求环境变量 WDSP_SIGNING_KEY 指向 Ed25519 发布私钥；私钥不会进入产物。
EOF
}

VERSION=''
OFFLINE_PACKAGE=''
RPM_DIR=''
OUTPUT_DIR="$REPO_ROOT/dist"
DEVELOPMENT=false
SKIP_IMAGES=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    -v|--version) VERSION="${2:-}"; shift 2 ;;
    --offline-package) OFFLINE_PACKAGE="${2:-}"; shift 2 ;;
    --rpm-dir) RPM_DIR="${2:-}"; shift 2 ;;
    --development) DEVELOPMENT=true; shift ;;
    --skip-images) SKIP_IMAGES=true; shift ;;
    -o|--output) OUTPUT_DIR="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "未知参数：$1" ;;
  esac
done

[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { usage >&2; die '必须提供语义化版本号'; }
[[ -f "$HEADER" ]] || die "缺少自解压头：$HEADER"
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd -P)"

if [[ -z "$OFFLINE_PACKAGE" ]]; then
  build_args=(-v "$VERSION" -p wdsp -a amd64 -o "$OUTPUT_DIR")
  [[ "$DEVELOPMENT" != "true" ]] || build_args+=(--development)
  [[ "$SKIP_IMAGES" != "true" ]] || build_args+=(--skip-images)
  "$BASE_BUILDER" "${build_args[@]}"
  OFFLINE_PACKAGE="$OUTPUT_DIR/jiuzhang-wdsp-offline-${VERSION}-amd64.tar.gz"
fi

[[ -f "$OFFLINE_PACKAGE" ]] || die "基础离线包不存在：$OFFLINE_PACKAGE"
OFFLINE_PACKAGE="$(cd "$(dirname "$OFFLINE_PACKAGE")" && pwd -P)/$(basename "$OFFLINE_PACKAGE")"
[[ "$(basename "$OFFLINE_PACKAGE")" == "jiuzhang-wdsp-offline-${VERSION}-amd64.tar.gz" ]] \
  || die '基础离线包名称与产品、版本或 amd64 架构不匹配'
[[ -f "${OFFLINE_PACKAGE}.sha256" ]] || die '基础离线包缺少 .sha256 旁车'
if [[ "$DEVELOPMENT" != "true" ]]; then
  [[ -f "${OFFLINE_PACKAGE}.sig" ]] || die '正式基础离线包缺少 .sig 签名旁车'
  [[ -n "${WDSP_SIGNING_KEY:-}" ]] || die '正式 .run 构建必须配置 WDSP_SIGNING_KEY'
fi
if [[ -n "$RPM_DIR" ]]; then
  [[ -d "$RPM_DIR" ]] || die "RPM 目录不存在：$RPM_DIR"
fi

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/jiuzhang-wdsp-run-build.XXXXXX")"
cleanup() {
  case "$WORK_DIR" in
    */jiuzhang-wdsp-run-build.*) rm -rf "$WORK_DIR" ;;
    *) log_warn "拒绝清理异常路径：$WORK_DIR" ;;
  esac
}
trap cleanup EXIT INT TERM HUP

PAYLOAD_DIR="$WORK_DIR/payload"
mkdir -p "$PAYLOAD_DIR"
cp "$OFFLINE_PACKAGE" "${OFFLINE_PACKAGE}.sha256" "$PAYLOAD_DIR/"
[[ ! -f "${OFFLINE_PACKAGE}.sig" ]] || cp "${OFFLINE_PACKAGE}.sig" "$PAYLOAD_DIR/"
if [[ -n "$RPM_DIR" ]]; then
  mkdir -p "$PAYLOAD_DIR/rpms"
  shopt -s nullglob
  rpm_files=("$RPM_DIR"/*.rpm)
  shopt -u nullglob
  [[ ${#rpm_files[@]} -gt 0 ]] || die "RPM 目录中没有 .rpm 文件：$RPM_DIR"
  cp "${rpm_files[@]}" "$PAYLOAD_DIR/rpms/"
fi

PAYLOAD="$WORK_DIR/payload.tar.gz"
tar -czf "$PAYLOAD" -C "$PAYLOAD_DIR" .
OUT="$OUTPUT_DIR/jiuzhang-wdsp-openeuler-zhaoxin-${VERSION}-amd64.run"
cp "$HEADER" "$OUT"
cat "$PAYLOAD" >> "$OUT"
chmod 0755 "$OUT"
(
  cd "$OUTPUT_DIR"
  sha256_of "$(basename "$OUT")" > "$(basename "$OUT").sha256"
)

if [[ -n "${WDSP_SIGNING_KEY:-}" ]]; then
  ed25519_sign_file "$WDSP_SIGNING_KEY" "$OUT" "${OUT}.sig" \
    || die '自解压包签名失败'
elif [[ "$DEVELOPMENT" == "true" ]]; then
  log_warn '已生成未签名 development .run；生产环境禁止使用'
else
  die '正式 .run 构建缺少发布签名私钥'
fi

log_info "openEuler / 兆芯 .run 已生成：$OUT"
log_info "校验：sha256sum -c $(basename "$OUT").sha256"
log_info "安装：sudo ./$(basename "$OUT")"
