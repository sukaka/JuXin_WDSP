#!/usr/bin/env bash
# WDSP openEuler / 兆芯自解压安装包头。构建器会在末尾标记后追加 tar.gz 载荷。
set -euo pipefail

MARKER='__WDSP_PAYLOAD_BELOW__'
INSTALL_ROOT='/opt/jiuzhang-wdsp'
MINIMAL_HOST=false
SKIP_TUNING=false
ALLOW_COMPATIBLE_OS=false
ALLOW_NON_ZHAOXIN=false
ALLOW_UNSIGNED=false
WDSP_RELEASE_PUBKEY_PEM='-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAJBzjZs04R6NVLDuKoJsViPuBEGlo70z/zpnKi6ZHq2s=
-----END PUBLIC KEY-----'

log() { printf '[WDSP run] %s\n' "$*"; }
die() { printf '[WDSP run] ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
用法: jiuzhang-wdsp-openeuler-zhaoxin-<version>-amd64.run [选项]

选项:
  --install-dir DIR       安装根目录（默认 /opt/jiuzhang-wdsp）
  --minimal-host          停用明确无关的打印、发现等服务，不卸载软件包
  --skip-tuning           跳过 limits/sysctl/Docker/CPU 调优
  --allow-compatible-os   允许已验证兼容的非 openEuler RPM 系统
  --allow-non-zhaoxin     允许已验证兼容的非兆芯 x86-64 CPU
  --allow-unsigned        仅放行 development 交付包
  -h, --help              显示帮助

安装包会先用 dnf（缺失时 yum）补齐基础工具，再解包、验签并调用 WDSP 标准安装向导。
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --install-dir) [[ $# -ge 2 ]] || die '--install-dir 缺少参数'; INSTALL_ROOT="$2"; shift 2 ;;
    --minimal-host) MINIMAL_HOST=true; shift ;;
    --skip-tuning) SKIP_TUNING=true; shift ;;
    --allow-compatible-os) ALLOW_COMPATIBLE_OS=true; shift ;;
    --allow-non-zhaoxin) ALLOW_NON_ZHAOXIN=true; shift ;;
    --allow-unsigned) ALLOW_UNSIGNED=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "未知参数：$1" ;;
  esac
done

[[ "$EUID" -eq 0 ]] || die '请以 root 执行 .run 安装包'

install_bootstrap_package() {
  local package="$1"
  if command -v dnf >/dev/null 2>&1; then
    dnf -y install "$package"
  elif command -v yum >/dev/null 2>&1; then
    yum -y install "$package"
  else
    die "缺少 ${package} 且未找到 dnf/yum，无法展开安装包"
  fi
}

command -v tar >/dev/null 2>&1 || install_bootstrap_package tar
command -v gzip >/dev/null 2>&1 || install_bootstrap_package gzip
command -v sha256sum >/dev/null 2>&1 || install_bootstrap_package coreutils
command -v openssl >/dev/null 2>&1 || install_bootstrap_package openssl
command -v tar >/dev/null 2>&1 || die 'tar 安装失败'
command -v gzip >/dev/null 2>&1 || die 'gzip 安装失败'
command -v sha256sum >/dev/null 2>&1 || die 'sha256sum 安装失败'
command -v openssl >/dev/null 2>&1 || die 'openssl 安装失败'

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/jiuzhang-wdsp-run.XXXXXX")"
cleanup() {
  case "$WORK_DIR" in
    */jiuzhang-wdsp-run.*) rm -rf "$WORK_DIR" ;;
    *) printf '拒绝清理异常路径：%s\n' "$WORK_DIR" >&2 ;;
  esac
}
trap cleanup EXIT INT TERM HUP

extract_payload() {
  local line found=false
  exec 9< "$0"
  while IFS= read -r line <&9; do
    if [[ "$line" == "$MARKER" ]]; then
      found=true
      break
    fi
  done
  [[ "$found" == "true" ]] || die '安装包载荷标记缺失'
  tar -xzf - -C "$WORK_DIR" <&9
  exec 9<&-
}

extract_payload

shopt -s nullglob
packages=("$WORK_DIR"/jiuzhang-wdsp-offline-*-amd64.tar.gz)
shopt -u nullglob
[[ ${#packages[@]} -eq 1 ]] || die '载荷中必须且只能包含一个 WDSP amd64 离线包'
PACKAGE="${packages[0]}"
[[ -f "${PACKAGE}.sha256" ]] || die '离线包缺少 .sha256 旁车'
(
  cd "$WORK_DIR"
  sha256sum -c "$(basename "${PACKAGE}.sha256")"
) || die '离线包哈希校验失败'

verify_package_signature() {
  local package="$1" signature="${1}.sig" public_key raw_signature
  if [[ ! -f "$signature" ]]; then
    [[ "$ALLOW_UNSIGNED" == "true" ]] \
      || die '离线包缺少 Ed25519 签名；生产安装拒绝继续'
    log '警告：已显式放行未签名 development 包，仅限本地测试'
    return 0
  fi
  public_key="$WORK_DIR/release-signing.pub"
  raw_signature="$WORK_DIR/release-signing.raw"
  printf '%s\n' "$WDSP_RELEASE_PUBKEY_PEM" > "$public_key"
  chmod 0600 "$public_key"
  base64 -d < "$signature" > "$raw_signature" 2>/dev/null \
    || die '离线包签名格式无效'
  openssl pkeyutl -verify -pubin -inkey "$public_key" -rawin \
    -in "$package" -sigfile "$raw_signature" >/dev/null 2>&1 \
    || die '离线包 Ed25519 验签失败'
  log '离线包 Ed25519 验签通过'
}

verify_package_signature "$PACKAGE"

if [[ -d "$WORK_DIR/rpms" ]]; then
  shopt -s nullglob
  rpms=("$WORK_DIR"/rpms/*.rpm)
  shopt -u nullglob
  if [[ ${#rpms[@]} -gt 0 ]]; then
    log "安装 ${#rpms[@]} 个随包依赖 RPM"
    if command -v dnf >/dev/null 2>&1; then
      dnf -y install "${rpms[@]}"
    elif command -v yum >/dev/null 2>&1; then
      yum -y install "${rpms[@]}"
    else
      die '载荷包含 RPM，但宿主机无 dnf/yum'
    fi
  fi
fi

PACKAGE_BASENAME="$(basename "$PACKAGE" .tar.gz)"
VERSION_PART="${PACKAGE_BASENAME#jiuzhang-wdsp-offline-}"
VERSION_PART="${VERSION_PART%-amd64}"
RELEASE_DIR="$INSTALL_ROOT/releases/$VERSION_PART"
mkdir -p "$RELEASE_DIR"
cp "$PACKAGE" "${PACKAGE}.sha256" "$RELEASE_DIR/"
[[ ! -f "${PACKAGE}.sig" ]] || cp "${PACKAGE}.sig" "$RELEASE_DIR/"
tar -xzf "$RELEASE_DIR/$(basename "$PACKAGE")" -C "$RELEASE_DIR"
PRODUCT_DIR="$RELEASE_DIR/$PACKAGE_BASENAME"
[[ -x "$PRODUCT_DIR/ops/install/prepare-openeuler-zhaoxin.sh" ]] \
  || die '离线包缺少 openEuler / 兆芯准备脚本'
[[ -x "$PRODUCT_DIR/ops/install/install.sh" ]] || die '离线包缺少标准安装向导'

prepare_args=()
[[ "$MINIMAL_HOST" != "true" ]] || prepare_args+=(--minimal-host)
[[ "$SKIP_TUNING" != "true" ]] || prepare_args+=(--skip-tuning)
[[ "$ALLOW_COMPATIBLE_OS" != "true" ]] || prepare_args+=(--allow-compatible-os)
[[ "$ALLOW_NON_ZHAOXIN" != "true" ]] || prepare_args+=(--allow-non-zhaoxin)
"$PRODUCT_DIR/ops/install/prepare-openeuler-zhaoxin.sh" "${prepare_args[@]}"

install_args=()
[[ "$ALLOW_UNSIGNED" != "true" ]] || install_args+=(--allow-unsigned)
(
  cd "$PRODUCT_DIR"
  ./ops/install/install.sh "${install_args[@]}"
)

ln -sfn "$PRODUCT_DIR" "$INSTALL_ROOT/current"
log "WDSP ${VERSION_PART} 安装完成：$PRODUCT_DIR"
exit 0
__WDSP_PAYLOAD_BELOW__
