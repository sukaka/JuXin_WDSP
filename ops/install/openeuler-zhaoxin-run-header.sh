#!/usr/bin/env bash
# WDSP openEuler / 兆芯自解压安装包头。构建器会在末尾标记后追加 tar.gz 载荷。
set -euo pipefail

MARKER='__WDSP_PAYLOAD_BELOW__'
INSTALL_ROOT='/opt/jiuzhang-wdsp'
MINIMAL_HOST=false
SKIP_TUNING=false
ALLOW_COMPATIBLE_OS=false
UNIFIED_PACKAGE=false
INSTALL_PLATFORM=''
ALLOW_NON_ZHAOXIN=false
ALLOW_UNSIGNED=false
UNINSTALL=false
DATA_MODE=""
CONFIRM_DELETE_DATA=false
WDSP_RELEASE_PUBKEY_PEM='-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAJBzjZs04R6NVLDuKoJsViPuBEGlo70z/zpnKi6ZHq2s=
-----END PUBLIC KEY-----'

log() { printf '[WDSP run] %s\n' "$*"; }
die() { printf '[WDSP run] ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
  if [[ "$UNIFIED_PACKAGE" == "true" ]]; then
    cat <<'EOF'
用法: jiuzhang-wdsp-install-<version>-amd64.run [选项]
支持 x86_64 openEuler 24.03 LTS SP4（兆芯）和 Alibaba Cloud Linux 4 OpenAnolis Edition。
自动选择已签名的本地 RPM 仓库，宿主机需提供 systemd 和基础解包、验签工具。
EOF
  else
    printf '%s\n' '用法: jiuzhang-wdsp-openeuler-zhaoxin-<version>-amd64.run [选项]'
  fi
  cat <<'EOF'

选项:
  --install-dir DIR       安装根目录（默认 /opt/jiuzhang-wdsp）
  --uninstall             卸载旧系统，默认保留数据、账号、密钥和证书
  --keep-data             显式保留数据（配合 --uninstall）
  --purge-data            删除本系统数据卷及安装目录（配合 --uninstall）
  --confirm-delete-data   确认不可恢复地删除数据（配合 --purge-data）
  --minimal-host          openEuler：停用明确无关的打印、发现等服务
  --skip-tuning           openEuler：跳过 limits/sysctl/Docker/CPU 调优
  --allow-compatible-os   单系统兼容包专用，双系统包按支持列表安装
  --allow-non-zhaoxin     允许已验证兼容的非兆芯 x86-64 CPU
  --allow-unsigned        仅放行 development 交付包
  -h, --help              显示帮助
EOF
}


read_install_os_value() {
  awk -v "key=$2" 'index($0, key "=") == 1 {
    value = substr($0, length(key) + 2)
    sub(/\r$/, "", value)
    sub(/^[\042\047]/, "", value)
    sub(/[\042\047]$/, "", value)
    print tolower(value)
    exit
  }' "$1"
}

read_install_os_id() {
  local release_file="$1" os_id
  [[ -r "$release_file" ]] || die "无法读取 os-release：$release_file"
  os_id="$(read_install_os_value "$release_file" ID)"
  [[ -n "$os_id" ]] || die "os-release 缺少有效 ID：$release_file"
  printf '%s\n' "$os_id"
}

check_install_platform() {
  local release_file="$1" architecture="${2:-$(uname -m)}" os_id version_id
  [[ "$architecture" == "x86_64" ]] || die "此安装包仅支持 x86_64，当前架构：$architecture"
  os_id="$(read_install_os_id "$release_file")" || return 1
  if [[ "$UNIFIED_PACKAGE" == "true" ]]; then
    version_id="$(read_install_os_value "$release_file" VERSION_ID)"
    case "$os_id/$version_id" in
      openeuler/24.03)
        [[ "$(read_install_os_value "$release_file" VERSION)" == "24.03 (lts-sp4)" ]] \
          || die '此安装包的 openEuler 依赖适用于 24.03 LTS SP4'
        INSTALL_PLATFORM=openeuler
        ;;
      alinux/4)
        [[ "$(read_install_os_value "$release_file" VARIANT_ID)" == "openanolis" ]] \
          || die '此安装包的 Alibaba Cloud Linux 4 依赖适用于 OpenAnolis Edition'
        INSTALL_PLATFORM=alinux4
        ;;
      *) die "不支持当前系统 ${os_id} ${version_id}；支持 openEuler 24.03 LTS SP4 或 Alibaba Cloud Linux 4 OpenAnolis Edition" ;;
    esac
    return 0
  fi
  if [[ "$os_id" != "openeuler" && "$ALLOW_COMPATIBLE_OS" != "true" ]]; then
    die "当前系统为 ${os_id}，此安装包面向 openEuler；其他已验证兼容系统需 --allow-compatible-os，且不能使用随包 openEuler RPM"
  fi
}

check_bundled_rpm_platform() {
  local os_id
  os_id="$(read_install_os_id "$1")" || return 1
  [[ "$os_id" == "openeuler" ]] \
    || die "拒绝将随包 openEuler RPM 安装到 ${os_id}；请使用目标系统原生依赖及不含这些 RPM 的安装包"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --install-dir) [[ $# -ge 2 ]] || die '--install-dir 缺少参数'; INSTALL_ROOT="$2"; shift 2 ;;
    --uninstall) UNINSTALL=true; shift ;;
    --keep-data|--purge-data)
      [[ -z "$DATA_MODE" || "$DATA_MODE" == "$1" ]] || die '保留数据与删除数据不可同时指定'
      DATA_MODE="$1"; shift ;;
    --confirm-delete-data) CONFIRM_DELETE_DATA=true; shift ;;
    --minimal-host) MINIMAL_HOST=true; shift ;;
    --skip-tuning) SKIP_TUNING=true; shift ;;
    --allow-compatible-os) ALLOW_COMPATIBLE_OS=true; shift ;;
    --allow-non-zhaoxin) ALLOW_NON_ZHAOXIN=true; shift ;;
    --allow-unsigned) ALLOW_UNSIGNED=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "未知参数：$1" ;;
  esac
done

if [[ "$UNINSTALL" != "true" && ( -n "$DATA_MODE" || "$CONFIRM_DELETE_DATA" == "true" ) ]]; then
  die '数据删除/保留选项只能用于 --uninstall'
fi
if [[ "$CONFIRM_DELETE_DATA" == "true" && "$DATA_MODE" != "--purge-data" ]]; then
  die '--confirm-delete-data 必须配合 --uninstall --purge-data'
fi
if [[ "$DATA_MODE" == "--purge-data" && "$CONFIRM_DELETE_DATA" != "true" ]]; then
  die '彻底删除需要 --confirm-delete-data 明确确认'
fi
[[ "$EUID" -eq 0 ]] || die '请以 root 执行 .run 安装包'
[[ "$UNINSTALL" == "true" ]] || check_install_platform /etc/os-release
if [[ "$UNIFIED_PACKAGE" == "true" && "$UNINSTALL" != "true" ]]; then
  [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null 2>&1 \
    || die '完整离线安装需要运行中的 systemd'
fi

install_bootstrap_package() {
  local package="$1"
  [[ "$UNINSTALL" != "true" ]] || die "卸载需要已有 ${package}，不会安装或替换宿主机软件"
  [[ "$UNIFIED_PACKAGE" != "true" ]] || die "启动安装器前需要宿主机提供基础工具 $package"
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
command -v python3 >/dev/null 2>&1 || install_bootstrap_package python3
command -v flock >/dev/null 2>&1 || install_bootstrap_package util-linux
command -v tar >/dev/null 2>&1 || die 'tar 安装失败'
command -v gzip >/dev/null 2>&1 || die 'gzip 安装失败'
command -v sha256sum >/dev/null 2>&1 || die 'sha256sum 安装失败'
command -v openssl >/dev/null 2>&1 || die 'openssl 安装失败'

command -v python3 >/dev/null 2>&1 || die 'python3 安装失败'
command -v flock >/dev/null 2>&1 || die 'flock 安装失败'
mkdir -p /run/lock
exec 8>/run/lock/jiuzhang-wdsp-install.lock
flock -n 8 || die '另一个 WDSP 安装或卸载正在执行'

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/jiuzhang-wdsp-run.XXXXXX")"
cleanup() {
  case "$WORK_DIR" in
    */jiuzhang-wdsp-run.*) rm -rf "$WORK_DIR" ;;
    *) printf '拒绝清理异常路径：%s\n' "$WORK_DIR" >&2 ;;
  esac
}
trap cleanup EXIT INT TERM HUP

safe_extract_tar() {
  local archive="$1" dest="$2" expected_root="${3:-}"
  python3 - "$archive" "$dest" "$expected_root" <<'PY'
import os, pathlib, sys, tarfile
archive, dest, expected_root = sys.argv[1:]
root = pathlib.Path(dest).resolve()
with tarfile.open(archive, "r:gz") as tf:
    members = tf.getmembers()
    if not members:
        raise SystemExit("归档为空")
    for m in members:
        rel = pathlib.PurePosixPath(m.name)
        if rel.is_absolute() or ".." in rel.parts:
            raise SystemExit(f"归档含不安全路径: {m.name}")
        if not (m.isdir() or m.isfile()):
            raise SystemExit(f"归档含不允许的符号链接、硬链接或特殊文件: {m.name}")
        if expected_root and rel.parts and rel.parts[0] != expected_root:
            raise SystemExit(f"归档根目录与期望不符: {m.name}")
        target = (root / rel).resolve()
        if root != target and root not in target.parents:
            raise SystemExit(f"归档路径越界: {m.name}")
    for m in members:
        rel = pathlib.PurePosixPath(m.name)
        target = (root / rel).resolve()
        if target == root:
            continue
        safe_mode = (m.mode & 0o0755) | (0o0700 if m.isdir() else 0o0600)
        m.mode = safe_mode
        m.uid = 0
        m.gid = 0
        m.uname = ""
        m.gname = ""
        tf.extract(m, path=root, set_attrs=True)
        os.chmod(target, safe_mode)
PY
}

extract_payload() {
  local line found=false payload_tmp="$WORK_DIR/.payload.tar.gz"
  exec 9< "$0"
  while IFS= read -r line <&9; do
    if [[ "$line" == "$MARKER" ]]; then
      found=true
      break
    fi
  done
  [[ "$found" == "true" ]] || die '安装包载荷标记缺失'
  cat <&9 > "$payload_tmp"
  exec 9<&-
  safe_extract_tar "$payload_tmp" "$WORK_DIR" || die '安装包载荷安全校验或解压失败'
  rm -f "$payload_tmp"
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

verify_rpm_repository() (
  cd "$1"
  export LC_ALL=C
  shopt -s nullglob
  local repository="rpms/$2"
  local -a rpms=("$repository"/*.rpm) metadata=("$repository"/repodata/*)
  [[ ${#rpms[@]} -gt 0 && -f "$repository/repodata/repomd.xml" ]] \
    || die "缺少 $2 的离线 RPM 仓库"
  verify_package_signature "$repository/rpms.sha256"
  local computed
  computed="$(sha256sum "${rpms[@]}" "${metadata[@]}")"
  [[ "$computed" == "$(< "$repository/rpms.sha256")" ]] \
    || die "$2 本地仓库的 RPM 或元数据校验失败"
)

install_selected_rpms() {
  local engine
  local -a packages=()
  verify_rpm_repository "$WORK_DIR" "$INSTALL_PLATFORM"
  log "已选择 $INSTALL_PLATFORM 离线依赖仓库"
  command -v curl >/dev/null 2>&1 || packages+=(curl)
  command -v jq >/dev/null 2>&1 || packages+=(jq)
  if ! command -v docker >/dev/null 2>&1; then
    case "$INSTALL_PLATFORM" in
      openeuler) engine=docker-ce ;;
      alinux4) engine=moby ;;
    esac
    packages+=("$engine")
  fi
  docker compose version >/dev/null 2>&1 || packages+=(docker-compose-plugin)
  if [[ ${#packages[@]} -gt 0 ]]; then
    command -v dnf >/dev/null 2>&1 || die '缺少 dnf，无法安装离线依赖'
    log "从本地仓库安装所缺组件：${packages[*]}"
    # The signed manifest above authenticates the full local repo, including repodata.
    dnf -y --noplugins --disablerepo='*' \
      --repofrompath="wdsp-offline,file://$WORK_DIR/rpms/$INSTALL_PLATFORM" \
      --enablerepo=wdsp-offline --setopt=wdsp-offline.gpgcheck=0 \
      --setopt=wdsp-offline.repo_gpgcheck=0 --setopt=install_weak_deps=False \
      install "${packages[@]}" || die "$INSTALL_PLATFORM 离线依赖安装失败"
  fi
  command -v curl >/dev/null && command -v jq >/dev/null \
    && docker compose version >/dev/null 2>&1 || die '离线运行组件安装后验证失败'
}

verify_package_signature "$PACKAGE"

PACKAGE_BASENAME="$(basename "$PACKAGE" .tar.gz)"
VERSION_PART="${PACKAGE_BASENAME#jiuzhang-wdsp-offline-}"
VERSION_PART="${VERSION_PART%-amd64}"
# Only execute lifecycle code after authenticating the containing archive.
LIFECYCLE="$WORK_DIR/lifecycle.py"
tar -xzOf "$PACKAGE" "$PACKAGE_BASENAME/ops/install/lifecycle.py" > "$LIFECYCLE" \
  || die '离线包缺少卸载与数据保留管理器'
if [[ "$UNINSTALL" == "true" ]]; then
  remove_args=()
  [[ "$DATA_MODE" != "--purge-data" ]] || remove_args+=(--purge-data)
  [[ "$CONFIRM_DELETE_DATA" != "true" ]] || remove_args+=(--confirm-delete-data)
  python3 "$LIFECYCLE" uninstall --install-root "$INSTALL_ROOT" "${remove_args[@]}"
  exit 0
fi
INSTALL_MODE="$(python3 "$LIFECYCLE" preflight --install-root "$INSTALL_ROOT")"

if [[ "$UNIFIED_PACKAGE" == "true" ]]; then
  install_selected_rpms
elif [[ -d "$WORK_DIR/rpms" ]]; then
  shopt -s nullglob
  rpms=("$WORK_DIR"/rpms/*.rpm)
  shopt -u nullglob
  if [[ ${#rpms[@]} -gt 0 ]]; then
    check_bundled_rpm_platform /etc/os-release
    if [[ -f "$WORK_DIR/rpms/rpms.sha256" ]]; then
      verify_package_signature "$WORK_DIR/rpms/rpms.sha256"
      (
        cd "$WORK_DIR"
        export LC_ALL=C
        shopt -s nullglob
        local_rpms=(rpms/*.rpm)
        computed="$(sha256sum "${local_rpms[@]}")"
        [[ "$computed" == "$(< rpms/rpms.sha256)" ]]
      ) || die '随包依赖 RPM 校验和验证失败，拒绝安装'
    fi
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

RELEASE_DIR="$INSTALL_ROOT/releases/$VERSION_PART"
if [[ -e "$RELEASE_DIR" ]]; then
  RELEASE_DIR="${RELEASE_DIR}-reinstall-$(date +%Y%m%d%H%M%S)-$$"
fi
mkdir -p "$RELEASE_DIR"
cp "$PACKAGE" "${PACKAGE}.sha256" "$RELEASE_DIR/"
[[ ! -f "${PACKAGE}.sig" ]] || cp "${PACKAGE}.sig" "$RELEASE_DIR/"
safe_extract_tar "$RELEASE_DIR/$(basename "$PACKAGE")" "$RELEASE_DIR" "$PACKAGE_BASENAME" \
  || die '离线包安全校验或解压失败'
PRODUCT_DIR="$RELEASE_DIR/$PACKAGE_BASENAME"
[[ -x "$PRODUCT_DIR/ops/install/prepare-openeuler-zhaoxin.sh" ]] \
  || die '离线包缺少 openEuler / 兆芯准备脚本'
[[ -x "$PRODUCT_DIR/ops/install/install.sh" ]] || die '离线包缺少标准安装向导'

if [[ "$INSTALL_MODE" == "retained" ]]; then
  python3 "$LIFECYCLE" restore --install-root "$INSTALL_ROOT" --destination "$PRODUCT_DIR"
fi

if [[ "$INSTALL_PLATFORM" == "alinux4" ]]; then
  systemctl enable --now docker
else
  prepare_args=()
  [[ "$MINIMAL_HOST" != "true" ]] || prepare_args+=(--minimal-host)
  [[ "$SKIP_TUNING" != "true" ]] || prepare_args+=(--skip-tuning)
  [[ "$ALLOW_COMPATIBLE_OS" != "true" ]] || prepare_args+=(--allow-compatible-os)
  [[ "$ALLOW_NON_ZHAOXIN" != "true" ]] || prepare_args+=(--allow-non-zhaoxin)
  "$PRODUCT_DIR/ops/install/prepare-openeuler-zhaoxin.sh" "${prepare_args[@]}"
fi

if [[ "$INSTALL_MODE" == "fresh" ]]; then
  python3 "$LIFECYCLE" check-empty --install-root "$INSTALL_ROOT"
fi
install_args=()
[[ "$INSTALL_MODE" != "retained" ]] || install_args+=(--reuse-env)
[[ "$ALLOW_UNSIGNED" != "true" ]] || install_args+=(--allow-unsigned)
(
  cd "$PRODUCT_DIR"
  ./ops/install/install.sh "${install_args[@]}"
)

ln -sfnT "$PRODUCT_DIR" "$INSTALL_ROOT/current"
python3 "$LIFECYCLE" complete --install-root "$INSTALL_ROOT"
log "WDSP ${VERSION_PART} 安装完成：$PRODUCT_DIR"
exit 0
__WDSP_PAYLOAD_BELOW__
