#!/usr/bin/env bash
# 一键构建完整 WDSP amd64 运行组件，并封装为正式签名 openEuler / 兆芯 .run 安装包。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
VERSION_FILE="$REPO_ROOT/VERSION.md"
RUN_BUILDER="$SCRIPT_DIR/build-openeuler-zhaoxin-run.sh"
TRUSTED_PUBLIC_KEY="$SCRIPT_DIR/release-signing.pub"
TARGET_ARCH="amd64"
MIN_FREE_GIB="${WDSP_PACKAGE_MIN_FREE_GIB:-30}"

# shellcheck source=../lib/common.sh
source "$REPO_ROOT/ops/lib/common.sh"
# shellcheck source=../lib/signing.sh
source "$REPO_ROOT/ops/lib/signing.sh"

usage() {
  cat <<'EOF'
用法: package-runtime-run.sh [选项]

从当前工作区构建完整 WDSP linux/amd64 运行组件，并生成正式签名的
openEuler / 兆芯 .run 安装包。交付包只包含运行时组件，不包含测试代码或产品文档。

选项:
  -v, --version X.Y.Z       交付版本；干净工作区可默认读取当前已发布版本
  -o, --output DIR          独立输出目录；默认 dist/run-YYYYmmdd-HHMMSS
      --signing-key FILE    Ed25519 发布私钥路径；也可通过 WDSP_SIGNING_KEY 提供
      --rpm-dir DIR         必填；匹配目标 openEuler x86-64 的完整离线 RPM 目录
      --dry-run             仅显示将执行的构建命令，不写入文件或调用 Docker
  -h, --help                显示帮助

示例:
  WDSP_SIGNING_KEY=/secure/wdsp-release.key \
    bash ops/offline-package/package-runtime-run.sh --rpm-dir /secure/openeuler-rpms
  bash ops/offline-package/package-runtime-run.sh --signing-key /secure/wdsp-release.key \
    --rpm-dir /secure/openeuler-rpms -v 1.2.1

本脚本不会修改版本号、提交/推送 Git、部署或使用 development/unsigned 打包模式。
RPM 目录必须在顶层包含 docker-compose-plugin 的 x86-64 RPM 及其全部依赖。
脚本校验 RPM 架构和文件完整性；依赖闭包仍须在干净 openEuler 测试机验收。
EOF
}

VERSION=''
VERSION_EXPLICIT=false
OUTPUT_DIR=''
SIGNING_KEY=''
RPM_DIR=''
DRY_RUN=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    -v|--version) VERSION="${2:-}"; VERSION_EXPLICIT=true; shift 2 ;;
    -o|--output) OUTPUT_DIR="${2:-}"; shift 2 ;;
    --signing-key) SIGNING_KEY="${2:-}"; shift 2 ;;
    --rpm-dir) RPM_DIR="${2:-}"; shift 2 ;;
    --dry-run) DRY_RUN=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "未知参数：$1" ;;
  esac
done

if [[ "$VERSION_EXPLICIT" != true ]] && [[ -n "$(git -C "$REPO_ROOT" status --porcelain --untracked-files=all 2>/dev/null)" ]]; then
  die '工作区存在未提交改动，不能默认沿用当前已发布版本；请用 --version 明确本次快照版本'
fi
if [[ -z "$VERSION" ]]; then
  [[ -f "$VERSION_FILE" ]] || die "缺少版本文件：$VERSION_FILE"
  VERSION="$(awk -F'`' '/当前已发布版本/ { print $2; exit }' "$VERSION_FILE")"
fi
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "版本号必须是 X.Y.Z：${VERSION:-<empty>}"

if [[ -z "$OUTPUT_DIR" ]]; then
  OUTPUT_DIR="$REPO_ROOT/dist/run-$(date +%Y%m%d-%H%M%S)"
fi
[[ -n "$OUTPUT_DIR" ]] || die '输出目录不能为空'

[[ -f "$RUN_BUILDER" ]] || die "缺少 .run 打包器：$RUN_BUILDER"
[[ -f "$REPO_ROOT/server/Dockerfile" ]] || die '缺少 server Dockerfile'
[[ -f "$REPO_ROOT/web/Dockerfile" ]] || die '缺少 web Dockerfile'
[[ -f "$REPO_ROOT/gateway/Dockerfile" ]] || die '缺少 gateway Dockerfile'
[[ -f "$REPO_ROOT/gateway/images/netmgrd/Dockerfile" ]] || die '缺少 netmgrd Dockerfile'
[[ -f "$REPO_ROOT/gateway/images/logrotator/Dockerfile" ]] || die '缺少 logrotator Dockerfile'
[[ -f "$REPO_ROOT/wdsp-agent/go.mod" ]] || die '缺少 wdsp-agent Go 模块'
[[ -f "$TRUSTED_PUBLIC_KEY" ]] || die "缺少发布信任公钥：$TRUSTED_PUBLIC_KEY"

validate_signing_key() {
  local private_key="$1" derived_public expected_fingerprint actual_fingerprint
  require_cmd openssl
  derived_public="$(mktemp "${TMPDIR:-/tmp}/wdsp-derived-pub.XXXXXX")"
  if ! openssl pkey -in "$private_key" -pubout -out "$derived_public" >/dev/null 2>&1; then
    rm -f "$derived_public"
    die '发布私钥无法由 OpenSSL 读取，必须是有效的 Ed25519 私钥'
  fi
  expected_fingerprint="$(ed25519_pubkey_fingerprint "$TRUSTED_PUBLIC_KEY")"
  actual_fingerprint="$(ed25519_pubkey_fingerprint "$derived_public")"
  rm -f "$derived_public"
  [[ -n "$expected_fingerprint" && "$actual_fingerprint" == "$expected_fingerprint" ]] \
    || die '发布私钥不匹配安装器信任公钥，拒绝生成无法安装的正式包'
}

if [[ -n "$SIGNING_KEY" ]]; then
  [[ -f "$SIGNING_KEY" ]] || die '指定的发布私钥不存在'
  SIGNING_KEY="$(cd "$(dirname "$SIGNING_KEY")" && pwd -P)/$(basename "$SIGNING_KEY")"
  export WDSP_SIGNING_KEY="$SIGNING_KEY"
fi
if [[ "$DRY_RUN" != true && -z "${WDSP_SIGNING_KEY:-}" ]]; then
  die '正式 .run 打包必须设置 WDSP_SIGNING_KEY 或传入 --signing-key；私钥不会进入产物'
fi
if [[ -n "${WDSP_SIGNING_KEY:-}" ]]; then
  [[ -f "$WDSP_SIGNING_KEY" ]] || die 'WDSP_SIGNING_KEY 指向的发布私钥不存在'
  validate_signing_key "$WDSP_SIGNING_KEY"
fi
[[ -n "$RPM_DIR" ]] || die '完整离线 .run 打包必须提供 --rpm-dir；其中必须包含 docker-compose-plugin 及其依赖 RPM'
[[ -d "$RPM_DIR" ]] || die "RPM 目录不存在：$RPM_DIR"
RPM_DIR="$(cd "$RPM_DIR" && pwd -P)"
shopt -s nullglob
RPM_FILES=("$RPM_DIR"/*.rpm)
COMPOSE_PLUGIN_RPMS=("$RPM_DIR"/docker-compose-plugin-*.rpm)
shopt -u nullglob
[[ ${#RPM_FILES[@]} -gt 0 ]] || die "RPM 目录中没有 .rpm 文件：$RPM_DIR"
[[ ${#COMPOSE_PLUGIN_RPMS[@]} -gt 0 ]] \
  || die "RPM 目录缺少 docker-compose-plugin RPM：$RPM_DIR"
for rpm_file in "${RPM_FILES[@]}"; do
  case "$(basename "$rpm_file")" in
    *.x86_64.rpm|*.noarch.rpm) ;;
    *) die "RPM 目录包含非 x86-64/noarch RPM：$(basename "$rpm_file")" ;;
  esac
done

print_command() {
  printf '+ '
  printf '%q ' "$@"
  printf '\n'
}

run_command() {
  if [[ "$DRY_RUN" == true ]]; then
    print_command "$@"
  else
    "$@"
  fi
}

preflight() {
  require_cmd bash
  require_cmd python3
  require_cmd docker
  require_cmd go
  require_cmd file
  require_cmd jq
  require_cmd openssl
  [[ "$MIN_FREE_GIB" =~ ^[0-9]+$ ]] || die 'WDSP_PACKAGE_MIN_FREE_GIB 必须是非负整数'
  local free_kib required_kib builder_info
  free_kib="$(df -Pk "$OUTPUT_DIR" | awk 'NR==2 {print $4}')"
  required_kib=$((MIN_FREE_GIB * 1024 * 1024))
  [[ "$free_kib" =~ ^[0-9]+$ && "$free_kib" -ge "$required_kib" ]] \
    || die "可用磁盘空间不足：完整打包至少需要 ${MIN_FREE_GIB} GiB"
  docker info >/dev/null 2>&1 || die 'Docker daemon 不可用'
  docker buildx version >/dev/null 2>&1 || die 'Docker buildx 不可用'
  builder_info="$(docker buildx inspect --bootstrap 2>/dev/null)" \
    || die 'Docker buildx builder 初始化失败'
  grep -q 'linux/amd64' <<<"$builder_info" \
    || die '当前 Docker buildx builder 不支持 linux/amd64'
  log_info '运行打包前校验（脚本语法、离线包单测、openEuler .run 验证）...'
  bash -n "$SCRIPT_DIR/build.sh" "$RUN_BUILDER" "$SCRIPT_DIR/package-runtime-run.sh"
  PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s "$REPO_ROOT/test/offline-package" -p 'test_*.py'
  bash "$REPO_ROOT/scripts/tests/openeuler-zhaoxin-run-harness.sh"
}

source_snapshot() {
  {
    git -C "$REPO_ROOT" rev-parse HEAD
    git -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=all
    git -C "$REPO_ROOT" diff --no-ext-diff --binary HEAD --
    while IFS= read -r -d '' untracked; do
      printf 'untracked:%s\n' "$untracked"
      sha256_of "$REPO_ROOT/$untracked"
    done < <(git -C "$REPO_ROOT" ls-files --others --exclude-standard -z)
  } | sha256_of | awk '{print $1}'
}

verify_delivery() {
  local run_file="$OUTPUT_DIR/jiuzhang-wdsp-openeuler-zhaoxin-${VERSION}-amd64.run"
  local offline_name="jiuzhang-wdsp-offline-${VERSION}-amd64.tar.gz"
  local offline_file scan_report manifest_member payload_dir rpm_file archive_listing
  local -a packaged_rpms required_images
  [[ -x "$run_file" ]] || die "最终 .run 不存在或不可执行：$run_file"
  [[ -f "${run_file}.sha256" && -f "${run_file}.sig" ]] || die '最终 .run 缺少哈希或签名旁车'
  sha256_check_sidecar "$run_file" || die '最终 .run SHA-256 校验失败'
  ed25519_verify_file "$TRUSTED_PUBLIC_KEY" "$run_file" "${run_file}.sig" \
    || die '最终 .run Ed25519 验签失败'
  bash "$run_file" --help >/dev/null || die '最终 .run --help 冒烟失败'

  payload_dir="$WORK_DIR/final-payload"
  mkdir -p "$payload_dir"
  awk '/^__WDSP_PAYLOAD_BELOW__$/{found=1; exit} END{exit !found}' "$run_file" \
    || die '最终 .run 缺少载荷边界'
  local marker_line
  marker_line="$(LC_ALL=C awk '/^__WDSP_PAYLOAD_BELOW__$/{print NR; exit}' "$run_file")"
  tail -n "+$((marker_line + 1))" "$run_file" | tar -xzf - -C "$payload_dir" \
    || die '最终 .run 载荷无法解压'
  offline_file="$payload_dir/$offline_name"
  [[ -f "$offline_file" && -f "${offline_file}.sha256" && -f "${offline_file}.sig" ]] \
    || die '最终 .run 未完整嵌入基础离线包及旁车'
  sha256_check_sidecar "$offline_file" || die '嵌入基础离线包 SHA-256 校验失败'
  ed25519_verify_file "$TRUSTED_PUBLIC_KEY" "$offline_file" "${offline_file}.sig" \
    || die '嵌入基础离线包 Ed25519 验签失败'

  shopt -s nullglob
  packaged_rpms=("$payload_dir"/rpms/*.rpm)
  shopt -u nullglob
  [[ ${#packaged_rpms[@]} -eq ${#RPM_FILES[@]} ]] || die '最终 .run 中 RPM 数量与输入目录不一致'
  for rpm_file in "${RPM_FILES[@]}"; do
    [[ -f "$payload_dir/rpms/$(basename "$rpm_file")" ]] || die "最终 .run 缺少 RPM：$(basename "$rpm_file")"
    [[ "$(sha256_of "$rpm_file" | awk '{print $1}')" == "$(sha256_of "$payload_dir/rpms/$(basename "$rpm_file")" | awk '{print $1}')" ]] \
      || die "最终 .run 中 RPM 内容不一致：$(basename "$rpm_file")"
  done

  scan_report="$OUTPUT_DIR/${offline_name%.tar.gz}.scan.json"
  [[ -f "$scan_report" ]] || die '基础离线包缺少最终扫描报告'
  jq -e --arg digest "$(sha256_of "$offline_file" | awk '{print $1}')" \
    '.result == "PASS" and .input.sha256 == $digest' "$scan_report" >/dev/null \
    || die '最终扫描报告未通过或未绑定本次基础离线包'

  archive_listing="$payload_dir/offline-members.txt"
  tar -tzf "$offline_file" > "$archive_listing" || die '基础离线包目录无法读取'
  manifest_member="$(awk '/\/manifest\.json$/{print; exit}' "$archive_listing")"
  [[ -n "$manifest_member" ]] || die '基础离线包缺少 manifest.json'
  tar -xOf "$offline_file" "$manifest_member" > "$payload_dir/manifest.json"
  jq -e --arg version "$VERSION" \
    '.edition == "wdsp" and .version == $version and .arch == "amd64" and
     .delivery_mode == "production" and .signed == true and (.images | length) == 9 and
     any(.files[]; .path == "agents/wdsp-agent")' "$payload_dir/manifest.json" >/dev/null \
    || die '基础离线包 manifest 的版本、架构、签名、镜像或 Agent 清单不完整'
  required_images=(jiuzhang-server jiuzhang-web jiuzhang-gateway jiuzhang-netmgrd jiuzhang-logrotator postgres valkey clickhouse opentelemetry-collector-contrib)
  for image_name in "${required_images[@]}"; do
    grep -q "/images/${image_name}\.tar$" "$archive_listing" \
      || die "基础离线包缺少运行镜像：$image_name"
  done
  if grep -Eq '(^|/)(test|tests|__tests__|docs)(/|$)' "$archive_listing"; then
    die '基础离线包混入测试目录或产品文档目录'
  fi
  log_info "最终验收通过：签名、哈希、9 个运行镜像、Agent、${#packaged_rpms[@]} 个 RPM、内容扫描均有效"
  log_warn 'RPM 依赖闭包仍须在干净的目标 openEuler x86-64 测试机完成离线安装验收'
}

build_image() {
  local name="$1" dockerfile="$2" context="$3"
  log_info "构建 linux/${TARGET_ARCH} 运行镜像：${name}:${VERSION}"
  run_command docker buildx build --platform "linux/${TARGET_ARCH}" --load \
    -f "$dockerfile" -t "${name}:${VERSION}" "$context"
}

WORK_DIR=''
cleanup() {
  case "$WORK_DIR" in
    "${TMPDIR:-/tmp}"/wdsp-runtime-run.*) rm -rf "$WORK_DIR" ;;
    '') ;;
    *) log_warn "拒绝清理异常临时目录：$WORK_DIR" ;;
  esac
}
trap cleanup EXIT INT TERM HUP

if [[ "$DRY_RUN" == true ]]; then
  log_info "干运行：版本 ${VERSION}，目标 linux/${TARGET_ARCH}，输出 ${OUTPUT_DIR}"
  AGENT_BINARY="$OUTPUT_DIR/.build/wdsp-agent"
else
  [[ ! -e "$OUTPUT_DIR" ]] || die "输出目录已存在，为避免覆盖请使用新的 --output：$OUTPUT_DIR"
  mkdir -p "$OUTPUT_DIR"
  OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd -P)"
  preflight
  WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/wdsp-runtime-run.XXXXXX")"
  AGENT_BINARY="$WORK_DIR/wdsp-agent"
  SOURCE_SNAPSHOT_BEFORE="$(source_snapshot)"
fi

cd "$REPO_ROOT"
build_image 'jiuzhang-server' 'server/Dockerfile' '.'
build_image 'jiuzhang-web' 'web/Dockerfile' 'web'
build_image 'jiuzhang-gateway' 'gateway/Dockerfile' 'gateway'
build_image 'jiuzhang-netmgrd' 'gateway/images/netmgrd/Dockerfile' 'gateway'
build_image 'jiuzhang-logrotator' 'gateway/images/logrotator/Dockerfile' 'gateway/images/logrotator'

log_info "构建 linux/${TARGET_ARCH} WDSP Agent"
AGENT_LDFLAGS="-s -w -X main.version=${VERSION}"
if [[ "$DRY_RUN" == true ]]; then
  print_command env CGO_ENABLED=0 GOOS=linux GOARCH="$TARGET_ARCH" GOAMD64=v1 \
    go build -trimpath -ldflags "$AGENT_LDFLAGS" -o "$AGENT_BINARY" ./cmd/agent
else
  (
    cd "$REPO_ROOT/wdsp-agent"
    env CGO_ENABLED=0 GOOS=linux GOARCH="$TARGET_ARCH" GOAMD64=v1 \
      go build -trimpath -ldflags "$AGENT_LDFLAGS" -o "$AGENT_BINARY" ./cmd/agent
  )
  file "$AGENT_BINARY" | grep -q 'ELF 64-bit.*x86-64' \
    || die '生成的 WDSP Agent 不是 linux/amd64 ELF 二进制'
fi

export WDSP_AGENT_BINARY="$AGENT_BINARY"
log_info '调用正式签名 .run 包装器（运行时裁剪、镜像历史清理、完整性校验由其执行）...'
run_command bash "$RUN_BUILDER" --version "$VERSION" --output "$OUTPUT_DIR" --rpm-dir "$RPM_DIR"

if [[ "$DRY_RUN" == true ]]; then
  log_info '干运行完成：未构建镜像、未创建输出目录。'
else
  SOURCE_SNAPSHOT_AFTER="$(source_snapshot)"
  [[ "$SOURCE_SNAPSHOT_AFTER" == "$SOURCE_SNAPSHOT_BEFORE" ]] \
    || die '构建期间源码或工作区状态发生变化，拒绝交付；请确认变更后重新打包'
  verify_delivery
  log_info "打包完成：$OUTPUT_DIR/jiuzhang-wdsp-openeuler-zhaoxin-${VERSION}-amd64.run"
fi
