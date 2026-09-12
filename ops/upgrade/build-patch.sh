#!/usr/bin/env bash
# 构建只含发生变化组件的运行时小补丁包；不包含源码和基础设施镜像。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

usage() {
  printf '%s\n' \
    '用法: build-patch.sh --from X.Y.Z --to X.Y.N [--arch amd64|arm64] [--output-dir DIR]' \
    '' \
    '仅允许同一主、次版本内的 Bug 修复版本递增。' \
    '包内只包含 jiuzhang-server 与 jiuzhang-web 两个运行时镜像。'
}

FROM_VERSION=""
TO_VERSION=""
ARCH="amd64"
OUTPUT_DIR="$REPO_ROOT/dist"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --from) FROM_VERSION="${2:-}"; shift 2 ;;
    --to) TO_VERSION="${2:-}"; shift 2 ;;
    --arch) ARCH="${2:-}"; shift 2 ;;
    --output-dir) OUTPUT_DIR="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) printf '未知参数: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ "$FROM_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { printf '%s\n' '--from 不是有效版本号' >&2; exit 2; }
[[ "$TO_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { printf '%s\n' '--to 不是有效版本号' >&2; exit 2; }
[[ "$ARCH" == "amd64" || "$ARCH" == "arm64" ]] || { printf '%s\n' '--arch 仅支持 amd64 或 arm64' >&2; exit 2; }

IFS=. read -r from_major from_minor from_patch <<<"$FROM_VERSION"
IFS=. read -r to_major to_minor to_patch <<<"$TO_VERSION"
if [[ "$from_major" != "$to_major" || "$from_minor" != "$to_minor" || "$to_patch" -ne $((from_patch + 1)) ]]; then
  printf '小补丁只允许 Bug 修复版本递增一次: %s -> %s\n' "$FROM_VERSION" "$TO_VERSION" >&2
  exit 2
fi

for cmd in docker jq tar; do
  command -v "$cmd" >/dev/null 2>&1 || { printf '缺少必需命令: %s\n' "$cmd" >&2; exit 1; }
done

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

file_size() {
  stat -f%z "$1" 2>/dev/null || stat -c%s "$1"
}

SERVER_IMAGE="jiuzhang-server:$TO_VERSION"
WEB_IMAGE="jiuzhang-web:$TO_VERSION"
for image in "$SERVER_IMAGE" "$WEB_IMAGE"; do
  docker image inspect "$image" >/dev/null 2>&1 || { printf '本机不存在镜像: %s\n' "$image" >&2; exit 1; }
  image_arch="$(docker image inspect "$image" --format '{{.Architecture}}')"
  [[ "$image_arch" == "$ARCH" ]] || { printf '镜像 %s 架构为 %s，目标为 %s\n' "$image" "$image_arch" "$ARCH" >&2; exit 1; }
done

mkdir -p "$OUTPUT_DIR"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/jiuzhang-patch.XXXXXX")"
trap 'rm -rf "$work_dir"' EXIT
package_name="jiuzhang-wdsp-patch-${FROM_VERSION}-to-${TO_VERSION}-${ARCH}"
package_dir="$work_dir/$package_name"
mkdir -p "$package_dir/images" "$package_dir/installer"

install -m 0755 "$SCRIPT_DIR/install-executor.sh" "$package_dir/installer/install-executor.sh"
install -m 0755 "$SCRIPT_DIR/upgrade-executor.sh" "$package_dir/installer/upgrade-executor.sh"

printf '导出小补丁镜像: %s, %s\n' "$SERVER_IMAGE" "$WEB_IMAGE"
docker save -o "$package_dir/images/runtime-images.tar" "$SERVER_IMAGE" "$WEB_IMAGE"

server_id="$(docker image inspect "$SERVER_IMAGE" --format '{{.Id}}')"
web_id="$(docker image inspect "$WEB_IMAGE" --format '{{.Id}}')"
image_archive_sha="$(sha256_file "$package_dir/images/runtime-images.tar")"
image_archive_size="$(file_size "$package_dir/images/runtime-images.tar")"

jq -n \
  --arg from "$FROM_VERSION" \
  --arg to "$TO_VERSION" \
  --arg arch "$ARCH" \
  --arg server_image "$SERVER_IMAGE" \
  --arg server_id "$server_id" \
  --arg web_image "$WEB_IMAGE" \
  --arg web_id "$web_id" \
  --arg archive_sha "$image_archive_sha" \
  --argjson archive_size "$image_archive_size" \
  '{
    format_version: 1,
    package_type: "runtime-patch",
    product: "wdsp",
    version_from: $from,
    version_to: $to,
    architecture: $arch,
    change_type: "bugfix",
    components: [
      {service: "api", image: $server_image, image_id: $server_id},
      {service: "web", image: $web_image, image_id: $web_id}
    ],
    images_archive: {path: "images/runtime-images.tar", sha256: $archive_sha, size: $archive_size},
    excluded_components: ["gateway", "postgres", "valkey", "logrotator", "clickhouse", "otel-collector"],
    web_console: {
      upload_supported: true,
      apply_supported_by_version_1_0_0: false,
      apply_supported_from_version: "1.0.1",
      bootstrap_installer: "installer/install-executor.sh",
      note: "Run the bundled installer once on 1.0.0; Web upgrades use the host executor from 1.0.1 onward."
    }
  }' > "$package_dir/manifest.json"

(
  cd "$package_dir"
  printf '%s  %s\n' "$(sha256_file manifest.json)" manifest.json > SHA256SUMS
  printf '%s  %s\n' "$image_archive_sha" images/runtime-images.tar >> SHA256SUMS
  printf '%s  %s\n' "$(sha256_file installer/install-executor.sh)" installer/install-executor.sh >> SHA256SUMS
  printf '%s  %s\n' "$(sha256_file installer/upgrade-executor.sh)" installer/upgrade-executor.sh >> SHA256SUMS
)

archive="$OUTPUT_DIR/$package_name.tar.gz"
tar -C "$work_dir" -czf "$archive" "$package_name"
printf '%s  %s\n' "$(sha256_file "$archive")" "$(basename "$archive")" > "$archive.sha256"
printf '已生成: %s\n' "$archive"
