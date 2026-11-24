#!/usr/bin/env bash
# 九章 WDSP 分布式流量采集 Agent 全平台打包脚本
# 产出：
#   - CentOS / RHEL 系：.rpm (x86_64, aarch64)
#   - Debian / Ubuntu 系：.deb (amd64, arm64)
#   - macOS：.pkg（仅 macOS 宿主构建）+ .tar.gz (arm64, amd64)
#   - Windows：.zip (amd64, arm64，含 install-agent.ps1 / uninstall-agent.ps1)
#   - 校验与索引：SHA256SUMS + manifest.json
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
AGENT_SRC="$REPO_ROOT/wdsp-agent"

VERSION="2.4.0"
OUTPUT_DIR=""
PLATFORMS="linux,darwin,windows"

usage() {
  cat <<'EOF'
用法:
  packaging/wdsp-agent/build-packages.sh [--version 2.4.0] [--output dist/agent-packages/2.4.0] [--platforms linux,darwin,windows]
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="${2:-}"; shift 2 ;;
    --output) OUTPUT_DIR="${2:-}"; shift 2 ;;
    --platforms) PLATFORMS="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "未知参数: $1" >&2; exit 1 ;;
  esac
done

[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.][A-Za-z0-9._-]+)?$ ]] || {
  echo "版本号格式非法: $VERSION" >&2
  exit 1
}

if [[ -z "$OUTPUT_DIR" ]]; then
  OUTPUT_DIR="$REPO_ROOT/dist/agent-packages/$VERSION"
fi
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/wdsp-agent-pkg.XXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT

has_platform() {
  [[ ",$PLATFORMS," == *",$1,"* ]]
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print tolower($1)}'
  else
    shasum -a 256 "$1" | awk '{print tolower($1)}'
  fi
}

file_size() {
  python3 -c 'import os,sys; print(os.path.getsize(sys.argv[1]))' "$1"
}

MANIFEST_ITEMS="$WORK_DIR/manifest_items.jsonl"
: > "$MANIFEST_ITEMS"

record_package() {
  local os="$1" distro="$2" arch="$3" fmt="$4" filepath="$5"
  local fname size sha
  fname="$(basename "$filepath")"
  size="$(file_size "$filepath")"
  sha="$(sha256_file "$filepath")"
  python3 - "$os" "$distro" "$arch" "$fmt" "$fname" "$size" "$sha" >> "$MANIFEST_ITEMS" <<'PY'
import json, sys
os_name, distro, arch, fmt, fname, size, sha = sys.argv[1:]
print(json.dumps({
    "os": os_name,
    "distro": distro,
    "arch": arch,
    "format": fmt,
    "filename": fname,
    "size": int(size),
    "sha256": sha,
}, ensure_ascii=False))
PY
  printf '[build-packages] 产出: %s (%s bytes, sha256=%s)\n' "$fname" "$size" "${sha:0:12}..."
}

build_binary() {
  local goos="$1" goarch="$2" out="$3"
  (
    cd "$AGENT_SRC"
    if [[ "$goarch" == "amd64" ]]; then
      env CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" GOAMD64=v1 \
        go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o "$out" ./cmd/agent
    else
      env CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
        go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o "$out" ./cmd/agent
    fi
  )
}

# 1. Linux (.rpm + .deb)
if has_platform "linux"; then
  for arch in amd64 arm64; do
    bin="$WORK_DIR/wdsp-agent-linux-$arch"
    build_binary linux "$arch" "$bin"

    rpm_arch="x86_64"
    [[ "$arch" == "arm64" ]] && rpm_arch="aarch64"
    rpm_out="$OUTPUT_DIR/wdsp-agent-${VERSION}-1.${rpm_arch}.rpm"
    python3 "$SCRIPT_DIR/tools/build_rpm.py" \
      --binary "$bin" --version "$VERSION" --release 1 --arch "$rpm_arch" --output "$rpm_out"
    record_package linux rpm "$arch" rpm "$rpm_out"

    deb_out="$OUTPUT_DIR/wdsp-agent_${VERSION}_${arch}.deb"
    python3 "$SCRIPT_DIR/tools/build_deb.py" \
      --binary "$bin" --version "$VERSION" --arch "$arch" --output "$deb_out"
    record_package linux deb "$arch" deb "$deb_out"
  done
fi

# 2. macOS (.tar.gz + 本机 macOS 上的原生 .pkg)
if has_platform "darwin"; then
  for arch in arm64 amd64; do
    bin="$WORK_DIR/wdsp-agent-darwin-$arch"
    build_binary darwin "$arch" "$bin"

    # .tar.gz（跨平台可构建）
    stage_tgz="$WORK_DIR/darwin-tgz-$arch/wdsp-agent-${VERSION}-darwin-${arch}"
    mkdir -p "$stage_tgz"
    cp "$bin" "$stage_tgz/wdsp-agent"
    chmod 0755 "$stage_tgz/wdsp-agent"
    cp "$SCRIPT_DIR/scripts/install-agent.sh" "$stage_tgz/install-agent.sh"
    chmod 0755 "$stage_tgz/install-agent.sh"
    tgz_out="$OUTPUT_DIR/wdsp-agent-${VERSION}-darwin-${arch}.tar.gz"
    COPYFILE_DISABLE=1 tar -C "$WORK_DIR/darwin-tgz-$arch" -czf "$tgz_out" "wdsp-agent-${VERSION}-darwin-${arch}"
    record_package darwin darwin "$arch" targz "$tgz_out"

    # 原生 .pkg（仅 macOS 构建机具备 pkgbuild）
    if [[ "$(uname -s)" == "Darwin" ]] && command -v pkgbuild >/dev/null 2>&1; then
      pkg_root="$WORK_DIR/darwin-pkg-root-$arch"
      pkg_scripts="$WORK_DIR/darwin-pkg-scripts-$arch"
      mkdir -p "$pkg_root/usr/local/bin" "$pkg_scripts"
      cp "$bin" "$pkg_root/usr/local/bin/wdsp-agent"
      chmod 0755 "$pkg_root/usr/local/bin/wdsp-agent"
      cat > "$pkg_scripts/postinstall" <<'POSTINST'
#!/bin/sh
set -e
install -d -m 0700 "/Library/Application Support/WDSPAgent" "/Library/Application Support/WDSPAgent/state"
install -d -m 0750 "/Library/Logs/WDSPAgent"
exit 0
POSTINST
      chmod 0755 "$pkg_scripts/postinstall"
      pkg_out="$OUTPUT_DIR/wdsp-agent-${VERSION}-darwin-${arch}.pkg"
      pkgbuild \
        --root "$pkg_root" \
        --scripts "$pkg_scripts" \
        --identifier "com.jiuzhang.wdsp-agent" \
        --version "$VERSION" \
        --install-location "/" \
        "$pkg_out" >/dev/null
      record_package darwin darwin "$arch" pkg "$pkg_out"
    fi
  done
fi

# 3. Windows (.zip 含 wdsp-agent.exe + PowerShell 安装/卸载脚本)
if has_platform "windows"; then
  for arch in amd64 arm64; do
    bin="$WORK_DIR/wdsp-agent-windows-$arch.exe"
    build_binary windows "$arch" "$bin"

    stage_win="$WORK_DIR/win-$arch/wdsp-agent-${VERSION}-windows-${arch}"
    mkdir -p "$stage_win"
    cp "$bin" "$stage_win/wdsp-agent.exe"
    cp "$SCRIPT_DIR/scripts/install-agent.ps1" "$stage_win/install-agent.ps1"
    cp "$SCRIPT_DIR/scripts/uninstall-agent.ps1" "$stage_win/uninstall-agent.ps1"
    cat > "$stage_win/README.txt" <<EOF
JiuZhang WDSP Distributed Traffic Agent v${VERSION} (Windows ${arch})

快速安装（请以管理员身份运行 PowerShell）:
  \$env:WDSP_ENROLL_TOKEN = "wdt_<一次性注册令牌>"
  .\install-agent.ps1 -Server "https://<WDSP管理面地址>" -LocalPackage ".\wdsp-agent-${VERSION}-windows-${arch}.zip"

卸载:
  .\uninstall-agent.ps1           # 保留配置与证书
  .\uninstall-agent.ps1 -Purge    # 彻底清理全部配置、证书与缓存

抓包说明:
  1. 生产环境推荐宿主机自行安装 Npcap（不随本包分发），Agent 将自动加载 System32\Npcap\wpcap.dll 进行纯旁路只读抓包。
  2. 未安装 Npcap 时，Agent 自动回退至 Windows 原生 IPv4 Raw Socket（仅 IPv4，受本机防火墙策略影响）。
EOF

    zip_out="$OUTPUT_DIR/wdsp-agent-${VERSION}-windows-${arch}.zip"
    rm -f "$zip_out"
    python3 - "$stage_win" "$zip_out" <<'PY'
import os, sys, zipfile
src_dir, dst_zip = sys.argv[1], sys.argv[2]
base_parent = os.path.dirname(src_dir)
with zipfile.ZipFile(dst_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
    for root, _, files in os.walk(src_dir):
        for fn in sorted(files):
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, base_parent)
            zf.write(full, rel)
PY
    record_package windows windows "$arch" zip "$zip_out"
  done
fi

# 4. 生成 manifest.json 与 SHA256SUMS
BUILT_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
python3 - "$VERSION" "$BUILT_AT" "$MANIFEST_ITEMS" "$OUTPUT_DIR/manifest.json" "$OUTPUT_DIR/SHA256SUMS" <<'PY'
import json, sys
version, built_at, items_path, manifest_path, sums_path = sys.argv[1:]
packages = []
with open(items_path, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if line:
            packages.append(json.loads(line))
packages.sort(key=lambda x: (x["os"], x["distro"], x["arch"], x["format"]))
manifest = {
    "version": version,
    "built_at": built_at,
    "packages": packages,
}
with open(manifest_path, "w", encoding="utf-8") as f:
    json.dump(manifest, f, ensure_ascii=False, indent=2)
    f.write("\n")
with open(sums_path, "w", encoding="utf-8") as f:
    for p in packages:
        f.write(f"{p['sha256']}  {p['filename']}\n")
PY

printf '[build-packages] 全部产物已生成于: %s\n' "$OUTPUT_DIR"
