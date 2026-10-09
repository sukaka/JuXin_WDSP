#!/bin/bash
# 九章 WDSP 裸机安装包 Go 二进制交叉构建脚本（linux/amd64）
#
# 目标机：openEuler x86_64（兆芯 KX/KH 等信创 CPU，无 AVX2），因此必须 GOAMD64=v1。
# 构建口径与容器镜像正式构建一致：
#   - bin/jiuzhang-api：与 server/Dockerfile 第 43 行一致（无 build tags）；
#   - bin/caddy：与 gateway/Dockerfile 第 46-50 行一致（xcaddy 构建，xcaddy v0.4.5
#     非 debug 模式默认即带 -trimpath -ldflags "-w -s"）；
#   - bin/netmgrd：gateway/cmd/netmgrd，纯标准库；
#   - bin/logrotator.sh：复制 gateway/images/logrotator/rotate.sh。
#
# 本脚本幂等，可重复执行：每次构建前先删除 bin/ 下对应产物再重建。
# 兼容 macOS /bin/bash 3.2（不使用关联数组等 bash4 特性）。
set -euo pipefail

# ---------- 版本锁定（与 server/Dockerfile、gateway/Dockerfile、docs/DEPENDENCIES.md 保持一致） ----------
CADDY_VERSION=v2.11.4
XCADDY_VERSION=v0.4.5
CORAZA_CADDY_VERSION=v2.5.0

# ---------- 交叉编译参数（目标 linux/amd64，GOAMD64=v1 锁定 x86-64 v1 基线） ----------
export CGO_ENABLED=0
export GOOS=linux
export GOARCH=amd64
export GOAMD64=v1
# Go 模块代理：保证国内可重复构建
export GOPROXY=https://goproxy.cn,direct

LDFLAGS="-s -w"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN_DIR="${REPO_ROOT}/dist/jiuzhang-wdsp-baremetal-linux-amd64/bin"
XCADDY_BIN="$(go env GOPATH)/bin/xcaddy"

command -v go >/dev/null 2>&1 || { echo "错误：未找到 go 工具链" >&2; exit 1; }

mkdir -p "${BIN_DIR}"

echo "==> 构建目标：linux/amd64 GOAMD64=${GOAMD64} CGO_ENABLED=${CGO_ENABLED}"
echo "==> 产物目录：${BIN_DIR}"

# ---------- 1. bin/jiuzhang-api（与 server/Dockerfile 第 43 行正式构建口径一致，不加 build tags） ----------
echo "==> [1/4] 构建 jiuzhang-api"
rm -f "${BIN_DIR}/jiuzhang-api"
(cd "${REPO_ROOT}/server" && go build -trimpath -ldflags="${LDFLAGS}" -o "${BIN_DIR}/jiuzhang-api" ./cmd/api)

# ---------- 2. bin/caddy（复刻 gateway/Dockerfile 第 46-50 行 xcaddy 构建） ----------
echo "==> [2/4] 安装 xcaddy@${XCADDY_VERSION}（本机宿主平台，仅为构建工具）"
# xcaddy 本身须为本机可执行，构建它的 go install 必须剥掉交叉编译环境变量；
# 交叉参数由 xcaddy 透传给底层构建 Caddy 的 go build。
env -u GOOS -u GOARCH -u GOAMD64 -u CGO_ENABLED \
    go install "github.com/caddyserver/xcaddy/cmd/xcaddy@${XCADDY_VERSION}"
"${XCADDY_BIN}" version

echo "==> [2/4] xcaddy 构建 caddy ${CADDY_VERSION}（模块下载量大，请耐心等待）"
rm -f "${BIN_DIR}/caddy"
"${XCADDY_BIN}" build "${CADDY_VERSION}" \
    --with "github.com/corazawaf/coraza-caddy/v2@${CORAZA_CADDY_VERSION}" \
    --with "github.com/jiuzhang-waf/gateway/dynamic_security=${REPO_ROOT}/gateway/dynamic_security" \
    --with "github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard=${REPO_ROOT}/gateway/modules/jiuzhang_guard" \
    --output "${BIN_DIR}/caddy"

# ---------- 3. bin/netmgrd ----------
echo "==> [3/4] 构建 netmgrd"
rm -f "${BIN_DIR}/netmgrd"
(cd "${REPO_ROOT}/gateway" && go build -trimpath -ldflags="${LDFLAGS}" -o "${BIN_DIR}/netmgrd" ./cmd/netmgrd)

# ---------- 4. bin/logrotator.sh ----------
echo "==> [4/4] 复制 logrotator.sh"
rm -f "${BIN_DIR}/logrotator.sh"
cp "${REPO_ROOT}/gateway/images/logrotator/rotate.sh" "${BIN_DIR}/logrotator.sh"
chmod +x "${BIN_DIR}/logrotator.sh"

# ---------- 产物清单与文件类型核验 ----------
echo ""
echo "==> 构建完成，产物清单："
ls -la "${BIN_DIR}"
echo ""
echo "==> 文件类型核验（Go 二进制应为 ELF 64-bit x86-64 statically linked）："
for name in jiuzhang-api caddy netmgrd logrotator.sh; do
    file "${BIN_DIR}/${name}"
done
