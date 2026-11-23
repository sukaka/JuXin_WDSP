#!/bin/bash
# assemble.sh —— 九章 WDSP 裸机安装包组装脚本（macOS 上运行，可重复执行）。
#
# 职责：构建前端 SPA + 刷新 dist/jiuzhang-wdsp-baremetal-linux-amd64/ 下除 bin/
# 以外的全部内容（bin/ 由 build-runtimes.sh / build-binaries.sh 产出，本脚本
# 【不删除 bin/】），最后打 tar.gz 并生成 .sha256 旁车。
#
# 用法：bash ops/baremetal/assemble.sh
# 前置：bin/ 下已具备 caddy / jiuzhang-api / netmgrd / logrotator.sh / pg/ / valkey/
# 兼容 macOS /bin/bash 3.2。
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PKG_SRC="${REPO_ROOT}/ops/baremetal/package"
DIST_PARENT="${REPO_ROOT}/dist"
PKG_NAME="jiuzhang-wdsp-baremetal-linux-amd64"
DIST_DIR="${DIST_PARENT}/${PKG_NAME}"
TARBALL="${DIST_PARENT}/${PKG_NAME}.tar.gz"

log_info() { printf '[INFO]  %s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }
log_err()  { printf '[ERROR] %s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2; }
die() { log_err "${1:-未知错误}"; exit "${2:-1}"; }

# ---------- 0. 前置检查：bin/ 半成品必须已就绪（保留，不删） ----------
log_info "==> [0/6] 前置检查（bin/ 半成品）"
for f in caddy jiuzhang-api netmgrd logrotator.sh; do
  [[ -f "${DIST_DIR}/bin/${f}" ]] || die "缺少 ${DIST_DIR}/bin/${f}——请先执行 ops/baremetal/build-binaries.sh"
done
[[ -x "${DIST_DIR}/bin/pg/lib/postgresql/16/bin/postgres" ]] || die "缺少 bin/pg 运行库——请先执行 ops/baremetal/build-runtimes.sh"
[[ -f "${DIST_DIR}/bin/valkey/valkey-server" ]] || die "缺少 bin/valkey 运行库——请先执行 ops/baremetal/build-runtimes.sh"
[[ -d "${PKG_SRC}" ]] || die "缺少包源目录 ${PKG_SRC}"
command -v npm >/dev/null 2>&1 || die "缺少 npm"

# ---------- 1. 构建前端 SPA ----------
log_info "==> [1/6] 构建管理前端（web/，npm ci + npm run build）"
(cd "${REPO_ROOT}/web" && npm ci --no-audit --no-fund && npm run build)
[[ -f "${REPO_ROOT}/web/dist/index.html" ]] || die "web 构建产物缺失：web/dist/index.html"

# ---------- 2. 清理非 bin 旧内容（绝不触碰 bin/） ----------
log_info "==> [2/6] 刷新包目录（保留 bin/）"
for item in web console gateway migrations assets geoip ops systemd tmpfiles.d \
            env.template install.sh uninstall.sh backup.sh restore.sh README.md; do
  rm -rf "${DIST_DIR:?}/${item}"
done

# ---------- 3. 拷贝动态内容（仓库构建/配置产物） ----------
log_info "==> [3/6] 汇集仓库产物"
cp -R "${REPO_ROOT}/web/dist" "${DIST_DIR}/web"

mkdir -p "${DIST_DIR}/gateway"
cp -R "${REPO_ROOT}/gateway/rules" "${DIST_DIR}/gateway/rules"
cp "${REPO_ROOT}/gateway/configs/blockpage.html" "${DIST_DIR}/gateway/blockpage.html"

cp -R "${REPO_ROOT}/server/migrations" "${DIST_DIR}/migrations"

mkdir -p "${DIST_DIR}/assets/fonts"
cp "${REPO_ROOT}/server/assets/fonts/NotoSansCJKsc-VF.ttf" "${DIST_DIR}/assets/fonts/"
cp "${REPO_ROOT}/server/assets/fonts/NotoSansCJKsc-Regular.otf" "${DIST_DIR}/assets/fonts/"

mkdir -p "${DIST_DIR}/geoip"
cp "${REPO_ROOT}/server/assets/geoip/ip2region_v4.xdb" "${DIST_DIR}/geoip/ip2region_v4.xdb"
cp "${REPO_ROOT}/web/public/assets/geo/city-ipv6.mmdb" "${DIST_DIR}/geoip/city-ipv6.mmdb"
cp "${REPO_ROOT}/web/public/assets/geo/country.mmdb" "${DIST_DIR}/geoip/country.mmdb"

# ops/：console-cert.sh 依赖 ops/lib/common.sh——拷入库并改写引用路径为包内相对位置
mkdir -p "${DIST_DIR}/ops/lib"
sed 's|source "$SCRIPT_DIR/../lib/common.sh"|source "$SCRIPT_DIR/lib/common.sh"|' \
  "${REPO_ROOT}/ops/install/console-cert.sh" > "${DIST_DIR}/ops/console-cert.sh"
grep -q 'source "$SCRIPT_DIR/lib/common.sh"' "${DIST_DIR}/ops/console-cert.sh" \
  || die "console-cert.sh 的 common.sh 引用路径改写失败"
cp "${REPO_ROOT}/ops/lib/fingerprint.sh" "${DIST_DIR}/ops/fingerprint.sh"
cp "${REPO_ROOT}/ops/lib/common.sh" "${DIST_DIR}/ops/lib/common.sh"

# ---------- 4. 拷贝静态包源（模板/单元/脚本/README） ----------
log_info "==> [4/6] 汇集包源（ops/baremetal/package/）"
# 注意：gateway/ 已在第 3 步创建（rules/blockpage），其模板须按文件拷入，
# 不能 cp -R 目录（目标已存在时会嵌套成 gateway/gateway）
for item in console env.template systemd tmpfiles.d \
            install.sh uninstall.sh backup.sh restore.sh README.md; do
  cp -R "${PKG_SRC}/${item}" "${DIST_DIR}/${item}"
done
cp "${PKG_SRC}/gateway/Caddyfile.bootstrap.template" \
  "${DIST_DIR}/gateway/Caddyfile.bootstrap.template"

# 可执行位与 macOS 杂物清理
chmod 755 "${DIST_DIR}/install.sh" "${DIST_DIR}/uninstall.sh" \
  "${DIST_DIR}/backup.sh" "${DIST_DIR}/restore.sh" \
  "${DIST_DIR}/ops/console-cert.sh" "${DIST_DIR}/ops/fingerprint.sh" \
  "${DIST_DIR}/bin/logrotator.sh"
find "${DIST_DIR}" -name '.DS_Store' -delete 2>/dev/null || true

# ---------- 5. 打包与旁车哈希 ----------
log_info "==> [5/6] 打包 ${TARBALL}"
rm -f "${TARBALL}" "${TARBALL}.sha256"
# COPYFILE_DISABLE=1：防止 macOS bsdtar 夹带 ._ AppleDouble 文件
(cd "${DIST_PARENT}" && COPYFILE_DISABLE=1 tar -czf "${TARBALL}" \
  --exclude='.DS_Store' "${PKG_NAME}")
(cd "${DIST_PARENT}" && shasum -a 256 "${PKG_NAME}.tar.gz" > "${PKG_NAME}.tar.gz.sha256")

# ---------- 6. 清单与体积 ----------
log_info "==> [6/6] 产物清单"
echo ""
echo "==> 包目录树（前两级）："
(cd "${DIST_DIR}" && find . -maxdepth 2 -mindepth 1 ! -path './bin/*' | LC_ALL=C sort \
  | sed 's|^\./|  |')
echo "  bin/（保留，未刷新）:"
(cd "${DIST_DIR}/bin" && ls -1 | sed 's/^/    /')
echo ""
echo "==> 体积："
du -sh "${DIST_DIR}" "${TARBALL}"
echo ""
echo "==> 旁车哈希："
cat "${TARBALL}.sha256"
echo ""
log_info "组装完成：${DIST_DIR}"
