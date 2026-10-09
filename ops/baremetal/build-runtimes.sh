#!/bin/bash
# build-runtimes.sh —— 构建九章 WDSP 裸机安装包的「免系统安装」数据库运行时（linux/amd64）
#
# 产物（供目标机 openEuler 24.03 x86_64 直接运行，无需系统安装 PostgreSQL/Valkey）：
#   dist/jiuzhang-wdsp-baremetal-linux-amd64/bin/pg/
#     lib/postgresql/16/bin/   PostgreSQL 16 全部客户端与服务端二进制（真实文件）
#     lib/postgresql/16/lib/   PostgreSQL 插件与私有库（保留原符号链接结构）
#     share/postgresql/16/     扩展 SQL、timezonesets、字符集等数据文件
#     syslib/                  第三方依赖库闭包（ldd 解析，排除 glibc 家族，平铺；
#                              目标机 glibc 2.38 前向兼容供体 bookworm 的 2.36）
#     syslib/ossl-modules/     OpenSSL 3 providers（scram 的 EVP 调用需要 default provider）
#   dist/jiuzhang-wdsp-baremetal-linux-amd64/bin/valkey/
#     valkey-server.bin / valkey-cli.bin  musl 动态链接的真实二进制（alpine 供体）
#     lib/    musl 加载器 ld-musl-x86_64.so.1 与 ldd 依赖闭包（目标机不能用 glibc 加载器直跑 musl 二进制）
#     valkey-server / valkey-cli          POSIX sh 包装脚本：用 lib/ 内 musl 加载器显式加载同名 .bin
#     valkey-check-aof / valkey-check-rdb 同法包装（镜像内为 valkey-server 的符号链接，靠 argv[0] 区分模式，
#                                         故包装脚本用 musl 加载器 --argv0 透传工具名）
#
# 【为什么 pg 不是扁平的 bin/pg/{bin,share} 布局】
#   Debian 版 PostgreSQL 二进制并非任意可重定位：initdb/postgres 依据 /proc/self/exe 的真实路径，
#   按「编译期 bindir 与实际 exe 路径的尾部公共分量」推算 sharedir（实测 postgres:16.14-bookworm
#   amd64：扁平 <ROOT>/{bin,share} 布局一律回退编译期路径 /usr/share/postgresql/16 报
#   postgres.bki 缺失；<ROOT>/lib/postgresql/16/bin 布局则正确定位 <ROOT>/share/postgresql/16）。
#   因此本脚本保持 Debian 相对结构：lib/postgresql/16/{bin,lib} + share/postgresql/16，
#   任意安装根下免配置自定位 share。另：Debian 把 postgresql.conf.sample 做成指向上级的相对软链，
#   提取后会悬空，脚本在提取阶段将其替换为实体文件。
#   （时区：供体编译使用 --with-system-tzdata，运行期读目标机 /usr/share/zoneinfo，无需自带。）
#
# 运行方式约定（由 install/systemd 侧负责设置）：
#   PostgreSQL: LD_LIBRARY_PATH=<...>/pg/syslib:<...>/pg/lib/postgresql/16/lib
#               OPENSSL_MODULES=<...>/pg/syslib/ossl-modules
#               可执行文件 <...>/pg/lib/postgresql/16/bin/{postgres,initdb,psql,pg_ctl,...}
#   Valkey:     直接调用 bin/valkey/valkey-server、bin/valkey/valkey-cli 包装脚本即可，无需任何环境变量。
#
# 供体镜像与锁定方式（tag@sha256:<镜像索引 digest>；--platform linux/amd64 拉取时解析到 amd64 清单）：
#   PostgreSQL  postgres:16.14-bookworm（debian bookworm / glibc 2.36；不用 alpine 版——musl 与目标 glibc 不符）
#   Valkey      valkey/valkey:8.1.8-alpine（与 ops/offline-package/build.sh 的 VALKEY_IMAGE_AMD64 同一常量）
#   自检运行器  debian:bookworm-slim（glibc 环境模拟目标机，仅构建期使用，不进入产物）
#   升级任一组件时：修改 tag，并用 `docker buildx imagetools inspect <tag>` 取新索引 digest 写回本脚本默认值。
#
# 自检（每次构建自动执行，在 debian:bookworm-slim amd64 容器内挂载只读产物）：
#   PostgreSQL 完整流程：initdb → postgres 启动 → createdb → psql select version() / SET TIME ZONE /
#                        CREATE EXTENSION pgcrypto → pg_ctl stop（同时验证 syslib 闭包与 share 自定位）
#   Valkey 完整流程：    包装脚本 --version → 启动 → PING(PONG) → set/get 往返 → shutdown nosave，
#                        另验证 valkey-check-aof/rdb 的 argv[0] 分派
#
# 本脚本幂等，可重复执行：每次先删除 bin/pg、bin/valkey 再重建。
# 兼容 macOS /bin/bash 3.2（不使用关联数组等 bash4 特性；中文与变量相邻一律 ${VAR} 花括号）。
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${REPO_ROOT}/dist/jiuzhang-wdsp-baremetal-linux-amd64"
BIN_DIR="${OUT_DIR}/bin"
PG_DIR="${BIN_DIR}/pg"
VALKEY_DIR="${BIN_DIR}/valkey"

# ---------- 供体镜像（digest 锁定，见头部注释） ----------
POSTGRES_IMAGE="${POSTGRES_IMAGE:-postgres:16.14-bookworm@sha256:64154d0babcb1741988719e703419af0382b19953706149f9872fbd0f438efa8}"
VALKEY_IMAGE="${VALKEY_IMAGE:-valkey/valkey:8.1.8-alpine@sha256:94365b275456ae14621001c03556c732b1d93a0cdeacc317d1bdd52eba680885}"
SELF_CHECK_IMAGE="${SELF_CHECK_IMAGE:-debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251}"

log()  { printf '[build-runtimes] %s\n' "$*"; }
fail() { printf '[build-runtimes] 错误: %s\n' "$*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || fail "需要 Docker"
docker info >/dev/null 2>&1       || fail "Docker 守护进程未运行"

# ---------- 0. 幂等清理 ----------
log "清理旧产物：${PG_DIR}、${VALKEY_DIR}"
rm -rf "${PG_DIR}" "${VALKEY_DIR}"
mkdir -p "${PG_DIR}/lib/postgresql/16" "${PG_DIR}/share/postgresql" "${VALKEY_DIR}/lib"

# ---------- 1. PostgreSQL 16 ----------
log "[1/2] 拉取 PostgreSQL 供体镜像 ${POSTGRES_IMAGE}（linux/amd64）"
docker pull --platform linux/amd64 "${POSTGRES_IMAGE}" >/dev/null

CID="$(docker create --platform linux/amd64 "${POSTGRES_IMAGE}" true)"
trap 'docker rm -f "${CID}" >/dev/null 2>&1 || true' EXIT
log "拷贝 PostgreSQL bin/lib/share（保持 Debian 相对结构，见头部注释）"
docker cp "${CID}:/usr/lib/postgresql/16/bin"   "${PG_DIR}/lib/postgresql/16/bin"
docker cp "${CID}:/usr/lib/postgresql/16/lib"   "${PG_DIR}/lib/postgresql/16/lib"
docker cp "${CID}:/usr/share/postgresql/16"     "${PG_DIR}/share/postgresql/16"
docker rm -f "${CID}" >/dev/null 2>&1
trap - EXIT

log "计算 PostgreSQL 依赖库闭包（ldd，排除 glibc 家族）并修复悬空软链"
docker run --rm -i --platform linux/amd64 \
  -v "${PG_DIR}:/pg" "${POSTGRES_IMAGE}" bash -s <<'EOS'
set -euo pipefail
needs="$(mktemp)"
for f in /pg/lib/postgresql/16/bin/* /pg/lib/postgresql/16/lib/*.so /pg/lib/postgresql/16/lib/*.so.*; do
  [ -f "$f" ] || continue
  ldd "$f" 2>/dev/null || true
done | awk '/=> \//{print $3}' | sort -u > "$needs"
mkdir -p /pg/syslib
# 排除 glibc 家族（libc/libm/libdl/libpthread/librt/ld-linux/libresolv/libnss_*/libanl），
# 这些由目标机系统 glibc 提供（2.38 前向兼容 bookworm 的 2.36）。
while IFS= read -r lib; do
  base="$(basename "$lib")"
  case "$base" in
    libc.so.*|libm.so.*|libdl.so.*|libpthread.so.*|librt.so.*|ld-linux*|libresolv.so.*|libnss_*|libanl.so.*) continue ;;
  esac
  cp -L "$lib" /pg/syslib/
done < "$needs"
# OpenSSL 3 providers（scram 等 EVP 调用需要 default provider）
cp -rL /usr/lib/x86_64-linux-gnu/ossl-modules /pg/syslib/
# Debian 把个别 share 文件（postgresql.conf.sample）做成指向上级 /usr/share/postgresql/ 的相对软链，
# 提取后悬空：以供体内真实文件替换（解引用为实体）。
find /pg/share -type l | while IFS= read -r l; do
  if [ ! -e "$l" ]; then
    src="/usr/share/postgresql/16/${l#/pg/share/postgresql/16/}"
    rm -f "$l"
    cp -L "$src" "$l"
    echo "修复悬空软链: ${l#/pg/}"
  fi
done
echo "pg/syslib 文件数: $(ls /pg/syslib | wc -l)"
EOS
ls "${PG_DIR}/syslib/"*.so* >/dev/null 2>&1 || fail "PostgreSQL 依赖库闭包为空（syslib 缺失）"

log "PostgreSQL 完整流程自检（glibc 容器：initdb→启动→建库→查询→停库）"
PG_CHECK="$(mktemp -t jiuzhang-pg-selfcheck)"
cat > "${PG_CHECK}" <<'EOF'
#!/bin/sh
set -eu
LDP=/pg/syslib:/pg/lib/postgresql/16/lib
B=/pg/lib/postgresql/16/bin
mkdir -p /tmp/t /tmp/sock
chown -R nobody:nogroup /tmp/t /tmp/sock 2>/dev/null || chown -R nobody:nobody /tmp/t /tmp/sock
su -s /bin/sh nobody -c "LD_LIBRARY_PATH=$LDP $B/initdb -D /tmp/t/data -U jiuzhang --locale=C -E UTF-8 --auth-local=trust" >/dev/null
su -s /bin/sh nobody -c "LD_LIBRARY_PATH=$LDP exec $B/postgres -D /tmp/t/data -k /tmp/sock" >/tmp/t/server.log 2>&1 &
i=0
until su -s /bin/sh nobody -c "LD_LIBRARY_PATH=$LDP $B/pg_isready -h /tmp/sock" >/dev/null 2>&1; do
  i=$((i+1))
  if [ "$i" -gt 60 ]; then echo "FAIL: postgres 未就绪" >&2; tail -20 /tmp/t/server.log >&2; exit 1; fi
  sleep 1
done
su -s /bin/sh nobody -c "LD_LIBRARY_PATH=$LDP $B/createdb -h /tmp/sock -U jiuzhang jiuzhang_waf"
su -s /bin/sh nobody -c "LD_LIBRARY_PATH=$LDP $B/psql -h /tmp/sock -U jiuzhang -d jiuzhang_waf -X -q -v ON_ERROR_STOP=1 -c 'select version()' -c \"set time zone 'Asia/Shanghai'; select now()\" -c 'create extension pgcrypto' -c 'select gen_random_uuid()'"
su -s /bin/sh nobody -c "LD_LIBRARY_PATH=$LDP $B/pg_ctl stop -D /tmp/t/data -m fast" >/dev/null
echo "PG_SELFCHECK_OK"
EOF
docker run --rm --platform linux/amd64 \
  -v "${PG_DIR}:/pg:ro" -v "${PG_CHECK}:/selfcheck.sh:ro" \
  "${SELF_CHECK_IMAGE}" sh /selfcheck.sh \
  || { rm -f "${PG_CHECK}"; fail "PostgreSQL 完整流程自检失败"; }
rm -f "${PG_CHECK}"

# ---------- 2. Valkey 8 ----------
log "[2/2] 拉取 Valkey 供体镜像 ${VALKEY_IMAGE}（linux/amd64）"
docker pull --platform linux/amd64 "${VALKEY_IMAGE}" >/dev/null

CID="$(docker create --platform linux/amd64 "${VALKEY_IMAGE}" true)"
trap 'docker rm -f "${CID}" >/dev/null 2>&1 || true' EXIT
log "拷贝 valkey-server / valkey-cli 二进制（改名 .bin）与 ossl-modules"
docker cp "${CID}:/usr/local/bin/valkey-server" "${VALKEY_DIR}/valkey-server.bin"
docker cp "${CID}:/usr/local/bin/valkey-cli"    "${VALKEY_DIR}/valkey-cli.bin"
docker cp "${CID}:/usr/lib/ossl-modules"        "${VALKEY_DIR}/lib/ossl-modules"
docker rm -f "${CID}" >/dev/null 2>&1
trap - EXIT

log "提取 musl 加载器与 Valkey 依赖库闭包"
docker run --rm -i --platform linux/amd64 \
  -v "${VALKEY_DIR}:/v" "${VALKEY_IMAGE}" sh -s <<'EOS'
set -eu
needs="$(mktemp)"
for f in /v/valkey-server.bin /v/valkey-cli.bin; do
  ldd "$f" 2>/dev/null || true
done | awk '/=> \//{print $3}' | sort -u > "$needs"
while IFS= read -r lib; do
  [ -n "$lib" ] || continue
  cp -L "$lib" /v/lib/
done < "$needs"
# musl 加载器本体必拷（ldd 输出中不带 =>，需显式拷贝）
cp -L /lib/ld-musl-x86_64.so.1 /v/lib/
echo "valkey/lib 文件数: $(ls /v/lib | wc -l)"
EOS
[ -f "${VALKEY_DIR}/lib/ld-musl-x86_64.so.1" ] || fail "musl 加载器提取失败（valkey/lib 缺失 ld-musl-x86_64.so.1）"
# DT_NEEDED 名为 libc.musl-x86_64.so.1，musl 加载器自身可满足；补一个软链兜底
ln -sf ld-musl-x86_64.so.1 "${VALKEY_DIR}/lib/libc.musl-x86_64.so.1"

log "写入 POSIX sh 包装脚本"
for tool in valkey-server valkey-cli; do
  cat > "${VALKEY_DIR}/${tool}" <<'EOF'
#!/bin/sh
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$DIR/lib/ld-musl-x86_64.so.1" --library-path "$DIR/lib" "$DIR/$(basename "$0").bin" "$@"
EOF
done
# 镜像内 valkey-check-aof/rdb 是指向 valkey-server 的符号链接（按 argv[0] 切换模式），
# 用 musl 加载器 --argv0 透传工具名实现同等行为。
for tool in valkey-check-aof valkey-check-rdb; do
  cat > "${VALKEY_DIR}/${tool}" <<'EOF'
#!/bin/sh
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$DIR/lib/ld-musl-x86_64.so.1" --library-path "$DIR/lib" --argv0 "$DIR/$(basename "$0")" "$DIR/valkey-server.bin" "$@"
EOF
done
chmod +x "${VALKEY_DIR}/valkey-server" "${VALKEY_DIR}/valkey-cli" \
         "${VALKEY_DIR}/valkey-check-aof" "${VALKEY_DIR}/valkey-check-rdb" \
         "${VALKEY_DIR}/valkey-server.bin" "${VALKEY_DIR}/valkey-cli.bin"

log "Valkey 完整流程自检（glibc 容器：启动→PING→set/get→shutdown）"
VK_CHECK="$(mktemp -t jiuzhang-valkey-selfcheck)"
cat > "${VK_CHECK}" <<'EOF'
#!/bin/sh
set -eu
/valkey/valkey-server --version
/valkey/valkey-check-rdb 2>&1 | head -1
/valkey/valkey-check-aof 2>&1 | head -1
/valkey/valkey-server --port 7777 --dir /tmp --requirepass testpw --daemonize no >/tmp/valkey.log 2>&1 &
VKPID=$!
i=0
until /valkey/valkey-cli -p 7777 -a testpw --no-auth-warning ping 2>/dev/null | grep -q PONG; do
  i=$((i+1))
  if [ "$i" -gt 30 ]; then echo "FAIL: valkey 未就绪" >&2; tail -20 /tmp/valkey.log >&2; exit 1; fi
  sleep 1
done
echo "PING -> PONG"
/valkey/valkey-cli -p 7777 -a testpw --no-auth-warning set foo bar
GET=$(/valkey/valkey-cli -p 7777 -a testpw --no-auth-warning get foo)
[ "$GET" = "bar" ] || { echo "FAIL: get 往返异常: $GET" >&2; exit 1; }
echo "get foo -> $GET"
/valkey/valkey-cli -p 7777 -a testpw --no-auth-warning shutdown nosave 2>/dev/null || true
wait "$VKPID" 2>/dev/null || true
kill "$VKPID" 2>/dev/null || true
echo "VALKEY_SELFCHECK_OK"
EOF
docker run --rm --platform linux/amd64 \
  -v "${VALKEY_DIR}:/valkey:ro" -v "${VK_CHECK}:/selfcheck.sh:ro" \
  "${SELF_CHECK_IMAGE}" sh /selfcheck.sh \
  || { rm -f "${VK_CHECK}"; fail "Valkey 完整流程自检失败"; }
rm -f "${VK_CHECK}"

# ---------- 3. 产物汇总 ----------
pg_files="$(find "${PG_DIR}" -not -type d | wc -l | tr -d ' ')"
pg_size="$(du -sh "${PG_DIR}" | awk '{print $1}')"
pg_kb="$(du -sk "${PG_DIR}" | awk '{print $1}')"
vk_files="$(find "${VALKEY_DIR}" -not -type d | wc -l | tr -d ' ')"
vk_size="$(du -sh "${VALKEY_DIR}" | awk '{print $1}')"
vk_kb="$(du -sk "${VALKEY_DIR}" | awk '{print $1}')"

log "完成。产物汇总："
printf '  pg:     %s 个文件，%s（%s KiB）  %s\n' "${pg_files}" "${pg_size}" "${pg_kb}" "${PG_DIR}"
printf '  valkey: %s 个文件，%s（%s KiB）  %s\n' "${vk_files}" "${vk_size}" "${vk_kb}" "${VALKEY_DIR}"
