#!/usr/bin/env bash
# backup.sh —— 九章 WDSP 裸机版备份脚本（root 执行）。
#
# 产物：<安装根>/backups/jiuzhang-wdsp-baremetal-<时间戳>.tar.gz（0600）
# 内容：db.sql.gz（PostgreSQL 逻辑备份）、env（含口令，恢复必需，归档整体 0600 管控）、
#       data-caddy/（网关 autosave）、runtime-{license,geoip,certificates,configs}/、
#       data-valkey/（先 BGREWRITEAOF 再拷）、console-certificates/（控制台证书）、
#       MANIFEST.txt（时间/主机/各文件 sha256+字节数；不含口令明文）。
# 排除：data/pgdata（以 db.sql.gz 代替）、data/logs、data/runtime/backups、
#       data/runtime/upgrade-packages、data/runtime/netdiag。
#
# 用法：sudo bash <安装根>/ops/backup.sh
# 建议 crontab 每日执行（见 README.md）。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
case "${SCRIPT_DIR}" in
  */ops) R_DEFAULT="$(cd "${SCRIPT_DIR}/.." && pwd)" ;;
  *)     R_DEFAULT="${SCRIPT_DIR}" ;;
esac
R="${INSTALL_ROOT:-${R_DEFAULT}}"
R="${R%/}"
ENV_FILE="${R}/env"
PG_LD="${R}/bin/pg/syslib:${R}/bin/pg/lib/postgresql/16/lib"
PG_OSSL="${R}/bin/pg/syslib/ossl-modules"
PG_BIN="${R}/bin/pg/lib/postgresql/16/bin"

log_info() { printf '[INFO]  %s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }
log_warn() { printf '[WARN]  %s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_err()  { printf '[ERROR] %s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2; }
die() { log_err "${1:-未知错误}"; exit "${2:-1}"; }

env_get() {
  local line
  line="$(grep -E "^$1=" "${ENV_FILE}" 2>/dev/null | tail -n 1 || true)"
  printf '%s' "${line#*=}"
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@";
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$@";
  else die "缺少 sha256sum/shasum"; fi
}

[[ "$(id -u)" == "0" ]] || die "请以 root 执行"
[[ -f "${ENV_FILE}" ]] || die "未找到 ${ENV_FILE}——安装根是否正确？（当前：${R}）"
for cmd in tar gzip; do
  command -v "${cmd}" >/dev/null 2>&1 || die "缺少必需命令：${cmd}"
done

PG_PW="$(env_get POSTGRES_PASSWORD)"
VK_PW="$(env_get VALKEY_PASSWORD)"
[[ -n "${PG_PW}" ]] || die "${ENV_FILE} 缺少 POSTGRES_PASSWORD"

TS="$(date '+%Y%m%d-%H%M%S')"
OUT_DIR="${R}/backups"
OUT="${OUT_DIR}/jiuzhang-wdsp-baremetal-${TS}.tar.gz"
umask 077
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
install -d -m 0700 -o root -g root "${OUT_DIR}"

log_info "备份目标：${OUT}"

# ---------- 1. PostgreSQL 逻辑备份 ----------
log_info "[1/6] pg_dump jiuzhang_waf"
env LD_LIBRARY_PATH="${PG_LD}" OPENSSL_MODULES="${PG_OSSL}" PGPASSWORD="${PG_PW}" \
  "${PG_BIN}/pg_dump" -h 127.0.0.1 -U jiuzhang -d jiuzhang_waf \
  --no-owner --no-privileges | gzip > "${WORK}/db.sql.gz"
[[ -s "${WORK}/db.sql.gz" ]] || die "pg_dump 产物为空"

# ---------- 2. env（含密，恢复必需） ----------
log_info "[2/6] env（含口令/主密钥，归档 0600 管控）"
cp -a "${ENV_FILE}" "${WORK}/env"

# ---------- 3. 网关 autosave ----------
log_info "[3/6] data/caddy（网关 autosave）"
if [[ -d "${R}/data/caddy" ]]; then
  cp -a "${R}/data/caddy" "${WORK}/data-caddy"
else
  log_warn "目录不存在，跳过：${R}/data/caddy"
fi

# ---------- 4. runtime 关键子目录 ----------
log_info "[4/6] data/runtime/{license,geoip,certificates,configs}"
for d in license geoip certificates configs; do
  if [[ -d "${R}/data/runtime/${d}" ]]; then
    cp -a "${R}/data/runtime/${d}" "${WORK}/runtime-${d}"
  else
    log_warn "目录不存在，跳过：${R}/data/runtime/${d}"
  fi
done

# ---------- 5. 控制台证书 ----------
log_info "[5/6] certificates（控制台证书）"
if [[ -d "${R}/certificates" ]]; then
  cp -a "${R}/certificates" "${WORK}/console-certificates"
fi

# ---------- 6. Valkey（先 BGREWRITEAOF 再拷） ----------
log_info "[6/6] data/valkey（BGREWRITEAOF 后拷贝）"
if [[ -n "${VK_PW}" ]] && [[ -d "${R}/data/valkey" ]]; then
  if env REDISCLI_AUTH="${VK_PW}" "${R}/bin/valkey/valkey-cli" BGREWRITEAOF >/dev/null 2>&1; then
    _vk_waited=0
    while (( _vk_waited < 60 )); do
      if env REDISCLI_AUTH="${VK_PW}" "${R}/bin/valkey/valkey-cli" INFO persistence 2>/dev/null \
         | tr -d '\r' | grep -qx 'aof_rewrite_in_progress:0'; then
        break
      fi
      sleep 1
      _vk_waited=$((_vk_waited + 1))
    done
    if (( _vk_waited >= 60 )); then
      log_warn "等待 Valkey BGREWRITEAOF 完成超时（60s），继续拷贝现有文件"
    fi
    unset _vk_waited
  else
    log_warn "BGREWRITEAOF 未成功（Valkey 未运行？），直接拷贝现有文件"
  fi
  cp -a "${R}/data/valkey" "${WORK}/data-valkey"
else
  log_warn "跳过 Valkey 备份（无口令或目录不存在）"
fi

# ---------- MANIFEST ----------
log_info "生成 MANIFEST.txt"
{
  echo "九章 WDSP 裸机版备份"
  echo "时间: $(date '+%Y-%m-%d %H:%M:%S %z')"
  echo "主机: $(hostname 2>/dev/null || echo unknown)"
  echo "安装根: ${R}"
  echo "敏感级别: 含密（env 含数据库/Valkey 口令与 JIUZHANG_MASTER_KEY；data-valkey/valkey.conf 含 requirepass）——归档整体 0600，请妥善保管"
  echo "内容: db.sql.gz env data-caddy/ runtime-{license,geoip,certificates,configs}/ data-valkey/ console-certificates/"
  echo "排除: data/pgdata(以 db.sql.gz 代替) data/logs data/runtime/backups data/runtime/upgrade-packages data/runtime/netdiag"
  echo ""
  echo "文件清单（sha256  字节数  相对路径）:"
  (cd "${WORK}" && find . -type f ! -name MANIFEST.txt | LC_ALL=C sort | while IFS= read -r f; do
    h="$(sha256_of "${f}" | awk '{print $1}')"
    s="$(stat -c%s "${f}" 2>/dev/null || stat -f%z "${f}")"
    printf '%s  %s  %s\n' "${h}" "${s}" "${f#./}"
  done)
} > "${WORK}/MANIFEST.txt"

# ---------- 打包 ----------
tar -czf "${OUT}" -C "${WORK}" .
chmod 600 "${OUT}"
SIZE="$(stat -c%s "${OUT}" 2>/dev/null || stat -f%z "${OUT}")"
log_info "备份完成：${OUT}（${SIZE} 字节）"
log_info "恢复：sudo bash ${R}/ops/restore.sh --from ${OUT}"
