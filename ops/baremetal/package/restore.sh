#!/usr/bin/env bash
# restore.sh —— 九章 WDSP 裸机版恢复脚本（root 执行）。
#
# 用法：
#   sudo bash <安装根>/ops/restore.sh --from <备份.tar.gz> [--yes] [--force-env]
#
# 流程：执行前自动先跑一次 backup.sh 兜底（失败仅提示）→ 停 web/api 等服务 →
#   恢复 env（默认不覆盖现有 env，--force-env 才覆盖并留存 .pre-restore 备份）与
#   data 子目录（caddy、runtime/{license,geoip,certificates,configs}、valkey、
#   控制台 certificates）→ dropdb + createdb + psql 灌库 → 修属主/权限 →
#   起服务 → 健康等待。
# JZ_SKIP_SYSTEMD=1 时跳过 systemctl 停/起与健康等待，打印手工指引。
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
RUN_USER="jiuzhang"
SKIP_SYSTEMD="${JZ_SKIP_SYSTEMD:-0}"
UNIT_START_ORDER="jiuzhang-postgres jiuzhang-valkey jiuzhang-gateway jiuzhang-api jiuzhang-web jiuzhang-netmgrd jiuzhang-mirrorcap jiuzhang-tproxyd jiuzhang-havipd jiuzhang-logrotator"
UNIT_STOP_ORDER="jiuzhang-web jiuzhang-api jiuzhang-netmgrd jiuzhang-mirrorcap jiuzhang-tproxyd jiuzhang-havipd jiuzhang-hasyncd jiuzhang-logrotator jiuzhang-gateway jiuzhang-valkey"

ARCHIVE=""
ASSUME_YES=0
FORCE_ENV=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --from)      ARCHIVE="$2"; shift 2 ;;
    --yes|-y)    ASSUME_YES=1; shift ;;
    --force-env) FORCE_ENV=1; shift ;;
    -h|--help)   grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) printf '[ERROR] 未知参数：%s\n' "$1" >&2; exit 2 ;;
  esac
done

log_info() { printf '[INFO]  %s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }
log_warn() { printf '[WARN]  %s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_err()  { printf '[ERROR] %s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2; }
die() { log_err "${1:-未知错误}"; exit "${2:-1}"; }

env_get() {
  local line
  line="$(grep -E "^$1=" "${ENV_FILE}" 2>/dev/null | tail -n 1 || true)"
  printf '%s' "${line#*=}"
}

[[ "$(id -u)" == "0" ]] || die "请以 root 执行"
[[ -n "${ARCHIVE}" ]] || die "用法：restore.sh --from <备份.tar.gz> [--yes] [--force-env]"
[[ -f "${ARCHIVE}" ]] || die "备份文件不存在：${ARCHIVE}"
[[ -d "${R}/bin" ]] || die "安装根不完整（缺少 bin/）：${R}"
for cmd in tar gzip gunzip curl; do
  command -v "${cmd}" >/dev/null 2>&1 || die "缺少必需命令：${cmd}"
done

# ---------- 0. 执行前兜底备份（失败仅提示） ----------
log_info "[0/7] 恢复前兜底备份"
if [[ -f "${R}/ops/backup.sh" ]]; then
  bash "${R}/ops/backup.sh" || log_warn "兜底备份失败（仅提示，继续恢复流程）"
else
  log_warn "未找到 ${R}/ops/backup.sh，跳过兜底备份"
fi

# ---------- 确认 ----------
if [[ "${ASSUME_YES}" != "1" ]]; then
  printf '即将用 %s 覆盖恢复 %s 的配置与数据，确认继续？[y/N] ' "${ARCHIVE}" "${R}"
  read -r ans
  [[ "${ans}" == "y" || "${ans}" == "Y" || "${ans}" == "yes" ]] || { log_info "已取消"; exit 0; }
fi

# ---------- 1. 安全校验并解包 + MANIFEST.txt SHA-256 校验 ----------
log_info "[1/7] 安全校验并解包备份"
umask 077
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
if command -v python3 >/dev/null 2>&1; then
  python3 - "${ARCHIVE}" "${WORK}" <<'PY' || die "备份归档安全校验或解压失败"
import os, pathlib, sys, tarfile
archive, dest = sys.argv[1:]
root = pathlib.Path(dest).resolve()
with tarfile.open(archive, "r:gz") as tf:
    members = tf.getmembers()
    if not members:
        raise SystemExit("备份归档为空")
    for m in members:
        rel = pathlib.PurePosixPath(m.name)
        if rel.is_absolute() or ".." in rel.parts:
            raise SystemExit(f"备份归档含非法路径: {m.name}")
        if not (m.isdir() or m.isfile()):
            raise SystemExit(f"备份归档含不允许的符号链接、硬链接或特殊文件: {m.name}")
        target = (root / rel).resolve()
        if root != target and root not in target.parents:
            raise SystemExit(f"备份归档路径越界: {m.name}")
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
else
  # 无 python3 时使用 tar -tzvf 逐条校验文件类型与路径安全，禁止绝对路径/..与非普通文件/目录
  while IFS= read -r entry_line; do
    entry_type="${entry_line:0:1}"
    case "${entry_type}" in
      -|d) ;;
      *) die "备份归档含不允许的链接或特殊文件条目: ${entry_line}" ;;
    esac
  done < <(tar -tzvf "${ARCHIVE}")
  while IFS= read -r entry_name; do
    case "${entry_name}" in
      /*|*../*|*/..|..) die "备份归档含不安全路径: ${entry_name}" ;;
    esac
  done < <(tar -tzf "${ARCHIVE}")
  tar --no-same-owner --no-same-permissions -xzf "${ARCHIVE}" -C "${WORK}"
fi
[[ -f "${WORK}/MANIFEST.txt" && ! -L "${WORK}/MANIFEST.txt" ]] || die "备份内缺少 MANIFEST.txt（非本包备份产物？）"
[[ -f "${WORK}/db.sql.gz" && ! -L "${WORK}/db.sql.gz" ]] || die "备份内缺少 db.sql.gz"

verify_manifest() {
  local work="$1"
  local sha size rel f actual_sha actual_size checked=0 listed_tmp actual_tmp
  listed_tmp="$(mktemp)"
  actual_tmp="$(mktemp)"
  while IFS= read -r line; do
    if [[ "${line}" =~ ^([0-9a-fA-F]{64})[[:space:]]{2}([0-9]+)[[:space:]]{2}(.+)$ ]]; then
      sha="$(printf '%s' "${BASH_REMATCH[1]}" | tr 'A-F' 'a-f')"
      size="${BASH_REMATCH[2]}"
      rel="${BASH_REMATCH[3]}"
      case "${rel}" in
        /*|*../*|*/..|..|MANIFEST.txt) rm -f "${listed_tmp}" "${actual_tmp}"; die "MANIFEST.txt 含非法路径: ${rel}" ;;
      esac
      f="${work}/${rel}"
      if [[ ! -f "${f}" || -L "${f}" ]]; then
        rm -f "${listed_tmp}" "${actual_tmp}"
        die "MANIFEST.txt 声明的文件缺失或为符号链接: ${rel}"
      fi
      actual_size="$(stat -c%s "${f}" 2>/dev/null || stat -f%z "${f}")"
      if [[ "${actual_size}" != "${size}" ]]; then
        rm -f "${listed_tmp}" "${actual_tmp}"
        die "备份文件大小不符: ${rel}（期望 ${size}，实际 ${actual_size}）"
      fi
      if command -v sha256sum >/dev/null 2>&1; then
        actual_sha="$(sha256sum "${f}" | awk '{print $1}')"
      else
        actual_sha="$(shasum -a 256 "${f}" | awk '{print $1}')"
      fi
      if [[ "${actual_sha}" != "${sha}" ]]; then
        rm -f "${listed_tmp}" "${actual_tmp}"
        die "备份文件 SHA-256 校验失败: ${rel}"
      fi
      printf '%s\n' "${rel}" >> "${listed_tmp}"
      checked=$((checked + 1))
    fi
  done < "${work}/MANIFEST.txt"
  if (( checked == 0 )); then
    rm -f "${listed_tmp}" "${actual_tmp}"
    die "MANIFEST.txt 缺少有效文件校验清单，拒绝恢复"
  fi
  LC_ALL=C sort -u "${listed_tmp}" -o "${listed_tmp}"
  (cd "${work}" && find . -type f ! -name MANIFEST.txt | sed 's|^\./||' | LC_ALL=C sort) > "${actual_tmp}"
  if ! cmp -s "${listed_tmp}" "${actual_tmp}"; then
    rm -f "${listed_tmp}" "${actual_tmp}"
    die "备份内存在未在 MANIFEST.txt 声明的额外文件，拒绝恢复"
  fi
  rm -f "${listed_tmp}" "${actual_tmp}"
  log_info "MANIFEST.txt SHA-256 完整性校验通过（${checked} 个文件）"
}
verify_manifest "${WORK}"

TS="$(date '+%Y%m%d-%H%M%S')"

# ---------- 2. 停服务（postgres 保持运行用于灌库） ----------
if [[ "${SKIP_SYSTEMD}" == "1" ]]; then
  log_warn "[2/7] JZ_SKIP_SYSTEMD=1：跳过 systemctl 停服——请确认服务已手工停止"
else
  log_info "[2/7] 停止服务（保留 jiuzhang-postgres）"
  for unit in ${UNIT_STOP_ORDER}; do
    systemctl stop "${unit}" 2>/dev/null || log_warn "停止 ${unit} 未成功（可能未运行），继续"
  done
fi

# ---------- 3. 恢复 env ----------
log_info "[3/7] 恢复 env"
if [[ -f "${WORK}/env" ]]; then
  if [[ -f "${ENV_FILE}" && "${FORCE_ENV}" != "1" ]]; then
    log_info "保留现有 ${ENV_FILE}（--force-env 可覆盖）"
  else
    if [[ -f "${ENV_FILE}" ]]; then
      cp -a "${ENV_FILE}" "${ENV_FILE}.pre-restore-${TS}"
    fi
    cp -a "${WORK}/env" "${ENV_FILE}"
    log_info "已恢复 ${ENV_FILE}"
  fi
  chown root:"${RUN_USER}" "${ENV_FILE}"
  chmod 0640 "${ENV_FILE}"
else
  log_warn "备份内无 env，保持现状"
fi
PG_PW="$(env_get POSTGRES_PASSWORD)"
[[ -n "${PG_PW}" ]] || die "生效的 ${ENV_FILE} 缺少 POSTGRES_PASSWORD（无法灌库）"

# ---------- 4. 恢复 data 子目录 ----------
log_info "[4/7] 恢复 data 子目录"
PRE_DIR="${R}/data/.pre-restore-${TS}"
restore_dir() { # SRC_IN_WORK DST
  local src="$1" dst="$2"
  [[ -e "${src}" ]] || { log_warn "备份内无 $(basename "${src}")，跳过 ${dst}"; return 0; }
  mkdir -p "${PRE_DIR}"
  if [[ -e "${dst}" ]]; then
    mv "${dst}" "${PRE_DIR}/$(basename "${dst}")"
  fi
  cp -a "${src}" "${dst}"
  log_info "  已恢复 ${dst}"
}
restore_dir "${WORK}/data-caddy" "${R}/data/caddy"
restore_dir "${WORK}/data-valkey" "${R}/data/valkey"
restore_dir "${WORK}/runtime-license" "${R}/data/runtime/license"
restore_dir "${WORK}/runtime-geoip" "${R}/data/runtime/geoip"
restore_dir "${WORK}/runtime-certificates" "${R}/data/runtime/certificates"
restore_dir "${WORK}/runtime-configs" "${R}/data/runtime/configs"
restore_dir "${WORK}/console-certificates" "${R}/certificates"
if [[ -d "${PRE_DIR}" ]]; then
  log_info "被替换的旧目录留存于 ${PRE_DIR}（确认无误后可删除）"
fi

# ---------- 5. 灌库 ----------
log_info "[5/7] 重建并灌入数据库 jiuzhang_waf"
pg_env() { env LD_LIBRARY_PATH="${PG_LD}" OPENSSL_MODULES="${PG_OSSL}" PGPASSWORD="${PG_PW}" "$@"; }
pg_env "${PG_BIN}/dropdb" -h 127.0.0.1 -U "${RUN_USER}" --if-exists jiuzhang_waf
pg_env "${PG_BIN}/createdb" -h 127.0.0.1 -U "${RUN_USER}" jiuzhang_waf
gunzip -c "${WORK}/db.sql.gz" | pg_env "${PG_BIN}/psql" -h 127.0.0.1 -U "${RUN_USER}" \
  -d jiuzhang_waf -v ON_ERROR_STOP=1 --quiet -o /dev/null
log_info "数据库灌入完成"

# ---------- 6. 修属主/权限 ----------
log_info "[6/7] 修正属主与权限"
chown -R "${RUN_USER}:${RUN_USER}" "${R}/data" "${R}/certificates" 2>/dev/null || true
chmod 0750 "${R}/data" 2>/dev/null || true
chmod 0700 "${R}/data/pgdata" "${R}/data/caddy" "${R}/data/caddy-console" "${R}/certificates" 2>/dev/null || true
chmod 0770 "${R}/data/run/caddy/sidecars" 2>/dev/null || true
if [[ -d "${R}/data/run/caddy/sidecars/diag" ]]; then
  chmod 0770 "${R}/data/run/caddy/sidecars/diag" 2>/dev/null || true
fi
if [[ -d "${R}/data/run/caddy/sidecars/keepalived" ]]; then
  chmod 0770 "${R}/data/run/caddy/sidecars/keepalived" 2>/dev/null || true
fi

# ---------- 7. 起服务与健康等待 ----------
wait_for() {
  local desc="$1"; shift
  local i
  for i in $(seq 1 60); do
    if "$@" >/dev/null 2>&1; then
      log_info "  健康检查通过：${desc}"
      return 0
    fi
    sleep 1
  done
  log_err "  健康检查超时（60s）：${desc}"
  return 1
}
VK_PW="$(env_get VALKEY_PASSWORD)"
WEB_PORT="$(env_get WEB_PORT)"; WEB_PORT="${WEB_PORT:-8080}"
check_pg()     { pg_env "${PG_BIN}/pg_isready" -h 127.0.0.1 -U "${RUN_USER}" -t 2; }
check_valkey() { env REDISCLI_AUTH="${VK_PW}" "${R}/bin/valkey/valkey-cli" ping 2>/dev/null | grep PONG >/dev/null 2>&1; }
check_api()    { curl -fsS -o /dev/null --max-time 3 "http://127.0.0.1:18081/api/v1/health"; }
check_web()    { curl -fsS -o /dev/null --max-time 3 "http://127.0.0.1:${WEB_PORT}/api/v1/health"; }

if [[ "${SKIP_SYSTEMD}" == "1" ]]; then
  log_warn "[7/7] JZ_SKIP_SYSTEMD=1：跳过起服务与健康等待。手工启动："
  for unit in ${UNIT_START_ORDER}; do
    echo "    systemctl enable --now ${unit}"
  done
else
  log_info "[7/7] 启动服务"
  for unit in ${UNIT_START_ORDER}; do
    systemctl start "${unit}" || die "启动 ${unit} 失败：journalctl -u ${unit} --since '5 min ago'"
  done
  if [[ -f "${R}/data/runtime/hasync.secret" ]] || systemctl is-enabled --quiet jiuzhang-hasyncd 2>/dev/null; then
    systemctl start jiuzhang-hasyncd || die "启动 jiuzhang-hasyncd 失败：journalctl -u jiuzhang-hasyncd --since '5 min ago'"
  fi
  failed=0
  wait_for "PostgreSQL" check_pg || failed=1
  wait_for "Valkey" check_valkey || failed=1
  wait_for "管理 API" check_api || failed=1
  wait_for "控制台反代" check_web || failed=1
  if [[ "${failed}" == "1" ]]; then
    log_err "部分服务未就绪：journalctl -u jiuzhang-postgres -u jiuzhang-valkey -u jiuzhang-api -u jiuzhang-web --since '10 min ago'"
    exit 1
  fi
fi

log_info "恢复完成。若使用了 --force-env 且其中口令与当前 PostgreSQL/Valkey 实例不一致，"
log_info "请按 README.md「日常运维」一节重置实例口令或改回 env。"
