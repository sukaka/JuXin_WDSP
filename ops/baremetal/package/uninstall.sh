#!/usr/bin/env bash
# uninstall.sh —— 九章 WDSP 裸机版卸载脚本（root 执行）。
#
# 用法：
#   sudo bash <安装根>/uninstall.sh [--yes]            # 停服务、删单元/链接，保留数据
#   sudo bash <安装根>/uninstall.sh --purge [--yes]    # 追加删除安装根与 jiuzhang 账户
#
# 默认保留 <安装根>（数据库/配置/授权/日志），仅移除 systemd 托管与宿主兼容符号链接；
# 符号链接仅当仍指向安装根时才移除。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
R="${INSTALL_ROOT:-${SCRIPT_DIR}}"
R="${R%/}"
RUN_USER="jiuzhang"
UNIT_LIST="jiuzhang-logrotator jiuzhang-netmgrd jiuzhang-web jiuzhang-api jiuzhang-gateway jiuzhang-valkey jiuzhang-postgres"

PURGE=0
ASSUME_YES=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --purge)   PURGE=1; shift ;;
    --yes|-y)  ASSUME_YES=1; shift ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) printf '[ERROR] 未知参数：%s\n' "$1" >&2; exit 2 ;;
  esac
done

log_info() { printf '[INFO]  %s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }
log_warn() { printf '[WARN]  %s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_err()  { printf '[ERROR] %s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2; }

[[ "$(id -u)" == "0" ]] || { log_err "请以 root 执行"; exit 1; }
# 安装根合法性：必须含包内标志物，防止误传 INSTALL_ROOT 时误删他处
if [[ ! -d "${R}/bin" && ! -f "${R}/env" && ! -f "${R}/env.template" ]]; then
  log_err "安装根校验失败：${R} 下无 bin/、env 或 env.template——拒绝操作"
  exit 1
fi

# --purge 且脚本在安装根内：先自我复制到 /tmp 再执行（避免删除运行中的脚本），
# 经 INSTALL_ROOT 把原安装根传给重执行副本（否则副本会把自身所在目录误当安装根）
if [[ "${PURGE}" == "1" ]]; then
  case "${SCRIPT_DIR}" in
    "${R}"|"${R}/"*)
      SELF_TMP="$(mktemp /tmp/jiuzhang-uninstall.XXXXXX.sh)"
      cp "$0" "${SELF_TMP}"
      chmod 700 "${SELF_TMP}"
      if [[ "${ASSUME_YES}" == "1" ]]; then
        exec env INSTALL_ROOT="${R}" bash "${SELF_TMP}" --purge --yes
      else
        exec env INSTALL_ROOT="${R}" bash "${SELF_TMP}" --purge
      fi
      ;;
  esac
fi

if [[ "${ASSUME_YES}" != "1" ]]; then
  if [[ "${PURGE}" == "1" ]]; then
    printf '即将卸载并【删除全部数据】（%s、账户 %s），确认继续？[y/N] ' "${R}" "${RUN_USER}"
  else
    printf '即将卸载九章 WDSP 服务（数据保留于 %s），确认继续？[y/N] ' "${R}"
  fi
  read -r ans
  [[ "${ans}" == "y" || "${ans}" == "Y" || "${ans}" == "yes" ]] || { log_info "已取消"; exit 0; }
fi

# ---------- 1. 停并禁用服务 ----------
log_info "[1/4] 停止并禁用 systemd 单元"
if command -v systemctl >/dev/null 2>&1; then
  for unit in ${UNIT_LIST}; do
    systemctl disable --now "${unit}" 2>/dev/null \
      && log_info "  已停用 ${unit}" \
      || log_warn "  ${unit} 停用未成功（可能本就不存在），继续"
  done
else
  log_warn "未找到 systemctl，跳过停服（请确认服务已停止）"
fi

# ---------- 2. 删除单元与 tmpfiles 配置 ----------
log_info "[2/4] 移除单元文件与 tmpfiles 配置"
for unit in jiuzhang-postgres jiuzhang-valkey jiuzhang-gateway jiuzhang-api jiuzhang-web jiuzhang-netmgrd jiuzhang-logrotator; do
  rm -f "/etc/systemd/system/${unit}.service"
done
rm -f /etc/tmpfiles.d/jiuzhang.conf
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
fi

# ---------- 3. 移除宿主兼容符号链接（仅当仍指向安装根） ----------
log_info "[3/4] 移除宿主兼容符号链接"
LINK_LIST_FILE="${R}/data/runtime/host-compat-links.list"
if [[ -f "${LINK_LIST_FILE}" ]]; then
  LINKS="$(cat "${LINK_LIST_FILE}")"
else
  LINKS="/etc/caddy/rules
/etc/caddy/certs
/srv/jiuzhang/blockpage.html
/var/log/caddy"
fi
printf '%s\n' "${LINKS}" | while IFS= read -r link; do
  [[ -n "${link}" ]] || continue
  if [[ -L "${link}" ]]; then
    cur="$(readlink "${link}")"
    case "${cur}" in
      "${R}"|"${R}/"*)
        rm -f "${link}"
        log_info "  已移除 ${link}（原指向 ${cur}）"
        ;;
      *)
        log_warn "  ${link} 现指向 ${cur}（不再指向安装根），保留不动"
        ;;
    esac
  else
    log_info "  ${link} 非符号链接或不存在，跳过"
  fi
done
rmdir /etc/caddy /srv/jiuzhang 2>/dev/null || true

# ---------- 4. 数据处置 ----------
if [[ "${PURGE}" == "1" ]]; then
  log_info "[4/4] --purge：删除安装根与运行账户"
  cd /
  rm -rf "${R}"
  rm -rf /tmp/coraza
  if id "${RUN_USER}" >/dev/null 2>&1; then
    userdel "${RUN_USER}" 2>/dev/null \
      && log_info "已删除账户 ${RUN_USER}" \
      || log_warn "账户 ${RUN_USER} 删除未成功（可能有残留进程），请人工检查"
  fi
  log_info "卸载完成（全部数据已删除）"
else
  log_info "[4/4] 保留数据"
  log_info "卸载完成。数据保留于 ${R}（数据库 data/pgdata、配置 env、授权 data/runtime/license、日志 data/logs）"
  log_info "彻底清理请执行：sudo bash ${R}/uninstall.sh --purge"
fi
