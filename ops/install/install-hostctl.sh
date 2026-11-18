#!/usr/bin/env bash
# install-hostctl.sh —— 准备 hostctl 标志目录并安装/更新 jiuzhang-hostctl systemd 单元。
# 完整安装默认保留告警后跳过语义；升级使用 --strict，安装失败明确返回非零。
# 非 systemd 或非 root 环境始终告警跳过，可手工执行 ops/system/hostctl-exec.sh。
# 退出码: 0=成功或非 systemd 跳过 1=安装失败 2=用法错误
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

INSTALL_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
STRICT=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --install-root) INSTALL_ROOT="${2:-}"; shift 2 ;;
    --strict) STRICT=true; shift ;;
    -h|--help)
      printf '%s\n' '用法: install-hostctl.sh [--install-root DIR] [--strict]'
      exit 0 ;;
    *) log_err "未知参数: $1"; exit 2 ;;
  esac
done
[[ -n "$INSTALL_ROOT" && -d "$INSTALL_ROOT" ]] || { log_err "安装根目录不存在: ${INSTALL_ROOT:-<空>}"; exit 2; }
INSTALL_ROOT="$(cd "$INSTALL_ROOT" && pwd -P)"

UNIT_TEMPLATE_DIR="${HOSTCTL_UNIT_TEMPLATE_DIR:-$SCRIPT_DIR/../../deployment/systemd}"
SYSTEMD_UNIT_DIR="${HOSTCTL_SYSTEMD_UNIT_DIR:-/etc/systemd/system}"
SYSTEMD_RUNTIME_DIR="${HOSTCTL_SYSTEMD_RUNTIME_DIR:-/run/systemd/system}"

install_error() {
  local message="$1"
  if [[ "$STRICT" == "true" ]]; then
    log_err "$message"
    exit 1
  fi
  log_warn "$message"
}

# API 容器以 uid 1000 写入标志；hostctl-exec.sh 执行前按同一约定 fail-closed 复核。
mkdir -p "$INSTALL_ROOT/runtime/hostctl"
chmod 755 "$INSTALL_ROOT/runtime/hostctl"
if ! chown 1000:1000 "$INSTALL_ROOT/runtime/hostctl" 2>/dev/null; then
  chmod 1777 "$INSTALL_ROOT/runtime/hostctl" 2>/dev/null \
    || log_warn "未能调整 $INSTALL_ROOT/runtime/hostctl 属主/权限，api 容器可能无法写入系统控制标志文件"
fi

_hc_uid="$(stat -c '%u' "$INSTALL_ROOT/runtime/hostctl" 2>/dev/null || stat -f '%u' "$INSTALL_ROOT/runtime/hostctl" 2>/dev/null || echo unknown)"
_hc_mode="$(stat -c '%a' "$INSTALL_ROOT/runtime/hostctl" 2>/dev/null || stat -f '%Lp' "$INSTALL_ROOT/runtime/hostctl" 2>/dev/null || echo "")"
_hc_insecure=false
[[ "$_hc_uid" == "1000" ]] || _hc_insecure=true
if [[ "$_hc_mode" =~ ^[0-7]{3,4}$ ]] && (( (8#${_hc_mode:${#_hc_mode}-3} & 2) != 0 )); then
  _hc_insecure=true
fi
if [[ "$_hc_insecure" == "true" ]]; then
  log_warn "==================== 安全警告（系统控制通道不可用） ===================="
  log_warn "  $INSTALL_ROOT/runtime/hostctl 当前属主 uid=${_hc_uid}、权限 ${_hc_mode:-unknown}，"
  log_warn "  不满足约定（属主 1000:1000、权限 755 且非全局可写）。"
  log_warn "  该状态下可写该目录的本地用户可伪造重启/关机/恢复出厂标志；"
  log_warn "  hostctl-exec.sh 将因执行前安全校验拒绝处理（fail-closed），"
  log_warn "  即 Web 端系统控制（重启/关机/恢复出厂）不可用，直至修复："
  log_warn "    sudo chown 1000:1000 $INSTALL_ROOT/runtime/hostctl && sudo chmod 755 $INSTALL_ROOT/runtime/hostctl"
  log_warn "======================================================================"
fi
unset _hc_uid _hc_mode _hc_insecure

if command -v systemctl >/dev/null 2>&1 && [[ -d "$SYSTEMD_RUNTIME_DIR" ]] && [[ "$(id -u)" == "0" ]]; then
  hostctl_install_ok=true
  if [[ ! -d "$SYSTEMD_UNIT_DIR" ]]; then
    install_error "systemd 单元目录不存在: $SYSTEMD_UNIT_DIR"
    hostctl_install_ok=false
  fi
  for unit in jiuzhang-hostctl.path jiuzhang-hostctl.service; do
    [[ "$hostctl_install_ok" == "true" ]] || break
    if [[ ! -f "$UNIT_TEMPLATE_DIR/$unit" ]]; then
      install_error "单元模板缺失: $UNIT_TEMPLATE_DIR/$unit，跳过 systemd 单元安装"
      hostctl_install_ok=false
      break
    fi
    # 仅覆盖带九章管理标记的既有文件，避免覆盖部署方自行维护的同名单元。
    if [[ -f "$SYSTEMD_UNIT_DIR/$unit" ]] && ! grep -q 'jiuzhang-managed: hostctl-unit' "$SYSTEMD_UNIT_DIR/$unit" 2>/dev/null; then
      install_error "$SYSTEMD_UNIT_DIR/$unit 已存在且非九章安装器管理，跳过覆盖"
      hostctl_install_ok=false
      break
    fi
    if ! sed "s|__INSTALL_ROOT__|$INSTALL_ROOT|g" "$UNIT_TEMPLATE_DIR/$unit" > "$SYSTEMD_UNIT_DIR/$unit"; then
      install_error "安装 $SYSTEMD_UNIT_DIR/$unit 失败"
      hostctl_install_ok=false
      break
    fi
  done
  if [[ "$hostctl_install_ok" == "true" ]]; then
    if systemctl daemon-reload && systemctl enable --now jiuzhang-hostctl.path; then
      log_info "jiuzhang-hostctl.path 已安装并启用（监视 $INSTALL_ROOT/runtime/hostctl/*.json）"
    else
      install_error "systemctl daemon-reload/enable 失败，请手工执行后启用 jiuzhang-hostctl.path"
    fi
  fi
else
  log_warn "systemd 不可用或非 root，跳过 jiuzhang-hostctl 单元安装；系统控制可手工执行 ops/system/hostctl-exec.sh"
fi
