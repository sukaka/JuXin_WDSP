#!/usr/bin/env bash
# 为 openEuler / 兆芯 x86-64 宿主机准备 WDSP 运行环境。
# 默认仅补齐依赖并写入保守的资源参数；系统精简必须显式传入 --minimal-host。
set -euo pipefail

ETC_ROOT="${ETC_ROOT:-/etc}"
PROC_SYS_ROOT="${PROC_SYS_ROOT:-/proc/sys}"
SYS_ROOT="${SYS_ROOT:-/sys}"
OS_RELEASE_FILE="${OS_RELEASE_FILE:-/etc/os-release}"
CPUINFO_FILE="${CPUINFO_FILE:-/proc/cpuinfo}"
SYSTEMD_RUNTIME_DIR="${SYSTEMD_RUNTIME_DIR:-/run/systemd/system}"
DRY_RUN="${DRY_RUN:-false}"

log() { printf '[WDSP host] %s\n' "$*"; }
warn() { printf '[WDSP host] WARN: %s\n' "$*" >&2; }
die() { printf '[WDSP host] ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
用法: prepare-openeuler-zhaoxin.sh [选项]

为 openEuler / 兆芯 x86-64 宿主机准备 WDSP：
  - 自动使用 dnf，缺失时回退 yum，补齐 tar/gzip/openssl/curl/jq/python3/Docker
  - 写入 limits、sysctl 与 Docker systemd 资源限制
  - 兆芯 CPU 支持时切换 performance governor
  - 可选停用与专用 WDSP 节点无关的桌面发现、打印等服务

选项:
  --check-only            只检查系统、CPU、依赖与参数，不修改宿主机
  --dry-run               显示将执行的命令，不修改宿主机
  --skip-tuning           不写入 limits/sysctl/Docker/CPU 调优
  --minimal-host          停用明确无关的服务（不卸载软件包）
  --allow-compatible-os   允许在非 openEuler 的 RPM 系发行版执行
  --allow-non-zhaoxin     允许在非兆芯 x86-64 CPU 执行
  -h, --help              显示帮助

安全边界：不会关闭 SELinux、防火墙、SSH、时间同步、网络或内核漏洞防护。
EOF
}

detect_os_id() {
  local file="${1:-$OS_RELEASE_FILE}" value
  [[ -r "$file" ]] || return 1
  value="$(awk -F= '$1 == "ID" {print substr($0, index($0, "=") + 1); exit}' "$file")"
  value="${value#\"}"; value="${value%\"}"
  value="${value#\'}"; value="${value%\'}"
  printf '%s\n' "$value" | tr '[:upper:]' '[:lower:]'
}

is_openeuler() {
  [[ "$(detect_os_id "${1:-$OS_RELEASE_FILE}" 2>/dev/null || true)" == "openeuler" ]]
}

detect_cpu_platform() {
  local file="${1:-$CPUINFO_FILE}"
  [[ -r "$file" ]] || { printf 'other\n'; return; }
  if grep -Eiq 'CentaurHauls|ZHAOXIN|兆芯|KaiXian|KaiSheng' "$file"; then
    printf 'zhaoxin\n'
  else
    printf 'other\n'
  fi
}

run_cmd() {
  if [[ "$DRY_RUN" == "true" ]]; then
    printf '[dry-run]'; printf ' %q' "$@"; printf '\n'
  else
    "$@"
  fi
}

install_packages() {
  [[ $# -gt 0 ]] || return 0
  if command -v dnf >/dev/null 2>&1; then
    run_cmd dnf -y install "$@"
  elif command -v yum >/dev/null 2>&1; then
    run_cmd yum -y install "$@"
  else
    die "未找到 dnf 或 yum，无法安装依赖：$*"
  fi
}

install_first_available() {
  local package
  for package in "$@"; do
    log "尝试安装软件包：$package"
    if install_packages "$package"; then
      return 0
    fi
    warn "软件包不可用：$package"
  done
  return 1
}

has_systemd_environment() {
  command -v systemctl >/dev/null 2>&1 && [[ -d "$SYSTEMD_RUNTIME_DIR" ]]
}

ensure_command() {
  local command_name="$1"; shift
  command -v "$command_name" >/dev/null 2>&1 && return 0
  log "缺少 ${command_name}，尝试安装：$*"
  install_packages "$@"
  [[ "$DRY_RUN" == "true" ]] || command -v "$command_name" >/dev/null 2>&1 \
    || die "依赖安装后仍未找到命令：${command_name}"
}

write_limits_config() {
  local dir="$ETC_ROOT/security/limits.d" file
  file="$dir/99-jiuzhang-wdsp.conf"
  if [[ "$DRY_RUN" == "true" ]]; then
    log "将写入 $file"
    return
  fi
  mkdir -p "$dir"
  printf '%s\n' \
    '# 九章 WDSP 专用宿主机资源限制' \
    '* soft nofile 1048576' \
    '* hard nofile 1048576' \
    '* soft nproc 262144' \
    '* hard nproc 262144' > "$file"
}

sysctl_candidate() {
  local key="$1" value="$2" probe
  probe="$PROC_SYS_ROOT/$(printf '%s' "$key" | tr '.' '/')"
  [[ -e "$probe" ]] && printf '%s = %s\n' "$key" "$value"
}

write_sysctl_config() {
  local dir="$ETC_ROOT/sysctl.d" file content
  file="$dir/99-jiuzhang-wdsp.conf"
  content="$({
    printf '%s\n' '# 九章 WDSP 高并发宿主机参数（仅写入当前内核支持项）'
    sysctl_candidate fs.file-max 2097152
    sysctl_candidate fs.nr_open 2097152
    sysctl_candidate net.core.somaxconn 65535
    sysctl_candidate net.core.netdev_max_backlog 131072
    sysctl_candidate net.ipv4.tcp_max_syn_backlog 131072
    sysctl_candidate net.ipv4.tcp_fin_timeout 15
    sysctl_candidate net.ipv4.tcp_keepalive_time 300
    sysctl_candidate net.ipv4.ip_local_port_range '10240 65535'
    sysctl_candidate net.netfilter.nf_conntrack_max 2097152
  })"
  if [[ "$DRY_RUN" == "true" ]]; then
    log "将写入 $file"
    return
  fi
  mkdir -p "$dir"
  printf '%s\n' "$content" > "$file"
}

write_docker_limits() {
  local dir="$ETC_ROOT/systemd/system/docker.service.d" file
  file="$dir/99-jiuzhang-wdsp.conf"
  if [[ "$DRY_RUN" == "true" ]]; then
    log "将写入 $file"
    return
  fi
  mkdir -p "$dir"
  printf '%s\n' \
    '[Service]' \
    'LimitNOFILE=1048576' \
    'LimitNPROC=infinity' \
    'TasksMax=infinity' > "$file"
}

write_zhaoxin_cpu_tuning_service() {
  local governors=() dir file
  shopt -s nullglob
  governors=("$SYS_ROOT"/devices/system/cpu/cpu*/cpufreq/scaling_governor)
  shopt -u nullglob
  [[ ${#governors[@]} -gt 0 ]] || { warn '未发现 cpufreq governor；不创建 CPU 调优服务'; return; }
  dir="$ETC_ROOT/systemd/system"
  file="$dir/jiuzhang-wdsp-cpu-performance.service"
  if [[ "$DRY_RUN" == "true" ]]; then
    log "将写入 $file"
    return
  fi
  mkdir -p "$dir"
  printf '%s\n' \
    '[Unit]' \
    'Description=Jiuzhang WDSP Zhaoxin CPU performance governor' \
    'After=multi-user.target' \
    '' \
    '[Service]' \
    'Type=oneshot' \
    "ExecStart=/bin/sh -c 'for governor in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do [ ! -w \"\$governor\" ] || echo performance > \"\$governor\"; done'" \
    'RemainAfterExit=yes' \
    '' \
    '[Install]' \
    'WantedBy=multi-user.target' > "$file"
}

apply_zhaoxin_cpu_tuning() {
  local governor changed=0
  shopt -s nullglob
  for governor in "$SYS_ROOT"/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    if [[ "$DRY_RUN" == "true" ]]; then
      log "将设置 ${governor}=performance"
    elif [[ -w "$governor" ]]; then
      printf 'performance\n' > "$governor"
      changed=1
    else
      warn "无法写入 CPU governor：$governor"
    fi
  done
  shopt -u nullglob
  [[ "$changed" -eq 1 || "$DRY_RUN" == "true" ]] \
    || warn "未发现可写的 cpufreq governor；保留固件/内核当前策略"
}

list_minimal_services() {
  printf '%s\n' \
    cups.service cups.socket \
    avahi-daemon.service avahi-daemon.socket \
    bluetooth.service \
    ModemManager.service \
    rpcbind.service rpcbind.socket \
    nfs-server.service \
    postfix.service
}

minimize_host_services() {
  command -v systemctl >/dev/null 2>&1 || { warn '无 systemctl，跳过服务精简'; return; }
  local service
  while IFS= read -r service; do
    systemctl cat "$service" >/dev/null 2>&1 || continue
    log "停用非 WDSP 必需服务：$service"
    run_cmd systemctl disable --now "$service"
  done < <(list_minimal_services)
}

ensure_runtime_dependencies() {
  ensure_command tar tar
  ensure_command gzip gzip
  ensure_command openssl openssl
  ensure_command curl curl
  ensure_command jq jq
  ensure_command python3 python3
  ensure_command sha256sum coreutils
  ensure_command flock util-linux
  if ! command -v docker >/dev/null 2>&1; then
    log '缺少 Docker，按 openEuler 新旧版本包名尝试安装'
    install_first_available docker docker-engine \
      || die 'Docker 安装失败；请检查 openEuler 软件源或随包提供依赖 RPM'
  fi
  [[ "$DRY_RUN" == "true" ]] || command -v docker >/dev/null 2>&1 \
    || die '未找到 Docker；请配置 openEuler 官方软件源后重试'
  if [[ "$DRY_RUN" != "true" ]] && ! docker compose version >/dev/null 2>&1; then
    install_first_available docker-compose-plugin || true
    docker compose version >/dev/null 2>&1 \
      || die 'Docker Compose v2 不可用；请在离线 RPM 目录中提供 docker-compose-plugin'
  fi
  if command -v systemctl >/dev/null 2>&1; then
    run_cmd systemctl enable --now docker
  fi
}

check_runtime_dependencies() {
  local command_name missing=0
  for command_name in tar gzip openssl curl jq python3 sha256sum flock docker; do
    if command -v "$command_name" >/dev/null 2>&1; then
      log "依赖可用：$command_name"
    else
      warn "缺少依赖：$command_name"
      missing=1
    fi
  done
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    log '依赖可用：Docker Compose v2'
  else
    warn '缺少依赖：Docker Compose v2'
    missing=1
  fi
  for command_name in \
    "$ETC_ROOT/security/limits.d/99-jiuzhang-wdsp.conf" \
    "$ETC_ROOT/sysctl.d/99-jiuzhang-wdsp.conf" \
    "$ETC_ROOT/systemd/system/docker.service.d/99-jiuzhang-wdsp.conf"; do
    if [[ -f "$command_name" ]]; then
      log "调优配置已存在：$command_name"
    else
      warn "调优配置尚未写入：$command_name"
    fi
  done
  return "$missing"
}

print_report() {
  log "操作系统：$(detect_os_id "$OS_RELEASE_FILE" 2>/dev/null || printf unknown)"
  log "CPU 平台：$(detect_cpu_platform "$CPUINFO_FILE")"
  log "架构：$(uname -m)"
  if command -v docker >/dev/null 2>&1; then
    log "Docker：$(docker --version 2>/dev/null || true)"
  else
    log 'Docker：未安装，将尝试通过 dnf/yum 补齐'
  fi
  return 0
}

main() {
  local check_only=false skip_tuning=false minimal_host=false
  local allow_compatible_os=false allow_non_zhaoxin=false
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --check-only) check_only=true; shift ;;
      --dry-run) DRY_RUN=true; shift ;;
      --skip-tuning) skip_tuning=true; shift ;;
      --minimal-host) minimal_host=true; shift ;;
      --allow-compatible-os) allow_compatible_os=true; shift ;;
      --allow-non-zhaoxin) allow_non_zhaoxin=true; shift ;;
      -h|--help) usage; return 0 ;;
      *) usage >&2; die "未知参数：$1" ;;
    esac
  done

  [[ "$EUID" -eq 0 || "$check_only" == "true" || "$DRY_RUN" == "true" ]] \
    || die '请以 root 执行宿主机准备脚本'
  is_openeuler "$OS_RELEASE_FILE" || [[ "$allow_compatible_os" == "true" ]] \
    || die '当前系统不是 openEuler；如已验证兼容性，可显式传入 --allow-compatible-os'
  [[ "$(uname -m)" == "x86_64" ]] || die '兆芯交付包仅支持 x86_64 架构'
  [[ "$(detect_cpu_platform "$CPUINFO_FILE")" == "zhaoxin" || "$allow_non_zhaoxin" == "true" ]] \
    || die '未识别到兆芯 CPU；如已验证兼容性，可显式传入 --allow-non-zhaoxin'
  has_systemd_environment \
    || die '未检测到运行中的 systemd；WDSP openEuler 安装包要求 systemd 宿主机环境'

  print_report
  if [[ "$check_only" == "true" ]]; then
    check_runtime_dependencies
    return
  fi
  ensure_runtime_dependencies
  if [[ "$skip_tuning" != "true" ]]; then
    write_limits_config
    write_sysctl_config
    write_docker_limits
    write_zhaoxin_cpu_tuning_service
    apply_zhaoxin_cpu_tuning
    if [[ "$DRY_RUN" != "true" ]] && command -v sysctl >/dev/null 2>&1; then
      sysctl --system >/dev/null
    fi
    if [[ "$DRY_RUN" != "true" ]] && command -v systemctl >/dev/null 2>&1; then
      systemctl daemon-reload
      if [[ -f "$ETC_ROOT/systemd/system/jiuzhang-wdsp-cpu-performance.service" ]]; then
        systemctl enable --now jiuzhang-wdsp-cpu-performance.service \
          || warn 'CPU performance governor 持久化服务启用失败'
      fi
      systemctl try-restart docker || warn 'Docker 重启失败，请检查 systemctl status docker'
    fi
  fi
  [[ "$minimal_host" == "true" ]] && minimize_host_services
  log 'openEuler / 兆芯 WDSP 宿主机准备完成'
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
