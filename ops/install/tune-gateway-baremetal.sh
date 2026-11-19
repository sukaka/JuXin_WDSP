#!/usr/bin/env bash
# tune-gateway-baremetal.sh —— 九章 WAF 裸机网关（systemd 形态）安装期性能调优。
# 面向通用 x86/ARM 平台（Intel/AMD，及海光 C86/兆芯 KX-KH=amd64、鲲鹏/飞腾=arm64
# 等国产化 CPU）+ 10G 光模块环境，按 6/8/10 Gbps HTTP 吞吐目标档应用：
#   sysctl 网络参数、网卡 ring/offload/队列/中断合并、MSI-X IRQ 绑同 NUMA 核、
#   CPU governor=performance，并生成 oneshot systemd unit 开机重放。
# 设计依据与验收方法见 docs/BARE_METAL_PERFORMANCE_TUNING.md（万兆实测留待物理环境复测）。
#
# 安全纪律（与 install-gateway-baremetal.sh 一致）：
#   - 幂等；生成文件带管理标记 `jiuzhang-managed: perf-tuning`，
#     目标文件已存在且不含标记时拒绝覆盖（die）；
#   - 各厂商网卡驱动差异大：单项 ethtool/IRQ 失败只告警不中断，最终在报告中列出；
#   - 不擅自停 irqbalance 等系统服务，仅打印处置建议。
#
# 退出码：0=成功（或 --check 全部一致） 1=失败（或 --check 存在不一致） 2=用法错误
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "$SCRIPT_DIR/../lib/common.sh"

# ---------- 常量 ----------
TUNE_MARKER="jiuzhang-managed: perf-tuning"
SYSCTL_DEST="/etc/sysctl.d/99-jiuzhang-gateway-tuning.conf"
UNIT_NAME="jiuzhang-gateway-tune-nic.service"
UNIT_DEST="/etc/systemd/system/$UNIT_NAME"
HELPER_DIR="/opt/jiuzhang-gateway"
HELPER_DEST="$HELPER_DIR/tune-nic.sh"
INSTALL_ENV_DIR="/etc/jiuzhang-gateway"
INSTALL_ENV_FILE="$INSTALL_ENV_DIR/install.env"
# sysfs 根路径抽为变量，测试 harness 可 stub 到临时目录构造伪 sysfs
SYSFS_ROOT="${SYSFS_ROOT:-/sys}"
# cpuinfo / os-release 路径抽为变量，测试 harness 可 stub 到临时文件
CPUINFO_FILE="${CPUINFO_FILE:-/proc/cpuinfo}"
OS_RELEASE_FILE="${OS_RELEASE_FILE:-/etc/os-release}"

# ---------- 参数 ----------
TARGET=6                 # 目标档：6|8|10（Gbps HTTP 吞吐）
MODE=""                  # apply|check；缺省 apply
MODE_EXPLICIT=false
IFACES=()
KEEP_IRQBALANCE=false
DRY_RUN=false

usage() {
  cat <<'EOF'
用法: tune-gateway-baremetal.sh [--target 6|8|10] [--iface IF ...] [--apply|--check]
                                [--keep-irqbalance] [--dry-run] [-h|--help]

裸机网关安装期性能调优（通用 x86/ARM 平台 + 10G 光模块，详见
docs/BARE_METAL_PERFORMANCE_TUNING.md）。

选项:
      --target N         性能目标档：6|8|10（Gbps HTTP 吞吐，缺省 6）
      --iface IF         显式指定 10G 业务网卡（可多次）；缺省自动发现
                         /sys/class/net/*/speed==10000 的接口
      --apply            应用调优（缺省）
      --check            只核对不调优：sysctl/unit/install.env 逐项比对，
                         全部一致 exit 0，不一致逐项输出并 exit 1
      --keep-irqbalance  保留 irqbalance 运行（缺省仅打印处置建议，不擅停服务）
      --dry-run          只打印将执行的操作，不修改系统（可在非 root/非 Linux 环境演练）
  -h, --help             显示帮助

退出码: 0=成功/--check 一致 1=失败/--check 不一致 2=用法错误
EOF
}

# ---------- 小工具 ----------

# run CMD... —— dry-run 下只打印不执行（仅用于有副作用的命令）。
run() {
  if [[ "$DRY_RUN" == "true" ]]; then
    printf '[DRY-RUN] %s\n' "$*"
    return 0
  fi
  "$@"
}

# write_file PATH VALUE —— 写 /proc、/sys 伪文件的 run() 等价物（重定向无法走 run）。
write_file() {
  local path="$1" value="$2"
  if [[ "$DRY_RUN" == "true" ]]; then
    printf '[DRY-RUN] 写入 %s ← %s\n' "$path" "$value"
    return 0
  fi
  printf '%s\n' "$value" > "$path"
}

# 报告收集器：已应用 / 告警 / 失败（不中断类）
APPLIED_ITEMS=()
WARN_ITEMS=()
FAILED_ITEMS=()
note_applied() { APPLIED_ITEMS+=("$1"); }
note_warn()    { WARN_ITEMS+=("$1"); log_warn "$1"; }
note_failed()  { FAILED_ITEMS+=("$1"); log_warn "$1"; }

# parse_cpu_list SPEC —— 把 "0-3,8,10-11" 展开为 "0 1 2 3 8 10 11"；非法格式返回 1。
parse_cpu_list() {
  local spec="$1" part out="" a b i
  local parts=()
  IFS=',' read -ra parts <<< "$spec"
  for part in "${parts[@]}"; do
    part="${part//[[:space:]]/}"
    [[ -z "$part" ]] && continue
    if [[ "$part" =~ ^([0-9]+)-([0-9]+)$ ]]; then
      a="${BASH_REMATCH[1]}"
      b="${BASH_REMATCH[2]}"
      for ((i = a; i <= b; i++)); do out+="$i "; done
    elif [[ "$part" =~ ^[0-9]+$ ]]; then
      out+="$part "
    else
      return 1
    fi
  done
  [[ -n "$out" ]] || return 1
  printf '%s\n' "${out% }"
}

# parse_cpu_mask MASK —— 把 local_cpus 的十六进制掩码（如 "ff" / "0,ffffffff"）
# 展开为 CPU 号列表（空格分隔）。掩码按 32 位分组，最右组对应 CPU 0-31。
parse_cpu_mask() {
  local mask="$1" group base bit v out=""
  local groups=()
  mask="${mask//[[:space:]]/}"
  IFS=',' read -ra groups <<< "$mask"
  base=$(((${#groups[@]} - 1) * 32))
  for group in "${groups[@]}"; do
    group="${group#0x}"
    [[ -n "$group" ]] || return 1
    v=$((16#$group))
    for ((bit = 0; bit < 32; bit++)); do
      if (((v >> bit) & 1)); then out+="$((base + bit)) "; fi
    done
    base=$((base - 32))
  done
  [[ -n "$out" ]] || return 1
  printf '%s\n' "${out% }"
}

# all_local_cpus —— 本机全部 CPU 号列表（拓扑读不到时的降级）。
all_local_cpus() {
  local n i out=""
  n="$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')"
  [[ "$n" =~ ^[0-9]+$ && "$n" -ge 1 ]] || n=1
  for ((i = 0; i < n; i++)); do out+="$i "; done
  printf '%s\n' "${out% }"
}

# list_10g_ifaces —— 遍历 $SYSFS_ROOT/class/net/*/speed==10000 的接口（跳过 lo）。
list_10g_ifaces() {
  local d name speed
  for d in "$SYSFS_ROOT"/class/net/*; do
    [[ -d "$d" || -L "$d" ]] || continue
    name="${d##*/}"
    [[ "$name" == "lo" ]] && continue
    [[ -r "$d/speed" ]] || continue
    speed="$(cat "$d/speed" 2>/dev/null || true)"
    [[ "$speed" == "10000" ]] && printf '%s\n' "$name"
  done
}

# iface_numa_node IF —— 输出网卡 NUMA 节点号；读不到返回 1（-1 表示未知也原样输出）。
iface_numa_node() {
  local f="$SYSFS_ROOT/class/net/$1/device/numa_node"
  [[ -r "$f" ]] || return 1
  cat "$f"
}

# iface_numa_cpus IF —— 输出该网卡 NUMA 节点的本地 CPU 列表（空格分隔）；
# 读不到时降级为本机全部 CPU 并告警。
iface_numa_cpus() {
  local iface="$1" dev="$SYSFS_ROOT/class/net/$1/device" cpus=""
  if [[ -r "$dev/local_cpulist" ]]; then
    cpus="$(parse_cpu_list "$(cat "$dev/local_cpulist")" || true)"
  elif [[ -r "$dev/local_cpus" ]]; then
    cpus="$(parse_cpu_mask "$(cat "$dev/local_cpus")" || true)"
  fi
  if [[ -z "$cpus" ]]; then
    log_warn "$iface: 无法读取 NUMA 本地 CPU 列表，降级为本机全部 CPU"
    cpus="$(all_local_cpus)"
  fi
  printf '%s\n' "$cpus"
}

# sysctl_params_for_target N —— 输出该目标档的 sysctl 参数（"key = value" 行）。
# 档位差异主要在缓冲区大小与 backlog；tcp_congestion_control=bbr 由写入方按
# 内核支持情况另行追加，不在本函数输出内。
sysctl_params_for_target() {
  case "$1" in
    6)
      cat <<'EOF'
net.core.somaxconn = 32768
net.core.netdev_max_backlog = 65536
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_max_syn_backlog = 65536
fs.file-max = 2097152
fs.nr_open = 2097152
net.netfilter.nf_conntrack_max = 1048576
EOF
      ;;
    8)
      cat <<'EOF'
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 131072
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.ipv4.tcp_max_syn_backlog = 131072
fs.file-max = 4194304
fs.nr_open = 4194304
net.netfilter.nf_conntrack_max = 2097152
EOF
      ;;
    10)
      cat <<'EOF'
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 262144
net.core.rmem_max = 268435456
net.core.wmem_max = 268435456
net.ipv4.tcp_rmem = 4096 87380 268435456
net.ipv4.tcp_wmem = 4096 65536 268435456
net.ipv4.tcp_max_syn_backlog = 262144
fs.file-max = 8388608
fs.nr_open = 8388608
net.netfilter.nf_conntrack_max = 4194304
EOF
      ;;
    *) return 1 ;;
  esac
  # 全档位通用项
  cat <<'EOF'
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 10240 65535
EOF
}

# ring_preset_for_target N —— 网卡 ring buffer 预设值（实际取 min(预设, 网卡上限)）。
ring_preset_for_target() {
  case "$1" in
    6|8) printf '4096\n' ;;
    10)  printf '8192\n' ;;
    *)   return 1 ;;
  esac
}

# ethtool_max IFACE -g|-l FIELD —— 从 ethtool "Pre-set maximums" 段解析字段上限；
# 读不到输出空。FIELD 如 RX / TX / Combined。
ethtool_max() {
  local iface="$1" opt="$2" field="$3"
  ethtool "$opt" "$iface" 2>/dev/null | awk -v f="$field" '
    /^Pre-set maximums:/ { p = 1; next }
    /^Current hardware settings:/ { p = 0 }
    p && $1 == f ":" { print $2; exit }'
}

# ethtool_try CMD... —— ethtool 子项执行：失败只告警不中断（国产网卡驱动差异大），
# 成功/失败均计入最终报告。
ethtool_try() {
  if [[ "$DRY_RUN" == "true" ]]; then
    printf '[DRY-RUN] %s\n' "$*"
    note_applied "$*（dry-run 演练）"
    return 0
  fi
  if "$@"; then
    note_applied "$*"
  else
    note_failed "执行失败（未中断，需人工确认）: $*"
  fi
}

# guard_managed FILE —— 目标已存在且不含管理标记时拒绝覆盖。
guard_managed() {
  local f="$1"
  if [[ -e "$f" ]] && ! grep -qF "$TUNE_MARKER" "$f" 2>/dev/null; then
    die "目标文件已存在且非九章调优管理（缺少标记 '$TUNE_MARKER'）：$f
       请人工确认后备份移除，或保留手工文件。"
  fi
}

# detect_cpu_platform —— 从 $CPUINFO_FILE 识别 CPU 平台：
#   GenuineIntel→intel、AuthenticAMD→amd、HygonGenuine/model 含海光→hygon、
#   CentaurHauls（VIA 系）/model 含 zhaoxin·兆芯→zhaoxin、
#   model 含 Kunpeng 或 CPU implementer 0x48（HiSilicon）→kunpeng、
#   model 含 Phytium 或 implementer 0x70→phytium；其余 aarch64→arm64；
#   文件读不到（非 Linux 环境）→generic（不报错，供 dry-run 演练）。
detect_cpu_platform() {
  local f="$CPUINFO_FILE"
  if [[ ! -r "$f" ]]; then
    printf 'generic\n'
    return 0
  fi
  local vendor model impl model_lc
  vendor="$(awk -F: '/^vendor_id/{gsub(/[ \t]/,"",$2); print $2; exit}' "$f")"
  model="$(awk -F: 'tolower($1) ~ /^model name/{sub(/^[ \t]+/,"",$2); print $2; exit}' "$f")"
  impl="$(awk -F: '/^CPU implementer/{gsub(/[ \t]/,"",$2); print $2; exit}' "$f")"
  case "$vendor" in
    GenuineIntel)  printf 'intel\n';   return 0 ;;
    AuthenticAMD)  printf 'amd\n';     return 0 ;;
    HygonGenuine)  printf 'hygon\n';   return 0 ;;
    CentaurHauls)  printf 'zhaoxin\n'; return 0 ;;
  esac
  model_lc="$(printf '%s' "$model" | tr 'A-Z' 'a-z')"
  case "$model_lc" in
    *zhaoxin*|*兆芯*) printf 'zhaoxin\n'; return 0 ;;
    *hygon*|*海光*)   printf 'hygon\n';   return 0 ;;
    *kunpeng*)        printf 'kunpeng\n'; return 0 ;;
    *phytium*)        printf 'phytium\n'; return 0 ;;
  esac
  case "$impl" in
    0x48) printf 'kunpeng\n'; return 0 ;;
    0x70) printf 'phytium\n'; return 0 ;;
  esac
  case "$(uname -m)" in
    aarch64|arm64) printf 'arm64\n'; return 0 ;;
  esac
  printf 'generic\n'
}

# ---------- 1. 前置检查 ----------
preflight() {
  log_info "步骤 1/6：前置检查"
  if [[ "$(id -u)" -ne 0 ]]; then
    if [[ "$DRY_RUN" == "true" ]]; then
      log_warn "非 root 运行（--dry-run 演练模式，继续）"
    elif [[ "$MODE" == "check" ]]; then
      log_warn "非 root 运行（--check 只读核对，继续）"
    else
      die "需 root 运行"
    fi
  fi
  local arch
  arch="$(detect_arch)"
  log_info "架构: ${arch}（海光 C86/兆芯 KX-KH 归 amd64，鲲鹏/飞腾归 arm64）"

  # CPU 平台识别（仅打印，不影响调优参数；识别不到按 generic 通用经验值继续）
  local cpu_platform cpu_desc
  cpu_platform="$(detect_cpu_platform)"
  case "$cpu_platform" in
    intel)   cpu_desc="Intel x86-64 通用平台" ;;
    amd)     cpu_desc="AMD x86-64 通用平台" ;;
    hygon)   cpu_desc="海光 C86（x86-64 兼容）" ;;
    zhaoxin) cpu_desc="兆芯 KX/KH（x86-64 兼容）" ;;
    kunpeng) cpu_desc="鲲鹏（arm64）" ;;
    phytium) cpu_desc="飞腾（arm64）" ;;
    arm64)   cpu_desc="ARM64 通用平台" ;;
    *)       cpu_desc="未识别，按通用经验值应用" ;;
  esac
  log_info "CPU 平台: ${cpu_platform}（${cpu_desc}）"

  # OS 识别（非阻断）：主流发行版（含国产化 OS）均为目标支持平台
  local os_id="unknown" os_name="unknown"
  if [[ -r "$OS_RELEASE_FILE" ]]; then
    os_id="$(awk -F= '$1=="ID"{gsub(/"/,"",$2);print $2}' "$OS_RELEASE_FILE")"
    os_name="$(awk -F= '$1=="PRETTY_NAME"{gsub(/"/,"",$2);print $2}' "$OS_RELEASE_FILE")"
  fi
  case "$os_id" in
    kylin|uos|openeuler|centos|rhel|rocky|almalinux|ubuntu|debian|anolis|opencloudos)
      log_info "OS: ${os_name}——目标支持平台" ;;
    unknown)
      log_warn "无法识别 OS（无 ${OS_RELEASE_FILE}；--dry-run 演练或非 Linux 环境则属正常），按通用路径继续" ;;
    *)
      log_warn "OS: ${os_name}（未列入目标支持平台清单，参数按通用 Linux 经验值应用，请复核后投产）" ;;
  esac
  log_info "内核: $(uname -sr 2>/dev/null || printf '未知')（bbr 需 ≥4.9，建议 ≥4.19）"
}

# ---------- 2. 网卡发现与 NUMA 拓扑 ----------
# 输出全局：IFACE_LIST / IFACE_NUMA / IFACE_CPUS / IFACE_NCPU（平行数组）
discover_ifaces() {
  log_info "步骤 2/6：10G 网卡发现与 NUMA 拓扑解析"
  IFACE_LIST=()
  if [[ "${#IFACES[@]}" -gt 0 ]]; then
    IFACE_LIST=("${IFACES[@]}")
    log_info "按 --iface 显式指定: ${IFACE_LIST[*]}"
  else
    local name
    while IFS= read -r name; do
      IFACE_LIST+=("$name")
    done < <(list_10g_ifaces)
  fi
  if [[ "${#IFACE_LIST[@]}" -eq 0 ]]; then
    if [[ "$DRY_RUN" == "true" ]]; then
      log_warn "未发现 speed==10000 的接口（dry-run 演练模式，以占位网卡 eth10g0 演示流程）"
      IFACE_LIST=("eth10g0")
    else
      die "未发现 10G 接口（$SYSFS_ROOT/class/net/*/speed == 10000）；
       若网卡尚未 UP 或驱动不报告速率，请用 --iface 显式指定业务网卡"
    fi
  fi
  IFACE_NUMA=()
  IFACE_CPUS=()
  IFACE_NCPU=()
  local iface node cpus n
  for iface in "${IFACE_LIST[@]}"; do
    node="$(iface_numa_node "$iface" || true)"
    cpus="$(iface_numa_cpus "$iface")"
    n="$(printf '%s' "$cpus" | wc -w | tr -d ' ')"
    [[ -n "$node" && "$node" != "-1" ]] || node="未知"
    IFACE_NUMA+=("$node")
    IFACE_CPUS+=("$cpus")
    IFACE_NCPU+=("$n")
    log_info "$iface: NUMA=$node 本地CPU=${n}核"
  done
}

# ---------- 3. sysctl ----------
write_sysctl_conf() {
  log_info "步骤 3/6：写入 sysctl 调优配置（$TARGET 档）"
  guard_managed "$SYSCTL_DEST"

  # bbr 仅在内核支持时写入（麒麟 V10/openEuler 20.03+ 内核 ≥4.19，通常支持）
  local bbr_line=""
  if [[ -r /proc/sys/net/ipv4/tcp_available_congestion_control ]]; then
    if grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control; then
      bbr_line="net.ipv4.tcp_congestion_control = bbr"
    else
      note_warn "内核 tcp_available_congestion_control 不含 bbr，跳过拥塞控制调优（其余项不受影响）"
    fi
  elif [[ "$DRY_RUN" == "true" ]]; then
    log_warn "无法检测 bbr 支持（dry-run/非 Linux 环境），按支持处理仅作演示"
    bbr_line="net.ipv4.tcp_congestion_control = bbr"
  else
    note_warn "无法读取 tcp_available_congestion_control，跳过 bbr 设置"
  fi

  if [[ "$DRY_RUN" == "true" ]]; then
    printf '[DRY-RUN] 写入 %s（%s 档参数 + 管理标记）\n' "$SYSCTL_DEST" "$TARGET"
    printf '[DRY-RUN] sysctl -p %s\n' "$SYSCTL_DEST"
    note_applied "sysctl 参数（$TARGET 档，dry-run 演练）"
    return 0
  fi
  local rendered
  rendered="$(mktemp "${TMPDIR:-/tmp}/jzgwtune.XXXXXX")"
  {
    printf '# %s\n' "$TUNE_MARKER"
    printf '# 九章裸机网关性能调优（tune-gateway-baremetal.sh 生成，目标 %s Gbps HTTP 吞吐）\n' "$TARGET"
    printf '# 手册与验收: docs/BARE_METAL_PERFORMANCE_TUNING.md\n'
    printf '#\n'
    printf '# somaxconn/netdev_max_backlog/tcp_max_syn_backlog：连接与收报队列深度，吸收突发；\n'
    printf '# rmem/wmem 与 tcp_rmem/tcp_wmem：socket/TCP 缓冲区上限，万兆长肥管道所需；\n'
    printf '# nf_conntrack_max：纯反代形态默认不加载 conntrack，未加载时内核忽略该键，无害；\n'
    printf '# tcp_congestion_control=bbr：仅在内核 tcp_available_congestion_control 含 bbr 时写入。\n'
    sysctl_params_for_target "$TARGET"
    [[ -n "$bbr_line" ]] && printf '%s\n' "$bbr_line"
  } > "$rendered"
  install -m 0644 -o root -g root "$rendered" "$SYSCTL_DEST"
  rm -f "$rendered"
  if sysctl -p "$SYSCTL_DEST" >/dev/null; then
    note_applied "sysctl 参数（$TARGET 档，${SYSCTL_DEST}）"
  else
    note_failed "sysctl -p $SYSCTL_DEST 应用存在失败项（文件已写入，请人工核对上方内核报错）"
  fi
}

# valid_iface NAME —— 严格校验网口名，防止命令注入或路径穿越。
valid_iface() {
  local name="$1"
  [[ "$name" =~ ^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$ ]] || return 1
  [[ "$name" != "." && "$name" != ".." ]] || return 1
  return 0
}

# add_replay_cmd CMD ARGS... —— 使用 printf '%q' 安全转义每个参数后再写入开机重放队列。
add_replay_cmd() {
  local formatted="" arg
  for arg in "$@"; do
    printf -v formatted '%s %q' "$formatted" "$arg"
  done
  REPLAY_CMDS+=("${formatted# }")
}

# ---------- 4. 网卡 ethtool 即时生效 + IRQ 亲和性 ----------
# 输出全局：REPLAY_CMDS（持久化辅助脚本要重放的命令）、IFACE_Q（队列数，报告用）
REPLAY_CMDS=()
IFACE_Q=()

tune_iface_nic() {
  local iface="$1" ncpu="$2"
  local rx tx q maxrx maxtx maxq
  valid_iface "$iface" || die "非法网卡名: $iface"
  rx="$(ring_preset_for_target "$TARGET")"
  tx="$rx"
  q="$ncpu"
  maxrx=""; maxtx=""; maxq=""
  if command -v ethtool >/dev/null 2>&1; then
    maxrx="$(ethtool_max "$iface" -g RX || true)"
    maxtx="$(ethtool_max "$iface" -g TX || true)"
    maxq="$(ethtool_max "$iface" -l Combined || true)"
  elif [[ "$DRY_RUN" != "true" ]]; then
    note_warn "缺少 ethtool，跳过 $iface 网卡参数即时调优（请安装 ethtool 后重跑；持久化 unit 仍会重放）"
    IFACE_Q+=("未调整")
    return 0
  fi
  # ring buffer：取 min(预设, 网卡上限)；dry-run/读不到上限时按预设演示
  if [[ "$maxrx" =~ ^[0-9]+$ ]] && ((maxrx < rx)); then rx="$maxrx"; fi
  if [[ "$maxtx" =~ ^[0-9]+$ ]] && ((maxtx < tx)); then tx="$maxtx"; fi
  if [[ -z "$maxrx" && "$DRY_RUN" == "true" ]]; then
    log_warn "$iface: ring 上限未知（dry-run/无 ethtool），按预设值演示"
  fi
  ethtool_try ethtool -G "$iface" rx "$rx" tx "$tx"
  add_replay_cmd ethtool -G "$iface" rx "$rx" tx "$tx"
  # TSO/GSO/GRO 开启降低 CPU 拷贝与协议栈开销；LRO 必须关——网桥/透明代理模式下
  # LRO 聚合后再转发会改写包内容并导致桥接转发异常（见设计文档 LRO 小节）。
  ethtool_try ethtool -K "$iface" tso on gso on gro on lro off
  add_replay_cmd ethtool -K "$iface" tso on gso on gro on lro off
  # 队列数：min(NUMA 本地核数, 网卡最大 combined 队列)
  if [[ "$maxq" =~ ^[0-9]+$ ]] && ((maxq > 0)); then
    ((maxq < q)) && q="$maxq"
  elif [[ "$DRY_RUN" == "true" ]]; then
    log_warn "$iface: 队列上限未知（dry-run/无 ethtool），按 NUMA 本地核数演示"
  else
    note_warn "$iface: 无法读取队列上限（ethtool -l），跳过队列数调整"
    IFACE_Q+=("未调整")
    return 0
  fi
  ethtool_try ethtool -L "$iface" combined "$q"
  add_replay_cmd ethtool -L "$iface" combined "$q"
  IFACE_Q+=("$q")
  # 中断合并：自适应模式；不支持的驱动告警跳过
  ethtool_try ethtool -C "$iface" adaptive-rx on adaptive-tx on
  add_replay_cmd ethtool -C "$iface" adaptive-rx on adaptive-tx on
}

# tune_iface_irq IFACE CPUS —— MSI-X IRQ 绑同 NUMA 核（轮转分配）。
tune_iface_irq() {
  local iface="$1" cpus="$2"
  valid_iface "$iface" || die "非法网卡名: $iface"
  local irqs="" irqdir="$SYSFS_ROOT/class/net/$iface/device/msi_irqs"
  if [[ -d "$irqdir" ]]; then
    irqs="$(ls "$irqdir" 2>/dev/null | sort -n | tr '\n' ' ' | sed 's/ $//')"
  fi
  if [[ -z "$irqs" && -r /proc/interrupts ]]; then
    irqs="$(awk -v iface="$iface" 'index($NF, iface) > 0 { gsub(":", "", $1); print $1 }' \
      /proc/interrupts 2>/dev/null | sort -n | tr '\n' ' ' | sed 's/ $//')"
  fi
  if [[ -z "$irqs" ]]; then
    if [[ "$DRY_RUN" == "true" ]]; then
      log_warn "$iface: 枚举不到 MSI-X IRQ（dry-run/无真实网卡），以占位 IRQ 90 演示"
      irqs="90"
    else
      note_warn "$iface: 无法枚举 MSI-X IRQ（msi_irqs 与 /proc/interrupts 均无），跳过 IRQ 亲和性"
      return 0
    fi
  fi
  local arr=() irq cpu i=0 n count=0
  read -ra arr <<< "$cpus"
  n="${#arr[@]}"
  if [[ "$n" -eq 0 ]]; then
    note_warn "$iface: NUMA 本地 CPU 列表为空，跳过 IRQ 亲和性"
    return 0
  fi
  for irq in $irqs; do
    [[ "$irq" =~ ^[0-9]+$ ]] || continue
    cpu="${arr[$((i % n))]}"
    [[ "$cpu" =~ ^[0-9]+$ ]] || continue
    if write_file "/proc/irq/$irq/smp_affinity_list" "$cpu"; then
      count=$((count + 1))
    else
      note_failed "$iface: 写入 /proc/irq/$irq/smp_affinity_list 失败"
    fi
    add_replay_cmd irq_affinity "$irq" "$cpu"
    i=$((i + 1))
  done
  note_applied "$iface: IRQ 亲和性（$count 个 IRQ 绑 NUMA 本地 ${n} 核轮转）"
}

apply_nic_tuning() {
  log_info "步骤 4/6：网卡 ethtool 即时生效与 IRQ 亲和性"
  local idx iface
  for idx in "${!IFACE_LIST[@]}"; do
    iface="${IFACE_LIST[$idx]}"
    tune_iface_nic "$iface" "${IFACE_NCPU[$idx]}"
    tune_iface_irq "$iface" "${IFACE_CPUS[$idx]}"
  done
}

# ---------- 5. CPU governor 与 irqbalance ----------
tune_governor_and_irqbalance() {
  log_info "步骤 5/6：CPU governor 与 irqbalance 处置"
  if [[ -e "$SYSFS_ROOT/devices/system/cpu/cpu0/cpufreq/scaling_governor" ]]; then
    local f count=0
    for f in "$SYSFS_ROOT"/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_governor; do
      [[ -e "$f" ]] || continue
      if write_file "$f" "performance"; then
        count=$((count + 1))
      else
        note_failed "governor 写入失败: $f"
      fi
    done
    note_applied "CPU governor=performance（$count 个核，幂等）"
  else
    log_info "无 cpufreq scaling_governor（虚拟机或 governor 已锁定），跳过"
  fi

  # irqbalance 在运行时会周期性重均衡 IRQ，冲掉上面的绑核结果。
  # 不擅自停系统服务：打印处置建议，由运维决策（--keep-irqbalance 表示已知悉并保留）。
  if command -v systemctl >/dev/null 2>&1 && \
     systemctl is-active --quiet irqbalance 2>/dev/null; then
    if [[ "$KEEP_IRQBALANCE" == "true" ]]; then
      log_warn "irqbalance 运行中且指定 --keep-irqbalance：请为其配置网卡 IRQ ban，否则会冲掉 IRQ 亲和性"
    else
      note_warn "irqbalance 运行中：建议 systemctl disable --now irqbalance，或在 /etc/sysconfig/irqbalance 配置网卡 IRQ ban（本脚本不擅停系统服务）"
    fi
  else
    log_info "irqbalance 未运行（或未安装），IRQ 亲和性不会被重均衡"
  fi
}

# ---------- 6. 持久化 unit + install.env 落档 ----------
write_persistence() {
  log_info "步骤 6/6：生成开机重放 unit 并落档 install.env"
  guard_managed "$HELPER_DEST"
  guard_managed "$UNIT_DEST"
  if [[ "$DRY_RUN" == "true" ]]; then
    printf '[DRY-RUN] 写入 %s（root 0750，重放 ethtool/IRQ 命令，带管理标记）\n' "$HELPER_DEST"
    printf '[DRY-RUN] 写入 %s（oneshot，After=network-pre.target Before=jiuzhang-gateway.service）\n' "$UNIT_DEST"
    printf '[DRY-RUN] systemctl daemon-reload && systemctl enable %s（不带 --now，即时生效已做）\n' "$UNIT_NAME"
    note_applied "开机重放 unit（dry-run 演练）"
  else
    install -d -m 0750 -o root -g root "$HELPER_DIR"
    local helper
    helper="$(mktemp "${TMPDIR:-/tmp}/jzgwtunehelper.XXXXXX")"
    {
      printf '#!/usr/bin/env bash\n'
      printf '# %s\n' "$TUNE_MARKER"
      printf '# 九章裸机网关网卡调优开机重放（tune-gateway-baremetal.sh 生成）\n'
      printf '# 单项失败只告警不退出非零：不阻断 jiuzhang-gateway.service 启动。\n'
      printf 'set -uo pipefail\n'
      printf 'run_cmd() { if ! "$@"; then echo "[WARN] tune-nic 执行失败: $*" >&2; fi; }\n'
      printf 'irq_affinity() { local f="/proc/irq/$1/smp_affinity_list"; [[ -e "$f" ]] || return 0; printf "%%s\\n" "$2" > "$f" || echo "[WARN] tune-nic 写入失败: $f" >&2; }\n'
      local c
      for c in ${REPLAY_CMDS[@]+"${REPLAY_CMDS[@]}"}; do
        printf 'run_cmd %s\n' "$c"
      done
      printf 'exit 0\n'
    } > "$helper"
    install -m 0750 -o root -g root "$helper" "$HELPER_DEST"
    rm -f "$helper"

    local unit
    unit="$(mktemp "${TMPDIR:-/tmp}/jzgwtuneunit.XXXXXX")"
    cat > "$unit" <<EOF
# $TUNE_MARKER
[Unit]
Description=JiuZhang gateway NIC performance tuning replay
Documentation=docs/BARE_METAL_PERFORMANCE_TUNING.md
DefaultDependencies=no
After=network-pre.target
Before=jiuzhang-gateway.service

[Service]
Type=oneshot
ExecStart=$HELPER_DEST
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    install -m 0644 -o root -g root "$unit" "$UNIT_DEST"
    rm -f "$unit"
    run systemctl daemon-reload
    # 不 --now：ethtool/IRQ 即时生效前面已做，unit 仅负责重启后重放
    run systemctl enable "$UNIT_NAME"
    note_applied "开机重放 unit（${UNIT_NAME}，enabled）"
  fi

  # 结果落档：幂等追加/更新 JIUZHANG_GW_TUNE_TARGET
  if [[ "$DRY_RUN" == "true" ]]; then
    printf '[DRY-RUN] 写入/更新 %s: JIUZHANG_GW_TUNE_TARGET=%s（不存在则创建 0640）\n' \
      "$INSTALL_ENV_FILE" "$TARGET"
    return 0
  fi
  install -d -m 0750 -o root -g root "$INSTALL_ENV_DIR"
  if [[ -f "$INSTALL_ENV_FILE" ]] && grep -q '^JIUZHANG_GW_TUNE_TARGET=' "$INSTALL_ENV_FILE"; then
    local tmp
    tmp="$(mktemp "${TMPDIR:-/tmp}/jzgwtuneenv.XXXXXX")"
    awk -v v="JIUZHANG_GW_TUNE_TARGET=$TARGET" \
      '{ if ($0 ~ /^JIUZHANG_GW_TUNE_TARGET=/) print v; else print }' \
      "$INSTALL_ENV_FILE" > "$tmp"
    cat "$tmp" > "$INSTALL_ENV_FILE"
    rm -f "$tmp"
  else
    printf 'JIUZHANG_GW_TUNE_TARGET=%s\n' "$TARGET" >> "$INSTALL_ENV_FILE"
  fi
  chmod 0640 "$INSTALL_ENV_FILE"
  note_applied "install.env 落档（JIUZHANG_GW_TUNE_TARGET=${TARGET}）"
}

# ---------- 报告 ----------
print_report() {
  local idx iface irq_note item
  cat <<EOF

==================== 九章裸机网关性能调优报告 ====================
  目标档:      ${TARGET} Gbps HTTP 吞吐
  网卡清单:
EOF
  for idx in "${!IFACE_LIST[@]}"; do
    iface="${IFACE_LIST[$idx]}"
    irq_note="${IFACE_Q[$idx]:-未调整}"
    printf '    - %s  NUMA=%s  本地CPU=%s核  队列=%s  IRQ=绑同NUMA核轮转\n' \
      "$iface" "${IFACE_NUMA[$idx]}" "${IFACE_NCPU[$idx]}" "$irq_note"
  done
  printf '  已应用项:\n'
  for item in ${APPLIED_ITEMS[@]+"${APPLIED_ITEMS[@]}"}; do printf '    - %s\n' "$item"; done
  if [[ "${#WARN_ITEMS[@]}" -gt 0 || "${#FAILED_ITEMS[@]}" -gt 0 ]]; then
    printf '  告警/待人工确认项:\n'
    for item in "${WARN_ITEMS[@]+"${WARN_ITEMS[@]}"}"; do printf '    - [WARN] %s\n' "$item"; done
    for item in "${FAILED_ITEMS[@]+"${FAILED_ITEMS[@]}"}"; do printf '    - [FAIL] %s\n' "$item"; done
  fi
  cat <<'EOF'
  验收指引: 万兆吞吐实测留待物理环境复测，步骤与判定标准见
            docs/BARE_METAL_PERFORMANCE_TUNING.md「验收方法」（本次安装未做实测）。
================================================================
EOF
}

# ---------- --check 模式（只读核对，不修改任何东西） ----------
CHECK_MISMATCHES=0
check_item() { # check_item OK|FAIL MSG
  if [[ "$1" == "OK" ]]; then
    printf '  [OK]   %s\n' "$2"
  else
    printf '  [FAIL] %s\n' "$2"
    CHECK_MISMATCHES=$((CHECK_MISMATCHES + 1))
  fi
}

# norm_ws —— 多值 sysctl（如 tcp_rmem）在 /proc 中为制表符分隔，统一归一为空格单分隔。
norm_ws() { awk '{$1=$1};1' <<< "$1"; }

check_mode() {
  log_info "--check 只读核对（目标档 ${TARGET}）"
  # 1) sysctl 文件存在且带标记，关键值已生效
  if [[ -f "$SYSCTL_DEST" ]] && grep -qF "$TUNE_MARKER" "$SYSCTL_DEST" 2>/dev/null; then
    check_item OK "sysctl 文件存在且含管理标记: $SYSCTL_DEST"
    local line key want proc got
    while IFS= read -r line; do
      key="${line%% =*}"
      want="$(norm_ws "${line#*= }")"
      proc="/proc/sys/${key//.//}"
      if [[ -r "$proc" ]]; then
        got="$(norm_ws "$(cat "$proc")")"
        if [[ "$got" == "$want" ]]; then
          check_item OK "$key = ${want}（已生效）"
        else
          check_item FAIL "$key 期望 $want 实际 $got"
        fi
      else
        check_item FAIL "$key 无法读取 ${proc}（非 Linux 环境或未应用）"
      fi
    done < <(sysctl_params_for_target "$TARGET")
    # bbr 仅当配置文件写入了该项才核对（内核不支持时安装期会跳过）
    if grep -q '^net.ipv4.tcp_congestion_control = bbr' "$SYSCTL_DEST" 2>/dev/null; then
      if [[ -r /proc/sys/net/ipv4/tcp_congestion_control ]] && \
         [[ "$(cat /proc/sys/net/ipv4/tcp_congestion_control)" == "bbr" ]]; then
        check_item OK "net.ipv4.tcp_congestion_control = bbr（已生效）"
      else
        check_item FAIL "net.ipv4.tcp_congestion_control 期望 bbr（配置已写入但未生效）"
      fi
    fi
  else
    check_item FAIL "sysctl 文件缺失或不含管理标记: $SYSCTL_DEST"
  fi
  # 2) unit 存在且 enabled
  if [[ -f "$UNIT_DEST" ]] && grep -qF "$TUNE_MARKER" "$UNIT_DEST" 2>/dev/null; then
    check_item OK "unit 文件存在且含管理标记: $UNIT_DEST"
    if command -v systemctl >/dev/null 2>&1 && \
       [[ "$(systemctl is-enabled "$UNIT_NAME" 2>/dev/null || true)" == "enabled" ]]; then
      check_item OK "$UNIT_NAME 已 enabled"
    else
      check_item FAIL "$UNIT_NAME 未 enabled（或无 systemctl 可核对）"
    fi
  else
    check_item FAIL "unit 文件缺失或不含管理标记: $UNIT_DEST"
  fi
  # 3) install.env 档位与 --target 一致
  if [[ -f "$INSTALL_ENV_FILE" ]] && \
     grep -q "^JIUZHANG_GW_TUNE_TARGET=$TARGET\$" "$INSTALL_ENV_FILE" 2>/dev/null; then
    check_item OK "install.env 档位一致: JIUZHANG_GW_TUNE_TARGET=$TARGET"
  else
    check_item FAIL "install.env 档位与 --target $TARGET 不一致（或文件缺失）: $INSTALL_ENV_FILE"
  fi
  printf '\n'
  if [[ "$CHECK_MISMATCHES" -eq 0 ]]; then
    log_info "--check 通过：全部一致"
    return 0
  fi
  log_warn "--check 发现 $CHECK_MISMATCHES 项不一致"
  return 1
}

# ---------- main ----------
main() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --target)          TARGET="$2"; shift 2 ;;
      --iface)
        valid_iface "${2:-}" || { log_err "--iface 非法网口名: ${2:-<空>}"; usage; exit 2; }
        IFACES+=("$2"); shift 2 ;;
      --apply)
        if [[ "$MODE_EXPLICIT" == "true" && "$MODE" != "apply" ]]; then
          log_err "--apply 与 --check 互斥"; usage; exit 2
        fi
        MODE="apply"; MODE_EXPLICIT=true; shift ;;
      --check)
        if [[ "$MODE_EXPLICIT" == "true" && "$MODE" != "check" ]]; then
          log_err "--apply 与 --check 互斥"; usage; exit 2
        fi
        MODE="check"; MODE_EXPLICIT=true; shift ;;
      --keep-irqbalance) KEEP_IRQBALANCE=true; shift ;;
      --dry-run)         DRY_RUN=true; shift ;;
      -h|--help)         usage; exit 0 ;;
      *) log_err "未知参数: $1"; usage; exit 2 ;;
    esac
  done
  [[ -z "$MODE" ]] && MODE="apply"
  case "$TARGET" in
    6|8|10) ;;
    *) log_err "--target 非法值: ${TARGET}（仅支持 6|8|10）"; usage; exit 2 ;;
  esac

  preflight
  if [[ "$MODE" == "check" ]]; then
    check_mode
    exit $?
  fi
  discover_ifaces
  write_sysctl_conf
  apply_nic_tuning
  tune_governor_and_irqbalance
  write_persistence
  print_report
}

# 允许测试 harness source 本脚本单测内部函数；直接执行时才进入 main。
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
