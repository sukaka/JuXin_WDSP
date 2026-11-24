#!/usr/bin/env bash
# CentOS 7 / openEuler / RHEL / Alibaba Cloud Linux 压测机初始化脚本
# 用途：安装压测与监控基础工具、安装静态 k6、源码编译 wrk/wrk2、应用压测端 TCP/FD 调优。
# 兼容离线内网环境（可通过 --k6-tarball / --wrk-src / --wrk2-src 指定本地离线包）。
set -euo pipefail

K6_VERSION="${K6_VERSION:-v0.55.0}"
K6_TARBALL=""
WRK_SRC=""
WRK2_SRC=""
INSTALL_BASE_PKGS=0
INSTALL_K6=0
BUILD_WRK=0
BUILD_WRK2=0
APPLY_SYSCTL=0
TUNE_IFACE=""
PREFIX="/usr/local/bin"

usage() {
  cat <<'EOF'
用法: setup-loadgen-centos7.sh [选项]

选项:
  --base-pkgs           安装系统基础工具 (iperf3, sysstat, ethtool, numactl, jq, gcc, make, openssl-devel, git, fio)
  --install-k6          安装静态编译版 k6 (兼容 CentOS 7 glibc 2.17)
  --k6-version VER      指定 k6 版本 (默认: v0.55.0)
  --k6-tarball PATH     使用本地 k6 tar.gz 离线安装 (内网无外网环境使用)
  --build-wrk           本地源码编译 wrk 并安装到 /usr/local/bin/wrk
  --wrk-src DIR         使用本地已解压的 wrk 源码目录编译
  --build-wrk2          本地源码编译 wrk2 (开环恒定 RPS) 并安装到 /usr/local/bin/wrk2
  --wrk2-src DIR        使用本地已解压的 wrk2 源码目录编译
  --apply-sysctl        写入压测机专用 sysctl 与 nofile 调优 (/etc/sysctl.d/99-wdsp-loadgen.conf)
  --tune-iface IFACE    检查并开启压测机万兆网卡 ring buffer 与 offload (需 root)
  --all                 等价于 --base-pkgs --install-k6 --build-wrk --build-wrk2 --apply-sysctl
  -h, --help            显示帮助

示例:
  # 联网 CentOS 7 / 阿里云 8C16G 压测机一键初始化
  sudo bash setup-loadgen-centos7.sh --all --tune-iface ens1f0

  # 内网离线 CentOS 7 仅应用内核调优并安装离线 k6
  sudo bash setup-loadgen-centos7.sh --apply-sysctl --install-k6 --k6-tarball /tmp/k6-v0.55.0-linux-amd64.tar.gz
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base-pkgs) INSTALL_BASE_PKGS=1; shift ;;
    --install-k6) INSTALL_K6=1; shift ;;
    --k6-version) K6_VERSION="$2"; shift 2 ;;
    --k6-tarball) K6_TARBALL="$2"; INSTALL_K6=1; shift 2 ;;
    --build-wrk) BUILD_WRK=1; shift ;;
    --wrk-src) WRK_SRC="$2"; BUILD_WRK=1; shift 2 ;;
    --build-wrk2) BUILD_WRK2=1; shift ;;
    --wrk2-src) WRK2_SRC="$2"; BUILD_WRK2=1; shift 2 ;;
    --apply-sysctl) APPLY_SYSCTL=1; shift ;;
    --tune-iface) TUNE_IFACE="$2"; shift 2 ;;
    --all)
      INSTALL_BASE_PKGS=1
      INSTALL_K6=1
      BUILD_WRK=1
      BUILD_WRK2=1
      APPLY_SYSCTL=1
      shift
      ;;
    -h|--help) usage; exit 0 ;;
    *) echo "未知参数: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ $INSTALL_BASE_PKGS -eq 0 && $INSTALL_K6 -eq 0 && $BUILD_WRK -eq 0 && $BUILD_WRK2 -eq 0 && $APPLY_SYSCTL -eq 0 && -z "$TUNE_IFACE" ]]; then
  usage
  exit 0
fi

require_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "错误: 此操作需要 root 权限（请使用 sudo）。" >&2
    exit 1
  fi
}

detect_pkg_mgr() {
  if command -v dnf >/dev/null 2>&1; then
    echo "dnf"
  elif command -v yum >/dev/null 2>&1; then
    echo "yum"
  elif command -v apt-get >/dev/null 2>&1; then
    echo "apt"
  else
    echo "unknown"
  fi
}

install_base_pkgs() {
  require_root
  local pm
  pm="$(detect_pkg_mgr)"
  echo "[loadgen] 使用包管理器 ($pm) 安装基础压测与监控工具..."
  case "$pm" in
    dnf|yum)
      "$pm" install -y epel-release >/dev/null 2>&1 || true
      "$pm" install -y iperf3 sysstat ethtool numactl jq gcc make openssl-devel zlib-devel git curl tar unzip fio iproute net-tools
      ;;
    apt)
      apt-get update -y
      apt-get install -y iperf3 sysstat ethtool numactl jq gcc make libssl-dev zlib1g-dev git curl tar unzip fio iproute2 net-tools
      ;;
    *)
      echo "错误: 未识别的包管理器，请手工安装 iperf3/sysstat/ethtool/numactl/jq/gcc/make/openssl-devel/fio。" >&2
      exit 1
      ;;
  esac
}

install_k6() {
  require_root
  local tmpdir
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' RETURN

  local arch
  arch="$(uname -m)"
  case "$arch" in
    x86_64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *) echo "错误: 不支持的架构 $arch" >&2; exit 1 ;;
  esac

  local tarball="$K6_TARBALL"
  if [[ -z "$tarball" ]]; then
    local url="https://github.com/grafana/k6/releases/download/${K6_VERSION}/k6-${K6_VERSION}-linux-${arch}.tar.gz"
    tarball="${tmpdir}/k6.tar.gz"
    echo "[loadgen] 下载静态 k6: $url"
    curl -fSL "$url" -o "$tarball"
  else
    [[ -f "$tarball" ]] || { echo "错误: 找不到本地 k6 包: $tarball" >&2; exit 1; }
  fi

  tar -xzf "$tarball" -C "$tmpdir"
  local k6_bin
  k6_bin="$(find "$tmpdir" -type f -name k6 | head -n 1)"
  [[ -n "$k6_bin" ]] || { echo "错误: 压缩包中未找到 k6 二进制" >&2; exit 1; }
  install -m 0755 "$k6_bin" "${PREFIX}/k6"
  echo "[loadgen] k6 安装完成: $("${PREFIX}/k6" version)"
}

build_wrk_like() {
  require_root
  local tool="$1"
  local repo="$2"
  local src_dir="$3"
  local tmpdir=""

  if [[ -z "$src_dir" ]]; then
    tmpdir="$(mktemp -d)"
    trap '[[ -n "$tmpdir" ]] && rm -rf "$tmpdir"' RETURN
    src_dir="${tmpdir}/${tool}"
    echo "[loadgen] 克隆 ${tool}: ${repo}"
    git clone --depth 1 "$repo" "$src_dir"
  else
    [[ -d "$src_dir" ]] || { echo "错误: 找不到源码目录: $src_dir" >&2; exit 1; }
  fi

  local jobs
  jobs="$(nproc 2>/dev/null || echo 4)"
  echo "[loadgen] 编译 ${tool} (-j${jobs})..."
  (
    cd "$src_dir"
    make -j"$jobs"
    local bin_name="$tool"
    [[ -x "./${bin_name}" ]] || bin_name="wrk"
    install -m 0755 "./${bin_name}" "${PREFIX}/${tool}"
  )
  echo "[loadgen] ${tool} 安装完成: ${PREFIX}/${tool}"
}

apply_sysctl() {
  require_root
  echo "[loadgen] 写入 /etc/sysctl.d/99-wdsp-loadgen.conf ..."
  cat <<'EOF' > /etc/sysctl.d/99-wdsp-loadgen.conf
# wdsp-managed: loadgen-tuning
# 回滚命令: rm -f /etc/sysctl.d/99-wdsp-loadgen.conf && sysctl --system
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 262144
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.ipv4.tcp_max_syn_backlog = 131072
net.ipv4.ip_local_port_range = 10240 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
fs.file-max = 2097152
fs.nr_open = 2097152
EOF
  sysctl -p /etc/sysctl.d/99-wdsp-loadgen.conf || true

  echo "[loadgen] 写入 /etc/security/limits.d/99-wdsp-loadgen.conf ..."
  cat <<'EOF' > /etc/security/limits.d/99-wdsp-loadgen.conf
# wdsp-managed: loadgen-tuning
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF
  echo "[loadgen] 提示: 重新登录 SSH 或执行 'ulimit -n 1048576' 使文件句柄上限立即生效。"
}

tune_iface() {
  require_root
  local iface="$1"
  if [[ ! -d "/sys/class/net/${iface}" ]]; then
    echo "错误: 网卡不存在: ${iface}" >&2
    exit 1
  fi
  local speed
  speed="$(cat "/sys/class/net/${iface}/speed" 2>/dev/null || echo unknown)"
  echo "[loadgen] 网卡 ${iface} 当前协商速率: ${speed} Mb/s"
  if [[ "$speed" != "10000" ]]; then
    echo "警告: ${iface} 速率非 10000Mb/s，万兆压测前请先排查光模块/光纤/对端自协商。" >&2
  fi
  ethtool -G "$iface" rx 4096 tx 4096 2>/dev/null || echo "[loadgen] 提示: ring buffer 设置被驱动跳过（可能已达上限）"
  ethtool -K "$iface" tso on gso on gro on 2>/dev/null || true
  ethtool -C "$iface" adaptive-rx on adaptive-tx on 2>/dev/null || true
}

[[ $INSTALL_BASE_PKGS -eq 1 ]] && install_base_pkgs
[[ $INSTALL_K6 -eq 1 ]] && install_k6
[[ $BUILD_WRK -eq 1 ]] && build_wrk_like "wrk" "https://github.com/wg/wrk.git" "$WRK_SRC"
[[ $BUILD_WRK2 -eq 1 ]] && build_wrk_like "wrk2" "https://github.com/giltene/wrk2.git" "$WRK2_SRC"
[[ $APPLY_SYSCTL -eq 1 ]] && apply_sysctl
[[ -n "$TUNE_IFACE" ]] && tune_iface "$TUNE_IFACE"

echo "[loadgen] 完成。当前可用压测工具核对："
for bin in iperf3 k6 wrk wrk2 fio mpstat iostat ethtool; do
  if command -v "$bin" >/dev/null 2>&1; then
    printf "  [OK]   %-8s -> %s\n" "$bin" "$(command -v "$bin")"
  else
    printf "  [MISS] %-8s\n" "$bin"
  fi
done
