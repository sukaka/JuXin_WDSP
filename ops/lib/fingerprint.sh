#!/usr/bin/env bash
# fingerprint.sh —— 九章 WAF 宿主机指纹采集脚本（安装期/运维期使用）。
#
# 与授权中心 tools/fingerprint 算法一致（逐字节相同的采集、规范化、拼接与哈希）：
#   fingerprint = "sha256:" + hex( sha256( "v1|<mac>|<machine_id>|<cpu_model>" ) )
# 三项采集（部署目标为 Linux）：
#   1. 主要非回环网卡 MAC：优先默认路由接口（ip route show default 的 dev），
#      读取 /sys/class/net/<if>/address；取不到则按内核 ifindex 顺序回退到
#      第一块“已启用、非回环、带 MAC”的网卡（与 Go net.Interfaces 遍历顺序一致）。
#   2. 机器标识：/etc/machine-id，缺失回退 /var/lib/dbus/machine-id。
#      （macOS 无这两个文件，得到 unknown，属预期。）
#   3. CPU 型号：/proc/cpuinfo 中首个 model name 的值。
# 每项拼接前规范化：去首尾空白、统一小写、连续空白折叠为单个空格；
# 某项取不到记 unknown，本脚本不因此报错退出。
#
# 用法：
#   fingerprint.sh          输出一行 sha256:<64位十六进制> 指纹
#   fingerprint.sh --json   输出三项原始值/规范化值/指纹（供核对采集内容）
#   fingerprint.sh --help   显示说明
# 退出码：0=成功 1=无法计算哈希（无任何可用 sha256 工具） 2=用法错误
#
# 本脚本不联网、不修改任何文件，仅读取 /sys /proc /etc 下的既定文件。
set -uo pipefail

# 指纹算法版本前缀（与授权中心 fingerprintVersion 常量一致；算法调整时同步递增）。
readonly FP_VERSION="v1"
# 采集源不可用时的占位值（与授权中心 unknownValue 常量一致）。
readonly FP_UNKNOWN="unknown"
# 向客户公开的算法说明（与授权中心 algorithmDesc 一致，--json 输出引用）。
readonly FP_ALGORITHM_DESC='sha256("v1|<mac>|<machine_id>|<cpu_model>")，各项先经过去除首尾空白、统一小写、连续空白折叠为单个空格的规范化'

usage() {
  cat <<'EOF'
用法: fingerprint.sh [--json|--help]

在需要授权的目标主机上运行，输出 sha256: 机器指纹串。
安装向导（ops/install/install.sh）会自动调用本脚本并写入
<安装根>/runtime/license/host_fingerprint；授权管理页面展示的指纹即来源于此。

  --json   以 JSON 输出三项采集明细（原始值与规范化值）与指纹，供核对
  --help   显示本说明
EOF
}

# normalize —— 与签发侧 normalize 一致：
# 去首尾空白 → 统一小写 → 内部连续空白（含制表/换行）折叠为单个空格。
normalize() {
  local s="$1"
  s="$(printf '%s' "$s" | tr '[:upper:]' '[:lower:]')"
  s="$(printf '%s' "$s" | tr -s '[:space:]' ' ')"
  s="${s# }"
  s="${s% }"
  printf '%s' "$s"
}

# or_unknown RAW —— 原始值规范化后为空则输出 unknown，否则原样输出。
or_unknown() {
  local raw="$1"
  if [[ -z "$(normalize "$raw")" ]]; then
    printf '%s' "$FP_UNKNOWN"
  else
    printf '%s' "$raw"
  fi
}

# trim —— 仅去首尾空白（对应签发侧 strings.TrimSpace，用于原始值）。
trim() {
  local s="$1"
  s="$(printf '%s' "$s" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  printf '%s' "$s"
}

# mac_from_sysfs IFACE —— 读取 /sys/class/net/<if>/address；
# 空值或全零地址（无 MAC 的虚拟接口）视为取不到。
mac_from_sysfs() {
  local ifname="$1" addr=""
  [[ -r "/sys/class/net/${ifname}/address" ]] || return 1
  addr="$(trim "$(cat "/sys/class/net/${ifname}/address" 2>/dev/null)")"
  [[ -n "$addr" && "$addr" != "00:00:00:00:00:00" ]] || return 1
  printf '%s' "$addr"
}

# iface_is_up IFACE —— 按 /sys/class/net/<if>/flags 的 IFF_UP(0x1) 位判定，
# 与签发侧 net.FlagUp 检查一致。
iface_is_up() {
  local ifname="$1" flags=""
  [[ -r "/sys/class/net/${ifname}/flags" ]] || return 1
  flags="$(cat "/sys/class/net/${ifname}/flags" 2>/dev/null)"
  [[ -n "$flags" ]] || return 1
  (( (flags) & 0x1 )) 2>/dev/null
}

# collect_mac —— 主要非回环网卡 MAC。
# 优先默认路由接口；取不到则按 ifindex 升序遍历（与 Go net.Interfaces
# 返回顺序一致）找第一块“已启用、非回环、带 MAC”的网卡。
collect_mac() {
  local ifname="" addr=""
  # 1) 默认路由接口（多默认路由时取第一条）
  if command -v ip >/dev/null 2>&1; then
    ifname="$(ip route show default 2>/dev/null \
      | awk '/^default/ {for (i = 1; i <= NF; i++) if ($i == "dev") {print $(i+1); exit}}')"
    if [[ -n "$ifname" ]]; then
      addr="$(mac_from_sysfs "$ifname")" && { printf '%s' "$addr"; return 0; }
    fi
  fi
  # 2) 回退：按内核 ifindex 顺序遍历 /sys/class/net
  local entries name idx
  entries="$(
    for path in /sys/class/net/*; do
      [[ -d "$path" ]] || continue
      name="${path##*/}"
      [[ "$name" == "lo" ]] && continue
      idx="$(cat "$path/ifindex" 2>/dev/null || printf '999999')"
      printf '%s %s\n' "$idx" "$name"
    done | sort -n
  )"
  while IFS=' ' read -r _ name; do
    [[ -n "${name:-}" ]] || continue
    iface_is_up "$name" || continue
    addr="$(mac_from_sysfs "$name")" && { printf '%s' "$addr"; return 0; }
  done <<< "$entries"
  return 1
}

# collect_machine_id —— /etc/machine-id，缺失回退 /var/lib/dbus/machine-id；
# 内容为空视为不存在（与签发侧一致）。macOS 两者皆无 → 空（归 unknown）。
collect_machine_id() {
  local f id
  for f in /etc/machine-id /var/lib/dbus/machine-id; do
    [[ -r "$f" ]] || continue
    id="$(trim "$(cat "$f" 2>/dev/null)")"
    if [[ -n "$id" ]]; then
      printf '%s' "$id"
      return 0
    fi
  done
  return 1
}

# collect_cpu —— /proc/cpuinfo 中首个 model name 冒号后的值（去首尾空白），
# 与签发侧 parseCPUInfo 一致。无 model name（如部分 ARM）→ 空（归 unknown）。
collect_cpu() {
  [[ -r /proc/cpuinfo ]] || return 1
  awk '
    /^model name/ {
      i = index($0, ":")
      if (i > 0) {
        v = substr($0, i + 1)
        gsub(/^[ \t]+/, "", v)
        gsub(/[ \t]+$/, "", v)
        if (v != "") { print v; exit }
      }
    }
  ' /proc/cpuinfo
}

# sha256_hex —— 从 stdin 读数据，输出小写 hex 摘要。
# 优先 sha256sum，回退 shasum -a 256，再回退 openssl dgst -sha256。
sha256_hex() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 | awk '{print $1}'
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 | awk '{print $NF}'
  else
    return 1
  fi
}

# json_escape —— 转义 JSON 字符串特殊字符（反斜杠/引号/制表/回车）。
json_escape() {
  awk -v s="$1" 'BEGIN {
    gsub(/\\/, "\\\\", s)
    gsub(/"/, "\\\"", s)
    gsub(/\t/, "\\t", s)
    gsub(/\r/, "\\r", s)
    printf "%s", s
  }'
}

main() {
  local as_json=false
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --json)    as_json=true; shift ;;
      -h|--help) usage; exit 0 ;;
      *) printf '[ERROR] 未知参数: %s\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
  done

  # 三项采集：任一取不到记 unknown，不报错退出
  local raw_mac raw_id raw_cpu
  raw_mac="$(or_unknown "$(collect_mac)")"
  raw_id="$(or_unknown "$(collect_machine_id)")"
  raw_cpu="$(or_unknown "$(collect_cpu)")"

  # 规范化（规范化后必非空：原始值为空时已归 unknown）
  local n_mac n_id n_cpu
  n_mac="$(normalize "$raw_mac")"; n_mac="${n_mac:-$FP_UNKNOWN}"
  n_id="$(normalize "$raw_id")";   n_id="${n_id:-$FP_UNKNOWN}"
  n_cpu="$(normalize "$raw_cpu")"; n_cpu="${n_cpu:-$FP_UNKNOWN}"

  # 拼接哈希输入：v1|<mac>|<machine_id>|<cpu_model>（无尾随换行）
  local joined fingerprint
  joined="${FP_VERSION}|${n_mac}|${n_id}|${n_cpu}"
  fingerprint="$(printf '%s' "$joined" | sha256_hex)" || {
    printf '[ERROR] 未找到可用的 sha256 工具（sha256sum / shasum / openssl 均不可用）\n' >&2
    exit 1
  }
  fingerprint="sha256:${fingerprint}"

  if [[ "$as_json" == "true" ]]; then
    # 输出结构与授权中心 tools/fingerprint --json 一致（raw/normalized/algorithm）
    cat <<EOF
{
  "fingerprint": "${fingerprint}",
  "raw": {
    "mac": "$(json_escape "$raw_mac")",
    "machine_id": "$(json_escape "$raw_id")",
    "cpu_model": "$(json_escape "$raw_cpu")"
  },
  "normalized": {
    "mac": "$(json_escape "$n_mac")",
    "machine_id": "$(json_escape "$n_id")",
    "cpu_model": "$(json_escape "$n_cpu")"
  },
  "algorithm": "$(json_escape "$FP_ALGORITHM_DESC")"
}
EOF
  else
    printf '%s\n' "$fingerprint"
  fi
}

main "$@"
