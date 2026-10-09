#!/usr/bin/env bash
# openEuler / 兆芯 WDSP 自解压安装包关键逻辑测试。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
PREPARE="$REPO_ROOT/ops/install/prepare-openeuler-zhaoxin.sh"
RUN_HEADER="$REPO_ROOT/ops/install/openeuler-zhaoxin-run-header.sh"
BUILD="$REPO_ROOT/ops/offline-package/build-openeuler-zhaoxin-run.sh"
BASE_BUILD="$REPO_ROOT/ops/offline-package/build.sh"

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/jz-openeuler-zhaoxin.XXXXXX")"
cleanup() {
  case "$TMP_ROOT" in
    */jz-openeuler-zhaoxin.*) rm -rf "$TMP_ROOT" ;;
    *) printf '拒绝清理非测试目录: %s\n' "$TMP_ROOT" >&2 ;;
  esac
}
trap cleanup EXIT INT TERM HUP

PASS_COUNT=0
FAIL_COUNT=0
pass() { PASS_COUNT=$((PASS_COUNT + 1)); printf 'PASS: %s\n' "$*"; }
fail() { FAIL_COUNT=$((FAIL_COUNT + 1)); printf 'FAIL: %s\n' "$*" >&2; }
check() {
  local name="$1"; shift
  if "$@" >/dev/null 2>&1; then pass "$name"; else fail "$name"; fi
}

for file in "$PREPARE" "$RUN_HEADER" "$BUILD"; do
  check "bash -n $(basename "$file")" bash -n "$file"
  check "$(basename "$file") --help" bash "$file" --help
done

OS_DIR="$TMP_ROOT/os"
mkdir -p "$OS_DIR"
printf 'ID=openEuler\nVERSION_ID="24.03"\n' > "$OS_DIR/openeuler"
printf 'ID=centos\nVERSION_ID="9"\n' > "$OS_DIR/centos"
CPU_DIR="$TMP_ROOT/cpu"
mkdir -p "$CPU_DIR"
printf 'vendor_id\t: CentaurHauls\nmodel name\t: ZHAOXIN KaiXian KX-7000\n' > "$CPU_DIR/zhaoxin"
printf 'vendor_id\t: GenuineIntel\nmodel name\t: Intel Xeon\n' > "$CPU_DIR/intel"

(
  source "$PREPARE"
  [[ "$(detect_os_id "$OS_DIR/openeuler")" == "openeuler" ]]
  is_openeuler "$OS_DIR/openeuler"
  ! is_openeuler "$OS_DIR/centos"
  [[ "$(detect_cpu_platform "$CPU_DIR/zhaoxin")" == "zhaoxin" ]]
  [[ "$(detect_cpu_platform "$CPU_DIR/intel")" == "other" ]]
) && pass "openEuler 与兆芯识别" || fail "openEuler 与兆芯识别"

BIN_DIR="$TMP_ROOT/bin"
LOG_FILE="$TMP_ROOT/pkg.log"
mkdir -p "$BIN_DIR"
printf '#!/bin/sh\nprintf "dnf %%s\\n" "$*" >> "$PKG_LOG"\n' > "$BIN_DIR/dnf"
printf '#!/bin/sh\nprintf "yum %%s\\n" "$*" >> "$PKG_LOG"\n' > "$BIN_DIR/yum"
chmod +x "$BIN_DIR/dnf" "$BIN_DIR/yum"
(
  source "$PREPARE"
  PATH="$BIN_DIR:/usr/bin:/bin"
  export PKG_LOG="$LOG_FILE"
  install_packages tar gzip
  grep -q '^dnf .*install.*tar gzip' "$LOG_FILE"
  ! grep -q '^yum ' "$LOG_FILE"
) && pass "依赖安装优先使用 dnf" || fail "依赖安装优先使用 dnf"

rm -f "$BIN_DIR/dnf" "$LOG_FILE"
(
  source "$PREPARE"
  PATH="$BIN_DIR:/usr/bin:/bin"
  export PKG_LOG="$LOG_FILE"
  install_packages tar
  grep -q '^yum .*install.*tar' "$LOG_FILE"
) && pass "dnf 缺失时回退 yum" || fail "dnf 缺失时回退 yum"

rm -f "$LOG_FILE"
printf '#!/bin/sh\nprintf "dnf %%s\\n" "$*" >> "$PKG_LOG"\ncase "$*" in *" docker-engine") exit 0 ;; *) exit 1 ;; esac\n' > "$BIN_DIR/dnf"
chmod +x "$BIN_DIR/dnf"
(
  source "$PREPARE"
  PATH="$BIN_DIR:/usr/bin:/bin"
  export PKG_LOG="$LOG_FILE"
  install_first_available docker docker-engine
  grep -q '^dnf .*install.*docker$' "$LOG_FILE"
  grep -q '^dnf .*install.*docker-engine$' "$LOG_FILE"
) && pass "Docker 软件包按新旧名称回退" || fail "Docker 软件包按新旧名称回退"

SYSTEMD_DIR="$TMP_ROOT/run/systemd/system"
mkdir -p "$SYSTEMD_DIR"
printf '#!/bin/sh\nexit 0\n' > "$BIN_DIR/systemctl"
chmod +x "$BIN_DIR/systemctl"
(
  source "$PREPARE"
  PATH="$BIN_DIR:/usr/bin:/bin"
  SYSTEMD_RUNTIME_DIR="$SYSTEMD_DIR"
  has_systemd_environment
) && pass "识别 systemd 运行环境" || fail "识别 systemd 运行环境"
(
  source "$PREPARE"
  PATH="$BIN_DIR:/usr/bin:/bin"
  SYSTEMD_RUNTIME_DIR="$TMP_ROOT/run/not-systemd"
  ! has_systemd_environment
) && pass "拒绝非 systemd 运行环境" || fail "拒绝非 systemd 运行环境"

ETC_ROOT="$TMP_ROOT/etc"
PROC_ROOT="$TMP_ROOT/proc/sys"
SYS_ROOT="$TMP_ROOT/sys"
mkdir -p "$ETC_ROOT" "$PROC_ROOT/fs" "$PROC_ROOT/net/core" \
  "$PROC_ROOT/net/ipv4" "$SYS_ROOT/devices/system/cpu/cpu0/cpufreq"
: > "$PROC_ROOT/fs/file-max"
: > "$PROC_ROOT/fs/nr_open"
: > "$PROC_ROOT/net/core/somaxconn"
: > "$PROC_ROOT/net/core/netdev_max_backlog"
: > "$PROC_ROOT/net/ipv4/tcp_max_syn_backlog"
printf 'powersave\n' > "$SYS_ROOT/devices/system/cpu/cpu0/cpufreq/scaling_governor"
(
  source "$PREPARE"
  ETC_ROOT="$ETC_ROOT" PROC_SYS_ROOT="$PROC_ROOT" SYS_ROOT="$SYS_ROOT" DRY_RUN=false
  write_limits_config &&
    write_sysctl_config &&
    write_zhaoxin_cpu_tuning_service &&
    apply_zhaoxin_cpu_tuning &&
    grep -q '^\* soft nofile 1048576$' "$ETC_ROOT/security/limits.d/99-jiuzhang-wdsp.conf" &&
    grep -q '^fs.file-max = 2097152$' "$ETC_ROOT/sysctl.d/99-jiuzhang-wdsp.conf" &&
    grep -q '^net.core.somaxconn = 65535$' "$ETC_ROOT/sysctl.d/99-jiuzhang-wdsp.conf" &&
    grep -q '^ExecStart=.*/sys/devices/system/cpu/cpu.*/cpufreq/scaling_governor' \
      "$ETC_ROOT/systemd/system/jiuzhang-wdsp-cpu-performance.service" &&
    [[ "$(cat "$SYS_ROOT/devices/system/cpu/cpu0/cpufreq/scaling_governor")" == "performance" ]]
) && pass "limits、sysctl 与兆芯性能 governor 持久化配置" \
  || fail "limits、sysctl 与兆芯性能 governor 持久化配置"

CHECK_BIN="$TMP_ROOT/check-bin"
mkdir -p "$CHECK_BIN"
for command_name in tar gzip openssl curl jq python3 sha256sum flock; do
  printf '#!/bin/sh\nexit 0\n' > "$CHECK_BIN/$command_name"
  chmod +x "$CHECK_BIN/$command_name"
done
printf '#!/bin/sh\n[ "$1 $2" = "compose version" ]\n' > "$CHECK_BIN/docker"
chmod +x "$CHECK_BIN/docker"
(
  source "$PREPARE"
  PATH="$CHECK_BIN:/usr/bin:/bin"
  check_runtime_dependencies >/dev/null 2>&1
) && pass "只读依赖预检" || fail "只读依赖预检"

(
  source "$PREPARE"
  PATH="/usr/bin:/bin"
  print_report >/dev/null 2>&1
) && pass "环境报告在 Docker 缺失时不终止准备流程" \
  || fail "环境报告在 Docker 缺失时不终止准备流程"

(
  source "$PREPARE"
  list_minimal_services | grep -qx 'cups.service'
  ! list_minimal_services | grep -Eq 'ssh|NetworkManager|firewalld|chronyd|docker'
  ! grep -Eq 'mitigations=off|selinux=0|nosmt' "$PREPARE"
) && pass "安全精简不触碰远程、网络、防火墙、时间与容器服务" \
  || fail "安全精简服务边界"

check "run header 含二进制载荷标记" grep -q '^__WDSP_PAYLOAD_BELOW__$' "$RUN_HEADER"
check "run header 先准备宿主机再启动标准安装" \
  grep -q 'prepare-openeuler-zhaoxin.sh' "$RUN_HEADER"
check "run header 在安装随包 RPM 前完成 Ed25519 验签" bash -c '
  verify_line=$(grep -n '\''verify_package_signature "$PACKAGE"'\'' "$1" | cut -d: -f1)
  rpm_line=$(grep -n '\''安装 .*个随包依赖 RPM'\'' "$1" | cut -d: -f1)
  [[ -n "$verify_line" && -n "$rpm_line" && "$verify_line" -lt "$rpm_line" ]]
' _ "$RUN_HEADER"
check "run header 可补齐哈希与验签基础工具" \
  grep -q 'install_bootstrap_package coreutils' "$RUN_HEADER"
check "构建器固定 wdsp/amd64 基线" grep -q 'jiuzhang-wdsp-offline-' "$BUILD"
check "构建器要求随包 RPM 包含 Compose v2 插件" \
  grep -q 'docker-compose-plugin-\*\.rpm' "$BUILD"
check "宿主机仅尝试安装 Compose v2 插件" \
  grep -q 'install_first_available docker-compose-plugin || true' "$PREPARE"
check "宿主机不将 docker-compose 当作 Compose v2 替代" \
  bash -c '! grep -q "install_first_available docker-compose-plugin docker-compose" "$1"' _ "$PREPARE"
check "构建器禁止写入 macOS 扩展属性" \
  grep -q 'COPYFILE_DISABLE=1' "$BUILD"
check "基础离线包禁止写入 macOS 扩展属性" \
  grep -q 'COPYFILE_DISABLE=1' "$BASE_BUILD"
check "离线包 allowlist 包含宿主机准备脚本" \
  grep -q '^file=install/prepare-openeuler-zhaoxin.sh$' "$REPO_ROOT/ops/offline-package/allowlist.v1"

FAKE_PACKAGE="$TMP_ROOT/jiuzhang-wdsp-offline-9.9.9-amd64.tar.gz"
FAKE_CONTENT="$TMP_ROOT/fake-package"
RUN_OUTPUT="$TMP_ROOT/run-output"
mkdir -p "$FAKE_CONTENT" "$RUN_OUTPUT"
printf 'structure-test\n' > "$FAKE_CONTENT/README"
tar -czf "$FAKE_PACKAGE" -C "$FAKE_CONTENT" .
(
  cd "$TMP_ROOT"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$(basename "$FAKE_PACKAGE")" > "$(basename "$FAKE_PACKAGE").sha256"
  else
    shasum -a 256 "$(basename "$FAKE_PACKAGE")" > "$(basename "$FAKE_PACKAGE").sha256"
  fi
)
if "$BUILD" --version 9.9.9 --offline-package "$FAKE_PACKAGE" \
  --development --output "$RUN_OUTPUT" >/dev/null 2>&1; then
  BUILT_RUN="$RUN_OUTPUT/jiuzhang-wdsp-openeuler-zhaoxin-9.9.9-amd64.run"
  [[ -x "$BUILT_RUN" ]] && pass "构建器生成可执行 .run" || fail "构建器生成可执行 .run"
  bash "$BUILT_RUN" --help >/dev/null 2>&1 \
    && pass "生成的 .run 可独立显示帮助" || fail "生成的 .run 可独立显示帮助"
  grep -aq '^__WDSP_PAYLOAD_BELOW__$' "$BUILT_RUN" \
    && pass "生成的 .run 包含自解压边界" || fail "生成的 .run 包含自解压边界"
else
  fail "构建器生成可执行 .run"
  fail "生成的 .run 可独立显示帮助"
  fail "生成的 .run 包含自解压边界"
fi

MISSING_PLUGIN_RPM_DIR="$TMP_ROOT/rpms-without-compose-plugin"
mkdir -p "$MISSING_PLUGIN_RPM_DIR"
: > "$MISSING_PLUGIN_RPM_DIR/docker-ce-27.3.1-1.x86_64.rpm"
if "$BUILD" --version 9.9.9 --offline-package "$FAKE_PACKAGE" \
  --development --rpm-dir "$MISSING_PLUGIN_RPM_DIR" --output "$TMP_ROOT/missing-plugin-output" \
  >"$TMP_ROOT/missing-plugin.log" 2>&1; then
  fail "构建器拒绝缺少 Compose v2 插件的 RPM 目录"
elif grep -q 'docker-compose-plugin' "$TMP_ROOT/missing-plugin.log"; then
  pass "构建器拒绝缺少 Compose v2 插件的 RPM 目录"
else
  fail "构建器拒绝缺少 Compose v2 插件的 RPM 目录"
fi

printf '\n结果: PASS=%d FAIL=%d\n' "$PASS_COUNT" "$FAIL_COUNT"
[[ "$FAIL_COUNT" -eq 0 ]]
