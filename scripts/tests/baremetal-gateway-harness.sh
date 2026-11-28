#!/usr/bin/env bash
# shellcheck disable=SC1090,SC2034
# baremetal-gateway-harness.sh —— 裸机网关安装/验收脚本的关键逻辑测试。
# 约定与 scripts/tests/kimi-frontend-harness.sh 一致：纯 bash、PASS/FAIL 计数、
# 全部在临时目录内进行，不触碰真实系统状态（安装脚本一律走 --dry-run）。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
INSTALL="$REPO_ROOT/ops/install/install-gateway-baremetal.sh"
VERIFY="$REPO_ROOT/ops/install/verify-gateway-baremetal.sh"
BUILD="$REPO_ROOT/ops/offline-package/build.sh"

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/jz-baremetal-harness.XXXXXX")"
cleanup() {
  case "$TMP_ROOT" in
    */jz-baremetal-harness.*) rm -rf "$TMP_ROOT" ;;
    *) echo "拒绝清理非测试临时目录: $TMP_ROOT" >&2 ;;
  esac
}
trap cleanup EXIT INT TERM HUP

PASS_COUNT=0
FAIL_COUNT=0
pass() { PASS_COUNT=$((PASS_COUNT+1)); printf 'PASS: %s\n' "$*"; }
fail() { FAIL_COUNT=$((FAIL_COUNT+1)); printf 'FAIL: %s\n' "$*" >&2; }
check() { # check NAME CMD...
  local name="$1"; shift
  if "$@" >/dev/null 2>&1; then pass "$name"; else fail "$name"; fi
}

# ---------- 0. 语法检查 ----------
for f in "$INSTALL" "$VERIFY" "$BUILD"; do
  check "bash -n $(basename "$f")" bash -n "$f"
done
check "install --help 退出码 0" bash "$INSTALL" -h
check "verify --help 退出码 0" bash "$VERIFY" -h
check "build --help 退出码 0" bash "$BUILD" -h
check "install 无输入参数退出码 2" bash -c "bash '$INSTALL' --dry-run >/dev/null 2>&1; [[ \$? -eq 2 ]]"
check "install --package 与 --from-image 互斥" \
  bash -c "bash '$INSTALL' --package a --from-image b >/dev/null 2>&1; [[ \$? -eq 2 ]]"
check "install --gw-uid 非数字退出码 2" \
  bash -c "bash '$INSTALL' --package a --gw-uid abc >/dev/null 2>&1; [[ \$? -eq 2 ]]"

# ---------- 1. UID/GID 分配与避让逻辑（source 后单测内部函数）----------
# stub id_taken：999/998/500 被占用，预期 find_free_id 返回 997
(
  source "$INSTALL"
  id_taken() { [[ "$2" == "999" || "$2" == "998" || "$2" == "500" ]]; }
  got="$(find_free_id user)"
  [[ "$got" == "997" ]] || { printf 'find_free_id=%s\n' "$got" >&2; exit 1; }
) && pass "find_free_id 系统段自高向低避让（999/998 占用 → 997）" \
  || fail "find_free_id 系统段自高向低避让"

# 全部占用时返回 1
(
  source "$INSTALL"
  id_taken() { return 0; }
  ! find_free_id group >/dev/null
) && pass "find_free_id 系统段占满时失败（交由 --gw-uid/--waf-gid 显式指定）" \
  || fail "find_free_id 占满场景"

# 覆盖参数校验：指定已被占用的 GID 必须 die（die 直接 exit，须用独立进程观察退出码）
if bash -c '
  source "'"$INSTALL"'"
  OPT_WAF_GID=500; OPT_GW_UID=""
  id_taken() { [[ "$2" == "500" ]]; }
  name_id() { return 1; }
  DRY_RUN=true
  resolve_ids >/dev/null 2>&1
' 2>/dev/null; then
  fail "resolve_ids 占用 GID 校验"
else
  pass "resolve_ids 拒绝已被占用的 --waf-gid"
fi

# 已存在的专用账号复用其实际 ID（幂等重装）
(
  source "$INSTALL"
  OPT_WAF_GID=""; OPT_GW_UID=""
  name_id() { [[ "$1" == "group" ]] && printf '432\n' || printf '567\n'; }
  DRY_RUN=true
  resolve_ids >/dev/null
  [[ "$WAF_GID" == "432" && "$GW_UID" == "567" ]]
) && pass "resolve_ids 幂等复用已存在账号的 UID/GID" || fail "resolve_ids 幂等复用"

# ---------- 2. unit 模板占位符渲染 ----------
(
  source "$INSTALL"
  GW_USER="jiuzhang-gw"; WAF_GROUP="jiuzhang-waf"
  tpl="$REPO_ROOT/deployment/systemd/jiuzhang-gateway.service"
  out="$TMP_ROOT/rendered.service"
  sed -e "s/__GW_USER__/$GW_USER/g" -e "s/__WAF_GROUP__/$WAF_GROUP/g" "$tpl" > "$out"
  ! grep -q '__GW_USER__\|__WAF_GROUP__' "$out" \
    && grep -q '^User=jiuzhang-gw$' "$out" \
    && grep -q '^Group=jiuzhang-waf$' "$out" \
    && grep -q -- '--resume' "$out"
) && pass "unit 模板渲染：占位符消除且 ExecStart 恒定带 --resume" \
  || fail "unit 模板渲染"

# ---------- 3. 伪造裸机包 + 全路径 --dry-run ----------
FAKE_PKG_DIR="$TMP_ROOT/gateway-linux-amd64"
mkdir -p "$FAKE_PKG_DIR/rules/crs"
printf '#!/bin/sh\necho fake-caddy\n' > "$FAKE_PKG_DIR/caddy"
chmod +x "$FAKE_PKG_DIR/caddy"
printf '2.11.4 h1:fake\n' > "$FAKE_PKG_DIR/VERSION"
printf '# fake crs\n' > "$FAKE_PKG_DIR/rules/crs/crs-setup.conf"
printf '<html>block</html>\n' > "$FAKE_PKG_DIR/blockpage.html"
cp "$REPO_ROOT/deployment/baremetal/Caddyfile.bootstrap" "$FAKE_PKG_DIR/"
cp "$REPO_ROOT/deployment/systemd/jiuzhang-gateway.service" "$FAKE_PKG_DIR/"
(cd "$FAKE_PKG_DIR" && shasum -a 256 caddy > sha256sums)
FAKE_PKG="$TMP_ROOT/gateway-linux-amd64.tar.gz"
tar -czf "$FAKE_PKG" -C "$TMP_ROOT" "gateway-linux-amd64"
# 测试发布密钥对：安装器验签闸门要求包带旁车 .sig（Ed25519），
# WDSP_PACKAGE_PUBLIC_KEY 覆盖脚本内置公钥指向本测试公钥
source "$REPO_ROOT/ops/lib/common.sh"
source "$REPO_ROOT/ops/lib/signing.sh"
openssl genpkey -algorithm ED25519 -out "$TMP_ROOT/test-release.key" 2>/dev/null
openssl pkey -in "$TMP_ROOT/test-release.key" -pubout -out "$TMP_ROOT/test-release.pub" 2>/dev/null
export WDSP_PACKAGE_PUBLIC_KEY="$TMP_ROOT/test-release.pub"
ed25519_sign_file "$TMP_ROOT/test-release.key" "$FAKE_PKG" "$FAKE_PKG.sig"

DRY_OUT="$TMP_ROOT/dry-run.out"
if bash "$INSTALL" --package "$FAKE_PKG" --dry-run > "$DRY_OUT" 2>&1; then
  pass "install --package --dry-run 全路径退出码 0"
else
  fail "install --package --dry-run 全路径（输出见 ${DRY_OUT}）"
fi
for needle in "SHA256 校验通过" "uid=" "DRY-RUN" "systemctl enable --now jiuzhang-gateway" \
              "安装报告" "group_add"; do
  if grep -q "$needle" "$DRY_OUT"; then
    pass "dry-run 输出含关键节点: $needle"
  else
    fail "dry-run 输出缺关键节点: $needle"
  fi
done

# 包被篡改时 sha256 校验必须失败（签名通过后的纵深层：篡改包用测试私钥重签，
# 验签通过后仍须被包内 sha256sums 自证拒绝）
printf 'evil\n' > "$FAKE_PKG_DIR/caddy"
tar -czf "$TMP_ROOT/evil.tar.gz" -C "$TMP_ROOT" "gateway-linux-amd64"
ed25519_sign_file "$TMP_ROOT/test-release.key" "$TMP_ROOT/evil.tar.gz" "$TMP_ROOT/evil.tar.gz.sig"
check "sha256 校验失败时拒绝安装" \
  bash -c "! bash '$INSTALL' --package '$TMP_ROOT/evil.tar.gz' --dry-run >/dev/null 2>&1"

# ---------- 4. bootstrap 与 unit 管理标记 ----------
check "bootstrap 含管理标记" grep -q 'jiuzhang-managed: baremetal-bootstrap' \
  "$REPO_ROOT/deployment/baremetal/Caddyfile.bootstrap"
check "unit 模板含管理标记" grep -q 'jiuzhang-managed: baremetal-gateway-unit' \
  "$REPO_ROOT/deployment/systemd/jiuzhang-gateway.service"
check "bootstrap 禁 TCP admin" grep -q 'admin unix//var/run/caddy/admin.sock' \
  "$REPO_ROOT/deployment/baremetal/Caddyfile.bootstrap"
check "bootstrap 含 rolling 指令" grep -q 'roll_size 100mib' \
  "$REPO_ROOT/deployment/baremetal/Caddyfile.bootstrap"

# ---------- 5. build.sh 新增函数存在性 ----------
check "build.sh 含裸机包函数" grep -q 'build_gateway_baremetal_pkg' "$BUILD"
check "build.sh compose 模板已补 rules 卷挂载" grep -q 'gateway-rules:/etc/caddy/rules:ro' "$BUILD"
check "build.sh compose 模板已补 blockpage 挂载" grep -q './gateway/blockpage.html:/srv/jiuzhang/blockpage.html:ro' "$BUILD"
check "build.sh compose 模板已补 Caddyfile 挂载" grep -q './gateway/Caddyfile:/etc/caddy/Caddyfile:ro' "$BUILD"

# ---------- 6. 性能调优脚本 tune-gateway-baremetal.sh ----------
TUNE="$REPO_ROOT/ops/install/tune-gateway-baremetal.sh"
check "bash -n tune 脚本" bash -n "$TUNE"
check "tune --help 退出码 0" bash "$TUNE" -h
check "tune --target 5 非法退出码 2" \
  bash -c "bash '$TUNE' --target 5 >/dev/null 2>&1; [[ \$? -eq 2 ]]"
check "tune --apply 与 --check 互斥退出码 2" \
  bash -c "bash '$TUNE' --apply --check >/dev/null 2>&1; [[ \$? -eq 2 ]]"

# parse_cpu_list 展开（source 后单测内部函数）
(
  source "$TUNE"
  got="$(parse_cpu_list '0-3,8,10-11')"
  [[ "$got" == "0 1 2 3 8 10 11" ]] || { printf 'parse_cpu_list=%s\n' "$got" >&2; exit 1; }
) && pass "parse_cpu_list 展开 0-3,8,10-11" || fail "parse_cpu_list 展开"

# sysctl_params_for_target：关键键齐全且缓冲区按档递增
(
  source "$TUNE"
  p6="$(sysctl_params_for_target 6)"
  p8="$(sysctl_params_for_target 8)"
  p10="$(sysctl_params_for_target 10)"
  for k in net.core.somaxconn net.core.netdev_max_backlog net.core.rmem_max net.core.wmem_max \
           net.ipv4.tcp_rmem net.ipv4.tcp_wmem net.ipv4.tcp_max_syn_backlog net.ipv4.tcp_tw_reuse \
           net.ipv4.ip_local_port_range fs.file-max fs.nr_open net.netfilter.nf_conntrack_max; do
    grep -q "^$k " <<< "$p6" || { printf '6 档缺键 %s\n' "$k" >&2; exit 1; }
    grep -q "^$k " <<< "$p10" || { printf '10 档缺键 %s\n' "$k" >&2; exit 1; }
  done
  v6="$(awk '$1=="net.core.rmem_max"{print $3}' <<< "$p6")"
  v8="$(awk '$1=="net.core.rmem_max"{print $3}' <<< "$p8")"
  v10="$(awk '$1=="net.core.rmem_max"{print $3}' <<< "$p10")"
  (( v8 > v6 && v10 > v8 )) || { printf 'rmem_max 6/8/10=%s/%s/%s 未递增\n' "$v6" "$v8" "$v10" >&2; exit 1; }
) && pass "sysctl_params_for_target 关键键齐全且缓冲区按档递增" || fail "sysctl_params_for_target"

# 伪 sysfs：10G 接口发现与 NUMA/local_cpus 解析
FAKE_SYS="$TMP_ROOT/sysfs"
mkdir -p "$FAKE_SYS/class/net/eth0/device" "$FAKE_SYS/class/net/eth1" "$FAKE_SYS/class/net/lo"
printf '10000\n' > "$FAKE_SYS/class/net/eth0/speed"
printf '1\n' > "$FAKE_SYS/class/net/eth0/device/numa_node"
printf '8-11\n' > "$FAKE_SYS/class/net/eth0/device/local_cpulist"
printf '1000\n' > "$FAKE_SYS/class/net/eth1/speed"
(
  source "$TUNE"
  SYSFS_ROOT="$FAKE_SYS"
  got="$(list_10g_ifaces)"
  [[ "$got" == "eth0" ]] || { printf 'ifaces=%s\n' "$got" >&2; exit 1; }
  [[ "$(iface_numa_node eth0)" == "1" ]] || { printf 'numa=%s\n' "$(iface_numa_node eth0)" >&2; exit 1; }
  cpus="$(iface_numa_cpus eth0)"
  [[ "$cpus" == "8 9 10 11" ]] || { printf 'cpus=%s\n' "$cpus" >&2; exit 1; }
) && pass "伪 sysfs 10G 接口发现与 NUMA 解析" || fail "伪 sysfs 10G 接口发现与 NUMA 解析"

check "tune --dry-run --target 10 非 root 跑通" bash "$TUNE" --dry-run --target 10

# detect_cpu_platform 分支（stub cpuinfo：intel/amd/hygon/读不到）
CPUINFO_DIR="$TMP_ROOT/cpuinfo"
mkdir -p "$CPUINFO_DIR"
printf 'processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Xeon(R) Gold 6230 CPU @ 2.10GHz\n' > "$CPUINFO_DIR/intel"
printf 'processor\t: 0\nvendor_id\t: AuthenticAMD\nmodel name\t: AMD EPYC 7702 64-Core Processor\n' > "$CPUINFO_DIR/amd"
printf 'processor\t: 0\nvendor_id\t: HygonGenuine\nmodel name\t: Hygon C86 7285 32-core Processor\n' > "$CPUINFO_DIR/hygon"
printf 'processor\t: 0\nCPU implementer\t: 0x48\nCPU part\t\t: 0xd01\n' > "$CPUINFO_DIR/kunpeng"
(
  source "$TUNE"
  CPUINFO_FILE="$CPUINFO_DIR/intel"
  [[ "$(detect_cpu_platform)" == "intel" ]] || exit 1
  CPUINFO_FILE="$CPUINFO_DIR/amd"
  [[ "$(detect_cpu_platform)" == "amd" ]] || exit 1
  CPUINFO_FILE="$CPUINFO_DIR/hygon"
  [[ "$(detect_cpu_platform)" == "hygon" ]] || exit 1
  CPUINFO_FILE="$CPUINFO_DIR/kunpeng"
  [[ "$(detect_cpu_platform)" == "kunpeng" ]] || exit 1
  CPUINFO_FILE="$CPUINFO_DIR/nonexistent"
  [[ "$(detect_cpu_platform)" == "generic" ]] || exit 1
) && pass "detect_cpu_platform intel/amd/hygon/kunpeng/读不到 五分支" \
  || fail "detect_cpu_platform 分支"

# OS 识别扩展：ubuntu 视为支持平台（不告警），未知发行版仍告警
printf 'ID=ubuntu\nPRETTY_NAME="Ubuntu 22.04 LTS"\n' > "$CPUINFO_DIR/os-release-ubuntu"
printf 'ID=fooos\nPRETTY_NAME="Foo OS 1.0"\n' > "$CPUINFO_DIR/os-release-foo"
(
  source "$TUNE"
  DRY_RUN=true
  OS_RELEASE_FILE="$CPUINFO_DIR/os-release-ubuntu"
  out="$(preflight 2>&1)"
  grep -q '目标支持平台' <<< "$out" || { printf '%s\n' "$out" >&2; exit 1; }
  ! grep -q '未列入目标支持平台清单' <<< "$out"
) && pass "preflight OS 识别：ubuntu 为支持平台（不告警）" || fail "preflight OS 识别 ubuntu"
(
  source "$TUNE"
  DRY_RUN=true
  OS_RELEASE_FILE="$CPUINFO_DIR/os-release-foo"
  out="$(preflight 2>&1)"
  grep -q '未列入目标支持平台清单' <<< "$out"
) && pass "preflight OS 识别：未知发行版仍告警继续" || fail "preflight OS 识别未知发行版"

# 安装器 --tune 集成（非法值 + dry-run 全路径，不依赖 docker）
check "install --tune 5 非法退出码 2" \
  bash -c "bash '$INSTALL' --package a --tune 5 >/dev/null 2>&1; [[ \$? -eq 2 ]]"
TUNE_OUT="$TMP_ROOT/install-tune.out"
if bash "$INSTALL" --package "$FAKE_PKG" --dry-run --tune 6 > "$TUNE_OUT" 2>&1; then
  pass "install --package --dry-run --tune 6 全路径退出码 0"
else
  fail "install --package --dry-run --tune 6 全路径（输出见 ${TUNE_OUT}）"
fi
for needle in "tune-gateway-baremetal.sh --target 6" "性能调优"; do
  if grep -q "$needle" "$TUNE_OUT"; then
    pass "--tune dry-run 输出含关键节点: $needle"
  else
    fail "--tune dry-run 输出缺关键节点: $needle"
  fi
done

printf '\n========== harness 结果: PASS=%d FAIL=%d ==========\n' "$PASS_COUNT" "$FAIL_COUNT"
[[ "$FAIL_COUNT" -eq 0 ]]
