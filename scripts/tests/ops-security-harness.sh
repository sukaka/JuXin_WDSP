#!/usr/bin/env bash
# shellcheck disable=SC1090,SC2034
# ops-security-harness.sh —— 批次5-B 安全修复的回归测试（HIGH-14 / MED-21 / MED-22 /
# MED-23 / LOW-O3）。约定与 scripts/tests/baremetal-gateway-harness.sh 一致：纯 bash、
# PASS/FAIL 计数、全部在临时目录内进行，不触碰真实系统状态（安装脚本一律 --dry-run）。
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
COMMON="$REPO_ROOT/ops/lib/common.sh"
HOSTCTL="$REPO_ROOT/ops/system/hostctl-exec.sh"
COLLECT="$REPO_ROOT/ops/diagnostics/collect.sh"
INSTALL="$REPO_ROOT/ops/install/install.sh"
BM_INSTALL="$REPO_ROOT/ops/install/install-gateway-baremetal.sh"
BUILD="$REPO_ROOT/ops/offline-package/build.sh"
HALAB_COMPOSE="$REPO_ROOT/deployment/ha-lab/docker-compose.ha-lab.yml"

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/jz-opssec-harness.XXXXXX")"
cleanup() {
  case "$TMP_ROOT" in
    */jz-opssec-harness.*) rm -rf "$TMP_ROOT" ;;
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
for f in "$COMMON" "$HOSTCTL" "$COLLECT" "$INSTALL" "$BM_INSTALL" "$BUILD"; do
  check "bash -n $(basename "$f")" bash -n "$f"
done

# ---------- 1. LOW-O3：validate_port_list（common.sh）----------
(
  source "$COMMON"
  validate_port_list "8080" \
    && validate_port_list "8080,8443,9000-9010" \
    && validate_port_list "1024-65535" \
    && ! validate_port_list "" \
    && ! validate_port_list "abc" \
    && ! validate_port_list "0" \
    && ! validate_port_list "65536" \
    && ! validate_port_list "9000-8000" \
    && ! validate_port_list "80,443,"
) && pass "validate_port_list 合法/非法清单判定" || fail "validate_port_list 判定"

check "install.sh --site-ports 非法值退出码 2" \
  bash -c "bash '$INSTALL' --site-ports 'abc' >/dev/null 2>&1; [[ \$? -eq 2 ]]"
check "install.sh --site-ports 越界值退出码 2" \
  bash -c "bash '$INSTALL' --site-ports '70000' >/dev/null 2>&1; [[ \$? -eq 2 ]]"
check "install.sh --site-ports 合法值通过参数校验（后续环境检查失败不算本项）" \
  bash -c "bash '$INSTALL' --site-ports '8080,9000-9010' --no-firewall --skip-accounts >/dev/null 2>&1; [[ \$? -ne 2 ]]"
check "install-gateway-baremetal --site-ports 非法值退出码 2" \
  bash -c "bash '$BM_INSTALL' --package /nonexistent.tar.gz --site-ports 'abc' >/dev/null 2>&1; [[ \$? -eq 2 ]]"
check "install 脚本不再默认放行 1024-65535" \
  bash -c "! grep -q 'add-port=1024-65535' '$INSTALL'"
check "install-gateway-baremetal 不再默认放行 1024-65535" \
  bash -c "! grep -q 'add-port=1024-65535' '$BM_INSTALL'"

# ---------- 2. MED-23：sha256_check_sidecar / manifest_files_verify（common.sh）----------
SB="$TMP_ROOT/sidecar"
mkdir -p "$SB"
printf 'payload\n' > "$SB/pkg.tar.gz"
(cd "$SB" && shasum -a 256 pkg.tar.gz > pkg.tar.gz.sha256)
(
  source "$COMMON"
  sha256_check_sidecar "$SB/pkg.tar.gz"
) && pass "sha256_check_sidecar 匹配返回 0" || fail "sha256_check_sidecar 匹配"

(
  source "$COMMON"
  rc=0; sha256_check_sidecar "$SB/no-sidecar.tar.gz" || rc=$?
  [[ "$rc" -eq 2 ]]
) && pass "sha256_check_sidecar 无旁车返回 2" || fail "sha256_check_sidecar 无旁车"

printf 'tampered\n' > "$SB/evil.tar.gz"
cp "$SB/pkg.tar.gz.sha256" "$SB/evil.tar.gz.sha256"
(
  source "$COMMON"
  rc=0; sha256_check_sidecar "$SB/evil.tar.gz" 2>/dev/null || rc=$?
  [[ "$rc" -eq 1 ]]
) && pass "sha256_check_sidecar 哈希不符返回 1" || fail "sha256_check_sidecar 不符"

printf 'not-a-hash  pkg.tar.gz\n' > "$SB/badfmt.tar.gz.sha256"
printf 'x\n' > "$SB/badfmt.tar.gz"
(
  source "$COMMON"
  rc=0; sha256_check_sidecar "$SB/badfmt.tar.gz" 2>/dev/null || rc=$?
  [[ "$rc" -eq 1 ]]
) && pass "sha256_check_sidecar 旁车格式非法返回 1" || fail "sha256_check_sidecar 格式非法"

# manifest_files_verify：构造微型包树
MF="$TMP_ROOT/mfpkg"
mkdir -p "$MF/ops"
printf 'hello\n' > "$MF/a.txt"
printf 'world\n' > "$MF/ops/b.sh"
h_a="$(shasum -a 256 "$MF/a.txt" | awk '{print $1}')"
h_b="$(shasum -a 256 "$MF/ops/b.sh" | awk '{print $1}')"
s_a="$(stat -f%z "$MF/a.txt")"
s_b="$(stat -f%z "$MF/ops/b.sh")"
jq -n --arg ha "$h_a" --arg hb "$h_b" --argjson sa "$s_a" --argjson sb "$s_b" \
  '{files:[{path:"a.txt",sha256:$ha,size:$sa},{path:"ops/b.sh",sha256:$hb,size:$sb}]}' \
  > "$MF/manifest.json"
(
  source "$COMMON"
  manifest_files_verify "$MF/manifest.json" "$MF" >/dev/null
) && pass "manifest_files_verify 完好包树通过" || fail "manifest_files_verify 完好"

printf 'tampered!\n' > "$MF/a.txt"
(
  source "$COMMON"
  rc=0; manifest_files_verify "$MF/manifest.json" "$MF" >/dev/null 2>&1 || rc=$?
  [[ "$rc" -eq 1 ]]
) && pass "manifest_files_verify 篡改检出返回 1" || fail "manifest_files_verify 篡改检出"
printf 'hello\n' > "$MF/a.txt"

jq -n '{product:"waf",version:"0.0.0"}' > "$MF/manifest-nofiles.json"
(
  source "$COMMON"
  rc=0; manifest_files_verify "$MF/manifest-nofiles.json" "$MF" >/dev/null 2>&1 || rc=$?
  [[ "$rc" -eq 2 ]]
) && pass "manifest_files_verify 无 files 清单返回 2（历史包降级）" || fail "manifest_files_verify 无 files"

jq -n --arg ha "$h_a" --argjson sa "$s_a" \
  '{files:[{path:"../escape",sha256:$ha,size:$sa}]}' > "$MF/manifest-escape.json"
(
  source "$COMMON"
  rc=0; manifest_files_verify "$MF/manifest-escape.json" "$MF" >/dev/null 2>&1 || rc=$?
  [[ "$rc" -eq 1 ]]
) && pass "manifest_files_verify 拒绝含 .. 的清单路径" || fail "manifest_files_verify .. 路径"

# ---------- 3. MED-23：裸机包先校验后解压 ----------
# 伪造裸机包（与 baremetal-gateway-harness.sh 同款），分三种旁车形态跑 --dry-run
fake_pkg() { # fake_pkg OUT_TAR [evil]
  local d="$TMP_ROOT/fakepkg-src" out="$1"
  rm -rf "$d"
  mkdir -p "$d/gateway-linux-arm64/rules/crs"
  printf '#!/bin/sh\necho fake-caddy\n' > "$d/gateway-linux-arm64/caddy"
  chmod +x "$d/gateway-linux-arm64/caddy"
  if [[ "${2:-}" == "evil" ]]; then
    printf 'evil\n' >> "$d/gateway-linux-arm64/caddy"
  fi
  printf '2.11.4 h1:fake\n' > "$d/gateway-linux-arm64/VERSION"
  printf '# fake crs\n' > "$d/gateway-linux-arm64/rules/crs/crs-setup.conf"
  printf '<html>block</html>\n' > "$d/gateway-linux-arm64/blockpage.html"
  cp "$REPO_ROOT/deployment/baremetal/Caddyfile.bootstrap" "$d/gateway-linux-arm64/"
  cp "$REPO_ROOT/deployment/systemd/jiuzhang-gateway.service" "$d/gateway-linux-arm64/"
  (cd "$d/gateway-linux-arm64" && shasum -a 256 caddy > sha256sums)
  tar -czf "$out" -C "$d" "gateway-linux-arm64"
}

P_GOOD="$TMP_ROOT/gw-good.tar.gz"
fake_pkg "$P_GOOD"
(cd "$TMP_ROOT" && shasum -a 256 "$(basename "$P_GOOD")" > "$(basename "$P_GOOD").sha256")
GOOD_OUT="$TMP_ROOT/gw-good.out"
if bash "$BM_INSTALL" --package "$P_GOOD" --allow-unsigned --dry-run > "$GOOD_OUT" 2>&1; then
  pass "裸机包（旁车齐全）--dry-run 退出码 0"
else
  fail "裸机包（旁车齐全）--dry-run（输出见 ${GOOD_OUT}）"
fi
check "dry-run 输出含旁车校验通过" grep -q "裸机包整包哈希校验通过" "$GOOD_OUT"

# 无旁车：告警降级、继续走包内自证
P_NOSB="$TMP_ROOT/gw-nosb.tar.gz"
fake_pkg "$P_NOSB"
NOSB_OUT="$TMP_ROOT/gw-nosb.out"
if bash "$BM_INSTALL" --package "$P_NOSB" --allow-unsigned --dry-run > "$NOSB_OUT" 2>&1 \
   && grep -q "无旁车哈希" "$NOSB_OUT" && grep -q "SHA256 校验通过" "$NOSB_OUT"; then
  pass "裸机包无旁车：告警降级 + 包内自证仍执行"
else
  fail "裸机包无旁车降级路径（输出见 ${NOSB_OUT}）"
fi

# 篡改包 + 过期旁车：解压前即拒绝
P_EVIL="$TMP_ROOT/gw-evil.tar.gz"
fake_pkg "$P_EVIL" evil
cp "$P_GOOD.sha256" "$P_EVIL.sha256"
EVIL_OUT="$TMP_ROOT/gw-evil.out"
if bash "$BM_INSTALL" --package "$P_EVIL" --allow-unsigned --dry-run > "$EVIL_OUT" 2>&1; then
  fail "篡改裸机包（旁车不符）应被拒绝"
else
  if grep -q "旁车哈希校验失败" "$EVIL_OUT" && ! grep -q "SHA256 校验通过" "$EVIL_OUT"; then
    pass "篡改裸机包：旁车校验失败即中止（未走到解压后校验）"
  else
    fail "篡改裸机包拒绝但输出异常（输出见 ${EVIL_OUT}）"
  fi
fi

# ---------- 4. HIGH-14：hostctl-exec.sh 属主/权限校验 + 共享密钥签名验真 ----------
# 非 root 测试以 HOSTCTL_EXPECT_UID=当前 uid 模拟「约定属主」
MY_UID="$(id -u)"
NOW_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
OLD_TS="2020-01-01T00:00:00Z"

mksecret() { # mksecret DIR —— 预置共享密钥（与脚本自举格式一致：64 hex + 600）
  openssl rand -hex 32 > "$1/.hostctl-secret"
  chmod 600 "$1/.hostctl-secret"
}
mkflag() { # mkflag DIR —— 写入未签名旧格式 reboot 标志（升级窗口遗留形态，应被拒）
  printf '{"action":"reboot","requestedBy":"t","requestID":"r1","requestedAt":"%s","delaySeconds":1}\n' \
    "$NOW_TS" > "$1/reboot-1-r1.json"
}
mksigned() { # mksigned DIR ACTION TS [FILENAME] —— 按目录内密钥正确签名写标志
  local dir="$1" action="$2" ts="$3" name="${4:-$2-1-r1.json}" payload mac
  payload="$(printf 'v1\n%s\ntester\nuid-1\nr1\n%s\n1' "$action" "$ts")"
  mac="$(printf '%s' "$payload" | openssl dgst -sha256 -hmac "$(tr -d '[:space:]' < "$dir/.hostctl-secret")" | awk '{print $NF}')"
  printf '{"action":"%s","requestedBy":"tester","userID":"uid-1","requestID":"r1","requestedAt":"%s","delaySeconds":1,"hmac":"%s"}\n' \
    "$action" "$ts" "$mac" > "$dir/$name"
}
mktampered() { # mktampered DIR —— 用 reboot 的合法签名装载 shutdown 内容（篡改 command）
  local dir="$1" payload mac
  payload="$(printf 'v1\nreboot\ntester\nuid-1\nr1\n%s\n1' "$NOW_TS")"
  mac="$(printf '%s' "$payload" | openssl dgst -sha256 -hmac "$(tr -d '[:space:]' < "$dir/.hostctl-secret")" | awk '{print $NF}')"
  printf '{"action":"shutdown","requestedBy":"tester","userID":"uid-1","requestID":"r1","requestedAt":"%s","delaySeconds":1,"hmac":"%s"}\n' \
    "$NOW_TS" "$mac" > "$dir/shutdown-1-r9.json"
}

# 签名正确 + 新鲜时间戳：放行
HC_OK="$TMP_ROOT/hc-ok"
mkdir -p "$HC_OK"; chmod 755 "$HC_OK"; mksecret "$HC_OK"; mksigned "$HC_OK" reboot "$NOW_TS"
HC_OK_OUT="$TMP_ROOT/hc-ok.out"
if HOSTCTL_EXPECT_UID="$MY_UID" bash "$HOSTCTL" --dry-run "$HC_OK" > "$HC_OK.out" 2>&1; then
  if grep -q "dry-run" "$HC_OK.out" && [[ -f "$HC_OK/reboot-1-r1.json.done" ]]; then
    pass "hostctl 合法签名标志：dry-run 通过并归档 .done"
  else
    fail "hostctl 合法签名路径输出/归档异常（输出见 $HC_OK.out）"
  fi
else
  fail "hostctl 合法签名路径应退出 0（输出见 $HC_OK.out）"
fi

# 无密钥时脚本自举：预置密钥被沿用，签名端与验签端密钥一致（上面用例已隐含）；
# 这里验证「无密钥 + 目录不可写导致自举失败」fail-closed
HC_RO="$TMP_ROOT/hc-nokey"
mkdir -p "$HC_RO"; chmod 755 "$HC_RO"; mkflag "$HC_RO"
chmod 555 "$HC_RO"
if HOSTCTL_EXPECT_UID="$MY_UID" bash "$HOSTCTL" --dry-run "$HC_RO" > "$TMP_ROOT/hc-ro.out" 2>&1; then
  chmod 755 "$HC_RO"; fail "hostctl 密钥缺失且无法自举应拒绝"
else
  if grep -q "共享密钥" "$TMP_ROOT/hc-ro.out" && [[ ! -f "$HC_RO/.hostctl-secret" ]]; then
    pass "hostctl 无密钥且自举失败：fail-closed 拒绝"
  else
    fail "hostctl 无密钥拒绝但输出异常（输出见 $TMP_ROOT/hc-ro.out）"
  fi
fi
chmod 755 "$HC_RO"

# 篡改 command（shutdown 内容 + reboot 的签名）：验签失败拒绝
HC_TAMPER="$TMP_ROOT/hc-tamper"
mkdir -p "$HC_TAMPER"; chmod 755 "$HC_TAMPER"; mksecret "$HC_TAMPER"; mktampered "$HC_TAMPER"
if HOSTCTL_EXPECT_UID="$MY_UID" bash "$HOSTCTL" --dry-run "$HC_TAMPER" > "$TMP_ROOT/hc-tamper.out" 2>&1; then
  fail "hostctl 篡改 command 的标志应拒绝"
else
  if grep -q "HMAC 验签失败" "$TMP_ROOT/hc-tamper.out" && [[ -f "$HC_TAMPER/shutdown-1-r9.json.done" ]]; then
    pass "hostctl 篡改 command：验签失败并归档拒绝"
  else
    fail "hostctl 篡改 command 拒绝但输出/归档异常（输出见 $TMP_ROOT/hc-tamper.out）"
  fi
fi

# 重放（正确签名但时间戳远超窗口）：拒绝
HC_REPLAY="$TMP_ROOT/hc-replay"
mkdir -p "$HC_REPLAY"; chmod 755 "$HC_REPLAY"; mksecret "$HC_REPLAY"; mksigned "$HC_REPLAY" reboot "$OLD_TS"
if HOSTCTL_EXPECT_UID="$MY_UID" bash "$HOSTCTL" --dry-run "$HC_REPLAY" > "$TMP_ROOT/hc-replay.out" 2>&1; then
  fail "hostctl 旧时间戳重放标志应拒绝"
else
  if grep -q "超出允许时间窗" "$TMP_ROOT/hc-replay.out" && [[ -f "$HC_REPLAY/reboot-1-r1.json.done" ]]; then
    pass "hostctl 重放（旧时间戳）：超窗拒绝并归档"
  else
    fail "hostctl 重放拒绝但输出/归档异常（输出见 $TMP_ROOT/hc-replay.out）"
  fi
fi

# 未签名旧格式标志（升级窗口内旧 server 产物）：fail-closed 拒绝
HC_UNS="$TMP_ROOT/hc-unsigned"
mkdir -p "$HC_UNS"; chmod 755 "$HC_UNS"; mksecret "$HC_UNS"; mkflag "$HC_UNS"
if HOSTCTL_EXPECT_UID="$MY_UID" bash "$HOSTCTL" --dry-run "$HC_UNS" > "$TMP_ROOT/hc-uns.out" 2>&1; then
  fail "hostctl 未签名标志应拒绝"
else
  if grep -q "未签名标志一律拒绝" "$TMP_ROOT/hc-uns.out" && [[ -f "$HC_UNS/reboot-1-r1.json.done" ]]; then
    pass "hostctl 未签名标志：fail-closed 拒绝并归档"
  else
    fail "hostctl 未签名标志拒绝但输出/归档异常（输出见 $TMP_ROOT/hc-uns.out）"
  fi
fi

# 目录 other-writable（1777 退化形态）：拒绝执行（目录校验优先于验签）
HC_W="$TMP_ROOT/hc-writable"
mkdir -p "$HC_W"; chmod 777 "$HC_W"; mkflag "$HC_W"
if HOSTCTL_EXPECT_UID="$MY_UID" bash "$HOSTCTL" --dry-run "$HC_W" > "$TMP_ROOT/hc-w.out" 2>&1; then
  fail "hostctl other-writable 目录应拒绝"
else
  if grep -q "other-writable" "$TMP_ROOT/hc-w.out" && [[ -f "$HC_W/reboot-1-r1.json.done" ]]; then
    pass "hostctl 拒绝 other-writable 目录并归档告警"
  else
    fail "hostctl other-writable 拒绝但输出/归档异常（输出见 $TMP_ROOT/hc-w.out）"
  fi
fi

# 目录属主非约定属主：拒绝执行
HC_OW="$TMP_ROOT/hc-owner"
mkdir -p "$HC_OW"; chmod 755 "$HC_OW"; mkflag "$HC_OW"
if HOSTCTL_EXPECT_UID=1000 bash "$HOSTCTL" --dry-run "$HC_OW" > "$TMP_ROOT/hc-ow.out" 2>&1; then
  fail "hostctl 属主不符应拒绝（测试 uid=$MY_UID 非约定 1000）"
else
  grep -q "非约定属主" "$TMP_ROOT/hc-ow.out" \
    && pass "hostctl 拒绝属主非约定的标志目录" \
    || fail "hostctl 属主不符拒绝但输出异常（输出见 $TMP_ROOT/hc-ow.out）"
fi

# 非法 action：正确签名通过验签后仍命中白名单纪律（归档拒绝）
HC_BAD="$TMP_ROOT/hc-badaction"
mkdir -p "$HC_BAD"; chmod 755 "$HC_BAD"; mksecret "$HC_BAD"; mksigned "$HC_BAD" rm_rf "$NOW_TS" "rm_rf-1-r2.json"
if HOSTCTL_EXPECT_UID="$MY_UID" bash "$HOSTCTL" --dry-run "$HC_BAD" > "$TMP_ROOT/hc-bad.out" 2>&1; then
  fail "hostctl 非法 action 应拒绝"
else
  grep -q "非法 action" "$TMP_ROOT/hc-bad.out" \
    && pass "hostctl 非法 action 白名单拒绝纪律不变" \
    || fail "hostctl 非法 action 拒绝但输出异常（输出见 $TMP_ROOT/hc-bad.out）"
fi

# install.sh 侧：chown 失败退化路径的安全警告文本存在
check "install.sh 含 hostctl 属主退化安全警告" grep -q "安全警告（系统控制通道不可用）" "$INSTALL"

# ---------- 5. MED-21：collect.sh .env 脱敏 ----------
FAKE_ENV="$TMP_ROOT/fake.env"
cat > "$FAKE_ENV" <<'EOF'
POSTGRES_PASSWORD=sup3r-secret
VALKEY_PASSWORD=another-secret
APM_CLICKHOUSE_DSN=clickhouse://apm_user:apmP%40ssw0rd@clickhouse.internal:9000/apm
APP_BASE_URL=http://127.0.0.1:8080
EXTRA_ENDPOINTS=targets=https://sync:SyncPass99@10.0.0.9:8443/push,retry=3
TZ=Asia/Shanghai
EOF
DIAG_OUT="$TMP_ROOT/diag"
mkdir -p "$DIAG_OUT"
if (cd "$TMP_ROOT" && bash "$COLLECT" -e "$FAKE_ENV" -o "$DIAG_OUT" --log-lines 5) > "$TMP_ROOT/collect.out" 2>&1; then
  pass "collect.sh 运行成功"
else
  fail "collect.sh 运行失败（输出见 $TMP_ROOT/collect.out）"
fi
diag_tgz="$(ls -1 "$DIAG_OUT"/diagnostics-*.tar.gz 2>/dev/null | head -1)"
if [[ -n "$diag_tgz" ]]; then
  tar -xzf "$diag_tgz" -C "$TMP_ROOT" ./env.sanitized.txt 2>/dev/null || tar -xzf "$diag_tgz" -C "$TMP_ROOT" env.sanitized.txt
  SAN="$TMP_ROOT/env.sanitized.txt"
  san_ok=true
  for needle in 'POSTGRES_PASSWORD=********' 'APM_CLICKHOUSE_DSN=********' 'APP_BASE_URL=********'; do
    grep -qF "$needle" "$SAN" || { san_ok=false; printf '缺脱敏行: %s\n' "$needle" >&2; }
  done
  grep -qF 'https://***:***@10.0.0.9:8443/push' "$SAN" || { san_ok=false; printf '通用 user:pass@ 段未脱敏\n' >&2; }
  grep -qF 'TZ=Asia/Shanghai' "$SAN" || { san_ok=false; printf '非敏感行被误伤\n' >&2; }
  for leak in 'sup3r-secret' 'apm_user' 'SyncPass99'; do
    grep -qF "$leak" "$SAN" && { san_ok=false; printf '敏感值泄漏: %s\n' "$leak" >&2; }
  done
  [[ "$san_ok" == "true" ]] && pass "collect.sh 脱敏：DSN/URL 键名掩码 + 值内 user:pass@ 通用掩码" \
    || fail "collect.sh 脱敏（见 ${SAN}）"
else
  fail "collect.sh 未产出诊断包"
fi

# ---------- 6. MED-22：ha-lab compose 必填注入 ----------
check "ha-lab compose 不再含默认口令" \
  bash -c "! grep -qE 'PASSWORD:-|MASTER_KEY:-' '$HALAB_COMPOSE'"
if docker compose version >/dev/null 2>&1; then
  HALAB_ENV="$TMP_ROOT/ha-lab.env"
  cat > "$HALAB_ENV" <<EOF
POSTGRES_PASSWORD=$(openssl rand -hex 24)
VALKEY_PASSWORD=$(openssl rand -hex 24)
JIUZHANG_MASTER_KEY=$(openssl rand -hex 32)
INITIAL_ADMIN_PASSWORD=Harness!$(openssl rand -hex 8)
EOF
  if docker compose --env-file "$HALAB_ENV" -f "$HALAB_COMPOSE" config -q >/dev/null 2>"$TMP_ROOT/compose-ok.err"; then
    pass "ha-lab compose 注入环境变量后 config 校验通过"
  else
    fail "ha-lab compose config（注入后）失败（见 $TMP_ROOT/compose-ok.err）"
  fi
  if (cd "$TMP_ROOT" && docker compose --env-file /dev/null -f "$HALAB_COMPOSE" config -q) >/dev/null 2>&1; then
    fail "ha-lab compose 缺敏感变量仍通过（必填注入未生效）"
  else
    pass "ha-lab compose 缺敏感变量时 config 报错（必填注入生效）"
  fi
else
  echo "SKIP: docker compose 不可用，跳过 ha-lab compose 渲染校验" >&2
fi

printf '\n========== harness 结果: PASS=%d FAIL=%d ==========\n' "$PASS_COUNT" "$FAIL_COUNT"
[[ "$FAIL_COUNT" -eq 0 ]]
