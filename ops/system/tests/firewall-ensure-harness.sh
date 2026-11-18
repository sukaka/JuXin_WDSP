#!/usr/bin/env bash
# firewall-ensure-harness.sh —— hostctl firewall_ensure 与 firewall-ensure.sh 回归测试。
# 所有防火墙、logger、sleep 命令均使用临时目录 mock，不触碰真实系统状态。
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SYSTEM_DIR="$(cd "$SCRIPT_DIR/.." && pwd -P)"
HOSTCTL="$SYSTEM_DIR/hostctl-exec.sh"
FIREWALL_ENSURE="$SYSTEM_DIR/firewall-ensure.sh"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/jz-firewall-ensure.XXXXXX")"
cleanup() {
  case "$TMP_ROOT" in
    */jz-firewall-ensure.*) rm -rf "$TMP_ROOT" ;;
    *) printf '拒绝清理非测试临时目录: %s\n' "$TMP_ROOT" >&2 ;;
  esac
}
trap cleanup EXIT INT TERM HUP

PASS_COUNT=0
FAIL_COUNT=0
pass() { PASS_COUNT=$((PASS_COUNT+1)); printf 'PASS: %s\n' "$*"; }
fail() { FAIL_COUNT=$((FAIL_COUNT+1)); printf 'FAIL: %s\n' "$*" >&2; }

for script in "$HOSTCTL" "$FIREWALL_ENSURE"; do
  if bash -n "$script"; then
    pass "bash -n $(basename "$script")"
  else
    fail "bash -n $(basename "$script")"
  fi
done

MOCK_BIN="$TMP_ROOT/bin"
mkdir -p "$MOCK_BIN"
export MOCK_FW_LOG="$TMP_ROOT/firewall.log"
export MOCK_LOGGER_LOG="$TMP_ROOT/logger.log"
export MOCK_SLEEP_LOG="$TMP_ROOT/sleep.log"
export MOCK_STATE_RC=0
export MOCK_ADD_RC=0
export MOCK_ZONE=public

cat > "$MOCK_BIN/firewall-cmd" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$MOCK_FW_LOG"
case "${1:-}" in
  --state) exit "${MOCK_STATE_RC:-0}" ;;
  --get-default-zone)
    printf '%s\n' "${MOCK_ZONE:-public}"
    exit "${MOCK_ZONE_RC:-0}" ;;
esac
for arg in "$@"; do
  if [[ "$arg" == --add-port=* ]]; then
    exit "${MOCK_ADD_RC:-0}"
  fi
done
exit 0
EOF
cat > "$MOCK_BIN/logger" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$MOCK_LOGGER_LOG"
EOF
cat > "$MOCK_BIN/sleep" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$MOCK_SLEEP_LOG"
EOF
chmod +x "$MOCK_BIN/firewall-cmd" "$MOCK_BIN/logger" "$MOCK_BIN/sleep"
export PATH="$MOCK_BIN:$PATH"

reset_mocks() {
  : > "$MOCK_FW_LOG"
  : > "$MOCK_LOGGER_LOG"
  : > "$MOCK_SLEEP_LOG"
  export MOCK_STATE_RC=0 MOCK_ADD_RC=0 MOCK_ZONE=public MOCK_ZONE_RC=0
}

no_remove_or_reload() {
  ! grep -E -- '--(remove|reload)' "$MOCK_FW_LOG" >/dev/null 2>&1
}

reset_mocks
if bash "$FIREWALL_ENSURE" "80,82,443" > "$TMP_ROOT/direct-ok.out" 2>&1; then
  grep -- '--add-port=' "$MOCK_FW_LOG" > "$TMP_ROOT/direct-ok.actual"
  cat > "$TMP_ROOT/direct-ok.expected" <<'EOF'
--zone=public --add-port=80/tcp
--permanent --zone=public --add-port=80/tcp
--zone=public --add-port=82/tcp
--permanent --zone=public --add-port=82/tcp
--zone=public --add-port=443/tcp
--permanent --zone=public --add-port=443/tcp
EOF
  if cmp -s "$TMP_ROOT/direct-ok.expected" "$TMP_ROOT/direct-ok.actual" && no_remove_or_reload; then
    pass "默认 zone 同时精确添加 runtime+permanent，且不 remove/reload"
  else
    fail "runtime+permanent 参数或只增纪律不符（见 $TMP_ROOT/direct-ok.actual）"
  fi
else
  fail "合法端口清单执行失败（见 $TMP_ROOT/direct-ok.out）"
fi

reset_mocks
if bash "$FIREWALL_ENSURE" "80,443" >/dev/null 2>&1 \
   && bash "$FIREWALL_ENSURE" "80,443" >/dev/null 2>&1; then
  add_count="$(grep -c -- '--add-port=' "$MOCK_FW_LOG")"
  if [[ "$add_count" == "8" ]] && no_remove_or_reload; then
    pass "重复执行幂等：重复 add 成功且无删除/reload"
  else
    fail "幂等执行调用序列异常"
  fi
else
  fail "重复执行合法端口清单应成功"
fi

ports_129="$(python3 -c 'print(",".join(str(p) for p in range(1, 130)))')"
invalid_inputs=(
  ""
  "0"
  "65536"
  "080"
  "443,80"
  "80,80"
  "80,080"
  "80,"
  "80,,443"
  "80,abc"
  "80-82"
  "80 443"
  "80;touch-PWNED"
  "$ports_129"
)
invalid_ok=true
for input in "${invalid_inputs[@]}"; do
  reset_mocks
  if bash "$FIREWALL_ENSURE" "$input" >/dev/null 2>&1; then
    printf '非法输入被接受: %s\n' "${input:-<空>}" >&2
    invalid_ok=false
  fi
  if grep -- '--add-port=' "$MOCK_FW_LOG" >/dev/null 2>&1; then
    printf '非法输入触发防火墙修改: %s\n' "${input:-<空>}" >&2
    invalid_ok=false
  fi
done
reset_mocks
if bash "$FIREWALL_ENSURE" "80,443" extra >/dev/null 2>&1; then
  invalid_ok=false
fi
[[ "$invalid_ok" == "true" ]] \
  && pass "空值、越界、非十进制、乱序、重复、129 项及多参数均拒绝且零修改" \
  || fail "非法输入校验"

ports_128="$(python3 -c 'print(",".join(str(p) for p in range(1, 129)))')"
reset_mocks
if bash "$FIREWALL_ENSURE" "$ports_128" >/dev/null 2>&1 \
   && [[ "$(grep -c -- '--add-port=' "$MOCK_FW_LOG")" == "256" ]]; then
  pass "128 项边界值接受并逐项双状态添加"
else
  fail "128 项边界值应接受"
fi

reset_mocks
export MOCK_STATE_RC=1
if bash "$FIREWALL_ENSURE" "80" >/dev/null 2>&1; then
  fail "firewalld 未运行应返回非零"
elif grep -q 'firewall_ensure_failed' "$MOCK_LOGGER_LOG" \
     && ! grep -- '--add-port=' "$MOCK_FW_LOG" >/dev/null 2>&1; then
  pass "firewalld 未运行明确非零并 logger，未添加规则"
else
  fail "firewalld 未运行错误记录不完整"
fi

reset_mocks
export MOCK_ADD_RC=1
if bash "$FIREWALL_ENSURE" "80" >/dev/null 2>&1; then
  fail "firewall-cmd 添加失败应返回非零"
elif grep -q 'firewall_ensure_failed' "$MOCK_LOGGER_LOG"; then
  pass "firewall-cmd 命令失败明确非零并 logger"
else
  fail "firewall-cmd 命令失败未记录 logger"
fi

MY_UID="$(id -u)"
FLAG_SEQUENCE=0
FLAG_DIR=""
make_flag() { # make_flag ACTION DELAY PORTS_CSV SIGN_VERSION [REQUESTED_AT]
  local action="$1" delay="$2" ports_csv="$3" version="$4"
  local requested_at="${5:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
  FLAG_SEQUENCE=$((FLAG_SEQUENCE+1))
  FLAG_DIR="$TMP_ROOT/hostctl-$FLAG_SEQUENCE"
  mkdir -p "$FLAG_DIR"
  chmod 755 "$FLAG_DIR"
  openssl rand -hex 32 > "$FLAG_DIR/.hostctl-secret"
  chmod 600 "$FLAG_DIR/.hostctl-secret"
  python3 - "$FLAG_DIR" "$action" "$delay" "$ports_csv" "$version" "$requested_at" <<'PY'
import hashlib
import hmac
import json
import os
import sys

directory, action, delay, ports_csv, version, requested_at = sys.argv[1:]
with open(os.path.join(directory, ".hostctl-secret"), encoding="ascii") as secret_file:
    secret = secret_file.read().strip()
ports = [] if ports_csv == "" else [int(p) if p.isdigit() else p for p in ports_csv.split(",")]
fields = [version, action, "gateway-publish", "user-uuid", "request-uuid", requested_at, delay]
if version == "v2":
    fields.append(ports_csv)
mac = hmac.new(secret.encode("ascii"), "\n".join(fields).encode("utf-8"), hashlib.sha256).hexdigest()
command = {
    "action": action,
    "requestedBy": "gateway-publish",
    "userID": "user-uuid",
    "requestID": "request-uuid",
    "requestedAt": requested_at,
    "delaySeconds": int(delay),
    "ports": ports,
    "hmac": mac,
}
path = os.path.join(directory, action + "-1-request-uuid.json")
with open(path, "w", encoding="utf-8") as flag_file:
    json.dump(command, flag_file, separators=(",", ":"))
    flag_file.write("\n")
PY
}

reset_mocks
make_flag firewall_ensure 0 "80,82,443" v2
if HOSTCTL_EXPECT_UID="$MY_UID" bash "$HOSTCTL" "$FLAG_DIR" > "$TMP_ROOT/hostctl-ok.out" 2>&1; then
  if [[ "$(grep -c -- '--add-port=' "$MOCK_FW_LOG")" == "6" ]] \
     && [[ ! -s "$MOCK_SLEEP_LOG" ]] \
     && [[ -f "$FLAG_DIR/firewall_ensure-1-request-uuid.json.done" ]] \
     && no_remove_or_reload; then
    pass "hostctl v2 验签后仅执行端口脚本，delay=0 不等待并原子归档"
  else
    fail "hostctl firewall_ensure 执行、归档或不等待纪律异常"
  fi
else
  fail "hostctl 合法 v2 firewall_ensure 应成功（见 $TMP_ROOT/hostctl-ok.out）"
fi

reset_mocks
make_flag firewall_ensure 0 "80,82,443" v2
if HOSTCTL_EXPECT_UID="$MY_UID" bash "$HOSTCTL" --dry-run "$FLAG_DIR" > "$TMP_ROOT/hostctl-dry.out" 2>&1; then
  if [[ ! -s "$MOCK_FW_LOG" && ! -s "$MOCK_SLEEP_LOG" ]] \
     && [[ -f "$FLAG_DIR/firewall_ensure-1-request-uuid.json.done" ]]; then
    pass "hostctl --dry-run 不触碰防火墙且不等待"
  else
    fail "hostctl --dry-run 产生防火墙或 sleep 调用"
  fi
else
  fail "hostctl 合法 v2 dry-run 应成功: $(cat "$TMP_ROOT/hostctl-dry.out")"
fi

old_actions_ok=true
for action in reboot shutdown factory_reset; do
  reset_mocks
  make_flag "$action" 1 "" v1
  if ! HOSTCTL_EXPECT_UID="$MY_UID" bash "$HOSTCTL" --dry-run "$FLAG_DIR" >/dev/null 2>&1; then
    printf '旧动作 v1 验签失败: %s\n' "$action" >&2
    old_actions_ok=false
  fi
  [[ -f "$FLAG_DIR/$action-1-request-uuid.json.done" ]] || old_actions_ok=false
  [[ ! -s "$MOCK_FW_LOG" ]] || old_actions_ok=false
done
[[ "$old_actions_ok" == "true" ]] \
  && pass "reboot/shutdown/factory_reset 原 v1 载荷逐字节兼容" \
  || fail "旧动作 v1 兼容性"

reset_mocks
make_flag firewall_ensure 0 "80,443" v1
if HOSTCTL_EXPECT_UID="$MY_UID" bash "$HOSTCTL" --dry-run "$FLAG_DIR" >/dev/null 2>&1; then
  fail "firewall_ensure 使用旧 v1 签名应拒绝"
elif [[ ! -s "$MOCK_FW_LOG" ]]; then
  pass "firewall_ensure 强制 v2，v1 签名不能混用"
else
  fail "v1 firewall_ensure 拒绝前触碰防火墙"
fi

host_invalid_ok=true
for input in "${invalid_inputs[@]}"; do
  reset_mocks
  make_flag firewall_ensure 0 "$input" v2
  if HOSTCTL_EXPECT_UID="$MY_UID" bash "$HOSTCTL" --dry-run "$FLAG_DIR" >/dev/null 2>&1; then
    printf 'hostctl 接受非法 ports: %s\n' "${input:-<空>}" >&2
    host_invalid_ok=false
  fi
  [[ -f "$FLAG_DIR/firewall_ensure-1-request-uuid.json.done" ]] || host_invalid_ok=false
  [[ ! -s "$MOCK_FW_LOG" ]] || host_invalid_ok=false
done
[[ "$host_invalid_ok" == "true" ]] \
  && pass "hostctl 对全部非法 ports 验签后仍归档拒绝且不执行" \
  || fail "hostctl 非法 ports 校验"

reset_mocks
make_flag firewall_ensure 1 "80" v2
if HOSTCTL_EXPECT_UID="$MY_UID" bash "$HOSTCTL" --dry-run "$FLAG_DIR" >/dev/null 2>&1; then
  fail "firewall_ensure 非零 delay 应拒绝"
elif [[ ! -s "$MOCK_SLEEP_LOG" && ! -s "$MOCK_FW_LOG" ]]; then
  pass "firewall_ensure 非零 delay 拒绝，不等待不执行"
else
  fail "非零 delay 拒绝路径产生副作用"
fi

printf '\n========== firewall ensure 结果: PASS=%d FAIL=%d ==========\n' "$PASS_COUNT" "$FAIL_COUNT"
[[ "$FAIL_COUNT" -eq 0 ]]
