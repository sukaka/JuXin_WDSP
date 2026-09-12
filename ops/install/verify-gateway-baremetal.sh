#!/usr/bin/env bash
# verify-gateway-baremetal.sh —— 九章裸机网关期1 验收清单运行器。
# 在目标 Linux 主机（openEuler/UOS）执行，逐项输出 PASS/FAIL/SKIP：
#   1. systemd unit 属性（Type/NotifyAccess、User/Group、Capability、sandbox 基线）
#   2. autosave/resume 恢复测试（默认执行，--skip-destructive 跳过）
#   3. sandbox 增强候选指令兼容性静态探测（systemd-analyze verify，不实际启用）
#   4. SELinux 共享目录上下文检查（Enforcing 时）
#   5. 日志 rolling 配置是否存在于运行配置
#   6. 外部可达性指引（监听端口列表 + firewalld 核对命令）
# 退出码：0=全部 PASS（允许 SKIP） 1=存在 FAIL 2=用法错误
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "$SCRIPT_DIR/../lib/common.sh"

UNIT_NAME="jiuzhang-gateway"
UNIT_FILE="/etc/systemd/system/jiuzhang-gateway.service"
ADMIN_SOCK="/var/run/caddy/admin.sock"
TEST_PORT=18099
SKIP_DESTRUCTIVE=false

PASS_N=0; FAIL_N=0; SKIP_N=0
ok()   { PASS_N=$((PASS_N+1)); printf '[PASS] %s\n' "$*"; }
bad()  { FAIL_N=$((FAIL_N+1)); printf '[FAIL] %s\n' "$*" >&2; }
skip() { SKIP_N=$((SKIP_N+1)); printf '[SKIP] %s\n' "$*"; }

usage() {
  cat <<'EOF'
用法: verify-gateway-baremetal.sh [选项]

期1 验收清单运行器：unit 属性 → autosave/resume 恢复 → sandbox 候选探测 →
SELinux 上下文 → 日志 rolling → 外部可达性指引。

选项:
      --skip-destructive  跳过 autosave/resume 恢复测试（含 /load 与 systemctl restart）
      --socket PATH       admin socket 路径（默认 /var/run/caddy/admin.sock）
      --port N            恢复测试临时站点端口（默认 18099）
  -h, --help              显示帮助

退出码: 0=全部 PASS（允许 SKIP） 1=存在 FAIL 2=用法错误
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-destructive) SKIP_DESTRUCTIVE=true; shift ;;
    --socket)           ADMIN_SOCK="$2"; shift 2 ;;
    --port)             TEST_PORT="$2"; shift 2 ;;
    -h|--help)          usage; exit 0 ;;
    *) log_err "未知参数: $1"; usage; exit 2 ;;
  esac
done

require_cmd systemctl
require_cmd curl

# sock_req METHOD PATH [CURL_ARGS...] —— 经 admin unix socket 请求。
sock_req() {
  local method="$1" path="$2"; shift 2
  curl -sS --unix-socket "$ADMIN_SOCK" -X "$method" "$@" "http://localhost$path"
}

# ---------- 1. unit 属性 ----------
check_unit() {
  log_info "检查 1/6：systemd unit 属性"
  systemctl cat "$UNIT_NAME" >/dev/null 2>&1 || { bad "unit 未安装: $UNIT_NAME"; return; }

  local props
  props="$(systemctl show "$UNIT_NAME" \
    -p Type -p NotifyAccess -p User -p Group -p CapabilityBoundingSet \
    -p ProtectSystem -p NoNewPrivileges -p ActiveState -p SubState 2>/dev/null)"
  prop() { printf '%s\n' "$props" | awk -F= -v k="$1" '$1==k{print $2}'; }

  local t; t="$(prop Type)"
  if [[ "$t" == "notify" ]]; then
    # Type=notify 时验证 sd_notify 实际就绪：READY=1 经 main 通道上报
    if [[ "$(prop NotifyAccess)" == "main" && "$(prop SubState)" == "running" ]]; then
      ok "Type=notify 且服务已 READY（NotifyAccess=main, SubState=running）"
    else
      bad "Type=notify 但未就绪（NotifyAccess=$(prop NotifyAccess) SubState=$(prop SubState)）——sd_notify 未生效，考虑降级 Type=simple"
    fi
  elif [[ "$t" == "simple" ]]; then
    ok "Type=simple（已按降级路径定稿）"
  else
    bad "Type 异常: ${t:-<空>}"
  fi

  [[ "$(prop User)" == "jiuzhang-gw" ]]  && ok "User=jiuzhang-gw"  || bad "User=$(prop User)（期望 jiuzhang-gw）"
  [[ "$(prop Group)" == "jiuzhang-waf" ]] && ok "Group=jiuzhang-waf" || bad "Group=$(prop Group)（期望 jiuzhang-waf）"

  local caps; caps="$(prop CapabilityBoundingSet)"
  if [[ "$caps" == "CAP_NET_BIND_SERVICE" ]]; then
    ok "CapabilityBoundingSet 仅 CAP_NET_BIND_SERVICE"
  else
    bad "CapabilityBoundingSet=${caps:-<空>}（期望仅 CAP_NET_BIND_SERVICE）"
  fi
  [[ "$(prop ProtectSystem)" == "strict" ]] && ok "ProtectSystem=strict" || bad "ProtectSystem=$(prop ProtectSystem)（期望 strict）"
  [[ "$(prop NoNewPrivileges)" == "yes" ]] && ok "NoNewPrivileges=yes" || bad "NoNewPrivileges=$(prop NoNewPrivileges)（期望 yes）"
  [[ "$(prop ActiveState)" == "active" ]] && ok "服务 ActiveState=active" || bad "ActiveState=$(prop ActiveState)"
}

# ---------- 2. autosave/resume 恢复测试 ----------
check_resume() {
  log_info "检查 2/6：autosave/resume 恢复测试（临时静态站点 :${TEST_PORT}）"
  if [[ "$SKIP_DESTRUCTIVE" == "true" ]]; then
    skip "按 --skip-destructive 跳过恢复测试"
    return
  fi
  [[ -S "$ADMIN_SOCK" ]] || { bad "admin socket 不存在: $ADMIN_SOCK"; return; }
  if [[ "$(id -u)" -ne 0 ]]; then
    skip "非 root：无法 systemctl restart，跳过恢复测试（请用 sudo 执行完整验收）"
    return
  fi

  local work saved cfg
  work="$(mktemp -d "${TMPDIR:-/tmp}/jzgwverify.XXXXXX")"
  saved="$work/saved.json"; cfg="$work/test-site.json"

  # 保存当前运行配置（测试结束后原样恢复；全新安装下即为 bootstrap 空配置）
  if ! sock_req GET /config/ > "$saved"; then
    bad "无法读取当前运行配置（GET /config/）"; rm -rf "$work"; return
  fi

  cat > "$cfg" <<EOF
{
  "admin": {"listen": "unix/$ADMIN_SOCK"},
  "apps": {"http": {"servers": {"jzverify": {
    "listen": [":$TEST_PORT"],
    "routes": [{"handle": [{"handler": "static_response", "body": "jiuzhang-verify-ok"}]}]
  }}}}
}
EOF

  local restored=false
  _restore() {
    [[ "$restored" == "true" ]] && return 0
    sock_req POST /load -H 'Content-Type: application/json' --data-binary "@$saved" >/dev/null 2>&1 || true
    restored=true
  }

  if ! sock_req POST /load -H 'Content-Type: application/json' --data-binary "@$cfg" >/dev/null; then
    bad "临时站点 /load 失败"; _restore; rm -rf "$work"; return
  fi
  sleep 1
  if curl -fsS --max-time 5 "http://127.0.0.1:$TEST_PORT/" 2>/dev/null | grep -q 'jiuzhang-verify-ok'; then
    ok "临时站点 :$TEST_PORT 可访问"
  else
    bad "临时站点 :$TEST_PORT 不可访问"; _restore; rm -rf "$work"; return
  fi

  systemctl restart "$UNIT_NAME"
  local i
  for ((i = 0; i < 30; i++)); do [[ -S "$ADMIN_SOCK" ]] && break; sleep 1; done
  [[ -S "$ADMIN_SOCK" ]] || { bad "restart 后 admin socket 未恢复"; _restore; rm -rf "$work"; return; }
  sleep 1
  # 重启后 autosave 应经 --resume 恢复：端口与配置均仍在
  if curl -fsS --max-time 5 "http://127.0.0.1:$TEST_PORT/" 2>/dev/null | grep -q 'jiuzhang-verify-ok'; then
    ok "systemctl restart 后临时站点仍可用（autosave/resume 生效）"
  else
    bad "systemctl restart 后站点丢失——检查 unit ExecStart 是否恒定携带 --resume"
  fi
  if sock_req GET /config/ 2>/dev/null | grep -q "$TEST_PORT"; then
    ok "restart 后运行配置仍含 :$TEST_PORT"
  else
    bad "restart 后运行配置丢失 :$TEST_PORT"
  fi

  _restore
  ok "已恢复测试前配置"
  rm -rf "$work"
  log_info "提示：「服务器整机重启」等价场景请人工复核（重启后同一 --resume 路径，预期一致）"
}

# ---------- 3. sandbox 候选指令静态探测 ----------
check_sandbox_candidates() {
  log_info "检查 3/6：sandbox 增强候选指令兼容性探测（systemd-analyze verify，不实际启用）"
  [[ -f "$UNIT_FILE" ]] || { skip "unit 文件不存在: $UNIT_FILE"; return; }
  if ! command -v systemd-analyze >/dev/null 2>&1; then
    skip "缺少 systemd-analyze，跳过静态探测"
    return
  fi
  # 与 unit 模板尾部注释块保持一致；标注 "Go runtime 敏感" 的三项需目标环境实测定稿
  local candidates=(
    PrivateDevices=true ProtectKernelTunables=true ProtectKernelModules=true
    ProtectKernelLogs=true ProtectControlGroups=true ProtectClock=true
    RestrictSUIDSGID=true LockPersonality=true RestrictRealtime=true
    SystemCallArchitectures=native
    MemoryDenyWriteExecute=true SystemCallFilter=@system-service
    RestrictAddressFamilies=AF_UNIX
  )
  local cand tmp verdict
  for cand in "${candidates[@]}"; do
    tmp="$(mktemp "${TMPDIR:-/tmp}/jzgwunit-probe.XXXXXX")"
    # 在 [Service] 段末尾追加候选指令的 unit 副本
    awk -v ins="$cand" '
      /^\[Install\]/ && !done {print ins; done=1}
      {print}
    ' "$UNIT_FILE" > "$tmp"
    if systemd-analyze verify "$tmp" >/dev/null 2>&1; then
      verdict="可行"
    else
      verdict="存疑（systemd-analyze verify 报错，需目标环境实测）"
    fi
    rm -f "$tmp"
    printf '  [PROBE] %-55s %s\n' "$cand" "$verdict"
  done
  ok "sandbox 候选静态探测完成（结果见 [PROBE] 行；存疑项不阻塞，开启前逐项实测）"
}

# ---------- 4. SELinux 上下文 ----------
check_selinux() {
  log_info "检查 4/6：SELinux 共享目录上下文"
  if ! command -v getenforce >/dev/null 2>&1; then
    skip "无 SELinux"
    return
  fi
  local mode; mode="$(getenforce 2>/dev/null || printf 'unknown')"
  if [[ "$mode" != "Enforcing" ]]; then
    skip "SELinux 状态 ${mode}（非 Enforcing，跳过上下文检查）"
    return
  fi
  local d ctx fail=0
  for d in /var/log/caddy /var/run/caddy /etc/caddy/certificates /var/lib/caddy/config; do
    [[ -e "$d" ]] || { bad "目录不存在: $d"; fail=1; continue; }
    ctx="$(ls -Zd "$d" 2>/dev/null | awk '{print $1}')"
    if [[ "$ctx" == *container_file_t* ]]; then
      ok "$d 上下文为 container_file_t"
    else
      bad "$d 上下文为 ${ctx:-<未知>}（候选方案期望 container_file_t，需 restorecon 或复核标签方案）"
      fail=1
    fi
  done
  [[ "$fail" == "0" ]] && log_info "SELinux 检查完成（不得 setenforce 0 规避）"
}

# ---------- 5. 日志 rolling ----------
check_log_rolling() {
  log_info "检查 5/6：日志 rolling 配置"
  [[ -S "$ADMIN_SOCK" ]] || { bad "admin socket 不存在: $ADMIN_SOCK"; return; }
  local cfg
  cfg="$(sock_req GET /config/ 2>/dev/null)" || { bad "GET /config/ 失败"; return; }
  # v2.11.4 实测 JSON：file writer 携带 roll/roll_size_mb/roll_keep/roll_keep_days
  if printf '%s' "$cfg" | grep -q '"roll"[[:space:]]*:[[:space:]]*true' \
     && printf '%s' "$cfg" | grep -q '"roll_size_mb"'; then
    ok "运行配置含 Caddy 原生日志 rolling（roll/roll_size_mb）"
  else
    bad "运行配置未见日志 rolling 字段——检查 bootstrap log 块与生成器日志配置"
  fi
}

# ---------- 6. 外部可达性指引 ----------
check_reachability() {
  log_info "检查 6/6：外部可达性指引"
  local ports=""
  if command -v ss >/dev/null 2>&1; then
    ports="$(ss -tlnH 2>/dev/null | awk '{split($4,a,":");print a[length(a)]}' | sort -n | uniq | tr '\n' ' ')"
  elif command -v netstat >/dev/null 2>&1; then
    ports="$(netstat -tln 2>/dev/null | awk 'NR>2{split($4,a,":");print a[length(a)]}' | sort -n | uniq | tr '\n' ' ')"
  fi
  log_info "当前监听 TCP 端口: ${ports:-<无法枚举>}"
  log_info "运维核对：1024-65535/tcp 按安装基线默认放行；对每个站点端口仍可执行 firewall-cmd --query-port=N/tcp"
  log_info "  1-1023 端口未包含在默认范围，需 firewall-cmd --add-port=N/tcp --permanent && firewall-cmd --reload"
  log_info "  （4.7：firewalld 未运行或策略未同步时，「配置发布成功」不等于「外部可达」）"
  ok "外部可达性指引已输出（需人工按站点端口逐项核对）"
}

main() {
  check_unit
  check_resume
  check_sandbox_candidates
  check_selinux
  check_log_rolling
  check_reachability
  printf '\n==================== 验收结果: PASS=%d FAIL=%d SKIP=%d ====================\n' \
    "$PASS_N" "$FAIL_N" "$SKIP_N"
  [[ "$FAIL_N" -eq 0 ]]
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main
fi
