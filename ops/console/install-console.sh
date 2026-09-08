#!/usr/bin/env bash
# install-console.sh —— 安装九章运维控制台（受限后台）：
#   创建 jiuzhang-ops 用户（登录 shell 指向 jiuzhang-console）→ 安装二进制与 netapply helper
#   → 写 sudoers 精确放行 → 生成随机初始口令（仅打印一次，沿用 install.sh 三权纪律）。
# 退出码：0=成功 1=失败 2=用法错误
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SCRIPT_DIR/../lib/common.sh" 2>/dev/null || true

usage() {
  cat <<'EOF'
用法: install-console.sh [选项]

选项:
  --binary FILE     已构建的 jiuzhang-console 二进制（缺省时用 go build 现编）
  --user NAME       控制台 OS 用户名（默认 jiuzhang-ops）
  --account NAME    控制台登录账号（默认 opsadmin）
  -h, --help        显示帮助

说明:
  - 需 root 运行；面向 Ubuntu 22.04+（netplan）/ RHEL 系（nmcli）交付环境。
  - 初始口令随机生成，仅在本脚本输出中打印一次；登录后用 passwd 命令修改。
EOF
}

BIN=""
OPS_USER="jiuzhang-ops"
ACCOUNT="opsadmin"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary)  BIN="$2"; shift 2 ;;
    --user)    OPS_USER="$2"; shift 2 ;;
    --account) ACCOUNT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "未知参数: $1" >&2; usage; exit 2 ;;
  esac
done

[[ $(id -u) -eq 0 ]] || { echo "需 root 运行" >&2; exit 1; }

# 1) 构建/校验二进制
if [[ -z "$BIN" ]]; then
  command -v go >/dev/null 2>&1 || { echo "缺少 go，请用 --binary 指定已构建产物" >&2; exit 1; }
  BIN="$(mktemp -t jiuzhang-console)"
  (cd "$REPO_ROOT/server" && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$BIN" ./cmd/console)
fi
[[ -x "$BIN" ]] || chmod +x "$BIN"

# 2) 安装二进制与 helper
install -m 0755 "$BIN" /usr/local/bin/jiuzhang-console
install -d -m 0750 /opt/jiuzhang/console
install -m 0750 "$SCRIPT_DIR/netapply.sh" /opt/jiuzhang/console/netapply.sh
grep -qx '/usr/local/bin/jiuzhang-console' /etc/shells 2>/dev/null \
  || echo '/usr/local/bin/jiuzhang-console' >> /etc/shells

# 3) 专用用户（登录 shell = 控制台）
if ! id "$OPS_USER" >/dev/null 2>&1; then
  useradd -m -s /usr/local/bin/jiuzhang-console "$OPS_USER"
else
  usermod -s /usr/local/bin/jiuzhang-console "$OPS_USER"
fi

# 4) sudoers 精确放行（仅 netapply 一个入口）
cat >/etc/sudoers.d/90-jiuzhang-console <<EOF
$OPS_USER ALL=(root) NOPASSWD: /opt/jiuzhang/console/netapply.sh
EOF
chmod 0440 /etc/sudoers.d/90-jiuzhang-console
visudo -cf /etc/sudoers.d/90-jiuzhang-console >/dev/null

# 4b) SSH 加固：该账户任何会话（含 exec/sftp/子系统）都强制进控制台，禁止转发隧道
#     —— 客户只拿得到白名单 REPL，接触不到系统 shell 与文件传输通道
if [[ -d /etc/ssh/sshd_config.d ]]; then
  cat >/etc/ssh/sshd_config.d/jiuzhang-console.conf <<EOF
Match User $OPS_USER
    ForceCommand /usr/local/bin/jiuzhang-console
    DisableForwarding yes
    X11Forwarding no
    PermitTunnel no
    AllowAgentForwarding no
EOF
  chmod 0644 /etc/ssh/sshd_config.d/jiuzhang-console.conf
  if sshd -t 2>/dev/null; then
    systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
  else
    rm -f /etc/ssh/sshd_config.d/jiuzhang-console.conf
    echo "警告: sshd 配置校验失败，已回退（不影响 TTY 控制台）" >&2
  fi
fi

# 5) 初始口令（随机，仅打印一次）；OS 密码与控制台口令同值，SSH/TTY 登录后直接进控制台
install -d -m 0750 /etc/jiuzhang
PASSWORD=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16 || true)
[[ ${#PASSWORD} -ge 16 ]] || { echo "随机口令生成失败" >&2; exit 1; }
echo "$OPS_USER:$PASSWORD" | chpasswd
HASH=$(printf '%s' "$PASSWORD" | /usr/local/bin/jiuzhang-console -hash-password)
install -m 0600 /dev/null /etc/jiuzhang/console.yaml
cat >/etc/jiuzhang/console.yaml <<EOF
# 九章运维控制台账号（passwd 命令维护，勿手改）
username: $ACCOUNT
password_hash: $HASH
EOF
chown "$OPS_USER:$OPS_USER" /etc/jiuzhang/console.yaml  # passwd 命令需写回

# 6) 审计：优先 syslog（tag jiuzhang-console，root 守护落盘，客户不可篡改）；
#    logger 不可用时控制台自动降级写 /var/log/jiuzhang-console.log
install -m 0640 -o "$OPS_USER" -g "$OPS_USER" /dev/null /var/log/jiuzhang-console.log

cat <<EOF

==========================================
九章运维控制台安装完成
  OS 用户:    $OPS_USER（SSH/TTY 登录，已禁用其转发与 sftp）
  控制台账号: $ACCOUNT
  初始口令:   $PASSWORD
  （仅打印一次，请立即记录；登录后 passwd 修改）
  审计:       syslog（tag jiuzhang-console），兜底 /var/log/jiuzhang-console.log
  root 口令无需交付客户；控制台内仅 passwd 可改自身口令
==========================================
EOF
