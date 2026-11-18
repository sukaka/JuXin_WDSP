#!/usr/bin/env bash
# hostctl-exec.sh —— 系统控制执行通道：扫描 hostctl 标志目录，执行重启/关机/恢复出厂/端口放行。
#
# 背景：API 容器 read_only + cap_drop ALL，不能执行主机命令；校验通过后仅往
# 标志目录写 <action>-<unixts>-<requestid>.json（JSON 内容含 action/requestedBy/
# userID/requestID/requestedAt/delaySeconds/hmac，firewall_ensure 另含 ports）。
# 宿主机由 jiuzhang-hostctl.path
# systemd path 单元监视目录并触发本脚本（无 systemd 环境可手工执行）。
#
# JSON 解析：优先 python3，缺失时回退 jq（二者须至少其一，用 require_cmd 检查）。
# 安全要点：执行前先 stat 校验标志目录属主（约定 uid 1000）、目录非 other-writable、
# 标志文件属主与目录属主一致，任一不满足即归档拒绝并 logger 告警（fail-closed）；
# 处理前先把标志文件改名为 <原名>.done（防 systemd path 单元重复触发）；
# action 必须在白名单（reboot/shutdown/factory_reset/firewall_ensure）内，非法标志同样改名归档并
# 报错退出（不改名会导致 path 单元反复触发同一非法文件）。
#
# 请求真实性（HIGH-14 后续增强）：属主/权限校验只证明文件来自预期本地用户，不证明
# 请求真实性，故标志文件必须携带共享密钥 HMAC-SHA256 签名（hmac 字段）。密钥为
# <标志目录>/.hostctl-secret（64 字符 hex，权限 600，属主=目录属主即写入方服务用户）；
# 本脚本启动时若密钥缺失且目录属主/权限符合约定则以安全权限自举（与 server 侧
# 自举对称，先到者生效）。验签 fail-closed：缺 hmac/requestedAt/delaySeconds 字段
# （含升级窗口内旧 server 写出的未签名标志）、hmac 格式非法、HMAC 不符、requestedAt
# 超出 ±HOSTCTL_MAX_SKEW 秒（默认 300，防重放）一律归档拒绝并告警。
# 规范化签名载荷（两端必须逐字节一致）：以 \n 连接、无结尾换行。旧动作固定使用 v1：
#   v1\n<action>\n<requestedBy>\n<userID>\n<requestID>\n<requestedAt>\n<delaySeconds>
# firewall_ensure 使用 v2，在原七字段后追加第 8 字段逗号分隔端口：
#   v2\nfirewall_ensure\n<requestedBy>\n<userID>\n<requestID>\n<requestedAt>\n0\n<portsCSV>
#
# 用法: hostctl-exec.sh [--dry-run] [标志目录]
#   标志目录：位置参数 $1 或环境变量 HOSTCTL_DIR，默认 <仓库根>/runtime/hostctl
#   --dry-run：只打印将执行的动作，不真正执行（供测试验收）
# 退出码: 0=成功（含无待处理标志） 1=失败 2=用法错误
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

DRY_RUN=false
POSITIONAL=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=true; shift ;;
    -h|--help)
      sed -n '2,18p' "$0"
      exit 0 ;;
    *) POSITIONAL+=("$1"); shift ;;
  esac
done
[[ ${#POSITIONAL[@]} -le 1 ]] || { log_err "参数过多: ${POSITIONAL[*]:1}"; exit 2; }

REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
HOSTCTL_DIR="${POSITIONAL[0]:-${HOSTCTL_DIR:-$REPO_ROOT/runtime/hostctl}}"
[[ -d "$HOSTCTL_DIR" ]] || { log_info "标志目录不存在（${HOSTCTL_DIR}），无待处理项"; exit 0; }

# JSON 解析器：优先 python3，回退 jq
if command -v python3 >/dev/null 2>&1; then
  JSON_TOOL=python3
elif command -v jq >/dev/null 2>&1; then
  JSON_TOOL=jq
else
  die "缺少 JSON 解析工具：请安装 python3 或 jq 之一"
fi
require_cmd logger
require_cmd openssl

# json_fields FILE —— 依次输出 action / requestedBy / userID / requestID /
# requestedAt / delaySeconds / hmac / ports 八行。ports 数组规范化为 CSV；
# 非数组输出固定非法标记，由调用方按动作校验（旧动作忽略该字段）。
json_fields() {
  local f="$1"
  if [[ "$JSON_TOOL" == "python3" ]]; then
    python3 - "$f" 2>/dev/null <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
def s(k):
    v = d.get(k, "")
    return "" if v is None else str(v)
print(s("action"))
print(s("requestedBy"))
print(s("userID"))
print(s("requestID"))
print(s("requestedAt"))
print(s("delaySeconds"))
print(s("hmac"))
ports = d.get("ports", [])
if ports is None:
    ports = []
if isinstance(ports, list):
    print(",".join("" if v is None else str(v) for v in ports))
else:
    print("<invalid-ports>")
PY
  else
    jq -r '[.action // "", .requestedBy // "", .userID // "", .requestID // "", .requestedAt // "", (.delaySeconds // ""), .hmac // "", ((.ports // []) | if type == "array" then map(if . == null then "" else tostring end) | join(",") else "<invalid-ports>" end)] | .[] | tostring' "$f" 2>/dev/null
  fi
}

# ts_epoch RFC3339 —— 输出 unix epoch，无法解析返回非 0
ts_epoch() {
  local ts="$1"
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$ts" 2>/dev/null <<'PY'
import sys
from datetime import datetime
s = sys.argv[1].strip()
if s.endswith("Z"):
    s = s[:-1] + "+00:00"
try:
    print(int(datetime.fromisoformat(s).timestamp()))
except ValueError:
    sys.exit(1)
PY
    return
  fi
  date -d "$ts" +%s 2>/dev/null || date -u -j -f "%Y-%m-%dT%H:%M:%SZ" "$ts" +%s 2>/dev/null
}

# ---- 执行前安全校验（HIGH-14）：root 执行通道先验证标志来源，再解析执行 ----
# 约定（ops/install/install.sh 步骤 5）：标志目录属主 1000:1000、权限 755，api 容器以
# uid 1000 写入标志。若目录属主错误（uid 1000 对应非预期本地用户）或 chown 失败退化
# 为 1777，能写该目录的本地用户即可伪造合法 JSON 让 root 执行 reboot/shutdown/
# factory_reset。此处 fail-closed：校验不过即归档拒绝并告警。
# 请求真实性由共享密钥 HMAC 签名保证（见文件头注释）：仅通过属主/权限校验的目录
# 才允许自举密钥，验签不过一律拒绝。
HOSTCTL_EXPECT_UID="${HOSTCTL_EXPECT_UID:-1000}"
HOSTCTL_MAX_SKEW="${HOSTCTL_MAX_SKEW:-300}"
[[ "$HOSTCTL_MAX_SKEW" =~ ^[0-9]+$ ]] || { log_err "HOSTCTL_MAX_SKEW 非法: $HOSTCTL_MAX_SKEW"; exit 2; }
SECRET_FILE="$HOSTCTL_DIR/.hostctl-secret"
SECRET=""

file_uid() { stat -c '%u' "$1" 2>/dev/null || stat -f '%u' "$1"; }
file_gid() { stat -c '%g' "$1" 2>/dev/null || stat -f '%g' "$1"; }
file_mode() { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"; }

dir_uid="$(file_uid "$HOSTCTL_DIR")"
dir_mode="$(file_mode "$HOSTCTL_DIR")"

dir_ok() { # 目录属主/权限是否符合约定（启动自举门控；执行路径另有逐条拒绝原因）
  [[ "$dir_mode" =~ ^[0-7]{3,4}$ ]] || return 1
  local perm="${dir_mode:${#dir_mode}-3}"
  [[ "$dir_uid" == "$HOSTCTL_EXPECT_UID" ]] || return 1
  (( (8#$perm & 2) == 0 ))
}

ensure_secret() { # ensure_secret —— 自举/校验共享密钥并装入 SECRET；失败返回 1
  if [[ ! -f "$SECRET_FILE" ]]; then
    # noclobber 原子创建，与 server 侧 O_EXCL 自举对称：先到者生效，后到者沿用
    ( umask 077; set -o noclobber; openssl rand -hex 32 > "$SECRET_FILE" ) 2>/dev/null || true
    if [[ -f "$SECRET_FILE" && "$(id -u)" != "$dir_uid" ]]; then
      chown "${dir_uid}:$(file_gid "$HOSTCTL_DIR")" "$SECRET_FILE" 2>/dev/null || true
    fi
  fi
  if [[ ! -f "$SECRET_FILE" ]]; then
    log_err "共享密钥缺失且无法自举: ${SECRET_FILE}（fail-closed）"
    return 1
  fi
  chmod 600 "$SECRET_FILE" 2>/dev/null || true
  local sec_uid
  sec_uid="$(file_uid "$SECRET_FILE")"
  if [[ "$sec_uid" != "$dir_uid" ]]; then
    log_err "共享密钥属主 uid=${sec_uid:-unknown} 与目录约定属主 uid=${dir_uid} 不一致（fail-closed）"
    return 1
  fi
  SECRET="$(tr -d '[:space:]' < "$SECRET_FILE" 2>/dev/null)"
  if [[ ! "$SECRET" =~ ^[0-9a-f]{64}$ ]]; then
    log_err "共享密钥格式非法（期望 64 字符 hex）: ${SECRET_FILE}（fail-closed）"
    SECRET=""
    return 1
  fi
}

# 启动时密钥自举：目录属主/权限符合约定才允许创建；目录正常而自举失败即
# fail-closed（不依赖 install.sh 预置）。目录异常时跳过自举，由执行路径拒绝。
if dir_ok; then
  if ! ensure_secret; then
    logger -t jiuzhang-hostctl -- "secret_bootstrap_failed dir=$HOSTCTL_DIR"
    exit 1
  fi
fi

# 取最新的未处理标志文件（.json 后缀；.done 为已处理归档）
latest_flag=""
shopt -s nullglob
flags=("$HOSTCTL_DIR"/*.json)
shopt -u nullglob
if [[ ${#flags[@]} -eq 0 ]]; then
  log_info "无待处理标志文件（${HOSTCTL_DIR}）"
  exit 0
fi
# 文件名含 unixts 但前缀为 action，字典序不可靠，按 mtime 取最新
latest_flag="$(ls -1t "${flags[@]}" 2>/dev/null | head -1)"
[[ -n "$latest_flag" && -f "$latest_flag" ]] || { log_info "无待处理标志文件"; exit 0; }
FLAG_BASE="$(basename "$latest_flag")"
log_info "发现标志文件: ${FLAG_BASE}（共 ${#flags[@]} 个待处理，仅执行最新一个）"

DONE_FILE="$latest_flag.done"

reject_flag() { # reject_flag REASON —— 归档标志、告警并退出（fail-closed）
  local reason="$1"
  mv "$latest_flag" "$DONE_FILE" \
    || log_warn "归档失败（原文件保留，path 单元将重复触发本条告警）"
  log_err "标志文件安全校验未通过：${reason}（已归档为 ${FLAG_BASE}.done，不执行）"
  logger -t jiuzhang-hostctl -- "security_rejected file=$FLAG_BASE reason=$reason"
  exit 1
}

[[ "$dir_mode" =~ ^[0-7]{3,4}$ ]] || reject_flag "无法读取标志目录权限: $HOSTCTL_DIR"
# 仅取末三位权限位（含粘滞位时 stat 输出四位，如 1777 → 777）
dir_perm="${dir_mode:${#dir_mode}-3}"
[[ "$dir_uid" == "$HOSTCTL_EXPECT_UID" ]] \
  || reject_flag "标志目录属主 uid=${dir_uid:-unknown} 非约定属主 uid=${HOSTCTL_EXPECT_UID}（属主配置错误，拒绝执行）"
(( (8#$dir_perm & 2) == 0 )) \
  || reject_flag "标志目录权限 ${dir_mode} 为 other-writable，任意本地用户可伪造标志（请 chmod 755 并核对属主）"
flag_uid="$(file_uid "$latest_flag")"
[[ -n "$flag_uid" && "$flag_uid" == "$dir_uid" ]] \
  || reject_flag "标志文件属主 uid=${flag_uid:-unknown} 与目录约定属主 uid=${dir_uid} 不一致（非 api 容器写入，拒绝执行）"
# 目录属主异常时启动自举已跳过，此处再兜一层（fail-closed）
[[ -n "$SECRET" ]] || reject_flag "共享密钥不可用（未自举或属主/格式非法）"

# 防重复触发：先改名为 .done，再做解析与执行；后续同名触发不会重复执行
mv "$latest_flag" "$DONE_FILE"

reject_parsed() { # reject_parsed REASON —— 已归档(.done)后的拒绝：告警并退出
  local reason="$1"
  log_err "标志文件安全校验未通过：${reason}（已归档为 ${FLAG_BASE}.done，不执行）"
  logger -t jiuzhang-hostctl -- "security_rejected file=$FLAG_BASE reason=$reason"
  exit 1
}

if ! parsed="$(json_fields "$DONE_FILE")"; then
  log_err "标志文件 JSON 解析失败: ${FLAG_BASE}（已归档为 ${FLAG_BASE}.done）"
  logger -t jiuzhang-hostctl -- "parse_failed file=$FLAG_BASE"
  exit 1
fi
# 逐行读入（兼容 bash 3.2，无 mapfile）
F=()
while IFS= read -r _line; do F+=("$_line"); done <<< "$parsed"
unset _line
ACTION="${F[0]:-}"
REQUESTED_BY="${F[1]:-}"
USER_ID="${F[2]:-}"
REQUEST_ID="${F[3]:-}"
REQUESTED_AT="${F[4]:-}"
DELAY="${F[5]:-}"
HMAC_FIELD="${F[6]:-}"
PORTS="${F[7]:-}"

# 签名验真（fail-closed）：缺字段（含升级窗口内旧 server 写出的未签名标志）、
# 格式非法、HMAC 不符、时间戳超窗一律拒绝
[[ -n "$HMAC_FIELD" && -n "$REQUESTED_AT" && -n "$DELAY" ]] \
  || reject_parsed "缺少 hmac/requestedAt/delaySeconds 字段（未签名标志一律拒绝）"
[[ "$HMAC_FIELD" =~ ^[0-9a-f]{64}$ ]] || reject_parsed "hmac 字段格式非法"

if [[ "$ACTION" == "firewall_ensure" ]]; then
  canonical="$(printf 'v2\n%s\n%s\n%s\n%s\n%s\n%s\n%s' \
    "$ACTION" "$REQUESTED_BY" "$USER_ID" "$REQUEST_ID" "$REQUESTED_AT" "$DELAY" "$PORTS")"
else
  canonical="$(printf 'v1\n%s\n%s\n%s\n%s\n%s\n%s' \
    "$ACTION" "$REQUESTED_BY" "$USER_ID" "$REQUEST_ID" "$REQUESTED_AT" "$DELAY")"
fi
expected_hmac="$(printf '%s' "$canonical" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $NF}')"
[[ -n "$expected_hmac" && "$expected_hmac" == "$HMAC_FIELD" ]] \
  || reject_parsed "HMAC 验签失败（内容被篡改或密钥不符）"

ts="$(ts_epoch "$REQUESTED_AT")" || reject_parsed "requestedAt 时间戳无法解析: $REQUESTED_AT"
now_ts="$(date +%s)"
skew=$(( now_ts - ts ))
(( skew < 0 )) && skew=$(( -skew ))
(( skew <= HOSTCTL_MAX_SKEW )) \
  || reject_parsed "requestedAt 超出允许时间窗（±${HOSTCTL_MAX_SKEW}s，疑似重放或时钟异常）"

# action 白名单校验
case "$ACTION" in
  reboot|shutdown|factory_reset|firewall_ensure) ;;
  *)
    log_err "非法 action: ${ACTION:-<空>}（白名单: reboot/shutdown/factory_reset/firewall_ensure），已归档不执行"
    logger -t jiuzhang-hostctl -- "rejected action=${ACTION:-empty} requestedBy=${REQUESTED_BY:-unknown} requestID=${REQUEST_ID:-unknown}"
    exit 1 ;;
esac

if [[ "$ACTION" == "firewall_ensure" ]]; then
  [[ "$PORTS" =~ ^[1-9][0-9]{0,4}(,[1-9][0-9]{0,4})*$ ]] \
    || reject_parsed "firewall_ensure ports 必须为十进制整数数组，每项 1..65535"
  IFS=',' read -r -a PORT_ITEMS <<< "$PORTS"
  (( ${#PORT_ITEMS[@]} >= 1 && ${#PORT_ITEMS[@]} <= 128 )) \
    || reject_parsed "firewall_ensure ports 必须包含 1..128 项"
  previous_port=0
  for port in "${PORT_ITEMS[@]}"; do
    port_number=$((10#$port))
    (( port_number >= 1 && port_number <= 65535 )) \
      || reject_parsed "firewall_ensure 端口超出 1..65535: $port"
    (( port_number > previous_port )) \
      || reject_parsed "firewall_ensure ports 必须严格升序且无重复"
    previous_port="$port_number"
  done
fi

# delaySeconds：旧动作默认 3、上限 60、非法值按 3；firewall_ensure 固定不等待。
if [[ "$ACTION" == "firewall_ensure" ]]; then
  [[ "$DELAY" == "0" ]] || reject_parsed "firewall_ensure 的 delaySeconds 必须为 0"
else
  [[ "$DELAY" =~ ^[0-9]+$ ]] || DELAY=3
  (( DELAY > 60 )) && DELAY=60
fi

logger -t jiuzhang-hostctl -- "execute action=$ACTION requestedBy=${REQUESTED_BY:-unknown} requestID=${REQUEST_ID:-unknown} delay=$DELAY file=$FLAG_BASE"
log_info "动作=$ACTION 操作人=${REQUESTED_BY:-unknown} requestID=${REQUEST_ID:-unknown} 延迟=${DELAY}s"

if [[ "$DRY_RUN" == "true" ]]; then
  if [[ "$ACTION" == "firewall_ensure" ]]; then
    log_info "[dry-run] 将执行: firewall-ensure.sh ${PORTS}（delay=0 不等待，不实际执行）"
  else
    log_info "[dry-run] 将 sleep ${DELAY}s 后执行: ${ACTION}（不实际执行）"
  fi
  exit 0
fi

(( DELAY > 0 )) && sleep "$DELAY"
case "$ACTION" in
  reboot)
    require_cmd systemctl
    log_info "执行 systemctl reboot"
    systemctl reboot ;;
  shutdown)
    require_cmd systemctl
    log_info "执行 systemctl poweroff"
    systemctl poweroff ;;
  factory_reset)
    [[ -x "$SCRIPT_DIR/factory-reset.sh" ]] || die "恢复出厂脚本不存在或不可执行: $SCRIPT_DIR/factory-reset.sh"
    log_info "执行恢复出厂: $SCRIPT_DIR/factory-reset.sh"
    JZ_ASSUME_YES=true bash "$SCRIPT_DIR/factory-reset.sh" ;;
  firewall_ensure)
    [[ -x "$SCRIPT_DIR/firewall-ensure.sh" ]] || die "防火墙放行脚本不存在或不可执行: $SCRIPT_DIR/firewall-ensure.sh"
    log_info "确保 firewalld runtime+permanent 放行: $PORTS"
    bash "$SCRIPT_DIR/firewall-ensure.sh" "$PORTS" ;;
esac
