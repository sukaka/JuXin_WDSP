#!/usr/bin/env bash
# install.sh —— 九章 WAF 安装向导：环境检查 → 生成 .env（随机口令/主密钥）→ 启动 → 三权账号引导。
# 初始口令仅打印一次，不写入任何日志文件。
# 退出码：0=成功 1=失败 2=用法错误
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

usage() {
  cat <<'EOF'
用法: install.sh [选项]

安装向导：
  1. 环境检查（docker / compose / 端口 / 内存 / 磁盘 / 时间同步）
  2. 生成 .env（随机 POSTGRES_PASSWORD / VALKEY_PASSWORD / JIUZHANG_MASTER_KEY）
  3. 启动 compose 项目并等待健康
  4. 初始化三权管理员账号（安全/审计管理员经 API 创建，临时口令仅打印一次）

选项:
  -c, --compose-file FILE  docker compose 文件（默认 docker-compose.yml）
  -e, --env-file FILE      生成的环境文件路径（默认 .env；已存在则拒绝覆盖，除非 --force）
      --api-url URL        管理 API 地址（默认 http://127.0.0.1:18081）
      --gateway-port PORT  网关对外端口检查（默认 80）
      --api-port PORT      API 端口检查（默认 18081）
      --force              允许覆盖已存在的 .env
      --skip-accounts      跳过三权账号初始化
  -h, --help               显示帮助

退出码: 0=成功 1=失败 2=用法错误
EOF
}

GATEWAY_PORT=80
API_PORT=18081
FORCE=false
SKIP_ACCOUNTS=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    -c|--compose-file) JZ_COMPOSE_FILE="$2"; shift 2 ;;
    -e|--env-file)     JZ_ENV_FILE="$2"; shift 2 ;;
    --api-url)         JZ_API_BASE="$2"; shift 2 ;;
    --gateway-port)    GATEWAY_PORT="$2"; shift 2 ;;
    --api-port)        API_PORT="$2"; shift 2 ;;
    --force)           FORCE=true; shift ;;
    --skip-accounts)   SKIP_ACCOUNTS=true; shift ;;
    -h|--help)         usage; exit 0 ;;
    *) log_err "未知参数: $1"; usage; exit 2 ;;
  esac
done

[[ -f "$JZ_COMPOSE_FILE" ]] || die "compose 文件不存在: $JZ_COMPOSE_FILE"
require_cmd docker
require_cmd openssl
require_cmd curl
docker compose version >/dev/null 2>&1 || die "缺少 docker compose 插件"

# ---------- 1. 环境检查 ----------
log_info "步骤 1/4：环境检查"

port_in_use() { # 检查本机端口占用（lsof 优先，/dev/tcp 兜底）
  local port="$1"
  if command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1
    return $?
  fi
  (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null && { exec 3>&- 3<&-; return 0; }
  return 1
}

for p in "$GATEWAY_PORT" "$API_PORT"; do
  if port_in_use "$p"; then
    die "端口 $p 已被占用，请先释放（或调整端口参数）"
  fi
done
log_info "端口 $GATEWAY_PORT / $API_PORT 可用"

# 内存 ≥4GB
mem_gb=0
if [[ "$(uname)" == "Darwin" ]]; then
  mem_gb=$(( $(sysctl -n hw.memsize) / 1024 / 1024 / 1024 ))
elif [[ -r /proc/meminfo ]]; then
  mem_gb=$(( $(awk '/MemTotal/ {print $2}' /proc/meminfo) / 1024 / 1024 ))
fi
if (( mem_gb > 0 && mem_gb < 4 )); then
  die "内存 ${mem_gb}GB，低于最低要求 4GB"
fi
log_info "内存 ${mem_gb}GB"

# 磁盘 ≥20GB 可用
free_gb="$(df -P -k . | awk 'NR==2 {print int($4/1024/1024)}')"
if (( free_gb < 20 )); then
  die "当前目录磁盘可用 ${free_gb}GB，低于最低要求 20GB"
fi
log_info "磁盘可用 ${free_gb}GB"

# 时间同步（偏移 >60s 视为异常；无法判定时告警不阻断）
local_epoch="$(date +%s)"
http_date="$(curl -sSI --max-time 5 https://www.baidu.com 2>/dev/null | grep -i '^date:' | head -1 | cut -d' ' -f2- || true)"
if [[ -n "$http_date" ]]; then
  remote_epoch="$(date -u -j -f '%a, %d %b %Y %T GMT' "$http_date" +%s 2>/dev/null || date -u -d "$http_date" +%s 2>/dev/null || echo 0)"
  if [[ "$remote_epoch" =~ ^[0-9]+$ ]] && (( remote_epoch > 0 )); then
    drift=$(( local_epoch - remote_epoch ))
    (( drift < 0 )) && drift=$(( -drift ))
    if (( drift > 60 )); then
      die "系统时间与网络时间偏差 ${drift}s（>60s），请先配置 NTP 时间同步"
    fi
    log_info "时间同步正常（偏差 ${drift}s）"
  else
    log_warn "无法解析远端时间，跳过时间同步检查"
  fi
else
  log_warn "无法访问外网时间源，跳过时间同步检查（离线环境请自行确认 NTP 正常）"
fi

# ---------- 2. 生成 .env ----------
log_info "步骤 2/4：生成环境文件 $JZ_ENV_FILE"
if [[ -f "$JZ_ENV_FILE" && "$FORCE" != "true" ]]; then
  die "$JZ_ENV_FILE 已存在（--force 可覆盖；覆盖前请备份）"
fi
POSTGRES_PASSWORD="$(random_hex 24)"
VALKEY_PASSWORD="$(random_hex 24)"
JIUZHANG_MASTER_KEY="$(random_hex 32)"
INITIAL_ADMIN_PASSWORD="$(random_hex 12)"
umask 077
cat > "$JZ_ENV_FILE" <<EOF
# 九章 WAF 环境配置（由 ops/install/install.sh 生成于 $(date -u '+%Y-%m-%dT%H:%M:%SZ')）
# 本文件含敏感信息，权限已设为 600，禁止提交到版本库。
APP_ENV=prod
POSTGRES_DB=jiuzhang_waf
POSTGRES_USER=jiuzhang
POSTGRES_PASSWORD=$POSTGRES_PASSWORD
VALKEY_PASSWORD=$VALKEY_PASSWORD
JIUZHANG_MASTER_KEY=$JIUZHANG_MASTER_KEY
COOKIE_SECURE=true
INITIAL_ADMIN_USERNAME=jiuzhang_admin
# 初始化完成后请删除下一行（初始口令仅用于首次登录）
INITIAL_ADMIN_PASSWORD=$INITIAL_ADMIN_PASSWORD
API_PORT=$API_PORT
GATEWAY_PORT=$GATEWAY_PORT
EOF
chmod 600 "$JZ_ENV_FILE"
log_info "已生成随机数据库口令、Valkey 口令与主密钥（不回显）"

# ---------- 3. 启动 ----------
log_info "步骤 3/4：启动服务（compose up -d）"
compose up -d
log_info "等待管理 API 健康检查（最长 180s）..."
wait_http_ok "$JZ_API_BASE/api/v1/health" 180 || die "管理 API 启动超时，请用 ops/diagnostics/collect.sh 收集诊断信息"
log_info "管理 API 已就绪"

# ---------- 4. 三权账号初始化 ----------
if [[ "$SKIP_ACCOUNTS" == "true" ]]; then
  log_warn "已跳过三权账号初始化（--skip-accounts）"
  exit 0
fi
log_info "步骤 4/4：初始化三权管理员账号"
require_cmd jq
JZ_ADMIN_PASSWORD="$INITIAL_ADMIN_PASSWORD"
trap api_cleanup EXIT
api_login "jiuzhang_admin"

# 初始管理员首次登录强制改密：改为安装期生成的正式口令（仅本次打印）
FINAL_ADMIN_PASSWORD="$(random_hex 12)Aa!"
chg="$(api_req POST /api/v1/auth/change-password "$(jq -n --arg o "$INITIAL_ADMIN_PASSWORD" --arg n "$FINAL_ADMIN_PASSWORD" \
  '{old_password:$o, new_password:$n}')"
)" || die "修改初始管理员密码失败"
api_cleanup
INITIAL_ADMIN_PASSWORD="$FINAL_ADMIN_PASSWORD"
JZ_ADMIN_PASSWORD="$FINAL_ADMIN_PASSWORD"
api_login "jiuzhang_admin"

declare -a created
create_account() { # create_account USERNAME DISPLAY ROLE
  local username="$1" display="$2" role="$3"
  local body resp code tmp_pwd
  body="$(jq -n --arg u "$username" --arg d "$display" --arg r "$role" \
    '{username:$u, display_name:$d, role_code:$r}')"
  resp="$(api_req POST /api/v1/users "$body")"
  code="$(api_code "$resp")"
  if [[ "$code" != "SUCCESS" ]]; then
    if printf '%s' "$resp" | grep -qi "已存在\|conflict\|duplicate"; then
      log_warn "账号 $username 已存在，跳过创建"
      return 0
    fi
    die "创建账号 $username 失败: $(printf '%s' "$resp" | jq -r '.message // "未知错误"')"
  fi
  tmp_pwd="$(printf '%s' "$resp" | jq -r '.data.temporary_password // empty')"
  [[ -n "$tmp_pwd" ]] || die "创建账号 $username 后未返回临时口令"
  created+=("$username|$role|$tmp_pwd")
}

create_account "jiuzhang_secadmin" "安全管理员" "SECURITY_ADMIN"
create_account "jiuzhang_auditadmin" "审计管理员" "AUDIT_ADMIN"

cat <<EOF

==================== 初始账号（仅打印一次，请立即记录并妥善保管） ====================
  系统管理员: jiuzhang_admin
    初始口令: $INITIAL_ADMIN_PASSWORD
EOF
for entry in "${created[@]:-}"; do
  [[ -z "$entry" ]] && continue
  IFS='|' read -r u r p <<< "$entry"
  printf '  %s (%s)\n    临时口令: %s\n' "$u" "$r" "$p"
done
cat <<'EOF'
====================================================================================
  提示: 所有初始/临时口令首次登录后必须修改；
        确认账号可用后，请从 .env 中删除 INITIAL_ADMIN_PASSWORD 并重启服务。
EOF
