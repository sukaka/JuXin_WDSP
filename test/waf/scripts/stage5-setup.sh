#!/usr/bin/env bash
# 九章阶段5 测试公共准备：登录、用户、应用、发布、可信代理工具函数
# 用法：source test/waf/scripts/stage5-setup.sh
# 环境变量：API_URL GATEWAY_URL SEC_USER SEC_PWD VALKEY_CONTAINER VALKEY_PASSWORD HOST_HEADER

API_URL="${API_URL:-http://127.0.0.1:18081}"
GATEWAY_URL="${GATEWAY_URL:-http://127.0.0.1:18080}"
HOST_HEADER="${HOST_HEADER:-waf-s5.local}"
SYS_USER="${SYS_USER:-jiuzhang_admin}"
SYS_PWD="${SYS_PWD:-SysAdmin@S5!2026}"
SYS_NEW_PWD="${SYS_NEW_PWD:-SysAdmin@S5!2026x}"
SEC_USER="${SEC_USER:-sec_admin_s5}"
SEC_PWD="${SEC_PWD:-SecAdmin@S5!2026}"
VALKEY_CONTAINER="${VALKEY_CONTAINER:-jiuzhang-stage5-valkey}"
VALKEY_PASSWORD="${VALKEY_PASSWORD:-CHANGE_ME_STRONG_PASSWORD}"
APP_CODE="${APP_CODE:-s5app}"
APP_PROTECTION_MODE="${APP_PROTECTION_MODE:-OFF}"

# 登录（验证码从 Valkey 读取），打印 CSRF；cookie 存 /tmp/s5-<user>.txt
# 注意：CSRF token 取自登录响应（/auth/me 每次调用都会轮换 token，重复调用会使先前 token 失效）
s5_login() {
  local user="$1" pass="$2"
  local capid capcode
  capid=$(curl -s "$API_URL/api/v1/auth/captcha" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['captcha_id'])" 2>/dev/null)
  capcode=$(docker exec "$VALKEY_CONTAINER" valkey-cli -a "$VALKEY_PASSWORD" --no-auth-warning GET "jiuzhang:captcha:$capid" 2>/dev/null)
  curl -s -c "/tmp/s5-$user.txt" -X POST "$API_URL/api/v1/auth/login" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"$user\",\"password\":\"$pass\",\"captcha_id\":\"$capid\",\"captcha_code\":\"$capcode\"}" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['csrf_token'])" 2>/dev/null
}

# 确保系统管理员可登录（首次登录强制改密）
s5_ensure_sysadmin() {
  local csrf
  csrf=$(s5_login "$SYS_USER" "$SYS_PWD")
  if [ -z "$csrf" ]; then echo "ERROR: sysadmin login failed" >&2; return 1; fi
  # /auth/me 会轮换 CSRF token，后续写操作必须使用其响应中的新 token
  local me
  me=$(curl -s -b "/tmp/s5-$SYS_USER.txt" "$API_URL/api/v1/auth/me")
  csrf=$(echo "$me" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['csrf_token'])" 2>/dev/null)
  # 若必须改密
  local must
  must=$(echo "$me" | python3 -c "import json,sys; print(json.load(sys.stdin)['data'].get('user',{}).get('must_change_password', False))" 2>/dev/null)
  if [ "$must" = "True" ]; then
    curl -s -b "/tmp/s5-$SYS_USER.txt" -X POST "$API_URL/api/v1/auth/change-password" \
      -H 'Content-Type: application/json' -H "X-CSRF-Token: $csrf" \
      -d "{\"old_password\":\"$SYS_PWD\",\"new_password\":\"$SYS_NEW_PWD\"}" > /dev/null
    csrf=$(s5_login "$SYS_USER" "$SYS_NEW_PWD")
  fi
  echo "$csrf"
}

# 确保安全管理员用户存在且密码为 SEC_PWD（存在则跳过）
s5_ensure_secuser() {
  local sys_csrf="$1"
  local tmp
  tmp=$(curl -s -b "/tmp/s5-$SYS_USER.txt" -X POST "$API_URL/api/v1/users" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $sys_csrf" \
    -d "{\"username\":\"$SEC_USER\",\"display_name\":\"安全管理员S5\",\"role_code\":\"SECURITY_ADMIN\"}" \
    | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('data',{}).get('temporary_password','') if d.get('code')=='SUCCESS' else '')" 2>/dev/null)
  if [ -n "$tmp" ]; then
    local csrf
    csrf=$(s5_login "$SEC_USER" "$tmp")
    curl -s -b "/tmp/s5-$SEC_USER.txt" -X POST "$API_URL/api/v1/auth/change-password" \
      -H 'Content-Type: application/json' -H "X-CSRF-Token: $csrf" \
      -d "{\"old_password\":\"$tmp\",\"new_password\":\"$SEC_PWD\"}" > /dev/null
  fi
  s5_login "$SEC_USER" "$SEC_PWD"
}

# 确保测试应用存在（默认 OFF 避免 WAF 干扰访问控制测试；可由环境变量覆盖），打印 app_id
s5_ensure_app() {
  local csrf="$1" cookie="/tmp/s5-$SEC_USER.txt"
  local existing
  existing=$(curl -s -b "$cookie" "$API_URL/api/v1/applications?keyword=$APP_CODE" | python3 -c "
import json,sys
items=json.load(sys.stdin)['data']['items'] or []
print(next((i['id'] for i in items if i['code']=='$APP_CODE'),''))" 2>/dev/null)
  if [ -n "$existing" ]; then echo "$existing"; return 0; fi
  local appid
  appid=$(curl -s -b "$cookie" -X POST "$API_URL/api/v1/applications" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $csrf" \
    -d "{\"code\":\"$APP_CODE\",\"name\":\"阶段5测试应用\",\"description\":\"访问控制与CC防护测试\",\"business_owner\":\"test\",\"technical_owner\":\"test\",\"protection_mode\":\"$APP_PROTECTION_MODE\"}" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['id'])" 2>/dev/null)
  # 域名
  curl -s -b "$cookie" -X POST "$API_URL/api/v1/applications/$appid/domains" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $csrf" \
    -d "{\"hostname\":\"$HOST_HEADER\",\"is_primary\":true,\"http_enabled\":true,\"https_enabled\":false,\"http_port\":8080,\"redirect_http_to_https\":false}" > /dev/null
  # 源站
  curl -s -b "$cookie" -X POST "$API_URL/api/v1/applications/$appid/upstreams" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $csrf" \
    -d '{"name":"testorigin","scheme":"http","host":"testorigin","port":8081,"weight":1,"priority":1,"health_check_enabled":false,"health_check_path":"/health","health_check_method":"GET","health_check_interval_seconds":10,"health_check_timeout_seconds":3,"expected_status_codes":"200","connect_timeout_ms":3000,"response_header_timeout_ms":10000,"tls_server_name":"","tls_verify":false}' > /dev/null
  # 启用应用（新建为 DRAFT，发布只含 ACTIVE）
  curl -s -b "$cookie" -X POST "$API_URL/api/v1/applications/$appid/enable" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $csrf" > /dev/null
  echo "$appid"
}

# 发布配置并等待成功；任务因 LOCK_BUSY（与其他发布并发）失败时退避重试
s5_publish() {
  local csrf="$1" cookie="/tmp/s5-$SEC_USER.txt"
  local task attempt code
  for attempt in $(seq 1 8); do
    task=$(curl -s -b "$cookie" -X POST "$API_URL/api/v1/gateway-config/publish" \
      -H 'Content-Type: application/json' -H "X-CSRF-Token: $csrf" \
      -d "{\"idempotency_key\":\"s5-$(date +%s)-$RANDOM\"}" \
      | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['id'])" 2>/dev/null)
    for _ in $(seq 1 30); do
      local st
      st=$(curl -s -b "$cookie" "$API_URL/api/v1/publish-tasks/$task" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['status'])" 2>/dev/null)
      case "$st" in
        SUCCESS) echo "PUBLISH_OK"; return 0;;
        FAILED)
          code=$(curl -s -b "$cookie" "$API_URL/api/v1/publish-tasks/$task" | python3 -c "import json,sys; print(json.load(sys.stdin)['data'].get('failure_code') or '')" 2>/dev/null)
          if [ "$code" = "LOCK_BUSY" ]; then sleep 3; break; fi
          echo "PUBLISH_FAILED"; return 1;;
      esac
      sleep 1
    done
    [ "$st" = "FAILED" ] && [ "$code" = "LOCK_BUSY" ] || { echo "PUBLISH_TIMEOUT"; return 1; }
  done
  echo "PUBLISH_FAILED"; return 1
}

# 发请求到网关（带 Host 头），可选额外 curl 参数
s5_req() {
  local path="$1"; shift
  curl -s -o /dev/null -w "%{http_code}" -H "Host: $HOST_HEADER" "$@" "$GATEWAY_URL$path"
}

# 查访问控制事件数（按类型）
s5_event_count() {
  local type="$1" cookie="/tmp/s5-$SEC_USER.txt"
  curl -s -b "$cookie" "$API_URL/api/v1/access-control-events?event_type=$type&page_size=1" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['total'])" 2>/dev/null || echo 0
}

# 创建规则/策略的通用 POST
s5_post() {
  local path="$1" body="$2" csrf="$3" cookie="/tmp/s5-$SEC_USER.txt"
  curl -s -b "$cookie" -X POST "$API_URL$path" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $csrf" -d "$body"
}

s5_post_code() {
  local path="$1" body="$2" csrf="$3" cookie="/tmp/s5-$SEC_USER.txt"
  curl -s -o /dev/null -w "%{http_code}" -b "$cookie" -X POST "$API_URL$path" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $csrf" -d "$body"
}
