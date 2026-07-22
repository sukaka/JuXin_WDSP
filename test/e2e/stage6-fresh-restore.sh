#!/usr/bin/env bash
# 九章阶段6 全新环境恢复测试：
# 在 stage5 环境创建 FULL 备份并下载 → 全新 compose 项目（全新卷）→ 导入 → 隔离恢复 → 确认 → 逐项验证
# 用法：bash test/e2e/stage6-fresh-restore.sh
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../waf/scripts/stage5-setup.sh"
# 阶段6专用测试账号（避免与其他会话共用的测试账号被重置）
# 源环境（stage5）：s6_sec/s6_sys；恢复环境（全新库）：仅初始管理员 jiuzhang_admin
SEC_USER="${S6_SEC_USER:-s6_sec}"
SEC_PWD="${S6_SEC_PWD:-S6Sec@Test2026!}"
SYS_USER="${S6_SYS_USER:-s6_sys}"
SYS_PWD="${S6_SYS_PWD:-S6Sys@Test2026!}"
# 恢复环境初始管理员（compose 注入 INITIAL_ADMIN_PASSWORD，首登强制改密为 R_SYS_NEW_PWD）
R_SYS_USER="${R_SYS_USER:-jiuzhang_admin}"
R_SYS_PWD="${R_SYS_PWD:-SysAdmin@S5!2026}"
R_SYS_NEW_PWD="${R_SYS_NEW_PWD:-SysAdmin@S5!2026x}"

R_COMPOSE="docker compose --env-file .env -f deployment/docker-compose.restore-test.yml"
R_API="http://127.0.0.1:18091"
R_GATEWAY="http://127.0.0.1:18090"

TOTAL=0; PASS=0; FAIL=0; FAILED=()
record() {
  local name="$1" ok="$2" detail="${3:-}"
  TOTAL=$((TOTAL+1))
  if [ "$ok" = "1" ]; then PASS=$((PASS+1)); echo "PASS  $name"
  else FAIL=$((FAIL+1)); FAILED+=("$name: $detail"); echo "FAIL  $name ($detail)"; fi
}
jid() { python3 -c "
import json,sys
d=json.load(sys.stdin).get('data') or {}
for k in ('id','job','report','check','package'):
    v = d.get(k)
    if isinstance(v, dict) and v.get('id'):
        print(v['id']); break
    elif k == 'id' and isinstance(v, str) and v:
        print(v); break
" 2>/dev/null; }
jst() { python3 -c "
import json,sys
d=json.load(sys.stdin).get('data') or {}
j=d.get('job') or d.get('report') or d
print(j.get('status',''))" 2>/dev/null; }

echo "============================================================"
echo "阶段6 全新环境恢复测试"
echo "============================================================"

echo ""
echo "---- 1. 源环境：创建 FULL 备份并下载 ----"
SYS_CSRF=$(s5_login "$SYS_USER" "$SYS_PWD"); SCK="/tmp/s5-$SYS_USER.txt"
BID=$(curl -s -b "$SCK" -X POST "$API_URL/api/v1/backups" -H 'Content-Type: application/json' -H "X-CSRF-Token: $SYS_CSRF" -d '{"backup_type":"FULL"}' | jid)
[ -n "$BID" ] && record "source-backup-create" 1 || record "source-backup-create" 0
ST=""
for i in $(seq 1 150); do
  ST=$(curl -s -b "$SCK" "$API_URL/api/v1/backups/$BID" | jst)
  case "$ST" in SUCCESS|FAILED) break;; esac
  sleep 2
done
[ "$ST" = "SUCCESS" ] && record "source-backup-success" 1 || record "source-backup-success" 0 "status=$ST"
curl -s -b "$SCK" -o /tmp/s6-restore-full.jzbk "$API_URL/api/v1/backups/$BID/download"
SIZE=$(stat -f%z /tmp/s6-restore-full.jzbk 2>/dev/null || stat -c%s /tmp/s6-restore-full.jzbk)
[ "$SIZE" -gt 10000 ] && record "source-backup-download" 1 "size=$SIZE" || record "source-backup-download" 0 "size=$SIZE"

echo ""
echo "---- 2. 全新环境启动（全新卷） ----"
$R_COMPOSE down -v > /dev/null 2>&1 || true
$R_COMPOSE up -d > /dev/null 2>&1
UP_OK=0
for i in $(seq 1 45); do
  if curl -s -o /dev/null "$R_API/api/v1/health"; then UP_OK=1; break; fi
  # 兜底：容器卡在 Created 时手动启动（当前 Docker 环境的时序问题）
  docker start jiuzhang-rstore-postgres jiuzhang-rstore-valkey > /dev/null 2>&1
  sleep 3
  docker start jiuzhang-rstore-api > /dev/null 2>&1
  sleep 3
done
[ "$UP_OK" = "1" ] && record "fresh-env-up" 1 || record "fresh-env-up" 0

echo ""
echo "---- 3. 全新环境：初始化并导入备份 ----"
# 登录辅助：依次尝试 新密码 → 旧密码（必要时改密后再登）。
# 注意：token 一律取自登录响应，避免 /auth/me 轮换 token 导致先前捕获失效。
r_login() {
  local capid capcode resp tok
  for pwd in "$R_SYS_NEW_PWD" "$R_SYS_PWD"; do
    capid=$(curl -s "$R_API/api/v1/auth/captcha" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['captcha_id'])" 2>/dev/null)
    capcode=$(docker exec jiuzhang-rstore-valkey valkey-cli -a "$VALKEY_PASSWORD" --no-auth-warning GET "jiuzhang:captcha:$capid" 2>/dev/null)
    resp=$(curl -s -c /tmp/s6r-sys.txt -X POST "$R_API/api/v1/auth/login" -H 'Content-Type: application/json' \
      -d "{\"username\":\"$R_SYS_USER\",\"password\":\"$pwd\",\"captcha_id\":\"$capid\",\"captcha_code\":\"$capcode\"}")
    tok=$(echo "$resp" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['csrf_token'])" 2>/dev/null)
    if [ -n "$tok" ]; then
      # 强制改密检测（仅当使用旧密码登录且必须改密时立即改）
      if [ "$pwd" = "$R_SYS_PWD" ] && [ "$(echo "$resp" | python3 -c "import json,sys; print(json.load(sys.stdin)['data'].get('user',{}).get('must_change_password', False))" 2>/dev/null)" = "True" ]; then
        curl -s -b /tmp/s6r-sys.txt -X POST "$R_API/api/v1/auth/change-password" -H 'Content-Type: application/json' -H "X-CSRF-Token: $tok" \
          -d "{\"old_password\":\"$R_SYS_PWD\",\"new_password\":\"$R_SYS_NEW_PWD\"}" > /dev/null
        echo "  [init] 初始管理员已完成首次改密"
        r_login
        return 0
      fi
      echo "$tok"
      return 0
    fi
  done
  echo ""
}
R_CSRF=$(r_login)
[ -n "$R_CSRF" ] && record "fresh-admin-login" 1 || record "fresh-admin-login" 0

# 恢复环境登录辅助（同 r_login，供后续段重登）
rlogin() { r_login; }

IMP=$(curl -s -b /tmp/s6r-sys.txt -X POST "$R_API/api/v1/restores/import" -H "X-CSRF-Token: $(r_login)" -F "file=@/tmp/s6-restore-full.jzbk")
IBID=$(echo "$IMP" | jid)
[ -n "$IBID" ] && record "import-backup" 1 || record "import-backup" 0 "$IMP"

echo ""
echo "---- 4. 隔离恢复 + 确认 ----"
R_CSRF=$(rlogin)
R2=$(curl -s -b /tmp/s6r-sys.txt -X POST "$R_API/api/v1/restores/validate" -H 'Content-Type: application/json' -H "X-CSRF-Token: $R_CSRF" -d "{\"backup_job_id\":\"$IBID\"}")
echo "$R2" | python3 -c "import json,sys; sys.exit(0 if json.load(sys.stdin)['code']=='SUCCESS' else 1)" && record "fresh-validate" 1 || record "fresh-validate" 0 "$R2"
RSID=$(curl -s -b /tmp/s6r-sys.txt -X POST "$R_API/api/v1/restores" -H 'Content-Type: application/json' -H "X-CSRF-Token: $R_CSRF" -d "{\"backup_job_id\":\"$IBID\",\"scope\":\"FULL\"}" | jid)
ST=""
for i in $(seq 1 150); do
  ST=$(curl -s -b /tmp/s6r-sys.txt "$R_API/api/v1/restores/$RSID" | jst)
  case "$ST" in AWAITING_CONFIRM|FAILED) break;; esac
  sleep 2
done
[ "$ST" = "AWAITING_CONFIRM" ] && record "fresh-isolated" 1 || record "fresh-isolated" 0 "status=$ST"
curl -s -b /tmp/s6r-sys.txt -X POST "$R_API/api/v1/restores/$RSID/confirm" -H 'Content-Type: application/json' -H "X-CSRF-Token: $R_CSRF" -d '{}' > /dev/null
ST=""
for i in $(seq 1 150); do
  ST=$(curl -s -b /tmp/s6r-sys.txt "$R_API/api/v1/restores/$RSID" | jst)
  case "$ST" in SUCCESS|FAILED) break;; esac
  sleep 2
done
[ "$ST" = "SUCCESS" ] && record "fresh-restore-success" 1 || record "fresh-restore-success" 0 "status=$ST"

echo ""
echo "---- 5. 恢复后验证 ----"
# 5.1 原安全管理员可登录（密码与源环境一致）
capid=$(curl -s "$R_API/api/v1/auth/captcha" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['captcha_id'])" 2>/dev/null)
capcode=$(docker exec jiuzhang-rstore-valkey valkey-cli -a "$VALKEY_PASSWORD" --no-auth-warning GET "jiuzhang:captcha:$capid" 2>/dev/null)
curl -s -c /tmp/s6r-sec.txt -X POST "$R_API/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$SEC_USER\",\"password\":\"$SEC_PWD\",\"captcha_id\":\"$capid\",\"captcha_code\":\"$capcode\"}" | grep -q SUCCESS \
  && record "restored-user-login" 1 || record "restored-user-login" 0
RS_CSRF=$(curl -s -b /tmp/s6r-sec.txt "$R_API/api/v1/auth/me" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['csrf_token'])" 2>/dev/null)
# 5.2 应用存在且发布可工作
APPS=$(curl -s -b /tmp/s6r-sec.txt "$R_API/api/v1/applications?page_size=10" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['total'])" 2>/dev/null)
[ "${APPS:-0}" -ge 1 ] && record "restored-apps" 1 || record "restored-apps" 0 "total=$APPS"
# 5.3 三权权限（系统管理员可见用户管理）
UC=$(curl -s -b /tmp/s6r-sys.txt "$R_API/api/v1/users?page_size=5" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['total'])" 2>/dev/null)
[ "${UC:-0}" -ge 2 ] && record "restored-rbac" 1 || record "restored-rbac" 0 "users=$UC"
# 5.4 审计记录存在（审计管理员查询；审计归档按设计不写回，恢复后新增审计计数≥1 即证明审计链路正常）
capid=$(curl -s "$R_API/api/v1/auth/captcha" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['captcha_id'])" 2>/dev/null)
capcode=$(docker exec jiuzhang-rstore-valkey valkey-cli -a "$VALKEY_PASSWORD" --no-auth-warning GET "jiuzhang:captcha:$capid" 2>/dev/null)
AUD_PWD="${S6_AUD_PWD:-S6Aud@Test2026!}"
curl -s -c /tmp/s6r-aud.txt -X POST "$R_API/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"s6_aud\",\"password\":\"$AUD_PWD\",\"captcha_id\":\"$capid\",\"captcha_code\":\"$capcode\"}" > /dev/null
AU=$(curl -s -b /tmp/s6r-aud.txt "$R_API/api/v1/audits?page_size=1" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['total'])" 2>/dev/null)
[ "${AU:-0}" -ge 1 ] && record "restored-audits" 1 || record "restored-audits" 0 "total=$AU"
# 5.5 策略与规则存在
POL=$(curl -s -b /tmp/s6r-sec.txt "$R_API/api/v1/protection-policies?page_size=1" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['total'])" 2>/dev/null)
[ "${POL:-0}" -ge 3 ] && record "restored-policies" 1 || record "restored-policies" 0 "total=$POL"
# 5.6 配置类规则已恢复（访问控制规则在备份范围内；事件表不属于备份数据，不验证）
RL=$(curl -s -b /tmp/s6r-sec.txt "$R_API/api/v1/access-rules?page_size=1" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['total'])" 2>/dev/null)
[ "${RL:-0}" -ge 1 ] && record "restored-access-rules" 1 || record "restored-access-rules" 0 "total=$RL"
# 5.7 发布可用（应用+guard 配置可重新发布）
PUB=$(curl -s -b /tmp/s6r-sec.txt -X POST "$R_API/api/v1/gateway-config/publish" -H 'Content-Type: application/json' -H "X-CSRF-Token: $RS_CSRF" -d "{\"idempotency_key\":\"s6r-$(date +%s)\"}" | jid)
ST=""
for i in $(seq 1 30); do
  ST=$(curl -s -b /tmp/s6r-sec.txt "$R_API/api/v1/publish-tasks/$PUB" | jst)
  case "$ST" in SUCCESS|FAILED) break;; esac
  sleep 1
done
[ "$ST" = "SUCCESS" ] && record "restored-publish" 1 || record "restored-publish" 0 "status=$ST"
# 5.8 网关流量可用
sleep 2
st=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $HOST_HEADER" "$R_GATEWAY/echo")
[ "$st" = "200" ] && record "restored-gateway-traffic" 1 || record "restored-gateway-traffic" 0 "status=$st"

echo ""
echo "---- 6. 清理全新环境 ----"
$R_COMPOSE down -v > /dev/null 2>&1
record "cleanup" 1

echo ""
echo "============================================================"
echo "全新环境恢复测试汇总: 总用例 $TOTAL 通过 $PASS 失败 $FAIL"
if [ "$FAIL" -gt 0 ]; then
  for c in "${FAILED[@]}"; do echo "  - $c"; done
fi
echo "============================================================"
[ "$FAIL" -eq 0 ]
