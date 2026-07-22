#!/usr/bin/env bash
# 九章阶段6 安全测试：统计越权、报告/备份路径安全、模板XSS、篡改拒绝、恢复防护、升级越权、调试面
# 依赖 stage5 环境。用法：bash test/security/stage6-security-tests.sh
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../waf/scripts/stage5-setup.sh"
# 阶段6专用测试账号（避免与其他会话共用的测试账号被重置）
SEC_USER="${S6_SEC_USER:-s6_sec}"
SEC_PWD="${S6_SEC_PWD:-S6Sec@Test2026!}"
SYS_USER="${S6_SYS_USER:-s6_sys}"
SYS_PWD="${S6_SYS_PWD:-S6Sys@Test2026!}"

TOTAL=0; PASS=0; FAIL=0; FAILED=()
record() {
  local name="$1" ok="$2" detail="${3:-}"
  TOTAL=$((TOTAL+1))
  if [ "$ok" = "1" ]; then PASS=$((PASS+1)); echo "PASS  $name"
  else FAIL=$((FAIL+1)); FAILED+=("$name: $detail"); echo "FAIL  $name ($detail)"; fi
}

echo "============================================================"
echo "九章阶段6 安全测试"
echo "============================================================"

SEC_CSRF=$(s5_login "$SEC_USER" "$SEC_PWD"); CK="/tmp/s5-$SEC_USER.txt"
SYS_CSRF=$(s5_login "$SYS_USER" "$SYS_PWD"); SCK="/tmp/s5-$SYS_USER.txt"

echo ""
echo "---- 1. 统计/报告越权 ----"
st=$(curl -s -o /dev/null -w "%{http_code}" -b "$CK" "$API_URL/api/v1/system-health")
[ "$st" = "403" ] && record "rbac-health-sec-403" 1 || record "rbac-health-sec-403" 0 "status=$st"
st=$(curl -s -o /dev/null -w "%{http_code}" -b "$SCK" "$API_URL/api/v1/dashboard/security-overview")
[ "$st" = "403" ] && record "rbac-overview-sys-403" 1 || record "rbac-overview-sys-403" 0 "status=$st"
st=$(curl -s -o /dev/null -w "%{http_code}" -b "$SCK" "$API_URL/api/v1/reports")
[ "$st" = "403" ] && record "rbac-reports-sys-403" 1 || record "rbac-reports-sys-403" 0 "status=$st"
st=$(curl -s -o /dev/null -w "%{http_code}" -b "$CK" -X POST "$API_URL/api/v1/backups" -H "X-CSRF-Token: $SEC_CSRF" -H 'Content-Type: application/json' -d '{"backup_type":"FULL"}')
[ "$st" = "403" ] && record "rbac-backup-sec-403" 1 || record "rbac-backup-sec-403" 0 "status=$st"
st=$(curl -s -o /dev/null -w "%{http_code}" -b "$CK" -X POST "$API_URL/api/v1/upgrades" -H "X-CSRF-Token: $SEC_CSRF" -H 'Content-Type: application/json' -d '{"package_id":"00000000-0000-0000-0000-000000000000"}')
[ "$st" = "403" ] && record "rbac-upgrade-sec-403" 1 || record "rbac-upgrade-sec-403" 0 "status=$st"
# 未认证访问
st=$(curl -s -o /dev/null -w "%{http_code}" "$API_URL/api/v1/dashboard/security-overview")
[ "$st" = "401" ] && record "unauth-overview-401" 1 || record "unauth-overview-401" 0 "status=$st"

echo ""
echo "---- 2. 报告安全 ----"
# 创建一个含 XSS 名称的模板 → 报告渲染转义（模板字段纯数据）
XSS='<script>alert(1)</script>'
TPL=$(curl -s -b "$CK" -X POST "$API_URL/api/v1/report-templates" -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" \
  -d "{\"name\":\"xss-tpl\",\"company_name\":\"$XSS\"}" | python3 -c "import json,sys; d=json.load(sys.stdin)['data']; print(d.get('template',{}).get('id',''))" 2>/dev/null)
T_START=$(date -u -v-1d +%Y-%m-%dT%H:%M:%SZ)
RID=$(curl -s -b "$CK" -X POST "$API_URL/api/v1/reports" -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" \
  -d "{\"report_type\":\"CUSTOM\",\"start_time\":\"$T_START\",\"end_time\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"template_id\":\"$TPL\",\"format\":\"html\"}" | python3 -c "import json,sys; d=json.load(sys.stdin)['data']; print(d.get('id') or d.get('report',{}).get('id',''))" 2>/dev/null)
ST=""
for i in $(seq 1 60); do
  ST=$(curl -s -b "$CK" "$API_URL/api/v1/reports/$RID" | python3 -c "import json,sys; d=json.load(sys.stdin)['data']; j=d.get('job') or d.get('report') or d; print(j.get('status',''))" 2>/dev/null)
  case "$ST" in SUCCESS|FAILED) break;; esac
  sleep 2
done
PREV=$(curl -s -b "$CK" "$API_URL/api/v1/reports/$RID/preview")
echo "$PREV" | grep -q "<script>alert(1)</script>" && record "report-template-xss" 0 "unescaped" || record "report-template-xss" 1
# 无外部资源引用
echo "$PREV" | grep -qiE "https?://[^\"' ]*(cdn|google|cloudflare)" && record "report-no-external-res" 0 "external ref" || record "report-no-external-res" 1
# 跨用户下载（他人报告不可见不可下）
AUD=$(curl -s -b "/tmp/s5-$SYS_USER.txt" -X POST "$API_URL/api/v1/users" -H 'Content-Type: application/json' -H "X-CSRF-Token: $SYS_CSRF" \
  -d '{"username":"s6_sec_other","display_name":"其他安全管理员","role_code":"SECURITY_ADMIN"}' | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('data',{}).get('temporary_password',''))" 2>/dev/null)
if [ -z "$AUD" ]; then
  # 已存在：重置密码
  OUID=$(docker exec jiuzhang-stage5-postgres psql -U jiuzhang -d jiuzhang_waf -tAc "SELECT id FROM users WHERE username='s6_sec_other'")
  AUD=$(curl -s -b "/tmp/s5-$SYS_USER.txt" -X POST "$API_URL/api/v1/users/$OUID/reset-password" -H 'Content-Type: application/json' -H "X-CSRF-Token: $SYS_CSRF" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('data',{}).get('temporary_password',''))" 2>/dev/null)
fi
O_CSRF=$(s5_login s6_sec_other "$AUD")
curl -s -b /tmp/s5-s6_sec_other.txt -X POST "$API_URL/api/v1/auth/change-password" -H 'Content-Type: application/json' -H "X-CSRF-Token: $O_CSRF" \
  -d "{\"old_password\":$(python3 -c "import json,sys; print(json.dumps(sys.argv[1]))" "$AUD"),\"new_password\":\"SecOther@S6!2026\"}" > /dev/null
O_CSRF=$(s5_login s6_sec_other 'SecOther@S6!2026')
st=$(curl -s -o /dev/null -w "%{http_code}" -b /tmp/s5-s6_sec_other.txt "$API_URL/api/v1/reports/$RID/download")
[ "$st" = "403" ] || [ "$st" = "404" ] && record "report-cross-user-download" 1 || record "report-cross-user-download" 0 "status=$st"
# 路径穿越（ID 注入 ../）
st=$(curl -s -o /dev/null -w "%{http_code}" -b "$CK" "$API_URL/api/v1/reports/..%2F..%2Fetc%2Fpasswd/download")
[ "$st" = "400" ] || [ "$st" = "404" ] && record "report-path-traversal" 1 || record "report-path-traversal" 0 "status=$st"

echo ""
echo "---- 3. 备份与恢复安全 ----"
# 备份下载防路径穿越
st=$(curl -s -o /dev/null -w "%{http_code}" -b "$SCK" "$API_URL/api/v1/backups/..%2F..%2Fetc%2Fpasswd/download")
[ "$st" = "400" ] || [ "$st" = "404" ] && record "backup-path-traversal" 1 || record "backup-path-traversal" 0 "status=$st"
# 篡改备份导入拒绝（加密文件改一字节）
BID=$(curl -s -b "$SCK" -X POST "$API_URL/api/v1/backups" -H 'Content-Type: application/json' -H "X-CSRF-Token: $SYS_CSRF" -d '{"backup_type":"CONFIG_ONLY"}' | python3 -c "import json,sys; d=json.load(sys.stdin)['data']; print(d.get('job',{}).get('id',''))" 2>/dev/null)
ST=""
for i in $(seq 1 90); do
  ST=$(curl -s -b "$SCK" "$API_URL/api/v1/backups/$BID" | python3 -c "import json,sys; d=json.load(sys.stdin)['data']; j=d.get('job') or d; print(j.get('status',''))" 2>/dev/null)
  case "$ST" in SUCCESS|FAILED) break;; esac
  sleep 2
done
curl -s -b "$SCK" -o /tmp/s6-sec-backup.jzbk "$API_URL/api/v1/backups/$BID/download"
python3 -c "
data = bytearray(open('/tmp/s6-sec-backup.jzbk','rb').read())
data[200] ^= 0xff
open('/tmp/s6-sec-tampered.jzbk','wb').write(bytes(data))"
st=$(curl -s -o /dev/null -w "%{http_code}" -b "$SCK" -X POST "$API_URL/api/v1/restores/import" -H "X-CSRF-Token: $SYS_CSRF" -F "file=@/tmp/s6-sec-tampered.jzbk")
[ "$st" = "400" ] && record "restore-tampered-rejected" 1 || record "restore-tampered-rejected" 0 "status=$st"
# 恢复必须经确认（create 后不确认不覆盖生产：users 数不变）
UB=$(docker exec jiuzhang-stage5-postgres psql -U jiuzhang -d jiuzhang_waf -tAc "SELECT count(*) FROM users")
RSID=$(curl -s -b "$SCK" -X POST "$API_URL/api/v1/restores" -H 'Content-Type: application/json' -H "X-CSRF-Token: $SYS_CSRF" -d "{\"backup_job_id\":\"$BID\",\"scope\":\"CONFIG\"}" | python3 -c "import json,sys; d=json.load(sys.stdin)['data']; print(d.get('job',{}).get('id',''))" 2>/dev/null)
ST=""
for i in $(seq 1 90); do
  ST=$(curl -s -b "$SCK" "$API_URL/api/v1/restores/$RSID" | python3 -c "import json,sys; d=json.load(sys.stdin)['data']; j=d.get('job') or d; print(j.get('status',''))" 2>/dev/null)
  case "$ST" in AWAITING_CONFIRM|FAILED) break;; esac
  sleep 2
done
UA=$(docker exec jiuzhang-stage5-postgres psql -U jiuzhang -d jiuzhang_waf -tAc "SELECT count(*) FROM users")
[ "$UB" = "$UA" ] && [ "$ST" = "AWAITING_CONFIRM" ] && record "restore-no-overwrite-without-confirm" 1 || record "restore-no-overwrite-without-confirm" 0 "users $UB->$UA status=$ST"
curl -s -b "$SCK" -X POST "$API_URL/api/v1/restores/$RSID/cancel" -H "X-CSRF-Token: $SYS_CSRF" -d '{}' > /dev/null

echo ""
echo "---- 4. 升级与调试面 ----"
# 升级包篡改（哈希与内容不符的登记可以，但执行时哈希校验）
# 预检越权（审计管理员）
A_CSRF=$(s5_login audit_s5_sec 'AuditS5@Sec2026!')
st=$(curl -s -o /dev/null -w "%{http_code}" -b /tmp/s5-audit_s5_sec.txt -X POST "$API_URL/api/v1/upgrades" -H 'Content-Type: application/json' -H "X-CSRF-Token: $A_CSRF" -d '{"package_id":"00000000-0000-0000-0000-000000000000"}')
[ "$st" = "403" ] && record "upgrade-audit-403" 1 || record "upgrade-audit-403" 0 "status=$st"
# 调试接口未暴露
st=$(curl -s -o /dev/null -w "%{http_code}" "$API_URL/debug/pprof/")
[ "$st" = "404" ] || [ "$st" = "401" ] && record "no-debug-pprof" 1 || record "no-debug-pprof" 0 "status=$st"
# 环境变量敏感值不经 API 泄露（健康接口不含密码/密钥明文）
BODY=$(curl -s "$API_URL/api/v1/health")
echo "$BODY" | grep -qiE "password|secret|master_key|CHANGE_ME" && record "health-no-secrets" 0 "$BODY" || record "health-no-secrets" 1
# Caddy Admin 未暴露 TCP
st=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "http://127.0.0.1:2019/config/" 2>/dev/null)
[ "$st" = "000" ] && record "caddy-admin-no-tcp" 1 || record "caddy-admin-no-tcp" 0 "status=$st"
# 错误响应不泄露堆栈
BODY=$(curl -s -b "$CK" -X POST "$API_URL/api/v1/reports" -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" -d '{invalid')
echo "$BODY" | grep -qiE "goroutine|panic|/go/src|/app/" && record "error-no-stack" 0 "leaks" || record "error-no-stack" 1

echo ""
echo "============================================================"
echo "阶段6安全测试汇总: 总用例 $TOTAL 通过 $PASS 失败 $FAIL"
if [ "$FAIL" -gt 0 ]; then
  for c in "${FAILED[@]}"; do echo "  - $c"; done
fi
echo "============================================================"
[ "$FAIL" -eq 0 ]
