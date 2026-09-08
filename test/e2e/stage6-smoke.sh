#!/usr/bin/env bash
# 九章阶段6 真实环境冒烟：态势/统计/报告/备份/恢复/升级/交付检查 端到端验证
# 依赖 stage5 编排（api:18081, gateway:18080）
# 用法：bash test/e2e/stage6-smoke.sh
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
# 解包 data.id / data.job.id / data.report.id
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
# 各段操作前重新登录（并发环境下会话可能被其他会话挤掉）
sec() { SEC_CSRF=$(s5_login "$SEC_USER" "$SEC_PWD"); CK="/tmp/s5-$SEC_USER.txt"; }
sys() { SYS_CSRF=$(s5_login "$SYS_USER" "$SYS_PWD"); SCK="/tmp/s5-$SYS_USER.txt"; }

echo "============================================================"
echo "九章阶段6 真实环境冒烟  api=$API_URL"
echo "============================================================"

s5_ensure_sysadmin > /dev/null || exit 1
SEC_CSRF=$(s5_ensure_secuser "$(s5_login "$SYS_USER" "$SYS_PWD")")
[ -z "$SEC_CSRF" ] && { echo "ERROR: sec login failed"; exit 1; }
CK="/tmp/s5-$SEC_USER.txt"
APP_ID=$(s5_ensure_app "$SEC_CSRF")

echo ""
echo "---- 0. 发布配置（含访问日志）并产生流量 ----"
sec; [ "$(s5_publish "$SEC_CSRF")" = "PUBLISH_OK" ] && record "publish" 1 || record "publish" 0
for i in $(seq 1 30); do s5_req /echo > /dev/null; done
sleep 70

echo ""
echo "---- 1. 态势与统计 ----"
sec
R=$(curl -s -b "$CK" "$API_URL/api/v1/dashboard/security-overview")
REQ=$(echo "$R" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['today']['requests_total'])" 2>/dev/null)
[ "${REQ:-0}" -ge 1 ] && record "overview-requests-real" 1 || record "overview-requests-real" 0 "requests=$REQ"
echo "$R" | python3 -c "import json,sys; d=json.load(sys.stdin)['data']; sys.exit(0 if ('trends' in d and 'top' in d) else 1)" && record "overview-structure" 1 || record "overview-structure" 0
R=$(curl -s -b "$CK" "$API_URL/api/v1/analytics/request-trend")
echo "$R" | python3 -c "import json,sys; sys.exit(0 if len(json.load(sys.stdin)['data']['times'])>0 else 1)" && record "analytics-request-trend" 1 || record "analytics-request-trend" 0
R=$(curl -s -b "$CK" "$API_URL/api/v1/analytics/attack-types")
echo "$R" | python3 -c "import json,sys; sys.exit(0 if 'items' in json.load(sys.stdin)['data'] else 1)" && record "analytics-attack-types" 1 || record "analytics-attack-types" 0
sys
R=$(curl -s -b "$SCK" "$API_URL/api/v1/dashboard/runtime-overview")
echo "$R" | python3 -c "import json,sys; sys.exit(0 if len(json.load(sys.stdin)['data']['components'])>=5 else 1)" && record "runtime-components" 1 || record "runtime-components" 0
R=$(curl -s -b "$SCK" "$API_URL/api/v1/system-health")
echo "$R" | python3 -c "import json,sys; s=json.load(sys.stdin)['data']['status'].upper(); sys.exit(0 if s in ('UP','DEGRADED') else 1)" && record "system-health" 1 || record "system-health" 0
R=$(curl -s -b "$SCK" "$API_URL/api/v1/system-health/storage")
echo "$R" | python3 -c "import json,sys; sys.exit(0 if json.load(sys.stdin)['data'].get('postgres_size_bytes',0)>0 else 1)" && record "system-storage" 1 || record "system-storage" 0

echo ""
echo "---- 2. 报告（HTML + PDF） ----"
sec
T_START=$(date -u -v-30d +%Y-%m-%dT%H:%M:%SZ)
T_END=$(date -u +%Y-%m-%dT%H:%M:%SZ)
RID=$(curl -s -b "$CK" -X POST "$API_URL/api/v1/reports" -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" \
  -d "{\"report_type\":\"CUSTOM\",\"start_time\":\"$T_START\",\"end_time\":\"$T_END\",\"format\":\"html\"}" | jid)
[ -n "$RID" ] && record "report-create-html" 1 || record "report-create-html" 0
ST=""
for i in $(seq 1 60); do
  ST=$(curl -s -b "$CK" "$API_URL/api/v1/reports/$RID" | jst)
  case "$ST" in SUCCESS|FAILED) break;; esac
  sleep 2
done
[ "$ST" = "SUCCESS" ] && record "report-html-success" 1 || record "report-html-success" 0 "status=$ST"
PREV=$(curl -s -b "$CK" "$API_URL/api/v1/reports/$RID/preview")
echo "$PREV" | grep -q "九章" && record "report-html-preview" 1 || record "report-html-preview" 0
HASH=$(curl -s -b "$CK" "$API_URL/api/v1/reports/$RID" | python3 -c "import json,sys; d=json.load(sys.stdin)['data']; j=d.get('job') or d.get('report') or d; print(j.get('file_hash',''))" 2>/dev/null)
[ "${#HASH}" = "64" ] && record "report-hash" 1 || record "report-hash" 0 "hash=$HASH"
PID=$(curl -s -b "$CK" -X POST "$API_URL/api/v1/reports" -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" \
  -d "{\"report_type\":\"CUSTOM\",\"start_time\":\"$T_START\",\"end_time\":\"$T_END\",\"format\":\"pdf\"}" | jid)
ST=""
for i in $(seq 1 90); do
  ST=$(curl -s -b "$CK" "$API_URL/api/v1/reports/$PID" | jst)
  case "$ST" in SUCCESS|FAILED) break;; esac
  sleep 2
done
[ "$ST" = "SUCCESS" ] && record "report-pdf-success" 1 || record "report-pdf-success" 0 "status=$ST"
curl -s -b "$CK" -o /tmp/s6-report.pdf "$API_URL/api/v1/reports/$PID/download"
MAGIC=$(head -c 5 /tmp/s6-report.pdf)
[ "$MAGIC" = "%PDF-" ] && record "report-pdf-download" 1 || record "report-pdf-download" 0 "magic=$MAGIC"
DID=$(curl -s -b "$CK" -X POST "$API_URL/api/v1/reports" -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" \
  -d "{\"report_type\":\"CUSTOM\",\"start_time\":\"$T_START\",\"end_time\":\"$T_END\",\"format\":\"docx\"}" | jid)
ST=""
for i in $(seq 1 90); do
  ST=$(curl -s -b "$CK" "$API_URL/api/v1/reports/$DID" | jst)
  case "$ST" in SUCCESS|FAILED) break;; esac
  sleep 2
done
[ "$ST" = "SUCCESS" ] && record "report-docx-success" 1 || record "report-docx-success" 0 "status=$ST"
curl -s -b "$CK" -o /tmp/s6-report.docx "$API_URL/api/v1/reports/$DID/download"
MAGIC=$(head -c 2 /tmp/s6-report.docx)
[ "$MAGIC" = "PK" ] && record "report-docx-download" 1 || record "report-docx-download" 0 "magic=$MAGIC"
sys
ST=$(curl -s -o /dev/null -w "%{http_code}" -b "$SCK" "$API_URL/api/v1/reports/$RID/download")
[ "$ST" = "403" ] && record "report-download-rbac" 1 || record "report-download-rbac" 0 "status=$ST"

echo ""
echo "---- 3. 系统告警 ----"
sec
R=$(curl -s -b "$CK" "$API_URL/api/v1/system-alerts?page_size=5")
echo "$R" | python3 -c "import json,sys; sys.exit(0 if 'total' in json.load(sys.stdin)['data'] else 1)" && record "alerts-list" 1 || record "alerts-list" 0

echo ""
echo "---- 4. 备份（FULL）与验证 ----"
sys
BID=$(curl -s -b "$SCK" -X POST "$API_URL/api/v1/backups" -H 'Content-Type: application/json' -H "X-CSRF-Token: $SYS_CSRF" -d '{"backup_type":"FULL"}' | jid)
[ -n "$BID" ] && record "backup-create" 1 || record "backup-create" 0
ST=""
for i in $(seq 1 150); do
  ST=$(curl -s -b "$SCK" "$API_URL/api/v1/backups/$BID" | jst)
  case "$ST" in SUCCESS|FAILED) break;; esac
  sleep 2
done
[ "$ST" = "SUCCESS" ] && record "backup-success" 1 || record "backup-success" 0 "status=$ST"
BHASH=$(curl -s -b "$SCK" "$API_URL/api/v1/backups/$BID" | python3 -c "import json,sys; d=json.load(sys.stdin)['data']; j=d.get('job') or d; print(j.get('file_hash',''))" 2>/dev/null)
[ "${#BHASH}" = "64" ] && record "backup-hash" 1 || record "backup-hash" 0
R=$(curl -s -b "$SCK" -X POST "$API_URL/api/v1/backups/$BID/verify" -H "X-CSRF-Token: $SYS_CSRF")
echo "$R" | python3 -c "import json,sys; sys.exit(0 if json.load(sys.stdin)['code']=='SUCCESS' else 1)" && record "backup-verify" 1 || record "backup-verify" 0 "$R"

echo ""
echo "---- 5. 恢复（隔离恢复 + 预览） ----"
sys
R=$(curl -s -b "$SCK" -X POST "$API_URL/api/v1/restores/validate" -H 'Content-Type: application/json' -H "X-CSRF-Token: $SYS_CSRF" -d "{\"backup_job_id\":\"$BID\"}")
echo "$R" | python3 -c "import json,sys; sys.exit(0 if json.load(sys.stdin)['code']=='SUCCESS' else 1)" && record "restore-validate" 1 || record "restore-validate" 0 "$R"
RSID=$(curl -s -b "$SCK" -X POST "$API_URL/api/v1/restores" -H 'Content-Type: application/json' -H "X-CSRF-Token: $SYS_CSRF" -d "{\"backup_job_id\":\"$BID\",\"scope\":\"CONFIG\"}" | jid)
ST=""
for i in $(seq 1 150); do
  ST=$(curl -s -b "$SCK" "$API_URL/api/v1/restores/$RSID" | jst)
  case "$ST" in AWAITING_CONFIRM|FAILED|SUCCESS) break;; esac
  sleep 2
done
[ "$ST" = "AWAITING_CONFIRM" ] && record "restore-isolated-preview" 1 || record "restore-isolated-preview" 0 "status=$ST"
curl -s -b "$SCK" -X POST "$API_URL/api/v1/restores/$RSID/cancel" -H 'Content-Type: application/json' -H "X-CSRF-Token: $SYS_CSRF" -d '{}' > /dev/null
sleep 2
ST=$(curl -s -b "$SCK" "$API_URL/api/v1/restores/$RSID" | jst)
[ "$ST" = "CANCELLED" ] && record "restore-cancel" 1 || record "restore-cancel" 0 "status=$ST"

echo ""
echo "---- 6. 升级包与预检 ----"
sys
FHASH=$(python3 -c "import hashlib; print(hashlib.sha256(b'stage6-test-package').hexdigest())")
UPID=$(curl -s -b "$SCK" -X POST "$API_URL/api/v1/upgrades/packages" -H 'Content-Type: application/json' -H "X-CSRF-Token: $SYS_CSRF" \
  -d "{\"file_name\":\"jiuzhang-2.0.1.tar.gz\",\"version_from\":\"2.0.0\",\"version_to\":\"2.0.1\",\"file_hash\":\"$FHASH\",\"file_size\":1024}" | jid)
[ -n "$UPID" ] && record "upgrade-package-register" 1 || record "upgrade-package-register" 0
R=$(curl -s -b "$SCK" -X POST "$API_URL/api/v1/upgrades/precheck" -H 'Content-Type: application/json' -H "X-CSRF-Token: $SYS_CSRF" -d "{\"package_id\":\"$UPID\"}")
echo "$R" | python3 -c "import json,sys; sys.exit(0 if json.load(sys.stdin)['code']=='SUCCESS' else 1)" && record "upgrade-precheck" 1 || record "upgrade-precheck" 0 "$R"

echo ""
echo "---- 7. 交付检查 ----"
sys
DCID=$(curl -s -b "$SCK" -X POST "$API_URL/api/v1/delivery-checks/run" -H "X-CSRF-Token: $SYS_CSRF" | jid)
[ -n "$DCID" ] && record "delivery-run" 1 || record "delivery-run" 0
sleep 8
R=$(curl -s -b "$SCK" "$API_URL/api/v1/delivery-checks/$DCID")
DCALL=$(echo "$R" | python3 -c "import json,sys; print(json.load(sys.stdin)['data'].get('overall_result',''))" 2>/dev/null)
echo "[info] delivery: overall=$DCALL"
[ -n "$DCALL" ] && record "delivery-result" 1 || record "delivery-result" 0
echo "$R" | python3 -c "
import json,sys
d=json.load(sys.stdin)['data']
for it in d.get('results') or []:
    if it.get('result') in ('FAIL','WARNING'): print(' ', it['result'], it.get('item_key'), '-', (it.get('message') or '')[:100])
" 2>/dev/null

echo ""
echo "============================================================"
echo "阶段6冒烟汇总: 总用例 $TOTAL 通过 $PASS 失败 $FAIL"
if [ "$FAIL" -gt 0 ]; then
  for c in "${FAILED[@]}"; do echo "  - $c"; done
fi
echo "============================================================"
[ "$FAIL" -eq 0 ]
