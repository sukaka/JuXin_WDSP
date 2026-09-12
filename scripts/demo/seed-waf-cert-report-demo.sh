#!/usr/bin/env bash
# 九章 WDSP 演示环境造数：WAF规则同步 / 证书 / 报表体系（模板/调度/报告/归档） / 站点发现
# 域负责人：WAF规则·证书·报表·站点发现域
#
# 用法：bash scripts/demo/seed-waf-cert-report-demo.sh
# 幂等：
#   - waf-rules 走 POST /api/v1/waf-rules/sync（天然幂等）
#   - 证书/模板/报告 走真实 API，按名称/标记（demo 模板）查重后补差
#   - 调度/归档/站点发现 走 SQL：确定性 uuid5 + ON CONFLICT DO NOTHING
# 数据安全：IP 仅用 RFC 5737 保留网段，域名仅 example.com 系，姓名全部虚构。
# 已知绕过：POST /api/v1/report-schedules 当前构建存在 SQL bug
#   （ERROR: INSERT has more target columns than expressions），调度只能 SQL 造数。
set -u
cd "$(dirname "$0")/../.."
# shellcheck source=../../test/waf/scripts/stage5-setup.sh
source test/waf/scripts/stage5-setup.sh

PG_CONTAINER="${PG_CONTAINER:-jiuzhang-stage5-postgres}"
PG() { docker exec "$PG_CONTAINER" psql -U jiuzhang -d jiuzhang_waf "$@"; }
# stdin 管道/heredoc 必须加 -i，否则 docker exec 不透传标准输入
PGI() { docker exec -i "$PG_CONTAINER" psql -U jiuzhang -d jiuzhang_waf "$@"; }

NS_PREFIX="jz-demo-wcr"
COOKIE="/tmp/s5-sec_admin_s5.txt"

# 演示应用
APP_SHOP="27464510-39d4-40e3-8a6f-4ccd82f2d810"   # shop-mall  shop.example.com
APP_UC="4888998e-dc35-432b-be85-fc850264d080"     # user-center uc.example.com
APP_OPEN="31f65aed-0cd6-423e-a5aa-119c1273686f"   # open-gw    open.example.com
APP_S5="a6a12f86-2e09-4fcb-b18f-298124a7c827"     # s5app      waf-s5.local

echo "============================================================"
echo "演示造数：WAF规则/证书/报表/站点发现  api=$API_URL db=$PG_CONTAINER"
echo "============================================================"

SYS_CSRF=$(s5_ensure_sysadmin) || exit 1
SEC_CSRF=$(s5_ensure_secuser "$SYS_CSRF") || exit 1
[ -n "$SEC_CSRF" ] || { echo "ERROR: sec login failed"; exit 1; }

# API POST（失败时重新登录重试一次；CSRF 被 /auth/me 轮换，本脚本不调用 /auth/me）
# 注意：仅对会话类错误（CSRF_INVALID/UNAUTHORIZED）重试，参数类错误直接返回，避免登录风暴
api_post() {
  local path="$1" payload="$2" out
  out=$(curl -s -b "$COOKIE" -X POST "$API_URL$path" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" -d "$payload")
  if echo "$out" | grep -qE 'CSRF_INVALID|UNAUTHORIZED|SESSION_EXPIRED|NOT_LOGGED_IN'; then
    sleep 1
    SEC_CSRF=$(s5_login "$SEC_USER" "$SEC_PWD")
    [ -n "$SEC_CSRF" ] || { echo "$out"; return 0; }
    out=$(curl -s -b "$COOKIE" -X POST "$API_URL$path" \
      -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" -d "$payload")
  fi
  echo "$out"
}

name_exists() { # $1=table $2=name
  [ "$(PG -t -A -c "SELECT count(*) FROM $1 WHERE name='$2' AND deleted_at IS NULL;")" != "0" ]
}

# ---------------------------------------------------------------
echo "== [1/6] WAF 规则同步（CRS 真实同步） =="
SYNC_OUT=$(curl -s -b "$COOKIE" -X POST "$API_URL/api/v1/waf-rules/sync" -H "X-CSRF-Token: $SEC_CSRF")
echo "$SYNC_OUT" | grep -q '"code":"SUCCESS"' || { SEC_CSRF=$(s5_login "$SEC_USER" "$SEC_PWD");
  SYNC_OUT=$(curl -s -b "$COOKIE" -X POST "$API_URL/api/v1/waf-rules/sync" -H "X-CSRF-Token: $SEC_CSRF"); }
echo "$SYNC_OUT" | python3 -c "import json,sys; d=json.load(sys.stdin)['data']; print('  total_in_db=%s added=%s updated=%s unchanged=%s' % (d['total_in_db'], d['added'], d['updated'], d['unchanged']))"

# ---------------------------------------------------------------
echo "== [2/6] 证书（API 上传自签证书） =="
TMPD=$(mktemp -d); trap 'rm -rf "$TMPD"' EXIT
# name|CN(domain)|SAN  extras|days_back
CERTS=(
  "演示证书-shop.example.com|shop.example.com|www.shop.example.com|1"
  "演示证书-uc.example.com|uc.example.com|sso.uc.example.com|2"
  "演示证书-open.example.com|open.example.com|gw.open.example.com|3"
  "演示证书-api.example.com|api.example.com|api2.example.com|4"
  "演示证书-pay.example.com|pay.example.com|cashier.pay.example.com|5"
  "演示证书-crm.example.com|crm.example.com|m.crm.example.com|6"
  "演示证书-oa.example.com|oa.example.com|mail.oa.example.com|7"
  "演示证书-docs.example.com|docs.example.com|wiki.docs.example.com|8"
  "演示证书-static.example.com|static.example.com|img.example.com|9"
  "演示证书-partner.example.com|partner.example.com|open.partner.example.com|10"
  "演示证书-openapi.example.com|openapi.example.com|sandbox.openapi.example.com|11"
  "演示证书-wildcard.example.com|*.example.com|example.com|12"
)
for spec in "${CERTS[@]}"; do
  IFS='|' read -r cname cn san2 back <<< "$spec"
  if name_exists certificates "$cname"; then echo "  skip $cname"; continue; fi
  openssl req -x509 -newkey rsa:2048 -keyout "$TMPD/k.pem" -out "$TMPD/c.pem" \
    -days 365 -nodes -subj "/CN=$cn/O=JuXinDeRen Demo/C=CN" \
    -addext "subjectAltName=DNS:$cn,DNS:$san2" 2>/dev/null
  python3 - "$TMPD" "$cname" > "$TMPD/payload.json" <<'PYEOF'
import json, sys
d, name = sys.argv[1], sys.argv[2]
print(json.dumps({"name": name, "cert_pem": open(d + "/c.pem").read(), "key_pem": open(d + "/k.pem").read()}))
PYEOF
  out=$(api_post "/api/v1/certificates" "$(cat "$TMPD/payload.json")")
  echo "$out" | grep -q '"code":"SUCCESS"' && echo "  + $cname" || { echo "  FAIL $cname: $(echo "$out" | head -c 200)"; exit 1; }
  sleep 0.3
done
# 时间铺开：created_at/updated_at 回拨 1-12 天（确定性，重跑同结果）
for spec in "${CERTS[@]}"; do
  IFS='|' read -r cname _ _ back <<< "$spec"
  PG -q -c "UPDATE certificates SET created_at=now()-interval '$back days' - interval '3 hours', updated_at=now()-interval '$back days' - interval '3 hours' WHERE name='$cname';" > /dev/null
done

# ---------------------------------------------------------------
echo "== [3/6] 报表模板（API 创建，补差至 12 含内置） =="
# name|company|prepared_by|reviewed_by|no_format|description|days_back
TEMPLATES=(
  "演示模板-安全运营月报|聚信得仁科技（演示）|李安然|王叙白|SOC-{YYYYMM}-{SEQ}|面向安全运营团队的月度综合报告|1"
  "演示模板-攻击态势周报|聚信得仁科技（演示）|陈沐阳|赵清岚|ATK-{YYYYMM}-{SEQ}|聚焦攻击类型、来源与趋势的一周复盘|2"
  "演示模板-等保合规检查|聚信得仁科技（演示）|林望舒|周其琛|DJCP-{YYYYMM}-{SEQ}|等级保护合规检查配套报告样式|3"
  "演示模板-管理层摘要|聚信得仁科技（演示）|苏听澜|李安然|MGT-{YYYYMM}-{SEQ}|面向管理层的一页式安全摘要|4"
  "演示模板-重保专项防护|聚信得仁科技（演示）|王叙白|陈沐阳|HB-{YYYYMM}-{SEQ}|重要保障期间专项防护报告|5"
  "演示模板-应急复盘报告|聚信得仁科技（演示）|赵清岚|林望舒|IR-{YYYYMM}-{SEQ}|安全事件应急响应事后复盘|6"
  "演示模板-CC防护专项|聚信得仁科技（演示）|周其琛|苏听澜|CC-{YYYYMM}-{SEQ}|CC 攻击与频率限制专项分析|7"
  "演示模板-访问控制审计|聚信得仁科技（演示）|李安然|王叙白|ACL-{YYYYMM}-{SEQ}|黑白名单与访问控制命中审计|8"
  "演示模板-证书资产清单|聚信得仁科技（演示）|陈沐阳|赵清岚|CERT-{YYYYMM}-{SEQ}|证书有效期与站点资产盘点|9"
  "演示模板-电商平台专项|聚信得仁科技（演示）|林望舒|周其琛|SHOP-{YYYYMM}-{SEQ}|shop-mall 电商平台专项防护报告|10"
  "演示模板-开放平台专项|聚信得仁科技（演示）|苏听澜|李安然|OPEN-{YYYYMM}-{SEQ}|open-gw 开放网关专项防护报告|11"
)
for spec in "${TEMPLATES[@]}"; do
  IFS='|' read -r tname comp prep rev fmt desc back <<< "$spec"
  if name_exists report_templates "$tname"; then echo "  skip $tname"; continue; fi
  payload=$(python3 -c "import json,sys; a=sys.argv[1:]; print(json.dumps({'name':a[0],'company_name':a[1],'prepared_by':a[2],'reviewed_by':a[3],'report_no_format':a[4],'description':a[5]}))" "$tname" "$comp" "$prep" "$rev" "$fmt" "$desc")
  out=$(api_post "/api/v1/report-templates" "$payload")
  echo "$out" | grep -q '"code":"SUCCESS"' && echo "  + $tname" || { echo "  FAIL $tname: $(echo "$out" | head -c 200)"; exit 1; }
  sleep 0.3
done
for spec in "${TEMPLATES[@]}"; do
  IFS='|' read -r tname _ _ _ _ _ back <<< "$spec"
  PG -q -c "UPDATE report_templates SET created_at=now()-interval '$back days' - interval '5 hours', updated_at=now()-interval '$back days' - interval '5 hours' WHERE name='$tname';" > /dev/null
done

# 取演示模板 ID（供报告/调度引用）
DEMO_TPL_IDS=$(PG -t -A -c "SELECT id FROM report_templates WHERE name LIKE '演示模板-%' AND deleted_at IS NULL ORDER BY name;")
TPL_ARR=()
while IFS= read -r line; do [ -n "$line" ] && TPL_ARR+=("$line"); done <<< "$DEMO_TPL_IDS"
[ "${#TPL_ARR[@]}" -ge 4 ] || { echo "ERROR: demo templates < 4"; exit 1; }

# ---------------------------------------------------------------
echo "== [4/6] 报表任务（API 创建，Worker 真实生成） =="
REPORT_TARGET=14
have=$(PG -t -A -c "SELECT count(*) FROM report_jobs WHERE template_id IN (SELECT id FROM report_templates WHERE name LIKE '演示模板-%');")
need=$((REPORT_TARGET - have))
echo "  existing demo reports=$have, need=$need"
# type|format|apps|tpl_idx|custom_start|custom_end
RSPECS=(
  "DAILY|html||0||"
  "DAILY|html|$APP_SHOP|1||"
  "DAILY|html|$APP_SHOP,$APP_UC|2||"
  "DAILY|pdf|$APP_OPEN|3||"
  "DAILY|html|$APP_S5|0||"
  "DAILY|html|$APP_SHOP,$APP_UC,$APP_OPEN|1||"
  "WEEKLY|html||2||"
  "WEEKLY|docx|$APP_SHOP|3||"
  "WEEKLY|html|$APP_UC|0||"
  "WEEKLY|html|$APP_OPEN,$APP_S5|1||"
  "MONTHLY|html||2||"
  "MONTHLY|pdf|$APP_SHOP,$APP_UC,$APP_OPEN,$APP_S5|3||"
  "CUSTOM|html||0|2026-09-01T00:00:00Z|2026-09-08T00:00:00Z"
  "CUSTOM|html|$APP_SHOP,$APP_UC|1|2026-08-25T00:00:00Z|2026-09-01T00:00:00Z"
)
created=0
for spec in "${RSPECS[@]}"; do
  [ "$created" -ge "$need" ] && break
  IFS='|' read -r rtype rfmt apps tidx cs ce <<< "$spec"
  payload=$(python3 -c "
import json,sys
rtype,rfmt,apps,tpl,cs,ce = sys.argv[1:7]
d={'report_type':rtype,'content_scope':'WAF','format':rfmt,'template_id':tpl or None,
   'application_ids':[a for a in apps.split(',') if a] or None}
if cs: d['start_time']=cs
if ce: d['end_time']=ce
print(json.dumps(d))" "$rtype" "$rfmt" "$apps" "${TPL_ARR[$tidx]}" "$cs" "$ce")
  out=$(api_post "/api/v1/reports" "$payload")
  if echo "$out" | grep -q '"code":"SUCCESS"'; then created=$((created+1)); echo "  + $rtype/$rfmt"; else echo "  FAIL $rtype/$rfmt: $(echo "$out" | head -c 200)"; fi
  sleep 0.5
done
if [ "$created" -lt "$need" ]; then
  echo "  WARN: 仅新建 $created/$need，缺口将在下次运行时补齐"
fi

# 等待 Worker 处理完演示任务（PENDING/RUNNING → 终态）
echo "  waiting for report worker..."
for i in $(seq 1 60); do
  running=$(PG -t -A -c "SELECT count(*) FROM report_jobs WHERE status IN ('PENDING','RUNNING') AND template_id IN (SELECT id FROM report_templates WHERE name LIKE '演示模板-%');")
  [ "$running" = "0" ] && break
  sleep 3
done
PG -t -A -c "SELECT status, count(*) FROM report_jobs WHERE template_id IN (SELECT id FROM report_templates WHERE name LIKE '演示模板-%') GROUP BY status ORDER BY 1;" | sed 's/^/  /'

# 演示报告时间铺开（仅 9 月内回拨 0-10 天，保证 report_no 的 YYYYMM 一致）
PGI -q > /dev/null <<'SQL'
WITH demo AS (
  SELECT j.id, row_number() OVER (ORDER BY j.requested_at) - 1 AS rn
  FROM report_jobs j
  WHERE j.template_id IN (SELECT id FROM report_templates WHERE name LIKE '演示模板-%')
)
UPDATE report_jobs j
SET requested_at = now() - make_interval(days => (demo.rn % 11)::int, hours => ((demo.rn * 3) % 24)::int),
    started_at   = now() - make_interval(days => (demo.rn % 11)::int, hours => ((demo.rn * 3) % 24)::int) + interval '3 seconds',
    finished_at  = now() - make_interval(days => (demo.rn % 11)::int, hours => ((demo.rn * 3) % 24)::int) + interval '18 seconds'
FROM demo WHERE j.id = demo.id AND j.status IN ('SUCCESS','FAILED','CANCELLED');
SQL

# ---------------------------------------------------------------
echo "== [5/6] 报表调度 + 归档（SQL，调度创建 API 当前有 bug） =="
SEC_UID=$(PG -t -A -c "SELECT id FROM users WHERE username='$SEC_USER';")
export SEC_UID APP_SHOP APP_UC APP_OPEN APP_S5 NS_PREFIX
python3 - <<'PYEOF' | PGI -q > /dev/null
import json, os, uuid

NS = uuid.NAMESPACE_URL
def U(key): return str(uuid.uuid5(NS, os.environ["NS_PREFIX"] + ":" + key))
SHOP, UC, OPEN, S5 = (os.environ[k] for k in ("APP_SHOP", "APP_UC", "APP_OPEN", "APP_S5"))
SEC = os.environ["SEC_UID"]

tpl = {}
import subprocess
rows = subprocess.run(
    ["docker", "exec", os.environ.get("PG_CONTAINER", "jiuzhang-stage5-postgres"),
     "psql", "-U", "jiuzhang", "-d", "jiuzhang_waf", "-t", "-A", "-c",
     "SELECT name, id FROM report_templates WHERE name LIKE '演示模板-%' AND deleted_at IS NULL;"],
    capture_output=True, text=True).stdout.strip().splitlines()
for line in rows:
    n, i = line.split("|")
    tpl[n] = i

def T(name): return "'" + tpl[name] + "'" if name in tpl else "NULL"

# name|type|fmt|tod|dow|dom|apps|tpl_name|enabled|days_back
SCHEDS = [
    ("演示调度-每日安全日报",   "DAILY",   "html", "06:30", 1, 1, [SHOP], "演示模板-安全运营月报", True, 1),
    ("演示调度-每日全量巡检",   "DAILY",   "html", "07:00", 1, 1, [], "演示模板-攻击态势周报", True, 2),
    ("演示调度-每日开放平台",   "DAILY",   "pdf",  "08:15", 1, 1, [OPEN], "演示模板-开放平台专项", True, 3),
    ("演示调度-每日用户中心",   "DAILY",   "html", "22:30", 1, 1, [UC], None, True, 4),
    ("演示调度-每日电商专项",   "DAILY",   "html", "23:45", 1, 1, [SHOP, UC], "演示模板-电商平台专项", True, 5),
    ("演示调度-每日凌晨快报",   "DAILY",   "html", "00:30", 1, 1, [], None, False, 6),
    ("演示调度-每周一运营周报", "WEEKLY",  "html", "06:00", 1, 1, [], "演示模板-等保合规检查", True, 7),
    ("演示调度-每周三攻击态势", "WEEKLY",  "pdf",  "07:30", 3, 1, [SHOP, UC, OPEN], None, True, 8),
    ("演示调度-每周五合规周报", "WEEKLY",  "html", "18:00", 5, 1, [], "演示模板-管理层摘要", True, 9),
    ("演示调度-每周日汇总",     "WEEKLY",  "docx", "20:00", 7, 1, [S5], None, False, 10),
    ("演示调度-每月合规月报",   "MONTHLY", "pdf",  "05:30", 1, 1, [], "演示模板-安全运营月报", True, 11),
    ("演示调度-每月管理层摘要", "MONTHLY", "html", "09:00", 1, 15, [], "演示模板-攻击态势周报", True, 12),
]
print("BEGIN;")
for name, rtype, fmt, tod, dow, dom, apps, tplname, enabled, back in SCHEDS:
    apps_json = json.dumps(apps)
    print(
        "INSERT INTO report_schedules (id, name, report_type, content_scope, application_ids, template_id,"
        " file_format, time_of_day, day_of_week, day_of_month, send_email, emails, enabled, next_run_at,"
        " include_api_assets, page_orientation, created_by, created_at, updated_at) VALUES ("
        f"'{U('sched:' + name)}', '{name}', '{rtype}', 'WAF', '{apps_json}'::jsonb, {T(tplname) if tplname else 'NULL'},"
        f" '{fmt}', '{tod}', {dow}, {dom}, false, '[]'::jsonb, {'true' if enabled else 'false'},"
        f" now() + interval '{back} days', false, 'P', '{SEC}',"
        f" now() - interval '{back} days' - interval '2 hours', now() - interval '{back} days' - interval '2 hours')"
        " ON CONFLICT (id) DO NOTHING;"
    )

NOTES = ["月度合规归档", "运营例会留存", "审计调阅备份", "重保材料归档", "季度汇总备查", "管理层报送底稿"]
# 归档：为每个演示 SUCCESS 任务生成确定性归档行（无归档写 API，直接 SQL）
rows = subprocess.run(
    ["docker", "exec", os.environ.get("PG_CONTAINER", "jiuzhang-stage5-postgres"),
     "psql", "-U", "jiuzhang", "-d", "jiuzhang_waf", "-t", "-A", "-c",
     "SELECT id FROM report_jobs WHERE status='SUCCESS' AND template_id IN "
     "(SELECT id FROM report_templates WHERE name LIKE '演示模板-%') ORDER BY finished_at;"],
    capture_output=True, text=True).stdout.strip().splitlines()
for idx, job_id in enumerate([r for r in rows if r]):
    note = NOTES[idx % len(NOTES)]
    print(
        f"INSERT INTO report_archives (id, report_job_id, archived_by, archived_at, note) VALUES ("
        f"'{U('arch:' + job_id)}', '{job_id}', '{SEC}',"
        f" now() - interval '{idx % 10} days' - interval '{(idx * 7) % 24} hours', '{note}')"
        " ON CONFLICT (id) DO NOTHING;"
    )
print("COMMIT;")
PYEOF
echo "  schedules=$(PG -t -A -c 'SELECT count(*) FROM report_schedules;') archives=$(PG -t -A -c 'SELECT count(*) FROM report_archives;')"

# ---------------------------------------------------------------
echo "== [6/6] 站点资产自动发现（SQL） =="
python3 - <<'PYEOF' | PGI -q > /dev/null
import os, uuid
NS = uuid.NAMESPACE_URL
def U(key): return str(uuid.uuid5(NS, os.environ["NS_PREFIX"] + ":" + key))
# domain|ip|port|proto|mode|seen|clients|status|first_days_back|last_hours_back
ROWS = [
    ("cdn.example.com",       "192.0.2.10",    443,  "HTTPS", "MIRROR",      15230, 342,  "CONFIRMED", 13, 2),
    ("beta.example.com",      "192.0.2.11",    443,  "HTTPS", "MIRROR",      8421,  156,  "NEW",       12, 5),
    ("staging.example.com",   "192.0.2.12",    8443, "HTTPS", "ROUTED",      312,   12,   "NEW",       11, 9),
    ("mobile.example.com",    "192.0.2.13",    443,  "HTTPS", "ROUTED",      22140, 1204, "CONFIRMED", 10, 1),
    ("files.example.com",     "192.0.2.14",    80,   "HTTP",  "MIRROR",      976,   88,   "NEW",       9, 14),
    ("intranet.example.com",  "198.51.100.20", 443,  "HTTPS", "TRANSPARENT", 5402,  210,  "IGNORED",   9, 30),
    ("legacy.example.com",    "198.51.100.21", 80,   "HTTP",  "TRANSPARENT", 1203,  45,   "IGNORED",   8, 26),
    ("edge.example.com",      "198.51.100.22", 443,  "HTTPS", "ROUTED",      18230, 990,  "CONFIRMED", 7, 3),
    ("lab.example.com",       "198.51.100.23", 8080, "HTTP",  "MIRROR",      210,   8,    "NEW",       6, 41),
    ("demo1.example.com",     "203.0.113.10",  443,  "HTTPS", "MIRROR",      6640,  301,  "NEW",       5, 7),
    ("test-shop.example.com", "203.0.113.11",  443,  "HTTPS", "ROUTED",      4310,  129,  "NEW",       4, 11),
    ("pre-live.example.com",  "203.0.113.12",  443,  "HTTPS", "TRANSPARENT", 980,   37,   "NEW",       3, 18),
    ("campaign.example.com",  "203.0.113.13",  80,   "HTTP",  "MIRROR",      15220, 2050, "CONFIRMED", 2, 4),
    ("helpdesk.example.com",  "203.0.113.14",  443,  "HTTPS", "ROUTED",      760,   52,   "NEW",       1, 22),
]
print("BEGIN;")
for domain, ip, port, proto, mode, seen, clients, status, fb, lh in ROWS:
    confirmed = status == "CONFIRMED"
    print(
        "INSERT INTO site_asset_discoveries (id, domain, ip, port, protocol, source_mode, gateway_node,"
        " seen_count, client_count, first_seen, last_seen, status, confirmed_by, confirmed_at, created_at, updated_at)"
        " VALUES ("
        f"'{U('disc:' + domain + '|' + ip + '|' + str(port))}', '{domain}', '{ip}', {port}, '{proto}', '{mode}',"
        f" 'gw-stage5-01', {seen}, {clients},"
        f" now() - interval '{fb} days' - interval '{(fb * 5) % 24} hours', now() - interval '{lh} hours', '{status}',"
        f" {'\'sec_admin_s5\'' if confirmed else '\'\''},"
        f" {('now() - interval \'%d days\'' % (fb - 1)) if confirmed else 'NULL'},"
        f" now() - interval '{fb} days' - interval '{(fb * 5) % 24} hours', now() - interval '{lh} hours')"
        " ON CONFLICT (id) DO NOTHING;"
    )
print("COMMIT;")
PYEOF
echo "  discoveries=$(PG -t -A -c 'SELECT count(*) FROM site_asset_discoveries;')"

# ---------------------------------------------------------------
echo "============================================================"
echo "验证（接口 total）"
echo "============================================================"
# 验证前刷新会话，避免前面步骤的会话失效影响读取
SEC_CSRF=$(s5_login "$SEC_USER" "$SEC_PWD")
for p in waf-rules certificates report-templates report-schedules reports report-archives site-discoveries; do
  printf "%-22s = " "$p"
  curl -s -b "$COOKIE" "$API_URL/api/v1/$p?page=1&page_size=1" \
    | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['data']['total'] if 'data' in d else d)"
done
