#!/usr/bin/env bash
# 九章 WDSP 演示造数：运维/系统/身份域
# 覆盖：users / audits(验证) / backups(API) / restores / upgrades / upgrade-packages
#       / delivery-checks / license/history / apm/agents / apm/services
# 幂等：用户与备份走真实 API（409/重复视为已存在）；其余用确定性 UUID(uuid5)
#       + ON CONFLICT DO NOTHING 直接 SQL。
# 数据安全：IP 仅 RFC 5737 文档段，域名仅 example.com 系，姓名全部虚构。
# 用法：bash scripts/demo/seed-ops-demo.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../test/waf/scripts/stage5-setup.sh
source "$REPO_ROOT/test/waf/scripts/stage5-setup.sh"

PG_CONTAINER="${PG_CONTAINER:-jiuzhang-stage5-postgres}"
PG_USER="${PG_USER:-jiuzhang}"
PG_DB="${PG_DB:-jiuzhang_waf}"
DEMO_USER_PWD="${DEMO_USER_PWD:-WdspDemo@2026}"
AUDIT_DEMO_USER="audit_liuyun"

psql_c() { docker exec "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" "$@"; }

echo "== [0] 登录系统管理员 =="
SYS_CSRF=$(s5_ensure_sysadmin)
[ -n "$SYS_CSRF" ] || { echo "ERROR: sysadmin login failed"; exit 1; }
SYS_COOKIE="/tmp/s5-$SYS_USER.txt"

api_post() { # path body -> stdout
  curl -s -b "$SYS_COOKIE" -X POST "$API_URL$1" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $SYS_CSRF" -d "$2"
}

# ---------------------------------------------------------------------------
echo "== [1] 演示用户（真实 API，已存在则跳过） =="
# 仅三个内置角色：SYSTEM_ADMIN / SECURITY_ADMIN / AUDIT_ADMIN（无 READONLY 角色）
USERS=(
  "ops_chenyf|陈云帆|SYSTEM_ADMIN"
  "ops_linhr|林皓然|SYSTEM_ADMIN"
  "ops_gaozy|高志远|SYSTEM_ADMIN"
  "sec_wangrx|王若曦|SECURITY_ADMIN"
  "sec_zhaoqm|赵启铭|SECURITY_ADMIN"
  "sec_sunky|孙可盈|SECURITY_ADMIN"
  "$AUDIT_DEMO_USER|刘云策|AUDIT_ADMIN"
  "audit_zhoutt|周庭婷|AUDIT_ADMIN"
  "audit_wujy|吴静怡|AUDIT_ADMIN"
)
created_users=()
for entry in "${USERS[@]}"; do
  IFS='|' read -r uname dname role <<< "$entry"
  resp=$(api_post /api/v1/users "{\"username\":\"$uname\",\"display_name\":\"$dname\",\"role_code\":\"$role\"}")
  code=$(echo "$resp" | python3 -c "import json,sys; print(json.load(sys.stdin).get('code',''))" 2>/dev/null || true)
  if [ "$code" = "SUCCESS" ]; then
    tmp=$(echo "$resp" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['temporary_password'])")
    # 首次登录强制改密：改为统一演示口令，保证演示可登录
    lcsrf=$(s5_login "$uname" "$tmp" || true)
    if [ -n "$lcsrf" ]; then
      curl -s -b "/tmp/s5-$uname.txt" -X POST "$API_URL/api/v1/auth/change-password" \
        -H 'Content-Type: application/json' -H "X-CSRF-Token: $lcsrf" \
        -d "{\"old_password\":\"$tmp\",\"new_password\":\"$DEMO_USER_PWD\"}" > /dev/null
      echo "  + $uname ($dname/$role) 已创建，口令=$DEMO_USER_PWD"
      created_users+=("$uname")
    else
      echo "  + $uname ($dname/$role) 已创建（改密登录失败，请手工处理）"
    fi
  elif echo "$resp" | grep -q "已存在\|CONFLICT"; then
    echo "  = $uname 已存在，跳过"
  else
    echo "  ! $uname 创建失败: $resp" >&2
  fi
done

# 新建用户 created_at 全部等于当前时刻，这里把时间铺开（最近 1-14 天）便于演示
if [ "${#created_users[@]}" -gt 0 ]; then
  in_list=$(printf "'%s'," "${created_users[@]}"); in_list="(${in_list%,})"
  psql_c --quiet <<SQL
UPDATE users u
SET created_at = now() - (('' || (1 + (hashtext(u.username) % 13))) || ' days')::interval
                    - ((hashtext(u.username || 'h') % 20) || ' hours')::interval,
    updated_at = now()
WHERE u.username IN $in_list;
SQL
  echo "  (created_at 已铺开)"
fi

# ---------------------------------------------------------------------------
echo "== [2] 备份任务（真实 API，异步执行；已有 >=3 个则跳过，保证幂等） =="
existing_backups=$(psql_c -t -A -c "SELECT count(*) FROM backup_jobs;")
if [ "${existing_backups:-0}" -ge 3 ]; then
  echo "  = 已有 $existing_backups 个备份，跳过创建"
else
  for bt in FULL CONFIG_ONLY FULL; do
    resp=$(api_post /api/v1/backups "{\"backup_type\":\"$bt\"}")
    code=$(echo "$resp" | python3 -c "import json,sys; print(json.load(sys.stdin).get('code',''))" 2>/dev/null || true)
    if [ "$code" = "SUCCESS" ]; then
      echo "  + backup $bt 已创建"
    else
      echo "  ! backup $bt 创建失败（不影响后续 SQL 造数）: $(echo "$resp" | head -c 200)" >&2
    fi
  done
fi

# 取备份任务 id 供 restore_jobs 关联（可能没有，则 restore.backup_job_id 置空）
BACKUP_IDS=$(psql_c -t -A -c "SELECT string_agg(id::text, ' ') FROM (SELECT id FROM backup_jobs ORDER BY requested_at DESC LIMIT 5) t;")
echo "  backup_jobs 现存量: $(psql_c -t -A -c 'SELECT count(*) FROM backup_jobs;')"

# ---------------------------------------------------------------------------
echo "== [3] 低频运维对象 + 许可历史 + APM（确定性 SQL 造数） =="
ADMIN_ID=$(psql_c -t -A -c "SELECT id FROM users WHERE lower(username)='jiuzhang_admin' LIMIT 1;")
APP_IDS=$(psql_c -t -A -c "SELECT string_agg(id::text, ' ') FROM applications WHERE deleted_at IS NULL;")

ADMIN_ID="$ADMIN_ID" BACKUP_IDS="$BACKUP_IDS" APP_IDS="$APP_IDS" python3 - << 'PYEOF' | docker exec -i "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -v ON_ERROR_STOP=1 --quiet
import hashlib, json, os, uuid

NS = uuid.UUID("3c9a7e52-6b41-4d8e-9f2a-1b5c7d3e8a60")
def U(key): return str(uuid.uuid5(NS, "jz-demo-ops:" + key))
def H(s): return hashlib.sha256(s.encode()).hexdigest()
def J(o): return json.dumps(o, ensure_ascii=False)

ADMIN = os.environ["ADMIN_ID"]
BACKUPS = os.environ.get("BACKUP_IDS", "").split()
APPS = os.environ.get("APP_IDS", "").split()

def q(v): return "NULL" if v is None else "'" + str(v).replace("'", "''") + "'"
def ts(days, hours=0, minutes=0):
    return f"(now() - interval '{days} days' - interval '{hours} hours' - interval '{minutes} minutes')"

print("BEGIN;")

# ---------- 3.1 追加 8 个演示应用（/api/v1/apm/services 列表计数 applications） ----------
# 现有 4 个（shop-mall/user-center/open-gw/s5app），补 8 个凑满 12
NEW_APPS = [
    ("demo-shop-svc",   "演示-商城交易服务"),
    ("demo-uc-svc",     "演示-用户账户服务"),
    ("demo-pay-svc",    "演示-支付清算服务"),
    ("demo-order-svc",  "演示-订单履约服务"),
    ("demo-search-svc", "演示-搜索推荐服务"),
    ("demo-crm-svc",    "演示-客户关系服务"),
    ("demo-report-svc", "演示-报表分析服务"),
    ("demo-msg-svc",    "演示-消息推送服务"),
]
new_app_ids = []
for i, (code, name) in enumerate(NEW_APPS):
    aid = U("app:" + code)
    new_app_ids.append(aid)
    print(f"""INSERT INTO applications (id, code, name, description, business_owner, technical_owner,
       status, protection_mode, created_by, created_at, updated_at)
VALUES ({q(aid)}, {q(code)}, {q(name)}, 'WDSP 演示环境虚构服务，仅用于 APM 列表展示',
        '演示业务部', '演示运维组', 'ACTIVE', 'OBSERVE', {q(ADMIN)},
        {ts(13 - i, i + 2)}, now())
ON CONFLICT DO NOTHING;""")

ALL_APPS = APPS + new_app_ids

# ---------- 3.2 apm_services：12 个服务（每应用一个，production） ----------
svc_ids = []
for i, aid in enumerate(ALL_APPS[:12]):
    sid = U("apm-svc:%d" % i)
    svc_ids.append((sid, aid, i))
    print(f"""INSERT INTO apm_services (id, service_name, environment, application_id, claim_status,
       first_seen_at, last_seen_at, created_at, updated_at)
SELECT {q(sid)}, a.code, 'production', a.id, 'CLAIMED',
       {ts(13 - i, i)}, now() - interval '5 minutes', {ts(13 - i, i)}, now()
FROM applications a WHERE a.id = {q(aid)}
ON CONFLICT DO NOTHING;""")

# ---------- 3.3 apm_agents：12 个探针 ----------
AGENTS = [
    # (服务序号, 语言, 状态, 心跳距今分钟, 节点IP)
    (0,  "java",   "CONNECTED_BASELINE",   2, "192.0.2.11"),
    (0,  "java",   "CONNECTED_BASELINE",   4, "192.0.2.12"),
    (1,  "go",     "CONNECTED_BASELINE",   1, "192.0.2.21"),
    (2,  "java",   "CONNECTED_BASELINE",   3, "192.0.2.31"),
    (3,  "nodejs", "CONNECTED_BASELINE",   6, "192.0.2.41"),
    (4,  "go",     "CONNECTED_BASELINE",   5, "192.0.2.51"),
    (5,  "python", "CONNECTED_BASELINE",   8, "198.51.100.23"),
    (6,  "java",   "CONNECTED_BASELINE",   7, "198.51.100.24"),
    (7,  "go",     "DIAGNOSING",           3, "198.51.100.25"),
    (8,  "java",   "CONNECTED_BASELINE",   9, "198.51.100.26"),
    (9,  "go",     "ENROLLING",         None, "203.0.113.10"),
    (10, "java",   "REVOKED",           4320, "203.0.113.11"),
]
for n, (si, lang, status, hb_min, ip) in enumerate(AGENTS):
    sid, aid, sidx = svc_ids[si]
    agid = U("apm-agent:%d" % n)
    inst = "demo-node-%02d" % (n + 1)
    fp = H("apm-agent-cert:%d" % n)
    hb = "NULL" if hb_min is None else f"now() - interval '{hb_min} minutes'"
    revoked = "now() - interval '2 days'" if status == "REVOKED" else "NULL"
    reason = "演示：节点退役吊销" if status == "REVOKED" else ""
    node = J({"host": inst, "ip": ip, "os": "linux", "arch": "amd64"})
    print(f"""INSERT INTO apm_agents (id, service_id, instance_id, language, agent_version, sdk_version,
       status, cert_fingerprint, cert_not_after, last_heartbeat_at, node_info,
       registered_at, revoked_at, revoke_reason)
SELECT {q(agid)}, s.id, {q(inst)}, {q(lang)}, '1.4.2', '0.9.1',
       {q(status)}, {q(fp)}, now() + interval '180 days', {hb}, {q(node)}::jsonb,
       {ts(12 - (n % 10), n + 1)}, {revoked}, {q(reason)}
FROM apm_services s WHERE s.id = {q(sid)}
ON CONFLICT DO NOTHING;""")

# ---------- 3.4 restore_jobs：12 条恢复历史 ----------
RESTORES = [
    ("FULL",        "SUCCESS",   ""),
    ("CONFIG",      "SUCCESS",   ""),
    ("DATABASE",    "SUCCESS",   ""),
    ("FULL",        "FAILED",    "RESTORE_FAILED"),
    ("CERTIFICATE", "SUCCESS",   ""),
    ("CONFIG",      "CANCELLED", ""),
    ("FULL",        "SUCCESS",   ""),
    ("DATABASE",    "FAILED",    "VALIDATE_FAILED"),
    ("CONFIG",      "SUCCESS",   ""),
    ("FULL",        "SUCCESS",   ""),
    ("CERTIFICATE", "CANCELLED", ""),
    ("DATABASE",    "SUCCESS",   ""),
]
for i, (scope, status, fcode) in enumerate(RESTORES):
    rid = U("restore:%d" % i)
    bid = BACKUPS[i % len(BACKUPS)] if BACKUPS else None
    days, hrs = 13 - i, (i * 3) % 20
    confirmed = status in ("SUCCESS", "FAILED")
    fmsg = {"RESTORE_FAILED": "演示：目标表空间校验不一致，已回滚隔离库",
            "VALIDATE_FAILED": "演示：备份清单签名校验失败"}.get(fcode, "")
    preview = J({"scope": scope, "tables": 42 - i % 7, "rows_estimate": 128000 + i * 977})
    print(f"""INSERT INTO restore_jobs (id, backup_job_id, restore_scope, status, preview,
       confirmed_by, confirmed_at, requested_by, requested_at, started_at, finished_at,
       failure_code, failure_message, request_id)
VALUES ({q(rid)}, {q(bid)}, {q(scope)}, {q(status)}, {q(preview)}::jsonb,
       {q(ADMIN) if confirmed else "NULL"}, {ts(days, hrs - 1) if confirmed else "NULL"},
       {q(ADMIN)}, {ts(days, hrs)}, {ts(days, hrs - 1)}, {ts(days, hrs - 2)},
       {q(fcode)}, {q(fmsg)}, {q('demo-restore-%02d' % i)})
ON CONFLICT DO NOTHING;""")

# ---------- 3.5 upgrade_packages：12 个升级包 ----------
PKG_STATUSES = (["VERIFIED"] * 8) + ["REGISTERED"] * 2 + ["REJECTED"] * 2
pkg_ids = []
for i in range(12):
    vf = "1.0.%d" % i
    vt = "1.0.%d" % (i + 1) if i < 9 else "1.1.%d" % (i - 9)
    fname = "jiuzhang-wdsp-upgrade-%s-to-%s.tar.gz" % (vf, vt)
    pid = U("pkg:%d" % i)
    pkg_ids.append(pid)
    manifest = J({"version_from": vf, "version_to": vt, "arch": "amd64",
                  "components": ["server", "gateway", "web"]})
    print(f"""INSERT INTO upgrade_packages (id, file_name, version_from, version_to, file_hash,
       file_size, manifest, status, uploaded_by, uploaded_at)
VALUES ({q(pid)}, {q(fname)}, {q(vf)}, {q(vt)}, {q(H(fname))},
       {52428800 + i * 1048576}, {q(manifest)}::jsonb, {q(PKG_STATUSES[i])},
       {q(ADMIN)}, {ts(13 - i, (i * 5) % 20)})
ON CONFLICT DO NOTHING;""")

# ---------- 3.6 upgrade_jobs：12 条升级任务 ----------
JOB_STATUSES = (["SUCCESS"] * 8) + ["FAILED"] * 2 + ["ROLLED_BACK"] * 2
for i in range(12):
    jid = U("upgjob:%d" % i)
    st = JOB_STATUSES[i]
    fcode = "APPLY_FAILED" if st == "FAILED" else ""
    fmsg = "演示：网关热更新后健康检查超时，已自动回滚" if st == "FAILED" else ""
    days, hrs = 13 - i, (i * 7) % 20
    precheck = J({"disk_free_gb": 86 - i, "db_connection": "ok", "license_valid": True,
                  "result": "PASS" if st != "FAILED" else "FAIL"})
    print(f"""INSERT INTO upgrade_jobs (id, package_id, status, precheck, backup_job_id,
       requested_by, requested_at, started_at, finished_at, failure_code, failure_message, request_id)
VALUES ({q(jid)}, {q(pkg_ids[i])}, {q(st)}, {q(precheck)}::jsonb, NULL,
       {q(ADMIN)}, {ts(days, hrs)}, {ts(days, hrs - 1)}, {ts(days, hrs - 2)},
       {q(fcode)}, {q(fmsg)}, {q('demo-upgrade-%02d' % i)})
ON CONFLICT DO NOTHING;""")

# ---------- 3.7 delivery_checks：12 次交付检查（含结果明细） ----------
CHECK_ITEMS = [
    ("sys.os",        "操作系统版本与内核参数",     "系统环境"),
    ("sys.time",      "系统时间同步（NTP）",        "系统环境"),
    ("db.conn",       "PostgreSQL 连接与迁移版本",  "数据库"),
    ("db.valkey",     "Valkey 连接与会话读写",      "数据库"),
    ("gw.config",     "网关配置加载与语法校验",     "网关"),
    ("gw.cert",       "站点证书链有效性",           "网关"),
    ("lic.status",    "授权状态与配额",             "授权"),
    ("sec.baseline",  "安全基线（默认口令/调试口）","安全基线"),
]
for i in range(12):
    cid = U("dlv:%d" % i)
    days, hrs = 13 - i, (i * 2) % 18
    # 结果分布：前 8 全 PASS，9-10 有 WARNING，11-12 有 FAIL
    n_warn = 1 if i in (8, 9) else 0
    n_fail = 1 if i >= 10 else 0
    n_pass = len(CHECK_ITEMS) - n_warn - n_fail
    overall = "FAIL" if n_fail else ("WARNING" if n_warn else "PASS")
    print(f"""INSERT INTO delivery_checks (id, overall_result, total, pass_count, warning_count,
       fail_count, requested_by, started_at, finished_at)
VALUES ({q(cid)}, {q(overall)}, {len(CHECK_ITEMS)}, {n_pass}, {n_warn}, {n_fail},
       {q(ADMIN)}, {ts(days, hrs)}, {ts(days, hrs - 1)})
ON CONFLICT DO NOTHING;""")
    for j, (key, name, cat) in enumerate(CHECK_ITEMS):
        iid = U("dlv:%d:item:%d" % (i, j))
        if n_fail and j == len(CHECK_ITEMS) - 1:
            res, msg, crit = "FAIL", "演示：检测到调试接口未关闭", True
        elif n_warn and j == len(CHECK_ITEMS) - 2:
            res, msg, crit = "WARNING", "演示：磁盘可用空间低于 20% 建议阈值", False
        else:
            res, msg, crit = "PASS", "检查通过", False
        print(f"""INSERT INTO delivery_check_results (id, check_id, item_key, item_name, category,
       result, critical, message, details, created_at)
VALUES ({q(iid)}, {q(cid)}, {q(key)}, {q(name)}, {q(cat)}, {q(res)}, {str(crit).lower()},
       {q(msg)}, '{{}}'::jsonb, {ts(days, hrs - 1)})
ON CONFLICT DO NOTHING;""")

# ---------- 3.8 licenses：补 11 条导入历史（现有 1 条 ACTIVE，共 12） ----------
LICS = [
    # (license_id, 类型, 状态, 到期日, 客户)
    ("LIC-20260105-DEMO01", "TRIAL",  "SUPERSEDED", "2026-02-04", "演示客户-试用导入"),
    ("LIC-20260202-DEMO02", "TRIAL",  "EXPIRED",    "2026-03-04", "演示客户-试用到期"),
    ("LIC-20260310-DEMO03", "FORMAL", "SUPERSEDED", "2027-03-09", "演示客户-正式首签"),
    ("LIC-20260418-DEMO04", "FORMAL", "INVALID",    "2027-04-17", "演示客户-签名异常作废"),
    ("LIC-20260520-DEMO05", "FORMAL", "SUPERSEDED", "2027-05-19", "演示客户-扩容换发"),
    ("LIC-20260608-DEMO06", "FORMAL", "EXPIRED",    "2026-09-01", "演示客户-短约到期"),
    ("LIC-20260630-DEMO07", "TRIAL",  "SUPERSEDED", "2026-07-30", "演示客户-二次试用"),
    ("LIC-20260715-DEMO08", "FORMAL", "FINGERPRINT_MISMATCH", "2027-07-14", "演示客户-迁移前旧机指纹"),
    ("LIC-20260722-DEMO09", "FORMAL", "SUPERSEDED", "2027-07-21", "演示客户-机房迁移换发"),
    ("LIC-20260814-DEMO10", "FORMAL", "SUPERSEDED", "2027-08-13", "演示客户-功能增补换发"),
    ("LIC-20260901-DEMO11", "TRIAL",  "EXPIRED",    "2026-09-08", "演示客户-售前 POC"),
]
for i, (lid, ltype, st, exp, cust) in enumerate(LICS):
    rid = U("lic:%d" % i)
    payload = J({"license_id": lid, "product": "wdsp", "customer": cust, "demo": True})
    sig = H("lic-sig:" + lid)
    quotas = J({"applications": 50, "qps": 20000, "api_assets": 500})
    feats = J(["waf", "cc", "bot_challenge", "api_security", "apm"])
    print(f"""INSERT INTO licenses (id, license_id, license_type, product, customer, payload,
       signature, status, imported_by, imported_at, expires_at, perpetual,
       machine_fingerprint, quotas, features, created_at, updated_at)
VALUES ({q(rid)}, {q(lid)}, {q(ltype)}, 'wdsp', {q(cust)}, {q(payload)}::jsonb,
       {q(sig)}, {q(st)}, {q(ADMIN)}, {ts(13 - (i % 12), i + 1)}, {q(exp)}, false,
       {q(H('fp:' + lid)[:32])}, {q(quotas)}::jsonb, {q(feats)}::jsonb,
       {ts(13 - (i % 12), i + 1)}, {ts(13 - (i % 12), i + 1)})
ON CONFLICT DO NOTHING;""")

print("COMMIT;")
PYEOF
echo "  SQL 造数完成"

# ---------------------------------------------------------------------------
echo "== [4] 验证 =="
get_total() { # cookie path
  curl -s -b "$1" "$API_URL$2" | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
    data=d.get('data',{})
    print(data.get('total','ERR:'+str(d.get('code'))))
except Exception as e:
    print('PARSE_ERR')" 2>/dev/null
}

echo "  /api/v1/users              total=$(get_total "$SYS_COOKIE" '/api/v1/users?page_size=1')"
echo "  /api/v1/backups            total=$(get_total "$SYS_COOKIE" '/api/v1/backups?page_size=1')"
echo "  /api/v1/restores           total=$(get_total "$SYS_COOKIE" '/api/v1/restores?page_size=1')"
echo "  /api/v1/upgrades           total=$(get_total "$SYS_COOKIE" '/api/v1/upgrades?page_size=1')"
echo "  /api/v1/upgrade-packages   total=$(get_total "$SYS_COOKIE" '/api/v1/upgrade-packages?page_size=1')"
echo "  /api/v1/delivery-checks    total=$(get_total "$SYS_COOKIE" '/api/v1/delivery-checks?page_size=1')"
echo "  /api/v1/license/history    total=$(get_total "$SYS_COOKIE" '/api/v1/license/history?page_size=1')"

# APM 权限点挂在安全管理员（apm.*），用 sec_admin_s5 验证
sleep 2
SECV_CSRF=$(s5_login "$SEC_USER" "$SEC_PWD" || true)
if [ -n "$SECV_CSRF" ]; then
  echo "  /api/v1/apm/agents         total=$(get_total "/tmp/s5-$SEC_USER.txt" '/api/v1/apm/agents?page_size=1') （用户 $SEC_USER / SECURITY_ADMIN）"
  echo "  /api/v1/apm/services       total=$(get_total "/tmp/s5-$SEC_USER.txt" '/api/v1/apm/services?page_size=1') （用户 $SEC_USER / SECURITY_ADMIN）"
else
  echo "  ! 安全管理员登录失败（可能触发限流），稍后手工验证 apm/agents、apm/services" >&2
fi

echo "== [5] audits（AUDIT_ADMIN 用户验证） =="
ACSRF=""
for attempt in 1 2 3; do
  sleep 3
  ACSRF=$(s5_login "$AUDIT_DEMO_USER" "$DEMO_USER_PWD" || true)
  [ -n "$ACSRF" ] && break
  echo "  ! 第 $attempt 次登录失败，等待重试（登录限流）" >&2
done
if [ -n "$ACSRF" ]; then
  echo "  /api/v1/audits             total=$(get_total "/tmp/s5-$AUDIT_DEMO_USER.txt" '/api/v1/audits?page_size=1') （用户 $AUDIT_DEMO_USER / AUDIT_ADMIN）"
else
  echo "  ! 审计演示用户登录失败，请稍后手工验证 /api/v1/audits" >&2
fi

echo "== 完成 =="
