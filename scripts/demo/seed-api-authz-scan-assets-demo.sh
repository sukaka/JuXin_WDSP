#!/usr/bin/env bash
# WDSP 演示环境造数：API 授权 / 主动扫描 / 服务资产域（stage5 本地测试栈专用）。
# 覆盖接口（/api/v1/api-security 下）：
#   authz/decisions、authz/field-permissions、authz/ownership、
#   authz/relations、authz/relations/candidates、authz/role-baselines、
#   scans/targets、scans/jobs、scans/findings、service-assets、runtime-policies
#
# 幂等：确定性 UUID（uuid5）+ ON CONFLICT DO NOTHING，可重复执行。
# 数据安全：IP 仅用 RFC 5737 保留网段，域名 example.com 系，主体/对象标识全部虚构。
# 用法：bash scripts/demo/seed-api-authz-scan-assets-demo.sh
set -u
PG_CONTAINER="${PG_CONTAINER:-jiuzhang-stage5-postgres}"
PG_USER="${POSTGRES_USER:-jiuzhang}"
PG_DB="${POSTGRES_DB:-jiuzhang_waf}"

echo "============================================================"
echo "API授权/扫描/服务资产域 演示种子  db=$PG_CONTAINER/$PG_DB"
echo "============================================================"

psql_q() { docker exec "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -t -A -c "$1"; }

APP_A=$(psql_q "SELECT id FROM applications WHERE code='shop-mall' LIMIT 1;")
APP_B=$(psql_q "SELECT id FROM applications WHERE code='user-center' LIMIT 1;")
APP_C=$(psql_q "SELECT id FROM applications WHERE code='open-gw' LIMIT 1;")
APP_S5=$(psql_q "SELECT id FROM applications WHERE code='s5app' LIMIT 1;")
ADMIN_USER=$(psql_q "SELECT id FROM users WHERE username='jiuzhang_admin' LIMIT 1;")
echo "[setup] shop=$APP_A uc=$APP_B open=$APP_C s5=$APP_S5 admin=$ADMIN_USER"
[ -z "$APP_A" ] || [ -z "$ADMIN_USER" ] && { echo "ERROR: 演示应用或管理员用户不存在"; exit 1; }

APP_A="$APP_A" APP_B="$APP_B" APP_C="$APP_C" APP_S5="$APP_S5" ADMIN_USER="$ADMIN_USER" \
python3 - << 'PYEOF' | docker exec -i "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -v ON_ERROR_STOP=1 --quiet
import hashlib, json, os, uuid

NS = uuid.UUID("8f2e6c1a-9b3d-4e5f-a7c8-9d0e1f2a3b4c")
def U(key): return str(uuid.uuid5(NS, "jz-api-authz-scan-demo:" + key))
def H(s, n=64): return hashlib.sha256(s.encode()).hexdigest()[:n]
def J(o): return json.dumps(o, ensure_ascii=False, separators=(",", ":"))
def q(v): return "NULL" if v is None else "'" + str(v).replace("'", "''") + "'"

A, B, C, S5 = (os.environ[k] for k in ("APP_A", "APP_B", "APP_C", "APP_S5"))
ADMIN = os.environ["ADMIN_USER"]

def E(key, app):
    return ("(SELECT id FROM api_endpoints WHERE endpoint_key=" + q(key) +
            " AND application_id=" + q(app) + " ORDER BY created_at ASC LIMIT 1)")

# 端点 key 常量
EP_ORDERS   = "GET /v1/orders"          # shop A
EP_ORDER_M  = "POST /v1/orders/{id}"    # shop A
EP_PRODUCT  = "GET /v1/products/{id}"   # shop A
EP_INV      = "GET /v1/inventory/{id}"  # shop A
EP_PAYCB    = "POST /v1/pay/callback"   # shop A
EP_USER     = "GET /v1/users/{id}"      # uc B
EP_PROFILE  = "GET /v1/users/profile"   # uc B
EP_SESSION  = "GET /v1/sessions/{id}"   # uc B
EP_LOGIN    = "POST /v1/users/login"    # uc B
EP_TOKEN    = "POST /v1/auth/token"     # uc B
EP_LEGACY   = "GET /v1/legacy/report"   # open-gw C
EP_METRICS  = "GET /v1/metrics"         # open-gw C

OBJREF = lambda k: "objref:" + H("objref:" + k, 64)
PRINC  = lambda k: H("principal:" + k, 32)
IDFP   = lambda k: H("idfp:" + k, 32)
POLICY = "authz-v1.3"

print("BEGIN;")

# ============================================================
# 1. 授权决策 api_authorization_decisions（20 行；ALLOW/OBSERVE_VIOLATION/UNKNOWN）
# ============================================================
# (key后缀, app, endpoint_key, decision, checks, 天数前, 小时前)
DECISIONS = [
    ("d01", A, EP_ORDERS, "OBSERVE_VIOLATION", [
        {"type": "BOLA", "decision": "OBSERVE_VIOLATION", "reason_code": "AUTHZ-BOLA-001",
         "relation_state": "OTHER_OWNER", "object_type": "order", "object_ref": OBJREF("d01"),
         "policy_version": POLICY, "model_version": "mv-2026-0908"}], 1, 3),
    ("d02", A, EP_ORDERS, "ALLOW", [
        {"type": "BOLA", "decision": "ALLOW", "relation_state": "OWNER",
         "object_type": "order", "object_ref": OBJREF("d02"),
         "policy_version": POLICY, "model_version": "mv-2026-0908"}], 1, 5),
    ("d03", A, EP_ORDER_M, "OBSERVE_VIOLATION", [
        {"type": "BFLA", "decision": "OBSERVE_VIOLATION", "reason_code": "AUTHZ-BFLA-001",
         "role_source": "VERIFIED_CLAIM", "policy_version": POLICY}], 2, 2),
    ("d04", A, EP_ORDER_M, "ALLOW", [
        {"type": "BFLA", "decision": "ALLOW", "role_source": "VERIFIED_CLAIM",
         "policy_version": POLICY}], 2, 6),
    ("d05", B, EP_USER, "OBSERVE_VIOLATION", [
        {"type": "BOLA", "decision": "OBSERVE_VIOLATION", "reason_code": "AUTHZ-BOLA-001",
         "relation_state": "OTHER_OWNER", "object_type": "user", "object_ref": OBJREF("d05"),
         "policy_version": POLICY, "model_version": "mv-2026-0905"}], 3, 1),
    ("d06", B, EP_USER, "ALLOW", [
        {"type": "BOLA", "decision": "ALLOW", "relation_state": "OWNER",
         "object_type": "user", "object_ref": OBJREF("d06"), "policy_version": POLICY}], 3, 8),
    ("d07", B, EP_SESSION, "UNKNOWN", [
        {"type": "BOLA", "decision": "UNKNOWN", "reason_code": "AUTHZ-RELATION-001",
         "relation_state": "NONE", "object_type": "session", "object_ref": OBJREF("d07"),
         "policy_version": POLICY}], 4, 4),
    ("d08", B, EP_USER, "UNKNOWN", [
        {"type": "BFLA", "decision": "UNKNOWN", "reason_code": "AUTHZ-IDENTITY-001",
         "policy_version": POLICY}], 4, 9),
    ("d09", A, EP_ORDERS, "OBSERVE_VIOLATION", [
        {"type": "BOLA", "decision": "OBSERVE_VIOLATION", "reason_code": "AUTHZ-BOLA-001",
         "relation_state": "OTHER_OWNER", "object_type": "order", "object_ref": OBJREF("d09"),
         "policy_version": POLICY, "model_version": "mv-2026-0908"},
        {"type": "TENANT", "decision": "OBSERVE_VIOLATION", "reason_code": "AUTHZ-TENANT-001",
         "tenant_state": "MISMATCH", "policy_version": POLICY}], 5, 2),
    ("d10", A, EP_PRODUCT, "ALLOW", [
        {"type": "BFLA", "decision": "ALLOW", "role_source": "VERIFIED_CLAIM",
         "policy_version": POLICY}], 5, 7),
    ("d11", B, EP_PROFILE, "ALLOW", [
        {"type": "BFLA", "decision": "ALLOW", "role_source": "VERIFIED_CLAIM",
         "policy_version": POLICY}], 6, 3),
    ("d12", B, EP_SESSION, "OBSERVE_VIOLATION", [
        {"type": "BOLA", "decision": "OBSERVE_VIOLATION", "reason_code": "AUTHZ-BOLA-001",
         "relation_state": "OTHER_OWNER", "object_type": "session", "object_ref": OBJREF("d12"),
         "policy_version": POLICY, "model_version": "mv-2026-0905"}], 6, 10),
    ("d13", A, EP_INV, "ALLOW", [
        {"type": "BFLA", "decision": "ALLOW", "role_source": "VERIFIED_CLAIM",
         "policy_version": POLICY}], 7, 5),
    ("d14", A, EP_ORDERS, "OBSERVE_VIOLATION", [
        {"type": "BOLA", "decision": "OBSERVE_VIOLATION", "reason_code": "AUTHZ-BOLA-001",
         "relation_state": "OTHER_OWNER", "object_type": "order", "object_ref": OBJREF("d14"),
         "policy_version": POLICY, "model_version": "mv-2026-0908"}], 8, 2),
    ("d15", B, EP_TOKEN, "UNKNOWN", [
        {"type": "POLICY", "decision": "UNKNOWN", "reason_code": "AUTHZ-POLICY-002",
         "policy_version": POLICY}], 9, 4),
    ("d16", B, EP_USER, "OBSERVE_VIOLATION", [
        {"type": "BOLA", "decision": "OBSERVE_VIOLATION", "reason_code": "AUTHZ-BOLA-001",
         "relation_state": "OTHER_OWNER", "object_type": "user", "object_ref": OBJREF("d16"),
         "policy_version": POLICY, "model_version": "mv-2026-0905"}], 10, 6),
    ("d17", A, EP_ORDER_M, "ALLOW", [
        {"type": "BOLA", "decision": "ALLOW", "relation_state": "OWNER",
         "object_type": "order", "object_ref": OBJREF("d17"),
         "policy_version": POLICY, "model_version": "mv-2026-0908"}], 11, 3),
    ("d18", C, EP_LEGACY, "UNKNOWN", [
        {"type": "BOLA", "decision": "UNKNOWN", "reason_code": "AUTHZ-OBJECT-001",
         "relation_state": "NONE", "object_type": "report", "object_ref": OBJREF("d18"),
         "policy_version": POLICY}], 12, 8),
    ("d19", A, EP_PAYCB, "ALLOW", [
        {"type": "BFLA", "decision": "ALLOW", "role_source": "VERIFIED_CLAIM",
         "policy_version": POLICY}], 13, 2),
    ("d20", B, EP_USER, "ALLOW", [
        {"type": "BOLA", "decision": "ALLOW", "relation_state": "SHARED",
         "object_type": "user", "object_ref": OBJREF("d20"), "policy_version": POLICY}], 14, 5),
]
for key, app, ep, dec, checks, dd, hh in DECISIONS:
    print(f"""INSERT INTO api_authorization_decisions
  (id, decision_id, application_id, endpoint_key, policy_version, decision, checks, evidence, occurred_at)
VALUES ({q(U('dec:'+key))}, {q(U('decid:'+key))}, {q(app)}, {q(ep)}, {q(POLICY)}, {q(dec)},
  {q(J(checks))}::jsonb, '{{}}'::jsonb, now() - interval '{dd} days {hh} hours')
ON CONFLICT DO NOTHING;""")

# ============================================================
# 2. 字段级权限 api_field_permissions（16 行；含默认行 role/tenant=NULL）
# ============================================================
# (key, endpoint, app, field_path, direction, attribute, role, tenant, 天数前)
FIELD_PERMS = [
    ("fp01", EP_USER, B, "phone",        "RESPONSE", "SENSITIVE",      "user",    None,      1),
    ("fp02", EP_USER, B, "phone",        "RESPONSE", "READABLE",       "admin",   None,      1),
    ("fp03", EP_USER, B, "phone",        "RESPONSE", "FORBIDDEN",      "partner", None,      2),
    ("fp04", EP_USER, B, "id_card",      "RESPONSE", "SENSITIVE",      "admin",   None,      2),
    ("fp05", EP_USER, B, "id_card",      "RESPONSE", "FORBIDDEN",      "user",    None,      3),
    ("fp06", EP_USER, B, "id_card",      "RESPONSE", "FORBIDDEN",      None,      None,      3),   # 默认行
    ("fp07", EP_USER, B, "email",        "RESPONSE", "SENSITIVE",      "user",    None,      4),
    ("fp08", EP_USER, B, "email",        "RESPONSE", "READABLE",       "admin",   None,      4),
    ("fp09", EP_PROFILE, B, "phone",     "RESPONSE", "SENSITIVE",      "user",    None,      5),
    ("fp10", EP_PROFILE, B, "id_card",   "RESPONSE", "FORBIDDEN",      "user",    None,      5),
    ("fp11", EP_ORDER_M, A, "remark",       "REQUEST",  "WRITABLE",       "user",    None,      6),
    ("fp12", EP_ORDER_M, A, "internal_note","REQUEST",  "ADMIN_WRITABLE", "admin",  None,      6),
    ("fp13", EP_ORDER_M, A, "internal_note","REQUEST",  "FORBIDDEN",      "user",    None,      7),
    ("fp14", EP_ORDERS, A, "buyer_phone",   "RESPONSE", "SENSITIVE",      "user",    None,      8),
    ("fp15", EP_ORDERS, A, "buyer_phone",   "RESPONSE", "READABLE",       "admin",   None,      9),
    ("fp16", EP_ORDERS, A, "payment_token", "RESPONSE", "SENSITIVE",      "admin",   None,      10),
]
for key, ep, app, fpath, direc, attr, role, tenant, dd in FIELD_PERMS:
    print(f"""INSERT INTO api_field_permissions
  (id, endpoint_id, field_path, direction, attribute, role, tenant, created_by, created_at, updated_at)
VALUES ({q(U(key))}, {E(ep, app)}, {q(fpath)}, {q(direc)}, {q(attr)}, {q(role)}, {q(tenant)},
  'sec_admin_s5', now() - interval '{dd} days', now() - interval '{dd} days')
ON CONFLICT DO NOTHING;""")

# ============================================================
# 3. 对象归属 api_object_ownership（14 行：订单/用户/会话）
# ============================================================
OWNERSHIP = (
    [(f"own-o{i:02d}", EP_ORDERS, A, "order", f"ord-2026{90-i:02d}1{i:04d}", IDFP(f"buyer-{i}"),
      14 - i, i % 3, 3 + i * 2) for i in range(6)] +
    [(f"own-u{i:02d}", EP_USER, B, "user", f"u-10{80+i}", IDFP(f"self-{i}"),
      12 - i, i % 2, 2 + i) for i in range(4)] +
    [(f"own-s{i:02d}", EP_SESSION, B, "session", f"sess-{H(str(i),8)}", IDFP(f"sess-{i}"),
      10 - i, 0, 1 + i) for i in range(4)]
)
for key, ep, app, otype, oid, fp, first_d, last_d, cnt in OWNERSHIP:
    print(f"""INSERT INTO api_object_ownership
  (id, endpoint_id, identity_fingerprint, object_type, object_id, first_seen, last_seen, access_count)
VALUES ({q(U(key))}, {E(ep, app)}, {q(fp)}, {q(otype)}, {q(oid)},
  now() - interval '{first_d} days', now() - interval '{last_d} hours', {cnt})
ON CONFLICT DO NOTHING;""")

# ============================================================
# 4. 对象授权关系 api_object_relations（14 行：OWNER/SHARED_WITH/DELEGATED_TO/SUPPORT_ACCESS）
# ============================================================
# (key, app, object_type, principal, tenant, relation, source, status, 有效起始天前, 有效截止天后或None)
RELATIONS = [
    ("rel01", A, "order",   "buyer-01",  "tenant-a", "OWNER",          "CREATE_BINDING", "CONFIRMED", 13, None),
    ("rel02", A, "order",   "buyer-02",  "tenant-a", "OWNER",          "CREATE_BINDING", "CONFIRMED", 12, None),
    ("rel03", A, "order",   "buyer-03",  "tenant-b", "OWNER",          "IMPORT",         "CONFIRMED", 12, None),
    ("rel04", A, "order",   "buyer-04",  "tenant-a", "OWNER",          "MANUAL",         "CONFIRMED", 11, None),
    ("rel05", B, "user",    "self-01",   "tenant-a", "OWNER",          "CREATE_BINDING", "CONFIRMED", 11, None),
    ("rel06", B, "user",    "self-02",   "tenant-b", "OWNER",          "IMPORT",         "CONFIRMED", 10, None),
    ("rel07", B, "session", "sess-01",   "tenant-a", "OWNER",          "CREATE_BINDING", "CONFIRMED", 9,  None),
    ("rel08", B, "session", "sess-02",   "tenant-a", "OWNER",          "CREATE_BINDING", "CONFIRMED", 9,  None),
    ("rel09", A, "order",   "cs-agent-1","tenant-a", "SUPPORT_ACCESS", "MANUAL",         "CONFIRMED", 8,  7),
    ("rel10", A, "order",   "partner-ops","tenant-b","SHARED_WITH",    "MANUAL",         "CONFIRMED", 7,  20),
    ("rel11", B, "user",    "auditor-01",None,       "SHARED_WITH",    "MANUAL",         "CONFIRMED", 6,  15),
    ("rel12", A, "order",   "delegate-01","tenant-a","DELEGATED_TO",   "MANUAL",         "CONFIRMED", 5,  10),
    ("rel13", A, "order",   "buyer-09",  "tenant-a", "OWNER",          "MANUAL",         "REVOKED",   4,  None),
    ("rel14", B, "user",    "self-09",   "tenant-b", "OWNER",          "IMPORT",         "EXPIRED",   13, -1),
]
for key, app, otype, principal, tenant, relation, source, status, start_d, until_d in RELATIONS:
    oref = OBJREF("rel:" + key)
    if until_d is None:
        valid_until = "NULL"
    elif until_d < 0:
        valid_until = f"now() - interval '{-until_d} days'"
    else:
        valid_until = f"now() + interval '{until_d} days'"
    print(f"""INSERT INTO api_object_relations
  (id, application_id, object_type, object_ref, principal_id, tenant_id, relation, source, status,
   valid_from, valid_until, evidence_ref, confirmed_by, confirmed_at, reason, created_at, updated_at)
VALUES ({q(U(key))}, {q(app)}, {q(otype)}, {q(oref)}, {q(PRINC(principal))}, {q(tenant)},
  {q(relation)}, {q(source)}, {q(status)}, now() - interval '{start_d} days', {valid_until},
  {q('demo-evidence://' + key)}, 'sec_admin_s5', now() - interval '{start_d} days',
  {q('演示：' + otype + ' ' + relation.lower() + ' 关系确认')},
  now() - interval '{start_d} days', now() - interval '{start_d} days')
ON CONFLICT DO NOTHING;""")

# ============================================================
# 5. 关系候选 api_object_relation_candidates（13 行：PENDING×9 REJECTED×2 FROZEN×1 CONFIRMED×1）
# ============================================================
# (key, app, endpoint, object_type, verified_principal_or_None, legacy_fp_or_None, status, 天数前, obs)
CANDIDATES = [
    ("cand01", A, EP_ORDERS,  "order",   "buyer-11",    None,           "PENDING",   1, 12),
    ("cand02", A, EP_ORDERS,  "order",   "buyer-12",    None,           "PENDING",   2, 8),
    ("cand03", A, EP_ORDER_M, "order",   "buyer-13",    None,           "PENDING",   2, 5),
    ("cand04", B, EP_USER,    "user",    "self-11",     None,           "PENDING",   3, 20),
    ("cand05", B, EP_USER,    "user",    "self-12",     None,           "PENDING",   4, 6),
    ("cand06", B, EP_SESSION, "session", "sess-11",     None,           "PENDING",   5, 9),
    ("cand07", A, EP_ORDERS,  "order",   None,          "legacy-ip-1",  "PENDING",   6, 4),
    ("cand08", B, EP_USER,    "user",    None,          "legacy-ip-2",  "PENDING",   7, 3),
    ("cand09", A, EP_ORDER_M, "order",   None,          "legacy-dev-1", "PENDING",   8, 2),
    ("cand10", A, EP_ORDERS,  "order",   "buyer-19",    None,           "REJECTED",  9, 15),
    ("cand11", B, EP_SESSION, "session", None,          "legacy-ip-9",  "REJECTED",  10, 7),
    ("cand12", A, EP_ORDERS,  "order",   "buyer-21",    None,           "FROZEN",    11, 30),
    ("cand13", B, EP_USER,    "user",    "self-21",     None,           "CONFIRMED", 12, 42),
]
for key, app, ep, otype, principal, legacy, status, dd, obs in CANDIDATES:
    pid = q(PRINC(principal)) if principal else "NULL"
    lfp = q(IDFP(legacy)) if legacy else "NULL"
    reviewed = ("'sec_admin_s5', now() - interval '%d days'" % (dd - 1)) if status in ("REJECTED", "CONFIRMED") else "NULL, NULL"
    reject = q("观测来源与既有 OWNER 冲突，人工驳回") if status == "REJECTED" else "NULL"
    conf = J({"observation_count": obs, "distinct_days": min(obs, 7), "identity_domain": "VERIFIED" if principal else "LEGACY"})
    print(f"""INSERT INTO api_object_relation_candidates
  (id, application_id, endpoint_id, object_type, object_ref, principal_id, tenant_id,
   legacy_identity_fingerprint, source, status, source_count, observation_count,
   first_seen, last_seen, confidence_inputs, evidence_ref, reject_reason, reviewed_by, reviewed_at,
   created_at, updated_at)
VALUES ({q(U(key))}, {q(app)}, {E(ep, app)}, {q(otype)}, {q(OBJREF('cand:'+key))}, {pid},
  {q('tenant-a' if app == A else 'tenant-b')}, {lfp}, 'OBSERVED_ACCESS', {q(status)}, 1, {obs},
  now() - interval '{dd} days', now() - interval '{dd-1} days',
  {q(conf)}::jsonb, {q('demo-evidence://' + key)}, {reject}, {reviewed},
  now() - interval '{dd} days', now() - interval '{dd-1} days')
ON CONFLICT DO NOTHING;""")

# ============================================================
# 6. 角色基线 api_role_baselines（14 行，全部 confirmed=true，合法 source/assurance）
# ============================================================
# (key, endpoint, app, role, method, action, allowed, source, confidence, assurance, 天数前)
ROLE_BASELINES = [
    ("rb01", EP_USER,    B, "user",    "GET",  "READ",  True,  "SPEC",     0.980, "VERIFIED", 1),
    ("rb02", EP_USER,    B, "admin",   "GET",  "READ",  True,  "SPEC",     0.990, "VERIFIED", 1),
    ("rb03", EP_USER,    B, "partner", "GET",  "READ",  False, "MANUAL",   1.000, "VERIFIED", 2),
    ("rb04", EP_ORDERS,  A, "user",    "GET",  "READ",  True,  "SPEC",     0.950, "VERIFIED", 2),
    ("rb05", EP_ORDERS,  A, "partner", "GET",  "READ",  True,  "OBSERVED", 0.860, "OBSERVED", 3),
    ("rb06", EP_ORDERS,  A, "admin",   "GET",  "READ",  True,  "SPEC",     0.990, "VERIFIED", 3),
    ("rb07", EP_ORDER_M, A, "user",    "POST", "WRITE", True,  "SPEC",     0.940, "VERIFIED", 4),
    ("rb08", EP_ORDER_M, A, "partner", "POST", "WRITE", False, "MANUAL",   1.000, "VERIFIED", 4),
    ("rb09", EP_ORDER_M, A, "admin",   "POST", "WRITE", True,  "SPEC",     0.990, "VERIFIED", 5),
    ("rb10", EP_TOKEN,   B, "partner", "POST", "WRITE", True,  "IMPORTED", 0.820, "VERIFIED", 6),
    ("rb11", EP_INV,     A, "partner", "GET",  "READ",  True,  "OBSERVED", 0.780, "OBSERVED", 7),
    ("rb12", EP_INV,     A, "user",    "GET",  "READ",  False, "MANUAL",   1.000, "VERIFIED", 8),
    ("rb13", EP_INV,     A, "admin",   "GET",  "READ",  True,  "SPEC",     0.970, "VERIFIED", 9),
    ("rb14", EP_LEGACY,  C, "admin",   "GET",  "READ",  True,  "MANUAL",   0.900, "VERIFIED", 10),
]
for key, ep, app, role, method, action, allowed, source, conf, assurance, dd in ROLE_BASELINES:
    print(f"""INSERT INTO api_role_baselines
  (id, endpoint_id, role, method, action, allowed, source, confidence, confirmed,
   created_by, identity_assurance, created_at, updated_at)
VALUES ({q(U(key))}, {E(ep, app)}, {q(role)}, {q(method)}, {q(action)}, {str(allowed).lower()},
  {q(source)}, {conf}, true, 'sec_admin_s5', {q(assurance)},
  now() - interval '{dd} days', now() - interval '{dd} days')
ON CONFLICT DO NOTHING;""")

# ============================================================
# 7. 服务资产：补充 DISABLED 源站（不参与发布/健康检查），使 host:port 视角 ≥12
# ============================================================
# (key, app, host, port, 天数前)
EXTRA_UPSTREAMS = [
    ("up01", A,  "192.0.2.21",    8080, 12),
    ("up02", A,  "192.0.2.22",    8080, 11),
    ("up03", A,  "192.0.2.23",    9090, 10),
    ("up04", A,  "198.51.100.21", 8443, 9),
    ("up05", B,  "192.0.2.31",    8080, 9),
    ("up06", B,  "192.0.2.32",    8443, 8),
    ("up07", B,  "198.51.100.31", 9000, 7),
    ("up08", C,  "203.0.113.21",  8080, 6),
    ("up09", C,  "203.0.113.22",  9443, 5),
    ("up10", C,  "198.51.100.41", 8000, 4),
    ("up11", S5, "192.0.2.41",    8080, 3),
]
for key, app, host, port, dd in EXTRA_UPSTREAMS:
    print(f"""INSERT INTO upstreams
  (id, application_id, name, scheme, host, normalized_host, port, weight, priority, status,
   health_check_enabled, created_by, created_at, updated_by, updated_at)
VALUES ({q(U(key))}, {q(app)}, {q('demo-svc-' + key)}, 'http', {q(host)}, {q(host)}, {port},
  0, 99, 'DISABLED', false, {q(ADMIN)}, now() - interval '{dd} days',
  {q(ADMIN)}, now() - interval '{dd} days')
ON CONFLICT DO NOTHING;""")

# ============================================================
# 8. 主动扫描：目标×12 → 授权×12 → 任务×14 → 发现×18
# ============================================================
# (key, app, name, base_url, allowed_paths, status, 天数前)
TARGETS = [
    ("t01", A,  "商城生产环境",     "https://shop.example.com",          ["/v1/orders", "/v1/products", "/v1/cart"],   "ENABLED",  13),
    ("t02", A,  "商城预发环境",     "https://shop-staging.example.com",  ["/v1/orders", "/v1/products"],                 "ENABLED",  12),
    ("t03", A,  "商城开放接口",     "https://shop-api.example.com",      ["/v1/inventory", "/v1/pay"],                   "DISABLED", 11),
    ("t04", B,  "用户中心生产",     "https://uc.example.com",            ["/v1/users", "/v1/sessions"],                  "ENABLED",  11),
    ("t05", B,  "用户中心预发",     "https://uc-staging.example.com",    ["/v1/users"],                                  "ENABLED",  10),
    ("t06", B,  "用户中心认证域",   "https://uc-auth.example.com",       ["/v1/auth", "/v1/users/login"],                "ENABLED",  10),
    ("t07", C,  "开放网关生产",     "https://open.example.com",          ["/v1/metrics", "/v1/webhook"],                 "ENABLED",  9),
    ("t08", C,  "开放网关预发",     "https://open-staging.example.com",  ["/v1/metrics"],                                "ENABLED",  8),
    ("t09", C,  "开放网关伙伴域",   "https://open-partner.example.com",  ["/v1/legacy"],                                 "DISABLED", 8),
    ("t10", S5, "S5 测试应用主域",  "https://s5-main.example.com",       ["/v1/sitecheck"],                              "ENABLED",  7),
    ("t11", S5, "S5 测试应用灰度",  "https://s5-gray.example.com",       ["/v1/sitecheck"],                              "ENABLED",  6),
    ("t12", S5, "S5 测试应用旁路",  "https://s5-mirror.example.com",     ["/v1/sitecheck"],                              "ENABLED",  5),
]
ALL_PROBES = ["AUTH_REQUIRED", "DEPRECATED_ALIVE", "SENSITIVE_EXPOSURE",
              "SCHEMA_CONFORM", "BOLA_COMPARE", "METHOD_ENUM"]
for key, app, name, url, paths, status, dd in TARGETS:
    print(f"""INSERT INTO api_scan_targets (id, application_id, name, base_url, allowed_paths, status, created_by, created_at, updated_at)
VALUES ({q(U('scan-target:'+key))}, {q(app)}, {q(name)}, {q(url)}, {q(J(paths))}::jsonb, {q(status)},
  {q(ADMIN)}, now() - interval '{dd} days', now() - interval '{dd} days')
ON CONFLICT DO NOTHING;""")
    # 每目标一张授权单；t03/t09 已撤销
    revoked = "now() - interval '1 days'" if key in ("t03", "t09") else "NULL"
    profile = ",".join(ALL_PROBES[:4] if key in ("t03", "t09") else ALL_PROBES)
    print(f"""INSERT INTO api_scan_authorizations
  (id, target_id, authorized_by, allowlist, time_window, max_qps, max_concurrency, test_profile,
   expires_at, revoked_at, created_at)
VALUES ({q(U('scan-authz:'+key))}, {q(U('scan-target:'+key))}, {q(ADMIN)},
  {q(J(ALL_PROBES))}::jsonb, '{{}}'::jsonb, 5, 1, {q(profile)},
  now() + interval '30 days', {revoked}, now() - interval '{dd} days')
ON CONFLICT DO NOTHING;""")

# (key, target, probe_set, status, 创建天前, 进行小时, findings数)
JOBS = [
    ("j01", "t01", "BOLA_COMPARE",       "COMPLETED", 10, 3, 6),
    ("j02", "t01", "SENSITIVE_EXPOSURE", "COMPLETED", 7,  2, 4),
    ("j03", "t01", "AUTH_REQUIRED",      "COMPLETED", 4,  2, 2),
    ("j04", "t02", "SCHEMA_CONFORM",     "COMPLETED", 6,  4, 2),
    ("j05", "t04", "BOLA_COMPARE",       "COMPLETED", 8,  3, 3),
    ("j06", "t04", "SENSITIVE_EXPOSURE", "COMPLETED", 5,  2, 1),
    ("j07", "t06", "AUTH_REQUIRED",      "COMPLETED", 3,  2, 0),
    ("j08", "t07", "METHOD_ENUM",        "COMPLETED", 9,  2, 1),
    ("j09", "t02", "DEPRECATED_ALIVE",   "COMPLETED", 12, 5, 0),
    ("j10", "t05", "BOLA_COMPARE",       "FAILED",     2,  1, 0),
    ("j11", "t01", "BOLA_COMPARE",       "RUNNING",   0,  1, 0),
    ("j12", "t04", "SCHEMA_CONFORM",     "PAUSED",    1,  6, 0),
    ("j13", "t08", "METHOD_ENUM",        "COMPLETED", 13, 2, 0),
    ("j14", "t10", "AUTH_REQUIRED",      "PENDING",   0,  0, 0),
]
for key, tkey, probe, status, dd, hours, nfind in JOBS:
    total_ep, done_ep = 24, 24 if status == "COMPLETED" else (10 if status == "RUNNING" else (14 if status == "PAUSED" else (5 if status == "FAILED" else 0)))
    progress = {"total": total_ep, "done": done_ep, "requests": done_ep * 6,
                "findings": nfind, "errors": 1 if status == "FAILED" else 0}
    if status == "FAILED":
        progress["last_error"] = "target connection timeout after 3 retries"
    started = "NULL" if status == "PENDING" else f"now() - interval '{dd} days {hours} hours'"
    finished = f"now() - interval '{dd} days'" if status in ("COMPLETED", "FAILED") else "NULL"
    print(f"""INSERT INTO api_scan_jobs
  (id, target_id, authorization_id, probe_set, status, progress, started_at, finished_at, created_by, created_at)
VALUES ({q(U('scan-job:'+key))}, {q(U('scan-target:'+tkey))}, {q(U('scan-authz:'+tkey))}, {q(probe)},
  {q(status)}, {q(J(progress))}::jsonb, {started}, {finished}, {q(ADMIN)}, now() - interval '{dd} days {hours+1} hours')
ON CONFLICT DO NOTHING;""")

# 发现（主要落在商城生产 t01 的 j01/j02/j03；request/response 样本全部脱敏虚构）
# (key, job, template, endpoint_key, category, severity, confidence, status, 天数前, evidence, req, resp)
FINDINGS = [
    ("f01", "j01", "BOLA_COMPARE", EP_ORDERS,  "AUTHZ",   "HIGH",     0.92, "CONFIRMED",      10,
     {"probe": "adjacent_object_compare", "object_pair": ["ord-a", "ord-b"], "status_codes": [200, 200]},
     "GET /v1/orders/ord-a HTTP/1.1\nHost: shop.example.com\nAuthorization: Bearer <redacted>",
     "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"order_id\":\"ord-a\",\"amount\":199.00}"),
    ("f02", "j01", "BOLA_COMPARE", EP_ORDERS,  "AUTHZ",   "HIGH",     0.88, "NEW",            10,
     {"probe": "adjacent_object_compare", "object_pair": ["ord-b", "ord-c"], "status_codes": [200, 200]},
     "GET /v1/orders/ord-b HTTP/1.1\nHost: shop.example.com\nAuthorization: Bearer <redacted>",
     "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"order_id\":\"ord-b\",\"amount\":58.50}"),
    ("f03", "j01", "BOLA_COMPARE", EP_ORDER_M, "AUTHZ",   "MEDIUM",   0.74, "NEW",            10,
     {"probe": "adjacent_object_compare", "object_pair": ["ord-c", "ord-d"], "status_codes": [403, 200]},
     "POST /v1/orders/ord-c HTTP/1.1\nHost: shop.example.com\nAuthorization: Bearer <redacted>",
     "HTTP/1.1 403 Forbidden\nContent-Type: application/json\n\n{\"error\":\"forbidden\"}"),
    ("f04", "j01", "BOLA_COMPARE", EP_ORDERS,  "AUTHZ",   "MEDIUM",   0.66, "FALSE_POSITIVE", 9,
     {"probe": "adjacent_object_compare", "note": "对象属同一主体，差异由订单状态引起"},
     "GET /v1/orders/ord-e HTTP/1.1\nHost: shop.example.com", "HTTP/1.1 200 OK"),
    ("f05", "j01", "BOLA_COMPARE", EP_ORDERS,  "AUTHZ",   "LOW",      0.51, "NEW",            9,
     {"probe": "adjacent_object_compare", "status_codes": [404, 200]},
     "GET /v1/orders/ord-f HTTP/1.1\nHost: shop.example.com", "HTTP/1.1 404 Not Found"),
    ("f06", "j01", "BOLA_COMPARE", EP_PRODUCT, "AUTHZ",   "INFO",     0.40, "RETIRED",        9,
     {"probe": "adjacent_object_compare"}, "GET /v1/products/p-1 HTTP/1.1", "HTTP/1.1 200 OK"),
    ("f07", "j02", "SENSITIVE_EXPOSURE", EP_ORDERS,  "SENSITIVE", "HIGH",   0.95, "CONFIRMED", 7,
     {"exposed_fields": ["buyer_phone", "payment_token"], "endpoint": EP_ORDERS},
     "GET /v1/orders HTTP/1.1\nHost: shop.example.com",
     "HTTP/1.1 200 OK\n\n{\"items\":[{\"buyer_phone\":\"<redacted>\",\"payment_token\":\"<redacted>\"}]}"),
    ("f08", "j02", "SENSITIVE_EXPOSURE", EP_PRODUCT, "SENSITIVE", "MEDIUM", 0.81, "NEW",       7,
     {"exposed_fields": ["supplier_cost"], "endpoint": EP_PRODUCT},
     "GET /v1/products/p-2 HTTP/1.1\nHost: shop.example.com",
     "HTTP/1.1 200 OK\n\n{\"sku\":\"p-2\",\"supplier_cost\":\"<redacted>\"}"),
    ("f09", "j02", "SENSITIVE_EXPOSURE", EP_INV,     "SENSITIVE", "LOW",    0.60, "NEW",       7,
     {"exposed_fields": ["warehouse_code"]},
     "GET /v1/inventory/wh-1 HTTP/1.1\nHost: shop.example.com", "HTTP/1.1 200 OK"),
    ("f10", "j02", "SENSITIVE_EXPOSURE", EP_ORDERS,  "SENSITIVE", "INFO",   0.35, "FALSE_POSITIVE", 6,
     {"exposed_fields": ["trace_id"], "note": "trace_id 非敏感"},
     "GET /v1/orders HTTP/1.1", "HTTP/1.1 200 OK"),
    ("f11", "j03", "AUTH_REQUIRED", EP_PAYCB, "AUTHN", "CRITICAL", 0.97, "CONFIRMED", 4,
     {"unauthenticated_status": 200, "expected": "401/403", "endpoint": EP_PAYCB},
     "POST /v1/pay/callback HTTP/1.1\nHost: shop.example.com\nContent-Type: application/json\n\n{\"sign\":\"<redacted>\"}",
     "HTTP/1.1 200 OK\n\n{\"result\":\"accepted\"}"),
    ("f12", "j03", "AUTH_REQUIRED", EP_ORDER_M, "AUTHN", "MEDIUM",  0.70, "NEW", 4,
     {"unauthenticated_status": 200, "endpoint": EP_ORDER_M},
     "POST /v1/orders/ord-g HTTP/1.1\nHost: shop.example.com", "HTTP/1.1 200 OK"),
    ("f13", "j04", "SCHEMA_CONFORM", EP_ORDER_M, "SCHEMA", "MEDIUM", 0.72, "NEW", 6,
     {"violation": "quantity=-1 accepted", "expected": "reject out-of-range"},
     "POST /v1/orders/ord-h HTTP/1.1\n\n{\"quantity\":-1}", "HTTP/1.1 200 OK"),
    ("f14", "j04", "SCHEMA_CONFORM", EP_ORDERS,  "SCHEMA", "LOW",    0.55, "NEW", 6,
     {"violation": "oversized page_size accepted"},
     "GET /v1/orders?page_size=100000 HTTP/1.1", "HTTP/1.1 200 OK"),
    ("f15", "j05", "BOLA_COMPARE", EP_USER,    "AUTHZ", "HIGH",   0.90, "CONFIRMED", 8,
     {"probe": "adjacent_object_compare", "object_pair": ["u-1001", "u-1002"], "status_codes": [200, 200]},
     "GET /v1/users/u-1001 HTTP/1.1\nHost: uc.example.com\nAuthorization: Bearer <redacted>",
     "HTTP/1.1 200 OK\n\n{\"user_id\":\"u-1001\",\"phone\":\"<redacted>\"}"),
    ("f16", "j05", "BOLA_COMPARE", EP_SESSION, "AUTHZ", "MEDIUM", 0.69, "NEW", 8,
     {"probe": "adjacent_object_compare", "status_codes": [200, 403]},
     "GET /v1/sessions/sess-x HTTP/1.1\nHost: uc.example.com", "HTTP/1.1 200 OK"),
    ("f17", "j05", "BOLA_COMPARE", EP_USER,    "AUTHZ", "LOW",    0.48, "NEW", 7,
     {"probe": "adjacent_object_compare"}, "GET /v1/users/u-1003 HTTP/1.1", "HTTP/1.1 404 Not Found"),
    ("f18", "j06", "SENSITIVE_EXPOSURE", EP_PROFILE, "SENSITIVE", "MEDIUM", 0.77, "NEW", 5,
     {"exposed_fields": ["id_card"], "endpoint": EP_PROFILE},
     "GET /v1/users/profile HTTP/1.1\nHost: uc.example.com\nAuthorization: Bearer <redacted>",
     "HTTP/1.1 200 OK\n\n{\"name\":\"<redacted>\",\"id_card\":\"<redacted>\"}"),
    ("f19", "j08", "METHOD_ENUM", EP_LEGACY, "LIFECYCLE", "LOW", 0.62, "NEW", 9,
     {"allowed_methods": ["GET", "HEAD", "TRACE"], "unexpected": ["TRACE"]},
     "OPTIONS /v1/legacy/report HTTP/1.1\nHost: open.example.com",
     "HTTP/1.1 204 No Content\nAllow: GET, HEAD, TRACE"),
]
for key, job, tpl, ep, cat, sev, confd, status, dd, ev, req, resp in FINDINGS:
    print(f"""INSERT INTO api_scan_findings
  (id, job_id, engine, template, endpoint_key, category, severity, confidence,
   evidence_json, request_sample, response_sample, status, weakness_id, created_at)
VALUES ({q(U('scan-finding:'+key))}, {q(U('scan-job:'+job))}, 'builtin', {q(tpl)}, {q(ep)}, {q(cat)},
  {q(sev)}, {confd}, {q(J(ev))}::jsonb, {q(req)}, {q(resp)}, {q(status)}, NULL,
  now() - interval '{dd} days')
ON CONFLICT DO NOTHING;""")

# ============================================================
# 9. 运行时策略 api_runtime_policies（+11 行 → 共 13）
# ============================================================
# (key, endpoint_id, model_version_id, runtime_version, status, 天数前)
RUNTIME_POLICIES = [
    ("rp01", "45d46d74-d6c4-5291-8f39-ab7682e38f5e", "47aaa80d-9e55-5f59-9e9a-5c516c5d9600", "v1", "ACTIVE",    9,  EP_ORDER_M, "POST", "/v1/orders/{id}"),
    ("rp02", "6a2716d1-fb01-5110-8be1-c9b083bb41c8", "4bc6fbdb-e02c-5556-8d97-d11d497e39d1", "v1", "ACTIVE",    8,  EP_USER,    "GET",  "/v1/users/{id}"),
    ("rp03", "6a2716d1-fb01-5110-8be1-c9b083bb41c8", "bd4fdd6e-00bb-51b0-ad15-5e953d301e17", "v2", "PUBLISHED", 3,  EP_USER,    "GET",  "/v1/users/{id}"),
    ("rp04", "8f729cf6-adcf-55fb-8fa5-f1bef61e8860", "2508436c-73f9-518d-aa72-51537b6def5a", "v1", "ACTIVE",    7,  EP_LOGIN,   "POST", "/v1/users/login"),
    ("rp05", "898e5aad-ccc2-5c01-88b8-3a9033d11de9", "1b741f02-59f0-53db-a9d5-18f9539d0f82", "v1", "ACTIVE",    6,  EP_ORDERS,  "GET",  "/v1/orders"),
    ("rp06", "06a05f4e-517c-5efd-bf5c-cfe8f39dfd78", "ab7b32d0-6699-56f4-b105-9aa8d5846dc0", "v1", "ACTIVE",    6,  EP_PAYCB,   "POST", "/v1/pay/callback"),
    ("rp07", "d6588c56-7755-53fa-9450-643727771a8f", "a69a3fec-f0ba-50c9-bd7a-de21faddacc4", "v1", "VALIDATED", 5,  EP_TOKEN,   "POST", "/v1/auth/token"),
    ("rp08", "4a9eda6d-7417-5d57-b312-f2ba49764e63", "51cddd3d-d92d-5b1d-86b8-e8a879b70d05", "v1", "PUBLISHED", 4,  EP_PRODUCT, "GET",  "/v1/products/{id}"),
    ("rp09", "c0b7cf35-bb84-561e-98b5-99d0527d4db3", "b1ee6302-0529-55f7-85dc-b8cfab7c2955", "v1", "DRAFT",     2,  EP_LEGACY,  "GET",  "/v1/legacy/report"),
    ("rp10", "2514e082-07a1-4af7-80a3-c70646a52a3d", "5cac918e-18ad-4bd9-816f-54969c51651e", "v2", "DRAFT",     1,  EP_ORDER_M, "POST", "/v1/orders/{id}"),
    ("rp11", "012b369c-5f3a-4066-b685-23653c5ea8f2", "b4ece3db-7486-4d45-9708-0601e18635f5", "v2", "VALIDATED", 1,  EP_USER,    "GET",  "/v1/users/{id}"),
]
for key, ep_id, mv_id, rver, status, dd, epkey, method, npath in RUNTIME_POLICIES:
    content = {"method": method, "endpoint_key": epkey, "normalized_path": npath,
               "content_type": "application/json", "compiler_version": "v1",
               "lifecycle": "CONFIRMED", "auth_requirement": None,
               "parameter_constraints": [], "response_schema": None, "request_schema": None}
    chash = H("policy:" + key + ":" + J(content), 64)
    published = f"now() - interval '{max(dd-1,0)} days'" if status in ("PUBLISHED", "ACTIVE") else "NULL"
    activated = f"now() - interval '{max(dd-1,0)} days'" if status == "ACTIVE" else "NULL"
    print(f"""INSERT INTO api_runtime_policies
  (id, endpoint_id, source_model_version_id, runtime_version, compiler_version, content_json, content_hash,
   status, error, created_at, published_at, activated_at)
VALUES ({q(U(key))}, {q(ep_id)}, {q(mv_id)}, {q(rver)}, 'v1', {q(J(content))}::jsonb, {q(chash)},
  {q(status)}, '', now() - interval '{dd} days', {published}, {activated})
ON CONFLICT DO NOTHING;""")

print("COMMIT;")
PYEOF

echo "[done] SQL 执行完成，开始统计："
psql_q "SELECT 'decisions='||count(*) FROM api_authorization_decisions;"
psql_q "SELECT 'field_permissions='||count(*) FROM api_field_permissions;"
psql_q "SELECT 'ownership='||count(*) FROM api_object_ownership;"
psql_q "SELECT 'relations='||count(*) FROM api_object_relations;"
psql_q "SELECT 'candidates='||count(*) FROM api_object_relation_candidates;"
psql_q "SELECT 'role_baselines='||count(*) FROM api_role_baselines;"
psql_q "SELECT 'scan_targets='||count(*) FROM api_scan_targets;"
psql_q "SELECT 'scan_jobs='||count(*) FROM api_scan_jobs;"
psql_q "SELECT 'scan_findings='||count(*) FROM api_scan_findings;"
psql_q "SELECT 'service_assets='||count(*) FROM (SELECT 1 FROM upstreams WHERE deleted_at IS NULL GROUP BY normalized_host, port) t;"
psql_q "SELECT 'runtime_policies='||count(*) FROM api_runtime_policies;"
echo "============================================================"
