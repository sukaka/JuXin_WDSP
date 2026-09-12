#!/usr/bin/env bash
# 阶段8 演示数据补充种子（开发/演示环境）：攻击活动故事线 + 数据规模补齐。
# 前置：已执行 test/waf/scripts/stage8-seed-demo.sh（建立演示应用/端点/模型基线）。
#
# 内容：
#   1. 6 组攻击活动（attack_session 由服务端聚合器 60s 一轮真实聚合产出）：
#      每组 = client_identity 攻击者身份 + identity_behavior_events 主锚 +
#      api_runtime_events / security_events（经 request_id 关联归属）。
#      C1 完整杀伤链：接口探测→登录尝试→Token异常→ID遍历→越权读订单→批量导出→WDSP阻断。
#   2. 规模补齐：安全事件 ~90、运行时事件 +78、学习样本 +126、参数模型 +25、
#      Schema 违例 +6、调用边 +10、风险发现 +8（批量赋值/响应侧/行为异常）。
#
# 幂等：确定性 UUID（uuid5）+ ON CONFLICT DO NOTHING。
# 数据安全：IP 仅用 RFC 5737 保留网段，域名 example.com，姓名/手机号等全部虚构。
# 用法：bash test/waf/scripts/stage8-seed-attack-demo.sh
set -u
PG_CONTAINER="${PG_CONTAINER:-jiuzhang-stage5-postgres}"
PG_USER="${POSTGRES_USER:-jiuzhang}"
PG_DB="${POSTGRES_DB:-jiuzhang_waf}"

echo "============================================================"
echo "阶段8 演示补充种子（攻击活动+规模）  db=$PG_CONTAINER/$PG_DB"
echo "============================================================"

# ---------- 应用/域名 ID（按 code 直查，幂等） ----------
read APP_A DOM_A <<< "$(docker exec "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -t -A -c \
  "SELECT a.id, d.id FROM applications a JOIN application_domains d ON d.application_id=a.id WHERE a.code='shop-mall' LIMIT 1;" | tr '|' ' ')"
read APP_B DOM_B <<< "$(docker exec "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -t -A -c \
  "SELECT a.id, d.id FROM applications a JOIN application_domains d ON d.application_id=a.id WHERE a.code='user-center' LIMIT 1;" | tr '|' ' ')"
read APP_C DOM_C <<< "$(docker exec "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -t -A -c \
  "SELECT a.id, d.id FROM applications a JOIN application_domains d ON d.application_id=a.id WHERE a.code='open-gw' LIMIT 1;" | tr '|' ' ')"
APP_S5=$(docker exec "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -t -A -c \
  "SELECT id FROM applications WHERE code='s5app' LIMIT 1;")
echo "[setup] A=$APP_A B=$APP_B C=$APP_C s5=$APP_S5"
[ -z "$APP_A" ] && { echo "ERROR: 演示应用不存在，请先执行 stage8-seed-demo.sh"; exit 1; }

APP_A="$APP_A" DOM_A="$DOM_A" APP_B="$APP_B" DOM_B="$DOM_B" APP_C="$APP_C" DOM_C="$DOM_C" APP_S5="$APP_S5" \
python3 - << 'PYEOF' | docker exec -i "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -v ON_ERROR_STOP=1 --quiet
import hashlib, json, os, uuid

NS = uuid.UUID("8f2e6c1a-9b3d-4e5f-a7c8-9d0e1f2a3b4c")
def U(key): return str(uuid.uuid5(NS, "jz-stage8-attack-demo:" + key))
def H(s): return hashlib.sha256(s.encode()).hexdigest()
def J(o): return json.dumps(o, ensure_ascii=False)

A, DA = os.environ["APP_A"], os.environ["DOM_A"]
B, DB = os.environ["APP_B"], os.environ["DOM_B"]
C, DC = os.environ["APP_C"], os.environ["DOM_C"]
S5 = os.environ["APP_S5"]

def q(v): return "NULL" if v is None else "'" + str(v).replace("'", "''") + "'"

# 端点 id 取子查询（种子脚本已保证同 key 恒单行优先取绑定行）
E = lambda k: "(SELECT id FROM api_endpoints WHERE endpoint_key=" + q(k) + " ORDER BY application_id NULLS LAST, created_at ASC LIMIT 1)"

print("BEGIN;")

# ============================================================
# 第一部分：6 组攻击活动
# ============================================================
# 攻击者身份（client_identity；identity_type=IP，保留网段）
IDENTS = {
    "c1": ("ip:192.0.2.11",     "192.0.2.11",    "UNKNOWN"),
    "c2": ("ip:198.51.100.23",  "198.51.100.23", "BOT"),
    "c3": ("ip:192.0.2.45",     "192.0.2.45",    "UNKNOWN"),
    "c4": ("ip:198.51.100.99",  "198.51.100.99", "BOT"),
    "c5": ("ip:192.0.2.77",     "192.0.2.77",    "HUMAN"),
    "c6": ("ip:203.0.113.10",   "203.0.113.10",  "BOT"),
}
for cid, (ikey, ip, itype) in IDENTS.items():
    print(f"""INSERT INTO client_identity (id, identity_key, identity_type, first_seen_at, last_seen_at,
  primary_ip, risk_score, risk_level, status, request_count)
VALUES ({q(U('ident:'+cid))}, {q(ikey)}, {q(itype)}, now() - interval '24 hours', now(), {q(ip)},
  0, 'LOW', 'NORMAL', 0)
ON CONFLICT DO NOTHING;""")

def ibe(cid, step, minutes_ago, rule, delta, method, path, app, dom, mode="OBSERVE", signal=""):
    """identity_behavior_events 主锚事件；request_id 供 security/runtime 事件关联归属。"""
    rid = "demo-%s-r%02d" % (cid, step)
    print(f"""INSERT INTO identity_behavior_events (id, identity_id, identity_key, occurred_at,
  event_kind, rule_code, rule_version, signal, risk_score_delta, mode, reason, metadata,
  request_id, client_ip, method, path, app_id, domain)
VALUES ({q(U('ibe:'+rid))}, {q(U('ident:'+cid))}, {q(IDENTS[cid][0])}, now() - interval '{minutes_ago} minutes',
  'RECON_SIGNAL', {q(rule)}, 'v1', {q(signal or rule.lower())}, {delta}, {q(mode)}, '演示攻击故事线',
  '{{}}'::jsonb, {q(rid)}, {q(IDENTS[cid][1])}, {q(method)}, {q(path)}, {q(app)}, {q(dom)})
ON CONFLICT DO NOTHING;""")
    return rid

def rte(cid, rid, minutes_ago, epkey, score, level, action, dets, status=200, method="GET", path="/"):
    """api_runtime_events（request_id 关联 ibe 归属）；dets=(detector,rule_id,severity,score_delta)"""
    details = [{"detector": d[0], "rule_id": d[1], "category": d[1].split(".")[0], "severity": d[2],
                "message": d[1], "evidence": {}, "score_delta": d[3]} for d in dets]
    print(f"""INSERT INTO api_runtime_events (id, request_id, endpoint_key, risk_score, risk_level,
  final_action, details_json, occurred_at, identity_fingerprint, client_ip, method, raw_path, response_status)
VALUES ({q(U('rte:'+rid))}, {q(rid)}, {q(epkey)}, {score}, {q(level)}, {q(action)},
  {q(J(details))}::jsonb, now() - interval '{minutes_ago} minutes', {q(H(IDENTS[cid][0])[:32])},
  {q(IDENTS[cid][1])}, {q(method)}, {q(path)}, {status})
ON CONFLICT DO NOTHING;""")

def sev(cid, rid, minutes_ago, app, dom, host, method, uri, atype, severity, anomaly, action, status, rules=3):
    """security_events（request_id 关联 ibe 归属）；attack_type 非空 → 聚合阶段 EXPLOIT。"""
    print(f"""INSERT INTO security_events (id, request_id, occurred_at, application_id,
  application_name_snapshot, domain, client_ip, request_method, request_uri, request_path,
  attack_type, severity, anomaly_score, action, response_status, rule_match_count, user_agent_summary)
VALUES ({q(U('sev:'+rid))}, {q(rid)}, now() - interval '{minutes_ago} minutes', {q(app)},
  '演示应用', {q(host)}, {q(IDENTS[cid][1])}, {q(method)}, {q(uri)}, {q(uri.split('?')[0])},
  {q(atype)}, {q(severity)}, {anomaly}, {q(action)}, {status}, {rules}, 'demo-attack-toolkit/1.0')
ON CONFLICT DO NOTHING;""")

# ---- C1 电商商城完整杀伤链（结束于 ~5 分钟前，保持 OPEN 进行中）----
# 接口探测 → 登录尝试 → Token异常 → ID遍历 → 越权读取订单 → 批量导出敏感数据 → WDSP阻断
r = ibe("c1", 1, 30, "RECON-URI-001", 5, "GET", "/v1/orders", A, "shop.example.com", signal="recon_uri_score")
r = ibe("c1", 2, 29, "RECON-URI-001", 5, "GET", "/v1/products/1", A, "shop.example.com", signal="recon_uri_score")
r = ibe("c1", 3, 28, "RECON-PATH-001", 5, "GET", "/v1/admin", A, "shop.example.com", signal="recon_path_probe")
for i in range(4):
    r = ibe("c1", 4+i, 26-i, "AUTH-FAIL-001", 10, "POST", "/v1/users/login", B, "uc.example.com", signal="auth_fail_burst")
    rte("c1", r, 26-i, "POST /v1/users/login", 10, "LOW", "OBSERVE",
        [("authentication", "auth.credential_fail", "LOW", 10)], status=401, method="POST", path="/v1/users/login")
r = ibe("c1", 8, 21, "AUTH-FAIL-001", 10, "POST", "/v1/auth/refresh", B, "uc.example.com", signal="token_reuse")
rte("c1", r, 21, "POST /v1/auth/refresh", 20, "MEDIUM", "OBSERVE",
    [("authentication", "auth.token_anomaly", "MEDIUM", 20)], status=401, method="POST", path="/v1/auth/refresh")
for i in range(3):
    r = ibe("c1", 9+i, 19-i, "BIZ-OBJENUM-001", 15, "GET", "/v1/orders/1000%d" % (i+1), A, "shop.example.com", signal="object_id_iteration")
r = ibe("c1", 12, 15, "BIZ-OBJENUM-001", 15, "GET", "/v1/orders/10042", A, "shop.example.com", signal="object_id_iteration")
rte("c1", r, 15, "GET /v1/orders/{id}", 35, "MEDIUM", "OBSERVE",
    [("resource_access", "resource.unauthenticated_object_access", "HIGH", 35)], status=200, path="/v1/orders/10042")
r = ibe("c1", 13, 12, "BIZ-EXPORT-001", 20, "POST", "/v1/orders/export", A, "shop.example.com", signal="bulk_export")
rte("c1", r, 12, "POST /v1/orders/export", 40, "HIGH", "OBSERVE",
    [("sensitive_data", "sensitive.value", "HIGH", 40)], status=200, method="POST", path="/v1/orders/export")
r = ibe("c1", 14, 8, "RECON-PARAM-001", 5, "GET", "/v1/users/1?id=1' OR '1'='1", A, "shop.example.com", mode="PROTECT", signal="recon_param_probe")
sev("c1", r, 8, A, "shop.example.com", "shop.example.com", "GET", "/v1/users/1?id=1' OR '1'='1",
    "SQL_INJECTION", "CRITICAL", 40, "BLOCK", 403, rules=5)
rte("c1", r, 8, "GET /v1/users/{id}", 40, "HIGH", "BLOCK",
    [("waf", "waf.sql_injection", "CRITICAL", 40)], status=403, path="/v1/users/1")

# ---- C2 用户中心撞库（结束 3 小时前，CLOSED）----
ibe("c2", 1, 190, "RECON-PATH-001", 5, "GET", "/v1/users/login", B, "uc.example.com", signal="recon_path_probe")
for i in range(6):
    r = ibe("c2", 2+i, 186-i, "AUTH-FAIL-001", 10, "POST", "/v1/users/login", B, "uc.example.com", signal="auth_fail_burst")
r = ibe("c2", 8, 178, "BIZ-LOGIN-001", 15, "POST", "/v1/users/login", B, "uc.example.com", mode="PROTECT", signal="credential_stuffing")
sev("c2", r, 178, B, "uc.example.com", "uc.example.com", "POST", "/v1/users/login",
    "SCANNER", "HIGH", 30, "BLOCK", 403, rules=2)

# ---- C3 开放平台批量导出（OBSERVE 未阻断，结束 6 小时前）----
ibe("c3", 1, 370, "RECON-URI-001", 5, "GET", "/v1/reports/daily", C, "open.example.com", signal="recon_uri_score")
r = ibe("c3", 2, 365, "BIZ-EXPORT-001", 20, "POST", "/v1/reports/export", C, "open.example.com", signal="bulk_export")
rte("c3", r, 365, "POST /v1/reports/export", 40, "HIGH", "OBSERVE",
    [("sensitive_data", "sensitive.value", "HIGH", 40)], status=200, method="POST", path="/v1/reports/export")
r = ibe("c3", 3, 362, "BIZ-EXPORT-001", 20, "GET", "/v1/users/export?format=csv", C, "open.example.com", signal="bulk_export")
rte("c3", r, 362, "GET /v1/users/export", 25, "MEDIUM", "OBSERVE",
    [("sensitive_data", "sensitive.value", "MEDIUM", 25)], status=200, path="/v1/users/export")

# ---- C4 Shadow API 探测（结束 9 小时前，低分）----
for i, p in enumerate(["/v1/ghost/ping", "/internal/debug/vars", "/openapi/v2/status"]):
    r = ibe("c4", 1+i, 545-i*2, "RECON-URI-001", 5, "GET", p, C, "open.example.com", signal="recon_uri_score")
    rte("c4", r, 545-i*2, "GET " + p, 10, "LOW", "OBSERVE",
        [("lifecycle", "lifecycle.new_endpoint", "LOW", 5)], status=200, path=p)

# ---- C5 BOLA 遍历用户（结束 13 小时前，HIGH）----
ibe("c5", 1, 790, "RECON-URI-001", 5, "GET", "/v1/users/1001", B, "uc.example.com", signal="recon_uri_score")
for i in range(4):
    r = ibe("c5", 2+i, 785-i*3, "BIZ-OBJENUM-001", 15, "GET", "/v1/users/%d" % (1002+i), B, "uc.example.com", signal="object_id_iteration")
r = ibe("c5", 6, 772, "BIZ-OBJENUM-001", 15, "GET", "/v1/users/1010", B, "uc.example.com", signal="object_id_iteration")
rte("c5", r, 772, "GET /v1/users/{id}", 35, "MEDIUM", "OBSERVE",
    [("resource_access", "resource.unauthenticated_object_access", "HIGH", 35)], status=200, path="/v1/users/1010")

# ---- C6 撞库 + 批量赋值尝试（结束 20 小时前，EXPLOIT 阻断）----
for i in range(3):
    ibe("c6", 1+i, 1205-i*2, "AUTH-FAIL-001", 10, "POST", "/v1/users/login", B, "uc.example.com", signal="auth_fail_burst")
r = ibe("c6", 4, 1198, "RECON-PARAM-001", 5, "POST", "/v1/users/register", B, "uc.example.com", mode="PROTECT", signal="recon_param_probe")
rte("c6", r, 1198, "POST /v1/users/register", 40, "HIGH", "BLOCK",
    [("api_schema", "schema.undefined_field", "HIGH", 40)], status=403, method="POST", path="/v1/users/register")
sev("c6", r, 1198, B, "uc.example.com", "uc.example.com", "POST", "/v1/users/register",
    "COMMAND_INJECTION", "HIGH", 30, "BLOCK", 403, rules=2)

# ============================================================
# 第二部分：规模补齐
# ============================================================

# ---- 通用安全事件（事件中心；~90 条，7 天铺开；独立 IP 段避免误归属攻击会话）----
APPS = [(A, "shop.example.com"), (B, "uc.example.com"), (C, "open.example.com"), (S5, "waf-s5.local")]
ATTACKS = [
    ("SQL_INJECTION", "HIGH", "/v1/products/search?q=1' UNION SELECT--", "GET"),
    ("XSS", "MEDIUM", "/v1/products/search?q=<script>alert(1)</script>", "GET"),
    ("PATH_TRAVERSAL", "MEDIUM", "/v1/files?f=../../etc/passwd", "GET"),
    ("COMMAND_INJECTION", "HIGH", "/v1/tools/ping?host=127.0.0.1;id", "GET"),
    ("SCANNER", "LOW", "/.git/config", "GET"),
    ("LOCAL_FILE_INCLUSION", "HIGH", "/v1/files?f=/etc/shadow", "GET"),
    ("XSS", "LOW", "/v1/comments", "POST"),
    ("SQL_INJECTION", "CRITICAL", "/v1/users/login", "POST"),
    ("SCANNER", "INFO", "/wp-login.php", "GET"),
    ("OTHER", "LOW", "/v1/orders", "POST"),
]
UAS = ["sqlmap/1.16", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "nuclei/3.2", "curl/8.5", "python-requests/2.31"]
for i in range(90):
    at, sev2, uri, m = ATTACKS[i % len(ATTACKS)]
    app, host = APPS[i % len(APPS)]
    blocked = (i % 10) < 3
    ip = ("192.0.2.%d" % (200 + i % 50)) if i % 2 == 0 else ("198.51.100.%d" % (100 + i % 50))
    print(f"""INSERT INTO security_events (id, request_id, occurred_at, application_id,
  application_name_snapshot, domain, client_ip, request_method, request_uri, request_path,
  attack_type, severity, anomaly_score, action, response_status, rule_match_count, user_agent_summary)
VALUES ({q(U('gsev:%d' % i))}, {q('demo-gen-%04d' % i)}, now() - interval '{i*107} minutes', {q(app)},
  '演示应用', {q(host)}, {q(ip)}, {q(m)}, {q(uri)}, {q(uri.split('?')[0])},
  {q(at)}, {q(sev2)}, {10 + (i*7) % 80}, {q('BLOCK' if blocked else 'OBSERVE')},
  {403 if blocked else 200}, {1 + i % 8}, {q(UAS[i % len(UAS)])})
ON CONFLICT DO NOTHING;""")

# ---- 通用 API 运行时事件（+78，正常流量为主）----
NORMAL_EPS = [
    ("GET /v1/products/{id}", "GET", "/v1/products/2001"),
    ("GET /v1/users/{id}", "GET", "/v1/users/1001"),
    ("POST /v1/orders/{id}", "POST", "/v1/orders/3001"),
    ("POST /v1/users/login", "POST", "/v1/users/login"),
    ("GET /v1/orders", "GET", "/v1/orders?page=1"),
    ("POST /v1/pay/callback", "POST", "/v1/pay/callback"),
]
for i in range(78):
    epkey, m, path = NORMAL_EPS[i % len(NORMAL_EPS)]
    warn = (i % 13) == 0  # 少量 OBSERVE 事件点缀
    dets = [{"detector": "identity", "rule_id": "identity.token_present", "category": "identity",
             "severity": "INFO", "message": "identity.token_present", "evidence": {}, "score_delta": 0}] if warn else []
    print(f"""INSERT INTO api_runtime_events (id, request_id, endpoint_key, risk_score, risk_level,
  final_action, details_json, occurred_at, identity_fingerprint, client_ip, method, raw_path,
  response_status, latency_ms)
VALUES ({q(U('grte:%d' % i))}, {q('demo-rt-%04d' % i)}, {q(epkey)}, {5 if warn else 0},
  {q('LOW' if warn else 'NONE')}, {q('OBSERVE' if warn else 'ALLOW')}, {q(J(dets))}::jsonb,
  now() - interval '{i*31} minutes', {q(H('normal-idf-%d' % (i % 9))[:32])},
  {q('203.0.113.%d' % (50 + i % 40))}, {q(m)}, {q(path)}, {200 if i % 17 else 401}, {20 + (i*13) % 380})
ON CONFLICT DO NOTHING;""")

# ---- 学习样本（+126 → 总量 150）----
sample_eps_keys = ["POST /v1/orders/{id}", "GET /v1/users/{id}", "GET /v1/orders", "POST /v1/users/login",
                   "GET /v1/products/{id}", "POST /v1/pay/callback"]
reasons = ["", "", "", "", "字段类型漂移", "", "超大小截断", "", "非JSON请求体", "", "重复样本", "", "响应状态异常"]
for i in range(126):
    ep = sample_eps_keys[i % len(sample_eps_keys)]
    reason = reasons[i % len(reasons)]
    acc = reason == ""
    print(f"""INSERT INTO api_learning_samples (id, api_endpoint_id, request_id, sample_hash,
  source_fingerprint, identity_fingerprint, response_status, accepted, exclude_reason, collected_at)
SELECT {q(U('gsample:%d' % i))}, {E(ep)}, {q('seed2-req-%04d' % i)}, {q(H('sample2-%d' % i)[:32])},
  {q(H('src2-%d' % (i % 8))[:16])}, {q(H('idf2-%d' % (i % 11))[:16])}, {200 if i % 11 else 500},
  {str(acc).upper()}, {q(reason)}, now() - interval '{i*3} hours'
WHERE EXISTS (SELECT 1 FROM api_endpoints WHERE id={E(ep)})
ON CONFLICT DO NOTHING;""")

# ---- 参数模型（+25，含嵌套结构/长度/必填约束）----
def mv(key, ver):
    return ("(SELECT id FROM api_model_versions WHERE endpoint_key=" + q(key) +
            " AND version_number=%d ORDER BY created_at DESC LIMIT 1)" % ver)
PMS2 = [
    ("POST /v1/orders/{id}", 2, "REQUEST", "BODY", "items[].sku_id", "string", "sku_id", True, False, "LOW", 0.95, {"max_length": 32}),
    ("POST /v1/orders/{id}", 2, "REQUEST", "BODY", "items[].quantity", "number", "count", True, False, "LOW", 0.96, {"min": 1, "max": 999}),
    ("POST /v1/orders/{id}", 2, "REQUEST", "BODY", "items[].price", "number", "money", True, False, "MEDIUM", 0.93, {"min": 0}),
    ("POST /v1/orders/{id}", 2, "REQUEST", "BODY", "receiver.name", "string", "name", True, False, "MEDIUM", 0.94, {"max_length": 64}),
    ("POST /v1/orders/{id}", 2, "REQUEST", "BODY", "receiver.phone", "string", "phone", True, False, "HIGH", 0.97, {"pattern": "^1[0-9]{10}$"}),
    ("POST /v1/orders/{id}", 2, "REQUEST", "BODY", "receiver.address", "string", "address", True, False, "MEDIUM", 0.9, {"max_length": 256}),
    ("POST /v1/orders/{id}", 2, "RESPONSE", "BODY", "order_id", "string", "order_id", True, False, "LOW", 0.99, {}),
    ("POST /v1/orders/{id}", 2, "RESPONSE", "BODY", "status", "string", "order_status", True, False, "LOW", 0.97, {"enum": ["CREATED", "PAID", "SHIPPED"]}),
    ("GET /v1/users/{id}", 3, "RESPONSE", "BODY", "phone", "string", "phone", False, True, "HIGH", 0.95, {"pattern": "^1[0-9]{10}$"}),
    ("GET /v1/users/{id}", 3, "RESPONSE", "BODY", "email", "string", "email", False, True, "MEDIUM", 0.93, {"max_length": 128}),
    ("GET /v1/users/{id}", 3, "RESPONSE", "BODY", "avatar", "string", "url", False, True, "LOW", 0.8, {"max_length": 512}),
    ("GET /v1/users/{id}", 3, "RESPONSE", "BODY", "profile.nickname", "string", "text", False, True, "LOW", 0.85, {"max_length": 64}),
    ("GET /v1/users/{id}", 3, "RESPONSE", "BODY", "profile.tags[]", "string", "text", False, True, "LOW", 0.7, {"max_length": 32}),
    ("POST /v1/users/login", 2, "REQUEST", "HEADER", "User-Agent", "string", "user_agent", False, True, "LOW", 0.9, {"max_length": 256}),
    ("POST /v1/users/login", 2, "RESPONSE", "BODY", "token", "string", "token", True, False, "HIGH", 0.99, {"max_length": 512}),
    ("POST /v1/users/login", 2, "RESPONSE", "BODY", "expires_in", "number", "ttl", True, False, "LOW", 0.95, {"min": 60}),
    ("GET /v1/orders", 1, "REQUEST", "QUERY", "keyword", "string", "text", False, True, "LOW", 0.6, {"max_length": 64}),
    ("GET /v1/orders", 1, "RESPONSE", "BODY", "items[].order_id", "string", "order_id", True, False, "LOW", 0.94, {}),
    ("GET /v1/orders", 1, "RESPONSE", "BODY", "items[].total", "number", "money", True, False, "MEDIUM", 0.92, {"min": 0}),
    ("GET /v1/orders", 1, "RESPONSE", "BODY", "total_count", "number", "count", True, False, "LOW", 0.96, {}),
    ("POST /v1/pay/callback", 1, "REQUEST", "HEADER", "X-Pay-Signature", "string", "signature", True, False, "HIGH", 0.98, {"max_length": 128}),
    ("GET /v1/products/{id}", 1, "REQUEST", "QUERY", "fields", "string", "text", False, True, "LOW", 0.55, {"max_length": 128}),
    ("GET /v1/products/{id}", 1, "RESPONSE", "BODY", "detail.seller.name", "string", "name", False, True, "LOW", 0.8, {"max_length": 64}),
    ("POST /v1/auth/token", 1, "REQUEST", "BODY", "app_id", "string", "client_id", True, False, "MEDIUM", 0.96, {"max_length": 64}),
    ("POST /v1/auth/token", 1, "REQUEST", "BODY", "app_secret", "string", "credential", True, False, "HIGH", 0.99, {"max_length": 128}),
]
for (epkey, ver, d, loc, path, base, sem, req, nullable, sens, conf, cons) in PMS2:
    pid = U("pm2:%s#%d:%s:%s" % (epkey, ver, loc, path))
    print(f"""INSERT INTO api_parameter_models (id, model_version_id, direction, location, structured_path,
  parameter_name, base_type, semantic_type, required, nullable, observed_constraints,
  recommended_constraints, confirmed_constraints, sensitivity_level, confidence)
SELECT {q(pid)}, {mv(epkey, ver)}, {q(d)}, {q(loc)}, {q(path)}, {q(path.split('.')[-1].replace('[]',''))},
  {q(base)}, {q(sem)}, {str(req).upper()}, {str(nullable).upper()}, {q(J(cons))}::jsonb,
  {q(J(cons))}::jsonb, '{{}}'::jsonb, {q(sens)}, {conf}
WHERE EXISTS (SELECT 1 FROM api_model_versions WHERE id={mv(epkey, ver)})
ON CONFLICT DO NOTHING;""")

# ---- Schema 违例（+6 → 18，含嵌套路径与响应侧）----
VIOS2 = [
    ("POST /v1/orders/{id}", "type_mismatch", "items[].quantity", "number", "string", "OBSERVE", 9),
    ("POST /v1/orders/{id}", "undefined_field", "receiver.id_card", "-", "string", "BLOCK", 4),
    ("GET /v1/users/{id}", "type_mismatch", "profile.tags[]", "string", "number", "OBSERVE", 12),
    ("POST /v1/users/register", "undefined_field", "is_admin", "-", "boolean", "BLOCK", 6),
    ("GET /v1/orders", "type_mismatch", "page_size", "number", "string", "OBSERVE", 18),
    ("POST /v1/pay/callback", "undefined_field", "debug", "-", "boolean", "BLOCK", 2),
]
for (ep, vt, field, want, got, act, hours) in VIOS2:
    print(f"""INSERT INTO api_schema_violations (id, endpoint_id, model_version_id, request_id,
  violation_type, field_path, expected, observed, action_taken, occurred_at)
SELECT {q(U('vio2:%s:%s' % (ep, field)))}, {E(ep)}, NULL, {q('seed2-vio-%s' % field)},
  {q(vt)}, {q(field)}, {q(want)}, {q(got)}, {q(act)}, now() - interval '{hours} hours'
WHERE EXISTS (SELECT 1 FROM api_endpoints WHERE id={E(ep)})
ON CONFLICT DO NOTHING;""")

# ---- 调用边（+10 → 20）----
EDGES2 = [
    ("gw-mini-program", None, "POST /v1/users/login", 480),
    ("gw-mini-program", "POST /v1/users/login", "GET /v1/users/profile", 430),
    ("gw-mobile-app", "GET /v1/users/profile", "POST /v1/cart/items", 390),
    ("gw-frontend-web", None, "GET /v1/products/{id}", 1750),
    ("gw-frontend-web", "GET /v1/products/{id}", "POST /v1/cart/items", 210),
    ("gw-partner-erp", None, "POST /v1/webhook/events", 220),
    ("gw-cron-reporter", None, "GET /v1/legacy/report", 5),
    ("gw-mobile-app", "POST /v1/auth/refresh", "GET /v1/users/{id}", 890),
    ("gw-open-thirdparty", None, "GET /openapi/v2/status", 12),
    ("gw-open-thirdparty", "POST /v1/auth/token", "GET /v1/orders", 45),
]
for (caller, srckey, tgtkey, n) in EDGES2:
    src_sql = "NULL" if srckey is None else E(srckey)
    print(f"""INSERT INTO api_call_edges (id, caller_fingerprint, source_endpoint_id, target_endpoint_id,
  call_count, first_seen_at, last_seen_at)
SELECT {q(U('edge2:%s>%s' % (caller, tgtkey)))}, {q(H(caller)[:24])}, {src_sql}, {E(tgtkey)}, {n},
  now() - interval '10 days', now() - interval '2 hours'
WHERE EXISTS (SELECT 1 FROM api_endpoints WHERE id={E(tgtkey)})
ON CONFLICT DO NOTHING;""")

# ---- 风险发现（+8：批量赋值/响应侧/行为异常；词表对齐 web/src/utils/stage8.ts）----
FDS2 = [
    ("POST /v1/users/register", "MASS_ASSIGNMENT", "HIGH", "NEW", "注册请求携带非预期敏感字段 is_admin",
     {"rule": "schema.undefined_field", "field": "is_admin", "risk": "批量赋值提权"}, 0),
    ("POST /v1/orders/{id}", "MASS_ASSIGNMENT", "MEDIUM", "CONFIRMED", "订单更新携带非预期字段 receiver.id_card",
     {"rule": "schema.undefined_field", "field": "receiver.id_card"}, 1),
    ("GET /v1/users/export", "SENSITIVE_LEAK", "CRITICAL", "NEW", "单次响应返回 5000 条用户数据（批量导出）",
     {"field": "*", "row_count": 5000}, 0),
    ("GET /v1/users/{id}", "SENSITIVE_LEAK", "HIGH", "IN_PROGRESS", "响应手机号未脱敏（明文 138****1234 缺失）",
     {"field": "phone", "masked": False}, 1),
    ("GET /v1/users/profile", "SENSITIVE_LEAK", "HIGH", "NEW", "响应身份证号未脱敏",
     {"field": "id_card", "masked": False}, 0),
    ("GET /v1/users/{id}", "SCHEMA_DEVIATION", "MEDIUM", "NEW", "响应结构偏离已确认模型（多出 profile.ext 嵌套）",
     {"rule": "schema.response_undefined_field", "field": "profile.ext"}, 1),
    ("GET /v1/orders", "BEHAVIOR_ANOMALY", "HIGH", "NEW", "正常身份 10 分钟内调用 27 个陌生接口",
     {"rule": "behavior.unfamiliar_endpoint_spike", "identity": "ip:198.51.100.99", "endpoints": 27}, 0),
    ("GET /v1/users/{id}", "BOLA", "HIGH", "NEW", "高频遍历用户 ID（10 分钟 400 次连续递增）",
     {"rule": "behavior.object_enumeration", "id_range": "1001-1400", "rate": "40/min"}, 0),
]
for (epkey, ftype, sev, st, title, detail, ago) in FDS2:
    print(f"""INSERT INTO api_runtime_findings (id, endpoint_id, request_id, finding_type, severity, status,
  title, detail, first_seen_at, last_seen_at)
SELECT {q(U('fd2:%s:%s' % (ftype, title)))}, {E(epkey)}, '', {q(ftype)}, {q(sev)}, {q(st)}, {q(title)},
  {q(J(detail))}::jsonb, now() - interval '{ago} days', now()
WHERE EXISTS (SELECT 1 FROM api_endpoints WHERE id={E(epkey)})
ON CONFLICT DO NOTHING;""")

print("COMMIT;")
print("SELECT 'attack_identities', count(*) FROM client_identity;")
print("SELECT 'ibe_events', count(*) FROM identity_behavior_events;")
print("SELECT 'security_events', count(*) FROM security_events;")
print("SELECT 'runtime_events', count(*) FROM api_runtime_events;")
print("SELECT 'samples', count(*) FROM api_learning_samples;")
print("SELECT 'parameters', count(*) FROM api_parameter_models;")
print("SELECT 'violations', count(*) FROM api_schema_violations;")
print("SELECT 'edges', count(*) FROM api_call_edges;")
print("SELECT 'findings', count(*) FROM api_runtime_findings;")
PYEOF

echo "[seed] 补充造数完成；攻击会话由聚合器 60s 一轮产出，稍后核对"
