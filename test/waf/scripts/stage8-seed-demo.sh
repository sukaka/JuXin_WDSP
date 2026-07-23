#!/usr/bin/env bash
# 阶段8 演示数据种子（开发/演示环境）：为接口防护全部功能页造语义匹配的数据。
# 幂等可重复执行：确定性 UUID（uuid5）+ ON CONFLICT DO NOTHING；真实 API 走业务流
# （建应用/域名、批量确认、模型创建与冻结、规范导入、发布），无写接口的表走 SQL。
# 用法：bash test/waf/scripts/stage8-seed-demo.sh
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/stage5-setup.sh"

PG_CONTAINER="${PG_CONTAINER:-jiuzhang-stage5-postgres}"
PG_USER="${POSTGRES_USER:-jiuzhang}"
PG_DB="${POSTGRES_DB:-jiuzhang_waf}"

echo "============================================================"
echo "阶段8 演示数据种子  api=$API_URL db=$PG_CONTAINER/$PG_DB"
echo "============================================================"

# ---------- 0. 登录 ----------
SYS_CSRF=$(s5_ensure_sysadmin) || exit 1
SEC_CSRF=$(s5_ensure_secuser "$SYS_CSRF")
[ -z "$SEC_CSRF" ] && { echo "ERROR: sec login failed"; exit 1; }

# ---------- 1. 建站点应用与域名（幂等，HTTP 真实链路） ----------
ensure_site() { # $1=code $2=name $3=hostname → 打印 "app_id domain_id"
  local code="$1" name="$2" host="$3" appid domid
  appid=$(curl -s -b "/tmp/s5-$SEC_USER.txt" "$API_URL/api/v1/applications?keyword=$code" | python3 -c "
import json,sys
items=json.load(sys.stdin)['data']['items']
print(next((i['id'] for i in items if i['code']=='$code'),''))" 2>/dev/null)
  if [ -z "$appid" ]; then
    appid=$(curl -s -b "/tmp/s5-$SEC_USER.txt" -X POST "$API_URL/api/v1/applications" \
      -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" \
      -d "{\"code\":\"$code\",\"name\":\"$name\",\"description\":\"阶段8演示站点\",\"business_owner\":\"demo\",\"technical_owner\":\"demo\",\"protection_mode\":\"OFF\"}" \
      | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['id'])" 2>/dev/null)
  fi
  domid=$(curl -s -b "/tmp/s5-$SEC_USER.txt" "$API_URL/api/v1/applications/$appid/domains" | python3 -c "
import json,sys
items=json.load(sys.stdin)['data'].get('items') or json.load(sys.stdin)['data'].get('domains') or []
print(next((d['id'] for d in items if d.get('hostname')=='$host'),''))" 2>/dev/null)
  if [ -z "$domid" ]; then
    curl -s -o /dev/null -b "/tmp/s5-$SEC_USER.txt" -X POST "$API_URL/api/v1/applications/$appid/domains" \
      -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" \
      -d "{\"hostname\":\"$host\",\"is_primary\":true,\"http_enabled\":true,\"https_enabled\":false,\"http_port\":8080,\"redirect_http_to_https\":false}"
    domid=$(curl -s -b "/tmp/s5-$SEC_USER.txt" "$API_URL/api/v1/applications/$appid/domains" | python3 -c "
import json,sys
d=json.load(sys.stdin)['data']
items=d.get('items') or d.get('domains') or []
print(next((x['id'] for x in items if x.get('hostname')=='$host'),''))" 2>/dev/null)
  fi
  # 启用应用（DRAFT→ACTIVE，发布只含 ACTIVE）
  curl -s -o /dev/null -b "/tmp/s5-$SEC_USER.txt" -X POST "$API_URL/api/v1/applications/$appid/enable" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF"
  echo "$appid $domid"
}

read APP_A DOM_A <<< "$(ensure_site shop-mall 电商商城 shop.example.com)"
read APP_B DOM_B <<< "$(ensure_site user-center 用户中心 uc.example.com)"
read APP_C DOM_C <<< "$(ensure_site open-gw 开放网关 open.example.com)"
APP_S5=$(curl -s -b "/tmp/s5-$SEC_USER.txt" "$API_URL/api/v1/applications?keyword=$APP_CODE" | python3 -c "
import json,sys
items=json.load(sys.stdin)['data']['items']
print(next((i['id'] for i in items if i['code']=='$APP_CODE'),''))" 2>/dev/null)
echo "[setup] sites: A=$APP_A B=$APP_B C=$APP_C s5=$APP_S5"
[ -z "$APP_S5" ] && { echo "ERROR: s5app 不存在（请先执行 stage8-gateway-tests 或 stage5-setup）"; exit 1; }

# ---------- 2. SQL 批量造数（确定性 UUID，幂等） ----------
APP_A="$APP_A" DOM_A="$DOM_A" APP_B="$APP_B" DOM_B="$DOM_B" APP_C="$APP_C" DOM_C="$DOM_C" APP_S5="$APP_S5" \
python3 - << 'PYEOF' | docker exec -i "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -v ON_ERROR_STOP=1 --quiet
import hashlib, json, os, uuid

NS = uuid.UUID("8f2e6c1a-9b3d-4e5f-a7c8-9d0e1f2a3b4c")
def U(key): return str(uuid.uuid5(NS, "jz-stage8-demo:" + key))
def H(s): return hashlib.sha256(s.encode()).hexdigest()
def J(o): return json.dumps(o, ensure_ascii=False)

A, DA = os.environ["APP_A"], os.environ["DOM_A"]
B, DB = os.environ["APP_B"], os.environ["DOM_B"]
C, DC = os.environ["APP_C"], os.environ["DOM_C"]
S5 = os.environ["APP_S5"]

def q(v): return "NULL" if v is None else "'" + str(v).replace("'", "''") + "'"

# ---------- 端点（asset_status/learning_status/hit/目录） ----------
# (method, path, app, dom, asset_status, learning_status, hits, days_ago)
EPS = [
    ("POST", "/v1/orders/{id}", A, DA, "DISCOVERED", "LEARNED", 1520, 12),
    ("GET",  "/v1/orders", A, DA, "DISCOVERED", "LEARNING", 860, 10),
    ("POST", "/v1/cart/items", A, DA, "DISCOVERED", "NOT_STARTED", 42, 3),
    ("GET",  "/v1/products/{id}", A, DA, "CONFIRMED", "NOT_STARTED", 3100, 15),
    ("GET",  "/v1/products/search", A, DA, "DISCOVERED", "NOT_STARTED", 95, 4),
    ("POST", "/v1/pay/callback", A, DA, "CONFIRMED", "LEARNED", 640, 9),
    ("GET",  "/v1/inventory/{id}", A, DA, "DISCOVERED", "NOT_STARTED", 54, 2),
    ("POST", "/v1/inventory/reserve", A, DA, "DISCOVERED", "NOT_STARTED", 12, 1),
    ("GET",  "/v1/users/{id}", B, DB, "CONFIRMED", "LEARNED", 5400, 20),
    ("POST", "/v1/users/login", B, DB, "CONFIRMED", "LEARNED", 2300, 18),
    ("GET",  "/v1/users/profile", B, DB, "DISCOVERED", "NOT_STARTED", 120, 5),
    ("POST", "/v1/auth/token", B, DB, "DISCOVERED", "NOT_STARTED", 88, 6),
    ("POST", "/v1/auth/refresh", B, DB, "IGNORED", "NOT_STARTED", 31, 7),
    ("GET",  "/openapi/v2/status", C, DC, "DISCOVERED", "NOT_STARTED", 12, 1),
    ("GET",  "/v1/legacy/report", C, DC, "DEPRECATED", "NOT_STARTED", 5, 60),
    ("POST", "/v1/webhook/events", C, DC, "DISCOVERED", "NOT_STARTED", 230, 8),
    ("GET",  "/v1/metrics", C, DC, "IGNORED", "NOT_STARTED", 999, 11),
    ("GET",  "/v1/ghost/ping", None, None, "DISCOVERED", "NOT_STARTED", 7, 1),
    ("POST", "/internal/debug/vars", None, None, "DISCOVERED", "NOT_STARTED", 2, 0),
    ("GET",  "/v1/sitecheck/health", S5, None, "DISCOVERED", "NOT_STARTED", 66, 3),
    ("POST", "/v1/sitecheck/echo", S5, None, "CONFIRMED", "NOT_STARTED", 140, 4),
    ("GET",  "/v1/sessions/{id}", B, DB, "DEPRECATED", "NOT_STARTED", 3, 45),
]
ep_ids = {}
print("BEGIN;")
for (m, p, app, dom, st, lst, hits, ago) in EPS:
    eid = U("ep:" + m + " " + p)
    ep_ids[m + " " + p] = eid
    key = m + " " + p
    directory = p.rsplit("/", 1)[0] if "/" in p[1:] else ""
    confirmed = "now() - interval '%d days'" % ago if st == "CONFIRMED" else "NULL"
    print(f"""INSERT INTO api_endpoints (id, application_id, domain_id, http_method, normalized_path,
  raw_path_example, directory_path, endpoint_key, api_confidence, asset_status, learning_status,
  is_api, hit_count, first_seen_at, last_seen_at, confirmed_at)
VALUES ({q(eid)}, {q(app)}, {q(dom)}, {q(m)}, {q(p)}, {q(p)}, {q(directory)}, {q(key)},
  {0.62 + (len(p) % 30) / 100.0:.2f}, {q(st)}, {q(lst)}, TRUE, {hits},
  now() - interval '{ago} days', now() - interval '{max(ago-1,0)} days', {confirmed})
ON CONFLICT (endpoint_key) DO UPDATE SET
  application_id = EXCLUDED.application_id, domain_id = EXCLUDED.domain_id,
  directory_path = EXCLUDED.directory_path, asset_status = EXCLUDED.asset_status,
  learning_status = EXCLUDED.learning_status, hit_count = EXCLUDED.hit_count,
  confirmed_at = EXCLUDED.confirmed_at, updated_at = now();""")

E = lambda k: "(SELECT id FROM api_endpoints WHERE endpoint_key=" + q(k) + ")"

# ---------- 模型版本（orders 与 users 的 FORMAL 由真实 API 创建，这里造其余状态） ----------
# (endpoint, version, status, schema, reason, days_ago)
MVS = [
    (E("POST /v1/orders/{id}"), 2, "CANDIDATE", {"id":"number","items":"array","total":"number","currency":"string","coupon":"string"}, "learning_threshold", 1),
    (E("GET /v1/users/{id}"), 1, "SUPERSEDED", {"id":"number","name":"string"}, "manual", 19),
    (E("GET /v1/users/{id}"), 3, "CANDIDATE", {"id":"number","name":"string","phone":"string","email":"string","avatar":"string"}, "relearn", 0),
    (E("POST /v1/users/login"), 2, "IN_REVIEW", {"username":"string","password":"string","captcha":"string"}, "manual", 2),
    (E("GET /v1/orders"), 1, "CANDIDATE", {"page":"number","page_size":"number","status":"string"}, "manual", 1),
    (E("POST /v1/pay/callback"), 1, "FORMAL", {"order_id":"string","amount":"number","sign":"string"}, "manual", 8),
    (E("POST /v1/auth/token"), 1, "REJECTED", {"app_id":"string","app_secret":"string"}, "manual", 5),
    (E("GET /v1/products/{id}"), 1, "FORMAL", {"id":"number","title":"string","price":"number","stock":"number"}, "manual", 14),
    (E("GET /v1/legacy/report"), 1, "ARCHIVED", {"year":"number","month":"number"}, "manual", 50),
]
mv_ids = {}
for (ep, ver, st, schema, reason, ago) in MVS:
    mid = U("mv:%s#%d" % (ep, ver))
    mv_ids[(ep, ver)] = mid
    frozen = f"now() - interval '{ago} days'" if st in ("FORMAL","SUPERSEDED","ARCHIVED") else "NULL"
    activated = frozen if st == "FORMAL" else "NULL"
    print(f"""INSERT INTO api_model_versions (id, api_endpoint_id, endpoint_key, version_number, status,
  schema_json, content_hash, created_reason, created_at, confirmed_at, activated_at)
SELECT {q(mid)}, {ep}, (SELECT endpoint_key FROM api_endpoints WHERE id={ep}), {ver}, {q(st)},
  {q(J(schema))}::jsonb, {q(H(J(schema)))}, {q(reason)}, now() - interval '{ago} days', {frozen}, {activated}
WHERE EXISTS (SELECT 1 FROM api_endpoints WHERE id={ep})
ON CONFLICT (id) DO NOTHING;""")

# FORMAL 版本回填端点 current_model_version_id（pay/callback 与 products）
for (ep, ver) in [(E("POST /v1/pay/callback"),1),(E("GET /v1/products/{id}"),1)]:
    print(f"""UPDATE api_endpoints SET current_model_version_id={q(mv_ids[(ep,ver)])} WHERE id={ep};""")

# ---------- 参数模型（挂 FORMAL 与候选版本） ----------
# (model, direction, location, path/name, base, semantic, required, nullable, sensitivity, conf)
PMS = [
    (mv_ids[(E("POST /v1/pay/callback"),1)], "REQUEST", "BODY", "order_id", "string", "order_id", True, False, "LOW", 0.98),
    (mv_ids[(E("POST /v1/pay/callback"),1)], "REQUEST", "BODY", "amount", "number", "money", True, False, "MEDIUM", 0.97),
    (mv_ids[(E("POST /v1/pay/callback"),1)], "REQUEST", "BODY", "sign", "string", "signature", True, False, "HIGH", 0.99),
    (mv_ids[(E("POST /v1/pay/callback"),1)], "REQUEST", "HEADER", "X-Request-Id", "string", "trace_id", False, True, "LOW", 0.9),
    (mv_ids[(E("POST /v1/pay/callback"),1)], "RESPONSE", "BODY", "code", "number", "status_code", True, False, "LOW", 0.95),
    (mv_ids[(E("GET /v1/products/{id}"),1)], "REQUEST", "PATH", "id", "number", "resource_id", True, False, "LOW", 0.99),
    (mv_ids[(E("GET /v1/products/{id}"),1)], "RESPONSE", "BODY", "title", "string", "text", True, False, "LOW", 0.96),
    (mv_ids[(E("GET /v1/products/{id}"),1)], "RESPONSE", "BODY", "price", "number", "money", True, False, "MEDIUM", 0.96),
    (mv_ids[(E("GET /v1/products/{id}"),1)], "RESPONSE", "BODY", "stock", "number", "count", True, False, "LOW", 0.94),
    (mv_ids[(E("POST /v1/orders/{id}"),2)], "REQUEST", "PATH", "id", "number", "resource_id", True, False, "LOW", 0.99),
    (mv_ids[(E("POST /v1/orders/{id}"),2)], "REQUEST", "BODY", "items", "array", "list", True, False, "LOW", 0.92),
    (mv_ids[(E("POST /v1/orders/{id}"),2)], "REQUEST", "BODY", "total", "number", "money", True, False, "MEDIUM", 0.9),
    (mv_ids[(E("POST /v1/orders/{id}"),2)], "REQUEST", "BODY", "currency", "string", "currency_code", True, False, "LOW", 0.88),
    (mv_ids[(E("POST /v1/orders/{id}"),2)], "REQUEST", "BODY", "coupon", "string", "coupon_code", False, True, "LOW", 0.6),
    (mv_ids[(E("POST /v1/users/login"),2)], "REQUEST", "BODY", "username", "string", "account", True, False, "MEDIUM", 0.97),
    (mv_ids[(E("POST /v1/users/login"),2)], "REQUEST", "BODY", "password", "string", "credential", True, False, "HIGH", 0.99),
    (mv_ids[(E("POST /v1/users/login"),2)], "REQUEST", "BODY", "captcha", "string", "captcha", False, True, "LOW", 0.7),
    (mv_ids[(E("GET /v1/orders"),1)], "REQUEST", "QUERY", "page", "number", "page", False, True, "LOW", 0.8),
    (mv_ids[(E("GET /v1/orders"),1)], "REQUEST", "QUERY", "page_size", "number", "page_size", False, True, "LOW", 0.8),
    (mv_ids[(E("GET /v1/orders"),1)], "REQUEST", "QUERY", "status", "string", "order_status", False, True, "LOW", 0.65),
]
for (mid, d, loc, name, base, sem, req, nullable, sens, conf) in PMS:
    pid = U("pm:%s:%s:%s" % (mid, loc, name))
    print(f"""INSERT INTO api_parameter_models (id, model_version_id, direction, location, structured_path,
  parameter_name, base_type, semantic_type, required, nullable, observed_constraints,
  recommended_constraints, confirmed_constraints, sensitivity_level, confidence)
VALUES ({q(pid)}, {q(mid)}, {q(d)}, {q(loc)}, {q(name)}, {q(name)}, {q(base)}, {q(sem)},
  {str(req).upper()}, {str(nullable).upper()}, '{{}}'::jsonb, '{{}}'::jsonb, '{{}}'::jsonb, {q(sens)}, {conf})
ON CONFLICT (id) DO NOTHING;""")

# ---------- 学习任务与样本 ----------
JOBS = [
    (E("GET /v1/orders"), "RUNNING", 100, 35, 33, 2, None, 1),
    (E("POST /v1/orders/{id}"), "COMPLETED", 100, 120, 118, 2, None, 9),
    (E("GET /v1/users/{id}"), "COMPLETED", 200, 200, 197, 3, None, 15),
    (E("POST /v1/auth/token"), "STOPPED", 50, 12, 9, 3, "样本来源单一，人工暂停", 4),
]
for (ep, st, target, collected, valid, excluded, err, ago) in JOBS:
    jid = U("job:%s" % ep)
    stopped = "now()" if st in ("STOPPED","COMPLETED") else "NULL"
    print(f"""INSERT INTO api_learning_jobs (id, endpoint_id, status, sample_target, collected_count,
  valid_count, excluded_count, last_error, started_at, stopped_at)
VALUES ({q(jid)}, {ep}, {q(st)}, {target}, {collected}, {valid}, {excluded}, {q(err or '')},
  now() - interval '{ago} days', {stopped})
ON CONFLICT (id) DO NOTHING;""")

sample_eps = [E("POST /v1/orders/{id}"), E("GET /v1/users/{id}"), E("GET /v1/orders"), E("POST /v1/users/login")]
reasons = ["", "", "", "字段类型漂移", "", "超大小截断", "", "非JSON请求体", "", "重复样本", "", "响应状态异常"]
for i in range(24):
    ep = sample_eps[i % len(sample_eps)]
    acc = reasons[i % len(reasons)] == ""
    sid = U("sample:%d" % i)
    print(f"""INSERT INTO api_learning_samples (id, api_endpoint_id, request_id, sample_hash,
  source_fingerprint, identity_fingerprint, response_status, accepted, exclude_reason, collected_at)
VALUES ({q(sid)}, {ep}, {q('seed-req-%03d' % i)}, {q(H('sample-%d' % i)[:32])},
  {q(H('src-%d' % (i % 5))[:16])}, {q(H('idf-%d' % (i % 7))[:16])}, {200 if i % 9 else 400},
  {str(acc).upper()}, {q(reasons[i % len(reasons)])}, now() - interval '{i} hours')
ON CONFLICT (id) DO NOTHING;""")

# ---------- 用途分类（内置 + 自定义 + 端点维度） ----------
BUILTIN = [
    ("AUTH", "认证鉴权"), ("TRADE", "交易支付"), ("USER_MGMT", "用户管理"), ("FILE", "文件传输"),
    ("QUERY", "查询检索"), ("ADMIN", "管理运维"), ("GENERAL", "通用业务"),
    ("INTERNAL", "内部使用"), ("PARTNER", "合作方开放"), ("PUBLIC", "公网开放"),
]
for (code, name) in BUILTIN:
    print(f"""INSERT INTO api_classifications (id, code, name, description, is_builtin)
VALUES ({q(U('cls:'+code))}, {q(code)}, {q(name)}, '', TRUE) ON CONFLICT (code) DO NOTHING;""")
CUSTOM = [("DATA_LEVEL", "PII", "含个人敏感信息"), ("DATA_LEVEL", "FINANCE", "含资金数据"), ("BU", "商城", "电商业务域")]
for (dim, val, desc) in CUSTOM:
    print(f"""INSERT INTO api_custom_taxonomies (id, dimension, value, description)
VALUES ({q(U('tax:'+dim+':'+val))}, {q(dim)}, {q(val)}, {q(desc)})
ON CONFLICT (dimension, value) DO NOTHING;""")

DIMS = [
    (E("POST /v1/orders/{id}"), "PURPOSE", "TRADE", "AUTO", 0.7), (E("POST /v1/orders/{id}"), "EXPOSURE", "PUBLIC", "MANUAL", 1.0),
    (E("POST /v1/pay/callback"), "PURPOSE", "TRADE", "AUTO", 0.7), (E("POST /v1/pay/callback"), "EXPOSURE", "PUBLIC", "AUTO", 0.7),
    (E("GET /v1/users/{id}"), "PURPOSE", "USER_MGMT", "AUTO", 0.6), (E("POST /v1/users/login"), "PURPOSE", "AUTH", "AUTO", 0.7),
    (E("POST /v1/users/login"), "DATA_LEVEL", "PII", "MANUAL", 1.0),
    (E("GET /v1/products/{id}"), "PURPOSE", "QUERY", "AUTO", 0.6),
    (E("POST /v1/webhook/events"), "EXPOSURE", "PUBLIC", "AUTO", 0.7),
    (E("GET /v1/legacy/report"), "PURPOSE", "ADMIN", "MANUAL", 0.9),
]
for (ep, dim, val, src, conf) in DIMS:
    print(f"""INSERT INTO api_classification_dimensions (id, endpoint_id, dimension, value, source, confidence)
VALUES ({q(U('dim:%s:%s' % (ep, dim)))}, {ep}, {q(dim)}, {q(val)}, {q(src)}, {conf})
ON CONFLICT (endpoint_id, dimension) DO NOTHING;""")
print(f"UPDATE api_endpoints SET classification_locked=TRUE WHERE id={E('POST /v1/users/login')};")

# ---------- 敏感字段 ----------
SENS = [
    (E("POST /v1/users/login"), "REQUEST", "password", "credential", 0.99),
    (E("POST /v1/users/login"), "REQUEST", "username", "name", 0.6),
    (E("GET /v1/users/{id}"), "RESPONSE", "phone", "phone", 0.95),
    (E("GET /v1/users/{id}"), "RESPONSE", "email", "email", 0.93),
    (E("GET /v1/users/profile"), "RESPONSE", "id_card", "id_card", 0.9),
    (E("POST /v1/pay/callback"), "REQUEST", "sign", "token", 0.85),
    (E("POST /v1/orders/{id}"), "REQUEST", "receiver.phone", "phone", 0.88),
    (E("POST /v1/orders/{id}"), "REQUEST", "receiver.address", "address", 0.8),
    (E("POST /v1/auth/token"), "REQUEST", "app_secret", "credential", 0.98),
    (E("POST /v1/webhook/events"), "REQUEST", "headers.x-hook-token", "token", 0.9),
    (E("GET /v1/users/{id}"), "RESPONSE", "bank_card", "bank_card", 0.75),
    (E("GET /v1/users/profile"), "RESPONSE", "real_name", "name", 0.85),
]
for (ep, d, path, dtype, conf) in SENS:
    print(f"""INSERT INTO api_sensitive_fields (id, endpoint_id, direction, structured_path, data_type, confidence)
VALUES ({q(U('sens:%s:%s' % (ep, path)))}, {ep}, {q(d)}, {q(path)}, {q(dtype)}, {conf})
ON CONFLICT (endpoint_id, direction, structured_path) DO NOTHING;""")

# ---------- 调用边（图谱/拓扑） ----------
EDGES = [
    ("gw-mobile-app", None, E("POST /v1/users/login"), 2300),
    ("gw-mobile-app", E("POST /v1/users/login"), E("GET /v1/users/{id}"), 5100),
    ("gw-mobile-app", E("GET /v1/users/{id}"), E("POST /v1/orders/{id}"), 1200),
    ("gw-mobile-app", E("POST /v1/cart/items"), E("POST /v1/orders/{id}"), 640),
    ("gw-partner-erp", None, E("GET /v1/products/{id}"), 2900),
    ("gw-partner-erp", E("GET /v1/products/{id}"), E("GET /v1/inventory/{id}"), 52),
    ("gw-pay-gateway", None, E("POST /v1/pay/callback"), 640),
    ("gw-frontend-web", None, E("GET /v1/products/search"), 95),
    ("gw-frontend-web", E("GET /v1/products/search"), E("GET /v1/products/{id}"), 88),
    ("gw-mobile-app", E("POST /v1/orders/{id}"), E("POST /v1/pay/callback"), 610),
]
for (caller, src, tgt, n) in EDGES:
    src_sql = "NULL" if src is None else src
    print(f"""INSERT INTO api_call_edges (id, caller_fingerprint, source_endpoint_id, target_endpoint_id,
  call_count, first_seen_at, last_seen_at)
VALUES ({q(U('edge:%s>%s' % (caller, tgt)))}, {q(H(caller)[:24])}, {src_sql}, {tgt}, {n},
  now() - interval '14 days', now() - interval '1 hour')
ON CONFLICT (id) DO NOTHING;""")

# ---------- 风险发现 ----------
# (endpoint|None, type, severity, status, title, detail, days_ago)
FDS = [
    (E("GET /openapi/v2/status"), "SHADOW", "MEDIUM", "OPEN", "未登记的接口 /openapi/v2/status", {"signal":"lifecycle.new_endpoint"}, 1),
    (E("GET /v1/ghost/ping"), "SHADOW", "HIGH", "OPEN", "未知来源调用 /v1/ghost/ping", {"signal":"no_known_endpoint"}, 1),
    (E("POST /internal/debug/vars"), "SHADOW", "CRITICAL", "ACKNOWLEDGED", "疑似调试端点暴露", {"signal":"debug_path"}, 0),
    (E("GET /v1/sitecheck/health"), "SHADOW", "LOW", "RESOLVED", "健康检查端点未登记", {}, 3),
    (E("GET /v1/legacy/report"), "ZOMBIE", "MEDIUM", "OPEN", "废弃 45 天仍有调用", {"last_seen_days":45}, 2),
    (E("GET /v1/sessions/{id}"), "ZOMBIE", "LOW", "ACKNOWLEDGED", "旧会话接口低频存活", {}, 5),
    (E("GET /v1/legacy/report"), "DEPRECATED", "MEDIUM", "OPEN", "已标记 DEPRECATED 仍被调用", {"hits":5}, 2),
    (E("POST /v1/auth/refresh"), "DEPRECATED", "LOW", "RESOLVED", "刷新令牌旧版本", {}, 6),
    (E("GET /v1/users/{id}"), "BOLA", "HIGH", "OPEN", "无凭据访问对象段 /users/{id}", {"rule":"resource.unauthenticated_object_access"}, 1),
    (E("GET /v1/users/{id}"), "BOLA", "MEDIUM", "ACKNOWLEDGED", "连续数字 ID 枚举疑似", {"id_range":"1001-1020"}, 2),
    (E("GET /v1/inventory/{id}"), "BOLA", "MEDIUM", "OPEN", "库存对象跨身份访问", {}, 1),
    (E("GET /v1/users/profile"), "BFLA", "HIGH", "OPEN", "低权限身份调用管理功能", {}, 1),
    (E("GET /v1/metrics"), "BFLA", "MEDIUM", "FALSE_POSITIVE", "监控端点功能级越权误报", {}, 4),
    (E("POST /v1/orders/{id}"), "SCHEMA_DEVIATION", "MEDIUM", "OPEN", "undefined field: coupon_ext", {"rule":"schema.undefined_field"}, 1),
    (E("POST /v1/orders/{id}"), "SCHEMA_DEVIATION", "HIGH", "OPEN", "type mismatch: total(string)", {"rule":"schema.type_mismatch"}, 1),
    (E("POST /v1/users/login"), "SCHEMA_DEVIATION", "LOW", "ACKNOWLEDGED", "missing field: captcha", {"rule":"schema.missing_field"}, 2),
    (E("GET /v1/users/{id}"), "SCHEMA_DEVIATION", "MEDIUM", "RESOLVED", "undefined field: avatar_url", {}, 3),
    (E("GET /v1/users/{id}"), "SENSITIVE_LEAK", "HIGH", "OPEN", "响应明文返回手机号", {"field":"phone"}, 1),
    (E("GET /v1/users/profile"), "SENSITIVE_LEAK", "CRITICAL", "OPEN", "响应明文返回身份证号", {"field":"id_card"}, 0),
    (E("POST /v1/orders/{id}"), "BEHAVIOR_ANOMALY", "MEDIUM", "ACKNOWLEDGED", "单一身份突发高频调用（3x 基线）", {"rule":"behavior.rate_spike"}, 2),
]
for (ep, ftype, sev, st, title, detail, ago) in FDS:
    print(f"""INSERT INTO api_runtime_findings (id, endpoint_id, request_id, finding_type, severity, status,
  title, detail, first_seen_at, last_seen_at)
VALUES ({q(U('fd:%s:%s' % (ftype, title)))}, {ep}, '', {q(ftype)}, {q(sev)}, {q(st)}, {q(title)},
  {q(J(detail))}::jsonb, now() - interval '{ago} days', now() - interval '{max(ago-1,0)} days')
ON CONFLICT (id) DO NOTHING;""")

# ---------- Schema 违例 ----------
VIOS = [
    (E("POST /v1/orders/{id}"), "undefined_field", "coupon_ext", "-", "string", "OBSERVE", 3),
    (E("POST /v1/orders/{id}"), "type_mismatch", "total", "number", "string", "BLOCK", 5),
    (E("POST /v1/orders/{id}"), "missing_field", "items", "array", "-", "OBSERVE", 2),
    (E("POST /v1/users/login"), "missing_field", "captcha", "string", "-", "OBSERVE", 7),
    (E("GET /v1/users/{id}"), "undefined_field", "avatar_url", "-", "string", "OBSERVE", 4),
    (E("POST /v1/pay/callback"), "type_mismatch", "amount", "number", "string", "BLOCK", 1),
    (E("GET /v1/products/{id}"), "type_mismatch", "id", "number", "string", "OBSERVE", 6),
    (E("POST /v1/users/login"), "undefined_field", "device_fp", "-", "string", "OBSERVE", 2),
    (E("POST /v1/orders/{id}"), "type_mismatch", "id", "number", "string", "BLOCK", 8),
    (E("GET /v1/orders"), "undefined_field", "sort", "-", "string", "OBSERVE", 1),
    (E("POST /v1/webhook/events"), "missing_field", "event_type", "string", "-", "OBSERVE", 3),
    (E("POST /v1/pay/callback"), "missing_field", "sign", "string", "-", "OBSERVE", 2),
]
for (ep, vt, field, want, got, act, hours) in VIOS:
    print(f"""INSERT INTO api_schema_violations (id, endpoint_id, model_version_id, request_id,
  violation_type, field_path, expected, observed, action_taken, occurred_at)
VALUES ({q(U('vio:%s:%s:%d' % (ep, field, hours)))}, {ep}, NULL, {q('seed-vio-%s-%d' % (field, hours))},
  {q(vt)}, {q(field)}, {q(want)}, {q(got)}, {q(act)}, now() - interval '{hours} hours')
ON CONFLICT (id) DO NOTHING;""")

# ---------- 生命周期事件 ----------
LCS = [
    (E("POST /v1/orders/{id}"), "DISCOVERED", "CONFIRMED", "人工确认为正式资产", "sec_admin_s5", 11),
    (E("GET /v1/orders"), "DISCOVERED", "CONFIRMED", "批量确认", "sec_admin_s5", 9),
    (E("POST /v1/pay/callback"), "DISCOVERED", "CONFIRMED", "人工确认", "sec_admin_s5", 8),
    (E("GET /v1/users/{id}"), "DISCOVERED", "CONFIRMED", "人工确认", "sec_admin_s5", 19),
    (E("POST /v1/users/login"), "DISCOVERED", "CONFIRMED", "人工确认", "sec_admin_s5", 17),
    (E("POST /v1/auth/refresh"), "CONFIRMED", "IGNORED", "旧版刷新接口不再维护", "sec_admin_s5", 6),
    (E("GET /v1/legacy/report"), "CONFIRMED", "DEPRECATED", "报表迁移到新接口", "sec_admin_s5", 44),
    (E("GET /v1/sessions/{id}"), "CONFIRMED", "DEPRECATED", "会话接口 v2 上线", "sec_admin_s5", 40),
    (E("GET /v1/metrics"), "DISCOVERED", "IGNORED", "内部监控端点不纳入资产", "sec_admin_s5", 10),
    (E("GET /v1/users/{id}"), "", "MERGED", "合并端点 /v1/users/{name}", "sec_admin_s5", 18),
    (E("POST /v1/orders/{id}"), "", "SPLIT", "拆分出 /v1/orders/{id}/items", "sec_admin_s5", 7),
    (E("GET /v1/users/{id}"), "LEARNING", "PAUSED", "停止学习", "sec_admin_s5", 16),
]
for (ep, frm, to, reason, actor, ago) in LCS:
    print(f"""INSERT INTO api_lifecycle_events (id, endpoint_id, from_status, to_status, reason, actor, created_at)
VALUES ({q(U('lc:%s:%s' % (ep, reason)))}, {ep}, {q(frm)}, {q(to)}, {q(reason)}, {q(actor)},
  now() - interval '{ago} days')
ON CONFLICT (id) DO NOTHING;""")

# ---------- 模型评审 ----------
for (mid, action, comment, ago) in [
    (mv_ids[(E("POST /v1/users/login"),2)], "SUBMIT", "新增 captcha 可选字段，请评审", 2),
    (mv_ids[(E("GET /v1/users/{id}"),1)], "APPROVE", "字段稳定，同意冻结", 18),
    (mv_ids[(E("POST /v1/auth/token"),1)], "REJECT", "app_secret 不应出现在模型", 5),
]:
    print(f"""INSERT INTO api_model_reviews (id, model_version_id, action, comment, created_at)
VALUES ({q(U('rev:%s:%s' % (mid, action)))}, {q(mid)}, {q(action)}, {q(comment)}, now() - interval '{ago} days')
ON CONFLICT (id) DO NOTHING;""")

# ---------- 统一运行时事件（统计/事件页数据源） ----------
ev_eps = [
    ("POST /v1/orders/{id}", "BLOCK", "HIGH", 70, [("api_schema","schema.type_mismatch","BLOCK","HIGH",40)]),
    ("POST /v1/orders/{id}", "OBSERVE", "MEDIUM", 25, [("authentication","auth.unauthenticated_api","OBSERVE","MEDIUM",10)]),
    ("GET /v1/users/{id}", "OBSERVE", "MEDIUM", 15, [("resource_access","resource.unauthenticated_object_access","OBSERVE","MEDIUM",15)]),
    ("GET /v1/users/{id}", "ALLOW", "NONE", 0, []),
    ("POST /v1/users/login", "OBSERVE", "LOW", 5, [("identity","identity.token_present","INFO","INFO",0)]),
    ("GET /v1/products/{id}", "ALLOW", "NONE", 0, []),
    ("POST /v1/pay/callback", "BLOCK", "HIGH", 40, [("api_schema","schema.type_mismatch","BLOCK","HIGH",40)]),
    ("GET /v1/legacy/report", "OBSERVE", "MEDIUM", 10, [("lifecycle","lifecycle.deprecated_api_call","OBSERVE","MEDIUM",10)]),
    ("GET /openapi/v2/status", "OBSERVE", "LOW", 5, [("lifecycle","lifecycle.new_endpoint","OBSERVE","LOW",5)]),
    ("GET /v1/ghost/ping", "OBSERVE", "MEDIUM", 20, [("lifecycle","lifecycle.new_endpoint","OBSERVE","LOW",5),("resource_access","resource.unauthenticated_object_access","OBSERVE","MEDIUM",15)]),
]
level_map = {"NONE":0,"LOW":5,"MEDIUM":25,"HIGH":70}
for i in range(22):
    ep, act, lvl, score, dets = ev_eps[i % len(ev_eps)]
    details = [{"detector":d[0],"rule_id":d[1],"category":d[2],"severity":d[3],"message":d[1],
                "evidence":{},"score_delta":d[4]} for d in dets]
    print(f"""INSERT INTO api_runtime_events (id, request_id, endpoint_key, risk_score, risk_level,
  final_action, details_json, occurred_at)
VALUES ({q(U('ev:%d' % i))}, {q('seed-ev-%04d' % i)}, {q(ep)}, {score}, {q(lvl)}, {q(act)},
  {q(J(details))}::jsonb, now() - interval '{i*47} minutes')
ON CONFLICT (id) DO NOTHING;""")

print("COMMIT;")
print("SELECT 'endpoints', count(*) FROM api_endpoints;")
print("SELECT 'model_versions', count(*) FROM api_model_versions;")
print("SELECT 'parameters', count(*) FROM api_parameter_models;")
print("SELECT 'samples', count(*) FROM api_learning_samples;")
print("SELECT 'sensitive', count(*) FROM api_sensitive_fields;")
print("SELECT 'edges', count(*) FROM api_call_edges;")
print("SELECT 'findings', count(*) FROM api_runtime_findings;")
print("SELECT 'violations', count(*) FROM api_schema_violations;")
print("SELECT 'lifecycle', count(*) FROM api_lifecycle_events;")
print("SELECT 'runtime_events', count(*) FROM api_runtime_events;")
PYEOF

echo "[seed] SQL 造数完成"

# ---------- 3. 真实 API：两个 FORMAL 模型（orders 与 users） ----------
mkmodel() { # $1=endpoint_key $2=schema_json
  local epid kw
  kw=$(python3 -c "import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1].split(' ',1)[1]))" "$1")
  epid=$(curl -s -b "/tmp/s5-$SEC_USER.txt" "$API_URL/api/v1/api-security/endpoints?keyword=$kw&page_size=20" | python3 -c "
import json,sys
items=json.load(sys.stdin)['data']['items']
print(next((i['id'] for i in items if i['endpoint_key']=='$1'),''))" 2>/dev/null)
  [ -z "$epid" ] && { echo "[seed] endpoint 未找到: $1"; return; }
  # 已有 FORMAL 则跳过（幂等）
  local formal
  formal=$(curl -s -b "/tmp/s5-$SEC_USER.txt" "$API_URL/api/v1/api-security/endpoints/$epid/models?page_size=20" | python3 -c "
import json,sys
items=json.load(sys.stdin)['data']['items']
print(next((v['id'] for v in items if v['status']=='FORMAL'),''))" 2>/dev/null)
  if [ -n "$formal" ]; then echo "[seed] 已有 FORMAL: $1"; return; fi
  local vid
  vid=$(curl -s -b "/tmp/s5-$SEC_USER.txt" -X POST "$API_URL/api/v1/api-security/endpoints/$epid/models" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" \
    -d "{\"schema\":$2,\"change_summary\":\"演示初始模型\"}" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['version']['id'])" 2>/dev/null)
  [ -n "$vid" ] && curl -s -o /dev/null -b "/tmp/s5-$SEC_USER.txt" -X POST "$API_URL/api/v1/api-security/models/$vid/confirm" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" -d '{}'
  echo "[seed] FORMAL 模型已冻结: $1 ($vid)"
}
mkmodel "POST /v1/orders/{id}" '{"id":"number","items":"array","total":"number","currency":"string"}'
mkmodel "GET /v1/users/{id}" '{"id":"number","name":"string","phone":"string","email":"string"}'

# ---------- 4. 真实 API：OpenAPI 规范导入（生成规范对比差异） ----------
SPEC_EXIST=$(curl -s -b "/tmp/s5-$SEC_USER.txt" "$API_URL/api/v1/api-security/specs?page_size=5" | python3 -c "
import json,sys
items=json.load(sys.stdin)['data']['items']
print(next((s['id'] for s in items if s.get('file_name')=='shop-openapi-demo.json'),''))" 2>/dev/null)
if [ -z "$SPEC_EXIST" ]; then
  curl -s -b "/tmp/s5-$SEC_USER.txt" -X POST "$API_URL/api/v1/api-security/specs/import" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" -d @- << 'JSON' | python3 -c "
import json,sys
d=json.load(sys.stdin)
print('[seed] 规范导入:', d.get('data',{}).get('message', d.get('message')))"
{"file_name":"shop-openapi-demo.json","spec":{
 "openapi":"3.0.1","info":{"title":"商城开放接口（演示）","version":"1.0.0"},
 "paths":{
  "/v1/orders/{id}":{"post":{"summary":"创建订单"}},
  "/v1/orders":{"get":{"summary":"订单列表"}},
  "/v1/orders/export":{"post":{"summary":"订单导出"}},
  "/v1/users/{id}":{"get":{"summary":"用户详情"}},
  "/v1/users/import":{"post":{"summary":"批量导入用户"}},
  "/v1/reports/daily":{"get":{"summary":"日报下载"}}
 }}}
JSON
else
  echo "[seed] 规范已存在: $SPEC_EXIST"
fi

# ---------- 5. 发布（FORMAL 模型与已知端点基线下发网关） ----------
PUB=$(s5_publish "$SEC_CSRF")
echo "[seed] 发布: $PUB"

echo "============================================================"
echo "阶段8 演示数据种子完成"
echo "============================================================"
