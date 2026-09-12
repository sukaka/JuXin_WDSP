#!/usr/bin/env bash
# 用途：为本地演示环境（stage5 测试栈）补充「访问控制与防护策略域」列表页演示数据。
#
# 覆盖接口：/access-rules /l7-rules /rate-limit-policies /protection-policies
#   /protected-addresses /trusted-proxies /exceptions /temporary-blocks
#   /custom-rules /rule-overrides /system-alerts，并触发一次配置发布。
#
# 纪律：
#   - 优先走真实管理 API（过业务校验）；temporary-blocks / system-alerts 无写接口，直接 SQL。
#   - SQL 造数用确定性 UUID（uuid5）+ ON CONFLICT DO NOTHING，幂等可重跑；
#     API 造数以「名称/编码/rule_id 已存在则跳过」实现幂等。
#   - IP 仅用 RFC 5737 保留网段（192.0.2.x / 198.51.100.x / 203.0.113.x），域名仅 example.com 系。
#   - 本脚本只面向开发/演示环境，禁止用于生产库。
#
# 用法：bash scripts/demo/seed-access-control-demo.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$REPO_ROOT/test/waf/scripts/stage5-setup.sh"

PG_CONTAINER="${PG_CONTAINER:-jiuzhang-stage5-postgres}"
PG_USER="${POSTGRES_USER:-jiuzhang}"
PG_DB="${POSTGRES_DB:-jiuzhang_waf}"
SEC_COOKIE="/tmp/s5-$SEC_USER.txt"

echo "============================================================"
echo "访问控制与防护策略域 演示种子  api=$API_URL db=$PG_CONTAINER/$PG_DB"
echo "============================================================"

# ---------- 登录（系统管理员 + 安全管理员） ----------
SYS_CSRF=$(s5_ensure_sysadmin)
[ -z "$SYS_CSRF" ] && { echo "ERROR: 系统管理员登录失败"; exit 1; }
SEC_CSRF=$(s5_ensure_secuser "$SYS_CSRF")
[ -z "$SEC_CSRF" ] && { echo "ERROR: 安全管理员登录失败"; exit 1; }
echo "[login] sec_admin_s5 就绪"

# ---------- 解析演示应用 ID 与带规则证据的安全事件 ID ----------
psql_q() { docker exec "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -t -A -c "$1"; }
APP_SHOP=$(psql_q "SELECT id FROM applications WHERE code='shop-mall';")
APP_UC=$(psql_q "SELECT id FROM applications WHERE code='user-center';")
APP_OPEN=$(psql_q "SELECT id FROM applications WHERE code='open-gw';")
[ -z "$APP_SHOP" ] && { echo "ERROR: 演示应用 shop-mall 不存在，请先执行 stage8 种子"; exit 1; }

ev_for_app() {
  psql_q "SELECT e.id FROM security_events e
          WHERE e.application_id='$1'
            AND EXISTS (SELECT 1 FROM security_event_matches m WHERE m.event_id=e.id)
          ORDER BY e.occurred_at DESC LIMIT 1;"
}
EV_SHOP=$(ev_for_app "$APP_SHOP")
EV_UC=$(ev_for_app "$APP_UC")
EV_OPEN=$(ev_for_app "$APP_OPEN")
echo "[setup] shop=$APP_SHOP uc=$APP_UC open=$APP_OPEN ev_shop=$EV_SHOP ev_uc=$EV_UC ev_open=$EV_OPEN"

export API_URL SEC_CSRF SEC_COOKIE APP_SHOP APP_UC APP_OPEN EV_SHOP EV_UC EV_OPEN

# ---------- 第一部分：真实管理 API 造数 ----------
python3 - << 'PYEOF'
import datetime, json, os, subprocess, sys

API = os.environ["API_URL"].rstrip("/")
CSRF = os.environ["SEC_CSRF"]
COOKIE = os.environ["SEC_COOKIE"]
APP = {"shop": os.environ["APP_SHOP"], "uc": os.environ["APP_UC"], "open": os.environ["APP_OPEN"]}
EV = {"shop": os.environ["EV_SHOP"], "uc": os.environ["EV_UC"], "open": os.environ["EV_OPEN"]}

now = datetime.datetime.now(datetime.timezone.utc)
def iso(days=0, hours=0):
    return (now + datetime.timedelta(days=days, hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")

stats = {}
failures = []

def call(method, path, body=None):
    cmd = ["curl", "-s", "-b", COOKIE, "-X", method, API + path]
    if body is not None:
        cmd += ["-H", "Content-Type: application/json", "-H", "X-CSRF-Token: " + CSRF, "-d", json.dumps(body, ensure_ascii=False)]
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    try:
        return json.loads(out)
    except Exception:
        return {"code": "__PARSE_ERROR__", "raw": out[:400]}

def items(path):
    r = call("GET", path + ("&" if "?" in path else "?") + "page_size=500")
    return (r.get("data") or {}).get("items") or []

def ensure(resource, path, key_fn, body, note=""):
    """key_fn(item)->hashable；已存在则跳过，冲突视为跳过，其余错误记失败。"""
    k = key_fn(body)
    for it in items(path):
        if key_fn(it) == k:
            stats[resource] = stats.get(resource, [0, 0])
            stats[resource][1] += 1
            return None
    r = call("POST", path, body)
    if r.get("code") == "SUCCESS":
        stats[resource] = stats.get(resource, [0, 0])
        stats[resource][0] += 1
        d = r.get("data") or {}
        return d.get("id") or (d.get("exception") or {}).get("id") or (d.get("rule") or {}).get("id")
    msg = str(r)
    if "已存在" in msg or "CONFLICT" in msg or "conflict" in msg:
        stats[resource] = stats.get(resource, [0, 0])
        stats[resource][1] += 1
        return None
    failures.append((resource, k, r))
    return None

NAME = lambda b: b.get("name")
CODE = lambda b: b.get("code")
RID = lambda b: b.get("rule_id")

# ========== 1. IP 访问控制规则 /access-rules ==========
ar = [
    dict(name="演示-境外扫描源封禁", rule_type="DENY", scope_type="GLOBAL", address="192.0.2.10", priority=10, validity_type="PERMANENT", reason="持续扫描探测源，全网封禁"),
    dict(name="演示-撞库攻击网段封禁", rule_type="DENY", scope_type="GLOBAL", address="192.0.2.128/28", priority=20, validity_type="PERMANENT", reason="撞库攻击聚集网段"),
    dict(name="演示-运维跳板机白名单", rule_type="ALLOW", scope_type="GLOBAL", address="198.51.100.8", priority=5, validity_type="PERMANENT", reason="运维跳板机出口IP"),
    dict(name="演示-爬虫集群临时封禁", rule_type="DENY", scope_type="GLOBAL", address="192.0.2.96/27", priority=30, validity_type="TEMPORARY", effective_until=iso(days=7), reason="恶意爬虫集群，观察7天"),
    dict(name="演示-商城恶意下单IP", rule_type="DENY", scope_type="APPLICATION", application_id=APP["shop"], address="192.0.2.20", priority=40, validity_type="PERMANENT", reason="批量恶意下单"),
    dict(name="演示-商城支付回调白名单", rule_type="ALLOW", scope_type="APPLICATION", application_id=APP["shop"], address="198.51.100.16", priority=6, validity_type="PERMANENT", reason="支付平台回调出口"),
    dict(name="演示-商城薅羊毛临时封禁", rule_type="DENY", scope_type="APPLICATION", application_id=APP["shop"], address="192.0.2.33", priority=41, validity_type="TEMPORARY", effective_until=iso(days=3), reason="活动刷接口为，临时封禁3天"),
    dict(name="演示-用户中心爆破源封禁", rule_type="DENY", scope_type="APPLICATION", application_id=APP["uc"], address="192.0.2.44", priority=42, validity_type="PERMANENT", reason="登录接口暴力破解"),
    dict(name="演示-用户中心合作方白名单", rule_type="ALLOW", scope_type="APPLICATION", application_id=APP["uc"], address="198.51.100.32", priority=7, validity_type="PERMANENT", reason="合作方SSO回调"),
    dict(name="演示-开放网关越权调用源", rule_type="DENY", scope_type="APPLICATION", application_id=APP["open"], address="192.0.2.66", priority=43, validity_type="PERMANENT", reason="越权调用开放接口"),
    dict(name="演示-开放网关签约客户白名单", rule_type="ALLOW", scope_type="APPLICATION", application_id=APP["open"], address="198.51.100.48", priority=8, validity_type="PERMANENT", reason="签约客户固定出口"),
    dict(name="演示-开放网关滥用临时封禁", rule_type="DENY", scope_type="APPLICATION", application_id=APP["open"], address="192.0.2.80/28", priority=44, validity_type="TEMPORARY", effective_until=iso(days=1), reason="超出配额滥用，临时封禁1天"),
]
if EV["shop"]:
    ar.append(dict(name="演示-事件联动封禁-SQL注入", rule_type="DENY", scope_type="APPLICATION", application_id=APP["shop"],
                   address="192.0.2.200", priority=45, validity_type="PERMANENT",
                   source_type="SECURITY_EVENT", source_event_id=EV["shop"], reason="安全事件联动：SQL注入攻击源"))
if EV["uc"]:
    ar.append(dict(name="演示-事件联动封禁-撞库", rule_type="DENY", scope_type="GLOBAL",
                   address="192.0.2.11", priority=46, validity_type="TEMPORARY", effective_until=iso(days=5),
                   source_type="SECURITY_EVENT", source_event_id=EV["uc"], reason="安全事件联动：登录撞库攻击源"))
for b in ar:
    b.setdefault("source_type", "MANUAL")
    ensure("access-rules", "/api/v1/access-rules", NAME, b)

# ========== 2. L7 访问控制规则 /l7-rules ==========
def l7(name, prio, conds, action, cfg=None, enabled=True):
    return dict(name=name, priority=prio, enabled=enabled, conditions=conds, action=action,
                action_config=cfg or {})
l7s = [
    l7("演示-封禁遗留后台路径扫描", 10, [dict(type="uri", op="prefix", value="/admin-backup")], "block",
       dict(status=403, message="Access Denied"), True),
    l7("演示-封禁TRACE/CONNECT方法", 20, [dict(type="method", values=["TRACE", "CONNECT"])], "block",
       dict(status=405, message="Method Not Allowed"), True),
    l7("演示-健康检查内网放行", 30, [dict(type="uri", op="prefix", value="/healthz"),
       dict(type="client_ip", values=["198.51.100.0/28"])], "allow", None, True),
    l7("演示-旧活动页跳转", 40, [dict(type="uri", op="eq", value="/old-promo")], "redirect",
       dict(redirect_url="https://shop.example.com/new-promo", redirect_status=302), True),
    l7("演示-维护窗口自定义页面", 50, [dict(type="uri", op="prefix", value="/maintenance-demo")], "custom_page",
       dict(status=503, content_type="text/html; charset=utf-8", body="<h1>系统维护中，请稍后访问</h1>"), False),
    l7("演示-内部调试参数拦截", 60, [dict(type="query", name="debug", op="eq", value="1")], "block",
       dict(status=403, message="Debug Forbidden"), False),
    l7("演示-未登录访问私有接口拦截", 70, [dict(type="uri", op="prefix", value="/api/private-demo"),
       dict(type="cookie", name="session_demo", op="not_exists")], "block",
       dict(status=401, message="Login Required"), True),
    l7("演示-仿冒WP路径拦截", 80, [dict(type="uri", op="regex", value="^/wp-content-demo/")], "block",
       dict(status=403, message="Forbidden"), True),
    l7("演示-合作伙伴网段放行", 90, [dict(type="client_ip", values=["192.0.2.64/27"]),
       dict(type="uri", op="prefix", value="/partner-demo")], "allow", None, False),
    l7("演示-可疑爬虫UA拦截", 100, [dict(type="header", name="User-Agent", op="contains", value="demo-bot")], "block",
       dict(status=403, message="Bot Rejected"), True),
    l7("演示-公开文档GET放行", 110, [dict(type="uri", op="prefix", value="/public-demo"),
       dict(type="method", values=["GET"])], "allow", None, True),
    l7("演示-缺失内部头的外部请求拦截", 120, [dict(type="uri", op="prefix", value="/internal-api-demo"),
       dict(type="header", name="X-Demo-Internal", op="not_exists")], "block",
       dict(status=403, message="Internal Only"), True),
]
for b in l7s:
    ensure("l7-rules", "/api/v1/l7-rules", NAME, b)

# ========== 3. CC 限速策略 /rate-limit-policies ==========
def rl(name, scope, app, match, pattern, dim, algo, limit, window, action, prio, **kw):
    b = dict(name=name, scope_type=scope, uri_match_type=match, uri_pattern=pattern,
             dimension=dim, algorithm=algo, requests_limit=limit, window_seconds=window,
             action=action, priority=prio, description=kw.pop("desc", ""), **kw)
    if app:
        b["application_id"] = app
    return b
rls = [
    rl("演示-全局IP限速观察", "GLOBAL", None, "ALL", "", "CLIENT_IP", "TOKEN_BUCKET", 1000, 60, "OBSERVE", 100, observe_only=True, desc="全局基线观察"),
    rl("演示-商城全站限速", "APPLICATION", APP["shop"], "ALL", "", "CLIENT_IP", "SLIDING_WINDOW", 300, 60, "REJECT", 110, desc="商城单IP 300req/min"),
    rl("演示-商城登录防爆破", "URI", APP["shop"], "EXACT", "/api/login", "CLIENT_IP", "TOKEN_BUCKET", 10, 60, "TEMP_BLOCK", 10, block_duration_seconds=600, desc="登录接口失败封禁10分钟"),
    rl("演示-用户中心短信防刷", "URI", APP["uc"], "PREFIX", "/api/sms", "CLIENT_IP", "SLIDING_WINDOW", 5, 60, "REJECT", 10, desc="短信验证码防刷"),
    rl("演示-开放网关租户级限速", "APPLICATION", APP["open"], "ALL", "", "CLIENT_IP_AND_APPLICATION", "TOKEN_BUCKET", 600, 60, "OBSERVE", 120, observe_only=True, desc="开放网关按IP+应用观察"),
    rl("演示-全局日志记录限速", "GLOBAL", None, "ALL", "", "CLIENT_IP", "SLIDING_WINDOW", 2000, 60, "LOG", 200, desc="超高频仅记录"),
    rl("演示-用户中心密码重置防滥", "URI", APP["uc"], "EXACT", "/api/password/reset", "CLIENT_IP", "TOKEN_BUCKET", 3, 300, "TEMP_BLOCK", 20, block_duration_seconds=1800, desc="密码重置5分钟3次"),
    rl("演示-商城搜索接口限速", "URI", APP["shop"], "PREFIX", "/api/search", "CLIENT_IP_AND_URI", "TOKEN_BUCKET", 120, 60, "REJECT", 30, burst_capacity=200, desc="搜索接口防爬"),
    rl("演示-开放网关导出限速", "URI", APP["open"], "REGEX", "^/v1/export", "CLIENT_IP", "SLIDING_WINDOW", 20, 3600, "REJECT", 40, desc="批量导出每小时20次"),
    rl("演示-商城商品详情限速观察", "URI", APP["shop"], "PREFIX", "/api/products", "CLIENT_IP", "TOKEN_BUCKET", 240, 60, "OBSERVE", 130, observe_only=True, desc="商品详情访问观察"),
    rl("演示-用户中心注册防批量", "URI", APP["uc"], "EXACT", "/api/register", "CLIENT_IP", "SLIDING_WINDOW", 8, 600, "REJECT", 50, desc="注册接口10分钟8次"),
    rl("演示-开放网关API全局兜底", "URI", APP["open"], "PREFIX", "/v1/", "CLIENT_IP_AND_URI", "TOKEN_BUCKET", 500, 60, "LOG", 210, desc="开放接口兜底记录"),
]
created_rl = {}
for b in rls:
    rid = ensure("rate-limit-policies", "/api/v1/rate-limit-policies", NAME, b)
    created_rl[b["name"]] = rid

# ========== 4. 防护策略 /protection-policies ==========
pls = [
    ("demo-plt-shop-protect", "演示-商城生产防护", "PROTECT", 2, 15, 15, "商城站生产防护策略"),
    ("demo-plt-shop-observe", "演示-商城新规则观察", "OBSERVE", 3, 10, 15, "新上线规则先观察"),
    ("demo-plt-uc-strict", "演示-用户中心严格防护", "PROTECT", 3, 10, 10, "账号体系严格防护"),
    ("demo-plt-open-observe", "演示-开放网关观察", "OBSERVE", 2, 20, 20, "开放API观察模式"),
    ("demo-plt-upload", "演示-上传接口专用", "PROTECT", 2, 12, 12, "上传场景放宽请求体"),
    ("demo-plt-api-json", "演示-纯JSON API 策略", "PROTECT", 2, 15, 15, "仅启用JSON解析"),
    ("demo-plt-legacy-off", "演示-遗留系统停用", "OFF", 1, 25, 25, "遗留系统迁移期停用"),
    ("demo-plt-high-sec", "演示-高安全等级", "PROTECT", 4, 5, 5, "高敏业务最高执行等级"),
    ("demo-plt-perf", "演示-性能优先", "PROTECT", 1, 30, 30, "高并发低等级低开销"),
    ("demo-plt-partner", "演示-合作方联调观察", "OBSERVE", 2, 18, 18, "合作方联调期观察"),
]
for code, name, mode, pl, inb, out, desc in pls:
    ensure("protection-policies", "/api/v1/protection-policies", CODE,
           dict(code=code, name=name, description=desc, protection_mode=mode, paranoia_level=pl,
                inbound_anomaly_threshold=inb, outbound_anomaly_threshold=out,
                request_body_access=True, response_body_access=(mode != "OFF")))

# ========== 5. 保护地址 /protected-addresses ==========
pas = [
    dict(name="演示-堡垒机", address="203.0.113.10", description="运维堡垒机，禁止封禁"),
    dict(name="演示-监控探针", address="203.0.113.11", description="可用性监控探针"),
    dict(name="演示-发布机", address="203.0.113.12", description="CI 发布机"),
    dict(name="演示-日志采集器", address="203.0.113.13", description="日志采集节点"),
    dict(name="演示-备份服务器", address="203.0.113.14", description="备份服务器"),
    dict(name="演示-安全扫描器", address="203.0.113.15", description="内部漏洞扫描器"),
    dict(name="演示-管理终端段", cidr="203.0.113.192/28", description="运维管理终端网段"),
    dict(name="演示-容器节点段", cidr="203.0.113.224/28", description="容器节点保留段"),
]
for b in pas:
    ensure("protected-addresses", "/api/v1/protected-addresses", NAME, b)

# ========== 6. 可信代理 /trusted-proxies ==========
tps = [
    dict(name="演示-办公网出口代理", cidr="198.51.100.128/28", header_type="X_FORWARDED_FOR", priority=10, scope="GLOBAL", description="办公网统一出口"),
    dict(name="演示-云厂商WAF前置", cidr="198.51.100.144/28", header_type="X_FORWARDED_FOR", priority=20, scope="GLOBAL", description="云前置清洗回源"),
    dict(name="演示-CDN回源段A", cidr="198.51.100.160/27", header_type="X_FORWARDED_FOR", priority=30, scope="GLOBAL", description="CDN 回源节点段 A"),
    dict(name="演示-CDN回源段B", cidr="198.51.100.192/27", header_type="X_FORWARDED_FOR", priority=40, scope="GLOBAL", description="CDN 回源节点段 B"),
    dict(name="演示-专线出口代理", cidr="192.0.2.224/28", header_type="X_REAL_IP", priority=50, scope="GLOBAL", description="合作伙伴专线出口"),
    dict(name="演示-内部负载均衡", cidr="192.0.2.240/28", header_type="X_FORWARDED_FOR", priority=60, scope="GLOBAL", description="内部 LVS/SLB 节点"),
    dict(name="演示-节点1前置代理", cidr="203.0.113.64/27", header_type="X_FORWARDED_FOR", priority=70, scope="NODE", node_name="gateway-node-1", description="节点1 前置代理段"),
    dict(name="演示-节点2前置代理", cidr="203.0.113.96/28", header_type="X_FORWARDED_FOR", priority=71, scope="NODE", node_name="gateway-node-2", description="节点2 前置代理段"),
    dict(name="演示-自定义头代理", cidr="198.51.100.224/28", header_type="CUSTOM", custom_header_name="X-Demo-Client-IP", priority=80, scope="GLOBAL", description="使用自定义头传递真实IP"),
    dict(name="演示-灰度环境代理", cidr="192.0.2.208/29", header_type="X_FORWARDED_FOR", priority=90, scope="GLOBAL", description="灰度环境前置"),
    dict(name="演示-运营商NAT出口", cidr="203.0.113.112/29", header_type="X_REAL_IP", priority=95, scope="GLOBAL", description="运营商级 NAT 出口"),
    dict(name="演示-应急旁路代理", cidr="198.51.100.240/29", header_type="X_FORWARDED_FOR", priority=100, scope="GLOBAL", description="应急旁路通道（停用）"),
]
for b in tps:
    pid = ensure("trusted-proxies", "/api/v1/trusted-proxies", NAME, b)
    if pid and b["name"] == "演示-应急旁路代理":
        call("POST", "/api/v1/trusted-proxies/%s/disable" % pid, {})

# ========== 7. 自定义规则 /custom-rules ==========
crs_ = [
    dict(rule_id=7100001, name="演示-拦截非常用UA", description="拦截已知扫描器UA", attack_type="SCANNER", severity="WARNING", phase=1, operator="rx", operator_value="(?i)(sqlmap|nikto|nmap-demo)", target_variables=["REQUEST_HEADERS:User-Agent"], action="BLOCK", tags=["scanner", "demo"]),
    dict(rule_id=7100002, name="演示-联合查询注入拦截", description="拦截 union select 特征", attack_type="SQLI", severity="CRITICAL", phase=2, operator="contains", operator_value="union select", target_variables=["ARGS"], action="BLOCK", tags=["sqli", "demo"]),
    dict(rule_id=7100003, name="演示-POST参数SQLi观察", description="POST 参数 SQLi 语义检测观察", attack_type="SQLI", severity="WARNING", phase=2, operator="detectSQLi", operator_value="", target_variables=["ARGS_POST"], action="OBSERVE", tags=["sqli", "demo"]),
    dict(rule_id=7100004, name="演示-仿冒管理后台路径", description="拦截 /demo-admin 前缀访问", attack_type="PATH_PROBE", severity="ERROR", phase=1, operator="beginsWith", operator_value="/demo-admin", target_variables=["REQUEST_URI"], action="BLOCK", tags=["path", "demo"]),
    dict(rule_id=7100005, name="演示-内部网段放行标记", description="记录内部保留网段访问", attack_type="INTERNAL", severity="NOTICE", phase=1, operator="ipMatch", operator_value="198.51.100.0/25", target_variables=["REMOTE_ADDR"], action="LOG", tags=["internal", "demo"]),
    dict(rule_id=7100006, name="演示-危险PURGE方法拦截", description="拦截缓存清除方法滥用", attack_type="PROTOCOL", severity="ERROR", phase=1, operator="streq", operator_value="PURGE", target_variables=["REQUEST_METHOD"], action="BLOCK", tags=["method", "demo"]),
    dict(rule_id=7100007, name="演示-备份文件探测拦截", description="拦截 .bak/.swp 文件探测", attack_type="FILE_PROBE", severity="ERROR", phase=1, operator="rx", operator_value="\\.(bak|swp|old)$", target_variables=["REQUEST_BASENAME"], action="BLOCK", tags=["file", "demo"]),
    dict(rule_id=7100008, name="演示-路径穿越观察", description="观察 ../ 路径穿越尝试", attack_type="LFI", severity="WARNING", phase=1, operator="rx", operator_value="\\.\\./", target_variables=["REQUEST_URI"], action="OBSERVE", tags=["lfi", "demo"]),
    dict(rule_id=7100009, name="演示-URL编码异常记录", description="记录 URL 编码异常请求", attack_type="PROTOCOL", severity="NOTICE", phase=1, operator="validateUrlEncoding", operator_value="", target_variables=["ARGS"], action="LOG", tags=["encoding", "demo"]),
    dict(rule_id=7100010, name="演示-GET参数XSS观察", description="GET 参数 XSS 语义检测观察", attack_type="XSS", severity="WARNING", phase=2, operator="detectXSS", operator_value="", target_variables=["ARGS_GET"], action="OBSERVE", tags=["xss", "demo"]),
    dict(rule_id=7100011, name="演示-数据库基准函数拦截", description="拦截 benchmark 时间盲注特征", attack_type="SQLI", severity="CRITICAL", phase=2, operator="contains", operator_value="benchmark(", target_variables=["ARGS_POST"], action="BLOCK", tags=["sqli", "demo"]),
    dict(rule_id=7100012, name="演示-异常长UA记录", description="记录超长UA（缓冲区探测）", attack_type="PROTOCOL", severity="NOTICE", phase=1, operator="rx", operator_value="^.{512,}$", target_variables=["REQUEST_HEADERS:User-Agent"], action="LOG", tags=["protocol", "demo"]),
]
for b in crs_:
    ensure("custom-rules", "/api/v1/custom-rules", RID, b)

# ========== 8. WAF 例外 /exceptions ==========
exc_ids = []
def exc(body):
    eid = ensure("exceptions", "/api/v1/exceptions", NAME, body)
    if eid:
        exc_ids.append((eid, body["name"]))
    return eid
exc(dict(name="演示-优惠券接口SQLi误报例外", description="优惠券批量接口参数误报", scope_type="APPLICATION",
         application_id=APP["shop"], uri_prefix="/api/coupon", methods=["POST"], rule_ids=[942100],
         exception_action="REMOVE_RULE", reason="业务参数含SQL关键字，误报处置"))
exc(dict(name="演示-头像上传XSS误报例外", description="富文本头像描述字段误报", scope_type="APPLICATION",
         application_id=APP["uc"], uri_exact="/api/profile/avatar", methods=["POST", "PUT"], rule_ids=[941100],
         exception_action="REMOVE_RULE", reason="富文本内容触发XSS规则误报"))
exc(dict(name="演示-开放网关Webhook参数例外", description="Webhook payload 字段摘除检测", scope_type="APPLICATION",
         application_id=APP["open"], uri_prefix="/v1/webhook", methods=["POST"], param_names=["payload"],
         exception_action="REMOVE_VAR_DETECTION", reason="payload 为下游转发的原始报文"))
exc(dict(name="演示-评论接口XSS标签例外", description="评论接口摘除 XSS 标签族", scope_type="APPLICATION",
         application_id=APP["shop"], uri_prefix="/api/comment", methods=["POST"], rule_tags=["attack-xss"],
         exception_action="REMOVE_RULE_TAG", reason="评论支持有限HTML，误报较多"))
exc(dict(name="演示-健康检查长URI例外", description="监控长URI触发协议规则", scope_type="GLOBAL",
         domain="open.example.com", uri_prefix="/healthz-full", methods=["GET"], rule_ids=[920270],
         exception_action="REMOVE_RULE", reason="监控探针长URI误报", risk_acknowledged=True))
exc(dict(name="演示-内部调用协议例外", description="内部保留网段调用摘除协议校验", scope_type="APPLICATION",
         application_id=APP["uc"], uri_prefix="/internal/", methods=["GET", "POST"],
         source_ips=["198.51.100.64/28"], rule_ids=[920440],
         exception_action="REMOVE_RULE", reason="内部服务间调用 Content-Type 不规范"))
exc(dict(name="演示-批量导入临时例外", description="数据迁移期临时摘除注入规则", scope_type="APPLICATION",
         application_id=APP["open"], uri_prefix="/v1/import", methods=["POST"], rule_ids=[942120],
         exception_action="REMOVE_RULE", is_temporary=True, effective_from=iso(), effective_until=iso(days=14),
         reason="历史数据迁移临时例外，14天后到期"))
exc(dict(name="演示-遗留接口正则例外", description="遗留接口路径正则匹配例外", scope_type="APPLICATION",
         application_id=APP["shop"], uri_regex="^/api/legacy/.*$", methods=["GET"], rule_ids=[933130],
         exception_action="REMOVE_RULE", reason="遗留系统接口误报", risk_acknowledged=True))
exc(dict(name="演示-订单Schema学习期观察", description="API引擎：订单接口Schema缺失字段学习期", scope_type="APPLICATION",
         application_id=APP["shop"], uri_prefix="/v1/orders", methods=["POST"], target_engine="API",
         api_rule_refs=[dict(detector_id="api_schema", rule_id="schema.required_missing")],
         exception_action="OBSERVE_RULE", reason="客户端新旧版本并存，Schema 例外学习期"))
exc(dict(name="演示-数据接入解析容错", description="API引擎：接入接口解析异常容错", scope_type="APPLICATION",
         application_id=APP["open"], uri_prefix="/v1/ingest", methods=["POST"], target_engine="API",
         api_rule_refs=[dict(detector_id="api_parser", rule_id="parser.body_malformed")],
         exception_action="OBSERVE_RULE", reason="上游截断报文容错观察"))
# 事件联动例外（可信源：应用/路径/规则证据取自服务端事件记录；按 source_event_id 幂等）
existing_ev = {str(it.get("source_event_id") or "") for it in items("/api/v1/exceptions")}
for app_key, label in (("shop", "商城"), ("uc", "用户中心")):
    if not EV[app_key]:
        continue
    if EV[app_key] in existing_ev:
        stats["exceptions"] = stats.get("exceptions", [0, 0]); stats["exceptions"][1] += 1
        continue
    r = call("POST", "/api/v1/security-events/%s/create-exception" % EV[app_key], {})
    if r.get("code") == "SUCCESS":
        stats["exceptions"] = stats.get("exceptions", [0, 0]); stats["exceptions"][0] += 1
    elif "已存在" in str(r) or "CONFLICT" in str(r):
        stats["exceptions"] = stats.get("exceptions", [0, 0]); stats["exceptions"][1] += 1
    else:
        failures.append(("exceptions", "from-event-%s" % label, r))
# 启用精确例外（DRAFT → ENABLED，走启用门禁；失败仅记录不致命）
for eid, nm in exc_ids:
    if nm in ("演示-优惠券接口SQLi误报例外", "演示-头像上传XSS误报例外", "演示-内部调用协议例外",
              "演示-开放网关Webhook参数例外"):
        r = call("POST", "/api/v1/exceptions/%s/enable" % eid, {})
        if r.get("code") != "SUCCESS":
            print("[warn] 例外启用失败 %s: %s" % (nm, str(r)[:200]))

# ========== 9. 规则覆盖 /rule-overrides ==========
policies = {p["code"]: p["id"] for p in items("/api/v1/protection-policies")}
STRICT = policies.get("strict") or policies.get("demo-plt-high-sec") or ""
STANDARD = policies.get("standard") or policies.get("demo-plt-shop-protect") or ""
def ovr(rule_id, scope, sid, action, reason, sev="", **kw):
    b = dict(rule_id=rule_id, scope_type=scope, action=action, reason=reason, **kw)
    if sid:
        b["scope_id"] = sid
    if sev:
        b["severity_override"] = sev
    return b
OKEY = lambda b: (b.get("rule_id"), b.get("scope_type"), b.get("scope_id") or None)
ovrs = [
    ovr(942100, "APPLICATION", APP["shop"], "DISABLE", "演示-商城搜索框SQLi高误报关闭"),
    ovr(942100, "APPLICATION", APP["uc"], "SEVERITY_OVERRIDE", "演示-用户中心降级为ERROR观察", sev="ERROR"),
    ovr(941100, "APPLICATION", APP["open"], "DISABLE", "演示-开放网关JSON报文XSS误报关闭"),
    ovr(920440, "GLOBAL", None, "SEVERITY_OVERRIDE", "演示-全局降级文件扩展名规则", sev="NOTICE"),
    ovr(949110, "APPLICATION", APP["shop"], "SEVERITY_OVERRIDE", "演示-商城入站评估提升为CRITICAL", sev="CRITICAL"),
    ovr(932100, "APPLICATION", APP["uc"], "DISABLE", "演示-用户中心RCE规则误报关闭"),
    ovr(920300, "GLOBAL", None, "DISABLE", "演示-全局关闭缺失Accept头规则"),
    ovr(920420, "APPLICATION", APP["open"], "SEVERITY_OVERRIDE", "演示-开放网关Content-Type降级", sev="WARNING"),
    ovr(944100, "GLOBAL", None, "ENABLE", "演示-全局启用反序列化检测"),
    ovr(950130, "APPLICATION", APP["shop"], "DISABLE", "演示-商城旧接口编码误报关闭",
        effective_until=iso(days=30)),
]
if STRICT:
    ovrs.append(ovr(933100, "POLICY", STRICT, "DISABLE", "演示-严格策略下PHP注入误报关闭"))
if STANDARD:
    ovrs.append(ovr(931130, "POLICY", STANDARD, "SEVERITY_OVERRIDE", "演示-标准策略RFI降级", sev="NOTICE"))
for b in ovrs:
    ensure("rule-overrides", "/api/v1/rule-overrides", OKEY, b)

# ---------- 汇总 ----------
print("\n[api-seed] 资源: 新建/跳过")
total_created = 0
for k in ["access-rules", "l7-rules", "rate-limit-policies", "protection-policies",
          "protected-addresses", "trusted-proxies", "custom-rules", "exceptions", "rule-overrides"]:
    c, s = stats.get(k, [0, 0])
    total_created += c
    print("  %-22s created=%d skipped=%d" % (k, c, s))
if failures:
    print("\n[api-seed] 失败明细:")
    for res, k, r in failures:
        print("  FAIL %s %s -> %s" % (res, k, str(r)[:300]))
    sys.exit(1)
print("[api-seed] 全部成功，新建 %d 条" % total_created)
PYEOF

echo "[api-seed] 完成"

# ---------- 第二部分：SQL 造数（temporary-blocks / system-alerts，无写 API） ----------
APP_SHOP="$APP_SHOP" APP_UC="$APP_UC" APP_OPEN="$APP_OPEN" \
python3 - << 'PYEOF' | docker exec -i "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -v ON_ERROR_STOP=1 --quiet
import os, uuid

NS = uuid.UUID("8f2e6c1a-9b3d-4e5f-a7c8-9d0e1f2a3b4c")
def U(key): return str(uuid.uuid5(NS, "jz-access-control-demo:" + key))
def q(v): return "NULL" if v is None else "'" + str(v).replace("'", "''") + "'"

A, B, C = os.environ["APP_SHOP"], os.environ["APP_UC"], os.environ["APP_OPEN"]

print("BEGIN;")

# ---- 临时封禁 temporary_blocks（14 条：ACTIVE/EXPIRED/MANUALLY_RELEASED）----
# (client_ip, app, trigger_type, policy_name(None=MANUAL), started_days_ago, expire_hours_from_now或-过期小时, status, hit_count)
RL = lambda name: "(SELECT id FROM rate_limit_policies WHERE name='%s' LIMIT 1)" % name
tbs = [
    ("192.0.2.100", A, "CC_AUTO", "演示-商城登录防爆破",      0, 6,    "ACTIVE", 87),
    ("192.0.2.101", A, "CC_AUTO", "演示-商城登录防爆破",      0, 2,    "ACTIVE", 43),
    ("192.0.2.102", B, "CC_AUTO", "演示-用户中心密码重置防滥", 0, 24,   "ACTIVE", 12),
    ("192.0.2.103", B, "CC_AUTO", "演示-用户中心短信防刷",    0, 1,    "ACTIVE", 31),
    ("192.0.2.104", C, "CC_AUTO", "演示-开放网关导出限速",    1, 30,   "ACTIVE", 9),
    ("192.0.2.105", A, "MANUAL",  None,                     0, 12,   "ACTIVE", 0),
    ("192.0.2.106", None, "MANUAL", None,                   1, 48,   "ACTIVE", 0),
    ("192.0.2.107", C, "CC_AUTO", "演示-开放网关导出限速",    2, 20,   "ACTIVE", 55),
    ("192.0.2.108", A, "CC_AUTO", "演示-商城登录防爆破",      3, -70,  "EXPIRED", 120),
    ("192.0.2.109", B, "CC_AUTO", "演示-用户中心短信防刷",    5, -118, "EXPIRED", 66),
    ("192.0.2.110", None, "MANUAL", None,                   6, -140, "EXPIRED", 0),
    ("192.0.2.111", A, "CC_AUTO", "演示-商城登录防爆破",      4, None, "MANUALLY_RELEASED", 95),
    ("192.0.2.112", B, "MANUAL",  None,                     7, None, "MANUALLY_RELEASED", 0),
    ("192.0.2.113", C, "CC_AUTO", "演示-开放网关导出限速",    8, None, "MANUALLY_RELEASED", 41),
]
for i, (ip, app, trig, pol, sd, eh, status, hits) in enumerate(tbs):
    started = "now() - interval '%d days %d hours'" % (sd, i % 9)
    if status == "ACTIVE":
        expires = "now() + interval '%d hours'" % eh
        rel_t = rel_at = "NULL"
    elif status == "EXPIRED":
        expires = "now() - interval '%d hours'" % (-eh)
        rel_t, rel_at = "'AUTO_EXPIRE'", "now() - interval '%d hours'" % (-eh)
    else:  # MANUALLY_RELEASED
        expires = "now() + interval '%d hours'" % (24 + i)
        rel_t, rel_at = "'MANUAL'", "now() - interval '%d hours'" % (i + 2)
    pol_sql = RL(pol) if pol else "NULL"
    print(f"""INSERT INTO temporary_blocks (id, client_ip, application_id, trigger_type, trigger_policy_id,
  block_started_at, block_expires_at, status, hit_count, release_type, released_at, created_at)
VALUES ({q(U('tb:%02d' % i))}, {q(ip)}, {q(app)}, {q(trig)}, {pol_sql},
  {started}, {expires}, {q(status)}, {hits}, {rel_t}, {rel_at}, {started})
ON CONFLICT DO NOTHING;""")

# ---- 系统告警 system_alerts（12 条，覆盖 OPEN/ACKNOWLEDGED/RESOLVED）----
# (alert_type, severity, component, title, message, status, days_ago_first, occ)
sas = [
    ("GATEWAY_DOWN",           "CRITICAL", "gateway-node-2",   "网关节点 gateway-node-2 心跳丢失", "连续 3 个心跳周期未收到节点上报", "RESOLVED", 13, 3),
    ("EVENT_COLLECTOR_LAG",    "HIGH",     "event-collector",  "事件采集积压超过阈值", "采集延迟 96s，超过阈值 60s", "ACKNOWLEDGED", 2, 37),
    ("CERTIFICATE_EXPIRING",   "MEDIUM",   "cert-manager",     "证书 shop.example.com 将于 25 天后到期", "请及时续期或更换证书", "OPEN", 3, 1),
    ("CONFIG_PUBLISH_FAILED",  "HIGH",     "publisher",        "配置发布任务失败", "发布任务锁冲突后重试耗尽", "RESOLVED", 9, 2),
    ("DISK_SPACE_LOW",         "HIGH",     "gateway-node-1",   "节点磁盘使用率 87%", "/var/log 分区剩余空间不足 15%", "ACKNOWLEDGED", 1, 12),
    ("SOURCE_UNHEALTHY",       "HIGH",     "upstream-shop",    "源站 shop-origin-2 健康检查失败", "连续 5 次健康检查超时", "OPEN", 0, 5),
    ("VALKEY_UNAVAILABLE",     "CRITICAL", "valkey",           "Valkey 连接失败", "缓存不可达，限速计数降级本地", "RESOLVED", 11, 1),
    ("LOGIN_BRUTE_FORCE",      "MEDIUM",   "auth-service",     "账号 demo_ops 连续登录失败锁定", "10 分钟内失败 6 次，已锁定 30 分钟", "OPEN", 0, 1),
    ("CC_BAN_SPIKE",           "MEDIUM",   "cc-guard",         "CC 封禁数量激增", "1 小时内新增封禁 42 条，超阈值 30", "OPEN", 1, 2),
    ("SECURITY_EVENT_SPIKE",   "HIGH",     "event-center",     "高危安全事件激增", "窗口内 HIGH/CRITICAL 事件 58 条，超阈值 50", "ACKNOWLEDGED", 4, 4),
    ("BACKUP_FAILED",          "MEDIUM",   "backup-job",       "每日备份任务失败", "备份上传校验和不匹配，已自动重试成功", "RESOLVED", 6, 2),
    ("DATABASE_CAPACITY_HIGH", "LOW",      "postgres",         "数据库容量使用率 72%", "表空间增长较快，建议规划扩容", "OPEN", 7, 1),
]
for i, (t, sev, comp, title, msg, status, days, occ) in enumerate(sas):
    first = "now() - interval '%d days %d hours'" % (days, (i * 3) % 11)
    last = "now() - interval '%d hours'" % max(0, days * 12 - 2)
    cols = ("id, alert_type, severity, component, title, message, status,\n"
            "  first_seen_at, last_seen_at, occurrence_count, created_at")
    vals = "%s, %s, %s, %s, %s, %s, %s,\n  %s, %s, %d, %s" % (
        q(U('alert:%02d' % i)), q(t), q(sev), q(comp), q(title), q(msg), q(status),
        first, last, occ, first)
    if status == "ACKNOWLEDGED":
        cols += ", acknowledged_at"
        vals += ", now() - interval '%d hours'" % max(1, days * 12 - 4)
    elif status == "RESOLVED":
        cols += ", resolved_at, resolve_type"
        vals += ", now() - interval '%d hours', 'MANUAL'" % max(1, days * 12 - 6)
    print("INSERT INTO system_alerts (%s)\nVALUES (%s)\nON CONFLICT DO NOTHING;" % (cols, vals))

print("COMMIT;")
PYEOF

echo "[sql-seed] temporary-blocks / system-alerts 完成"

# ---------- 第三部分：API 造数 created_at 铺开（演示观感，仅触碰本脚本演示行） ----------
docker exec -i "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" --quiet << 'SQL'
WITH t AS (SELECT id, row_number() OVER (ORDER BY created_at, name) rn FROM ip_access_rules WHERE name LIKE '演示-%')
UPDATE ip_access_rules r SET created_at = now() - (t.rn * interval '19 hours'),
  hit_count = (t.rn * 13) % 211,
  last_hit_at = CASE WHEN t.rn % 3 = 0 THEN NULL ELSE now() - (t.rn * interval '47 minutes') END
FROM t WHERE r.id = t.id;
WITH t AS (SELECT id, row_number() OVER (ORDER BY created_at, name) rn FROM l7_access_rules WHERE name LIKE '演示-%')
UPDATE l7_access_rules r SET created_at = now() - (t.rn * interval '21 hours') FROM t WHERE r.id = t.id;
WITH t AS (SELECT id, row_number() OVER (ORDER BY created_at, name) rn FROM rate_limit_policies WHERE name LIKE '演示-%')
UPDATE rate_limit_policies r SET created_at = now() - (t.rn * interval '23 hours') FROM t WHERE r.id = t.id;
WITH t AS (SELECT id, row_number() OVER (ORDER BY created_at, code) rn FROM protection_policies WHERE code LIKE 'demo-plt-%')
UPDATE protection_policies r SET created_at = now() - (t.rn * interval '25 hours') FROM t WHERE r.id = t.id;
WITH t AS (SELECT id, row_number() OVER (ORDER BY created_at, name) rn FROM protected_addresses WHERE name LIKE '演示-%')
UPDATE protected_addresses r SET created_at = now() - (t.rn * interval '27 hours') FROM t WHERE r.id = t.id;
WITH t AS (SELECT id, row_number() OVER (ORDER BY created_at, name) rn FROM trusted_proxies WHERE name LIKE '演示-%')
UPDATE trusted_proxies r SET created_at = now() - (t.rn * interval '17 hours') FROM t WHERE r.id = t.id;
WITH t AS (SELECT id, row_number() OVER (ORDER BY created_at, name) rn FROM custom_rules WHERE name LIKE '演示-%')
UPDATE custom_rules r SET created_at = now() - (t.rn * interval '22 hours') FROM t WHERE r.id = t.id;
WITH t AS (SELECT id, row_number() OVER (ORDER BY created_at, name) rn FROM exception_policies WHERE name LIKE '演示-%' OR name LIKE '事件例外-%')
UPDATE exception_policies r SET created_at = now() - (t.rn * interval '18 hours') FROM t WHERE r.id = t.id;
WITH t AS (SELECT id, row_number() OVER (ORDER BY created_at) rn FROM rule_overrides WHERE reason LIKE '演示-%')
UPDATE rule_overrides r SET created_at = now() - (t.rn * interval '20 hours') FROM t WHERE r.id = t.id;
SQL

echo "[spread] created_at 铺开完成"

# ---------- 第四部分：发布 ----------
echo "[publish] 触发配置发布..."
PUB=$(s5_publish "$SEC_CSRF")
echo "[publish] $PUB"
[ "$PUB" = "PUBLISH_OK" ] || { echo "ERROR: 发布失败"; exit 1; }

# ---------- 第五部分：验收 ----------
echo ""
echo "==================== 列表 total 验收 ===================="
FAIL=0
for p in access-rules l7-rules rate-limit-policies protection-policies protected-addresses \
         trusted-proxies exceptions temporary-blocks custom-rules rule-overrides system-alerts; do
  t=$(curl -s -b "$SEC_COOKIE" "$API_URL/api/v1/$p?page_size=1" | python3 -c "import json,sys;print(json.load(sys.stdin)['data']['total'])" 2>/dev/null || echo ERR)
  ok="OK"; if [ "$t" = "ERR" ] || [ "$t" -lt 12 ]; then ok="FAIL"; FAIL=1; fi
  printf "  /api/v1/%-22s total=%s [%s]\n" "$p" "$t" "$ok"
done
v=$(curl -s -b "$SEC_COOKIE" "$API_URL/api/v1/access-control/versions?page_size=1" | python3 -c "import json,sys;print(json.load(sys.stdin)['data']['total'])" 2>/dev/null || echo ERR)
printf "  /api/v1/%-22s total=%s\n" "access-control/versions" "$v"
[ "$FAIL" = "0" ] && echo "全部列表 total≥12，造数完成" || { echo "存在不达标列表"; exit 1; }
