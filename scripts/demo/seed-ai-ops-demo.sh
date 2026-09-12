#!/usr/bin/env bash
# AI 安全运营域演示数据种子（开发/演示环境）：
#   /ai/sessions、/ai/tasks、/ai/drafts(ai_recommendations)、/ai/noise/clusters、
#   /ai/noise/sweeps、/ai/audits（哈希链）、/ai/evaluation-runs。
#
# 内容设计：
#   1. AI 会话：事件分析/攻击链分析/误报研判/策略建议等，关联 demo security_events
#      （request_id 如 demo-gen-0001），jiuzhang_admin 与 sec_admin_s5 双账号可见。
#   2. AI 任务：挂在会话下（列表接口按会话归属过滤），含 SUCCESS/FAILED/CANCELLED。
#   3. AI 草稿（策略建议）：EXCEPTION/BLACKLIST/CC_POLICY/CUSTOM_RULE/POLICY_CHANGE/REPORT_SUMMARY。
#   4. 降噪聚簇：把 demo 的重复 SCANNER 事件（demo-gen-0004/0008/...）按 host+uri 聚类，
#      4 个聚簇真实关联 security_events，其余为指纹各异的合成聚簇。
#   5. 降噪扫描轮次：近 14 天每日一轮，含 SUCCESS/PARTIAL/FAILED。
#   6. AI 审计：严格按 server/internal/aiaudit/aiaudit.go 的 computeHash 公式
#      （sha256(occurred_at_utc_rfc3339nano|username|action|task_id或空|previous_hash)）
#      在本地构造完整哈希链；仅在表中无"非本种子"记录时插入，不破坏链式校验语义。
#   7. 评测运行：关联既有 ai_evaluation_sets，含 SUCCESS/FAILED 与用例明细。
#
# 幂等：确定性 UUID（uuid5）+ ON CONFLICT DO NOTHING，可重复执行。
# 数据安全：IP 仅用 RFC 5737 保留网段，域名 example.com 系，内容全部虚构。
# 用法：bash scripts/demo/seed-ai-ops-demo.sh
set -u
set -o pipefail
PG_CONTAINER="${PG_CONTAINER:-jiuzhang-stage5-postgres}"
PG_USER="${POSTGRES_USER:-jiuzhang}"
PG_DB="${POSTGRES_DB:-jiuzhang_waf}"

echo "============================================================"
echo "AI 安全运营域演示种子  db=$PG_CONTAINER/$PG_DB"
echo "============================================================"

# ---------- 运行时解析：用户 / 应用 / 模型 ----------
PSQL="docker exec $PG_CONTAINER psql -U $PG_USER -d $PG_DB -t -A"
ADMIN_ID=$($PSQL -c "SELECT id FROM users WHERE username='jiuzhang_admin' LIMIT 1;")
SEC_ID=$($PSQL -c "SELECT id FROM users WHERE username='sec_admin_s5' LIMIT 1;")
APP_A=$($PSQL -c "SELECT id FROM applications WHERE code='shop-mall' LIMIT 1;")
APP_B=$($PSQL -c "SELECT id FROM applications WHERE code='user-center' LIMIT 1;")
APP_C=$($PSQL -c "SELECT id FROM applications WHERE code='open-gw' LIMIT 1;")
MODEL_ID=$($PSQL -c "SELECT id FROM ai_models ORDER BY priority ASC LIMIT 1;")
echo "[setup] admin=$ADMIN_ID sec=$SEC_ID A=$APP_A B=$APP_B C=$APP_C model=$MODEL_ID"
[ -z "$ADMIN_ID" ] && { echo "ERROR: jiuzhang_admin 不存在"; exit 1; }
[ -z "$SEC_ID" ] && { echo "ERROR: sec_admin_s5 不存在"; exit 1; }
[ -z "$APP_A" ] && { echo "ERROR: 演示应用不存在，请先执行 stage8 演示种子"; exit 1; }

ADMIN_ID="$ADMIN_ID" SEC_ID="$SEC_ID" APP_A="$APP_A" APP_B="$APP_B" APP_C="$APP_C" MODEL_ID="$MODEL_ID" \
python3 - << 'PYEOF' | docker exec -i "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -v ON_ERROR_STOP=1 --quiet
import hashlib, json, os, uuid
from datetime import datetime, timedelta, timezone

NS = uuid.UUID("8f2e6c1a-9b3d-4e5f-a7c8-9d0e1f2a3b4c")
def U(key): return str(uuid.uuid5(NS, "jz-ai-ops-demo:" + key))
def H(s): return hashlib.sha256(s.encode()).hexdigest()
def J(o): return json.dumps(o, ensure_ascii=False)

ADMIN = os.environ["ADMIN_ID"]; SEC = os.environ["SEC_ID"]
A = os.environ["APP_A"]; B = os.environ["APP_B"]; C = os.environ["APP_C"]
MODEL = os.environ["MODEL_ID"]

def q(v):
    if v is None: return "NULL"
    return "'" + str(v).replace("'", "''") + "'"

NOW = datetime.now(timezone.utc).replace(microsecond=0)
def T(days, hour=10, minute=0, second=0, micro=0):
    return NOW - timedelta(days=days) + timedelta(hours=hour-10, minutes=minute, seconds=second, microseconds=micro)
def TS(t):  # SQL timestamptz 字面量（UTC）
    return t.strftime("%Y-%m-%d %H:%M:%S") + (".%06d" % t.microsecond if t.microsecond else "") + "+00"

print("BEGIN;")

# ============================================================
# 1. AI 会话（jiuzhang_admin 13 ACTIVE + 2 ARCHIVED；sec_admin_s5 6 ACTIVE）
# ============================================================
# (key, user, title, days_ago, scope_apps, summary, archived)
sessions = [
    ("s01", ADMIN, "事件分析：demo-gen-0001 XSS 攻击研判", 13, [A], "结论：真实 XSS 攻击，CRS 941 系命中，已阻断；同源性 IP 需持续观察。", False),
    ("s02", ADMIN, "事件分析：demo-gen-0000 SQL 注入研判", 12, [A], "结论：真实 SQL 注入（UNION 探测），异常评分 20，已阻断。", False),
    ("s03", ADMIN, "事件分析：demo-gen-0003 命令注入研判", 11, [A], "结论：真实命令注入（;cat /etc/passwd），已阻断。", False),
    ("s04", ADMIN, "攻击链分析：192.0.2.204 从扫描到注入的演进", 10, [A, C], "攻击者先探测 /.git/config，后升级为 SQL 注入与 XSS，符合典型侦察-利用链路。", False),
    ("s05", ADMIN, "攻击链分析：198.51.100.23 多阶段探测", 9, [B], "扫描→登录爆破→接口遍历，尚未进入利用阶段，建议提前封禁。", False),
    ("s06", ADMIN, "误报研判：/.git/config 扫描告警（shop-mall）", 8, [A], "聚簇内 3 起事件指纹一致，判 LIKELY_FALSE_POSITIVE（外部扫描器噪声）。", False),
    ("s07", ADMIN, "误报研判：/wp-login.php 扫描告警（open-gw）", 7, [C], "WordPress 特征探测与站点技术栈不符，判误报噪声，建议自动抑制。", False),
    ("s08", ADMIN, "规则解释：CRS 913100 扫描器检测", 6, [], "已解释 User-Agent 特征匹配逻辑与豁免方式。", False),
    ("s09", ADMIN, "策略建议：shop-mall CC 阈值调优", 5, [A], "建议 /api/login 限速收紧至 60 次/分钟，并产出 CC_POLICY 草稿。", False),
    ("s10", ADMIN, "策略建议：open-gw 黑名单加固", 4, [C], "建议将 198.51.100.0/25 中两个活跃扫描源加入黑名单。", False),
    ("s11", ADMIN, "What-If：封禁 192.0.2.0/24 影响评估", 3, [A], "评估结论：无白名单重叠，预计日阻断 300+ 扫描请求，无误伤。", False),
    ("s12", ADMIN, "周报摘要：近 7 天安全态势", 2, [A, B, C], "7 天阻断攻击 1.2k，扫描噪声占比 41%，建议开启自动抑制。", False),
    ("s13", ADMIN, "根因分析：uc.example.com 5xx 突增", 1, [B], "定位为源站连接池耗尽，与 WAF 策略无关，已出具说明。", False),
    ("s14", ADMIN, "事件分析：demo-gen-0002 路径穿越（已归档）", 6, [A], "研判完成并归档。", True),
    ("s15", ADMIN, "通用问答：CRS 基线配置（已归档）", 3, [], "问答完成并归档。", True),
    ("t01", SEC, "事件分析：demo-gen-0007 SQL 注入复核", 12, [A], "复核确认真实攻击，维持阻断。", False),
    ("t02", SEC, "误报研判：扫描器指纹聚簇复核", 9, [A, C], "确认 4 个扫描聚簇为噪声，同意抑制。", False),
    ("t03", SEC, "攻击画像：192.0.2.214 行为画像", 7, [C], "画像：自动化扫描器，UA 伪造，未发现手工操作痕迹。", False),
    ("t04", SEC, "策略建议：user-center 例外策略", 5, [B], "建议为内部健康检查路径加例外（草稿待审）。", False),
    ("t05", SEC, "日志查询：近 24h HIGH 事件梳理", 2, [], "输出 HIGH 事件清单与时间线。", False),
    ("t06", SEC, "报告摘要：本周误报处置情况", 1, [], "本周误报 9 起，处置率 100%。", False),
]

session_ids = {}
for key, user, title, days, apps, summary, archived in sessions:
    sid = U("session:" + key)
    session_ids[key] = sid
    created = T(days, 9, 15 + (days * 7) % 40)
    updated = created + timedelta(hours=1, minutes=23)
    status = "ARCHIVED" if archived else "ACTIVE"
    archived_at = q(TS(updated + timedelta(days=1))) if archived else "NULL"
    print(
        "INSERT INTO ai_sessions (id, user_id, title, status, project_scope, application_ids,"
        " context_summary, context_token_count, created_at, updated_at, archived_at) VALUES ("
        + ", ".join([q(sid), q(user), q(title), q(status), q(""), q(J([str(a) for a in apps])),
                     q(summary), q(1200 + days * 137), q(TS(created)), q(TS(updated)), archived_at])
        + ") ON CONFLICT DO NOTHING;"
    )

# ============================================================
# 2. 会话消息（每会话一问一答，演示详情页可读）
# ============================================================
MSG = {
    "s01": ("帮我分析安全事件 demo-gen-0001，判断是否为真实 XSS 攻击。",
            "事件 demo-gen-0001（shop.example.com，源 192.0.2.x）在查询参数中携带 <script> 变体载荷，命中 CRS 941 系规则，异常评分 15，响应 403。结论：真实攻击。建议保持阻断，并关注同源 IP 的后续行为。"),
    "s04": ("分析 192.0.2.204 最近一周的攻击行为是否存在攻击链。",
            "该来源先探测 /.git/config（demo-gen-0004），随后出现 SQL 注入与 XSS 尝试，时间间隔小于 30 分钟，符合侦察→利用的典型链路，风险等级评估为 HIGH。"),
    "s06": ("/.git/config 的扫描告警是否为误报？",
            "聚簇内 demo-gen-0004/0024/0044 三起事件指纹一致（同 URI、同规则、周期出现），载荷未变体，判定 LIKELY_FALSE_POSITIVE，建议对指纹聚簇执行抑制。"),
    "s09": ("shop-mall 的登录接口最近 CC 告警偏多，给出阈值建议。",
            "近 7 天 /api/login 峰值 82 次/分钟（含攻击流量），正常用户 P99 为 24 次/分钟。建议 CC 阈值设为 60 次/分钟并启用渐进处置，已生成 CC_POLICY 草稿。"),
    "s12": ("总结近 7 天的整体安全态势。",
            "近 7 天共阻断攻击类事件 1.2k 起，其中扫描噪声占 41%；SQL 注入与 XSS 为主要真实攻击类型，集中于 shop.example.com。建议开启扫描噪声自动抑制。"),
    "t01": ("复核 demo-gen-0007 的 SQL 注入研判结论。",
            "复核确认：demo-gen-0007 载荷含 UNION SELECT 特征，命中 CRS 942 系规则，响应 403，维持真实攻击结论。"),
    "t03": ("生成 192.0.2.214 的攻击画像。",
            "画像：自动化扫描器；UA 轮换且伪造浏览器特征；请求节奏固定 5s 间隔；未发现手工操作痕迹；建议加入观察名单。"),
}
for key, (qu, qa) in MSG.items():
    sid = session_ids[key]
    base = T(13, 9, 30) if key.startswith("s") else T(12, 9, 40)
    print(
        "INSERT INTO ai_messages (id, session_id, role, content, input_tokens, output_tokens, created_at) VALUES ("
        + ", ".join([q(U("msg:%s:u" % key)), q(sid), q("user"), q(qu), q(60), q(0), q(TS(base))])
        + ") ON CONFLICT DO NOTHING;"
    )
    print(
        "INSERT INTO ai_messages (id, session_id, role, content, model_id, input_tokens, output_tokens, finish_reason, created_at) VALUES ("
        + ", ".join([q(U("msg:%s:a" % key)), q(sid), q("assistant"), q(qa), q(MODEL), q(0), q(220), q("stop"), q(TS(base + timedelta(minutes=2)))])
        + ") ON CONFLICT DO NOTHING;"
    )

# ============================================================
# 3. AI 任务（挂会话；admin 14 条 + sec 4 条）
# ============================================================
# (key, session_key, task_type, status, risk, plan, days_ago, failure)
tasks = [
    ("k01", "s01", "EVENT_ANALYSIS", "SUCCESS", "LOW", "分析事件 demo-gen-0001：收集事件详情→规则命中解释→真伪研判", 13, None),
    ("k02", "s02", "EVENT_ANALYSIS", "SUCCESS", "LOW", "分析事件 demo-gen-0000：载荷解构→误报比对→结论输出", 12, None),
    ("k03", "s03", "EVENT_ANALYSIS", "SUCCESS", "LOW", "分析事件 demo-gen-0003：命令注入特征确认", 11, None),
    ("k04", "s04", "ATTACK_CHAIN", "SUCCESS", "MEDIUM", "聚合 192.0.2.204 近 7 天事件→时序关联→链路重建", 10, None),
    ("k05", "s05", "ATTACK_CHAIN", "SUCCESS", "MEDIUM", "聚合 198.51.100.23 多阶段行为→阶段划分→处置建议", 9, None),
    ("k06", "s06", "FALSE_POSITIVE_ANALYSIS", "SUCCESS", "LOW", "对 /.git/config 聚簇做指纹一致性比对与误判率评估", 8, None),
    ("k07", "s07", "FALSE_POSITIVE_ANALYSIS", "SUCCESS", "LOW", "对 /wp-login.php 聚簇做技术栈匹配与误报判定", 7, None),
    ("k08", "s08", "RULE_EXPLANATION", "SUCCESS", "LOW", "解释 CRS 913100 规则逻辑、命中条件与豁免方式", 6, None),
    ("k09", "s09", "POLICY_RECOMMENDATION", "SUCCESS", "MEDIUM", "统计 /api/login 流量基线→阈值仿真→产出 CC_POLICY 草稿", 5, None),
    ("k10", "s10", "POLICY_RECOMMENDATION", "SUCCESS", "MEDIUM", "评估黑名单候选源命中率→产出 BLACKLIST 草稿", 4, None),
    ("k11", "s11", "WHAT_IF_ANALYSIS", "FAILED", "LOW", "仿真封禁 192.0.2.0/24 的影响面", 3, ("LLM_TIMEOUT", "模型推理超时（120s），请重试")),
    ("k12", "s12", "REPORT_SUMMARY", "SUCCESS", "LOW", "汇总近 7 天事件分布→趋势计算→生成周报摘要", 2, None),
    ("k13", "s13", "ROOT_CAUSE_ANALYSIS", "SUCCESS", "MEDIUM", "关联 5xx 突增与源站指标→定位连接池耗尽", 1, None),
    ("k14", "s01", "WHAT_IF_ANALYSIS", "CANCELLED", "LOW", "仿真对 192.0.2.204 单独封禁的影响（用户取消）", 13, None),
    ("u01", "t01", "EVENT_ANALYSIS", "SUCCESS", "LOW", "复核事件 demo-gen-0007 研判结论", 12, None),
    ("u02", "t02", "FALSE_POSITIVE_ANALYSIS", "SUCCESS", "LOW", "复核 4 个扫描聚簇的误报判定", 9, None),
    ("u03", "t03", "ATTACK_PROFILE", "SUCCESS", "MEDIUM", "生成 192.0.2.214 攻击画像", 7, None),
    ("u04", "t04", "POLICY_RECOMMENDATION", "SUCCESS", "MEDIUM", "产出 user-center 例外策略草稿", 5, None),
]
task_ids = {}
for key, skey, ttype, status, risk, plan, days, failure in tasks:
    tid = U("task:" + key)
    task_ids[key] = tid
    created = T(days, 9, 20)
    started = created + timedelta(seconds=8)
    finished = "NULL" if status in ("RUNNING",) else q(TS(started + timedelta(minutes=3, seconds=41)))
    fcode = q(failure[0]) if failure else q("")
    fmsg = q(failure[1]) if failure else q("")
    print(
        "INSERT INTO ai_tasks (id, session_id, task_type, status, risk_level, plan_summary,"
        " started_at, finished_at, failure_code, failure_message, created_at) VALUES ("
        + ", ".join([q(tid), q(session_ids[skey]), q(ttype), q(status), q(risk), q(plan),
                     q(TS(started)), finished, fcode, fmsg, q(TS(created))])
        + ") ON CONFLICT DO NOTHING;"
    )

# ============================================================
# 4. AI 草稿 / 策略建议（ai_recommendations）
# ============================================================
# (key, task_key|None, type, target_type, target_id, summary, evidence reqids, risk, status, days_ago, reviewed)
recs = [
    ("r01", "k06", "EXCEPTION", "application", A, "为内部漏洞扫描器 192.0.2.204 增加 WAF 例外：仅豁免 /.git/config 等探测路径的 913100 命中，有效期 7 天。", ["demo-gen-0004", "demo-gen-0024"], "MEDIUM", "DRAFT", 8, False),
    ("r02", "k07", "EXCEPTION", "application", C, "open-gw：对 /wp-login.php 扫描噪声按指纹抑制，豁免 913100（站点非 WordPress）。", ["demo-gen-0018", "demo-gen-0038"], "LOW", "PENDING_REVIEW", 7, False),
    ("r03", "u04", "EXCEPTION", "application", B, "user-center：为内部健康检查 /healthz 增加规则例外（仅内网源 198.51.100.10）。", ["demo-gen-0011"], "MEDIUM", "ACCEPTED", 5, True),
    ("r04", "k10", "BLACKLIST", "application", C, "将扫描源 198.51.100.23 加入黑名单 30 天：近 7 天触发 913100 共 46 次，无正常访问记录。", ["demo-gen-0008", "demo-gen-0028"], "HIGH", "PENDING_REVIEW", 4, False),
    ("r05", "k10", "BLACKLIST", "application", A, "将 203.0.113.66 加入黑名单：命令注入与路径穿越混合攻击来源。", ["demo-gen-0003", "demo-gen-0013"], "HIGH", "ACCEPTED", 4, True),
    ("r06", None, "BLACKLIST", "application", A, "将 192.0.2.250 加入黑名单 7 天：登录爆破来源，失败后转目录扫描。", ["demo-gen-0017"], "MEDIUM", "REJECTED", 6, True),
    ("r07", "k09", "CC_POLICY", "application", A, "shop-mall /api/login CC 阈值调整为 60 次/分钟，单 IP 维度，超阈先挑战后封禁。", ["demo-gen-0000", "demo-gen-0010"], "MEDIUM", "PENDING_REVIEW", 5, False),
    ("r08", "k09", "CC_POLICY", "application", A, "shop-mall 全站突发限速：单 IP 300 次/5 分钟，超出 429。", ["demo-gen-0007"], "MEDIUM", "DRAFT", 5, False),
    ("r09", None, "CC_POLICY", "application", B, "user-center /api/token 限速 30 次/分钟，防止凭据填充。", ["demo-gen-0005"], "HIGH", "ACCEPTED", 3, True),
    ("r10", "k08", "CUSTOM_RULE", "application", A, "新增自定义规则：阻断对 /.git/、/.svn/、/.env 路径的所有访问（除白名单源）。", ["demo-gen-0004", "demo-gen-0014"], "LOW", "ACCEPTED", 6, True),
    ("r11", None, "CUSTOM_RULE", "application", C, "新增自定义规则：对含 ../ 编码变体的请求直接阻断（路径穿越前置防护）。", ["demo-gen-0002", "demo-gen-0012"], "MEDIUM", "PENDING_REVIEW", 2, False),
    ("r12", None, "CUSTOM_RULE", "application", A, "新增自定义规则：登录接口密码字段出现 SQLi 特征时提升处置为阻断。", ["demo-gen-0000"], "MEDIUM", "DRAFT", 1, False),
    ("r13", "k12", "POLICY_CHANGE", "application", A, "策略变更建议：开启扫描噪声聚簇自动抑制（阈值≥5 且指纹一致）。", ["demo-gen-0024", "demo-gen-0044"], "MEDIUM", "PENDING_REVIEW", 2, False),
    ("r14", "k13", "POLICY_CHANGE", "application", B, "策略变更建议：uc.example.com 源站 5xx 期间临时放宽 CC 全局限速，避免叠加雪崩。", ["demo-gen-0015"], "LOW", "EXPIRED", 1, False),
    ("r15", "k12", "REPORT_SUMMARY", "system", "", "近 7 天安全态势周报：阻断 1.2k 起，扫描噪声占 41%，真实攻击以 SQLi/XSS 为主。", ["demo-gen-0001", "demo-gen-0007"], "LOW", "ACCEPTED", 2, True),
    ("r16", None, "REPORT_SUMMARY", "system", "", "本周误报处置摘要：误报 9 起全部闭环，聚簇抑制贡献 6 起。", ["demo-gen-0018", "demo-gen-0058"], "LOW", "DRAFT", 1, False),
]
rec_ids = {}
for key, tkey, rtype, ttype_, tid_target, summary, ev, risk, status, days, reviewed in recs:
    rid = U("rec:" + key)
    rec_ids[key] = rid
    evidence = J([{"type": "security_event", "request_id": r} for r in ev])
    ref = "draft:%s:%s" % (rtype.lower(), hashlib.sha256(key.encode()).hexdigest()[:8])
    created = T(days, 14, 5)
    reviewed_by = q(ADMIN) if reviewed else "NULL"
    reviewed_at = q(TS(created + timedelta(hours=5))) if reviewed else "NULL"
    print(
        "INSERT INTO ai_recommendations (id, task_id, recommendation_type, target_type, target_id,"
        " summary, evidence_references, risk_level, status, draft_reference, created_by_ai,"
        " reviewed_by, reviewed_at, created_at) VALUES ("
        + ", ".join([q(rid), q(task_ids[tkey]) if tkey else "NULL", q(rtype), q(ttype_), q(str(tid_target)),
                     q(summary), q(evidence), q(risk), q(status), q(ref), q(True),
                     reviewed_by, reviewed_at, q(TS(created))])
        + ") ON CONFLICT DO NOTHING;"
    )

# ============================================================
# 5. 降噪聚簇 + 关联事件
# ============================================================
def fp(source, host, uri, rule_id, detector, ip):
    key = ("rule:%d" % rule_id) if rule_id is not None else ("detector:" + detector if detector else "")
    return H("|".join([source, host.lower().strip(), uri, key, (ip or "").strip()]))

# 关联 demo SCANNER 事件的 4 个聚簇：(key, host, uri, rule, ip, [request_ids], status, verdict, conf, summary)
linked_clusters = [
    ("c01", "shop.example.com", "/.git/config", 913100, "192.0.2.204",
     ["demo-gen-0004", "demo-gen-0024", "demo-gen-0044"], A, "ACTIVE", "LIKELY_FALSE_POSITIVE", "0.930",
     "指纹一致的周期性 .git 探测（3 起，demo-gen-0004/0024/0044），载荷无变体，判定扫描器噪声。"),
    ("c02", "shop.example.com", "/wp-login.php", 913100, "192.0.2.208",
     ["demo-gen-0008", "demo-gen-0028", "demo-gen-0048"], A, "SUPPRESSED", "LIKELY_FALSE_POSITIVE", "0.912",
     "WordPress 特征探测与站点技术栈不符（3 起），已按指纹抑制。"),
    ("c03", "open.example.com", "/.git/config", 913100, "192.0.2.214",
     ["demo-gen-0014", "demo-gen-0034", "demo-gen-0054"], C, "ACTIVE", "LIKELY_FALSE_POSITIVE", "0.905",
     "open-gw 的周期性 .git 探测（3 起），与 c01 同源扫描器指纹。"),
    ("c04", "open.example.com", "/wp-login.php", 913100, "192.0.2.218",
     ["demo-gen-0018", "demo-gen-0038", "demo-gen-0058"], C, "RESOLVED", "TRUE_POSITIVE", "0.870",
     "早期误判为噪声，复核后发现伴随登录爆破行为，已转人工处置并加入黑名单。"),
]
# 无关联事件的合成聚簇（丰富列表）
synth_clusters = [
    ("c05", "shop.example.com", "/manager/html", 913100, "198.51.100.23", A, 5, "ACTIVE", "UNKNOWN", None, "Tomcat 管理端探测，样本量不足，待 LLM 判定。"),
    ("c06", "uc.example.com", "/login", 942100, "203.0.113.66", B, 8, "ACTIVE", "TRUE_POSITIVE", "0.886", "登录接口 SQLi 特征反复出现，聚簇内 8 起事件均为真实攻击。"),
    ("c07", "open.example.com", "/actuator/env", 913100, "198.51.100.77", C, 3, "ACTIVE", "UNKNOWN", None, "Spring Actuator 探测，待积累更多样本。"),
    ("c08", "shop.example.com", "/api/v1/users", 942100, "192.0.2.99", A, 12, "SUPPRESSED", "LIKELY_FALSE_POSITIVE", "0.901", "内部测试工具批量调用触发 942100，已加白并抑制。"),
    ("c09", "uc.example.com", "/api/token", 942100, "203.0.113.101", B, 6, "ACTIVE", "TRUE_POSITIVE", "0.855", "凭据填充伴随 SQLi 载荷，建议限速+黑名单。"),
    ("c10", "waf-s5.local", "/console/setup", 913100, "192.0.2.150", None, 2, "ACTIVE", "UNKNOWN", None, "低频次探测，观察中。"),
    ("c11", "shop.example.com", "/search?q=", 941100, "192.0.2.177", A, 9, "RESOLVED", "TRUE_POSITIVE", "0.943", "反射型 XSS 尝试聚簇，规则加固后已闭环。"),
    ("c12", "open.example.com", "/api/v1/files", 930100, "198.51.100.55", C, 4, "ACTIVE", "LIKELY_FALSE_POSITIVE", "0.780", "路径穿越特征弱，疑似误报，待复核。"),
    ("c13", "uc.example.com", "/static/../../etc/passwd", 930100, "203.0.113.88", B, 7, "SUPPRESSED", "LIKELY_FALSE_POSITIVE", "0.833", "静态资源路径归一化误判，已通过例外抑制。"),
    ("c14", "shop.example.com", "/wp-admin/", 913100, "192.0.2.230", A, 11, "ACTIVE", "LIKELY_FALSE_POSITIVE", "0.917", "高频 WordPress 管理端探测噪声，建议自动抑制。"),
]
cluster_ids = {}
for key, host, uri, rule, ip, reqids, app, status, verdict, conf, summary in linked_clusters:
    cid = U("cluster:" + key)
    cluster_ids[key] = cid
    first = T(len(reqids) + 6, 3, 10)
    last = T(1, 4, 22)
    print(
        "INSERT INTO ai_noise_clusters (id, source, fingerprint_hash, application_id, host, normalized_uri,"
        " rule_id, detector_code, client_ip, event_count, first_seen, last_seen, status,"
        " ai_verdict, ai_confidence, ai_summary, created_at, updated_at) VALUES ("
        + ", ".join([q(cid), q("WAF"), q(fp("WAF", host, uri, rule, None, ip)), q(str(app)), q(host), q(uri),
                     q(rule), "NULL", q(ip), q(len(reqids)), q(TS(first)), q(TS(last)), q(status),
                     q(verdict), q(conf), q(summary), q(TS(first)), q(TS(last))])
        + ") ON CONFLICT DO NOTHING;"
    )
    for i, rid_req in enumerate(reqids):
        print(
            "INSERT INTO ai_noise_cluster_events (id, cluster_id, event_id, source, is_representative, created_at)"
            " SELECT " + ", ".join([q(U("ce:%s:%d" % (key, i))), q(cid), "e.id", q("WAF"), q(i == 0), q(TS(first + timedelta(hours=i * 24)))])
            + " FROM security_events e WHERE e.request_id=" + q(rid_req)
            + " ORDER BY e.occurred_at DESC LIMIT 1 ON CONFLICT DO NOTHING;"
        )
for key, host, uri, rule, ip, app, count, status, verdict, conf, summary in synth_clusters:
    cid = U("cluster:" + key)
    first = T(min(count + 2, 13), 5, 40)
    last = T(1, 6, 5)
    print(
        "INSERT INTO ai_noise_clusters (id, source, fingerprint_hash, application_id, host, normalized_uri,"
        " rule_id, detector_code, client_ip, event_count, first_seen, last_seen, status,"
        " ai_verdict, ai_confidence, ai_summary, created_at, updated_at) VALUES ("
        + ", ".join([q(cid), q("WAF"), q(fp("WAF", host, uri, rule, None, ip)), q(str(app)) if app else "NULL", q(host), q(uri),
                     q(rule), "NULL", q(ip), q(count), q(TS(first)), q(TS(last)), q(status),
                     q(verdict), q(conf) if conf else "NULL", q(summary), q(TS(first)), q(TS(last))])
        + ") ON CONFLICT DO NOTHING;"
    )

# ============================================================
# 6. 降噪扫描轮次（近 14 天每日一轮）
# ============================================================
sweep_status = ["SUCCESS"] * 12 + ["PARTIAL", "FAILED"]
sweep_err = {12: "WAF 事件源查询超时，本轮按部分结果完成", 13: "LLM 服务不可用：连接 ollama 超时"}
for i in range(14):
    days = 13 - i
    started = T(days, 3, 7 + (i * 11) % 50)
    finished = started + timedelta(seconds=20 + (i * 13) % 90)
    status = sweep_status[i]
    scanned = 60 + (i * 37) % 320
    newc = 0 if status == "FAILED" else (i * 3) % 4
    upd = 0 if status == "FAILED" else (i * 5) % 13
    llm = 0 if status == "FAILED" else newc + upd // 2
    tokens = llm * (900 + (i * 61) % 500)
    print(
        "INSERT INTO ai_noise_sweep_runs (id, started_at, finished_at, scanned_events, new_clusters,"
        " updated_clusters, llm_calls, tokens_used, status, error, created_at) VALUES ("
        + ", ".join([q(U("sweep:%02d" % i)), q(TS(started)), q(TS(finished)), q(scanned), q(newc),
                     q(upd), q(llm), q(tokens), q(status), q(sweep_err.get(i, "")), q(TS(finished))])
        + ") ON CONFLICT DO NOTHING;"
    )

# ============================================================
# 7. AI 审计（哈希链；仅在表内无非本种子记录时插入）
# ============================================================
def rfc3339nano(t):
    base = t.strftime("%Y-%m-%dT%H:%M:%S")
    frac = ("%06d" % t.microsecond).rstrip("0")
    return base + ("." + frac if frac else "") + "Z"

# (key, user, username, roles, session_key|None, task_key|None, action, task_type, agent, tool,
#  in_tok, out_tok, dur_ms, req, res, draft_ref_key|None, confirm, days, hour, minute, micro)
audits = [
    ("a01", ADMIN, "jiuzhang_admin", "SYSTEM_ADMIN", "s01", "k01", "analyze", "EVENT_ANALYSIS", "event_analysis", "", 412, 358, 8420,
     "分析安全事件 demo-gen-0001（XSS）", "结论：真实攻击；命中 CRS 941 系；响应 403", None, "", 13, 9, 24, 123456),
    ("a02", ADMIN, "jiuzhang_admin", "SYSTEM_ADMIN", "s01", "k01", "tool_call", "EVENT_ANALYSIS", "", "get_event_detail", 0, 0, 132,
     "tool=get_event_detail request_id=demo-gen-0001", "status=SUCCESS err=", None, "", 13, 9, 25, 234567),
    ("a03", ADMIN, "jiuzhang_admin", "SYSTEM_ADMIN", "s04", "k04", "analyze", "ATTACK_CHAIN", "attack_chain", "", 620, 512, 15300,
     "攻击链分析：192.0.2.204 近 7 天行为", "重建链路：扫描→注入→XSS；风险 HIGH", None, "", 10, 10, 2, 345678),
    ("a04", SEC, "sec_admin_s5", "SECURITY_ADMIN", "t01", "u01", "analyze", "EVENT_ANALYSIS", "event_analysis", "", 388, 296, 7650,
     "复核安全事件 demo-gen-0007（SQL 注入）", "复核维持真实攻击结论", None, "", 12, 9, 45, 456789),
    ("a05", ADMIN, "jiuzhang_admin", "SYSTEM_ADMIN", "s06", "k06", "analyze", "FALSE_POSITIVE_ANALYSIS", "false_positive", "", 455, 402, 11200,
     "误报研判：/.git/config 聚簇（demo-gen-0004 等 3 起）", "判定 LIKELY_FALSE_POSITIVE，置信度 0.930", None, "", 8, 9, 32, 567890),
    ("a06", ADMIN, "jiuzhang_admin", "SYSTEM_ADMIN", "s09", "k09", "analyze", "POLICY_RECOMMENDATION", "policy_advice", "", 530, 467, 13400,
     "策略建议：shop-mall /api/login CC 阈值", "建议 60 次/分钟；生成 CC_POLICY 草稿", "r07", "", 5, 14, 8, 111111),
    ("a07", ADMIN, "jiuzhang_admin", "SYSTEM_ADMIN", "s09", "k09", "draft_create", "POLICY_RECOMMENDATION", "", "draft_cc_policy", 0, 0, 210,
     "创建 CC_POLICY 草稿：/api/login 60 次/分钟", "status=DRAFT ref 已生成", "r07", "", 5, 14, 9, 222222),
    ("a08", ADMIN, "jiuzhang_admin", "SYSTEM_ADMIN", "s10", "k10", "draft_create", "POLICY_RECOMMENDATION", "", "draft_blacklist", 0, 0, 180,
     "创建 BLACKLIST 草稿：封禁 203.0.113.66", "status=DRAFT ref 已生成", "r05", "", 4, 10, 15, 333333),
    ("a09", ADMIN, "jiuzhang_admin", "SYSTEM_ADMIN", None, None, "recommendation_accept", "", "", "", 0, 0, 95,
     "采纳 BLACKLIST 草稿（203.0.113.66）", "草稿已转为黑名单规则并发布", "r05", "CONFIRMED", 4, 15, 41, 444444),
    ("a10", SEC, "sec_admin_s5", "SECURITY_ADMIN", "t04", "u04", "analyze", "POLICY_RECOMMENDATION", "policy_advice", "", 470, 389, 12100,
     "策略建议：user-center 健康检查例外", "产出 EXCEPTION 草稿", "r03", "", 5, 11, 3, 555555),
    ("a11", ADMIN, "jiuzhang_admin", "SYSTEM_ADMIN", None, None, "recommendation_reject", "", "", "", 0, 0, 88,
     "驳回 BLACKLIST 草稿（192.0.2.250）：样本不足", "草稿已驳回", "r06", "CONFIRMED", 6, 16, 20, 666666),
    ("a12", ADMIN, "jiuzhang_admin", "SYSTEM_ADMIN", "s12", "k12", "analyze", "REPORT_SUMMARY", "report_summary", "", 810, 705, 18900,
     "生成近 7 天安全态势周报摘要", "周报已生成；扫描噪声占 41%", "r15", "", 2, 9, 50, 777777),
    ("a13", ADMIN, "jiuzhang_admin", "SYSTEM_ADMIN", None, None, "evaluation_run", "", "", "", 2350, 1980, 245000,
     "运行评测集 eval_event_analysis（模型 qwen2.5:3b）", "score=87.50 total=8 passed=7", None, "", 3, 21, 5, 888888),
    ("a14", ADMIN, "jiuzhang_admin", "SYSTEM_ADMIN", "s13", "k13", "analyze", "ROOT_CAUSE_ANALYSIS", "root_cause", "", 560, 488, 14700,
     "根因分析：uc.example.com 5xx 突增", "定位源站连接池耗尽，与 WAF 策略无关", None, "", 1, 9, 12, 999999),
    ("a15", SEC, "sec_admin_s5", "SECURITY_ADMIN", "t02", "u02", "analyze", "FALSE_POSITIVE_ANALYSIS", "false_positive", "", 402, 350, 9800,
     "复核扫描聚簇 c01-c04 误报判定", "同意抑制 c01-c03，c04 转人工", None, "", 9, 10, 30, 135792),
    ("a16", ADMIN, "jiuzhang_admin", "SYSTEM_ADMIN", "s01", None, "chat", "GENERAL_SECURITY_QA", "", "", 320, 275, 6900,
     "追问：同源 IP 后续是否再出现？", "近 48 小时无新事件，建议保持观察", None, "", 13, 10, 5, 246813),
]
audit_ids = [U("audit:" + k) for k, *_ in audits]
# 哈希链按 occurred_at 升序构建（VerifyChain 以 occurred_at ASC, id ASC 回放）
audits = sorted(audits, key=lambda r: T(r[17], r[18], r[19], 30, r[20]))
prev = ""
audit_rows = []
for (key, uid, uname, roles, skey, tkey, action, ttype, agent, tool, in_t, out_t, dur, req, res, dkey, confirm, days, hour, minute, micro) in audits:
    aid = U("audit:" + key)
    at = T(days, hour, minute, 30, micro)
    task_id = task_ids[tkey] if tkey else None
    obj = str(task_id) if task_id else ""
    rh = H("|".join([rfc3339nano(at), uname, action, obj, prev]))
    audit_rows.append((aid, at, uid, uname, roles, session_ids.get(skey) if skey else None, task_id,
                       action, ttype, agent, tool, "qwen2.5:3b", "v1", in_t, out_t, dur, req, res,
                       dkey, confirm, prev, rh))
    prev = rh
# 真实 draft_reference 文本（与 ai_recommendations.draft_reference 对齐）
ref_by_key = {r[0]: "draft:%s:%s" % (r[2].lower(), hashlib.sha256(r[0].encode()).hexdigest()[:8]) for r in recs}
guard = "SELECT count(*) FROM ai_audit_records WHERE NOT (id = ANY(ARRAY[" + ",".join(q(i) + "::uuid" for i in audit_ids) + "]))"
cols = ("id, occurred_at, user_id, username, role_codes, session_id, task_id, action, task_type, agent_code,"
        " tool_code, model_code, prompt_version, input_tokens, output_tokens, duration_ms, estimated_cost,"
        " request_summary, result_summary, draft_reference, confirm_result, previous_hash, record_hash")
for (aid, at, uid, uname, roles, sid, tid, action, ttype, agent, tool, model_code, pv, in_t, out_t, dur, req, res, dkey, confirm, ph, rh) in audit_rows:
    print(
        "INSERT INTO ai_audit_records (" + cols + ") SELECT " + ", ".join([
            q(aid), q(TS(at)), q(uid), q(uname), q(roles), q(sid) if sid else "NULL", q(tid) if tid else "NULL",
            q(action), q(ttype), q(agent), q(tool), q(model_code), q(pv), q(in_t), q(out_t), q(dur), q(0),
            q(req), q(res), q(ref_by_key.get(dkey, "")), q(confirm), q(ph), q(rh)])
        + " WHERE (" + guard + ") = 0 ON CONFLICT DO NOTHING;"
    )

# ============================================================
# 8. 评测集运行记录
# ============================================================
# (key, set_code, status, score, days_ago, total, passed)
runs = [
    ("e01", "eval_event_analysis", "SUCCESS", 87.50, 3, 8, 7),
    ("e02", "eval_event_analysis", "SUCCESS", 90.00, 1, 8, 7),
    ("e03", "eval_false_positive", "SUCCESS", 85.00, 12, 6, 5),
    ("e04", "eval_false_positive", "SUCCESS", 92.50, 2, 6, 6),
    ("e05", "eval_rule_explain", "SUCCESS", 95.00, 11, 5, 5),
    ("e06", "eval_attack_profile", "SUCCESS", 80.00, 10, 5, 4),
    ("e07", "eval_attack_chain", "SUCCESS", 83.30, 9, 6, 5),
    ("e08", "eval_root_cause", "SUCCESS", 75.00, 8, 4, 3),
    ("e09", "eval_policy_advice", "SUCCESS", 88.00, 7, 5, 4),
    ("e10", "eval_what_if", "FAILED", None, 6, 5, 0),
    ("e11", "eval_report_summary", "SUCCESS", 91.00, 5, 5, 5),
    ("e12", "eval_prompt_injection", "SUCCESS", 100.00, 4, 6, 6),
    ("e13", "eval_privilege_denial", "SUCCESS", 100.00, 3, 4, 4),
    ("e14", "eval_insufficient_data", "SUCCESS", 86.70, 1, 6, 5),
]
for key, set_code, status, score, days, total, passed in runs:
    started = T(days, 21, 3 + (days * 7) % 40)
    finished = "NULL" if status == "RUNNING" else q(TS(started + timedelta(minutes=4, seconds=12)))
    if status == "FAILED":
        details = J({"total": total, "passed": 0, "truncated": False, "error": "LLM 推理超时，评测中止",
                     "cases": [{"question": "演示用例", "expected_contains": "结论", "passed": False, "error": "执行失败"}]})
    else:
        details = J({"total": total, "passed": passed, "truncated": False,
                     "cases": [{"question": "分析事件 demo-gen-0001 是否为真实攻击", "expected_contains": "真实攻击",
                                "passed": True, "answer_excerpt": "结论：真实攻击，已阻断。"},
                               {"question": "扫描告警 demo-gen-0004 是否为误报", "expected_contains": "误报",
                                "passed": passed == total, "answer_excerpt": "判定 LIKELY_FALSE_POSITIVE。"}]})
    print(
        "INSERT INTO ai_evaluation_runs (id, evaluation_set_id, model_id, status, score, details,"
        " started_at, finished_at, created_at) VALUES ("
        + ", ".join([q(U("eval:" + key)),
                     "(SELECT id FROM ai_evaluation_sets WHERE code=" + q(set_code) + ")",
                     q(MODEL), q(status), q(score) if score is not None else "NULL", q(details),
                     q(TS(started)), finished, q(TS(started))])
        + ") ON CONFLICT DO NOTHING;"
    )

print("COMMIT;")
PYEOF
rc=$?
[ $rc -ne 0 ] && { echo "ERROR: 种子执行失败 rc=$rc"; exit $rc; }

echo "============================================================"
echo "完成。计数："
docker exec "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -t -A -c "
SELECT 'ai_sessions(admin,ACTIVE)', count(*) FROM ai_sessions WHERE user_id=(SELECT id FROM users WHERE username='jiuzhang_admin') AND status='ACTIVE'
UNION ALL SELECT 'ai_sessions(sec,ACTIVE)', count(*) FROM ai_sessions WHERE user_id=(SELECT id FROM users WHERE username='sec_admin_s5') AND status='ACTIVE'
UNION ALL SELECT 'ai_tasks(all)', count(*) FROM ai_tasks
UNION ALL SELECT 'ai_recommendations', count(*) FROM ai_recommendations
UNION ALL SELECT 'ai_noise_clusters', count(*) FROM ai_noise_clusters
UNION ALL SELECT 'ai_noise_cluster_events', count(*) FROM ai_noise_cluster_events
UNION ALL SELECT 'ai_noise_sweep_runs', count(*) FROM ai_noise_sweep_runs
UNION ALL SELECT 'ai_audit_records', count(*) FROM ai_audit_records
UNION ALL SELECT 'ai_evaluation_runs', count(*) FROM ai_evaluation_runs;"
