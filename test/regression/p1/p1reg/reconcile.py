"""事件/决策对账层（P1-04 任务书 §5.2，R2 真实栈回放）。

职责：把执行层 HTTP 观测与管理面事件存储（security_events /
access_control_events，经管理 API 只读查询）对账，填充判定器所需的
detection / observed_action / final_decision 证据。

铁律（与 judge.py 同源）：
- HTTP 403/429 或响应关键字不能单独证明指定模块正确处理；检测（规则命中）、
  最终动作（final_decision / 访问控制动作）、HTTP 结果与源站到达分离；
- 对账键为网关生成并经响应头 X-Jiuzhang-Request-ID 回显的 request_id
  （生成配置 set 覆盖客户端注入的 X-Request-Id；回放侧注入 id 仅作
  证据内追溯，不具备事件关联效力，更不具有授权作用）；判定请求 =
  用例最后一步的最终请求（Bot 求解流取 -rty 重放请求，挑战/verify
  子请求只作旁证引用，不混入检测口径）；
- 事件采集为异步管道（网关日志 → 管理面采集器），期望检测缺失时按截止时间
  轮询；期望无检测时同样保留短宽限后复查，宁可慢不得漏记误报；
- 本模块只读管理 API（GET），凭据只存在于环境描述符（mktemp，0600），
  证据输出不含 Cookie/CSRF。
"""

from __future__ import annotations

import http.client
import json
import time
from urllib.parse import urlencode, urlsplit

# 自定义规则 ID 段（server/internal/customrules：7000000-7199999 九章段，
# 7100000+ 用户自定义段）→ 检测模块 custom_pack；其余 WAF 命中归 coraza_crs
CUSTOM_RULE_ID_MIN = 7000000
CUSTOM_RULE_ID_MAX = 7199999

# CRS 规则 ID 前三位 → 规则族（OWASP CRS 4.x 文件分区惯例）。
# 不含 949/959/980：它们是评分汇总/阻断评估/相关规则，不是检测证据——
# 真实栈实测阻断事件的 matches 里 949110 常居首（如 SQLi 事件），若计入
# 规则族归属会把 sqli 攻击误归 protocol。九章二次评估段（9000100-9000199）
# 同理只做 module 归属、不参与规则族判定。
CRS_FAMILY_BY_PREFIX = {
    920: "protocol", 921: "protocol",
    930: "path_traversal", 931: "rfi",
    932: "rce", 933: "php", 934: "application_attack",
    941: "xss", 942: "sqli", 943: "session_fixation",
    944: "java_attack",
}

# 纯评估/计分规则（阻断评估与相关汇总）：不计入规则族归属
JZ_EVAL_RULE_ID_MIN = 9000100
JZ_EVAL_RULE_ID_MAX = 9000199

# Bot 事件类型 → (module, rule_family)；仅安全相关事件算检出，
# 通行/验证成功等流程事件（BOT_CLEARANCE_ACCEPTED/BOT_VERIFY_SUCCESS）不算 finding
BOT_EVENT_FAMILY = {
    "BOT_CHALLENGE_OFFERED": ("bot", "challenge"),
    "BOT_VERIFY_REJECTED": ("bot", "verify_protocol"),
    "BOT_CHALLENGE_EXPIRED": ("bot", "verify_protocol"),
    "BOT_STATE_UNAVAILABLE": ("bot", "verify_protocol"),
}

BOT_NAMESPACE_PREFIX = "/_wdsp/bot/v1/"

DEFAULT_EVENT_GRACE_MS = 3000
DEFAULT_EVENT_WAIT_TIMEOUT_MS = 20000


class ReconcileError(Exception):
    """对账层结构性错误（API 不可用、响应封套非法等）。"""


class ApiClient:
    """管理面只读 API 客户端（标准库 http.client；仅 GET）。

    cookie_header 为完整 Cookie 头值（仅存在于内存与环境描述符，不入证据）。
    """

    def __init__(self, base_url: str, cookie_header: str, timeout: float = 10.0):
        self.base_url = base_url
        self.cookie_header = cookie_header
        self.timeout = timeout

    def get_json(self, path: str, params: dict | None = None) -> dict:
        parts = urlsplit(self.base_url)
        p = path
        if params:
            p = f"{path}?{urlencode(params)}"
        conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=self.timeout)
        try:
            conn.request("GET", p, headers={"Cookie": self.cookie_header})
            resp = conn.getresponse()
            raw = resp.read()
        except OSError as exc:
            raise ReconcileError(f"管理 API 连接失败: {exc}") from exc
        finally:
            conn.close()
        if resp.status != 200:
            raise ReconcileError(f"管理 API {path} 返回 {resp.status}")
        try:
            doc = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ReconcileError(f"管理 API {path} 响应不是合法 JSON") from exc
        if not isinstance(doc, dict) or doc.get("code") != "SUCCESS":
            raise ReconcileError(f"管理 API {path} 业务码异常: {doc.get('code')!r}")
        return doc.get("data") or {}

    def list_security_events(self, request_id: str) -> list:
        data = self.get_json("/api/v1/security-events",
                             {"request_id": request_id, "page": 1, "page_size": 20})
        items = data.get("items")
        return items if isinstance(items, list) else []

    def get_security_event_detail(self, event_id: str) -> dict:
        return self.get_json(f"/api/v1/security-events/{event_id}")

    def list_access_control_events(self, request_id: str) -> list:
        data = self.get_json("/api/v1/access-control-events",
                             {"request_id": request_id, "page": 1, "page_size": 20})
        items = data.get("items")
        return items if isinstance(items, list) else []


def _crs_family(rule_id) -> str | None:
    """CRS 规则族：纯评估/计分规则（949/959/980 段与九章二次评估段）不参与归属。"""
    try:
        rid = int(rule_id)
    except (TypeError, ValueError):
        return None
    if JZ_EVAL_RULE_ID_MIN <= rid <= JZ_EVAL_RULE_ID_MAX:
        return None
    return CRS_FAMILY_BY_PREFIX.get(rid // 1000)


def _waf_detection(matches: list, custom_families: dict) -> dict:
    """由 security_event_matches 归纳检测观测（模块/规则族，自定义段优先精确映射）。

    rule_family 为首个可归族的非评估规则（展示用）；matched_families 为全部
    命中族（有序去重、剔除评估规则）——多规则命中是常态（如 RCE 载荷同时触发
    930 文件访问与 932 命令执行），判定层按集合成员判定而非首条顺序。
    """
    module = None
    family = None
    families: list = []
    for m in matches:
        rid = m.get("rule_id")
        try:
            rid_int = int(rid)
        except (TypeError, ValueError):
            continue
        if CUSTOM_RULE_ID_MIN <= rid_int <= CUSTOM_RULE_ID_MAX:
            module = "custom_pack"
            fam = custom_families.get(str(rid_int))
            if fam:
                family = fam
                if fam not in families:
                    families.append(fam)
                break
        else:
            if module is None:
                module = "coraza_crs"
            fam = _crs_family(rid_int)
            if fam:
                if family is None:
                    family = fam
                if fam not in families:
                    families.append(fam)
    return {"detected": bool(matches), "module": module if matches else None,
            "rule_family": family if matches else None,
            "matched_families": families if matches else []}


def _verdict_request_id(observation: dict) -> str | None:
    """判定请求 = 最后一步的最终请求（Bot 求解流取 -rty 重放）。

    事件对账键取网关生成的 X-Jiuzhang-Request-ID（生成配置以 set 覆盖
    客户端注入头，响应侧回显为唯一可信关联通道）；缺失时退化回放侧
    注入 id（查不到事件即如实缺证据，不伪造关联）。
    """
    perf = observation.get("perf") or []
    if not perf:
        return None
    last = perf[-1]
    return last.get("gateway_request_id") or last.get("request_id")


def _poll_events(client: ApiClient, request_id: str, need_detection: bool,
                 grace_ms: int, timeout_ms: int) -> tuple[list, list, int]:
    """按期望轮询事件存储。返回 (security_events, access_control_events, waited_ms)。

    无检测期望：先等采集宽限再查一次（漏记误报比慢更糟）；
    有检测期望：轮询至命中或截止（缺失即如实缺证据，不提前放行）。
    """
    started = time.monotonic()
    if not need_detection:
        if grace_ms > 0:
            time.sleep(grace_ms / 1000.0)
        sec = client.list_security_events(request_id)
        acc = client.list_access_control_events(request_id)
        return sec, acc, int((time.monotonic() - started) * 1000)
    deadline = started + timeout_ms / 1000.0
    while True:
        sec = client.list_security_events(request_id)
        acc = client.list_access_control_events(request_id)
        if sec or acc or time.monotonic() >= deadline:
            return sec, acc, int((time.monotonic() - started) * 1000)
        time.sleep(0.5)


def reconcile_case(client: ApiClient, case_doc: dict, observation: dict,
                   custom_families: dict | None = None,
                   grace_ms: int = DEFAULT_EVENT_GRACE_MS,
                   timeout_ms: int = DEFAULT_EVENT_WAIT_TIMEOUT_MS) -> dict:
    """对账单条用例（就地填充 observation.detection / observed_action /
    reconciliation 证据），返回 observation。

    custom_families: {str(rule_id): family} 环境登记映射（stack-up 写入
    描述符；对账不猜测规则语义）。
    """
    custom_families = custom_families or {}
    rid = _verdict_request_id(observation)
    if not rid or not observation.get("executed") or observation.get("execution_state") != "COMPLETED":
        return observation

    profile = observation.get("profile")
    exp = (case_doc.get("expectations_by_profile") or {}).get(profile) or {}
    exp_det = exp.get("expected_detection") or {}
    # 墓碑类检测证据来自响应捕获（本地处置不产生事件），不做事件轮询
    need_detection = (exp_det.get("module", "none") != "none"
                      and exp_det.get("rule_family") != "tombstone")

    sec, acc, waited = _poll_events(client, rid, need_detection, grace_ms, timeout_ms)

    detail_sec: list = []
    matches_all: list = []
    final_decisions: list = []
    for ev in sec:
        ev_summary = {"id": ev.get("id"), "action": ev.get("action"),
                      "attack_type": ev.get("attack_type"),
                      "response_status": ev.get("response_status"),
                      "rule_match_count": ev.get("rule_match_count")}
        try:
            det = client.get_security_event_detail(str(ev.get("id")))
        except ReconcileError:
            det = {}
        evt_doc = det.get("event") or {}
        fd = evt_doc.get("final_decision")
        if isinstance(fd, dict):
            final_decisions.append(fd)
            ev_summary["final_decision"] = {
                "security_action": fd.get("security_action"),
                "executor_module": fd.get("executor_module"),
                "completion_status": fd.get("completion_status"),
                "http_status": fd.get("http_status"),
            }
        ms = det.get("matches") or []
        ev_summary["matches"] = [
            {"rule_id": m.get("rule_id"), "severity": m.get("severity"),
             "rule_source": m.get("rule_source")}
            for m in ms if isinstance(m, dict)
        ]
        matches_all.extend(ev_summary["matches"])
        detail_sec.append(ev_summary)

    detail_acc = [
        {"id": e.get("id"), "event_type": e.get("event_type"), "action": e.get("action"),
         "response_status": e.get("response_status"), "path": e.get("request_path")}
        for e in acc
    ]

    last_status = ((observation.get("http") or {}).get("last_status"))
    origin_reached = observation.get("origin_reached")

    # ---- detection ----
    detection = {"detected": False, "module": None, "rule_family": None}
    if matches_all:
        detection = _waf_detection(matches_all, custom_families)
    elif acc:
        # 访问控制/Bot 事件（取首个可映射类型）。OBSERVE 模式的
        # BOT_CHALLENGE_OFFERED（action=OBSERVE）是"假设会挑战"的流程记录、
        # 非检测 finding——真实栈实测其对任何合格首导航都会记录，计入检出会把
        # 正常浏览器导航误判为误报；仅 action=CHALLENGE（PROTECT 实签发）算检出。
        for e in detail_acc:
            fam = BOT_EVENT_FAMILY.get(e.get("event_type"))
            if not fam:
                continue
            if e.get("event_type") == "BOT_CHALLENGE_OFFERED" and e.get("action") != "CHALLENGE":
                continue
            detection = {"detected": True, "module": fam[0], "rule_family": fam[1]}
            break
    if not detection["detected"] and last_status in (404, 405) and origin_reached is False:
        # 保留命名空间本地墓碑：响应捕获为本地处置证据（无事件 emit 时的诚实来源）
        verdict_path = ""
        for e in detail_acc:
            verdict_path = e.get("path") or ""
        steps = case_doc.get("steps") or []
        if steps:
            verdict_path = (steps[-1].get("request") or {}).get("path") or verdict_path
        if verdict_path.startswith(BOT_NAMESPACE_PREFIX):
            detection = {"detected": True, "module": "bot", "rule_family": "tombstone"}

    # ---- observed_action ----
    action = None
    acc_types = {e.get("event_type"): e for e in detail_acc}
    if detection["rule_family"] == "tombstone":
        action = "LOCAL_REJECT"
    elif "BOT_CHALLENGE_OFFERED" in acc_types and acc_types["BOT_CHALLENGE_OFFERED"].get("action") == "CHALLENGE" \
            and last_status == 403 and origin_reached is False:
        action = "BLOCK_403"
    elif "BOT_VERIFY_REJECTED" in acc_types and last_status in (400, 403, 409, 429):
        action = {400: "BLOCK_403", 403: "BLOCK_403", 409: "BLOCK_403", 429: "RATE_LIMIT_429"}[last_status]
    elif final_decisions:
        fd = final_decisions[0]
        sec_action = fd.get("security_action")
        status = fd.get("http_status") or last_status
        if sec_action in ("BLOCK", "TEMP_BLOCK"):
            action = {401: "BLOCK_401", 429: "RATE_LIMIT_429"}.get(status, "BLOCK_403")
        elif matches_all and origin_reached:
            action = "DETECT_PASS"
    elif matches_all and origin_reached:
        # OBSERVE 检出放行（final_decision 缺省时的诚实现测）
        action = "DETECT_PASS"
    elif "BOT_CHALLENGE_OFFERED" in acc_types and acc_types["BOT_CHALLENGE_OFFERED"].get("action") == "CHALLENGE" \
            and origin_reached:
        # 实签发挑战却又到达源站的矛盾态（不应出现；如实记 DETECT_PASS 由判定层暴露）
        action = "DETECT_PASS"

    if action is None:
        if origin_reached and last_status is not None and 200 <= last_status < 400:
            action = "PASS"
        elif last_status is not None and last_status >= 500:
            action = "UNEXPECTED_ERROR"
        elif last_status in (401, 403, 429) and not origin_reached:
            # 有拦截结果但无任何事件/决策证据归属——不得按安全通过，也不冒充模块正确
            action = "UNEXPECTED_ERROR"
        elif last_status in (404, 405):
            action = "LOCAL_REJECT" if detection["detected"] else "UNEXPECTED_ERROR"

    observation["detection"] = detection
    observation["observed_action"] = action
    observation["reconciliation"] = {
        "verdict_request_id": rid,
        "event_wait_ms": waited,
        "security_events": detail_sec,
        "access_control_events": detail_acc,
        "subflow_evidence": [p.get("request_id") for p in (observation.get("perf") or [])
                             if p.get("kind") in ("verify", "retry")],
    }
    refs = observation.setdefault("evidence_refs", [])
    refs.extend(f"security-event:{e['id']}" for e in detail_sec if e.get("id"))
    refs.extend(f"access-control-event:{e['id']}" for e in detail_acc if e.get("id"))
    return observation
