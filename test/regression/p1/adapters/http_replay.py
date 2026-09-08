"""HTTP 回放适配器（P1-04 任务书 §4.3，R1/S1 交付工具层，R2 接真实隔离栈）。

职责边界：
- 由 case steps 生成确定性原始请求计划（多步骤、等待条件、敏感头脱敏后入证据）；
- 生成每 run_id 独立 Valkey 命名空间的重置计划描述（本模块只描述，不执行重置）；
- 执行层：无隔离环境句柄（environment=None）时返回 BLOCKED /
  ENVIRONMENT_UNAVAILABLE，绝不伪造 PASS；
- 真实传输仅使用标准库 http.client，且目标必须经 p0bench.isolation
  允许表判定（本 project 发布端口或登记目标），重定向不得逃离允许集合。

R2 真实执行能力（仅当 environment 句柄注入时启用）：
- HTTPS 虚拟主机：base_url 主机名为站点 Host/SNI，environment["resolve_to"]
  指定实际拨号地址（隔离栈本网关 127.0.0.1）；TLS 用不验证上下文（栈内
  自签证书仅本轮有效），绝不跳过目标允许表判定；
- 每用例独立 Cookie 会话罐（Bot 会话/通行 Cookie 按真实 Set-Cookie 记账，
  不跨用例泄漏）；
- case 声明 client.bot_challenge_solve=true 时，遇 Bot 挑战页按浏览器同构
  流程现场求解 PoW（SHA-256 长度前缀编码，与网关 botchallenge/pow.go 同一
  构造）并 POST verify，再携带通行 Cookie 重放本步骤；求解子请求与重放
  请求使用派生 request_id（<步骤id>-vfy/-rty）入证据，不冒充原始步骤；
- 每个真实发出的 HTTP 请求记录状态码与客户端观测延迟（perf 明细，供性能
  关联证据），网络异常如实映射 execution_state=ERROR，绝不转通过。

关联纪律：回放侧 X-Request-Id（<run_id>-<case_id>-<seq>）仅作对账键，
不具有授权作用；可信关联以网关生成的 request_id 为准（任务书 §5.2）。
"""

from __future__ import annotations

import hashlib
import http.client
import json
import re
import socket
import ssl
import time
from urllib.parse import urlsplit

from p0bench.isolation import classify_target

from p1reg.replayplan import VALKEY_NAMESPACE_TEMPLATE
from p1reg.vocab import REASON_ENVIRONMENT_UNAVAILABLE

# 敏感头：进入请求计划/证据时只保留 sha256 前缀（真实值只在执行瞬间存在于内存）
SENSITIVE_HEADERS = ("authorization", "proxy-authorization", "cookie", "x-api-key")

# 受控源站标记契约：隔离栈源站对每个到达请求回写该响应头
ORIGIN_MARK_HEADER = "x-wdsp-origin-mark"

# Bot 挑战页参数块（与 gateway botchallenge/render.go 页面契约同构）
BOT_PARAMS_RE = re.compile(
    r'id="wdsp-bot-params" type="application/json">(.*?)</script>', re.S)
BOT_CLEARANCE_COOKIE = "__Host-wdsp-bot-clearance"

# PoW 求解迭代上限（difficulty 由服务端状态决定；超出即如实失败，不降低难度）
POW_MAX_ITER = 1 << 26

DEFAULT_TIMEOUT_S = 30.0
DEFAULT_WAIT_TIMEOUT_MS = 5000


class AdapterError(Exception):
    """适配器结构性错误（非法步骤、目标被拒、等待条件无法满足等）。"""


def _redact_headers(headers: dict) -> dict:
    out = {}
    for k, v in (headers or {}).items():
        if k.lower() in SENSITIVE_HEADERS:
            out[k] = "sha256:" + hashlib.sha256(v.encode("utf-8")).hexdigest()[:16]
        else:
            out[k] = v
    return out


def build_request_plan(case_doc: dict, profile: str, run_id: str) -> dict:
    """由 case steps 生成确定性请求计划（脱敏；可入证据目录）。"""
    case_id = case_doc["case_id"]
    steps = []
    for i, step in enumerate(case_doc.get("steps") or [], 1):
        req = step.get("request") or {}
        steps.append({
            "seq": i,
            "step_id": step.get("step_id"),
            "request_id": f"{run_id}-{case_id}-{i:02d}",
            "method": req.get("method", "GET"),
            "path": req.get("path", "/"),
            "query": req.get("query"),
            "headers": _redact_headers(req.get("headers") or {}),
            "body_sha256": (
                hashlib.sha256(req["body"].encode("utf-8")).hexdigest()
                if isinstance(req.get("body"), str) else None
            ),
            "body_len": len(req["body"]) if isinstance(req.get("body"), str) else 0,
            "wait": step.get("wait"),
            "assert": step.get("assert") or [],
        })
    return {
        "case_id": case_id,
        "case_version": case_doc.get("case_version"),
        "profile": profile,
        "run_id": run_id,
        "seed": case_doc.get("seed"),
        "steps": steps,
    }


def describe_reset_plan(case_doc: dict, run_id: str) -> dict:
    """每 run_id 独立 Valkey 命名空间的重置计划描述（只描述，不执行）。"""
    case_id = case_doc["case_id"]
    rp = case_doc.get("reset_plan") or {}
    actions = list(rp.get("actions") or ["none"])
    forbidden = [a for a in actions if "flushall" in a.lower() or "flushdb" in a.lower()]
    if forbidden:
        raise AdapterError(f"非法全局重置动作 {forbidden}（case {case_id}）")
    tpl = rp.get("valkey_prefix_template") or VALKEY_NAMESPACE_TEMPLATE
    return {
        "run_id": run_id,
        "case_id": case_id,
        "scope": rp.get("scope", "case"),
        "actions": actions,
        "valkey_namespace": tpl.replace("{run_id}", run_id).replace("{case_id}", case_id),
        "forbidden_globally": ["FLUSHALL", "FLUSHDB", "drop_shared_tables", "reset_other_runs"],
        "note": "重置仅作用于本 run_id 命名空间；真实栈跨 run 隔离由每 run 独立"
                "身份材料（User-Agent 携带 run_id）与独立 Cookie 会话承担，"
                "不做任何全局 FLUSH",
    }


def _evaluate_assertion(assertion: dict, status: int | None, headers: dict, body_text: str) -> dict:
    """求值单条断言。headers 为小写键映射。返回 {type, met, detail}。"""
    atype = assertion.get("type")
    met = False
    detail = ""
    if atype == "http_status_in":
        met = status in set(assertion.get("statuses") or [])
        detail = f"status={status}"
    elif atype == "header_present":
        name = (assertion.get("name") or "").lower()
        met = name in headers
        detail = f"header {name} {'present' if met else 'absent'}"
    elif atype == "header_absent":
        name = (assertion.get("name") or "").lower()
        met = name not in headers
        detail = f"header {name} {'absent' if met else 'present'}"
    elif atype == "body_contains":
        needle = assertion.get("text") or ""
        met = needle in body_text
        detail = f"body {'contains' if met else 'missing'} {needle[:40]!r}"
    elif atype == "body_not_contains":
        needle = assertion.get("text") or ""
        met = needle not in body_text
        detail = f"body {'lacks' if met else 'contains'} {needle[:40]!r}"
    elif atype == "json_field_equals":
        path = assertion.get("path") or ""
        want = assertion.get("value")
        try:
            cur = json.loads(body_text)
            for part in path.split("."):
                if isinstance(cur, dict) and part in cur:
                    cur = cur[part]
                else:
                    raise KeyError(path)
            met = cur == want
            detail = f"{path}={cur!r}"
        except (json.JSONDecodeError, KeyError, TypeError):
            met = False
            detail = f"无法取到字段 {path}"
    elif atype == "origin_marker_present":
        met = ORIGIN_MARK_HEADER in headers
        detail = f"{ORIGIN_MARK_HEADER} {'present' if met else 'absent'}"
    elif atype == "origin_marker_absent":
        met = ORIGIN_MARK_HEADER not in headers
        detail = f"{ORIGIN_MARK_HEADER} {'absent' if met else 'present'}"
    else:
        raise AdapterError(f"无法解析的断言类型 {atype!r}（应已被语料校验拒绝）")
    return {"type": atype, "met": met, "detail": detail}


def _lp(b: bytes) -> bytes:
    """长度前缀帧（与 botchallenge/pow.go lp 同一构造：4 字节大端长度 + 内容）。"""
    return len(b).to_bytes(4, "big") + b


def pow_solve(challenge_id: str, nonce: str, app: str, host: str, difficulty: int,
              max_iter: int = POW_MAX_ITER) -> str | None:
    """PoW 求解（浏览器内嵌 JS 求解器的 Python 同构实现；现场计算，不复用结果）。

    digest = SHA-256("wdsp-bot-pow-v1" ‖ lp(challenge_id) ‖ lp(nonce) ‖ lp(app)
                     ‖ lp(host) ‖ lp(solution))；通过 ⟺ 前 difficulty 比特为 0。
    """
    try:
        cid = bytes.fromhex(challenge_id)
        nn = bytes.fromhex(nonce)
    except ValueError:
        return None
    prefix = (b"wdsp-bot-pow-v1" + _lp(cid) + _lp(nn)
              + _lp(app.encode("utf-8")) + _lp(host.encode("utf-8")))
    full_zero, rem = divmod(difficulty, 8)
    for i in range(max_iter):
        d = hashlib.sha256(prefix + _lp(str(i).encode("ascii"))).digest()
        if d[:full_zero] == b"\x00" * full_zero and (rem == 0 or d[full_zero] >> (8 - rem) == 0):
            return str(i)
    return None


def parse_challenge_params(body_text: str) -> dict | None:
    """从挑战页 HTML 提取 wdsp-bot-params 参数块；非挑战页返回 None。"""
    m = BOT_PARAMS_RE.search(body_text or "")
    if not m:
        return None
    try:
        params = json.loads(m.group(1))
    except json.JSONDecodeError:
        return None
    if not isinstance(params, dict) or not params.get("challenge_id") or not params.get("nonce"):
        return None
    return params


class _ResolvedHTTPSConnection(http.client.HTTPSConnection):
    """按 SNI/Host 虚主机名建 TLS，但实际拨号到隔离栈固定地址（resolve_to）。"""

    def __init__(self, host, port=None, resolve_to=None, **kw):
        super().__init__(host, port=port, **kw)
        self._resolve_to = resolve_to

    def connect(self):
        sock = socket.create_connection(
            (self._resolve_to or self.host, self.port), self.timeout, self.source_address)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class HttpReplayAdapter:
    """HTTP 回放适配器。

    environment=None（缺省）：无隔离环境句柄，execute_case 一律返回
    BLOCKED/ENVIRONMENT_UNAVAILABLE（S1 工具层行为，不假执行）。

    environment 句柄（R2 隔离栈接线后注入）为 dict：
      base_url:    本 run 隔离栈网关入口（必须在 allowed_targets 内）；
                   https 时主机名即站点 Host/SNI
      resolve_to:  https 实际拨号地址（缺省按 base_url 主机名拨号）；
                   TLS 不验证证书（栈内自签，目标已过允许表）
      origin_mark: 受控源站标记值（origin_mark 必须匹配，防串 run 对账）
      wait_event:  可选 callable(wait:dict, deadline:float) -> bool，
                   供 event_persisted 等待条件查询事件存储；缺省时该等待
                   条件不可满足，按 AdapterError 拒绝执行（不假装已等待）
    """

    def __init__(self, allowed_targets=(), environment: dict | None = None, timeout: float = DEFAULT_TIMEOUT_S):
        self.allowed_targets = frozenset(allowed_targets or ())
        self.environment = environment
        self.timeout = timeout

    def execute_case(self, case_doc: dict, profile: str, run_id: str) -> dict:
        """执行单条用例并产出观测；无环境句柄时诚实返回 BLOCKED 观测。"""
        base = {
            "case_id": case_doc.get("case_id"),
            "profile": profile,
            "executed": False,
            "valid": False,
            "execution_state": "UNKNOWN",
            "detection": None,
            "observed_action": None,
            "origin_reached": None,
            "assertions": None,
            "side_effects": None,
            "evidence_refs": [],
            "perf": [],
        }
        if self.environment is None:
            base["blocked_reason"] = REASON_ENVIRONMENT_UNAVAILABLE
            base["execution_state"] = "UNKNOWN"
            return base

        base_url = self.environment.get("base_url")
        cls, reason = classify_target(base_url or "", self.allowed_targets)
        if cls != "allowed":
            raise AdapterError(f"回放目标被拒绝（隔离允许表判定）: {base_url!r}（{reason}）")

        origin_mark = self.environment.get("origin_mark")
        solve_bot = bool((case_doc.get("client") or {}).get("bot_challenge_solve"))
        run_marker = self.environment.get("ua_run_marker")
        self._case_ua_marker = (
            f"{run_marker}/{case_doc['case_id']}" if run_marker else None)
        cookie_jar: dict[str, str] = {}
        executed_any = False
        assertions_out: list[dict] = []
        perf: list[dict] = []
        evidence_refs: list[str] = []
        last_status: int | None = None
        last_origin_reached: bool | None = None
        prev_failed = False

        for i, step in enumerate(case_doc.get("steps") or [], 1):
            sid = step.get("step_id")
            wait = step.get("wait")
            if wait:
                wtype = wait.get("type")
                if wtype == "delay_ms":
                    time.sleep(wait["ms"] / 1000.0)
                elif wtype == "previous_step_status_in":
                    if prev_failed or last_status not in set(wait.get("statuses") or []):
                        return {**base, "executed": executed_any, "valid": False,
                                "execution_state": "ABORTED",
                                "assertions": assertions_out, "perf": perf,
                                "abort_reason": f"步骤 {sid} 前置等待未满足（上一步 status={last_status}）"}
                elif wtype == "event_persisted":
                    waiter = self.environment.get("wait_event")
                    if not callable(waiter):
                        raise AdapterError(
                            f"步骤 {sid} 的 event_persisted 等待需要环境提供事件存储句柄，拒绝假装已等待"
                        )
                    deadline = time.monotonic() + wait.get("timeout_ms", DEFAULT_WAIT_TIMEOUT_MS) / 1000.0
                    if not waiter(wait, deadline):
                        return {**base, "executed": executed_any, "valid": False,
                                "execution_state": "PENDING_CORRELATION",
                                "assertions": assertions_out, "perf": perf,
                                "abort_reason": f"步骤 {sid} 等待事件持久化超时"}
                else:
                    raise AdapterError(f"无法解析的等待条件 {wtype!r}")

            req = step.get("request") or {}
            rid = f"{run_id}-{case_doc['case_id']}-{i:02d}"
            status, headers, body_text = self._send(
                base_url, req, rid, cookie_jar, perf, seq=i, kind="step")
            executed_any = True
            if status is None:
                return {**base, "executed": True, "valid": False,
                        "execution_state": "ERROR",
                        "assertions": assertions_out, "perf": perf,
                        "abort_reason": f"步骤 {sid} 连接/传输错误"}

            # Bot 挑战求解（仅 case 显式声明 client.bot_challenge_solve）：
            # 403 + 挑战参数块 → 现场 PoW 求解 → verify → 携带通行 Cookie 重放
            if solve_bot and status == 403:
                params = parse_challenge_params(body_text)
                if params is not None:
                    evidence_refs.append(f"bot-challenge:{rid}")
                    status, headers, body_text = self._bot_solve_flow(
                        base_url, req, rid, params, cookie_jar, perf, seq=i)
                    if status is None:
                        return {**base, "executed": True, "valid": False,
                                "execution_state": "ERROR",
                                "assertions": assertions_out, "perf": perf,
                                "evidence_refs": evidence_refs,
                                "abort_reason": f"步骤 {sid} Bot 求解/verify/重放失败"}
                    evidence_refs.append(f"bot-verify:{rid}-vfy")

            last_status = status
            prev_failed = False
            reached = headers.get(ORIGIN_MARK_HEADER) == origin_mark if origin_mark else ORIGIN_MARK_HEADER in headers
            last_origin_reached = reached
            for a in step.get("assert") or []:
                rec = _evaluate_assertion(a, status, headers, body_text)
                rec["step_id"] = sid
                assertions_out.append(rec)
                if rec["met"] is False:
                    prev_failed = True

        return {
            **base,
            "executed": True,
            "valid": True,
            "execution_state": "COMPLETED",
            "observed_action": None,  # 最终动作由事件/决策对账层填充，HTTP 状态不冒充
            "origin_reached": last_origin_reached,
            "http": {"last_status": last_status},
            "assertions": assertions_out,
            "perf": perf,
            "evidence_refs": evidence_refs + [f"http-replay:{run_id}:{case_doc['case_id']}"],
        }

    def _bot_solve_flow(self, base_url: str, req: dict, rid: str, params: dict,
                        cookie_jar: dict, perf: list, seq: int):
        """挑战求解子流程：PoW → verify → 重放。返回最终 (status, headers, body)。

        任何子环节失败返回 (None, {}, "")，由调用方如实映射 ERROR；
        verify 非 204（含 409/403/429/503）同样算失败——不重放、不猜结局。
        """
        solution = pow_solve(
            params["challenge_id"], params["nonce"],
            str(params.get("app", "")), str(params.get("host", "")),
            int(params.get("difficulty", 0)))
        if solution is None:
            return None, {}, ""
        vbody = json.dumps({"challenge_id": params["challenge_id"], "solution": solution})
        vreq = {
            "method": "POST",
            "path": params.get("verify_path") or "/_wdsp/bot/v1/verify",
            "headers": {
                "Content-Type": "application/json",
                "Origin": "https://" + str(params.get("host", "")),
            },
            "body": vbody,
        }
        vstatus, _, _ = self._send(base_url, vreq, rid + "-vfy", cookie_jar, perf,
                                   seq=seq, kind="verify")
        if vstatus != 204 or BOT_CLEARANCE_COOKIE not in cookie_jar:
            return None, {}, ""
        return self._send(base_url, req, rid + "-rty", cookie_jar, perf, seq=seq, kind="retry")

    def _send(self, base_url: str, req: dict, request_id: str, cookie_jar: dict | None,
              perf: list | None, seq: int, kind: str = "step"):
        """真实 HTTP 传输（标准库 http.client；目标已过允许表）。

        返回 (status|None, headers小写dict, body_text)。网络异常返回 (None, {}, "")，
        由调用方映射为 execution_state=ERROR（不得转通过）。
        每个真实发出的请求向 perf 追加一条 {request_id, seq, kind, status,
        latency_ms, origin_reached} 客户端观测记录（性能关联证据）。
        """
        parts = urlsplit(base_url)
        # 站点占位符替换（按 profile 站点自适应；确定性、仅替换显式占位符）：
        # {site_host}=站点主机名，{site_origin}=scheme://host[:port]（Bot verify
        # 严格同源 Origin 等场景）
        site_host = parts.hostname or ""
        default_port = 443 if parts.scheme == "https" else 80
        site_origin = f"{parts.scheme}://{site_host}" + (
            f":{parts.port}" if parts.port and parts.port != default_port else "")
        path = req.get("path") or "/"
        if req.get("query"):
            path = f"{path}?{req['query']}"
        headers = dict(req.get("headers") or {})
        for k, v in list(headers.items()):
            if "{site_host}" in v or "{site_origin}" in v:
                headers[k] = v.replace("{site_host}", site_host).replace("{site_origin}", site_origin)
        body = req.get("body")
        if isinstance(body, str) and ("{site_host}" in body or "{site_origin}" in body):
            body = body.replace("{site_host}", site_host).replace("{site_origin}", site_origin)
        headers["X-Request-Id"] = request_id
        # 身份隔离标记：User-Agent 追加确定性 p1reg/<run_id>/<case_id> 标记。
        # 网关身份键对匿名身份 = 指纹(salt, UA…)，每 run/用例唯一 UA 使行为窗口、
        # Bot 信号计数等 Valkey 状态天然按 run/case 隔离——替代任何全局 FLUSH，
        # 跨 run 回放确定性由身份材料新鲜性承担（见 describe_reset_plan 纪律）。
        marker = getattr(self, "_case_ua_marker", None)
        if marker:
            ua_key = next((k for k in headers if k.lower() == "user-agent"), "User-Agent")
            headers[ua_key] = (headers.get(ua_key, "").strip() + " " + marker).strip()
        if cookie_jar:
            cookie = "; ".join(f"{k}={v}" for k, v in sorted(cookie_jar.items()))
            if cookie and "cookie" not in {k.lower() for k in headers}:
                headers["Cookie"] = cookie
        if parts.scheme == "https":
            ctx = ssl._create_unverified_context()  # 栈内自签证书；目标已过允许表
            conn = _ResolvedHTTPSConnection(
                parts.hostname, parts.port, resolve_to=self.environment.get("resolve_to"),
                timeout=self.timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=self.timeout)
        started = time.monotonic()
        try:
            conn.request(req.get("method", "GET"), path,
                         body=body.encode("utf-8") if isinstance(body, str) else None,
                         headers=headers)
            resp = conn.getresponse()
            raw = resp.read()
            latency_ms = (time.monotonic() - started) * 1000.0
            hdict: dict[str, str] = {}
            if cookie_jar is not None:
                for k, v in resp.getheaders():
                    if k.lower() == "set-cookie":
                        pair = v.split(";", 1)[0]
                        if "=" in pair:
                            name, val = pair.split("=", 1)
                            cookie_jar[name.strip()] = val.strip()
            for k, v in resp.getheaders():
                hdict[k.lower()] = v
            if perf is not None:
                mark = self.environment.get("origin_mark") or ""
                perf.append({
                    "request_id": request_id,
                    "gateway_request_id": hdict.get("x-jiuzhang-request-id"),
                    "seq": seq,
                    "kind": kind,
                    "status": resp.status,
                    "latency_ms": round(latency_ms, 3),
                    "origin_reached": hdict.get(ORIGIN_MARK_HEADER) == mark if mark
                    else ORIGIN_MARK_HEADER in hdict,
                })
            return resp.status, hdict, raw.decode("utf-8", errors="replace")
        except OSError:
            if perf is not None:
                perf.append({
                    "request_id": request_id, "seq": seq, "kind": kind,
                    "status": None,
                    "latency_ms": round((time.monotonic() - started) * 1000.0, 3),
                    "origin_reached": None,
                })
            return None, {}, ""
        finally:
            conn.close()
