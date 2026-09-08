"""HTTP 回放适配器（P1-04 任务书 §4.3，R1/S1 交付）。

职责边界：
- 由 case steps 生成确定性原始请求计划（多步骤、等待条件、敏感头脱敏后入证据）；
- 生成每 run_id 独立 Valkey 命名空间的重置计划描述（本模块只描述，不执行重置）；
- 执行层：无隔离环境句柄（environment=None）时返回 BLOCKED /
  ENVIRONMENT_UNAVAILABLE，绝不伪造 PASS；
- 真实传输仅使用标准库 http.client，且目标必须经 p0bench.isolation
  允许表判定（本 project 发布端口或登记目标），重定向不得逃离允许集合。

本阶段（S1）不连接任何真实网关：run.sh regression 在隔离栈接线前一律
BLOCKED。本适配器的真实执行路径供后续 R2 隔离环境就绪后调用；单元测试
不伪造网关响应冒充回放成功。

关联纪律：回放侧 X-Request-Id（<run_id>-<case_id>-<seq>）仅作对账键，
不具有授权作用；可信关联以网关生成的 request_id 为准（任务书 §5.2）。
"""

from __future__ import annotations

import hashlib
import http.client
import json
import time
from urllib.parse import urlsplit

from p0bench.isolation import classify_target

from p1reg.replayplan import VALKEY_NAMESPACE_TEMPLATE
from p1reg.vocab import REASON_ENVIRONMENT_UNAVAILABLE

# 敏感头：进入请求计划/证据时只保留 sha256 前缀（真实值只在执行瞬间存在于内存）
SENSITIVE_HEADERS = ("authorization", "proxy-authorization", "cookie", "x-api-key")

# 受控源站标记契约：隔离栈源站对每个到达请求回写该响应头
ORIGIN_MARK_HEADER = "x-wdsp-origin-mark"

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
        "note": "重置仅作用于本 run_id 命名空间；本阶段为描述，不执行",
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


class HttpReplayAdapter:
    """HTTP 回放适配器。

    environment=None（缺省）：无隔离环境句柄，execute_case 一律返回
    BLOCKED/ENVIRONMENT_UNAVAILABLE（S1 工具层行为，不假执行）。

    environment 句柄（后续 R2 隔离栈接线后注入）为 dict：
      base_url:    本 run 隔离栈网关入口（必须在 allowed_targets 内）
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
        executed_any = False
        assertions_out: list[dict] = []
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
                                "assertions": assertions_out,
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
                                "assertions": assertions_out,
                                "abort_reason": f"步骤 {sid} 等待事件持久化超时"}
                else:
                    raise AdapterError(f"无法解析的等待条件 {wtype!r}")

            req = step.get("request") or {}
            status, headers, body_text = self._send(base_url, req, run_id, case_doc["case_id"], i)
            executed_any = True
            if status is None:
                return {**base, "executed": True, "valid": False,
                        "execution_state": "ERROR",
                        "assertions": assertions_out,
                        "abort_reason": f"步骤 {sid} 连接/传输错误"}
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
            "evidence_refs": [f"http-replay:{run_id}:{case_doc['case_id']}"],
        }

    def _send(self, base_url: str, req: dict, run_id: str, case_id: str, seq: int):
        """真实 HTTP 传输（标准库 http.client；目标已过允许表）。

        返回 (status|None, headers小写dict, body_text)。网络异常返回 (None, {}, "")，
        由调用方映射为 execution_state=ERROR（不得转通过）。
        """
        parts = urlsplit(base_url)
        path = req.get("path") or "/"
        if req.get("query"):
            path = f"{path}?{req['query']}"
        headers = dict(req.get("headers") or {})
        headers["X-Request-Id"] = f"{run_id}-{case_id}-{seq:02d}"
        body = req.get("body")
        conn_cls = http.client.HTTPSConnection if parts.scheme == "https" else http.client.HTTPConnection
        conn = conn_cls(parts.hostname, parts.port, timeout=self.timeout)
        try:
            conn.request(req.get("method", "GET"), path,
                         body=body.encode("utf-8") if isinstance(body, str) else None,
                         headers=headers)
            resp = conn.getresponse()
            raw = resp.read()
            return resp.status, {k.lower(): v for k, v in resp.getheaders()}, raw.decode("utf-8", errors="replace")
        except OSError:
            return None, {}, ""
        finally:
            conn.close()
