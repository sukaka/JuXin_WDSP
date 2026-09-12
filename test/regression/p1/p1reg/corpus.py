"""P1 语料 manifest schema v1 校验器（P1-04 任务书 §4，S0 冻结契约 2）。

与 p0bench.corpus 的关系：P0 校验器与 P0 语料 v1（模板/generator/七模式）
硬绑定；本模块实现 P1 独立 schema，不修改、不继承 P0 校验口径。

样本 = manifest 条目（case_id/case_version/file/content_sha256）+
corpus/cases/ 内 JSON 文件。content_sha256 为 case 文件原始字节的 sha256：
改动任一请求、真值或断言即失配（REG-002），语义变化必须升 case_version。

校验拒绝：未知 schema 主版本、重复 case_id / 重复文件路径、路径越界
（引用文件必须落在 corpus/cases/ 内）、无法解析的断言、哈希失配、
manifest 条目与文件内 case_id/case_version 不一致。

分母口径：truth=UNKNOWN 与 deferred=true 不计入任何准确率/检出率分母
（§4.1、REG-003）；deferred 必须附 deferred_reason 且不得为 MANDATORY。
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from p0bench.corpus import ACTIONS as FINAL_ACTIONS  # 复用 P0 动作词表
from p0bench.plan import RFC3339_RE, SHA256_RE, sha256_file

from .profiles import DEFAULT_PROFILE_IDS
from .vocab import EXTRA_ACTIONS

# P1 期望/观测动作全集 = P0 词表 + P1 本地扩展（LOCAL_REJECT）
EXPECTED_ACTIONS = FINAL_ACTIONS + EXTRA_ACTIONS

CASE_ID_RE = re.compile(r"^[A-Z][A-Z0-9]*-(BEN|ATK|UNK)-[A-Z0-9]+-[0-9]{3}$")

SCHEMA_VERSION = 1
TRUTHS = ("BENIGN", "ATTACK", "UNKNOWN")
CRITICALITIES = ("MANDATORY", "STANDARD")
PARTITIONS = ("TRAIN", "VALIDATION", "HOLDOUT")
FAMILIES = ("waf", "api", "jwt", "exception", "bot", "agent", "apm")
SOURCES = ("self_synthetic",)
HTTP_METHODS = ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE")
ORIGIN_EXPECTATIONS = ("reached", "not_reached")
RESET_SCOPES = ("none", "case", "run")
RESET_ACTIONS = ("none", "reset_app_state", "flush_valkey_prefix", "recreate_objects")
EVIDENCE_KEYS = ("access_log", "security_event", "final_decision", "response_capture", "origin_counters")

# 断言 DSL：未知类型或参数缺失/类型错误即“无法解析的断言”，拒绝载入
ASSERTION_PARAM_TYPES: dict[str, dict[str, tuple]] = {
    "http_status_in": {"statuses": (list,)},
    "header_present": {"name": (str,)},
    "header_absent": {"name": (str,)},
    "body_contains": {"text": (str,)},
    "body_not_contains": {"text": (str,)},
    "json_field_equals": {"path": (str,), "value": (str, int, float, bool, type(None))},
    "origin_marker_present": {},
    "origin_marker_absent": {},
}

WAIT_PARAM_TYPES: dict[str, dict[str, tuple]] = {
    "previous_step_status_in": {"statuses": (list,)},
    "delay_ms": {"ms": (int,)},
    "event_persisted": {"event_type": (str,), "timeout_ms": (int,)},
}

_FORBIDDEN_RESET_TOKENS = ("flushall", "flushdb")


CLIENT_KEYS = ("bot_challenge_solve",)


def _validate_client(client, path: str, errors: list[str]) -> None:
    """可选 client 对象：声明回放客户端行为（执行层解释，校验层只钉结构）。

    bot_challenge_solve=true：遇到 Bot 挑战页（403 + wdsp-bot-params）时，
    客户端按浏览器同构流程现场求解 PoW 并 verify（不得复用预计算结果），
    然后携带通行 Cookie 重放本步骤请求；缺省/为 false 时不求解（脚本客户端）。
    """
    if client is None:
        return
    if not isinstance(client, dict):
        _err(errors, path, "client: 必须是对象")
        return
    for k in client:
        if k not in CLIENT_KEYS:
            _err(errors, path, f"client: 未知键 {k!r}（允许: {list(CLIENT_KEYS)}）")
    v = client.get("bot_challenge_solve")
    if v is not None and not isinstance(v, bool):
        _err(errors, path, "client.bot_challenge_solve: 必须为布尔值")


class CorpusError(Exception):
    """P1 语料不满足 schema v1 契约。"""


def _err(errors: list[str], path: str, msg: str) -> None:
    errors.append(f"{path}: {msg}")


def _is_nonempty_str(v) -> bool:
    return isinstance(v, str) and bool(v.strip())


def load_manifest(path: str | Path) -> dict:
    p = Path(path)
    try:
        with p.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError as exc:
        raise CorpusError(f"语料 manifest 不存在: {p}") from exc
    except json.JSONDecodeError as exc:
        raise CorpusError(f"语料 manifest 不是合法 JSON: {p}: {exc}") from exc
    if not isinstance(data, dict):
        raise CorpusError("语料 manifest 顶层必须是 JSON 对象")
    return data


def resolve_case_file(corpus_dir: Path, rel) -> tuple[Path | None, str | None]:
    """把 manifest 条目的 file 解析为 corpus/cases/ 内路径；越界即拒绝。"""
    if not _is_nonempty_str(rel):
        return None, "必须为非空相对路径"
    if "\\" in rel:
        return None, "禁止反斜杠（跨平台路径歧义）"
    if rel.startswith("/") or (len(rel) > 1 and rel[1] == ":"):
        return None, "禁止绝对路径"
    parts = rel.split("/")
    if any(part in ("", ".", "..") for part in parts):
        return None, "禁止空段、'.' 或 '..'（路径越界防护）"
    if not rel.startswith("cases/") or len(parts) != 2:
        return None, "引用文件必须直接位于 corpus/cases/ 内（形如 cases/<name>.json）"
    if not rel.endswith(".json"):
        return None, "引用文件必须是 .json"
    cases_dir = (corpus_dir / "cases").resolve()
    resolved = (corpus_dir / rel).resolve()
    if resolved.parent != cases_dir:
        return None, "路径越界：解析结果不在 corpus/cases/ 内"
    return resolved, None


def _validate_assertion(assertion, path: str, errors: list[str]) -> None:
    if not isinstance(assertion, dict):
        _err(errors, path, "断言必须是对象")
        return
    atype = assertion.get("type")
    if atype not in ASSERTION_PARAM_TYPES:
        _err(errors, path, f"无法解析的断言类型 {atype!r}（允许: {sorted(ASSERTION_PARAM_TYPES)}）")
        return
    spec = ASSERTION_PARAM_TYPES[atype]
    for key in assertion:
        if key != "type" and key not in spec:
            _err(errors, path, f"断言 {atype} 不接受参数 {key!r}")
    for key, types in spec.items():
        v = assertion.get(key)
        if key not in assertion or not isinstance(v, types) or (types == (int,) and isinstance(v, bool)):
            _err(errors, path, f"断言 {atype} 缺参数或类型错误: {key}")
            continue
        if atype == "http_status_in" and key == "statuses":
            if not v or not all(isinstance(s, int) and not isinstance(s, bool) and 100 <= s <= 599 for s in v):
                _err(errors, path, "statuses 必须为非空合法 HTTP 状态码数组")


def _validate_wait(wait, path: str, errors: list[str]) -> None:
    if wait is None:
        return
    if not isinstance(wait, dict):
        _err(errors, path, "wait 必须是对象或 null")
        return
    wtype = wait.get("type")
    if wtype not in WAIT_PARAM_TYPES:
        _err(errors, path, f"无法解析的等待条件 {wtype!r}（允许: {sorted(WAIT_PARAM_TYPES)}）")
        return
    spec = WAIT_PARAM_TYPES[wtype]
    for key in wait:
        if key != "type" and key not in spec:
            _err(errors, path, f"等待条件 {wtype} 不接受参数 {key!r}")
    for key, types in spec.items():
        v = wait.get(key)
        if key not in wait or not isinstance(v, types) or (types == (int,) and isinstance(v, bool)):
            _err(errors, path, f"等待条件 {wtype} 缺参数或类型错误: {key}")
    if wtype == "previous_step_status_in" and isinstance(wait.get("statuses"), list):
        if not wait["statuses"] or not all(isinstance(s, int) and 100 <= s <= 599 for s in wait["statuses"]):
            _err(errors, path, "statuses 必须为非空合法 HTTP 状态码数组")
    for key in ("ms", "timeout_ms"):
        if key in wait and isinstance(wait.get(key), int) and wait[key] < 1:
            _err(errors, path, f"{key} 必须为正整数")


def _validate_request(req, path: str, errors: list[str]) -> None:
    if not isinstance(req, dict):
        _err(errors, path, "request 必须是对象")
        return
    if req.get("method") not in HTTP_METHODS:
        _err(errors, path, f"request.method: 必须为 {HTTP_METHODS} 之一")
    p = req.get("path")
    if not isinstance(p, str) or not p.startswith("/"):
        _err(errors, path, "request.path: 必须以 / 开头")
    if "\r" in str(p) or "\n" in str(p):
        _err(errors, path, "request.path: 禁止 CRLF")
    if "query" in req and req["query"] is not None and not isinstance(req["query"], str):
        _err(errors, path, "request.query: 必须为字符串或缺省")
    headers = req.get("headers")
    if headers is not None:
        if not isinstance(headers, dict):
            _err(errors, path, "request.headers: 必须是对象")
        else:
            for k, v in headers.items():
                if not _is_nonempty_str(k) or not isinstance(v, str):
                    _err(errors, path, f"request.headers.{k!r}: 键值必须为字符串")
                    continue
                if any(c in k for c in "\r\n:") or "\r" in v or "\n" in v:
                    _err(errors, path, f"request.headers.{k!r}: 禁止 CRLF/冒号（防请求走私）")
    if "body" in req and req["body"] is not None and not isinstance(req["body"], str):
        _err(errors, path, "request.body: 必须为字符串或缺省（二进制经 base64 文本承载）")


def _validate_steps(steps, path: str, errors: list[str]) -> None:
    if not isinstance(steps, list) or not steps:
        _err(errors, path, "steps: 必须为非空数组（单请求用例即单步）")
        return
    seen_step_ids: set[str] = set()
    for i, step in enumerate(steps):
        spath = f"{path}[{i}]"
        if not isinstance(step, dict):
            _err(errors, spath, "step 必须是对象")
            continue
        sid = step.get("step_id")
        if not _is_nonempty_str(sid):
            _err(errors, spath, "step_id: 必须为非空字符串")
        elif sid in seen_step_ids:
            _err(errors, spath, f"step_id 重复: {sid}")
        else:
            seen_step_ids.add(sid)
        if step.get("action") != "http_request":
            _err(errors, spath, f"action: schema v1 仅支持 http_request（收到 {step.get('action')!r}）")
        else:
            _validate_request(step.get("request"), f"{spath}.request", errors)
        _validate_wait(step.get("wait"), f"{spath}.wait", errors)
        assertions = step.get("assert")
        if assertions is not None:
            if not isinstance(assertions, list):
                _err(errors, spath, "assert: 必须是数组")
            else:
                for j, a in enumerate(assertions):
                    _validate_assertion(a, f"{spath}.assert[{j}]", errors)


def _validate_reset_plan(rp, path: str, errors: list[str]) -> None:
    if not isinstance(rp, dict):
        _err(errors, path, "reset_plan: 必须是对象")
        return
    scope = rp.get("scope")
    if scope not in RESET_SCOPES:
        _err(errors, path, f"reset_plan.scope: 必须为 {RESET_SCOPES} 之一")
    actions = rp.get("actions")
    if not isinstance(actions, list) or not actions:
        _err(errors, path, "reset_plan.actions: 必须为非空数组（无重置需求时用 [\"none\"]）")
        actions = []
    for a in actions:
        if not isinstance(a, str) or a not in RESET_ACTIONS:
            _err(errors, path, f"reset_plan.actions: 未知重置动作 {a!r}（允许: {RESET_ACTIONS}）")
        elif isinstance(a, str) and any(tok in a.lower() for tok in _FORBIDDEN_RESET_TOKENS):
            _err(errors, path, f"reset_plan.actions: 禁止全局重置动作 {a!r}")
    if scope == "none" and any(a != "none" for a in actions):
        _err(errors, path, "scope=none 时 actions 只能为 [\"none\"]")
    tpl = rp.get("valkey_prefix_template")
    if "flush_valkey_prefix" in actions:
        if not _is_nonempty_str(tpl) or "{run_id}" not in tpl or "{case_id}" not in tpl:
            _err(errors, path, "flush_valkey_prefix 要求 valkey_prefix_template 同时含 {run_id} 与 {case_id}（禁止全局 FLUSHALL）")
    elif tpl is not None and not _is_nonempty_str(tpl):
        _err(errors, path, "valkey_prefix_template: 必须为非空字符串")


def _validate_scope(scope, path: str, errors: list[str]) -> None:
    if not isinstance(scope, dict):
        _err(errors, path, "scope: 必须是对象")
        return
    if not _is_nonempty_str(scope.get("capability")):
        _err(errors, path, "scope.capability: 必须为非空字符串（对应声明能力标识）")
    for key in ("applications", "roles", "protocols"):
        v = scope.get(key)
        if v is not None and (not isinstance(v, list) or not all(_is_nonempty_str(x) for x in v)):
            _err(errors, path, f"scope.{key}: 必须为非空字符串数组")
    aw = scope.get("applies_when")
    if aw is not None and not isinstance(aw, dict):
        _err(errors, path, "scope.applies_when: 必须是对象")


def _validate_prerequisites(pre, path: str, errors: list[str]) -> None:
    if not isinstance(pre, dict):
        _err(errors, path, "prerequisites: 必须是对象")
        return
    env = pre.get("environment")
    if not isinstance(env, list) or not env or not all(_is_nonempty_str(x) for x in env):
        _err(errors, path, "prerequisites.environment: 必须为非空字符串数组（独立环境条件）")
    if "notes" in pre and not isinstance(pre["notes"], str):
        _err(errors, path, "prerequisites.notes: 必须为字符串")


def _validate_expectations(exp, path: str, known_profiles, errors: list[str]) -> None:
    if not isinstance(exp, dict) or not exp:
        _err(errors, path, "expectations_by_profile: 必须为非空对象")
        return
    for pid in exp:
        if pid not in known_profiles:
            _err(errors, f"{path}.{pid}", f"未知 profile（已登记: {list(known_profiles)}）")
    for pid in known_profiles:
        if pid not in exp:
            _err(errors, path, f"缺 profile {pid} 的期望（每条样本必须覆盖全部已登记 profile）")
    for pid, e in exp.items():
        epath = f"{path}.{pid}"
        if pid not in known_profiles or not isinstance(e, dict):
            if not isinstance(e, dict):
                _err(errors, epath, "期望必须是对象")
            continue
        det = e.get("expected_detection")
        if not isinstance(det, dict) or not _is_nonempty_str(det.get("module")):
            _err(errors, epath, "expected_detection.module: 必须为非空字符串（无检测期望用 \"none\"）")
            det = None
        if det is not None and "rule_family" in det and not _is_nonempty_str(det.get("rule_family")):
            _err(errors, epath, "expected_detection.rule_family: 必须为非空字符串")
        action = e.get("expected_final_action")
        if action not in EXPECTED_ACTIONS:
            _err(errors, epath, f"expected_final_action: 必须为 {EXPECTED_ACTIONS} 之一")
        if e.get("expected_origin") not in ORIGIN_EXPECTATIONS:
            _err(errors, epath, f"expected_origin: 必须为 {ORIGIN_EXPECTATIONS} 之一")
        # 期望自洽：检测期望与动作期望不得互相矛盾
        if det is not None and action in EXPECTED_ACTIONS:
            module = det.get("module")
            if module == "none" and action != "PASS":
                _err(errors, epath, "期望矛盾：无检测期望（module=none）时动作只能为 PASS")
            if module != "none" and action == "PASS":
                _err(errors, epath, "期望矛盾：有检测期望时动作不得为 PASS（OBSERVE 应填 DETECT_PASS）")
        evs = e.get("expected_events")
        if evs is not None:
            if not isinstance(evs, list) or not evs:
                _err(errors, epath, "expected_events: 必须为非空数组")
            else:
                for j, ev in enumerate(evs):
                    if not isinstance(ev, dict) or not _is_nonempty_str(ev.get("type")):
                        _err(errors, f"{epath}.expected_events[{j}]", "事件期望必须含非空 type")
        se = e.get("expected_side_effects")
        if se is not None and not isinstance(se, dict):
            _err(errors, epath, "expected_side_effects: 必须是对象")


def _validate_evidence_requirements(erq, path: str, errors: list[str]) -> None:
    if not isinstance(erq, dict) or not erq:
        _err(errors, path, "evidence_requirements: 必须为非空对象")
        return
    for k, v in erq.items():
        if k not in EVIDENCE_KEYS:
            _err(errors, path, f"未知证据需求键 {k!r}（允许: {EVIDENCE_KEYS}）")
        elif not isinstance(v, bool):
            _err(errors, path, f"evidence_requirements.{k}: 必须为布尔值")
    if not any(erq.get(k) is True for k in EVIDENCE_KEYS):
        _err(errors, path, "evidence_requirements: 至少需要一项证据需求为 true")


def validate_case_doc(doc, known_profiles=DEFAULT_PROFILE_IDS, path: str = "case") -> list[str]:
    """校验单个 case 文件内容（不含 manifest 条目与哈希核对）。"""
    errors: list[str] = []
    if not isinstance(doc, dict):
        return [f"{path}: 顶层必须是 JSON 对象"]
    if doc.get("schema_version") != SCHEMA_VERSION:
        _err(errors, path, "schema_version: 必须为 1")
    cid = doc.get("case_id")
    if not isinstance(cid, str) or not CASE_ID_RE.match(cid):
        _err(errors, path, f"case_id: 必须匹配 {CASE_ID_RE.pattern}")
    cv = doc.get("case_version")
    if not (isinstance(cv, int) and not isinstance(cv, bool) and cv >= 1):
        _err(errors, path, "case_version: 必须为正整数（语义变化必须升版本）")
    if doc.get("family") not in FAMILIES:
        _err(errors, path, f"family: 必须为 {FAMILIES} 之一（S1 仅交付 waf 类样本）")
    tags = doc.get("tags")
    if not isinstance(tags, list) or not tags or not all(_is_nonempty_str(t) for t in tags):
        _err(errors, path, "tags: 必须为非空字符串数组")
    crit = doc.get("criticality")
    if crit not in CRITICALITIES:
        _err(errors, path, f"criticality: 必须为 {CRITICALITIES} 之一")
    truth = doc.get("truth")
    if truth not in TRUTHS:
        _err(errors, path, f"truth: 必须为 {TRUTHS} 之一")
    if not _is_nonempty_str(doc.get("truth_reason")):
        _err(errors, path, "truth_reason: 必须为非空人工核验依据")
    deferred = doc.get("deferred") is True
    if "deferred" in doc and not isinstance(doc["deferred"], bool):
        _err(errors, path, "deferred: 必须为布尔值")
    if deferred and not _is_nonempty_str(doc.get("deferred_reason")):
        _err(errors, path, "deferred=true 必须附 deferred_reason（依赖未交付能力的说明）")
    if deferred and crit == "MANDATORY":
        _err(errors, path, "deferred 样本不得为 MANDATORY（不执行的强制项无意义）")
    if truth == "UNKNOWN" and crit == "MANDATORY":
        _err(errors, path, "truth=UNKNOWN 的探索样本不得为 MANDATORY（未声明能力不构成强制门槛）")
    if doc.get("source") not in SOURCES:
        _err(errors, path, f"source: 必须为 {SOURCES} 之一（本阶段仅接受自建合成）")
    if not _is_nonempty_str(doc.get("license")):
        _err(errors, path, "license: 必须为非空许可证说明")
    if not _is_nonempty_str(doc.get("authorization")):
        _err(errors, path, "authorization: 必须为非空授权说明")
    _validate_scope(doc.get("scope"), f"{path}.scope", errors)
    _validate_prerequisites(doc.get("prerequisites"), f"{path}.prerequisites", errors)
    _validate_steps(doc.get("steps"), f"{path}.steps", errors)
    seed = doc.get("seed")
    if not (isinstance(seed, int) and not isinstance(seed, bool)):
        _err(errors, path, "seed: 必须为整数（固定随机种子）")
    _validate_reset_plan(doc.get("reset_plan"), f"{path}.reset_plan", errors)
    _validate_expectations(doc.get("expectations_by_profile"), f"{path}.expectations_by_profile", known_profiles, errors)
    _validate_evidence_requirements(doc.get("evidence_requirements"), f"{path}.evidence_requirements", errors)
    if doc.get("dataset_partition") not in PARTITIONS:
        _err(errors, path, f"dataset_partition: 必须为 {PARTITIONS} 之一")
    _validate_client(doc.get("client"), f"{path}.client", errors)

    # 真值与期望一致性（§4.1：不以规则命中反向生成类别）
    exp = doc.get("expectations_by_profile")
    if isinstance(exp, dict):
        mods = []
        for e in exp.values():
            if isinstance(e, dict) and isinstance(e.get("expected_detection"), dict):
                mods.append(e["expected_detection"].get("module"))
        if truth == "BENIGN" and any(m not in (None, "none") for m in mods):
            _err(errors, path, "truth=BENIGN 的样本不得期望检测（正常业务误报防护样本）")
        if truth == "ATTACK" and not deferred and mods and all(m in (None, "none") for m in mods):
            _err(errors, path, "truth=ATTACK 但所有 profile 均无检测期望；未声明能力的攻击样本应标 UNKNOWN 或 deferred")
    return errors


def validate_manifest_structure(manifest) -> list[str]:
    """顶层与条目结构校验（不读文件系统）。"""
    errors: list[str] = []
    if not isinstance(manifest, dict):
        return ["manifest 顶层必须是 JSON 对象"]
    sv = manifest.get("schema_version")
    if isinstance(sv, int) and not isinstance(sv, bool) and sv != SCHEMA_VERSION:
        errors.append(f"schema_version: 未知 schema 主版本 {sv}（本校验器仅支持 v{SCHEMA_VERSION}）")
    elif not isinstance(sv, int) or isinstance(sv, bool):
        errors.append("schema_version: 必须为整数 1")
    if not _is_nonempty_str(manifest.get("corpus_id")):
        errors.append("corpus_id: 必须为非空字符串")
    created = manifest.get("created_at")
    if not isinstance(created, str) or not RFC3339_RE.match(created):
        errors.append("created_at: 必须为 RFC3339 时间戳")
    if not _is_nonempty_str(manifest.get("description")):
        errors.append("description: 必须为非空说明")
    cases = manifest.get("cases")
    if not isinstance(cases, list) or not cases:
        errors.append("cases: 必须为非空数组")
        return errors
    seen_ids: set[str] = set()
    seen_files: set[str] = set()
    for i, entry in enumerate(cases):
        path = f"cases[{i}]"
        if not isinstance(entry, dict):
            _err(errors, path, "条目必须是对象（case_id/case_version/file/content_sha256）")
            continue
        cid = entry.get("case_id")
        if not isinstance(cid, str) or not CASE_ID_RE.match(cid):
            _err(errors, path, f"case_id: 必须匹配 {CASE_ID_RE.pattern}")
        elif cid in seen_ids:
            _err(errors, path, f"重复 case_id: {cid}")
        else:
            seen_ids.add(cid)
        cv = entry.get("case_version")
        if not (isinstance(cv, int) and not isinstance(cv, bool) and cv >= 1):
            _err(errors, path, "case_version: 必须为正整数")
        f = entry.get("file")
        if not _is_nonempty_str(f):
            _err(errors, path, "file: 必须为非空相对路径")
        elif f in seen_files:
            _err(errors, path, f"重复引用文件: {f}")
        else:
            seen_files.add(f)
        sha = entry.get("content_sha256")
        if not isinstance(sha, str) or not SHA256_RE.match(sha):
            _err(errors, path, "content_sha256: 必须为 64 位小写 sha256（case 文件原始字节）")
        for key in ("case_id", "case_version", "file", "content_sha256"):
            if key not in entry:
                _err(errors, path, f"缺必填字段 {key}")
    return errors


def validate_corpus(manifest_path: str | Path, known_profiles=DEFAULT_PROFILE_IDS) -> tuple[dict, list[str]]:
    """完整校验：manifest 结构 + 路径越界 + 内容哈希自校验 + case 文件逐字段校验。

    返回 (corpus, errors)。corpus 含 manifest、manifest_sha256、cases 映射
    （case_id -> {"entry", "doc", "file_path"}）；有错误时 corpus 仍尽量填充
    可用部分，调用方必须以 errors 为准。
    """
    mp = Path(manifest_path)
    corpus_dir = mp.parent
    corpus: dict = {"manifest_path": str(mp), "manifest": None, "manifest_sha256": None, "cases": {}}
    try:
        manifest = load_manifest(mp)
    except CorpusError as exc:
        return corpus, [str(exc)]
    corpus["manifest"] = manifest
    corpus["manifest_sha256"] = sha256_file(mp)

    errors = validate_manifest_structure(manifest)
    entries = manifest.get("cases") if isinstance(manifest, dict) else None
    if not isinstance(entries, list):
        return corpus, errors

    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            continue
        path = f"cases[{i}]"
        rel = entry.get("file")
        resolved, perr = resolve_case_file(corpus_dir, rel)
        if perr:
            _err(errors, f"{path}.file", perr)
            continue
        if not resolved.is_file():
            _err(errors, f"{path}.file", f"引用文件不存在: {rel}")
            continue
        actual = sha256_file(resolved)
        want = entry.get("content_sha256")
        if isinstance(want, str) and SHA256_RE.match(want) and actual != want:
            _err(
                errors,
                f"{path}.content_sha256",
                f"内容哈希失配（登记 {want[:16]}…，实际 {actual[:16]}…）："
                "样本被改动必须升 case_version 并重新登记（REG-002）",
            )
        try:
            with resolved.open("r", encoding="utf-8") as fh:
                doc = json.load(fh)
        except json.JSONDecodeError as exc:
            _err(errors, f"{path}.file", f"case 文件不是合法 JSON: {exc}")
            continue
        errors.extend(validate_case_doc(doc, known_profiles, path=f"{rel}"))
        if isinstance(doc, dict):
            if doc.get("case_id") != entry.get("case_id"):
                _err(errors, path, f"manifest 条目 case_id={entry.get('case_id')!r} 与文件内 {doc.get('case_id')!r} 不一致")
            if doc.get("case_version") != entry.get("case_version"):
                _err(errors, path, f"manifest 条目 case_version={entry.get('case_version')!r} 与文件内 {doc.get('case_version')!r} 不一致")
            cid = entry.get("case_id")
            if isinstance(cid, str):
                corpus["cases"][cid] = {"entry": entry, "doc": doc, "file_path": str(resolved)}
    return corpus, errors


def require_valid_corpus(manifest_path: str | Path, known_profiles=DEFAULT_PROFILE_IDS) -> dict:
    corpus, errors = validate_corpus(manifest_path, known_profiles)
    if errors:
        raise CorpusError("P1 语料不满足 schema v1 契约：\n" + "\n".join(f"  - {e}" for e in errors))
    return corpus


def iter_active_cases(corpus: dict):
    """产出非 deferred 样本（deferred 不进入任何执行计划与分母）。"""
    for cid in sorted(corpus["cases"]):
        item = corpus["cases"][cid]
        if not item["doc"].get("deferred"):
            yield item


def accuracy_cases(corpus: dict):
    """产出可进入准确率/检出率分母的样本：非 deferred 且 truth != UNKNOWN。"""
    for item in iter_active_cases(corpus):
        if item["doc"].get("truth") != "UNKNOWN":
            yield item
