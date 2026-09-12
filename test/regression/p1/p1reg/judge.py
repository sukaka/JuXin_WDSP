"""逐例判定器骨架（P1-04 任务书 §5.2）。

输入：case 文档 + profile + 执行层观测（observation）。
观测契约（执行层/对账层填充；任何字段缺失按缺证据处理）：
  executed          bool    是否实际发起执行
  valid             bool    请求/响应有效性预检（源站正确性等）
  blocked_reason    str     环境阻塞原因（ENVIRONMENT_UNAVAILABLE → BLOCKED）
  execution_state   str     COMPLETED/ABORTED/ERROR/UNKNOWN/PENDING_CORRELATION
  detection         dict|None  {"detected": bool, "module": str|None, "rule_family": str|None}
  observed_action   str|None   PASS/DETECT_PASS/BLOCK_403/RATE_LIMIT_429/UNEXPECTED_ERROR
  origin_reached    bool|None  源站是否实际收到（受控源站标记对账，不是 HTTP 状态推断）
  assertions        list|None  [{"step_id","type","met":bool,"detail":str}]
  side_effects      dict|None  源站业务副作用实测（如写入计数）
  evidence_refs     list       脱敏证据引用（日志/事件 ID）

铁律：
- 必须区分规则命中（detection）、最终动作（observed_action）、HTTP 结果与
  源站副作用；HTTP 403/429 或响应关键字不能单独证明指定模块正确处理（REG-004）。
- ABORTED/ERROR/UNKNOWN/PENDING_CORRELATION 不得默认转通过；等待结束仍缺
  证据不通过。
- truth=UNKNOWN 照样判定并记录，但由 summarize/compare 排除出分母（REG-003）。
"""

from __future__ import annotations

from p0bench.corpus import ACTIONS as FINAL_ACTIONS
from p0bench.metrics import NA

from .vocab import (
    EXTRA_ACTIONS,
    NON_PASSABLE_EXECUTION_STATES,
    REASON_ENVIRONMENT_UNAVAILABLE,
    REASON_EXPECTATION_MISMATCH,
    REASON_INVALID_EXECUTION,
    REASON_MISSING_EVIDENCE,
    REASON_NOT_ATTEMPTED,
    REASON_PROFILE_NOT_APPLICABLE,
)

EXPECTED_ACTIONS = FINAL_ACTIONS + EXTRA_ACTIONS
OBSERVED_ACTIONS = FINAL_ACTIONS + EXTRA_ACTIONS + ("UNEXPECTED_ERROR",)


def judge_case(case_doc: dict, profile: str, observation: dict | None) -> dict:
    """逐例判定。返回结构化结果（可直接序列化为 cases.jsonl 行）。"""
    doc = case_doc
    result: dict = {
        "case_id": doc.get("case_id"),
        "case_version": doc.get("case_version"),
        "profile": profile,
        "truth": doc.get("truth"),
        "criticality": doc.get("criticality"),
        "family": doc.get("family"),
        "dataset_partition": doc.get("dataset_partition"),
        "executed": False,
        "valid": False,
        "status": "NOT_RUN",
        "reasons": [],
        "detail": {},
    }
    exp = (doc.get("expectations_by_profile") or {}).get(profile)
    if exp is None:
        result["status"] = "NOT_APPLICABLE"
        result["reasons"].append(f"{REASON_PROFILE_NOT_APPLICABLE}: 样本不适用于 profile {profile}")
        return result
    result["expectation"] = exp

    if observation is None:
        result["status"] = "NOT_RUN"
        result["reasons"].append(f"{REASON_NOT_ATTEMPTED}: 无执行观测")
        return result
    result["executed"] = bool(observation.get("executed"))
    result["valid"] = bool(observation.get("valid"))

    if observation.get("blocked_reason") == REASON_ENVIRONMENT_UNAVAILABLE:
        result["status"] = "BLOCKED"
        result["reasons"].append(f"{REASON_ENVIRONMENT_UNAVAILABLE}: 隔离环境不可用，未执行")
        return result
    if not result["executed"]:
        result["status"] = "NOT_RUN"
        result["reasons"].append(f"{REASON_NOT_ATTEMPTED}: 未实际执行")
        return result

    state = observation.get("execution_state", "COMPLETED")
    if state in NON_PASSABLE_EXECUTION_STATES:
        result["status"] = "FAIL"
        result["reasons"].append(
            f"执行状态 {state} 不得默认转通过；等待结束仍缺证据按不通过处理（§5.2）"
        )
        result["detail"]["execution_state"] = state
        return result
    if state != "COMPLETED":
        result["status"] = "FAIL"
        result["reasons"].append(f"未知执行状态 {state!r}，拒绝按通过处理")
        return result
    if not result["valid"]:
        # 执行无效（如源站预检失败）：不计入分母，也绝不构成通过
        result["status"] = "NOT_APPLICABLE"
        result["reasons"].append(f"{REASON_INVALID_EXECUTION}: 执行有效性预检未过，不计入分母")
        return result

    reasons: list[str] = []
    detail: dict = {}

    # 1) 检测判定（规则命中/统一 finding 层，与 HTTP 结果分离）
    det_exp = exp.get("expected_detection") or {}
    det_obs = observation.get("detection")
    exp_module = det_exp.get("module", "none")
    exp_family = det_exp.get("rule_family")
    if det_obs is None:
        reasons.append(f"{REASON_MISSING_EVIDENCE}: 缺检测证据（事件/日志对账未提供）")
        det_detail = {"expected_module": exp_module, "expected_rule_family": exp_family,
                      "observed_module": None, "observed_rule_family": None,
                      "detected": None, "correct": False}
    else:
        detected = bool(det_obs.get("detected"))
        obs_module = det_obs.get("module")
        obs_family = det_obs.get("rule_family")
        obs_families = det_obs.get("matched_families") or ([obs_family] if obs_family else [])
        if exp_module == "none":
            correct = not detected
        else:
            correct = (
                detected
                and obs_module == exp_module
                # 规则族按命中集合成员判定：多规则命中是常态，首条顺序不代表语义
                and (exp_family is None or exp_family in obs_families)
            )
        det_detail = {"expected_module": exp_module, "expected_rule_family": exp_family,
                      "observed_module": obs_module, "observed_rule_family": obs_family,
                      "observed_matched_families": obs_families,
                      "detected": detected, "correct": correct}
        if not correct:
            if exp_module == "none" and detected:
                reasons.append(
                    f"{REASON_EXPECTATION_MISMATCH}: 正常样本被误报检测"
                    f"（module={obs_module!r} family={obs_family!r}）"
                )
            elif exp_module != "none" and not detected:
                reasons.append(f"{REASON_EXPECTATION_MISMATCH}: 期望模块 {exp_module} 检出但未检出")
            elif obs_module != exp_module:
                reasons.append(
                    f"{REASON_EXPECTATION_MISMATCH}: 检出模块不符（期望 {exp_module}，实际 {obs_module!r}）"
                    "——HTTP 结果或无关模块命中不能冒充目标模块正确检测"
                )
            else:
                reasons.append(
                    f"{REASON_EXPECTATION_MISMATCH}: 规则族不符（期望 {exp_family}，实际 {obs_family!r}）"
                )
    detail["detection"] = det_detail

    # 2) 最终动作判定（网关 final_decision / API final_action 层）
    exp_action = exp.get("expected_final_action")
    obs_action = observation.get("observed_action")
    if obs_action is None:
        reasons.append(f"{REASON_MISSING_EVIDENCE}: 缺最终处置证据")
        action_detail = {"expected": exp_action, "observed": None, "correct": False}
    else:
        if obs_action not in OBSERVED_ACTIONS:
            reasons.append(f"观测到非法动作 {obs_action!r}，拒绝按通过处理")
        elif obs_action == "UNEXPECTED_ERROR":
            reasons.append(f"{REASON_EXPECTATION_MISMATCH}: 请求产生非预期错误（不得按安全通过处理）")
        elif obs_action != exp_action:
            reasons.append(
                f"{REASON_EXPECTATION_MISMATCH}: 最终动作不符（期望 {exp_action}，实际 {obs_action}）"
            )
        action_detail = {"expected": exp_action, "observed": obs_action,
                         "correct": obs_action == exp_action and obs_action in EXPECTED_ACTIONS}
    detail["action"] = action_detail

    # 3) 源站到达判定（受控源站标记对账；HTTP 状态不能替代）
    exp_origin = exp.get("expected_origin")
    obs_origin = observation.get("origin_reached")
    if exp_origin in ("reached", "not_reached"):
        if obs_origin is None:
            reasons.append(f"{REASON_MISSING_EVIDENCE}: 缺源站到达证据（受控源站标记/计数缺失）")
            origin_detail = {"expected": exp_origin, "observed": None, "correct": False}
        else:
            want = exp_origin == "reached"
            origin_detail = {"expected": exp_origin, "observed": obs_origin, "correct": obs_origin == want}
            if obs_origin != want:
                reasons.append(
                    f"{REASON_EXPECTATION_MISMATCH}: 源站到达性不符（期望 {exp_origin}，实际 "
                    f"{'reached' if obs_origin else 'not_reached'}）"
                )
        detail["origin"] = origin_detail

    # 4) 步骤断言（适配器已求值；任一未满足即不符）
    assertions = observation.get("assertions")
    if assertions:
        unmet = [a for a in assertions if isinstance(a, dict) and a.get("met") is False]
        detail["assertions"] = {"total": len(assertions), "unmet": len(unmet)}
        for a in unmet:
            reasons.append(
                f"{REASON_EXPECTATION_MISMATCH}: 步骤断言未满足 "
                f"{a.get('step_id')}/{a.get('type')}（{a.get('detail', '')}）"
            )

    # 5) 业务副作用（源站计数/写入等；期望存在时必须提供实测）
    exp_se = exp.get("expected_side_effects")
    if exp_se:
        obs_se = observation.get("side_effects")
        if not isinstance(obs_se, dict):
            reasons.append(f"{REASON_MISSING_EVIDENCE}: 缺业务副作用实测（期望核对 {sorted(exp_se)}）")
            detail["side_effects"] = {"expected": exp_se, "observed": None, "correct": False}
        else:
            mism = {k: {"expected": v, "observed": obs_se.get(k)} for k, v in exp_se.items()
                    if k not in obs_se or obs_se.get(k) != v}
            detail["side_effects"] = {"expected": exp_se, "observed": obs_se, "correct": not mism}
            for k, m in mism.items():
                reasons.append(
                    f"{REASON_EXPECTATION_MISMATCH}: 副作用 {k} 不符"
                    f"（期望 {m['expected']!r}，实际 {m['observed']!r}）"
                )

    result["detail"] = detail
    result["reasons"] = reasons
    result["status"] = "PASS" if not reasons else "FAIL"
    return result


def _rate(num: int, denom: int):
    return NA if denom == 0 else num / denom


def summarize(results: list[dict], planned_by_profile: dict | None = None) -> dict:
    """逐例结果 → 分 profile 汇总（检测/处置分离；零分母 N/A）。

    分母 = 适用且实际执行有效（executed 且 valid）且 truth != UNKNOWN 的样本；
    同时给出计划数、执行数、有效数与缺失数；执行不完整不产生完整通过口径。
    """
    profiles: dict[str, dict] = {}

    def _bucket(pid: str) -> dict:
        if pid not in profiles:
            profiles[pid] = {
                "planned": (planned_by_profile or {}).get(pid),
                "executed": 0,
                "valid": 0,
                "invalid": 0,
                "blocked": 0,
                "not_run": 0,
                "excluded_unknown": 0,
                "pass": 0,
                "fail": 0,
                "detection_false_positive": {"count": 0, "denominator": 0, "rate": NA},
                "block_false_positive": {"count": 0, "denominator": 0, "rate": NA},
                "detection_miss": {"count": 0, "denominator": 0, "rate": NA},
                "block_miss": {"count": 0, "denominator": 0, "rate": NA},
                "failures": [],
            }
        return profiles[pid]

    for r in results:
        b = _bucket(r.get("profile"))
        st = r.get("status")
        if st == "BLOCKED":
            b["blocked"] += 1
            continue
        if st == "NOT_RUN":
            b["not_run"] += 1
            continue
        if r.get("executed"):
            b["executed"] += 1
        if not r.get("valid"):
            b["invalid"] += 1
            continue
        b["valid"] += 1
        if r.get("truth") == "UNKNOWN":
            b["excluded_unknown"] += 1
            continue
        if st == "PASS":
            b["pass"] += 1
        elif st == "FAIL":
            b["fail"] += 1
            b["failures"].append({"case_id": r.get("case_id"), "reasons": r.get("reasons") or []})

        det = (r.get("detail") or {}).get("detection") or {}
        act = (r.get("detail") or {}).get("action") or {}
        truth = r.get("truth")
        detected = det.get("detected") is True
        obs_action = act.get("observed")
        exp_action = act.get("expected")
        exp_module = det.get("expected_module")

        if truth == "BENIGN":
            b["detection_false_positive"]["denominator"] += 1
            b["block_false_positive"]["denominator"] += 1
            if detected:
                b["detection_false_positive"]["count"] += 1
            if obs_action in ("BLOCK_403", "RATE_LIMIT_429"):
                b["block_false_positive"]["count"] += 1
        elif truth == "ATTACK":
            if exp_module not in (None, "none"):
                b["detection_miss"]["denominator"] += 1
                if not detected:
                    b["detection_miss"]["count"] += 1
            # 拦截漏报只在期望阻断的 profile 计入分母；OBSERVE 正确放行不计
            if exp_action == "BLOCK_403":
                b["block_miss"]["denominator"] += 1
                if obs_action != "BLOCK_403":
                    b["block_miss"]["count"] += 1

    for b in profiles.values():
        planned = b["planned"]
        b["missing"] = None if planned is None else max(0, planned - b["executed"])
        for key in ("detection_false_positive", "block_false_positive", "detection_miss", "block_miss"):
            m = b[key]
            m["rate"] = _rate(m["count"], m["denominator"])
    return {"profiles": profiles}
