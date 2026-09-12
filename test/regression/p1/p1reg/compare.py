"""前后版本逐例配对比较（P1-04 任务书 §5；compare 子命令的计算核心）。

铁律：
- 只读两个已完成证据目录（cases.jsonl 等），不重新执行、不猜测期望（§3/§5）。
- 期望取自基线/候选运行各自记录的快照；同一 case_id+case_version 期望不一致
  即完整性告警 EXPECTATION_CHANGED_SAME_VERSION（语义变化必须升版本，REG-002）。
- 分母 = 两侧均适用且实际执行有效（executed 且 valid）且 truth != UNKNOWN
  的配对样本；同时展示计划/有效/缺失数；分母为零显示 N/A（REG-003）。
- 历史已知漏报持续列出：前后都未通过不因“相同”算通过（§4.2、REG-011）。
- 不可比较逐例给出原因：缺失、版本变化、执行无效、UNKNOWN/deferred 排除。
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from p0bench.isolation import validate_run_id
from p0bench.metrics import NA

from .vocab import STATUSES

REQUIRED_RUN_FILES = ("plan.json", "manifest.json", "status.json", "cases.jsonl")
TRUTHS = ("BENIGN", "ATTACK", "UNKNOWN")
CRITICALITIES = ("MANDATORY", "STANDARD")

REQUIRED_ROW_KEYS = (
    "case_id", "case_version", "profile", "truth", "criticality",
    "executed", "valid", "status",
)


class CompareError(Exception):
    """compare 输入结构性错误（目录缺失等）。"""


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load_run(run_dir: str | Path) -> dict:
    """装载一个已完成回归证据目录。只读；结构问题逐条进 integrity_errors。"""
    d = Path(run_dir)
    if not d.is_dir():
        raise CompareError(f"证据目录不存在: {d}")
    run: dict = {"run_dir": str(d), "run_id": d.name, "integrity_errors": [], "rows": {}, "files_sha256": {}}
    for name in REQUIRED_RUN_FILES:
        f = d / name
        if not f.is_file():
            run["integrity_errors"].append(f"原始文件缺失: {name}")
            continue
        run["files_sha256"][name] = _sha256_file(f)

    manifest_path = d / "manifest.json"
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            run["integrity_errors"].append(f"manifest.json 不是合法 JSON: {exc}")
            manifest = None
        if isinstance(manifest, dict):
            mid = manifest.get("run_id")
            if mid != d.name:
                run["integrity_errors"].append(
                    f"manifest.run_id={mid!r} 与目录名 {d.name!r} 不一致"
                )
            elif not validate_run_id(mid):
                run["integrity_errors"].append(f"manifest.run_id 格式非法: {mid!r}")

    status_path = d / "status.json"
    if status_path.is_file():
        try:
            status_doc = json.loads(status_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            run["integrity_errors"].append(f"status.json 不是合法 JSON: {exc}")
            status_doc = None
        if isinstance(status_doc, dict):
            for tid, rec in (status_doc.get("records") or {}).items():
                st = rec.get("status") if isinstance(rec, dict) else None
                if st not in STATUSES:
                    run["integrity_errors"].append(f"status.json: {tid} 状态非法: {st!r}")
                elif st == "SKIP" and rec.get("mandatory", True):
                    run["integrity_errors"].append(f"status.json: {tid} 强制项非法 SKIP")

    cases_path = d / "cases.jsonl"
    if cases_path.is_file():
        with cases_path.open("r", encoding="utf-8") as fh:
            for ln, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError as exc:
                    run["integrity_errors"].append(f"cases.jsonl 第 {ln} 行不是合法 JSON: {exc}")
                    continue
                if not isinstance(row, dict):
                    run["integrity_errors"].append(f"cases.jsonl 第 {ln} 行必须是对象")
                    continue
                missing = [k for k in REQUIRED_ROW_KEYS if k not in row]
                if missing:
                    run["integrity_errors"].append(f"cases.jsonl 第 {ln} 行缺字段: {missing}")
                    continue
                bad = False
                if not isinstance(row["case_id"], str) or not isinstance(row["profile"], str):
                    bad = True
                if not isinstance(row["case_version"], int) or isinstance(row["case_version"], bool):
                    bad = True
                if row["truth"] not in TRUTHS or row["criticality"] not in CRITICALITIES:
                    bad = True
                if not isinstance(row["executed"], bool) or not isinstance(row["valid"], bool):
                    bad = True
                if row["status"] not in STATUSES:
                    bad = True
                if bad:
                    run["integrity_errors"].append(f"cases.jsonl 第 {ln} 行字段类型/词表非法")
                    continue
                key = (row["case_id"], row["profile"])
                if key in run["rows"]:
                    run["integrity_errors"].append(f"cases.jsonl 重复行: {key}")
                    continue
                run["rows"][key] = row
    return run


def _detection_correct(row: dict) -> bool | None:
    det = (row.get("detail") or {}).get("detection")
    if not isinstance(det, dict):
        return None
    if isinstance(det.get("correct"), bool):
        return det["correct"]
    detected = det.get("detected")
    exp_module = det.get("expected_module")
    if detected is None or exp_module is None:
        return None
    if exp_module == "none":
        return detected is False
    return detected is True and det.get("observed_module") == exp_module


def _observed_action(row: dict):
    act = (row.get("detail") or {}).get("action")
    return act.get("observed") if isinstance(act, dict) else None


def _observed_origin(row: dict):
    ori = (row.get("detail") or {}).get("origin")
    return ori.get("observed") if isinstance(ori, dict) else None


def _expectation_snapshot(row: dict):
    """期望快照取自判定器记录的 expectation 字段（执行失败的行 detail 为空，
    不能据此误判期望漂移）。"""
    exp = row.get("expectation") or {}
    det = exp.get("expected_detection") or {}
    return {
        "detection": {"expected_module": det.get("module"),
                      "expected_rule_family": det.get("rule_family")},
        "action": {"expected": exp.get("expected_final_action")},
        "origin": {"expected": exp.get("expected_origin")},
    }


def _incomparable(entry: dict, reason: str) -> dict:
    return {"case_id": entry["case_id"], "profile": entry["profile"], "reason": reason}


def compare_runs(baseline_dir: str | Path, candidate_dir: str | Path) -> dict:
    """配对比较两个已完成回归运行。返回结构化 compare 文档。"""
    baseline = load_run(baseline_dir)
    candidate = load_run(candidate_dir)

    doc: dict = {
        "schema_version": 1,
        "kind": "p1_regression_compare",
        "baseline": {"run_id": baseline["run_id"], "cases_sha256": baseline["files_sha256"].get("cases.jsonl")},
        "candidate": {"run_id": candidate["run_id"], "cases_sha256": candidate["files_sha256"].get("cases.jsonl")},
        "integrity_errors": (
            [f"baseline: {e}" for e in baseline["integrity_errors"]]
            + [f"candidate: {e}" for e in candidate["integrity_errors"]]
        ),
        "pairs": [],
        "incomparable": [],
        "summary": {},
        "verdict": "NOT_PASSED",
        "verdict_reasons": [],
    }

    keys = sorted(set(baseline["rows"]) | set(candidate["rows"]))
    new_correct: list[dict] = []
    new_fp: list[dict] = []
    new_block_fp: list[dict] = []
    lost: list[dict] = []
    action_changes: list[dict] = []
    origin_changes: list[dict] = []
    fixed_fp: list[dict] = []
    new_failures: list[dict] = []
    persistent_failures: list[dict] = []
    unchanged_correct = 0
    paired = 0
    paired_benign = 0
    paired_attack = 0
    mandatory_incomparable = 0

    for case_id, profile in keys:
        brow = baseline["rows"].get((case_id, profile))
        crow = candidate["rows"].get((case_id, profile))
        ref = brow or crow or {}
        base_entry = {"case_id": case_id, "profile": profile,
                      "truth": ref.get("truth"), "criticality": ref.get("criticality")}
        if brow is None:
            doc["incomparable"].append(_incomparable(base_entry, "CASE_MISSING_IN_BASELINE"))
            if ref.get("criticality") == "MANDATORY":
                mandatory_incomparable += 1
            continue
        if crow is None:
            doc["incomparable"].append(_incomparable(base_entry, "CASE_MISSING_IN_CANDIDATE"))
            if ref.get("criticality") == "MANDATORY":
                mandatory_incomparable += 1
            continue
        if brow["case_version"] != crow["case_version"]:
            doc["incomparable"].append(_incomparable(base_entry, "CASE_VERSION_CHANGED"))
            if ref.get("criticality") == "MANDATORY":
                mandatory_incomparable += 1
            continue
        if _expectation_snapshot(brow) != _expectation_snapshot(crow):
            doc["integrity_errors"].append(
                f"EXPECTATION_CHANGED_SAME_VERSION: {case_id}/{profile} "
                f"v{brow['case_version']} 两侧期望不一致（语义变化必须升 case_version）"
            )
            doc["incomparable"].append(_incomparable(base_entry, "EXPECTATION_CHANGED_SAME_VERSION"))
            if ref.get("criticality") == "MANDATORY":
                mandatory_incomparable += 1
            continue
        if brow.get("truth") == "UNKNOWN":
            doc["incomparable"].append(_incomparable(base_entry, "TRUTH_UNKNOWN_EXCLUDED"))
            continue
        if not (brow["executed"] and brow["valid"]):
            doc["incomparable"].append(_incomparable(
                base_entry, f"EXECUTION_INVALID_IN_BASELINE(status={brow['status']})"))
            if ref.get("criticality") == "MANDATORY":
                mandatory_incomparable += 1
            continue
        if not (crow["executed"] and crow["valid"]):
            doc["incomparable"].append(_incomparable(
                base_entry, f"EXECUTION_INVALID_IN_CANDIDATE(status={crow['status']})"))
            if ref.get("criticality") == "MANDATORY":
                mandatory_incomparable += 1
            continue

        paired += 1
        truth = brow["truth"]
        if truth == "BENIGN":
            paired_benign += 1
        elif truth == "ATTACK":
            paired_attack += 1

        b_det = _detection_correct(brow)
        c_det = _detection_correct(crow)
        b_act, c_act = _observed_action(brow), _observed_action(crow)
        b_ori, c_ori = _observed_origin(brow), _observed_origin(crow)

        pair = dict(base_entry)
        pair.update({
            "case_version": brow["case_version"],
            "baseline": {"status": brow["status"], "detection_correct": b_det,
                         "observed_action": b_act, "origin_reached": b_ori},
            "candidate": {"status": crow["status"], "detection_correct": c_det,
                          "observed_action": c_act, "origin_reached": c_ori},
            "changes": [],
        })

        both_pass = brow["status"] == "PASS" and crow["status"] == "PASS"
        both_fail = brow["status"] == "FAIL" and crow["status"] == "FAIL"

        if truth == "ATTACK":
            if b_det is False and c_det is True:
                new_correct.append(dict(base_entry))
                pair["changes"].append("new_correct_detection")
            if b_det is True and c_det is False:
                lost.append(dict(base_entry))
                pair["changes"].append("lost_detection")
        elif truth == "BENIGN":
            b_clean = brow["status"] == "PASS"
            c_clean = crow["status"] == "PASS"
            if b_clean and not c_clean:
                new_fp.append(dict(base_entry))
                pair["changes"].append("new_false_positive")
                if c_act in ("BLOCK_403", "RATE_LIMIT_429"):
                    new_block_fp.append(dict(base_entry))
                    pair["changes"].append("new_block_false_positive")
            elif not b_clean and c_clean:
                fixed_fp.append(dict(base_entry))
                pair["changes"].append("fixed_false_positive")

        if b_act != c_act:
            action_changes.append({**base_entry, "from": b_act, "to": c_act})
            pair["changes"].append("action_change")
        if b_ori != c_ori:
            origin_changes.append({**base_entry, "from": b_ori, "to": c_ori})
            pair["changes"].append("origin_change")
        if both_fail:
            persistent_failures.append(dict(base_entry))
            pair["changes"].append("persistent_failure")
        if brow["status"] == "PASS" and crow["status"] == "FAIL":
            # baseline 通过而候选失败：无论真值类别均为回归（§5.2 逐例列出）
            new_failures.append(dict(base_entry))
            pair["changes"].append("new_failure")
        if both_pass and not pair["changes"]:
            unchanged_correct += 1
        doc["pairs"].append(pair)

    def _rate(num: int, denom: int):
        return NA if denom == 0 else num / denom

    doc["summary"] = {
        "paired": paired,
        "denominator": paired,
        "paired_benign": paired_benign,
        "paired_attack": paired_attack,
        "unchanged_correct": unchanged_correct,
        "new_correct_detections": new_correct,
        "new_false_positives": new_fp,
        "new_block_false_positives": new_block_fp,
        "lost_detections": lost,
        "action_changes": action_changes,
        "origin_changes": origin_changes,
        "fixed_false_positives": fixed_fp,
        "new_failures": new_failures,
        "persistent_failures": persistent_failures,
        "incomparable_count": len(doc["incomparable"]),
        "mandatory_incomparable": mandatory_incomparable,
        "new_false_positive_rate": _rate(len(new_fp), paired_benign),
        "lost_detection_rate": _rate(len(lost), paired_attack),
        "new_failure_rate": _rate(len(new_failures), paired),
    }

    reasons: list[str] = []
    if doc["integrity_errors"]:
        reasons.extend(f"完整性: {e}" for e in doc["integrity_errors"])
    if paired == 0:
        reasons.append("可配对且执行有效的样本数为 0（执行数量不足，比较无效）")
    if mandatory_incomparable:
        reasons.append(f"强制用例不可比较 {mandatory_incomparable} 条（缺失/版本变化/执行无效）")
    mandatory_lost = [e for e in lost if e["criticality"] == "MANDATORY"]
    mandatory_persistent = [e for e in persistent_failures if e["criticality"] == "MANDATORY"]
    if new_failures:
        reasons.append(
            f"新增失败 {len(new_failures)} 条（baseline 通过→候选失败）: "
            f"{[e['case_id'] for e in new_failures]}"
        )
    if lost:
        reasons.append(f"丢失检测 {len(lost)} 条（强制 {len(mandatory_lost)}）: {[e['case_id'] for e in lost]}")
    if new_fp:
        reasons.append(f"新增误报 {len(new_fp)} 条（其中新增误拦截 {len(new_block_fp)} 条）")
    if mandatory_persistent:
        reasons.append(
            f"历史强制缺陷持续存在 {len(mandatory_persistent)} 条（前后相同不算通过，§4.2）: "
            f"{[e['case_id'] for e in mandatory_persistent]}"
        )

    if doc["integrity_errors"] or paired == 0 or mandatory_incomparable:
        doc["verdict"] = "NOT_PASSED"
    elif new_failures or lost or mandatory_persistent:
        doc["verdict"] = "FAIL"
    else:
        doc["verdict"] = "PASS"
    doc["verdict_reasons"] = reasons
    return doc


def _fmt_rate(v) -> str:
    return NA if v == NA else f"{v * 100:.2f}%"


def render_compare_markdown(doc: dict) -> str:
    s = doc["summary"]
    lines: list[str] = []
    add = lines.append
    add("# P1-04 前后版本回归对比报告")
    add("")
    add(f"- baseline: `{doc['baseline']['run_id']}`（cases.sha256 `{str(doc['baseline']['cases_sha256'])[:16]}…`）")
    add(f"- candidate: `{doc['candidate']['run_id']}`（cases.sha256 `{str(doc['candidate']['cases_sha256'])[:16]}…`）")
    add("- 比较方式：只读两个已完成证据目录逐例配对；不重新执行、不猜测期望")
    add("")
    add("## 总判定")
    add("")
    add(f"**{doc['verdict']}**")
    for r in doc["verdict_reasons"]:
        add(f"- {r}")
    if not doc["verdict_reasons"]:
        add("- 全部可配对样本无回归差异")
    add("")
    add("## 汇总")
    add("")
    add("| 指标 | 值 |")
    add("|---|---|")
    add(f"| 可配对有效样本（分母） | {s['paired']} |")
    add(f"| 其中正常样本 | {s['paired_benign']} |")
    add(f"| 其中攻击样本 | {s['paired_attack']} |")
    add(f"| 前后一致且通过 | {s['unchanged_correct']} |")
    add(f"| 新增失败（baseline 通过→候选失败） | {len(s['new_failures'])}（{_fmt_rate(s['new_failure_rate'])}） |")
    add(f"| 新增正确命中 | {len(s['new_correct_detections'])} |")
    add(f"| 新增误报（率） | {len(s['new_false_positives'])}（{_fmt_rate(s['new_false_positive_rate'])}） |")
    add(f"| 其中新增误拦截 | {len(s['new_block_false_positives'])} |")
    add(f"| 丢失检测（率） | {len(s['lost_detections'])}（{_fmt_rate(s['lost_detection_rate'])}） |")
    add(f"| 动作变化 | {len(s['action_changes'])} |")
    add(f"| 源站变化 | {len(s['origin_changes'])} |")
    add(f"| 修复的历史误报 | {len(s['fixed_false_positives'])} |")
    add(f"| 持续存在的历史缺陷 | {len(s['persistent_failures'])} |")
    add(f"| 不可比较（强制） | {s['incomparable_count']}（{s['mandatory_incomparable']}） |")
    add("")

    def _table(title: str, rows, extra=None):
        add(f"## {title}")
        add("")
        if not rows:
            add("无")
            add("")
            return
        add("| case_id | profile | truth | criticality |" + (" 变化 |" if extra else ""))
        add("|---|---|---|---|" + ("---|" if extra else ""))
        for e in rows:
            tail = f" {extra(e)} |" if extra else ""
            add(f"| {e['case_id']} | {e['profile']} | {e.get('truth')} | {e.get('criticality')} |{tail}")
        add("")

    _table("新增失败（回归）", s["new_failures"])
    _table("新增正确命中", s["new_correct_detections"])
    _table("新增误报", s["new_false_positives"])
    _table("丢失检测", s["lost_detections"])
    _table("动作变化", s["action_changes"], lambda e: f"{e['from']} → {e['to']}")
    _table("源站变化", s["origin_changes"], lambda e: f"{e['from']} → {e['to']}")
    _table("持续存在的历史缺陷（前后相同不算通过）", s["persistent_failures"])
    _table("不可比较样本", doc["incomparable"], lambda e: e["reason"])
    return "\n".join(lines)


def write_compare(doc: dict, out_dir: str | Path) -> tuple[Path, Path]:
    """写出 compare.json 与 report.md（新建目录，不改动输入证据目录）。"""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    cj = out / "compare.json"
    tmp = cj.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(cj)
    md = out / "report.md"
    tmp = md.with_suffix(".md.tmp")
    tmp.write_text(render_compare_markdown(doc), encoding="utf-8")
    tmp.replace(md)
    return cj, md
