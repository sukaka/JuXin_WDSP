"""回归 run 目录只读汇总与 report.md 渲染（证据根 docs/evidence/regressions/<run-id>/）。

目录纪律沿用 P0-02 benchmarks：plan.json 0444 冻结、manifest.json、status.json、
replay-plan.json（0444）、cases.jsonl、corpus-validation.txt、report.md 只读生成。
本模块只读已登记数据，不填入估计值冒充实测；任一必需文件缺失、强制项
FAIL/BLOCKED/NOT_RUN/非法 SKIP、执行数量不足均不产生完整通过结论。
"""

from __future__ import annotations

import json
from pathlib import Path

from p0bench.metrics import NA

from .compare import REQUIRED_RUN_FILES, load_run
from .judge import summarize
from .vocab import STATUSES

EXTRA_ARTIFACTS = ("replay-plan.json",)


class ReportError(Exception):
    """run 目录结构不完整，无法生成报告。"""


def _fmt_rate(v) -> str:
    return NA if v == NA else f"{v * 100:.3f}%"


def load_regression_run(run_dir: str | Path) -> dict:
    """装载回归 run 目录：compare.load_run 通用件 + replay-plan.json。"""
    d = Path(run_dir)
    if not d.is_dir():
        raise ReportError(f"run 目录不存在: {d}")
    run = load_run(d)
    for name in EXTRA_ARTIFACTS:
        if not (d / name).is_file():
            run["integrity_errors"].append(f"原始文件缺失: {name}")
    rp = d / "replay-plan.json"
    run["replay_plan"] = None
    if rp.is_file():
        try:
            plan = json.loads(rp.read_text(encoding="utf-8"))
            if plan.get("kind") != "p1_replay_plan":
                run["integrity_errors"].append("replay-plan.json kind 非法")
            else:
                run["replay_plan"] = plan
        except json.JSONDecodeError as exc:
            run["integrity_errors"].append(f"replay-plan.json 不是合法 JSON: {exc}")
    status_doc = {}
    sp = d / "status.json"
    if sp.is_file():
        try:
            status_doc = json.loads(sp.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass
    run["status_records"] = (status_doc.get("records") or {}) if isinstance(status_doc, dict) else {}
    return run


def overall_verdict(run: dict) -> tuple[str, list[str]]:
    """总判定：强制项 FAIL → FAIL；完整性/强制项未通过/执行数量不足 → NOT_PASSED。"""
    reasons: list[str] = []
    if run["integrity_errors"]:
        reasons.extend(f"完整性: {e}" for e in run["integrity_errors"])
    if not run["status_records"]:
        reasons.append("无任何验收状态记录")
    for tid, rec in sorted(run["status_records"].items()):
        st = rec.get("status")
        mandatory = bool(rec.get("mandatory", True))
        if st == "FAIL":
            reasons.append(f"{tid}: FAIL（{rec.get('reason', '')}）")
        elif mandatory and st in ("SKIP", "BLOCKED", "NOT_RUN", "NOT_APPLICABLE"):
            reasons.append(f"{tid}: 强制项未通过（{st}：{rec.get('reason', '')}）")
    rows = list(run["rows"].values())
    mandatory_rows = [r for r in rows if r.get("criticality") == "MANDATORY"]
    for r in mandatory_rows:
        if r["status"] == "SKIP":
            reasons.append(f"{r['case_id']}/{r['profile']}: 强制用例非法 SKIP")
    planned_total = 0
    if run.get("replay_plan"):
        planned_total = sum((run["replay_plan"].get("planned_counts") or {}).values())
    executed = sum(1 for r in rows if r.get("executed"))
    if planned_total and executed < planned_total:
        reasons.append(f"执行数量不足：计划 {planned_total}，实际执行 {executed}")
    if any(r["status"] == "FAIL" and r.get("truth") != "UNKNOWN" for r in rows):
        reasons.append("存在 FAIL 用例（逐例明细见下表）")

    if any(r["status"] == "FAIL" and r.get("truth") != "UNKNOWN" for r in rows) or any(
        rec.get("status") == "FAIL" for rec in run["status_records"].values()
    ):
        return "FAIL", reasons
    if reasons:
        return "NOT_PASSED", reasons
    return "PASS", reasons


def render_markdown(run: dict) -> str:
    verdict, reasons = overall_verdict(run)
    rows = list(run["rows"].values())
    planned_by_profile = (run.get("replay_plan") or {}).get("planned_counts") or None
    summary = summarize(rows, planned_by_profile)
    lines: list[str] = []
    add = lines.append

    add("# P1-04 规则/模型回归运行报告")
    add("")
    add(f"- run 目录: `{run['run_dir']}`")
    add(f"- run_id: `{run['run_id']}`")
    corpus_info = (run.get("replay_plan") or {}).get("corpus") or {}
    add(f"- 语料: `{corpus_info.get('corpus_id', '未知')}`（manifest.sha256 `{str(corpus_info.get('manifest_sha256'))[:16]}…`）")
    add(f"- 回放种子: `{(run.get('replay_plan') or {}).get('seed', '未知')}`")
    add("")

    add("## 完整性检查")
    add("")
    if run["integrity_errors"]:
        for e in run["integrity_errors"]:
            add(f"- ❌ {e}")
    else:
        add("- ✅ 必需原始文件完整（plan/manifest/status/replay-plan/cases）")
    add("")

    add("## 验收状态记录（status.json）")
    add("")
    if not run["status_records"]:
        add("NOT_RUN（无 status.json 记录）")
    else:
        add("| ID | 状态 | 强制 | 说明 |")
        add("|---|---|---|---|")
        for tid, rec in sorted(run["status_records"].items()):
            add(f"| {tid} | {rec.get('status')} | {'是' if rec.get('mandatory', True) else '否'} | {rec.get('reason') or '-'} |")
    add("")

    add("## 分 profile 汇总（检测/处置分离，零分母 N/A）")
    add("")
    add("| Profile | 计划 | 执行 | 有效 | 缺失 | BLOCKED | NOT_RUN | 检测误报 | 拦截误报 | 检测漏报 | 拦截漏报 |")
    add("|---|---|---|---|---|---|---|---|---|---|---|")
    for pid in sorted(summary["profiles"]):
        b = summary["profiles"][pid]
        planned = b["planned"] if b["planned"] is not None else "?"
        missing = b["missing"] if b["missing"] is not None else "?"
        df = b["detection_false_positive"]
        bf = b["block_false_positive"]
        dm = b["detection_miss"]
        bm = b["block_miss"]
        add(
            f"| {pid} | {planned} | {b['executed']} | {b['valid']} | {missing} "
            f"| {b['blocked']} | {b['not_run']} "
            f"| {df['count']}/{df['denominator']} ({_fmt_rate(df['rate'])}) "
            f"| {bf['count']}/{bf['denominator']} ({_fmt_rate(bf['rate'])}) "
            f"| {dm['count']}/{dm['denominator']} ({_fmt_rate(dm['rate'])}) "
            f"| {bm['count']}/{bm['denominator']} ({_fmt_rate(bm['rate'])}) |"
        )
    add("")
    add("说明：分母=适用且实际执行有效且 truth≠UNKNOWN 的样本；OBSERVE 下正确放行攻击不计拦截漏报；"
        "UNKNOWN/deferred/执行无效均排除出分母并单列计数。")
    add("")

    add("## 逐例结果")
    add("")
    if not rows:
        add("无 cases.jsonl 记录")
    else:
        add("| case_id | profile | truth | criticality | partition | 状态 | 原因 |")
        add("|---|---|---|---|---|---|---|")
        for r in sorted(rows, key=lambda x: (x["case_id"], x["profile"])):
            reason = "；".join(r.get("reasons") or []) or "-"
            add(
                f"| {r['case_id']} | {r['profile']} | {r['truth']} | {r['criticality']} "
                f"| {r.get('dataset_partition', '-')} | {r['status']} | {reason} |"
            )
    add("")

    add("## 总判定")
    add("")
    add(f"**{verdict}**")
    for r in reasons:
        add(f"- {r}")
    add("")
    return "\n".join(lines)


def write_report(run_dir: str | Path) -> Path:
    run = load_regression_run(run_dir)
    text = render_markdown(run)
    out = Path(run_dir) / "report.md"
    tmp = out.with_suffix(".md.tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(out)
    return out
