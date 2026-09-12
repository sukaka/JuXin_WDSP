"""报告核心：只读 run 目录 → report.md（P0-02 任务书 §8，验收 BENCH-05/06/07）。

铁律：
- 只读已采集数据，不填入估计值冒充实测。
- 七模式全展示；缺失项显示 NOT_RUN/BLOCKED；未完成的 72 小时长稳不得用短测顶替。
- 分位数跨重复合并用原始样本连接后重算最近秩（或合并同 bin 直方图），禁止平均。
- 检测/处置指标分离，零分母显示 N/A。
- 任一强制用例 SKIP、原始文件缺失、语料哈希错误 → 总判定 NOT_PASSED（BENCH-07）。
"""

from __future__ import annotations

import json
from pathlib import Path

from .metrics import NA, compute_truth_metrics, merged_samples_quantile, nearest_rank_quantile
from .plan import JWT_PAIR_PROFILES, PROFILES, check_corpus_hash, load_plan, validate_plan

TEST_STATUSES = ("PASS", "FAIL", "SKIP", "BLOCKED", "NOT_RUN", "NOT_APPLICABLE")

REQUIRED_ARTIFACTS = ("plan.json", "manifest.json", "status.json")

# 报告展示 profile 全集：七模式主基线 + JWT-18 配对（后者仅在有数据/状态记录时渲染）
DISPLAY_PROFILES = PROFILES + JWT_PAIR_PROFILES


class ReportError(Exception):
    """run 目录结构不完整，无法生成报告。"""


def _resource_for_profile(run: dict, name: str) -> dict | None:
    """Combine container-memory and optional ``<profile>-rss`` evidence."""
    docs = [run["resources"].get(name), run["resources"].get(f"{name}-rss")]
    docs = [doc for doc in docs if doc is not None]
    if not docs:
        return None
    return {
        "container_mem_peak_bytes": max(
            (doc["container_mem_peak_bytes"] for doc in docs
             if doc["container_mem_peak_bytes"] is not None), default=None,
        ),
        "container_mem_sample_count": sum(doc["container_mem_sample_count"] for doc in docs),
        "rss_peak_bytes": max(
            (doc["rss_peak_bytes"] for doc in docs if doc["rss_peak_bytes"] is not None),
            default=None,
        ),
        "rss_sample_count": sum(doc["rss_sample_count"] for doc in docs),
        "memory_scope": "+".join(sorted({doc["memory_scope"] for doc in docs})),
    }


def _validate_longrun_contract(run: dict) -> None:
    """Reject PASS artifacts that omit the evidence needed for re-review."""
    for name, rec in run["soak"].items():
        if not isinstance(rec, dict):
            run["integrity_errors"].append(f"soak/{name}.json 必须是 JSON 对象")
            continue
        status = rec.get("status")
        if status not in TEST_STATUSES:
            run["integrity_errors"].append(f"soak/{name}.json 状态非法: {status!r}")
            continue
        if status == "BLOCKED" and not isinstance(rec.get("reason"), str):
            run["integrity_errors"].append(f"soak/{name}.json BLOCKED 缺 reason")
        if status != "PASS":
            continue
        duration = rec.get("duration_minutes")
        if not isinstance(duration, (int, float)) or isinstance(duration, bool) or duration <= 0:
            run["integrity_errors"].append(f"soak/{name}.json PASS 缺有效 duration_minutes")
        for field in ("started_at", "ended_at"):
            if not isinstance(rec.get(field), str) or not rec[field]:
                run["integrity_errors"].append(f"soak/{name}.json PASS 缺 {field}")
        resource = _resource_for_profile(run, name)
        if resource is None:
            run["integrity_errors"].append(f"soak/{name}.json PASS 缺同名资源报告")
        else:
            if resource["container_mem_sample_count"] <= 0:
                run["integrity_errors"].append(f"soak/{name}.json PASS 缺容器内存样本")
            if resource["rss_sample_count"] <= 0:
                run["integrity_errors"].append(f"soak/{name}.json PASS 缺进程 RSS 样本")

    recovery = run.get("recovery")
    if recovery is None:
        return
    if not isinstance(recovery, dict):
        run["integrity_errors"].append("recovery.json 必须是 JSON 对象")
        return
    status = recovery.get("status")
    if status not in TEST_STATUSES:
        run["integrity_errors"].append(f"recovery.json 状态非法: {status!r}")
        return
    if status == "BLOCKED" and not isinstance(recovery.get("reason"), str):
        run["integrity_errors"].append("recovery.json BLOCKED 缺 reason")
    if status == "BLOCKED":
        return
    for field in ("scenario", "fault_injected_at"):
        if not isinstance(recovery.get(field), str) or not recovery[field]:
            run["integrity_errors"].append(f"recovery.json 缺 {field}")
    elapsed = recovery.get("recovery_time_seconds")
    limit = recovery.get("limit_seconds")
    if not isinstance(elapsed, (int, float)) or isinstance(elapsed, bool) or elapsed < 0:
        run["integrity_errors"].append("recovery.json recovery_time_seconds 无效")
    if not isinstance(limit, (int, float)) or isinstance(limit, bool) or limit <= 0:
        run["integrity_errors"].append("recovery.json limit_seconds 无效")
    if status == "PASS":
        if not isinstance(recovery.get("gateway_healthy_at"), str) or not recovery["gateway_healthy_at"]:
            run["integrity_errors"].append("recovery.json PASS 缺 gateway_healthy_at")
        if recovery.get("catchup_verified") is not True:
            run["integrity_errors"].append("recovery.json PASS 缺 catchup_verified=true")
        if isinstance(elapsed, (int, float)) and isinstance(limit, (int, float)) and elapsed > limit:
            run["integrity_errors"].append("recovery.json PASS 但恢复时间超过 limit_seconds")
    elif status == "FAIL" and isinstance(elapsed, (int, float)) and isinstance(limit, (int, float)) and elapsed <= limit:
        run["integrity_errors"].append("recovery.json FAIL 但恢复时间未超过 limit_seconds")


def _load_json(path: Path):
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def load_run(run_dir: str | Path, repo_root: str | Path) -> dict:
    """装载 run 目录。任何必需文件缺失/损坏都记录进 integrity_errors，不静默。"""
    run_dir = Path(run_dir)
    run: dict = {
        "run_dir": str(run_dir),
        "integrity_errors": [],
        "plan": None,
        "manifest": None,
        "statuses": {},
        "truth_metrics": {},
        "perf": {},
        "resources": {},
        "reconciliation": None,
        "soak": {},
        "recovery": None,
    }
    if not run_dir.is_dir():
        raise ReportError(f"run 目录不存在: {run_dir}")

    for name in REQUIRED_ARTIFACTS:
        if not (run_dir / name).is_file():
            run["integrity_errors"].append(f"原始文件缺失: {name}")

    plan_path = run_dir / "plan.json"
    if plan_path.is_file():
        try:
            run["plan"] = _load_json(plan_path)
        except json.JSONDecodeError as exc:
            run["integrity_errors"].append(f"plan.json 不是合法 JSON: {exc}")
        else:
            for err in validate_plan(run["plan"]):
                run["integrity_errors"].append(f"plan.json 校验失败: {err}")
            corpus_err = check_corpus_hash(run["plan"], repo_root)
            if corpus_err:
                run["integrity_errors"].append(corpus_err)

    manifest_path = run_dir / "manifest.json"
    if manifest_path.is_file():
        try:
            run["manifest"] = _load_json(manifest_path)
        except json.JSONDecodeError as exc:
            run["integrity_errors"].append(f"manifest.json 不是合法 JSON: {exc}")

    status_path = run_dir / "status.json"
    if status_path.is_file():
        try:
            raw = _load_json(status_path)
        except json.JSONDecodeError as exc:
            run["integrity_errors"].append(f"status.json 不是合法 JSON: {exc}")
        else:
            records = raw.get("records", {}) if isinstance(raw, dict) else {}
            for tid, rec in records.items():
                status = rec.get("status") if isinstance(rec, dict) else None
                if status not in TEST_STATUSES:
                    run["integrity_errors"].append(f"status.json: {tid} 状态非法: {status!r}")
                    continue
                run["statuses"][tid] = {
                    "status": status,
                    "mandatory": bool(rec.get("mandatory", True)),
                    "reason": rec.get("reason", ""),
                    "evidence": rec.get("evidence", ""),
                }

    truth_dir = run_dir / "truth"
    for profile in DISPLAY_PROFILES:
        tp = truth_dir / f"{profile}.json"
        if not tp.is_file():
            continue
        try:
            cases = _load_json(tp)
            run["truth_metrics"][profile] = compute_truth_metrics(cases, profile)
        except (json.JSONDecodeError, ValueError) as exc:
            run["integrity_errors"].append(f"truth/{profile}.json 解析失败: {exc}")

    perf_dir = run_dir / "perf"
    for profile in DISPLAY_PROFILES:
        pdir = perf_dir / profile
        if not pdir.is_dir():
            continue
        points = []
        for f in sorted(pdir.glob("*.json")):
            try:
                rec = _load_json(f)
            except json.JSONDecodeError as exc:
                run["integrity_errors"].append(f"perf/{profile}/{f.name} 解析失败: {exc}")
                continue
            points.append(rec)
        if points:
            run["perf"][profile] = aggregate_perf(points)

    recon_path = run_dir / "reconciliation.json"
    if recon_path.is_file():
        try:
            doc = _load_json(recon_path)
            # collect.py 写 {"reconciliation": {...}, "catchup_complete": ..., "permanent_loss": ...}
            if isinstance(doc, dict) and isinstance(doc.get("reconciliation"), dict):
                run["reconciliation"] = doc["reconciliation"]
                run["reconciliation_meta"] = {
                    "catchup_complete": doc.get("catchup_complete"),
                    "permanent_loss": doc.get("permanent_loss"),
                }
            else:
                run["reconciliation"] = doc
        except json.JSONDecodeError as exc:
            run["integrity_errors"].append(f"reconciliation.json 解析失败: {exc}")

    resources_dir = run_dir / "resources"
    if resources_dir.is_dir():
        for f in sorted(resources_dir.glob("*.json")):
            try:
                resource_doc = _load_json(f)
            except json.JSONDecodeError as exc:
                run["integrity_errors"].append(f"resources/{f.name} 解析失败: {exc}")
                continue
            records = resource_doc.get("records") if isinstance(resource_doc, dict) else None
            if not isinstance(records, list):
                run["integrity_errors"].append(f"resources/{f.name} 缺少 records 数组")
                continue
            memory = [r.get("mem_usage_bytes") for r in records
                      if isinstance(r, dict) and isinstance(r.get("mem_usage_bytes"), (int, float))]
            rss = [r.get("rss_bytes") for r in records
                   if isinstance(r, dict) and isinstance(r.get("rss_bytes"), (int, float))]
            run["resources"][f.stem] = {
                "source": resource_doc.get("source", "unknown"),
                "sample_count": len(records),
                "container_mem_peak_bytes": max(memory) if memory else None,
                "container_mem_sample_count": len(memory),
                "rss_peak_bytes": max(rss) if rss else None,
                "rss_sample_count": len(rss),
                "memory_scope": "container_memory" if memory and not rss else (
                    "process_rss" if rss and not memory else "container_memory+process_rss"
                    if memory and rss else "unknown"
                ),
                "platform_note": resource_doc.get("platform_note", ""),
            }

    soak_dir = run_dir / "soak"
    if soak_dir.is_dir():
        for f in sorted(soak_dir.glob("*.json")):
            try:
                run["soak"][f.stem] = _load_json(f)
            except json.JSONDecodeError as exc:
                run["integrity_errors"].append(f"soak/{f.name} 解析失败: {exc}")

    recovery_path = run_dir / "recovery.json"
    if recovery_path.is_file():
        try:
            run["recovery"] = _load_json(recovery_path)
        except json.JSONDecodeError as exc:
            run["integrity_errors"].append(f"recovery.json 解析失败: {exc}")

    _validate_longrun_contract(run)

    return run


def aggregate_perf(points: list[dict]) -> dict:
    """聚合同一 profile 的多次重复/负载点。

    分位数：连接各点原始延迟样本后重算最近秩；没有原始样本只有直方图时
    合并同 bin 直方图（merge_histograms 会拒绝 bin 不一致）。两者都缺则 N/A。
    """
    sample_groups = [p.get("latency_ms_samples") or [] for p in points]
    offered = sum(int(p.get("offered") or 0) for p in points)
    completed = sum(int(p.get("completed") or 0) for p in points)
    error_classes: dict[str, int] = {}
    for p in points:
        for cls, n in (p.get("error_classes") or {}).items():
            error_classes[cls] = error_classes.get(cls, 0) + int(n)
    unexpected = error_classes.get("unexpected_error", 0)
    unexpected_rate = (unexpected / completed) if completed else NA
    throughput_samples = [
        float(p["requests_per_second"])
        for p in points
        if isinstance(p.get("requests_per_second"), (int, float)) and p["requests_per_second"] >= 0
    ]
    throughput_sources = sorted({
        str((p.get("throughput_evidence") or {}).get("source"))
        for p in points
        if (p.get("throughput_evidence") or {}).get("source")
    })
    throughput_scopes = {
        str((p.get("throughput_evidence") or {}).get("scope"))
        for p in points
        if (p.get("throughput_evidence") or {}).get("scope")
    }
    end_to_end_throughput = (
        bool(throughput_sources)
        and "end_to_end_loadgen" in throughput_scopes
    )

    def q(quantile):
        if any(sample_groups):
            v = merged_samples_quantile(sample_groups, quantile)
            return v
        hists = [p["latency_histogram"] for p in points if p.get("latency_histogram")]
        if len(hists) == len(points) and hists:
            from .metrics import merge_histograms, histogram_quantile

            return histogram_quantile(merge_histograms(hists), quantile)
        return None

    return {
        "repeats": len(points),
        "offered": offered,
        "completed": completed,
        "p50_ms": q(0.50),
        "p95_ms": q(0.95),
        "p99_ms": q(0.99),
        "throughput_rps": (
            {"p50": nearest_rank_quantile(throughput_samples, 0.50),
             "p95": nearest_rank_quantile(throughput_samples, 0.95),
             "p99": nearest_rank_quantile(throughput_samples, 0.99)}
            if throughput_samples else None
        ),
        "throughput_evidence": {
            "status": "MEASURED" if throughput_samples else "NOT_AVAILABLE",
            "scope": "end_to_end_loadgen" if end_to_end_throughput else "unknown",
            "sample_count": len(throughput_samples),
            "sources": throughput_sources,
        },
        "error_classes": error_classes,
        "unexpected_error_rate": unexpected_rate,
    }


def overall_verdict(run: dict) -> tuple[str, list[str]]:
    """总判定。BENCH-07：SKIP/缺文件/哈希错误一律未通过。"""
    reasons: list[str] = []
    if run["integrity_errors"]:
        reasons.extend(f"完整性: {e}" for e in run["integrity_errors"])
    if not run["statuses"]:
        reasons.append("无任何验收状态记录")
    for tid, rec in sorted(run["statuses"].items()):
        if rec["status"] == "FAIL":
            reasons.append(f"{tid}: FAIL（{rec['reason']}）")
        elif rec["mandatory"] and rec["status"] in ("SKIP", "BLOCKED", "NOT_RUN"):
            reasons.append(f"{tid}: 强制用例未通过（{rec['status']}：{rec['reason']}）")
    if any(rec["status"] == "FAIL" for rec in run["statuses"].values()):
        return "FAIL", reasons
    if reasons:
        return "NOT_PASSED", reasons
    return "PASS", reasons


def _fmt_ms(v) -> str:
    if v is None:
        return "N/A"
    return f"{v:.2f}"


def _fmt_rate(v) -> str:
    if v == NA:
        return NA
    return f"{v * 100:.3f}%"


def _render_profiles(run: dict) -> tuple:
    """报告展示的 profile 序列：七模式主基线全展示（缺失显示 NOT_RUN/BLOCKED）；
    JWT-18 配对 profile（jwt_off/jwt_protect）仅在本 run 有数据或状态记录时追加，
    未声明 jwt_pair 的运行报告保持纯七模式。"""
    out = list(PROFILES)
    for p in JWT_PAIR_PROFILES:
        if (
            p in run["truth_metrics"]
            or p in run["perf"]
            or f"correctness:{p}" in run["statuses"]
            or f"matrix:{p}" in run["statuses"]
            or f"soak:{p}" in run["statuses"]
        ):
            out.append(p)
    return tuple(out)


def render_markdown(run: dict) -> str:
    plan = run.get("plan") or {}
    manifest = run.get("manifest") or {}
    verdict, reasons = overall_verdict(run)
    profiles = _render_profiles(run)
    pair_shown = any(p in JWT_PAIR_PROFILES for p in profiles)
    lines: list[str] = []
    add = lines.append

    add("# P0-02 同配置安全与性能基准报告")
    add("")
    add(f"- run 目录: `{run['run_dir']}`")
    add(f"- run_id: `{manifest.get('run_id', '未知')}`")
    add(f"- plan_id: `{plan.get('plan_id', '未知')}` / purpose: `{plan.get('purpose', '未知')}`")
    env = plan.get("environment") or {}
    add(f"- 环境标识: `{env.get('environment_id', '未知')}`")
    build = plan.get("build") or {}
    add(
        f"- 构建: `{build.get('git_commit', '未知')}`"
        f"（worktree_dirty={build.get('worktree_dirty', '未知')}）"
    )
    lg = (plan.get("load") or {}).get("loadgen") or {}
    add(f"- 压测器: `{lg.get('tool', '?')}` 登记版本 `{lg.get('version', '?')}`；"
        f"运行采集版本见 manifest（loadgen_versions）")
    add("")

    add("## 完整性检查")
    add("")
    if run["integrity_errors"]:
        for e in run["integrity_errors"]:
            add(f"- ❌ {e}")
    else:
        add("- ✅ 计划、语料哈希与必需原始文件完整")
    add("")

    add("## 七模式性能矩阵")
    add("")
    add("| Profile | 重复数 | offered | completed | P50(ms) | P95(ms) | P99(ms) | 吞吐P50/P95/P99(RPS) | 预期403/429 | 非预期错误率 |")
    add("|---|---|---|---|---|---|---|---|---|---|")
    for profile in profiles:
        perf = run["perf"].get(profile)
        if perf is None:
            status = "NOT_RUN"
            st = run["statuses"].get(f"matrix:{profile}")
            st = st or run["statuses"].get("matrix:formal_environment")
            if st and st["status"] == "BLOCKED":
                status = "BLOCKED"
            add(f"| {profile} | {status} | - | - | - | - | - | - | - | - |")
            continue
        sec = perf["error_classes"].get("expected_security", 0)
        throughput = perf.get("throughput_rps")
        throughput_text = (
            f"{throughput['p50']:.2f}/{throughput['p95']:.2f}/{throughput['p99']:.2f}"
            if throughput else "N/A"
        )
        add(
            f"| {profile} | {perf['repeats']} | {perf['offered']} | {perf['completed']} "
            f"| {_fmt_ms(perf['p50_ms'])} | {_fmt_ms(perf['p95_ms'])} | {_fmt_ms(perf['p99_ms'])} "
            f"| {throughput_text} | {sec} | {_fmt_rate(perf['unexpected_error_rate'])} |"
        )
    add("")
    add("说明：分位数为各重复原始样本连接后的最近秩重算（或同 bin 直方图合并），不做跨运行平均；"
        "闭环并发工具（ab）的结果不伪称固定到达率。")
    measured_sources = sorted({
        source
        for perf in run["perf"].values()
        for source in (perf.get("throughput_evidence") or {}).get("sources", [])
    })
    add("吞吐证据：end_to_end_loadgen 的压测器 requests_per_second 样本"
        + (f"（来源 {', '.join(measured_sources)}）。" if measured_sources else "（当前无可用样本）。"))
    if pair_shown:
        add("jwt_off/jwt_protect 为 JWT-18 配对 profile（同构建同基础配置，仅 JWT 信任链 "
            "OFF vs PROTECT 静态 JWKS），不属于七模式主基线；与无 JWT 旧结果对比时不得直接归因代码回归。")
    add("")

    add("## 安全正确性（检测/处置分离，BENCH-05）")
    add("")
    add("| Profile | 检测误报 | 拦截误报 | 检测漏报 | 拦截漏报 | TP/FP/TN/FN | 断言不符样本 |")
    add("|---|---|---|---|---|---|---|")
    for profile in profiles:
        tm = run["truth_metrics"].get(profile)
        if tm is None:
            status = "NOT_RUN"
            st = run["statuses"].get(f"correctness:{profile}")
            if st and st["status"] == "BLOCKED":
                status = "BLOCKED"
            add(f"| {profile} | {status} | - | - | - | - | - |")
            continue
        c = tm["confusion"]
        add(
            f"| {profile} "
            f"| {tm['detection_false_positive']['count']}/{tm['detection_false_positive']['denominator']} ({_fmt_rate(tm['detection_false_positive']['rate'])}) "
            f"| {tm['block_false_positive']['count']}/{tm['block_false_positive']['denominator']} ({_fmt_rate(tm['block_false_positive']['rate'])}) "
            f"| {tm['detection_miss']['count']}/{tm['detection_miss']['denominator']} ({_fmt_rate(tm['detection_miss']['rate'])}) "
            f"| {tm['block_miss']['count']}/{tm['block_miss']['denominator']} ({_fmt_rate(tm['block_miss']['rate'])}) "
            f"| {c['TP']}/{c['FP']}/{c['TN']}/{c['FN']} "
            f"| {len(tm['mismatches'])} |"
        )
    add("")
    add("说明：检测与处置分开计算；零分母显示 N/A；OBSERVE 下正确放行攻击不计拦截漏报。")
    if pair_shown:
        add("JWT 配对轮次中 A-JWT-01（篡改签名）在 jwt_protect 下期望 BLOCK_401"
            "（JWT_AUTH_FAILED 事件落 access_control_events），jwt_off 下期望 PASS；"
            "七模式基线（JWT 关闭）下该样本期望 PASS，不构成漏报。")
    add("")

    add("## 事件可见性与完整性对账（§6.2）")
    add("")
    recon = run.get("reconciliation")
    if recon is None:
        add("NOT_RUN（无 reconciliation.json）")
    else:
        add("| eligible | generated | persisted_unique | duplicated | pending | dropped | unknown | foreign |")
        add("|---|---|---|---|---|---|---|---|")
        foreign = recon.get("foreign_generated", 0) + recon.get("foreign_persisted", 0)
        add(
            f"| {recon.get('eligible', 0)} | {recon.get('generated', 0)} "
            f"| {recon.get('persisted_unique', 0)} | {recon.get('duplicated', 0)} "
            f"| {recon.get('pending', 0)} | {recon.get('dropped', 0)} "
            f"| {recon.get('unknown', 0)} | {foreign} |"
        )
        meta = run.get("reconciliation_meta") or {}
        loss = meta.get("permanent_loss")
        loss_str = "不可判定（恢复追平未完成）" if loss is None else str(loss)
        add(f"\n追平完成: {meta.get('catchup_complete')}；永久丢失: {loss_str}")
    add("")

    add("## 长稳与恢复（§6.3）")
    add("")
    if not run["soak"]:
        st = run["statuses"].get("soak:formal_environment")
        if st and st["status"] == "BLOCKED":
            add(f"- 长稳: BLOCKED（{st['reason'] or '正式环境不可用'}）")
        else:
            add("- 长稳: NOT_RUN（无 soak/ 记录；72 小时 combined_protect 不得以短测顶替）")
    else:
        for name, rec in sorted(run["soak"].items()):
            resource = _resource_for_profile(run, name)
            if resource and resource["container_mem_peak_bytes"] is not None:
                memory_text = f"；容器内存峰值 {resource['container_mem_peak_bytes']:.0f} bytes"
            else:
                memory_text = "；容器内存峰值 N/A"
            if resource and resource["rss_peak_bytes"] is not None:
                memory_text += f"；进程 RSS 峰值 {resource['rss_peak_bytes']:.0f} bytes"
            add(f"- 长稳 {name}: {rec.get('status', '未知')}"
                f"（时长 {rec.get('duration_minutes', '?')} 分钟{memory_text}）")
    if run.get("recovery") is None:
        st = run["statuses"].get("recovery:formal_environment")
        if st and st["status"] == "BLOCKED":
            add(f"- 恢复: BLOCKED（{st['reason'] or '正式环境不可用'}）")
        else:
            add("- 恢复: NOT_RUN（无 recovery.json）")
    else:
        rec = run["recovery"]
        add(f"- 恢复: {rec.get('status', '未知')}"
            f"（恢复时间 {rec.get('recovery_time_seconds', '?')}s）")
    add("")

    add("## 验收状态")
    add("")
    if not run["statuses"]:
        add("NOT_RUN（无 status.json 记录）")
    else:
        add("| ID | 状态 | 强制 | 说明 |")
        add("|---|---|---|---|")
        for tid, rec in sorted(run["statuses"].items()):
            add(
                f"| {tid} | {rec['status']} | {'是' if rec['mandatory'] else '否'} "
                f"| {rec['reason'] or '-'} |"
            )
    add("")

    add("## 总判定")
    add("")
    add(f"**{verdict}**")
    for r in reasons:
        add(f"- {r}")
    add("")
    return "\n".join(lines)


def write_report(run_dir: str | Path, repo_root: str | Path) -> Path:
    run = load_run(run_dir, repo_root)
    text = render_markdown(run)
    out = Path(run_dir) / "report.md"
    tmp = out.with_suffix(".md.tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(out)
    return out
