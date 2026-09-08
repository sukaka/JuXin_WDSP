"""真实隔离栈执行器（P1-04 R2）：回放计划 → 适配器执行 → 事件对账 → 逐例判定。

输入：冻结的 replay-plan.json（seed 驱动顺序）、语料 manifest（内容哈希绑定）、
环境描述符（stack-up.sh 写出的 p1reg_stage5_env JSON，0600，含管理面只读凭据——
凭据只用于内存中的 API 查询，绝不写入证据目录）。

输出（写 run 目录）：
- cases.jsonl      逐例判定结果（覆盖 init-cases 骨架；judge 输出行 + 对账/性能摘要）
- perf.jsonl       逐请求性能原始分布（status/latency_ms/origin_reached）
- execution-summary.json  执行计数与逐 profile 状态分布
- env-summary.json 环境非敏感摘要（主机/应用/规则族映射；不含任何凭据）

退出语义由 CLI 层解释：0=全部执行并判定完成且无 FAIL；1=存在 FAIL；
3=执行不完整（BLOCKED/NOT_RUN/执行无效）；2=结构错误。任何单例异常不静默：
记录为该例 FAIL（EXECUTION_ERROR）并继续，汇总时计入不完整。
"""

from __future__ import annotations

import json
from pathlib import Path

from p0bench.plan import sha256_file

from . import reconcile as reconcile_mod
from .corpus import require_valid_corpus
from .judge import judge_case
from .profiles import profile_ids
from .replayplan import PLAN_KIND

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from adapters.http_replay import AdapterError, HttpReplayAdapter  # noqa: E402


class ExecutorError(Exception):
    """执行器结构错误（描述符非法、计划不符等）。"""


def load_env_descriptor(path: str | Path) -> dict:
    p = Path(path)
    if not p.is_file():
        raise ExecutorError(f"环境描述符不存在: {p}")
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ExecutorError(f"环境描述符不是合法 JSON: {exc}") from exc
    if not isinstance(doc, dict) or doc.get("kind") != "p1reg_stage5_env":
        raise ExecutorError("环境描述符 kind 必须为 p1reg_stage5_env")
    for key in ("api_url", "sec_cookie", "origin_mark", "profiles"):
        if key not in doc:
            raise ExecutorError(f"环境描述符缺字段 {key}")
    if not isinstance(doc["profiles"], dict) or not doc["profiles"]:
        raise ExecutorError("环境描述符 profiles 必须为非空对象")
    return doc


def env_public_summary(desc: dict) -> dict:
    """非敏感环境摘要（可入证据；绝不含 sec_cookie/CSRF/密钥）。"""
    return {
        "kind": desc.get("kind"),
        "api_url": desc.get("api_url"),
        "origin_mark": desc.get("origin_mark"),
        "gateway_scheme": desc.get("gateway_scheme", "https"),
        "profiles": {
            pid: {"host": p.get("host"), "app_id": p.get("app_id"), "app_code": p.get("app_code")}
            for pid, p in (desc.get("profiles") or {}).items()
        },
        "custom_rule_families": desc.get("custom_rule_families") or {},
        "allowed_targets": desc.get("allowed_targets") or [],
        "stack": desc.get("stack") or {},
    }


def execute_run(replay_plan_path: str | Path, manifest_path: str | Path,
                profiles_dir: str | Path, env_path: str | Path,
                run_dir: str | Path, run_id: str) -> dict:
    """执行整个回放计划。返回执行汇总（同时写出 cases.jsonl/perf.jsonl 等）。"""
    run_dir = Path(run_dir)
    plan = json.loads(Path(replay_plan_path).read_text(encoding="utf-8"))
    if plan.get("kind") != PLAN_KIND:
        raise ExecutorError("replay-plan kind 非法")
    if plan.get("run_id") != run_id:
        raise ExecutorError(f"replay-plan run_id={plan.get('run_id')!r} 与运行 {run_id!r} 不一致")
    known = profile_ids(profiles_dir)
    corpus = require_valid_corpus(manifest_path, known)
    if (plan.get("corpus") or {}).get("manifest_sha256") != corpus.get("manifest_sha256"):
        raise ExecutorError("replay-plan 语料哈希与 manifest 实际不一致，拒绝执行")
    desc = load_env_descriptor(env_path)

    client = reconcile_mod.ApiClient(desc["api_url"], desc["sec_cookie"])
    allowed = set(desc.get("allowed_targets") or [])
    scheme = desc.get("gateway_scheme", "https")
    custom_families = desc.get("custom_rule_families") or {}

    adapters: dict[str, HttpReplayAdapter] = {}
    for pid in plan.get("profiles") or []:
        pconf = (desc.get("profiles") or {}).get(pid)
        if not pconf:
            raise ExecutorError(f"环境描述符缺 profile {pid} 的接入配置")
        port = pconf.get("port")
        base = f"{scheme}://{pconf['host']}" + (f":{port}" if port else "")
        adapters[pid] = HttpReplayAdapter(
            allowed_targets=allowed,
            environment={
                "base_url": base,
                "resolve_to": desc.get("resolve_to"),
                "origin_mark": desc.get("origin_mark"),
                "ua_run_marker": f"p1reg/{run_id}",
            })

    rows: list[dict] = []
    perf_rows: list[dict] = []
    counts = {"PASS": 0, "FAIL": 0, "BLOCKED": 0, "NOT_RUN": 0, "SKIP": 0, "NOT_APPLICABLE": 0}
    incomplete = 0

    for entry in plan.get("entries", []):
        cid, pid = entry["case_id"], entry["profile"]
        item = corpus["cases"].get(cid)
        if item is None:
            raise ExecutorError(f"计划引用语料外 case {cid}")
        doc = item["doc"]
        adapter = adapters.get(pid)
        try:
            obs = adapter.execute_case(doc, pid, run_id)
            obs = reconcile_mod.reconcile_case(client, doc, obs, custom_families)
        except AdapterError as exc:
            obs = {"executed": False, "valid": False, "execution_state": "ERROR",
                   "blocked_reason": None, "assertions": None,
                   "evidence_refs": [], "perf": [], "abort_reason": f"适配器错误: {exc}"}
        except reconcile_mod.ReconcileError as exc:
            # 对账通道故障：该例已执行部分如实保留，状态 ERROR 不转通过
            obs = {**obs, "valid": False, "execution_state": "ERROR",
                   "abort_reason": f"对账失败: {exc}"}
        except Exception as exc:  # 不静默：记为该例 FAIL 并继续
            obs = {"executed": False, "valid": False, "execution_state": "ERROR",
                   "assertions": None, "evidence_refs": [], "perf": [],
                   "abort_reason": f"执行器异常: {type(exc).__name__}: {exc}"}

        result = judge_case(doc, pid, obs)
        detail = result.setdefault("detail", {})
        if obs.get("reconciliation"):
            detail["reconciliation"] = obs["reconciliation"]
        if obs.get("abort_reason"):
            detail["abort_reason"] = obs["abort_reason"]
        if obs.get("http"):
            detail["http"] = obs["http"]
        rows.append(result)
        counts[result["status"]] = counts.get(result["status"], 0) + 1
        if result["status"] in ("BLOCKED", "NOT_RUN") or (result.get("executed") and not result.get("valid")):
            incomplete += 1
        for p in obs.get("perf") or []:
            perf_rows.append({
                "run_id": run_id, "case_id": cid, "profile": pid,
                "family": doc.get("family"), "truth": doc.get("truth"),
                **p,
            })

    with (run_dir / "cases.jsonl").open("w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    with (run_dir / "perf.jsonl").open("w", encoding="utf-8") as fh:
        for p in perf_rows:
            fh.write(json.dumps(p, ensure_ascii=False) + "\n")

    status_counts: dict[str, dict[str, int]] = {}
    for p in perf_rows:
        b = status_counts.setdefault(p["profile"], {})
        key = str(p.get("status"))
        b[key] = b.get(key, 0) + 1
    summary = {
        "run_id": run_id,
        "kind": "p1_regression_execution",
        "planned": len(plan.get("entries", [])),
        "executed_cases": sum(1 for r in rows if r.get("executed")),
        "status_counts": counts,
        "incomplete": incomplete,
        "http_requests": len(perf_rows),
        "status_distribution_by_profile": status_counts,
        "cases_sha256": sha256_file(run_dir / "cases.jsonl"),
        "perf_sha256": sha256_file(run_dir / "perf.jsonl"),
        "env_descriptor_sha256": sha256_file(env_path),
    }
    with (run_dir / "execution-summary.json").open("w", encoding="utf-8") as fh:
        json.dump(summary, fh, ensure_ascii=False, indent=2, sort_keys=True)
        fh.write("\n")
    with (run_dir / "env-summary.json").open("w", encoding="utf-8") as fh:
        json.dump(env_public_summary(desc), fh, ensure_ascii=False, indent=2, sort_keys=True)
        fh.write("\n")
    return summary
