"""确定性回放计划生成（P1-04 任务书 §4.3，seed 驱动）。

generate_plan 产出 kind=p1_replay_plan 的确定性文档：
- 同一 seed + 同一语料（按内容哈希绑定）在任何机器上产出字节一致的计划；
- profile 执行顺序与用例执行顺序由 seed 驱动的洗牌决定（防顺序依赖）；
- deferred 样本不进入计划；truth=UNKNOWN 样本进入计划但标记
  excluded_from_denominator=true，不进入准确率/检出率分母；
- 每条计划条目携带 case_version 与 content_sha256，回放与判定只接受
  与该哈希一致的语料内容（REG-002）；
- 重置描述为每 run_id 独立 Valkey 命名空间（p1reg:<run_id>:<case_id>:），
  只描述、不执行；任何全局重置动作（FLUSHALL/FLUSHDB/共享表）在此层即被拒绝。
"""

from __future__ import annotations

import hashlib
import json
import random

from .corpus import iter_active_cases
from .vocab import NA  # noqa: F401  （词表出口，供报告层统一引用）

PLAN_KIND = "p1_replay_plan"
VALKEY_NAMESPACE_TEMPLATE = "p1reg:{run_id}:{case_id}:"

# 分母口径随计划冻结，报告与 compare 不得自行改写
DENOMINATOR_POLICY = {
    "included": "满足适用范围（expectations 覆盖该 profile）且实际执行有效（executed=true 且 valid=true）",
    "excluded": ["truth=UNKNOWN", "deferred=true", "executed=false 或 valid=false"],
    "zero_denominator": NA,
}


def plan_reset_descriptor(case_id: str, run_id: str, reset_plan: dict) -> dict:
    """每 run_id 独立命名空间的重置描述（只描述，不执行）。"""
    actions = list((reset_plan or {}).get("actions") or ["none"])
    forbidden = [a for a in actions if "flushall" in a.lower() or "flushdb" in a.lower()]
    if forbidden:
        raise ValueError(f"非法全局重置动作 {forbidden}（case {case_id}）")
    tpl = (reset_plan or {}).get("valkey_prefix_template") or VALKEY_NAMESPACE_TEMPLATE
    return {
        "scope": (reset_plan or {}).get("scope", "case"),
        "actions": actions,
        "valkey_namespace": tpl.replace("{run_id}", run_id).replace("{case_id}", case_id),
        "forbidden_globally": ["FLUSHALL", "FLUSHDB", "drop_shared_tables", "reset_other_runs"],
    }


def generate_plan(corpus: dict, profiles, seed: int, run_id: str | None = None) -> dict:
    """由已校验语料生成确定性回放计划。run_id 缺省时为模板占位（干跑/预览）。"""
    if not isinstance(seed, int) or isinstance(seed, bool):
        raise ValueError("seed 必须为整数")
    profile_list = sorted(profiles)
    if not profile_list:
        raise ValueError("profiles 不能为空")
    rid = run_id or "{run_id}"

    active = [item for item in iter_active_cases(corpus)]
    rng = random.Random(seed)
    shuffled_profiles = list(profile_list)
    rng.shuffle(shuffled_profiles)

    entries: list[dict] = []
    for pid in shuffled_profiles:
        case_ids = [item["doc"]["case_id"] for item in active]
        rng.shuffle(case_ids)
        for cid in case_ids:
            item = corpus["cases"][cid]
            doc = item["doc"]
            truth = doc.get("truth")
            entries.append({
                "profile": pid,
                "case_id": cid,
                "case_version": doc.get("case_version"),
                "content_sha256": item["entry"].get("content_sha256"),
                "truth": truth,
                "criticality": doc.get("criticality"),
                "family": doc.get("family"),
                "dataset_partition": doc.get("dataset_partition"),
                "excluded_from_denominator": truth == "UNKNOWN",
                "step_count": len(doc.get("steps") or []),
                "seed": doc.get("seed"),
                "reset": plan_reset_descriptor(cid, rid, doc.get("reset_plan")),
            })

    return {
        "schema_version": 1,
        "kind": PLAN_KIND,
        "run_id": run_id,
        "seed": seed,
        "corpus": {
            "corpus_id": (corpus.get("manifest") or {}).get("corpus_id"),
            "manifest_sha256": corpus.get("manifest_sha256"),
        },
        "profiles": shuffled_profiles,
        "planned_counts": {pid: len(active) for pid in profile_list},
        "denominator_policy": DENOMINATOR_POLICY,
        "entries": entries,
    }


def plan_sha256(plan: dict) -> str:
    """计划的确定编码摘要（排序键、紧凑分隔符），用于证据绑定。"""
    blob = json.dumps(plan, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def planned_pairs(plan: dict) -> list[tuple[str, str]]:
    """(case_id, profile) 计划对列表（生成 cases.jsonl 骨架用）。"""
    return [(e["case_id"], e["profile"]) for e in plan.get("entries", [])]
