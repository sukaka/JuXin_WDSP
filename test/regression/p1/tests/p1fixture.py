"""测试共用夹具：构造最小合法 P1 语料、观测与回归证据目录。

本模块只构造纯本地合成夹具；不伪造网关响应冒充真实回放成功
（执行层测试仅覆盖 BLOCKED/目标拒绝等诚实路径）。
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

P1_DIR = Path(__file__).resolve().parents[1]
REPO_MANIFEST = P1_DIR / "corpus" / "manifest.json"
PROFILES_DIR = P1_DIR / "profiles"
RUN_PLAN_EXAMPLE = P1_DIR / "run-plan.example.json"

VALID_RUN_ID = "20260906T100000-aaaaaa"
VALID_RUN_ID_B = "20260906T110000-bbbbbb"


def minimal_case_doc(case_id: str = "WAF-BEN-TST-001", truth: str = "BENIGN", **over) -> dict:
    if truth == "BENIGN":
        exp = {
            "expected_detection": {"module": "none"},
            "expected_final_action": "PASS",
            "expected_origin": "reached",
        }
    else:
        exp = {
            "expected_detection": {"module": "coraza_crs", "rule_family": "sqli"},
            "expected_final_action": "BLOCK_403",
            "expected_origin": "not_reached",
        }
    doc = {
        "schema_version": 1,
        "case_id": case_id,
        "case_version": 1,
        "family": "waf",
        "tags": ["test"],
        "criticality": "STANDARD" if truth == "UNKNOWN" else "MANDATORY",
        "truth": truth,
        "truth_reason": "测试夹具人工核验依据",
        "source": "self_synthetic",
        "license": "test-license",
        "authorization": "test-authorization",
        "scope": {"capability": "waf.test"},
        "prerequisites": {"environment": ["isolated_stack"]},
        "steps": [
            {
                "step_id": "s1",
                "action": "http_request",
                "request": {"method": "GET", "path": "/t", "headers": {}},
                "wait": None,
                "assert": [{"type": "http_status_in", "statuses": [200]}],
            }
        ],
        "seed": 42,
        "reset_plan": {"scope": "none", "actions": ["none"]},
        "expectations_by_profile": {"OBSERVE": dict(exp), "PROTECT": dict(exp)},
        "evidence_requirements": {"access_log": True, "final_decision": True},
        "dataset_partition": "VALIDATION",
    }
    doc.update(over)
    return doc


def write_corpus(root: Path, docs: list, manifest_over: dict | None = None) -> Path:
    """把 case 文档写入 corpus/cases/ 并生成带正确 content_sha256 的 manifest。"""
    corpus_dir = root / "corpus"
    cases_dir = corpus_dir / "cases"
    cases_dir.mkdir(parents=True, exist_ok=True)
    entries = []
    for doc in docs:
        fname = doc["case_id"].lower() + ".json"
        p = cases_dir / fname
        p.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        entries.append({
            "case_id": doc["case_id"],
            "case_version": doc["case_version"],
            "file": f"cases/{fname}",
            "content_sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
        })
    manifest = {
        "schema_version": 1,
        "corpus_id": "test-corpus",
        "created_at": "2026-09-06T00:00:00Z",
        "description": "测试夹具语料",
        "cases": entries,
    }
    if manifest_over:
        manifest.update(manifest_over)
    mp = corpus_dir / "manifest.json"
    mp.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return mp


def load_repo_corpus():
    import sys

    sys.path.insert(0, str(P1_DIR))
    from p1reg import corpus as corpus_mod
    from p1reg.profiles import profile_ids

    return corpus_mod, corpus_mod.require_valid_corpus(REPO_MANIFEST, profile_ids(PROFILES_DIR))


def make_observation(case_doc: dict, profile: str, **over) -> dict:
    """构造与期望完全一致的观测（judge 应判 PASS）。"""
    exp = case_doc["expectations_by_profile"][profile]
    module = exp["expected_detection"]["module"]
    obs = {
        "executed": True,
        "valid": True,
        "execution_state": "COMPLETED",
        "detection": {
            "detected": module != "none",
            "module": None if module == "none" else module,
            "rule_family": exp["expected_detection"].get("rule_family"),
        },
        "observed_action": exp["expected_final_action"],
        "origin_reached": exp.get("expected_origin") == "reached",
        "assertions": [{"step_id": "s1", "type": "http_status_in", "met": True, "detail": "ok"}],
        "side_effects": None,
        "evidence_refs": ["test-ref"],
    }
    obs.update(over)
    return obs


def make_judge_row(case_doc: dict, profile: str, observation: dict | None):
    """用真实判定器产出 cases.jsonl 行（compare 测试输入不经手写伪造）。"""
    import sys

    sys.path.insert(0, str(P1_DIR))
    from p1reg.judge import judge_case

    return judge_case(case_doc, profile, observation)


def write_run_dir(root: Path, run_id: str, rows: list, status_records: dict | None = None,
                  with_replay_plan: bool = False, planned_counts: dict | None = None) -> Path:
    d = root / run_id
    d.mkdir(parents=True, exist_ok=True)
    (d / "plan.json").write_text(
        json.dumps({"kind": "p1_regression_run_plan"}, ensure_ascii=False) + "\n", encoding="utf-8")
    (d / "manifest.json").write_text(
        json.dumps({"run_id": run_id}, ensure_ascii=False) + "\n", encoding="utf-8")
    records = status_records
    if records is None:
        records = {"regression-execution": {"status": "PASS", "mandatory": True,
                                            "reason": "夹具", "evidence": ""}}
    (d / "status.json").write_text(
        json.dumps({"records": records}, ensure_ascii=False) + "\n", encoding="utf-8")
    with (d / "cases.jsonl").open("w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    if with_replay_plan:
        (d / "replay-plan.json").write_text(json.dumps({
            "schema_version": 1,
            "kind": "p1_replay_plan",
            "seed": 42,
            "corpus": {"corpus_id": "test-corpus", "manifest_sha256": "0" * 64},
            "planned_counts": planned_counts or {},
            "entries": [],
        }, ensure_ascii=False) + "\n", encoding="utf-8")
    return d
