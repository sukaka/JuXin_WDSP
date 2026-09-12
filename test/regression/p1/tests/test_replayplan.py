"""确定性回放计划生成测试（seed 驱动、哈希绑定、deferred/UNKNOWN 口径、重置命名空间）。"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
P1_DIR = TESTS_DIR.parents[0]
for p in (str(TESTS_DIR), str(P1_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

import p1fixture  # noqa: E402
from p1reg import corpus as corpus_mod  # noqa: E402
from p1reg import replayplan  # noqa: E402
from p1reg.profiles import profile_ids  # noqa: E402

PROFILES = ("OBSERVE", "PROTECT")


class PlanFixture(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.root = Path(self._td.name)
        self.docs = [
            p1fixture.minimal_case_doc("WAF-BEN-TST-001", "BENIGN"),
            p1fixture.minimal_case_doc("WAF-ATK-TST-001", "ATTACK"),
            p1fixture.minimal_case_doc("WAF-UNK-TST-001", "UNKNOWN"),
            p1fixture.minimal_case_doc("WAF-ATK-TST-002", "ATTACK",
                                       deferred=True, deferred_reason="依赖未交付",
                                       criticality="STANDARD"),
        ]
        mp = p1fixture.write_corpus(self.root, self.docs)
        self.corpus = corpus_mod.require_valid_corpus(mp, PROFILES)


class TestReplayPlanDeterminism(PlanFixture):
    def test_same_seed_identical_bytes(self):
        a = replayplan.generate_plan(self.corpus, PROFILES, seed=7, run_id=p1fixture.VALID_RUN_ID)
        b = replayplan.generate_plan(self.corpus, PROFILES, seed=7, run_id=p1fixture.VALID_RUN_ID)
        self.assertEqual(
            json.dumps(a, sort_keys=True, ensure_ascii=False),
            json.dumps(b, sort_keys=True, ensure_ascii=False),
        )
        self.assertEqual(replayplan.plan_sha256(a), replayplan.plan_sha256(b))

    def test_different_seed_shuffles_order(self):
        a = replayplan.generate_plan(self.corpus, PROFILES, seed=1, run_id=p1fixture.VALID_RUN_ID)
        b = replayplan.generate_plan(self.corpus, PROFILES, seed=999983, run_id=p1fixture.VALID_RUN_ID)
        seq_a = [(e["profile"], e["case_id"]) for e in a["entries"]]
        seq_b = [(e["profile"], e["case_id"]) for e in b["entries"]]
        self.assertEqual(sorted(seq_a), sorted(seq_b), "同一语料计划集合必须一致")
        # 18+ 条随机排列在两个不同 seed 下完全相同的概率可忽略；若偶发失败请换 seed 复验
        repo_corpus = corpus_mod.require_valid_corpus(
            p1fixture.REPO_MANIFEST, profile_ids(p1fixture.PROFILES_DIR))
        ra = replayplan.generate_plan(repo_corpus, PROFILES, seed=1)
        rb = replayplan.generate_plan(repo_corpus, PROFILES, seed=999983)
        self.assertNotEqual(
            [(e["profile"], e["case_id"]) for e in ra["entries"]],
            [(e["profile"], e["case_id"]) for e in rb["entries"]],
        )

    def test_run_id_changes_namespaces_but_not_order(self):
        a = replayplan.generate_plan(self.corpus, PROFILES, seed=7, run_id=p1fixture.VALID_RUN_ID)
        b = replayplan.generate_plan(self.corpus, PROFILES, seed=7, run_id=p1fixture.VALID_RUN_ID_B)
        seq_a = [(e["profile"], e["case_id"]) for e in a["entries"]]
        seq_b = [(e["profile"], e["case_id"]) for e in b["entries"]]
        self.assertEqual(seq_a, seq_b, "run_id 不影响执行顺序")
        ns_a = {e["reset"]["valkey_namespace"] for e in a["entries"]}
        ns_b = {e["reset"]["valkey_namespace"] for e in b["entries"]}
        self.assertTrue(ns_a.isdisjoint(ns_b), "不同 run_id 的 Valkey 命名空间必须隔离")


class TestReplayPlanDenominator(PlanFixture):
    def test_deferred_excluded_from_plan(self):
        plan = replayplan.generate_plan(self.corpus, PROFILES, seed=7)
        ids = {e["case_id"] for e in plan["entries"]}
        self.assertNotIn("WAF-ATK-TST-002", ids)

    def test_unknown_in_plan_but_excluded_from_denominator(self):
        plan = replayplan.generate_plan(self.corpus, PROFILES, seed=7)
        unk = [e for e in plan["entries"] if e["case_id"] == "WAF-UNK-TST-001"]
        self.assertEqual(len(unk), len(PROFILES))
        for e in unk:
            self.assertTrue(e["excluded_from_denominator"])
        for e in plan["entries"]:
            if e["case_id"] != "WAF-UNK-TST-001":
                self.assertFalse(e["excluded_from_denominator"])

    def test_planned_counts(self):
        plan = replayplan.generate_plan(self.corpus, PROFILES, seed=7)
        self.assertEqual(plan["planned_counts"], {"OBSERVE": 3, "PROTECT": 3})

    def test_entries_bind_case_hashes(self):
        plan = replayplan.generate_plan(self.corpus, PROFILES, seed=7)
        for e in plan["entries"]:
            item = self.corpus["cases"][e["case_id"]]
            self.assertEqual(e["content_sha256"], item["entry"]["content_sha256"])
            self.assertEqual(e["case_version"], item["doc"]["case_version"])

    def test_reset_descriptor_carries_run_and_case(self):
        plan = replayplan.generate_plan(self.corpus, PROFILES, seed=7, run_id=p1fixture.VALID_RUN_ID)
        for e in plan["entries"]:
            ns = e["reset"]["valkey_namespace"]
            self.assertIn(p1fixture.VALID_RUN_ID, ns)
            self.assertIn(e["case_id"], ns)
            self.assertIn("FLUSHALL", e["reset"]["forbidden_globally"])

    def test_invalid_seed_rejected(self):
        with self.assertRaises(ValueError):
            replayplan.generate_plan(self.corpus, PROFILES, seed="7")
        with self.assertRaises(ValueError):
            replayplan.generate_plan(self.corpus, PROFILES, seed=True)

    def test_empty_profiles_rejected(self):
        with self.assertRaises(ValueError):
            replayplan.generate_plan(self.corpus, [], seed=7)

    def test_planned_pairs_count(self):
        plan = replayplan.generate_plan(self.corpus, PROFILES, seed=7)
        self.assertEqual(len(replayplan.planned_pairs(plan)), 3 * len(PROFILES))


class TestRepoPlanShape(unittest.TestCase):
    def test_repo_plan_has_48_entries(self):
        repo_corpus = corpus_mod.require_valid_corpus(
            p1fixture.REPO_MANIFEST, profile_ids(p1fixture.PROFILES_DIR))
        plan = replayplan.generate_plan(repo_corpus, PROFILES, seed=20260906)
        self.assertEqual(len(plan["entries"]), 24 * 2)
        self.assertEqual(plan["planned_counts"], {"OBSERVE": 24, "PROTECT": 24})


if __name__ == "__main__":
    unittest.main()
