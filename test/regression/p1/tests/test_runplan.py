"""回归 run-plan（kind=p1_regression_run_plan）结构校验测试。"""

from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
P1_DIR = TESTS_DIR.parents[0]
for p in (str(TESTS_DIR), str(P1_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

import p1fixture  # noqa: E402
from p1reg import runplan as runplan_mod  # noqa: E402

PROFILES = ("OBSERVE", "PROTECT")


def load_example() -> dict:
    return json.loads(p1fixture.RUN_PLAN_EXAMPLE.read_text(encoding="utf-8"))


class TestRunPlanValidation(unittest.TestCase):
    def test_example_plan_valid(self):
        self.assertEqual(runplan_mod.validate_run_plan(load_example(), PROFILES), [])

    def test_kind_must_distinguish_from_p0(self):
        plan = load_example()
        plan["kind"] = "p0_run_plan"
        errors = runplan_mod.validate_run_plan(plan, PROFILES)
        self.assertTrue(any("kind" in e for e in errors))

    def test_bad_purpose(self):
        plan = load_example()
        plan["purpose"] = "WHATEVER"
        self.assertTrue(any("purpose" in e for e in runplan_mod.validate_run_plan(plan, PROFILES)))

    def test_baseline_purpose_accepted(self):
        plan = load_example()
        plan["purpose"] = "BASELINE"
        self.assertEqual(runplan_mod.validate_run_plan(plan, PROFILES), [])

    def test_bad_plan_id(self):
        plan = load_example()
        plan["plan_id"] = "whatever"
        self.assertTrue(any("plan_id" in e for e in runplan_mod.validate_run_plan(plan, PROFILES)))

    def test_unknown_profile_rejected(self):
        plan = load_example()
        plan["profiles"] = ["OBSERVE", "MAYBE"]
        self.assertTrue(any("未知 profile" in e for e in runplan_mod.validate_run_plan(plan, PROFILES)))

    def test_duplicate_profile_rejected(self):
        plan = load_example()
        plan["profiles"] = ["OBSERVE", "OBSERVE"]
        self.assertTrue(any("重复" in e for e in runplan_mod.validate_run_plan(plan, PROFILES)))

    def test_empty_profiles_rejected(self):
        plan = load_example()
        plan["profiles"] = []
        self.assertTrue(any("profiles" in e for e in runplan_mod.validate_run_plan(plan, PROFILES)))

    def test_bad_manifest_hash(self):
        plan = load_example()
        plan["corpus"]["manifest_sha256"] = "zz"
        self.assertTrue(any("manifest_sha256" in e for e in runplan_mod.validate_run_plan(plan, PROFILES)))

    def test_bad_seed(self):
        plan = load_example()
        plan["corpus"]["seed"] = "42"
        self.assertTrue(any("seed" in e for e in runplan_mod.validate_run_plan(plan, PROFILES)))

    def test_missing_isolation(self):
        plan = load_example()
        del plan["environment"]["isolation"]
        self.assertTrue(any("isolation" in e for e in runplan_mod.validate_run_plan(plan, PROFILES)))

    def test_missing_build_binding(self):
        plan = load_example()
        plan["build"]["worktree_dirty"] = "no"
        self.assertTrue(any("worktree_dirty" in e for e in runplan_mod.validate_run_plan(plan, PROFILES)))

    def test_missing_environment(self):
        plan = load_example()
        del plan["environment"]
        self.assertTrue(any("environment" in e for e in runplan_mod.validate_run_plan(plan, PROFILES)))


if __name__ == "__main__":
    unittest.main()
