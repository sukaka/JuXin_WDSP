"""前后版本配对比较测试（任务书 §5；REG-003/011；compare 只读、不重新执行、不猜测期望）。"""

from __future__ import annotations

import hashlib
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
from p1reg import compare as compare_mod  # noqa: E402

BENIGN = p1fixture.minimal_case_doc("WAF-BEN-TST-001", "BENIGN")
ATTACK = p1fixture.minimal_case_doc("WAF-ATK-TST-001", "ATTACK")
RID_B = p1fixture.VALID_RUN_ID
RID_C = p1fixture.VALID_RUN_ID_B


def row_pass(doc, profile):
    return p1fixture.make_judge_row(doc, profile, p1fixture.make_observation(doc, profile))


def row_attack_missed(doc, profile):
    obs = p1fixture.make_observation(doc, profile)
    obs["detection"] = {"detected": False, "module": None, "rule_family": None}
    obs["observed_action"] = "PASS"
    obs["origin_reached"] = True
    return p1fixture.make_judge_row(doc, profile, obs)


def row_benign_blocked(doc, profile):
    obs = p1fixture.make_observation(doc, profile)
    obs["detection"] = {"detected": True, "module": "coraza_crs", "rule_family": "sqli"}
    obs["observed_action"] = "BLOCK_403"
    obs["origin_reached"] = False
    return p1fixture.make_judge_row(doc, profile, obs)


class CompareFixture(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.root = Path(self._td.name)

    def run_pair(self, baseline_rows, candidate_rows, cid=RID_C):
        b = p1fixture.write_run_dir(self.root, RID_B, baseline_rows)
        c = p1fixture.write_run_dir(self.root, cid, candidate_rows)
        return compare_mod.compare_runs(b, c)


class TestCompareHappyPath(CompareFixture):
    def test_identical_runs_pass(self):
        rows_b = [row_pass(BENIGN, "OBSERVE"), row_pass(ATTACK, "PROTECT")]
        rows_c = [row_pass(BENIGN, "OBSERVE"), row_pass(ATTACK, "PROTECT")]
        doc = self.run_pair(rows_b, rows_c)
        self.assertEqual(doc["verdict"], "PASS", doc["verdict_reasons"])
        self.assertEqual(doc["summary"]["paired"], 2)
        self.assertEqual(doc["summary"]["unchanged_correct"], 2)

    def test_new_correct_detection(self):
        rows_b = [row_attack_missed(ATTACK, "PROTECT")]
        rows_c = [row_pass(ATTACK, "PROTECT")]
        doc = self.run_pair(rows_b, rows_c)
        self.assertEqual(len(doc["summary"]["new_correct_detections"]), 1)
        # baseline FAIL → candidate PASS：不是回归
        self.assertEqual(doc["summary"]["new_failures"], [])
        self.assertEqual(doc["verdict"], "PASS", doc["verdict_reasons"])

    def test_fixed_false_positive_informational(self):
        rows_b = [row_benign_blocked(BENIGN, "PROTECT")]
        rows_c = [row_pass(BENIGN, "PROTECT")]
        doc = self.run_pair(rows_b, rows_c)
        self.assertEqual(len(doc["summary"]["fixed_false_positives"]), 1)
        self.assertEqual(doc["verdict"], "PASS", doc["verdict_reasons"])

    def test_deterministic(self):
        rows_b = [row_pass(BENIGN, "OBSERVE")]
        rows_c = [row_pass(BENIGN, "OBSERVE")]
        a = self.run_pair(rows_b, rows_c)
        b = self.run_pair(rows_b, rows_c)
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))


class TestCompareRegressions(CompareFixture):
    def test_lost_detection_fail(self):
        doc = self.run_pair([row_pass(ATTACK, "PROTECT")], [row_attack_missed(ATTACK, "PROTECT")])
        s = doc["summary"]
        self.assertEqual(doc["verdict"], "FAIL")
        self.assertEqual(len(s["lost_detections"]), 1)
        self.assertEqual(s["lost_detection_rate"], 1.0)
        self.assertEqual(len(s["new_failures"]), 1)

    def test_new_false_positive_fail(self):
        doc = self.run_pair([row_pass(BENIGN, "PROTECT")], [row_benign_blocked(BENIGN, "PROTECT")])
        s = doc["summary"]
        self.assertEqual(doc["verdict"], "FAIL")
        self.assertEqual(len(s["new_false_positives"]), 1)
        self.assertEqual(len(s["new_block_false_positives"]), 1)
        self.assertEqual(s["new_false_positive_rate"], 1.0)

    def test_action_change_listed(self):
        obs = p1fixture.make_observation(ATTACK, "PROTECT", observed_action="RATE_LIMIT_429")
        row_c = p1fixture.make_judge_row(ATTACK, "PROTECT", obs)
        self.assertEqual(row_c["status"], "FAIL")
        doc = self.run_pair([row_pass(ATTACK, "PROTECT")], [row_c])
        s = doc["summary"]
        self.assertEqual(len(s["action_changes"]), 1)
        self.assertEqual(s["action_changes"][0]["from"], "BLOCK_403")
        self.assertEqual(s["action_changes"][0]["to"], "RATE_LIMIT_429")
        self.assertEqual(doc["verdict"], "FAIL")

    def test_origin_change_listed_even_when_both_pass(self):
        # 构造同状态 PASS 但 origin 观测不同的行（直改 detail，模拟对账差异）
        rb = row_pass(BENIGN, "OBSERVE")
        rc = row_pass(BENIGN, "OBSERVE")
        rc["detail"]["origin"]["observed"] = False
        doc = self.run_pair([rb], [rc])
        s = doc["summary"]
        self.assertEqual(len(s["origin_changes"]), 1)
        self.assertEqual(doc["verdict"], "PASS", doc["verdict_reasons"])

    def test_persistent_mandatory_failure_fail(self):
        """REG-011：历史强制漏报前后相同仍失败，平均值不能覆盖。"""
        rows = [row_attack_missed(ATTACK, "PROTECT")]
        doc = self.run_pair(rows, rows)
        self.assertEqual(doc["verdict"], "FAIL")
        self.assertEqual(len(doc["summary"]["persistent_failures"]), 1)
        self.assertTrue(any("前后相同不算通过" in r for r in doc["verdict_reasons"]))

    def test_persistent_standard_failure_not_blocking(self):
        std = p1fixture.minimal_case_doc("WAF-ATK-TST-009", "ATTACK", criticality="STANDARD")
        rows = [row_attack_missed(std, "PROTECT"), row_pass(BENIGN, "OBSERVE")]
        rows_c = [row_attack_missed(std, "PROTECT"), row_pass(BENIGN, "OBSERVE")]
        doc = self.run_pair(rows, rows_c)
        self.assertEqual(doc["verdict"], "PASS", doc["verdict_reasons"])
        self.assertEqual(len(doc["summary"]["persistent_failures"]), 1)


class TestCompareIncomparable(CompareFixture):
    def test_missing_in_candidate(self):
        doc = self.run_pair([row_pass(BENIGN, "OBSERVE"), row_pass(ATTACK, "PROTECT")],
                            [row_pass(BENIGN, "OBSERVE")])
        self.assertEqual(doc["verdict"], "NOT_PASSED")
        reasons = [i["reason"] for i in doc["incomparable"]]
        self.assertIn("CASE_MISSING_IN_CANDIDATE", reasons)
        self.assertEqual(doc["summary"]["mandatory_incomparable"], 1)

    def test_missing_in_baseline_standard_not_blocking(self):
        std = p1fixture.minimal_case_doc("WAF-ATK-TST-009", "ATTACK", criticality="STANDARD")
        doc = self.run_pair([row_pass(BENIGN, "OBSERVE")],
                            [row_pass(BENIGN, "OBSERVE"), row_pass(std, "PROTECT")])
        self.assertEqual(doc["verdict"], "PASS", doc["verdict_reasons"])
        self.assertEqual(doc["summary"]["incomparable_count"], 1)

    def test_version_changed_incomparable(self):
        rb = row_pass(ATTACK, "PROTECT")
        rc = row_pass(ATTACK, "PROTECT")
        rc["case_version"] = 2
        doc = self.run_pair([rb], [rc])
        self.assertEqual(doc["verdict"], "NOT_PASSED")
        self.assertIn("CASE_VERSION_CHANGED", [i["reason"] for i in doc["incomparable"]])

    def test_unknown_excluded_from_denominator(self):
        unk = p1fixture.minimal_case_doc("WAF-UNK-TST-001", "UNKNOWN")
        rb = [row_pass(BENIGN, "OBSERVE"), row_pass(unk, "OBSERVE")]
        rc = [row_pass(BENIGN, "OBSERVE"), row_pass(unk, "OBSERVE")]
        doc = self.run_pair(rb, rc)
        self.assertEqual(doc["summary"]["paired"], 1)
        self.assertIn("TRUTH_UNKNOWN_EXCLUDED", [i["reason"] for i in doc["incomparable"]])
        self.assertEqual(doc["verdict"], "PASS", doc["verdict_reasons"])

    def test_invalid_execution_incomparable(self):
        rb = [row_pass(ATTACK, "PROTECT")]
        blocked = p1fixture.make_judge_row(
            ATTACK, "PROTECT",
            {"executed": False, "valid": False, "blocked_reason": "ENVIRONMENT_UNAVAILABLE"})
        self.assertEqual(blocked["status"], "BLOCKED")
        doc = self.run_pair(rb, [blocked])
        self.assertEqual(doc["verdict"], "NOT_PASSED")
        self.assertTrue(any("EXECUTION_INVALID_IN_CANDIDATE" in i["reason"]
                            for i in doc["incomparable"]))

    def test_zero_denominator_not_passed(self):
        unk = p1fixture.minimal_case_doc("WAF-UNK-TST-001", "UNKNOWN")
        doc = self.run_pair([row_pass(unk, "OBSERVE")], [row_pass(unk, "OBSERVE")])
        self.assertEqual(doc["summary"]["paired"], 0)
        self.assertEqual(doc["summary"]["new_false_positive_rate"], "N/A")
        self.assertEqual(doc["summary"]["lost_detection_rate"], "N/A")
        self.assertEqual(doc["verdict"], "NOT_PASSED")

    def test_expectation_changed_same_version_integrity(self):
        import copy as _copy

        rb = row_pass(ATTACK, "PROTECT")
        tampered_doc = _copy.deepcopy(ATTACK)
        rc = row_pass(tampered_doc, "PROTECT")
        rc["expectation"]["expected_detection"]["module"] = "custom_pack"
        doc = self.run_pair([rb], [rc])
        self.assertEqual(doc["verdict"], "NOT_PASSED")
        self.assertTrue(any("EXPECTATION_CHANGED_SAME_VERSION" in e
                            for e in doc["integrity_errors"]))


class TestCompareEvidenceIntegrity(CompareFixture):
    def test_missing_cases_file(self):
        b = p1fixture.write_run_dir(self.root, RID_B, [row_pass(BENIGN, "OBSERVE")])
        c = p1fixture.write_run_dir(self.root, RID_C, [row_pass(BENIGN, "OBSERVE")])
        (c / "cases.jsonl").unlink()
        doc = compare_mod.compare_runs(b, c)
        self.assertEqual(doc["verdict"], "NOT_PASSED")
        self.assertTrue(any("原始文件缺失" in e for e in doc["integrity_errors"]))

    def test_malformed_row(self):
        b = p1fixture.write_run_dir(self.root, RID_B, [row_pass(BENIGN, "OBSERVE")])
        c = p1fixture.write_run_dir(self.root, RID_C, [row_pass(BENIGN, "OBSERVE")])
        with (c / "cases.jsonl").open("a", encoding="utf-8") as fh:
            fh.write("{not json}\n")
        doc = compare_mod.compare_runs(b, c)
        self.assertEqual(doc["verdict"], "NOT_PASSED")
        self.assertTrue(any("不是合法 JSON" in e for e in doc["integrity_errors"]))

    def test_duplicate_row_rejected(self):
        r = row_pass(BENIGN, "OBSERVE")
        b = p1fixture.write_run_dir(self.root, RID_B, [r])
        c = p1fixture.write_run_dir(self.root, RID_C, [r, dict(r)])
        doc = compare_mod.compare_runs(b, c)
        self.assertTrue(any("重复行" in e for e in doc["integrity_errors"]))

    def test_run_id_dir_mismatch(self):
        b = p1fixture.write_run_dir(self.root, RID_B, [row_pass(BENIGN, "OBSERVE")])
        c = p1fixture.write_run_dir(self.root, RID_C, [row_pass(BENIGN, "OBSERVE")])
        (c / "manifest.json").write_text(json.dumps({"run_id": RID_B}) + "\n", encoding="utf-8")
        doc = compare_mod.compare_runs(b, c)
        self.assertTrue(any("不一致" in e for e in doc["integrity_errors"]))

    def test_illegal_mandatory_skip_in_status(self):
        b = p1fixture.write_run_dir(self.root, RID_B, [row_pass(BENIGN, "OBSERVE")])
        c = p1fixture.write_run_dir(
            self.root, RID_C, [row_pass(BENIGN, "OBSERVE")],
            status_records={"regression-execution": {"status": "SKIP", "mandatory": True,
                                                     "reason": "偷懒", "evidence": ""}})
        doc = compare_mod.compare_runs(b, c)
        self.assertTrue(any("非法 SKIP" in e for e in doc["integrity_errors"]))
        self.assertEqual(doc["verdict"], "NOT_PASSED")

    def test_missing_dir_structural_error(self):
        with self.assertRaises(compare_mod.CompareError):
            compare_mod.compare_runs(self.root / "nope", self.root / "nope2")

    def test_inputs_not_mutated(self):
        b = p1fixture.write_run_dir(self.root, RID_B, [row_pass(BENIGN, "OBSERVE")])
        c = p1fixture.write_run_dir(self.root, RID_C, [row_benign_blocked(BENIGN, "OBSERVE")])

        def snapshot(d: Path):
            return {f.name: hashlib.sha256(f.read_bytes()).hexdigest() for f in sorted(d.iterdir())}

        before_b, before_c = snapshot(b), snapshot(c)
        out = self.root / "cmp-out"
        doc = compare_mod.compare_runs(b, c)
        compare_mod.write_compare(doc, out)
        self.assertEqual(snapshot(b), before_b, "compare 不得修改 baseline 证据目录")
        self.assertEqual(snapshot(c), before_c, "compare 不得修改 candidate 证据目录")
        self.assertTrue((out / "compare.json").is_file())
        self.assertTrue((out / "report.md").is_file())


class TestCompareMarkdown(CompareFixture):
    def test_markdown_sections(self):
        doc = self.run_pair([row_pass(ATTACK, "PROTECT")], [row_attack_missed(ATTACK, "PROTECT")])
        md = compare_mod.render_compare_markdown(doc)
        self.assertIn("**FAIL**", md)
        self.assertIn("丢失检测", md)
        self.assertIn("WAF-ATK-TST-001", md)
        self.assertIn("只读", md)

    def test_markdown_na_rendering(self):
        unk = p1fixture.minimal_case_doc("WAF-UNK-TST-001", "UNKNOWN")
        doc = self.run_pair([row_pass(unk, "OBSERVE")], [row_pass(unk, "OBSERVE")])
        md = compare_mod.render_compare_markdown(doc)
        self.assertIn("N/A", md)


if __name__ == "__main__":
    unittest.main()
