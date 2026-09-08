"""逐例判定器与汇总口径测试（任务书 §5.2；REG-003/004/005）。"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
P1_DIR = TESTS_DIR.parents[0]
for p in (str(TESTS_DIR), str(P1_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

import p1fixture  # noqa: E402
from p1reg.judge import judge_case, summarize  # noqa: E402
from p1reg.vocab import REASON_ENVIRONMENT_UNAVAILABLE  # noqa: E402

BENIGN = p1fixture.minimal_case_doc("WAF-BEN-TST-001", "BENIGN")
ATTACK = p1fixture.minimal_case_doc("WAF-ATK-TST-001", "ATTACK")
# ATTACK 夹具的 OBSERVE 期望按真实语义改写为 DETECT_PASS + reached
ATTACK_OBSERVE = p1fixture.minimal_case_doc("WAF-ATK-TST-001", "ATTACK")
ATTACK_OBSERVE["expectations_by_profile"]["OBSERVE"] = {
    "expected_detection": {"module": "coraza_crs", "rule_family": "sqli"},
    "expected_final_action": "DETECT_PASS",
    "expected_origin": "reached",
}


class TestJudgeStatusMapping(unittest.TestCase):
    def test_benign_pass(self):
        r = judge_case(BENIGN, "OBSERVE", p1fixture.make_observation(BENIGN, "OBSERVE"))
        self.assertEqual(r["status"], "PASS", r["reasons"])

    def test_attack_protect_pass(self):
        r = judge_case(ATTACK, "PROTECT", p1fixture.make_observation(ATTACK, "PROTECT"))
        self.assertEqual(r["status"], "PASS", r["reasons"])

    def test_attack_observe_detect_pass_correct(self):
        r = judge_case(ATTACK_OBSERVE, "OBSERVE",
                       p1fixture.make_observation(ATTACK_OBSERVE, "OBSERVE"))
        self.assertEqual(r["status"], "PASS", r["reasons"])

    def test_profile_not_applicable(self):
        r = judge_case(BENIGN, "NOPE", None)
        self.assertEqual(r["status"], "NOT_APPLICABLE")

    def test_no_observation_is_not_run(self):
        r = judge_case(BENIGN, "OBSERVE", None)
        self.assertEqual(r["status"], "NOT_RUN")

    def test_environment_unavailable_is_blocked(self):
        obs = {"executed": False, "valid": False,
               "blocked_reason": REASON_ENVIRONMENT_UNAVAILABLE}
        r = judge_case(BENIGN, "OBSERVE", obs)
        self.assertEqual(r["status"], "BLOCKED")
        self.assertIn(REASON_ENVIRONMENT_UNAVAILABLE, r["reasons"][0])

    def test_aborted_not_passed(self):
        obs = p1fixture.make_observation(ATTACK, "PROTECT", execution_state="ABORTED")
        r = judge_case(ATTACK, "PROTECT", obs)
        self.assertEqual(r["status"], "FAIL")
        self.assertTrue(any("不得默认转通过" in x for x in r["reasons"]))

    def test_error_state_not_passed(self):
        obs = p1fixture.make_observation(BENIGN, "OBSERVE", execution_state="ERROR")
        self.assertEqual(judge_case(BENIGN, "OBSERVE", obs)["status"], "FAIL")

    def test_unknown_state_not_passed(self):
        obs = p1fixture.make_observation(BENIGN, "OBSERVE", execution_state="UNKNOWN")
        self.assertEqual(judge_case(BENIGN, "OBSERVE", obs)["status"], "FAIL")

    def test_pending_correlation_not_passed(self):
        obs = p1fixture.make_observation(BENIGN, "OBSERVE", execution_state="PENDING_CORRELATION")
        self.assertEqual(judge_case(BENIGN, "OBSERVE", obs)["status"], "FAIL")

    def test_unexpected_state_string_not_passed(self):
        obs = p1fixture.make_observation(BENIGN, "OBSERVE", execution_state="MAYBE")
        self.assertEqual(judge_case(BENIGN, "OBSERVE", obs)["status"], "FAIL")

    def test_invalid_execution_not_applicable(self):
        obs = p1fixture.make_observation(BENIGN, "OBSERVE", valid=False)
        r = judge_case(BENIGN, "OBSERVE", obs)
        self.assertEqual(r["status"], "NOT_APPLICABLE")
        self.assertTrue(any("不计入分母" in x for x in r["reasons"]))


class TestJudgeExpectations(unittest.TestCase):
    def test_missing_detection_evidence_fails(self):
        obs = p1fixture.make_observation(ATTACK, "PROTECT", detection=None)
        r = judge_case(ATTACK, "PROTECT", obs)
        self.assertEqual(r["status"], "FAIL")
        self.assertTrue(any("缺检测证据" in x for x in r["reasons"]))

    def test_wrong_module_fails(self):
        """REG-004：别的模块/来源命中不能冒充目标模块正确检测。"""
        obs = p1fixture.make_observation(ATTACK, "PROTECT")
        obs["detection"]["module"] = "cc_limiter"
        r = judge_case(ATTACK, "PROTECT", obs)
        self.assertEqual(r["status"], "FAIL")
        self.assertTrue(any("检出模块不符" in x for x in r["reasons"]))

    def test_missing_detection_fails(self):
        obs = p1fixture.make_observation(ATTACK, "PROTECT")
        obs["detection"] = {"detected": False, "module": None, "rule_family": None}
        r = judge_case(ATTACK, "PROTECT", obs)
        self.assertEqual(r["status"], "FAIL")
        self.assertTrue(any("未检出" in x for x in r["reasons"]))

    def test_benign_detected_fails(self):
        obs = p1fixture.make_observation(BENIGN, "OBSERVE")
        obs["detection"] = {"detected": True, "module": "coraza_crs", "rule_family": "sqli"}
        r = judge_case(BENIGN, "OBSERVE", obs)
        self.assertEqual(r["status"], "FAIL")
        self.assertTrue(any("误报" in x for x in r["reasons"]))

    def test_action_mismatch_fails(self):
        obs = p1fixture.make_observation(ATTACK, "PROTECT", observed_action="DETECT_PASS")
        r = judge_case(ATTACK, "PROTECT", obs)
        self.assertEqual(r["status"], "FAIL")
        self.assertTrue(any("最终动作不符" in x for x in r["reasons"]))

    def test_unexpected_error_action_fails(self):
        obs = p1fixture.make_observation(BENIGN, "OBSERVE", observed_action="UNEXPECTED_ERROR")
        r = judge_case(BENIGN, "OBSERVE", obs)
        self.assertEqual(r["status"], "FAIL")
        self.assertTrue(any("非预期错误" in x for x in r["reasons"]))

    def test_missing_action_evidence_fails(self):
        obs = p1fixture.make_observation(BENIGN, "OBSERVE", observed_action=None)
        r = judge_case(BENIGN, "OBSERVE", obs)
        self.assertEqual(r["status"], "FAIL")
        self.assertTrue(any("缺最终处置证据" in x for x in r["reasons"]))

    def test_illegal_observed_action_fails(self):
        obs = p1fixture.make_observation(BENIGN, "OBSERVE", observed_action="ALLOW_PLEASE")
        self.assertEqual(judge_case(BENIGN, "OBSERVE", obs)["status"], "FAIL")

    def test_origin_mismatch_fails(self):
        obs = p1fixture.make_observation(ATTACK, "PROTECT", origin_reached=True)
        r = judge_case(ATTACK, "PROTECT", obs)
        self.assertEqual(r["status"], "FAIL")
        self.assertTrue(any("源站到达性不符" in x for x in r["reasons"]))

    def test_origin_missing_evidence_fails(self):
        obs = p1fixture.make_observation(BENIGN, "OBSERVE", origin_reached=None)
        r = judge_case(BENIGN, "OBSERVE", obs)
        self.assertEqual(r["status"], "FAIL")
        self.assertTrue(any("缺源站到达证据" in x for x in r["reasons"]))

    def test_assertion_unmet_fails(self):
        obs = p1fixture.make_observation(
            BENIGN, "OBSERVE",
            assertions=[{"step_id": "s1", "type": "http_status_in", "met": False, "detail": "status=500"}])
        r = judge_case(BENIGN, "OBSERVE", obs)
        self.assertEqual(r["status"], "FAIL")
        self.assertTrue(any("步骤断言未满足" in x for x in r["reasons"]))

    def test_side_effect_mismatch_fails(self):
        doc = p1fixture.minimal_case_doc("WAF-BEN-TST-002", "BENIGN")
        for pid in ("OBSERVE", "PROTECT"):
            doc["expectations_by_profile"][pid]["expected_side_effects"] = {"origin_write_count": 1}
        obs = p1fixture.make_observation(doc, "OBSERVE", side_effects={"origin_write_count": 0})
        r = judge_case(doc, "OBSERVE", obs)
        self.assertEqual(r["status"], "FAIL")
        self.assertTrue(any("副作用" in x for x in r["reasons"]))

    def test_side_effect_missing_evidence_fails(self):
        doc = p1fixture.minimal_case_doc("WAF-BEN-TST-002", "BENIGN")
        for pid in ("OBSERVE", "PROTECT"):
            doc["expectations_by_profile"][pid]["expected_side_effects"] = {"origin_write_count": 1}
        obs = p1fixture.make_observation(doc, "OBSERVE", side_effects=None)
        r = judge_case(doc, "OBSERVE", obs)
        self.assertEqual(r["status"], "FAIL")
        self.assertTrue(any("缺业务副作用实测" in x for x in r["reasons"]))


class TestSummarize(unittest.TestCase):
    def _rows(self):
        rows = []
        rows.append(judge_case(BENIGN, "PROTECT", p1fixture.make_observation(BENIGN, "PROTECT")))
        fp = p1fixture.minimal_case_doc("WAF-BEN-TST-003", "BENIGN")
        obs_fp = p1fixture.make_observation(fp, "PROTECT")
        obs_fp["detection"] = {"detected": True, "module": "coraza_crs", "rule_family": "sqli"}
        obs_fp["observed_action"] = "BLOCK_403"
        rows.append(judge_case(fp, "PROTECT", obs_fp))
        rows.append(judge_case(ATTACK, "PROTECT", p1fixture.make_observation(ATTACK, "PROTECT")))
        miss = p1fixture.minimal_case_doc("WAF-ATK-TST-002", "ATTACK")
        obs_miss = p1fixture.make_observation(miss, "PROTECT")
        obs_miss["detection"] = {"detected": False, "module": None, "rule_family": None}
        obs_miss["observed_action"] = "PASS"
        obs_miss["origin_reached"] = True
        rows.append(judge_case(miss, "PROTECT", obs_miss))
        return rows

    def test_denominators_and_counts(self):
        s = summarize(self._rows())["profiles"]["PROTECT"]
        self.assertEqual(s["detection_false_positive"]["denominator"], 2)
        self.assertEqual(s["detection_false_positive"]["count"], 1)
        self.assertEqual(s["block_false_positive"]["count"], 1)
        self.assertEqual(s["detection_miss"]["denominator"], 2)
        self.assertEqual(s["detection_miss"]["count"], 1)
        self.assertEqual(s["block_miss"]["denominator"], 2)
        self.assertEqual(s["block_miss"]["count"], 1)
        self.assertEqual(s["pass"], 2)
        self.assertEqual(s["fail"], 2)
        self.assertEqual(len(s["failures"]), 2)

    def test_zero_denominator_na(self):
        rows = [judge_case(BENIGN, "OBSERVE", p1fixture.make_observation(BENIGN, "OBSERVE"))]
        s = summarize(rows)["profiles"]["OBSERVE"]
        self.assertEqual(s["detection_miss"]["rate"], "N/A")
        self.assertEqual(s["detection_miss"]["denominator"], 0)
        self.assertEqual(s["detection_false_positive"]["rate"], 0.0)

    def test_unknown_excluded_from_denominator(self):
        unk = p1fixture.minimal_case_doc("WAF-UNK-TST-001", "UNKNOWN")
        rows = [judge_case(unk, "OBSERVE", p1fixture.make_observation(unk, "OBSERVE"))]
        s = summarize(rows)["profiles"]["OBSERVE"]
        self.assertEqual(s["excluded_unknown"], 1)
        self.assertEqual(s["detection_false_positive"]["denominator"], 0)
        self.assertEqual(s["detection_miss"]["denominator"], 0)

    def test_invalid_execution_excluded(self):
        obs = p1fixture.make_observation(BENIGN, "OBSERVE", valid=False)
        rows = [judge_case(BENIGN, "OBSERVE", obs)]
        s = summarize(rows)["profiles"]["OBSERVE"]
        self.assertEqual(s["invalid"], 1)
        self.assertEqual(s["valid"], 0)
        self.assertEqual(s["detection_false_positive"]["denominator"], 0)

    def test_blocked_and_not_run_counted_separately(self):
        rows = [
            judge_case(BENIGN, "OBSERVE", {"executed": False, "valid": False,
                                           "blocked_reason": REASON_ENVIRONMENT_UNAVAILABLE}),
            judge_case(ATTACK, "OBSERVE", None),
        ]
        s = summarize(rows, {"OBSERVE": 5})["profiles"]["OBSERVE"]
        self.assertEqual(s["blocked"], 1)
        self.assertEqual(s["not_run"], 1)
        self.assertEqual(s["missing"], 5)

    def test_observe_correct_release_not_block_miss(self):
        """REG-005：OBSERVE 下正确放行攻击（DETECT_PASS）不构成拦截漏报。"""
        rows = [judge_case(ATTACK_OBSERVE, "OBSERVE",
                           p1fixture.make_observation(ATTACK_OBSERVE, "OBSERVE"))]
        s = summarize(rows)["profiles"]["OBSERVE"]
        self.assertEqual(s["block_miss"]["denominator"], 0)
        self.assertEqual(s["block_miss"]["rate"], "N/A")
        self.assertEqual(s["detection_miss"]["denominator"], 1)
        self.assertEqual(s["detection_miss"]["count"], 0)


if __name__ == "__main__":
    unittest.main()
