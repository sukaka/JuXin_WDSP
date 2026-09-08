"""HTTP 回放适配器测试：请求计划、脱敏、重置描述、BLOCKED 语义与目标允许表。

纪律：不伪造网关响应冒充回放成功；执行层只覆盖诚实路径
（无环境 → BLOCKED、目标被拒 → AdapterError、全局重置 → 拒绝）。
"""

from __future__ import annotations

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
from adapters.http_replay import (  # noqa: E402
    AdapterError,
    HttpReplayAdapter,
    build_request_plan,
    describe_reset_plan,
)
from p1reg import corpus as corpus_mod  # noqa: E402
from p1reg.judge import judge_case  # noqa: E402
from p1reg.profiles import profile_ids  # noqa: E402
from p1reg.vocab import REASON_ENVIRONMENT_UNAVAILABLE  # noqa: E402

RID = p1fixture.VALID_RUN_ID


class TestRequestPlan(unittest.TestCase):
    def setUp(self):
        self.case = p1fixture.minimal_case_doc()

    def test_deterministic(self):
        a = build_request_plan(self.case, "OBSERVE", RID)
        b = build_request_plan(self.case, "OBSERVE", RID)
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))

    def test_request_id_format(self):
        plan = build_request_plan(self.case, "OBSERVE", RID)
        self.assertEqual(plan["steps"][0]["request_id"], f"{RID}-WAF-BEN-TST-001-01")

    def test_multistep_order_and_wait_preserved(self):
        corpus = corpus_mod.require_valid_corpus(
            p1fixture.REPO_MANIFEST, profile_ids(p1fixture.PROFILES_DIR))
        doc = corpus["cases"]["WAF-BEN-FORM-001"]["doc"]
        plan = build_request_plan(doc, "PROTECT", RID)
        self.assertEqual(len(plan["steps"]), 2)
        self.assertEqual(plan["steps"][0]["step_id"], "s1")
        self.assertEqual(plan["steps"][1]["step_id"], "s2")
        self.assertEqual(plan["steps"][1]["wait"],
                         {"type": "previous_step_status_in", "statuses": [200]})

    def test_sensitive_header_redacted(self):
        doc = p1fixture.minimal_case_doc()
        doc["steps"][0]["request"]["headers"] = {
            "Authorization": "Bearer synthetic.jwt.token",
            "X-Normal": "visible",
        }
        doc["steps"][0]["request"]["body"] = "payload"
        plan = build_request_plan(doc, "OBSERVE", RID)
        headers = plan["steps"][0]["headers"]
        self.assertNotIn("synthetic.jwt.token", json.dumps(plan))
        self.assertTrue(headers["Authorization"].startswith("sha256:"))
        self.assertEqual(headers["X-Normal"], "visible")
        self.assertNotIn("body", plan["steps"][0], "请求计划只携带 body 摘要与长度，不带原文")
        self.assertEqual(plan["steps"][0]["body_len"], 7)
        self.assertTrue(plan["steps"][0]["body_sha256"])

    def test_all_repo_cases_build_plan(self):
        corpus = corpus_mod.require_valid_corpus(
            p1fixture.REPO_MANIFEST, profile_ids(p1fixture.PROFILES_DIR))
        for cid, item in corpus["cases"].items():
            plan = build_request_plan(item["doc"], "OBSERVE", RID)
            self.assertEqual(len(plan["steps"]), len(item["doc"]["steps"]), cid)


class TestResetDescription(unittest.TestCase):
    def test_namespace_isolated_per_run(self):
        a = describe_reset_plan(p1fixture.minimal_case_doc(), p1fixture.VALID_RUN_ID)
        b = describe_reset_plan(p1fixture.minimal_case_doc(), p1fixture.VALID_RUN_ID_B)
        self.assertNotEqual(a["valkey_namespace"], b["valkey_namespace"])
        self.assertIn(p1fixture.VALID_RUN_ID, a["valkey_namespace"])
        self.assertIn("WAF-BEN-TST-001", a["valkey_namespace"])

    def test_forbidden_global_actions_listed(self):
        desc = describe_reset_plan(p1fixture.minimal_case_doc(), RID)
        self.assertIn("FLUSHALL", desc["forbidden_globally"])
        self.assertIn("FLUSHDB", desc["forbidden_globally"])

    def test_global_reset_action_rejected(self):
        doc = p1fixture.minimal_case_doc()
        doc["reset_plan"] = {"scope": "run", "actions": ["FLUSHALL"]}
        with self.assertRaises(AdapterError):
            describe_reset_plan(doc, RID)


class TestExecutionHonesty(unittest.TestCase):
    def test_no_environment_returns_blocked(self):
        adapter = HttpReplayAdapter(allowed_targets=(), environment=None)
        obs = adapter.execute_case(p1fixture.minimal_case_doc(), "OBSERVE", RID)
        self.assertFalse(obs["executed"])
        self.assertEqual(obs["blocked_reason"], REASON_ENVIRONMENT_UNAVAILABLE)
        r = judge_case(p1fixture.minimal_case_doc(), "OBSERVE", obs)
        self.assertEqual(r["status"], "BLOCKED")

    def test_blocked_result_never_passes(self):
        adapter = HttpReplayAdapter(allowed_targets=(), environment=None)
        for doc in (p1fixture.minimal_case_doc(),
                    p1fixture.minimal_case_doc("WAF-ATK-TST-001", "ATTACK")):
            obs = adapter.execute_case(doc, "PROTECT", RID)
            r = judge_case(doc, "PROTECT", obs)
            self.assertEqual(r["status"], "BLOCKED")
            self.assertNotEqual(r["status"], "PASS")

    def test_target_outside_allowlist_rejected(self):
        adapter = HttpReplayAdapter(allowed_targets={"127.0.0.1:8080"},
                                    environment={"base_url": "http://169.254.169.254/latest/"})
        with self.assertRaises(AdapterError):
            adapter.execute_case(p1fixture.minimal_case_doc(), "OBSERVE", RID)

    def test_target_with_credentials_rejected(self):
        adapter = HttpReplayAdapter(allowed_targets={"127.0.0.1:8080"},
                                    environment={"base_url": "http://user:pass@127.0.0.1:8080/"})
        with self.assertRaises(AdapterError):
            adapter.execute_case(p1fixture.minimal_case_doc(), "OBSERVE", RID)

    def test_event_persisted_wait_requires_store(self):
        doc = p1fixture.minimal_case_doc()
        doc["steps"][0]["wait"] = {"type": "event_persisted",
                                   "event_type": "waf_security_event", "timeout_ms": 100}
        adapter = HttpReplayAdapter(allowed_targets={"127.0.0.1:9"},
                                    environment={"base_url": "http://127.0.0.1:9"})
        with self.assertRaises(AdapterError):
            adapter.execute_case(doc, "OBSERVE", RID)


if __name__ == "__main__":
    unittest.main()
