"""R2 对账层与执行器单元测试（假 ApiClient/假环境，不冒充真实栈证据）。"""

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
from p1reg import executor as executor_mod  # noqa: E402
from p1reg import reconcile as reconcile_mod  # noqa: E402
from p1reg.judge import judge_case  # noqa: E402

RID = p1fixture.VALID_RUN_ID


class FakeApiClient:
    """按 request_id 预置事件数据的假客户端（替代 HTTP 层）。"""

    def __init__(self, sec=None, acc=None, details=None):
        self.sec = sec or {}
        self.acc = acc or {}
        self.details = details or {}

    def list_security_events(self, request_id):
        return self.sec.get(request_id, [])

    def get_security_event_detail(self, event_id):
        return self.details.get(event_id, {})

    def list_access_control_events(self, request_id):
        return self.acc.get(request_id, [])


def _obs(rid_suffix="01", status=200, origin=True):
    return {
        "case_id": "WAF-BEN-TST-001", "profile": "PROTECT",
        "executed": True, "valid": True, "execution_state": "COMPLETED",
        "detection": None, "observed_action": None,
        "origin_reached": origin, "assertions": [], "side_effects": None,
        "evidence_refs": [],
        "http": {"last_status": status},
        "perf": [{"request_id": f"{RID}-WAF-BEN-TST-001-{rid_suffix}", "seq": 1,
                  "kind": "step", "status": status, "latency_ms": 1.0,
                  "origin_reached": origin}],
    }


def _case(exp_det, exp_action, exp_origin="reached"):
    doc = p1fixture.minimal_case_doc()
    for prof in doc["expectations_by_profile"].values():
        prof["expected_detection"] = exp_det
        prof["expected_final_action"] = exp_action
        prof["expected_origin"] = exp_origin
    return doc


class TestReconcileWaf(unittest.TestCase):
    def test_waf_block_with_final_decision(self):
        rid = f"{RID}-WAF-BEN-TST-001-01"
        client = FakeApiClient(
            sec={rid: [{"id": "e1", "action": "BLOCK", "attack_type": "SQL_INJECTION",
                        "response_status": 403, "rule_match_count": 1}]},
            details={"e1": {
                "event": {"final_decision": {"security_action": "BLOCK",
                                             "executor_module": "WAF",
                                             "completion_status": "COMPLETED",
                                             "http_status": 403}},
                "matches": [{"rule_id": 942100, "severity": "CRITICAL",
                             "rule_source": "OWASP_CRS"}],
            }})
        obs = _obs(status=403, origin=False)
        doc = _case({"module": "coraza_crs", "rule_family": "sqli"}, "BLOCK_403", "not_reached")
        out = reconcile_mod.reconcile_case(client, doc, obs, grace_ms=0)
        self.assertEqual(out["detection"]["module"], "coraza_crs")
        self.assertEqual(out["detection"]["rule_family"], "sqli")
        self.assertEqual(out["observed_action"], "BLOCK_403")
        r = judge_case(doc, "PROTECT", out)
        self.assertEqual(r["status"], "PASS")
        self.assertIn("security-event:e1", out["evidence_refs"])

    def test_waf_observe_detect_pass(self):
        rid = f"{RID}-WAF-BEN-TST-001-01"
        client = FakeApiClient(
            sec={rid: [{"id": "e2", "action": "OBSERVE", "attack_type": "XSS",
                        "response_status": 200, "rule_match_count": 1}]},
            details={"e2": {"event": {}, "matches": [
                {"rule_id": 941100, "severity": "CRITICAL", "rule_source": "OWASP_CRS"}]}})
        obs = _obs(status=200, origin=True)
        doc = _case({"module": "coraza_crs", "rule_family": "xss"}, "DETECT_PASS")
        out = reconcile_mod.reconcile_case(client, doc, obs, grace_ms=0)
        self.assertEqual(out["observed_action"], "DETECT_PASS")
        self.assertEqual(judge_case(doc, "PROTECT", out)["status"], "PASS")

    def test_custom_pack_family_from_descriptor(self):
        rid = f"{RID}-WAF-BEN-TST-001-01"
        client = FakeApiClient(
            sec={rid: [{"id": "e3", "action": "BLOCK", "attack_type": "OTHER",
                        "response_status": 403, "rule_match_count": 1}]},
            details={"e3": {
                "event": {"final_decision": {"security_action": "BLOCK", "http_status": 403}},
                "matches": [{"rule_id": 7100001, "severity": "CRITICAL"}],
            }})
        obs = _obs(status=403, origin=False)
        doc = _case({"module": "custom_pack", "rule_family": "webshell_uploads"},
                    "BLOCK_403", "not_reached")
        out = reconcile_mod.reconcile_case(
            client, doc, obs, custom_families={"7100001": "webshell_uploads"}, grace_ms=0)
        self.assertEqual(out["detection"]["module"], "custom_pack")
        self.assertEqual(out["detection"]["rule_family"], "webshell_uploads")
        self.assertEqual(judge_case(doc, "PROTECT", out)["status"], "PASS")

    def test_benign_no_detection_pass(self):
        client = FakeApiClient()
        obs = _obs(status=200, origin=True)
        doc = _case({"module": "none"}, "PASS")
        out = reconcile_mod.reconcile_case(client, doc, obs, grace_ms=0)
        self.assertFalse(out["detection"]["detected"])
        self.assertEqual(out["observed_action"], "PASS")
        self.assertEqual(judge_case(doc, "PROTECT", out)["status"], "PASS")

    def test_unattributed_403_is_unexpected_error(self):
        client = FakeApiClient()
        obs = _obs(status=403, origin=False)
        doc = _case({"module": "coraza_crs", "rule_family": "sqli"}, "BLOCK_403", "not_reached")
        out = reconcile_mod.reconcile_case(client, doc, obs, grace_ms=0, timeout_ms=100)
        self.assertEqual(out["observed_action"], "UNEXPECTED_ERROR")
        self.assertEqual(judge_case(doc, "PROTECT", out)["status"], "FAIL")


class TestReconcileBot(unittest.TestCase):
    def test_challenge_block(self):
        rid = f"{RID}-WAF-BEN-TST-001-01"
        client = FakeApiClient(acc={rid: [
            {"id": "a1", "event_type": "BOT_CHALLENGE_OFFERED", "action": "CHALLENGE",
             "response_status": 403, "request_path": "/"}]})
        obs = _obs(status=403, origin=False)
        doc = _case({"module": "bot", "rule_family": "challenge"}, "BLOCK_403", "not_reached")
        out = reconcile_mod.reconcile_case(client, doc, obs, grace_ms=0)
        self.assertEqual(out["detection"]["module"], "bot")
        self.assertEqual(out["observed_action"], "BLOCK_403")
        self.assertEqual(judge_case(doc, "PROTECT", out)["status"], "PASS")

    def test_observe_would_challenge_detect_pass(self):
        # OBSERVE 模式"假设会挑战"（action=OBSERVE）是流程记录，不算检测 finding；
        # 检出=False、动作=PASS（真实栈实测：合格首导航均记录该事件）
        rid = f"{RID}-WAF-BEN-TST-001-01"
        client = FakeApiClient(acc={rid: [
            {"id": "a2", "event_type": "BOT_CHALLENGE_OFFERED", "action": "OBSERVE",
             "response_status": 200, "request_path": "/"}]})
        obs = _obs(status=200, origin=True)
        doc = _case({"module": "none"}, "PASS")
        out = reconcile_mod.reconcile_case(client, doc, obs, grace_ms=0)
        self.assertFalse(out["detection"]["detected"])
        self.assertEqual(out["observed_action"], "PASS")
        self.assertEqual(judge_case(doc, "PROTECT", out)["status"], "PASS")

    def test_protect_challenge_offered_is_detection(self):
        # PROTECT 实签发挑战（action=CHALLENGE）+ 403 未达源站 → bot/challenge 检出 + BLOCK_403
        rid = f"{RID}-WAF-BEN-TST-001-01"
        client = FakeApiClient(acc={rid: [
            {"id": "a2c", "event_type": "BOT_CHALLENGE_OFFERED", "action": "CHALLENGE",
             "response_status": 403, "request_path": "/"}]})
        obs = _obs(status=403, origin=False)
        doc = _case({"module": "bot", "rule_family": "challenge"}, "BLOCK_403",
                    exp_origin="not_reached")
        out = reconcile_mod.reconcile_case(client, doc, obs, grace_ms=0)
        self.assertEqual(out["detection"], {"detected": True, "module": "bot",
                                            "rule_family": "challenge"})
        self.assertEqual(out["observed_action"], "BLOCK_403")
        self.assertEqual(judge_case(doc, "PROTECT", out)["status"], "PASS")

    def test_clearance_accepted_not_detection(self):
        rid = f"{RID}-WAF-BEN-TST-001-01-rty"
        client = FakeApiClient(acc={rid: [
            {"id": "a3", "event_type": "BOT_CLEARANCE_ACCEPTED", "action": "PASS",
             "response_status": 200, "request_path": "/"}]})
        obs = _obs(status=200, origin=True)
        obs["perf"] = [
            {"request_id": f"{RID}-WAF-BEN-TST-001-01", "seq": 1, "kind": "step",
             "status": 403, "latency_ms": 1.0, "origin_reached": False},
            {"request_id": f"{RID}-WAF-BEN-TST-001-01-vfy", "seq": 1, "kind": "verify",
             "status": 204, "latency_ms": 1.0, "origin_reached": False},
            {"request_id": rid, "seq": 1, "kind": "retry",
             "status": 200, "latency_ms": 1.0, "origin_reached": True},
        ]
        doc = _case({"module": "none"}, "PASS")
        out = reconcile_mod.reconcile_case(client, doc, obs, grace_ms=0)
        self.assertFalse(out["detection"]["detected"])
        self.assertEqual(out["observed_action"], "PASS")
        self.assertEqual(out["reconciliation"]["verdict_request_id"], rid)
        self.assertEqual(judge_case(doc, "PROTECT", out)["status"], "PASS")

    def test_tombstone_local_reject(self):
        obs = _obs(status=405, origin=False)
        doc = p1fixture.minimal_case_doc("BOT-UNK-TST-001", "UNKNOWN")
        doc["steps"] = [{"step_id": "s1", "action": "http_request",
                         "request": {"method": "GET", "path": "/_wdsp/bot/v1/verify"},
                         "wait": None, "assert": []}]
        for prof in doc["expectations_by_profile"].values():
            prof["expected_detection"] = {"module": "bot", "rule_family": "tombstone"}
            prof["expected_final_action"] = "LOCAL_REJECT"
            prof["expected_origin"] = "not_reached"
        obs["case_id"] = "BOT-UNK-TST-001"
        out = reconcile_mod.reconcile_case(FakeApiClient(), doc, obs, grace_ms=0)
        self.assertEqual(out["detection"]["rule_family"], "tombstone")
        self.assertEqual(out["observed_action"], "LOCAL_REJECT")
        self.assertEqual(judge_case(doc, "PROTECT", out)["status"], "PASS")


class TestEnvDescriptor(unittest.TestCase):
    def test_missing_file_rejected(self):
        with self.assertRaises(executor_mod.ExecutorError):
            executor_mod.load_env_descriptor("/nonexistent/env.json")

    def test_kind_and_fields_validated(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "env.json"
            p.write_text(json.dumps({"kind": "other"}), encoding="utf-8")
            with self.assertRaises(executor_mod.ExecutorError):
                executor_mod.load_env_descriptor(p)
            p.write_text(json.dumps({"kind": "p1reg_stage5_env", "api_url": "http://x",
                                     "sec_cookie": "c", "origin_mark": "m",
                                     "profiles": {"OBSERVE": {"host": "h"}}}),
                         encoding="utf-8")
            desc = executor_mod.load_env_descriptor(p)
            self.assertEqual(desc["origin_mark"], "m")

    def test_public_summary_redacts_cookie(self):
        desc = {"kind": "p1reg_stage5_env", "api_url": "http://x",
                "sec_cookie": "session=SECRET", "origin_mark": "m",
                "profiles": {"OBSERVE": {"host": "h", "app_id": "a", "app_code": "c"}},
                "custom_rule_families": {"7100001": "webshell_uploads"},
                "allowed_targets": ["h"], "stack": {"stack_id": "s"}}
        summary = json.dumps(executor_mod.env_public_summary(desc))
        self.assertNotIn("SECRET", summary)
        self.assertNotIn("sec_cookie", summary)


if __name__ == "__main__":
    unittest.main()
