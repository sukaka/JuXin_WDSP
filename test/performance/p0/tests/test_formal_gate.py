"""P0-02 正式环境门禁的可审计行为测试。"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

P0_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(P0_DIR))

from p0bench.cli import main  # noqa: E402
from p0bench.formal_gate import evaluate, write_evidence  # noqa: E402


class TestFormalGate(unittest.TestCase):
    def setUp(self):
        self.plan = {"environment": {"environment_id": "dedicated-host-001"}}

    def test_matching_explicit_declaration_is_ready(self):
        result = evaluate(self.plan, "1", "dedicated-host-001")
        self.assertEqual(result["status"], "READY")
        self.assertTrue(result["formal_claim"])
        self.assertEqual(result["details"], [])

    def test_missing_declaration_is_blocked_without_formal_claim(self):
        result = evaluate(self.plan, "0", "")
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["reason"], "ENVIRONMENT_UNAVAILABLE")
        self.assertFalse(result["formal_claim"])
        self.assertIsNone(result["runtime_environment_id"])

    def test_environment_id_mismatch_is_blocked(self):
        result = evaluate(self.plan, "1", "shared-dev-host")
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn("不一致", " ".join(result["details"]))

    def test_evidence_is_machine_readable_and_contains_no_extra_environment_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_evidence(Path(tmp) / "formal-environment.json", evaluate(self.plan, "0", ""))
            evidence = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(evidence["reason"], "ENVIRONMENT_UNAVAILABLE")
            self.assertEqual(set(evidence), {
                "details", "formal_claim", "plan_environment_id", "ready_assertion",
                "reason", "runtime_environment_id", "status",
            })

    def test_cli_uses_blocked_exit_code_and_writes_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan = root / "plan.json"
            evidence = root / "formal-environment.json"
            plan.write_text(json.dumps(self.plan), encoding="utf-8")
            rc = main([
                "formal-gate", "--plan", str(plan), "--ready", "0",
                "--environment-id", "", "--evidence", str(evidence),
            ])
            self.assertEqual(rc, 3)
            self.assertEqual(json.loads(evidence.read_text(encoding="utf-8"))["status"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
