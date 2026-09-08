"""p1reg CLI 与回归 run 报告测试（含篡改检测演示与 compare 退出码）。"""

from __future__ import annotations

import json
import shutil
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
from p1reg import cli, report as report_mod  # noqa: E402
from p1reg import replayplan  # noqa: E402
from p1reg import corpus as corpus_mod  # noqa: E402

BENIGN = p1fixture.minimal_case_doc("WAF-BEN-TST-001", "BENIGN")
ATTACK = p1fixture.minimal_case_doc("WAF-ATK-TST-001", "ATTACK")
RID_B = p1fixture.VALID_RUN_ID
RID_C = p1fixture.VALID_RUN_ID_B


class CliFixture(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.root = Path(self._td.name)

    def copy_repo_corpus(self) -> Path:
        dst = self.root / "corpus"
        shutil.copytree(p1fixture.REPO_MANIFEST.parent, dst)
        return dst / "manifest.json"


class TestCliCorpus(CliFixture):
    def test_validate_repo_corpus_ok(self):
        rc = cli.main(["validate-corpus", "--manifest", str(p1fixture.REPO_MANIFEST),
                       "--profiles-dir", str(p1fixture.PROFILES_DIR)])
        self.assertEqual(rc, 0)

    def test_tampered_copy_exit_2(self):
        mp = self.copy_repo_corpus()
        case_file = mp.parent / "cases" / "waf-ben-sql-001.json"
        raw = case_file.read_bytes()
        case_file.write_bytes(raw[:-2] + b" }\n")
        rc = cli.main(["validate-corpus", "--manifest", str(mp)])
        self.assertEqual(rc, 2)

    def test_validate_run_plan_example_ok(self):
        rc = cli.main(["validate-run-plan", "--plan", str(p1fixture.RUN_PLAN_EXAMPLE),
                       "--profiles-dir", str(p1fixture.PROFILES_DIR)])
        self.assertEqual(rc, 0)

    def test_validate_run_id_rejects_traversal(self):
        self.assertEqual(cli.main(["validate-run-id", "--run-id", "../../etc"]), 2)
        self.assertEqual(cli.main(["validate-run-id", "--run-id", RID_B]), 0)

    def test_gen_plan_deterministic(self):
        argv = ["gen-plan", "--manifest", str(p1fixture.REPO_MANIFEST),
                "--profiles-dir", str(p1fixture.PROFILES_DIR), "--seed", "7"]
        import io
        from contextlib import redirect_stdout

        buf_a, buf_b = io.StringIO(), io.StringIO()
        with redirect_stdout(buf_a):
            self.assertEqual(cli.main(argv), 0)
        with redirect_stdout(buf_b):
            self.assertEqual(cli.main(argv), 0)
        self.assertEqual(buf_a.getvalue(), buf_b.getvalue())
        plan = json.loads(buf_a.getvalue())
        self.assertEqual(plan["kind"], replayplan.PLAN_KIND)

    def test_init_cases_not_run_skeleton(self):
        corpus = corpus_mod.require_valid_corpus(p1fixture.REPO_MANIFEST)
        plan = replayplan.generate_plan(corpus, ("OBSERVE", "PROTECT"), 7, RID_B)
        pp = self.root / "replay-plan.json"
        pp.write_text(json.dumps(plan), encoding="utf-8")
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            self.assertEqual(cli.main(["init-cases", "--replay-plan", str(pp)]), 0)
        rows = [json.loads(ln) for ln in buf.getvalue().splitlines() if ln.strip()]
        self.assertEqual(len(rows), 36)
        for r in rows:
            self.assertEqual(r["status"], "NOT_RUN")
            self.assertFalse(r["executed"])


class TestCliCompare(CliFixture):
    def test_compare_pass_exit_0(self):
        rb = [p1fixture.make_judge_row(BENIGN, "OBSERVE", p1fixture.make_observation(BENIGN, "OBSERVE"))]
        rc = [p1fixture.make_judge_row(BENIGN, "OBSERVE", p1fixture.make_observation(BENIGN, "OBSERVE"))]
        b = p1fixture.write_run_dir(self.root, RID_B, rb)
        c = p1fixture.write_run_dir(self.root, RID_C, rc)
        out = self.root / "out"
        self.assertEqual(cli.main(["compare", "--baseline", str(b), "--candidate", str(c),
                                   "--out", str(out)]), 0)
        doc = json.loads((out / "compare.json").read_text(encoding="utf-8"))
        self.assertEqual(doc["verdict"], "PASS")

    def test_compare_fail_exit_1(self):
        rb = [p1fixture.make_judge_row(ATTACK, "PROTECT", p1fixture.make_observation(ATTACK, "PROTECT"))]
        obs = p1fixture.make_observation(ATTACK, "PROTECT")
        obs["detection"] = {"detected": False, "module": None, "rule_family": None}
        obs["observed_action"] = "PASS"
        obs["origin_reached"] = True
        rc = [p1fixture.make_judge_row(ATTACK, "PROTECT", obs)]
        b = p1fixture.write_run_dir(self.root, RID_B, rb)
        c = p1fixture.write_run_dir(self.root, RID_C, rc)
        self.assertEqual(cli.main(["compare", "--baseline", str(b), "--candidate", str(c)]), 1)

    def test_compare_missing_dir_exit_2(self):
        self.assertEqual(cli.main(["compare", "--baseline", str(self.root / "nope"),
                                   "--candidate", str(self.root / "nope2")]), 2)


class TestRunReport(CliFixture):
    def _write_blocked_run(self) -> Path:
        rows = []
        corpus = corpus_mod.require_valid_corpus(p1fixture.REPO_MANIFEST)
        plan = replayplan.generate_plan(corpus, ("OBSERVE", "PROTECT"), 7, RID_B)
        for e in plan["entries"]:
            doc = corpus["cases"][e["case_id"]]["doc"]
            from p1reg.judge import judge_case

            rows.append(judge_case(doc, e["profile"], None))
        d = p1fixture.write_run_dir(
            self.root, RID_B, rows,
            status_records={
                "regression-plan": {"status": "PASS", "mandatory": True, "reason": "夹具", "evidence": ""},
                "corpus-validation": {"status": "PASS", "mandatory": True, "reason": "夹具", "evidence": ""},
                "regression-execution": {"status": "BLOCKED", "mandatory": True,
                                         "reason": "ENVIRONMENT_UNAVAILABLE：夹具", "evidence": ""},
            },
            with_replay_plan=True, planned_counts={"OBSERVE": 18, "PROTECT": 18})
        return d

    def test_blocked_run_not_passed(self):
        d = self._write_blocked_run()
        run = report_mod.load_regression_run(d)
        verdict, reasons = report_mod.overall_verdict(run)
        self.assertEqual(verdict, "NOT_PASSED")
        self.assertTrue(any("执行数量不足" in r for r in reasons))
        md = report_mod.render_markdown(run)
        self.assertIn("**NOT_PASSED**", md)
        self.assertIn("NOT_RUN", md)

    def test_all_pass_run_passes(self):
        rows = [
            p1fixture.make_judge_row(BENIGN, "OBSERVE", p1fixture.make_observation(BENIGN, "OBSERVE")),
            p1fixture.make_judge_row(BENIGN, "PROTECT", p1fixture.make_observation(BENIGN, "PROTECT")),
        ]
        d = p1fixture.write_run_dir(self.root, RID_B, rows, with_replay_plan=True,
                                    planned_counts={"OBSERVE": 1, "PROTECT": 1})
        run = report_mod.load_regression_run(d)
        verdict, reasons = report_mod.overall_verdict(run)
        self.assertEqual(verdict, "PASS", reasons)
        out = report_mod.write_report(d)
        self.assertTrue(out.is_file())

    def test_missing_artifacts_reported(self):
        d = p1fixture.write_run_dir(
            self.root, RID_B,
            [p1fixture.make_judge_row(BENIGN, "OBSERVE", p1fixture.make_observation(BENIGN, "OBSERVE"))])
        run = report_mod.load_regression_run(d)
        self.assertTrue(any("replay-plan.json" in e for e in run["integrity_errors"]))
        verdict, _ = report_mod.overall_verdict(run)
        self.assertEqual(verdict, "NOT_PASSED")

    def test_mandatory_skip_not_passed(self):
        d = p1fixture.write_run_dir(
            self.root, RID_B,
            [p1fixture.make_judge_row(BENIGN, "OBSERVE", p1fixture.make_observation(BENIGN, "OBSERVE"))],
            status_records={"regression-execution": {"status": "SKIP", "mandatory": True,
                                                     "reason": "偷懒", "evidence": ""}},
            with_replay_plan=True, planned_counts={"OBSERVE": 1})
        run = report_mod.load_regression_run(d)
        verdict, reasons = report_mod.overall_verdict(run)
        self.assertEqual(verdict, "NOT_PASSED")
        self.assertTrue(any("SKIP" in r for r in reasons))

    def test_cli_write_report(self):
        d = self._write_blocked_run()
        self.assertEqual(cli.main(["write-report", "--run-dir", str(d)]), 0)
        self.assertTrue((d / "report.md").is_file())


if __name__ == "__main__":
    unittest.main()
