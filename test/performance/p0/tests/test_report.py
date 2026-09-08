"""报告生成器测试（BENCH-05/06/07 的可单测部分）。"""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

P0_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(P0_DIR))

from p0bench.report_core import (  # noqa: E402
    aggregate_perf,
    load_run,
    overall_verdict,
    render_markdown,
    write_report,
)


def _write(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False) + "\n", encoding="utf-8")


class RunDirFixture(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.root = Path(self._td.name)
        self.repo = self.root / "repo"
        self.run = self.root / "run"
        self.repo.mkdir()
        self.run.mkdir()
        corpus_content = b'{"schema_version":1}'
        (self.repo / "corpus").mkdir()
        (self.repo / "corpus" / "manifest.json").write_bytes(corpus_content)
        digest = hashlib.sha256(corpus_content).hexdigest()

        plan = json.loads((P0_DIR / "run-plan.example.json").read_text(encoding="utf-8"))
        plan["corpus"] = {
            "manifest_path": "corpus/manifest.json",
            "manifest_sha256": digest,
            "seed": 42,
        }
        _write(self.run / "plan.json", plan)
        _write(self.run / "manifest.json", {"run_id": "20260906T100000-aaaaaa"})
        _write(self.run / "status.json", {"records": {}})

    def add_status(self, tid, status, mandatory=True, reason=""):
        doc = json.loads((self.run / "status.json").read_text(encoding="utf-8"))
        doc["records"][tid] = {"status": status, "mandatory": mandatory, "reason": reason}
        _write(self.run / "status.json", doc)

    def add_truth(self, profile, recs):
        _write(self.run / "truth" / f"{profile}.json", recs)

    def add_perf(self, profile, name, rec):
        _write(self.run / "perf" / profile / f"{name}.json", rec)


class TestAggregatePerf(unittest.TestCase):
    """BENCH-06：聚合分位数来自样本合并，不是平均。"""

    def test_merged_quantiles(self):
        agg = aggregate_perf(
            [
                {"offered": 100, "completed": 100, "latency_ms_samples": [10.0] * 100},
                {"offered": 100, "completed": 100, "latency_ms_samples": [1000.0] * 100},
            ]
        )
        self.assertEqual(agg["p99_ms"], 1000.0)
        self.assertEqual(agg["repeats"], 2)
        self.assertEqual(agg["offered"], 200)

    def test_unexpected_error_rate(self):
        agg = aggregate_perf(
            [
                {
                    "offered": 10,
                    "completed": 10,
                    "latency_ms_samples": [1.0] * 10,
                    "error_classes": {"ok": 8, "expected_security": 1, "unexpected_error": 1},
                }
            ]
        )
        self.assertAlmostEqual(agg["unexpected_error_rate"], 0.1)

    def test_no_samples_returns_none(self):
        agg = aggregate_perf([{"offered": 0, "completed": 0}])
        self.assertIsNone(agg["p99_ms"])
        self.assertEqual(agg["unexpected_error_rate"], "N/A")


class TestReportVerdict(RunDirFixture):
    """BENCH-07：SKIP/缺文件/哈希错误 → 未通过。"""

    def test_all_pass(self):
        self.add_status("BENCH-05", "PASS")
        self.add_status("BENCH-06", "PASS")
        run = load_run(self.run, self.repo)
        verdict, reasons = overall_verdict(run)
        self.assertEqual(verdict, "PASS", reasons)

    def test_mandatory_skip_not_passed(self):
        self.add_status("BENCH-05", "SKIP", reason="环境缺依赖")
        run = load_run(self.run, self.repo)
        verdict, reasons = overall_verdict(run)
        self.assertEqual(verdict, "NOT_PASSED")
        self.assertTrue(any("SKIP" in r for r in reasons))

    def test_fail_is_fail(self):
        self.add_status("BENCH-09", "FAIL", reason="恢复超时")
        run = load_run(self.run, self.repo)
        verdict, _ = overall_verdict(run)
        self.assertEqual(verdict, "FAIL")

    def test_missing_status_file_not_passed(self):
        (self.run / "status.json").unlink()
        run = load_run(self.run, self.repo)
        verdict, reasons = overall_verdict(run)
        self.assertEqual(verdict, "NOT_PASSED")
        self.assertTrue(any("缺失" in r for r in run["integrity_errors"]))

    def test_corpus_hash_mismatch_not_passed(self):
        (self.repo / "corpus" / "manifest.json").write_bytes(b'{"tampered":true}')
        run = load_run(self.run, self.repo)
        verdict, _ = overall_verdict(run)
        self.assertEqual(verdict, "NOT_PASSED")
        self.assertTrue(any("哈希不匹配" in e for e in run["integrity_errors"]))

    def test_no_records_not_passed(self):
        run = load_run(self.run, self.repo)
        verdict, reasons = overall_verdict(run)
        self.assertEqual(verdict, "NOT_PASSED")
        self.assertTrue(any("无" in r for r in reasons))


class TestReportRendering(RunDirFixture):
    def test_seven_profiles_shown_with_not_run(self):
        self.add_status("BENCH-05", "PASS")
        # 只给一个 profile 数据，其余必须显示 NOT_RUN
        self.add_perf("proxy", "r1-100rps-ab", {
            "offered": 100, "completed": 100, "latency_ms_samples": [5.0] * 100,
        })
        self.add_status("matrix:waf_protect", "BLOCKED", reason="模式切换失败")
        run = load_run(self.run, self.repo)
        md = render_markdown(run)
        self.assertIn("| proxy | 1 | 100 | 100 |", md)
        self.assertIn("| waf_protect | BLOCKED |", md)
        self.assertIn("| api_observe | NOT_RUN |", md)
        self.assertIn("combined_protect", md)
        # 72h 长稳缺失必须显示 NOT_RUN
        self.assertIn("NOT_RUN（无 soak/ 记录", md)

    def test_na_rendering_for_zero_denominator(self):
        self.add_status("BENCH-05", "PASS")
        self.add_truth("proxy", [
            {"case_id": "N-1", "label": "normal", "detected": False,
             "observed_action": "PASS", "expected_action": "PASS", "valid": True,
             "deferred": False},
        ])
        run = load_run(self.run, self.repo)
        md = render_markdown(run)
        self.assertIn("N/A", md)
        section = md.split("安全正确性")[1].split("##")[0]
        # 零分母类别（检测/拦截漏报）必须渲染 N/A；非零分母的 0/1 (0.000%) 是合法真实值
        self.assertIn("0/0 (N/A)", section)
        proxy_row = [ln for ln in section.splitlines() if ln.startswith("| proxy")][0]
        cells = [c.strip() for c in proxy_row.split("|")]
        self.assertEqual(cells[4], "0/0 (N/A)")  # 检测漏报
        self.assertEqual(cells[5], "0/0 (N/A)")  # 拦截漏报

    def test_report_file_written_readonly_source(self):
        self.add_status("BENCH-05", "PASS")
        before = {p.name for p in self.run.iterdir()}
        out = write_report(self.run, self.repo)
        self.assertTrue(out.is_file())
        after = {p.name for p in self.run.iterdir()}
        self.assertEqual(after - before, {"report.md"}, "报告生成只新增 report.md")
        text = out.read_text(encoding="utf-8")
        self.assertIn("**PASS**", text)

    def test_deterministic_output(self):
        self.add_status("BENCH-05", "PASS")
        run = load_run(self.run, self.repo)
        self.assertEqual(render_markdown(run), render_markdown(run))


class TestJwtPairRendering(RunDirFixture):
    """JWT-18 配对 profile：有数据/状态时渲染配对行，无配对运行时报告保持纯七模式。"""

    def test_pair_rows_rendered_when_present(self):
        self.add_status("BENCH-05", "PASS")
        self.add_truth("jwt_off", [
            {"case_id": "A-JWT-01", "label": "attack", "detected": False,
             "observed_action": "PASS", "expected_action": "PASS", "valid": True,
             "deferred": False},
        ])
        self.add_truth("jwt_protect", [
            {"case_id": "A-JWT-01", "label": "attack", "detected": True,
             "observed_action": "BLOCK_401", "expected_action": "BLOCK_401", "valid": True,
             "deferred": False},
        ])
        self.add_perf("jwt_protect", "r1-100rps-ab", {
            "offered": 50, "completed": 50, "latency_ms_samples": [3.0] * 50,
        })
        run = load_run(self.run, self.repo)
        self.assertIn("jwt_protect", run["truth_metrics"])
        self.assertIn("jwt_protect", run["perf"])
        md = render_markdown(run)
        self.assertIn("| jwt_protect |", md)
        self.assertIn("| jwt_off |", md)
        self.assertIn("JWT-18 配对", md)
        # BLOCK_401 指标：jwt_protect 检测/拦截漏报分母各 1、无漏报
        tm = run["truth_metrics"]["jwt_protect"]
        self.assertEqual(tm["block_miss"]["denominator"], 1)
        self.assertEqual(tm["block_miss"]["count"], 0)

    def test_pair_status_blocked_rendered(self):
        self.add_status("correctness:jwt_protect", "BLOCKED",
                        reason="JWT 配对模式切换/生效验证失败", mandatory=False)
        run = load_run(self.run, self.repo)
        md = render_markdown(run)
        self.assertIn("| jwt_protect | BLOCKED |", md)

    def test_no_pair_data_keeps_pure_seven_mode_report(self):
        self.add_status("BENCH-05", "PASS")
        run = load_run(self.run, self.repo)
        md = render_markdown(run)
        self.assertNotIn("jwt_off", md)
        self.assertNotIn("jwt_protect", md)


if __name__ == "__main__":
    unittest.main()
