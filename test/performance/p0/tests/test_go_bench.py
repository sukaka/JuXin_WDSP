"""Raw Go benchmark parser and P0-02 reporting tests."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

P0_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(P0_DIR))

from p0bench.go_bench import (  # noqa: E402
    GoBenchmarkError,
    parse_go_benchmark_output,
    summarize_go_benchmarks,
    write_report,
)


class TestGoBenchmarkParser(unittest.TestCase):
    def test_parses_count_samples_and_strips_gomaxprocs_suffix(self):
        text = """goos: darwin
goarch: arm64
BenchmarkEvaluateAuthorizationAuthzPair/authz_enabled-10  10  100 ns/op  32 B/op  1 allocs/op
BenchmarkEvaluateAuthorizationAuthzPair/authz_enabled-10  10  200 ns/op  64 B/op  2 allocs/op
BenchmarkEvaluateAuthorizationAuthzPair/authz_enabled-10  10  300 ns/op  96 B/op  3 allocs/op
PASS
"""
        samples = parse_go_benchmark_output(text)
        self.assertEqual(len(samples), 3)
        self.assertEqual(samples[0]["name"], "BenchmarkEvaluateAuthorizationAuthzPair/authz_enabled")
        self.assertEqual(samples[2]["bytes_per_op"], 96.0)

    def test_malformed_benchmark_row_is_rejected(self):
        with self.assertRaises(GoBenchmarkError):
            parse_go_benchmark_output("BenchmarkBroken-8  10  nope ns/op  1 B/op 1 allocs/op\n")

    def test_missing_benchmem_is_rejected_by_default(self):
        with self.assertRaises(GoBenchmarkError):
            parse_go_benchmark_output("BenchmarkFoo-8  10  100 ns/op\n")

    def test_scientific_notation_and_optional_allocs(self):
        text = "BenchmarkFoo-8  10  1.5e+03 ns/op  2.5e+01 B/op  2e+00 allocs/op\n"
        sample = parse_go_benchmark_output(text)[0]
        self.assertEqual(sample["ns_per_op"], 1500.0)
        self.assertEqual(sample["bytes_per_op"], 25.0)
        self.assertEqual(sample["allocs_per_op"], 2.0)


class TestGoBenchmarkSummary(unittest.TestCase):
    def test_quantiles_throughput_and_allocations_use_raw_samples(self):
        text = "\n".join(
            [
                "BenchmarkFoo-8  10  100 ns/op  10 B/op  1 allocs/op",
                "BenchmarkFoo-8  10  200 ns/op  20 B/op  2 allocs/op",
                "BenchmarkFoo-8  10  300 ns/op  30 B/op  3 allocs/op",
                "BenchmarkFoo-8  10  400 ns/op  40 B/op  4 allocs/op",
            ]
        )
        summary = summarize_go_benchmarks(parse_go_benchmark_output(text))["benchmarks"][0]
        self.assertEqual(summary["sample_count"], 4)
        self.assertEqual(summary["ns_per_op"], {"p50": 200.0, "p95": 400.0, "p99": 400.0})
        self.assertAlmostEqual(summary["throughput_ops_per_second"]["p50"], 3_333_333.3333333335)
        self.assertEqual(summary["bytes_per_op"]["p95"], 40.0)
        self.assertEqual(summary["allocs_per_op"]["p99"], 4.0)

    def test_authz_pair_reports_p95_overhead(self):
        text = "\n".join(
            [
                "BenchmarkEvaluateAuthorizationAuthzPair/authz_disabled-8  1  100 ns/op  10 B/op  1 allocs/op",
                "BenchmarkEvaluateAuthorizationAuthzPair/authz_enabled-8  1  300 ns/op  20 B/op  2 allocs/op",
            ]
        )
        comparison = summarize_go_benchmarks(parse_go_benchmark_output(text))["paired_comparison"]
        self.assertEqual(comparison["p95_ns_per_op_delta"], 200.0)
        self.assertAlmostEqual(comparison["p95_ms_delta"], 0.0002)

    def test_report_preserves_scope_and_writes_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            raw = root / "raw.txt"
            report_path = root / "report.json"
            raw.write_text("BenchmarkFoo-8  1  100 ns/op  0 B/op  0 allocs/op\n", encoding="utf-8")
            report = write_report(
                output=report_path,
                status="LOCAL_ONLY",
                scope="authz-01-local-short",
                input_path=raw,
                reason="LOCAL_SHORT_TEST_ONLY",
                max_p95_delta_ms=0.0002,
                relation_count=200_000,
            )
            self.assertEqual(report["status"], "LOCAL_ONLY")
            self.assertFalse(report["formal_claim"])
            self.assertFalse(report["formal_component"])
            self.assertEqual(json.loads(report_path.read_text(encoding="utf-8"))["metrics"]["sample_count"], 1)
            self.assertEqual(report["coverage"]["rss"]["status"], "NOT_RUN")
            self.assertEqual(report["coverage"]["soak"]["status"], "NOT_RUN")
            self.assertEqual(report["coverage"]["race"]["status"], "NOT_RUN")
            self.assertEqual(report["gates"]["p95_overhead"]["status"], "BLOCKED")
            self.assertEqual(report["benchmark_fixture"]["relation_count"], 200_000)

    def test_report_records_race_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            raw = root / "raw.txt"
            raw.write_text("BenchmarkFoo-8  1  100 ns/op  0 B/op  0 allocs/op\n", encoding="utf-8")
            report = write_report(
                output=root / "race.json",
                status="LOCAL_ONLY",
                scope="authz-01-local-short",
                input_path=raw,
                race_status="PASS",
                race_reason="RACE_DECISION_MATRIX_PASS",
            )
            self.assertEqual(report["coverage"]["race"], {
                "status": "PASS", "reason": "RACE_DECISION_MATRIX_PASS"
            })

    def test_p95_gate_passes_or_fails_only_when_explicitly_requested(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            raw = root / "raw.txt"
            raw.write_text(
                "\n".join(
                    [
                        "BenchmarkEvaluateAuthorizationAuthzPair/authz_disabled-8  1  100 ns/op  10 B/op  1 allocs/op",
                        "BenchmarkEvaluateAuthorizationAuthzPair/authz_enabled-8  1  300 ns/op  20 B/op  2 allocs/op",
                    ]
                ),
                encoding="utf-8",
            )
            passing = write_report(
                output=root / "pass.json",
                status="LOCAL_ONLY",
                scope="authz-01-local-short",
                input_path=raw,
                max_p95_delta_ms=0.0002,
            )
            failing = write_report(
                output=root / "fail.json",
                status="LOCAL_ONLY",
                scope="authz-01-local-short",
                input_path=raw,
                max_p95_delta_ms=0.0001,
            )
            self.assertEqual(passing["gates"]["p95_overhead"]["status"], "PASS")
            self.assertEqual(failing["gates"]["p95_overhead"]["status"], "FAIL")

    def test_negative_p95_gate_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            raw = Path(tmp) / "raw.txt"
            raw.write_text("BenchmarkFoo-8  1  100 ns/op  0 B/op  0 allocs/op\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                write_report(
                    output=Path(tmp) / "report.json",
                    status="LOCAL_ONLY",
                    scope="authz-01-local-short",
                    input_path=raw,
                    max_p95_delta_ms=-1,
                )

    def test_blocked_report_does_not_fabricate_measurements(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = write_report(
                output=Path(tmp) / "blocked.json",
                status="BLOCKED",
                scope="authz-01-formal",
                reason="ENVIRONMENT_UNAVAILABLE",
            )
            self.assertEqual(report["status"], "BLOCKED")
            self.assertNotIn("metrics", report)
            self.assertEqual(report["coverage"]["rss"]["status"], "BLOCKED")
            self.assertEqual(report["coverage"]["soak"]["status"], "BLOCKED")
            self.assertEqual(report["coverage"]["race"]["status"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
