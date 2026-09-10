"""Parse and summarize raw ``go test -bench -benchmem`` samples.

The Go benchmark output contains one aggregate sample per ``-count`` run.  It
does not contain request-level observations, so this module reports the
microbenchmark scope explicitly and never presents it as a gateway load-test
result.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

from .metrics import nearest_rank_quantile


class GoBenchmarkError(ValueError):
    """Raised when benchmark output cannot be reviewed without guessing."""


_NUMBER = r"[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?"
_BENCH_LINE = re.compile(
    rf"^(?P<name>Benchmark\S+)\s+"
    rf"(?P<iterations>[0-9]+)\s+"
    rf"(?P<ns>{_NUMBER})\s+ns/op"
    rf"(?:\s+(?P<bytes>{_NUMBER})\s+B/op\s+"
    rf"(?P<allocs>{_NUMBER})\s+allocs/op)?\s*$"
)
_GOMAXPROCS_SUFFIX = re.compile(r"-[0-9]+$")
_AUTHZ_DISABLED = "BenchmarkEvaluateAuthorizationAuthzPair/authz_disabled"
_AUTHZ_ENABLED = "BenchmarkEvaluateAuthorizationAuthzPair/authz_enabled"


def _benchmark_name(name: str) -> str:
    """Remove Go's GOMAXPROCS suffix while preserving sub-benchmark names."""

    return _GOMAXPROCS_SUFFIX.sub("", name)


def parse_go_benchmark_output(text: str, *, require_allocs: bool = True) -> list[dict]:
    """Parse all benchmark rows from raw Go output.

    Lines beginning with ``Benchmark`` must parse successfully.  This avoids
    silently dropping a malformed row and producing an incomplete percentile.
    """

    samples: list[dict] = []
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line:
            continue
        if not line.startswith("Benchmark"):
            continue
        match = _BENCH_LINE.match(line)
        if match is None:
            raise GoBenchmarkError(f"无法解析 Go benchmark 第 {line_number} 行: {line}")
        row = match.groupdict()
        sample = {
            "name": _benchmark_name(row["name"]),
            "iterations": int(row["iterations"]),
            "ns_per_op": float(row["ns"]),
            "bytes_per_op": float(row["bytes"]) if row["bytes"] is not None else None,
            "allocs_per_op": float(row["allocs"]) if row["allocs"] is not None else None,
        }
        if sample["iterations"] <= 0 or sample["ns_per_op"] <= 0:
            raise GoBenchmarkError(f"benchmark 第 {line_number} 行含无效计数或耗时")
        if require_allocs and (
            sample["bytes_per_op"] is None or sample["allocs_per_op"] is None
        ):
            raise GoBenchmarkError(f"benchmark 第 {line_number} 行缺少 -benchmem 分配指标")
        samples.append(sample)

    if not samples:
        raise GoBenchmarkError("输入中没有可解析的 Go benchmark 样本")
    return samples


def _quantiles(values: list[float]) -> dict[str, float]:
    return {
        "p50": nearest_rank_quantile(values, 0.50),
        "p95": nearest_rank_quantile(values, 0.95),
        "p99": nearest_rank_quantile(values, 0.99),
    }


def summarize_go_benchmarks(samples: list[dict]) -> dict:
    """Summarize each benchmark from raw ``-count`` samples.

    ``throughput_ops_per_second`` is the reciprocal of each Go ``ns/op``
    sample.  Its percentile values are therefore derived from the raw samples,
    while the reported central throughput is the median reciprocal.
    """

    groups: dict[str, list[dict]] = defaultdict(list)
    for sample in samples:
        groups[sample["name"]].append(sample)

    summaries = []
    for name in sorted(groups):
        rows = groups[name]
        ns = [row["ns_per_op"] for row in rows]
        throughput = [1_000_000_000.0 / value for value in ns]
        bytes_values = [row["bytes_per_op"] for row in rows if row["bytes_per_op"] is not None]
        alloc_values = [row["allocs_per_op"] for row in rows if row["allocs_per_op"] is not None]
        summary = {
            "name": name,
            "sample_count": len(rows),
            "iterations": [row["iterations"] for row in rows],
            "ns_per_op": _quantiles(ns),
            "throughput_ops_per_second": _quantiles(throughput),
            "bytes_per_op": _quantiles(bytes_values) if bytes_values else None,
            "allocs_per_op": _quantiles(alloc_values) if alloc_values else None,
            "raw_samples": rows,
        }
        summaries.append(summary)

    by_name = {summary["name"]: summary for summary in summaries}
    paired_comparison = None
    if _AUTHZ_DISABLED in by_name and _AUTHZ_ENABLED in by_name:
        disabled_p95 = by_name[_AUTHZ_DISABLED]["ns_per_op"]["p95"]
        enabled_p95 = by_name[_AUTHZ_ENABLED]["ns_per_op"]["p95"]
        delta_ns = enabled_p95 - disabled_p95
        paired_comparison = {
            "baseline": _AUTHZ_DISABLED,
            "candidate": _AUTHZ_ENABLED,
            "p95_ns_per_op_delta": delta_ns,
            "p95_ms_delta": delta_ns / 1_000_000.0,
            "scope": "local_go_microbenchmark",
        }

    return {
        "benchmark_count": len(summaries),
        "sample_count": len(samples),
        "benchmarks": summaries,
        "paired_comparison": paired_comparison,
    }


def _coverage(
    status: str,
    reason: str | None,
    *,
    has_metrics: bool,
    race_status: str = "NOT_RUN",
    race_reason: str | None = None,
    relation_count: int | None = None,
) -> dict:
    """Describe measured dimensions and deliberately unavailable P0 evidence."""

    if has_metrics:
        measured = {"status": "MEASURED"}
        throughput = {
            "status": "MEASURED",
            "definition": "reciprocal of Go ns/op samples",
            "scope": "microbenchmark",
        }
    else:
        unavailable_status = "BLOCKED" if status == "BLOCKED" else "NOT_RUN"
        measured = {"status": unavailable_status, "reason": reason or "NO_INPUT"}
        throughput = dict(measured)
    long_run_status = "BLOCKED" if status == "BLOCKED" else "NOT_RUN"
    long_run_reason = reason if status == "BLOCKED" else "COMPONENT_BENCHMARK_DOES_NOT_START_GATEWAY"
    if status == "BLOCKED":
        race_status = "BLOCKED"
        race_reason = reason or "ENVIRONMENT_UNAVAILABLE"
    return {
        "p95_p99": measured,
        "throughput": throughput,
        "allocations": measured,
        "rss": {"status": long_run_status, "reason": long_run_reason},
        "soak": {"status": long_run_status, "reason": long_run_reason},
        "race": {"status": race_status, "reason": race_reason or "RACE_NOT_REQUESTED"},
    }


def write_report(
    *,
    output: Path,
    status: str,
    scope: str,
    reason: str | None = None,
    input_path: Path | None = None,
    environment_id: str | None = None,
    formal_plan: str | None = None,
    max_p95_delta_ms: float | None = None,
    race_status: str = "NOT_RUN",
    race_reason: str | None = None,
    relation_count: int | None = None,
) -> dict:
    """Write a reviewable JSON artifact for local or formal invocation."""

    if max_p95_delta_ms is not None and max_p95_delta_ms < 0:
        raise ValueError("P95 增量阈值不能为负数")
    if relation_count is not None and (
        isinstance(relation_count, bool) or not isinstance(relation_count, int) or relation_count <= 0
    ):
        raise ValueError("relation_count 必须为正整数")

    report: dict = {
        "schema_version": 1,
        "status": status,
        "scope": scope,
        # A component benchmark is evidence for the formal run, but does not
        # establish the gateway load/soak acceptance criteria by itself.
        "formal_claim": False,
        "formal_component": status == "FORMAL_COMPONENT",
    }
    if reason:
        report["reason"] = reason
    if environment_id:
        report["environment_id"] = environment_id
    if formal_plan:
        report["formal_plan"] = formal_plan
    if input_path is not None:
        text = input_path.read_text(encoding="utf-8")
        report["source"] = {
            "tool": "go test",
            "input": str(input_path),
            "requires_benchmem": True,
            "aggregation": "nearest-rank over raw -count samples",
        }
        report["metrics"] = summarize_go_benchmarks(parse_go_benchmark_output(text))
    if relation_count is not None:
        report["benchmark_fixture"] = {
            "relation_count": relation_count,
            "evidence": "fixed AUTHZ-01 benchmark fixture; verify source before formal acceptance",
            "scope": "component_microbenchmark",
        }
    report["coverage"] = _coverage(
        status,
        reason,
        has_metrics="metrics" in report,
        race_status=race_status,
        race_reason=race_reason,
    )
    comparison = report.get("metrics", {}).get("paired_comparison")
    if max_p95_delta_ms is None:
        report["gates"] = {
            "p95_overhead": {"status": "NOT_RUN", "reason": "THRESHOLD_NOT_PROVIDED"}
        }
    elif comparison is None:
        report["gates"] = {
            "p95_overhead": {"status": "BLOCKED", "reason": "PAIRED_SAMPLES_MISSING"}
        }
    else:
        observed = comparison["p95_ms_delta"]
        report["gates"] = {
            "p95_overhead": {
                "status": "PASS" if observed <= max_p95_delta_ms else "FAIL",
                "max_p95_delta_ms": max_p95_delta_ms,
                "observed_p95_delta_ms": observed,
                "scope": "local_go_microbenchmark",
            }
        }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return report


def _main() -> int:
    parser = argparse.ArgumentParser(description="Summarize raw Go benchmark samples")
    parser.add_argument("--input", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--status", choices=("LOCAL_ONLY", "FORMAL_COMPONENT", "BLOCKED"), default="LOCAL_ONLY")
    parser.add_argument("--scope", default="authz-01-local-microbenchmark")
    parser.add_argument("--reason")
    parser.add_argument("--environment-id")
    parser.add_argument("--formal-plan")
    parser.add_argument(
        "--relation-count",
        type=int,
        help="固定 AUTHZ-01 关系索引 fixture 的关系数；报告中与 raw benchmark 一起留证",
    )
    parser.add_argument(
        "--race-status",
        choices=("NOT_RUN", "PASS", "FAIL", "BLOCKED"),
        default="NOT_RUN",
        help="决策矩阵 -race 验收结果；未请求时保持 NOT_RUN",
    )
    parser.add_argument("--race-reason")
    parser.add_argument(
        "--max-p95-delta-ms",
        type=float,
        help="可选：对 AUTHZ 配对微基准的 P95 增量执行显式门禁（毫秒）",
    )
    args = parser.parse_args()

    if args.status != "BLOCKED" and args.input is None:
        parser.error("非 BLOCKED 报告必须提供 --input")
    try:
        report = write_report(
            output=args.output,
            status=args.status,
            scope=args.scope,
            reason=args.reason,
            input_path=args.input,
            environment_id=args.environment_id,
            formal_plan=args.formal_plan,
            max_p95_delta_ms=args.max_p95_delta_ms,
            race_status=args.race_status,
            race_reason=args.race_reason,
            relation_count=args.relation_count,
        )
    except (OSError, GoBenchmarkError, ValueError) as exc:
        parser.error(str(exc))
    if report.get("metrics"):
        for benchmark in report["metrics"]["benchmarks"]:
            ns = benchmark["ns_per_op"]
            throughput = benchmark["throughput_ops_per_second"]["p50"]
            allocs = benchmark["allocs_per_op"]["p50"] if benchmark["allocs_per_op"] else "N/A"
            bytes_per_op = benchmark["bytes_per_op"]["p50"] if benchmark["bytes_per_op"] else "N/A"
            print(
                f"[go-bench] {benchmark['name']} "
                f"P50/P95/P99={ns['p50']}/{ns['p95']}/{ns['p99']} ns/op "
                f"throughput_p50={throughput} ops/s "
                f"alloc={bytes_per_op} B/op, {allocs} allocs/op"
            )
    gate = report.get("gates", {}).get("p95_overhead", {})
    if gate.get("status") == "FAIL":
        print(
            "[go-bench] FAIL p95 overhead: "
            f"{gate['observed_p95_delta_ms']}ms > {gate['max_p95_delta_ms']}ms",
            file=sys.stderr,
        )
        return 4
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
