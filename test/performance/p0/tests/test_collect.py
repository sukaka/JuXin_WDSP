"""采集器与事件对账测试（§6.1/§6.2，BENCH-08 的可单测部分）。"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

P0_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(P0_DIR))

from p0bench.collectors import (  # noqa: E402
    CollectorError,
    parse_ab_output,
    parse_docker_stats_jsonl,
    summarize_curl_tsv,
)
from p0bench.reconcile import permanent_loss, reconcile_events  # noqa: E402

import collect  # noqa: E402  # collect.py（采集 CLI）的纯函数直接单测


class TestDeriveObservedAction(unittest.TestCase):
    """truthbuild 观测归类：JWT PROTECT 的 401 必须归为 BLOCK_401（非 UNEXPECTED_ERROR）。"""

    def test_status_mapping(self):
        self.assertEqual(collect._derive_observed_action(None, False, False), "UNEXPECTED_ERROR")
        self.assertEqual(collect._derive_observed_action(403, False, True), "BLOCK_403")
        self.assertEqual(collect._derive_observed_action(401, False, False), "BLOCK_401")
        self.assertEqual(collect._derive_observed_action(429, False, False), "RATE_LIMIT_429")
        self.assertEqual(collect._derive_observed_action(200, True, False), "PASS")
        self.assertEqual(collect._derive_observed_action(200, True, True), "DETECT_PASS")
        self.assertEqual(collect._derive_observed_action(500, False, False), "UNEXPECTED_ERROR")

AB_SAMPLE = """
This is ApacheBench, Version 2.3
Complete requests:      1000
Failed requests:        2
Non-2xx responses:      5
Requests per second:    512.34 [#/sec] (mean)
Time per request:       19.517 [ms] (mean)
Time per request:       1.952 [ms] (mean, across all concurrent requests)
Transfer rate:          204.93 [Kbytes/sec] received

Percentage of the requests served within a certain time (ms)
  50%     12
  95%     48
  99%     90
 100%    120 (longest request)
"""


class TestAbParsing(unittest.TestCase):
    def test_parse_ab(self):
        out = parse_ab_output(AB_SAMPLE)
        self.assertEqual(out["complete_requests"], 1000)
        self.assertEqual(out["failed_requests"], 2)
        self.assertEqual(out["non_2xx_responses"], 5)
        self.assertAlmostEqual(out["requests_per_second"], 512.34)
        self.assertEqual(out["percentile_table_ms"][95], 48)
        self.assertEqual(out["percentile_table_ms"][99], 90)
        # (mean, across all) 行不得覆盖单行 mean
        self.assertAlmostEqual(out["time_per_request_ms_mean"], 19.517)

    def test_parse_ab_rejects_garbage(self):
        with self.assertRaises(CollectorError):
            parse_ab_output("hello world")
        with self.assertRaises(CollectorError):
            parse_ab_output("Requests per second: 1.0 [#/sec] (mean)\n")


class TestCurlTsv(unittest.TestCase):
    def test_summarize(self):
        lines = [
            "r-0001\t200\t0.012\t127.0.0.1\n",
            "r-0002\t403\t0.010\t127.0.0.1\n",  # 预期 403 单列
            "r-0003\t429\t0.010\t127.0.0.1\n",
            "r-0004\t500\t0.100\t127.0.0.1\n",  # 非预期错误
            "r-0005\t000\t0.000\t-\n",          # 连接失败
            "garbage-line\n",
        ]
        s = summarize_curl_tsv(lines)
        self.assertEqual(s["offered"], 6)
        self.assertEqual(s["completed"], 4)
        self.assertEqual(s["error_classes"]["expected_security"], 2)
        self.assertEqual(s["error_classes"]["unexpected_error"], 1)
        self.assertEqual(s["error_classes"]["connection_error"], 1)
        self.assertEqual(s["error_classes"]["ok"], 1)
        self.assertEqual(s["unparseable_lines"], 1)
        self.assertEqual(len(s["latency_ms_samples"]), 4)


class TestDockerStats(unittest.TestCase):
    def test_parse(self):
        lines = [
            '{"Name":"p0bench-x-gateway-1","CPUPerc":"12.5%","MemUsage":"128MiB / 4GiB","MemPerc":"3.1%","NetIO":"1MB / 2MB","BlockIO":"0B / 0B","PIDs":"42"}\n',
            "\n",
            '{"Name":"p0bench-x-api-1","CPUPerc":"1.0%","MemUsage":"64MiB / 2GiB","MemPerc":"3.1%"}\n',
        ]
        recs = parse_docker_stats_jsonl(lines)
        self.assertEqual(len(recs), 2)
        self.assertEqual(recs[0]["container"], "p0bench-x-gateway-1")
        self.assertAlmostEqual(recs[0]["cpu_percent"], 12.5)
        self.assertEqual(recs[0]["mem_usage"], "128MiB")

    def test_bad_line_raises(self):
        with self.assertRaises(CollectorError):
            parse_docker_stats_jsonl(["{bad json\n"])


class TestReconcile(unittest.TestCase):
    """BENCH-08：采样/重复/积压的各层数量可解释。"""

    def test_counters(self):
        eligible = ["r1", "r2", "r3", "r4", "r5"]
        generated = ["r1", "r2", "r2", "r3"]        # r2 重复生成
        persisted = ["r1", "r1", "r2"]              # r1 持久化重复；r3 积压 pending
        dropped = ["r5"]                            # 明确丢弃
        r = reconcile_events(eligible, generated, persisted, dropped)
        self.assertEqual(r["eligible"], 5)
        self.assertEqual(r["generated"], 3)
        self.assertEqual(r["persisted_unique"], 2)
        self.assertEqual(r["duplicated"], 1)
        self.assertEqual(r["pending"], 1)           # r3
        self.assertEqual(r["dropped"], 1)           # r5
        self.assertEqual(r["unknown"], 1)           # r4 既未生成也无丢弃记录

    def test_foreign_ids_counted(self):
        r = reconcile_events(["r1"], ["r1", "evil"], ["r1", "evil2"])
        self.assertEqual(r["foreign_generated"], 1)
        self.assertEqual(r["foreign_persisted"], 1)
        self.assertEqual(r["persisted_unique"], 1)

    def test_permanent_loss_requires_catchup(self):
        r = reconcile_events(["r1", "r2"], ["r1"], ["r1"], [])
        self.assertIsNone(permanent_loss(r, catchup_complete=False))
        # 追平后：r2 未持久化且无丢弃记录 → 永久丢失 1
        self.assertEqual(permanent_loss(r, catchup_complete=True), 1)
        r2 = reconcile_events(["r1"], ["r1"], ["r1"], [])
        self.assertEqual(permanent_loss(r2, catchup_complete=True), 0)


if __name__ == "__main__":
    unittest.main()
