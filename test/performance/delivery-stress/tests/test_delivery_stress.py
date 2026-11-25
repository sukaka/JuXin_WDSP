#!/usr/bin/env python3
"""交付压测脚本包单元测试：校验事件对账、二分搜索、带压安全评分卡、RFC 9411 报告汇总、证书生成与脚本语法。"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import tempfile
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS_DIR = os.path.join(BASE_DIR, "scripts")
CORPUS_PATH = os.path.join(BASE_DIR, "corpus", "owasp-security-corpus.json")


def load_module(name: str, filename: str):
    path = os.path.join(SCRIPTS_DIR, filename)
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


reconcile = load_module("reconcile_events", "reconcile-events.py")
summarize = load_module("summarize_run", "summarize-run.py")
binsearch = load_module("binary_search", "binary-search.py")
secload = load_module("security_under_load", "security-under-load.py")
l4tp = load_module("l4_throughput", "l4-throughput.py")


class TestL4Throughput(unittest.TestCase):
    def test_parse_tcp_forward_and_bidir_and_udp(self):
        tcp_raw = {
            "start": {
                "connected": [{"remote_host": "10.10.1.20", "remote_port": 5201}],
                "tcp_mss_default": 1448,
                "test_start": {"protocol": "TCP", "num_streams": 16, "blksize": 131072, "duration": 30, "omit": 5, "bidir": 1},
            },
            "end": {
                "sum_sent": {"seconds": 30.0, "bytes": 34650000000, "bits_per_second": 9240000000.0, "retransmits": 0},
                "sum_received": {"seconds": 30.0, "bytes": 34650000000, "bits_per_second": 9240000000.0},
                "sum_sent_bidir_reverse": {"seconds": 30.0, "bytes": 34425000000, "bits_per_second": 9180000000.0, "retransmits": 0},
                "sum_received_bidir_reverse": {"seconds": 30.0, "bytes": 34425000000, "bits_per_second": 9180000000.0},
                "cpu_utilization_percent": {"host_total": 32.5, "remote_total": 35.1},
            },
        }
        res = l4tp.parse_iperf3_json(tcp_raw, mode="routed_forward")
        self.assertEqual(res["config"]["proto"], "tcp")
        self.assertEqual(res["config"]["direction"], "bidir")
        self.assertEqual(res["summary"]["throughput_gbps"], 18.42)
        self.assertEqual(res["summary"]["tx_gbps"], 9.24)
        self.assertEqual(res["summary"]["rx_gbps"], 9.18)
        self.assertTrue(res["summary"]["zero_loss_pass"])
        self.assertGreater(res["summary"]["pps"], 1_000_000)

        udp_raw = {
            "start": {"test_start": {"protocol": "UDP", "num_streams": 8, "blksize": 1400, "duration": 30, "omit": 5}},
            "end": {
                "sum_received": {
                    "seconds": 30.0,
                    "bytes": 34200000000,
                    "bits_per_second": 9120000000.0,
                    "jitter_ms": 0.082,
                    "lost_packets": 0,
                    "packets": 24428571,
                    "lost_percent": 0.0,
                }
            },
        }
        ures = l4tp.parse_iperf3_json(udp_raw, mode="transparent_bridge")
        self.assertEqual(ures["config"]["proto"], "udp")
        self.assertEqual(ures["summary"]["throughput_gbps"], 9.12)
        self.assertEqual(ures["summary"]["udp_loss_pct"], 0.0)
        self.assertTrue(ures["summary"]["zero_loss_pass"])

    def test_cli_parse_raw_json_and_help(self):
        script = os.path.join(SCRIPTS_DIR, "l4-throughput.py")
        proc = subprocess.run(["python3", script, "--help"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        with tempfile.TemporaryDirectory() as td:
            raw_p = os.path.join(td, "raw-iperf.json")
            out_p = os.path.join(td, "l4-norm.json")
            with open(raw_p, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "start": {"test_start": {"protocol": "TCP", "num_streams": 8, "blksize": 65536, "duration": 10}},
                        "end": {
                            "sum_sent": {"seconds": 10.0, "bytes": 11750000000, "bits_per_second": 9400000000.0, "retransmits": 0},
                            "sum_received": {"seconds": 10.0, "bytes": 11750000000, "bits_per_second": 9400000000.0},
                        },
                    },
                    f,
                )
            rc = l4tp.main(["--parse-raw-json", raw_p, "--mode", "direct_baseline", "--out-json", out_p])
            self.assertEqual(rc, 0)
            with open(out_p, "r", encoding="utf-8") as f:
                doc = json.load(f)
            self.assertEqual(doc["summary"]["throughput_gbps"], 9.4)
            self.assertTrue(doc["summary"]["zero_loss_pass"])


class TestReconcileEvents(unittest.TestCase):
    def test_parse_checkpoint_offset_formats(self):
        self.assertEqual(reconcile.parse_checkpoint_offset("123456\n"), 123456)
        self.assertEqual(reconcile.parse_checkpoint_offset('{"offset": 98765, "inode": 1}'), 98765)
        self.assertEqual(reconcile.parse_checkpoint_offset('{"Offset": 42}'), 42)
        self.assertIsNone(reconcile.parse_checkpoint_offset(""))
        self.assertIsNone(reconcile.parse_checkpoint_offset("{bad json"))

    def test_scan_gateway_log_lines_filters_and_dedups(self):
        lines = [
            json.dumps({"request_id": "req-1", "endpoint_key": "GET /v1/ky-evt01/{id}", "final_action": "OBSERVE"}),
            json.dumps({"request_id": "req-2", "endpoint_key": "GET /v1/ky-evt01/{id}", "final_action": "BLOCK"}),
            json.dumps({"request_id": "req-2", "endpoint_key": "GET /v1/ky-evt01/{id}", "final_action": "BLOCK"}),
            json.dumps({"request_id": "req-other", "endpoint_key": "GET /v1/other/{id}", "final_action": "OBSERVE"}),
            "not-json ky-evt01",
        ]
        res = reconcile.scan_gateway_log_lines(lines, "ky-evt01")
        self.assertEqual(res["matched_lines"], 3)
        self.assertEqual(res["unique_count"], 2)
        self.assertEqual(res["duplicate_log_ids"], 1)
        self.assertEqual(res["parse_errors"], 1)
        self.assertEqual(res["action_breakdown"], {"OBSERVE": 1, "BLOCK": 2})

    def test_reconcile_id_sets_verdicts(self):
        gw = {"r1", "r2", "r3"}
        ok = reconcile.reconcile_id_sets(gw, {"r1", "r2", "r3"}, db_total_rows=3, drained=True)
        self.assertTrue(ok["passed"])
        self.assertEqual(ok["verdict"], "PASS")

        loss = reconcile.reconcile_id_sets(gw, {"r1", "r3"}, db_total_rows=2, drained=True)
        self.assertFalse(loss["passed"])
        self.assertEqual(loss["verdict"], "FAIL_DATA_LOSS")
        self.assertEqual(loss["missing_sample_ids"], ["r2"])

        dup = reconcile.reconcile_id_sets(gw, {"r1", "r2", "r3"}, db_total_rows=4, drained=True)
        self.assertFalse(dup["passed"])
        self.assertEqual(dup["verdict"], "FAIL_DUPLICATE_PRIMARY_EVENTS")

        undrained = reconcile.reconcile_id_sets(gw, {"r1", "r2", "r3"}, db_total_rows=3, drained=False)
        self.assertFalse(undrained["passed"])
        self.assertEqual(undrained["verdict"], "FAIL_DRAIN_TIMEOUT")

    def test_wait_for_drain_local_file(self):
        with tempfile.TemporaryDirectory() as td:
            log_p = os.path.join(td, "api-runtime-events.log")
            ckpt_p = log_p + ".checkpoint"
            with open(log_p, "w", encoding="utf-8") as f:
                f.write('{"request_id":"a"}\n')
            sz = os.path.getsize(log_p)
            with open(ckpt_p, "w", encoding="utf-8") as f:
                json.dump({"offset": sz}, f)
            info = reconcile.wait_for_drain(log_p, timeout_sec=5, poll_sec=1)
            self.assertTrue(info["drained"])
            self.assertEqual(info["remaining_lag_bytes"], 0)


class TestBinarySearch(unittest.TestCase):
    def test_converges_to_exact_lossless_knee(self):
        # 模拟网关真实无损上限为 6000 RPS
        def fake_trial(_step: int, rate: float, _phase: str):
            over = rate > 6000.0
            return {
                "summary": {
                    "completed": int(rate * 10),
                    "achieved_rps": min(rate, 6000.0),
                    "achieved_cps": 0.0,
                    "goodput_gbps": round(min(rate, 6000.0) * 0.0005, 3),
                    "error_rate_pct": 0.5 if over else 0.0,
                    "backpressure_drop_pct": 0.0,
                },
                "latency": {"ttlb": {"p99_ms": 80.0 if over else 18.5}},
            }

        res = binsearch.run_binary_search(
            trial_fn=fake_trial,
            mode="tps",
            min_val=1000.0,
            max_val=10000.0,
            tolerance_pct=5.0,
            max_iterations=12,
            max_err_pct=0.0,
            max_p99_ms=50.0,
            max_drop_pct=1.0,
            confirm_fn=lambda v: fake_trial(99, v, "confirm"),
        )
        self.assertEqual(res["status"], "CONVERGED")
        self.assertIsNotNone(res["converged_max_lossless"])
        self.assertGreaterEqual(res["converged_max_lossless"], 5700.0)
        self.assertLessEqual(res["converged_max_lossless"], 6000.0)
        self.assertTrue(res["confirmation"]["passed"])

    def test_lower_bound_failed(self):
        def always_fail(_step: int, rate: float, _phase: str):
            return {
                "summary": {"completed": 100, "achieved_rps": rate, "error_rate_pct": 5.0, "backpressure_drop_pct": 0.0},
                "latency": {"ttlb": {"p99_ms": 120.0}},
            }

        res = binsearch.run_binary_search(
            trial_fn=always_fail,
            mode="tps",
            min_val=500.0,
            max_val=5000.0,
            tolerance_pct=5.0,
            max_iterations=6,
            max_err_pct=0.0,
            max_p99_ms=50.0,
            max_drop_pct=1.0,
        )
        self.assertEqual(res["status"], "LOWER_BOUND_FAILED")
        self.assertIsNone(res["converged_max_lossless"])


class TestSecurityUnderLoad(unittest.TestCase):
    def test_corpus_integrity_and_scorecard(self):
        with open(CORPUS_PATH, "r", encoding="utf-8") as f:
            doc = json.load(f)
        cases = doc["cases"]
        groups = {c["group"] for c in cases}
        self.assertEqual(groups, {"attack", "evasion", "benign"})
        self.assertEqual(doc["source"], "self_synthetic")

        # 模拟一个完美拦截攻击+逃逸（含部分 TCP Reset 断连）、零误报的 WAF
        def mock_sender(case):
            if case["group"] == "attack":
                return (403, "", 2.5)
            if case["group"] == "evasion":
                if case["case_id"] == "EVA-LFI-01":
                    return (0, "connection_reset", 1.8)  # 测 treat_reset_as_block
                return (403, "", 3.1)
            return (200, "", 1.2)

        res = secload.evaluate_corpus(
            cases=cases,
            sender=mock_sender,
            rounds=2,
            block_statuses={401, 403, 406, 444},
            treat_reset_as_block=True,
        )
        sc = res["scorecard"]
        self.assertEqual(sc["attack_catch_rate_pct"], 100.0)
        self.assertEqual(sc["evasion_catch_rate_pct"], 100.0)
        self.assertEqual(sc["overall_threat_catch_rate_pct"], 100.0)
        self.assertEqual(sc["false_positive_rate_pct"], 0.0)
        self.assertEqual(sc["benign_unexpected_err_pct"], 0.0)


class TestSummarizeRun(unittest.TestCase):
    def test_nearest_rank_and_linear_slope(self):
        vals = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0]
        self.assertEqual(summarize.nearest_rank(vals, 50.0), 5.0)
        self.assertEqual(summarize.nearest_rank(vals, 90.0), 9.0)
        self.assertEqual(summarize.nearest_rank(vals, 99.0), 10.0)

        xs = [0.0, 3600.0, 7200.0, 10800.0]
        ys = [100.0, 110.0, 120.0, 130.0]
        slope = summarize.linear_slope_per_hour(xs, ys)
        self.assertIsNotNone(slope)
        self.assertAlmostEqual(slope, 10.0, places=4)

    def test_end_to_end_rfc9411_summary_and_not_run_markers(self):
        with tempfile.TemporaryDirectory() as td:
            fp_path = os.path.join(td, "fingerprint.json")
            with open(fp_path, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "hostname": "ky5288-sut",
                        "os": "openEuler 24.03 (LTS-SP3)",
                        "kernel": "6.6.0",
                        "arch": "x86_64",
                        "cpu": {"model": "ZHAOXIN KaiSheng KH-40000/16", "logical_cores": 32, "avx2": False, "aes": True},
                        "memory_gib": 64.0,
                        "disks": [{"name": "sda", "size": "240G", "media": "SSD_OR_NVME"}],
                        "nics": [{"name": "ens1f0", "speed_mbps": "10000", "numa_node": "0"}],
                        "wdsp_deploy_mode": "baremetal",
                        "recommendations": ["test rec"],
                    },
                    f,
                )

            l7_path = os.path.join(td, "l7.json")
            with open(l7_path, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "config": {
                            "mode": "emix",
                            "target_base_url": "https://10.10.1.10",
                            "tls_version": "1.3",
                            "tls_resume": False,
                            "http2": False,
                            "local_ip_count": 32,
                        },
                        "steady_window": {"duration_seconds": 180.0},
                        "summary": {
                            "completed": 1800000,
                            "achieved_rps": 10000.0,
                            "achieved_cps": 5.0,
                            "goodput_gbps": 6.12,
                            "throughput_est_gbps": 6.31,
                            "error_rate_pct": 0.0,
                            "backpressure_drop_pct": 0.0,
                            "zero_loss_pass": True,
                        },
                        "latency": {
                            "tcp_connect": {"p99_ms": 0.8},
                            "tls_handshake": {"p99_ms": 5.4},
                            "ttfb": {"p99_ms": 14.2},
                            "ttlb": {"p50_ms": 6.1, "p95_ms": 16.0, "p99_ms": 24.5, "p999_ms": 41.0},
                        },
                        "errors": {"tcp_reset": 0, "timeout": 0},
                    },
                    f,
                )

            bs_path = os.path.join(td, "bs.json")
            with open(bs_path, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "mode": "emix",
                        "status": "CONVERGED",
                        "converged_max_lossless": 10000.0,
                        "thresholds": {"max_err_pct": 0.0, "max_p99_ms": 50.0, "max_drop_pct": 1.0},
                        "trials": [{"step": 1}, {"step": 2}],
                        "confirmation": {"passed": True, "reasons": []},
                    },
                    f,
                )

            sec_path = os.path.join(td, "sec.json")
            with open(sec_path, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "under_background_load": True,
                        "block_statuses": [401, 403],
                        "treat_reset_as_block": False,
                        "rounds": 3,
                        "background_load_summary": {"achieved_rps": 7500.0, "goodput_gbps": 4.5, "error_rate_pct": 0.0},
                        "scorecard": {
                            "attack_total": 36,
                            "attack_blocked_tp": 36,
                            "attack_catch_rate_pct": 100.0,
                            "evasion_total": 18,
                            "evasion_blocked_tp": 17,
                            "evasion_catch_rate_pct": 94.44,
                            "overall_threat_catch_rate_pct": 98.15,
                            "benign_total": 30,
                            "benign_false_positive_fp": 0,
                            "false_positive_rate_pct": 0.0,
                            "benign_unexpected_err": 0,
                            "benign_unexpected_err_pct": 0.0,
                        },
                    },
                    f,
                )

            l4_path = os.path.join(td, "l4.json")
            with open(l4_path, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "layer": "L4",
                        "config": {"proto": "tcp", "direction": "forward", "mode": "routed_forward", "streams": 16, "packet_len_bytes": 1448, "duration_sec": 30},
                        "summary": {"tx_gbps": 9.45, "rx_gbps": 9.45, "throughput_gbps": 9.45, "retransmits": 0, "retrans_pct": 0.0, "pps": 815200.0, "client_cpu_pct": 21.0, "server_cpu_pct": 24.5, "zero_loss_pass": True},
                    },
                    f,
                )

            l7_http_bw = os.path.join(td, "l7-http-256k.json")
            with open(l7_http_bw, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "config": {
                            "mode": "tps",
                            "target_base_url": "http://10.10.1.10",
                            "path": "/static/256k.bin",
                            "local_ip_count": 32,
                        },
                        "steady_window": {"duration_seconds": 120.0},
                        "summary": {
                            "completed": 446400,
                            "achieved_rps": 3720.0,
                            "achieved_cps": 2.0,
                            "goodput_gbps": 7.62,
                            "throughput_est_gbps": 7.86,
                            "error_rate_pct": 0.0,
                            "backpressure_drop_pct": 0.0,
                            "zero_loss_pass": True,
                        },
                        "latency": {
                            "tcp_connect": {"p99_ms": 0.5},
                            "tls_handshake": {"p99_ms": 0.0},
                            "ttfb": {"p99_ms": 6.4},
                            "ttlb": {"p50_ms": 8.2, "p95_ms": 15.1, "p99_ms": 19.2, "p999_ms": 31.0},
                        },
                        "errors": {"tcp_reset": 0, "timeout": 0},
                    },
                    f,
                )

            out_md = os.path.join(td, "report.md")
            out_html = os.path.join(td, "report.html")
            out_json = os.path.join(td, "summary.json")
            rc = summarize.main(
                [
                    "--env-name", "KY5288G1-裸机",
                    "--fingerprint", fp_path,
                    "--l4-json", f"4层-TCP单向转发={l4_path}",
                    "--l7bench-json", f"7层-HTTP大包吞吐={l7_http_bw}",
                    "--l7bench-json", f"EMIX_TLS13={l7_path}",
                    "--binary-search-json", f"BS_EMIX={bs_path}",
                    "--security-scorecard-json", sec_path,
                    "--out-md", out_md,
                    "--out-html", out_html,
                    "--out-json", out_json,
                ]
            )
            self.assertEqual(rc, 0)
            with open(out_md, "r", encoding="utf-8") as f:
                md = f.read()
            self.assertIn("聚信压测工具", md)
            self.assertIn("核心测试结论", md)
            self.assertIn("4 层与 7 层吞吐能力对比", md)
            self.assertIn("4层-TCP单向转发", md)
            self.assertIn("9.45", md)
            self.assertIn("7层-HTTP大包吞吐", md)
            self.assertIn("7.86", md)
            self.assertIn("EMIX_TLS13", md)
            self.assertIn("6.12 / 6.31", md)
            self.assertIn("已收敛至稳定基线", md)
            self.assertIn("98.15%", md)
            self.assertIn("`本次未测`（未提供安全日志完整性核对数据）", md)
            with open(out_html, "r", encoding="utf-8") as f:
                hdoc = f.read()
            self.assertIn("<!DOCTYPE html>", hdoc)
            self.assertIn("聚信压测工具", hdoc)
            self.assertIn("4层传输吞吐", hdoc)
            self.assertIn("7层HTTP全防护", hdoc)
            self.assertIn("达标基线（通过）", hdoc)
            self.assertIn("过载超限（回退）", hdoc)
            self.assertIn("<svg ", hdoc)
            self.assertIn("EMIX_TLS13", hdoc)


class TestScriptsAndCertGen(unittest.TestCase):
    def test_no_third_party_tester_branding(self):
        forbidden = ("思博伦", "spirent", "cyberflood", "avalanche")
        for root, dirs, files in os.walk(BASE_DIR):
            dirs[:] = [d for d in dirs if d not in ("dist", "__pycache__")]
            for fn in files:
                if fn == "test_delivery_stress.py":
                    continue
                fp = os.path.join(root, fn)
                with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read().lower()
                for word in forbidden:
                    self.assertNotIn(word, text, msg=f"forbidden brand word {word!r} found in {fp}")

    def test_bash_scripts_syntax(self):
        for fname in (
            "setup-loadgen-centos7.sh",
            "setup-multi-ip.sh",
            "gen-test-certs.sh",
            "preflight-fingerprint.sh",
            "collect-metrics.sh",
        ):
            path = os.path.join(SCRIPTS_DIR, fname)
            proc = subprocess.run(["bash", "-n", path], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, msg=f"bash -n failed on {fname}: {proc.stderr}")

    def test_gen_test_certs_produces_rsa_and_ecdsa(self):
        with tempfile.TemporaryDirectory() as td:
            script = os.path.join(SCRIPTS_DIR, "gen-test-certs.sh")
            proc = subprocess.run(
                ["bash", script, "--out-dir", td, "--domain", "bench.wdsp.local"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            for fn in ("bench-rsa2048.crt", "bench-rsa2048.key", "bench-ecdsa-p256.crt", "bench-ecdsa-p256.key"):
                self.assertTrue(os.path.isfile(os.path.join(td, fn)), msg=f"missing {fn}")


if __name__ == "__main__":
    unittest.main()
