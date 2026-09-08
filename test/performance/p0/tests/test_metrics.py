"""分位数与检测/处置指标测试（BENCH-05/06 的可单测部分）。"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

P0_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(P0_DIR))

from p0bench.metrics import (  # noqa: E402
    NA,
    classify_error,
    compute_truth_metrics,
    histogram_quantile,
    merge_histograms,
    merged_samples_quantile,
    nearest_rank_quantile,
)


class TestQuantiles(unittest.TestCase):
    """BENCH-06：已知分布校验最近秩分位数。"""

    def test_known_distribution(self):
        samples = list(range(1, 101))  # 1..100ms
        self.assertEqual(nearest_rank_quantile(samples, 0.50), 50)
        self.assertEqual(nearest_rank_quantile(samples, 0.95), 95)
        self.assertEqual(nearest_rank_quantile(samples, 0.99), 99)
        self.assertEqual(nearest_rank_quantile(samples, 1.0), 100)

    def test_small_sample(self):
        self.assertEqual(nearest_rank_quantile([5.0], 0.99), 5.0)
        self.assertEqual(nearest_rank_quantile([9, 1, 5], 0.5), 5)
        self.assertIsNone(nearest_rank_quantile([], 0.95))

    def test_merge_is_not_average(self):
        # 两组运行：一组全 10ms，一组全 1000ms。
        # 平均 P99 伪汇总 = (10+1000)/2 = 505；正确合并 = 1000（最近秩）。
        g1 = [10.0] * 100
        g2 = [1000.0] * 100
        merged = merged_samples_quantile([g1, g2], 0.99)
        self.assertEqual(merged, 1000.0)
        self.assertNotEqual(merged, (10.0 + 1000.0) / 2)

    def test_histogram_merge_and_quantile(self):
        bins = [{"lower": 0, "upper": 10}, {"lower": 10, "upper": 100}, {"lower": 100, "upper": 1000}]
        h1 = {"bins": bins, "counts": [50, 45, 5]}
        h2 = {"bins": bins, "counts": [40, 55, 5]}
        merged = merge_histograms([h1, h2])
        self.assertEqual(merged["counts"], [90, 100, 10])
        # 总 200；rank=ceil(q*200)，落入累计计数首个 >= rank 的 bin，取上界
        self.assertEqual(histogram_quantile(merged, 0.45), 10)   # rank 90 → bin0
        self.assertEqual(histogram_quantile(merged, 0.5), 100)   # rank 100 → bin1
        self.assertEqual(histogram_quantile(merged, 0.95), 100)  # rank 190 → bin1
        self.assertEqual(histogram_quantile(merged, 0.96), 1000)  # rank 192 → bin2

    def test_histogram_bin_mismatch_rejected(self):
        h1 = {"bins": [{"lower": 0, "upper": 10}], "counts": [1]}
        h2 = {"bins": [{"lower": 0, "upper": 20}], "counts": [1]}
        with self.assertRaises(ValueError):
            merge_histograms([h1, h2])

    def test_histogram_empty(self):
        h = {"bins": [{"lower": 0, "upper": 10}], "counts": [0]}
        self.assertIsNone(histogram_quantile(h, 0.99))


class TestTruthMetrics(unittest.TestCase):
    """BENCH-05：检测/处置分离、分母正确、零分母 N/A。"""

    def _rec(self, case_id, label, detected, observed, expected, valid=True, deferred=False):
        return {
            "case_id": case_id,
            "label": label,
            "detected": detected,
            "observed_action": observed,
            "expected_action": expected,
            "valid": valid,
            "deferred": deferred,
        }

    def test_separation_detection_vs_disposition(self):
        # waf_observe：正常样本被误检测（检测误报）但正确放行（非拦截误报）
        recs = [
            self._rec("N-1", "normal", detected=True, observed="DETECT_PASS", expected="PASS"),
            self._rec("N-2", "normal", detected=False, observed="PASS", expected="PASS"),
            self._rec("A-1", "attack", detected=True, observed="DETECT_PASS", expected="DETECT_PASS"),
        ]
        m = compute_truth_metrics(recs, "waf_observe")
        self.assertEqual(m["detection_false_positive"]["count"], 1)
        self.assertEqual(m["detection_false_positive"]["denominator"], 2)
        self.assertEqual(m["detection_false_positive"]["rate"], 0.5)
        self.assertEqual(m["block_false_positive"]["count"], 0)
        self.assertEqual(m["block_false_positive"]["rate"], 0.0)
        self.assertEqual(m["confusion"], {"TP": 1, "FP": 1, "TN": 1, "FN": 0})

    def test_observe_pass_attack_not_block_miss(self):
        # OBSERVE 期望 DETECT_PASS 的攻击正确放行：不进拦截漏报分母
        recs = [self._rec("A-1", "attack", True, "DETECT_PASS", "DETECT_PASS")]
        m = compute_truth_metrics(recs, "waf_observe")
        self.assertEqual(m["block_miss"]["denominator"], 0)
        self.assertEqual(m["block_miss"]["rate"], NA)

    def test_zero_denominator_is_na_not_zero(self):
        recs = [self._rec("N-1", "normal", False, "PASS", "PASS")]
        m = compute_truth_metrics(recs, "proxy")
        self.assertEqual(m["detection_miss"]["rate"], NA)
        self.assertEqual(m["block_miss"]["rate"], NA)
        self.assertNotEqual(m["detection_miss"]["rate"], 0.0)

    def test_protect_block_miss_counted(self):
        recs = [
            self._rec("A-1", "attack", True, "BLOCK_403", "BLOCK_403"),
            self._rec("A-2", "attack", False, "PASS", "BLOCK_403"),
        ]
        m = compute_truth_metrics(recs, "waf_protect")
        self.assertEqual(m["block_miss"]["count"], 1)
        self.assertEqual(m["block_miss"]["denominator"], 2)
        self.assertEqual(m["block_miss"]["rate"], 0.5)
        self.assertEqual(m["detection_miss"]["count"], 1)

    def test_deferred_and_invalid_excluded(self):
        recs = [
            self._rec("A-9", "attack", False, "PASS", "BLOCK_403", deferred=True),
            self._rec("N-9", "normal", True, "PASS", "PASS", valid=False),
        ]
        m = compute_truth_metrics(recs, "waf_protect")
        self.assertEqual(m["skipped_deferred"], 1)
        self.assertEqual(m["invalid_samples"], 1)
        self.assertEqual(m["detection_miss"]["rate"], NA)
        self.assertEqual(m["detection_false_positive"]["rate"], NA)

    def test_mismatch_recorded(self):
        recs = [self._rec("N-1", "normal", False, "BLOCK_403", "PASS")]
        m = compute_truth_metrics(recs, "combined_protect")
        self.assertEqual(len(m["mismatches"]), 1)
        self.assertEqual(m["block_false_positive"]["count"], 1)

    def test_block_401_jwt_protect_semantics(self):
        """JWT-18 配对：BLOCK_401 是 jwt_trust PROTECT 的实断期望（P0-03 真实行为）。"""
        recs = [
            # 篡改签名 Token：PROTECT 下 401 + JWT_AUTH_FAILED 事件证据 → 无漏报
            self._rec("A-JWT-01", "attack", True, "BLOCK_401", "BLOCK_401"),
            # 合法 Token：VERIFIED 放行
            self._rec("N-JWT-01", "normal", False, "PASS", "PASS"),
        ]
        m = compute_truth_metrics(recs, "jwt_protect")
        self.assertEqual(m["block_miss"]["count"], 0)
        self.assertEqual(m["block_miss"]["denominator"], 1)
        self.assertEqual(m["detection_miss"]["count"], 0)
        self.assertEqual(m["detection_miss"]["denominator"], 1)
        self.assertEqual(m["confusion"]["TP"], 1)
        self.assertEqual(m["mismatches"], [])

    def test_block_401_miss_counted(self):
        # 期望 401 实断但实际放行：拦截漏报 + 检测漏报（无事件证据）
        recs = [self._rec("A-JWT-01", "attack", False, "PASS", "BLOCK_401")]
        m = compute_truth_metrics(recs, "jwt_protect")
        self.assertEqual(m["block_miss"]["count"], 1)
        self.assertEqual(m["detection_miss"]["count"], 1)
        self.assertEqual(m["confusion"]["FN"], 1)

    def test_block_401_on_normal_is_false_positive(self):
        recs = [self._rec("N-1", "normal", False, "BLOCK_401", "PASS")]
        m = compute_truth_metrics(recs, "jwt_protect")
        self.assertEqual(m["block_false_positive"]["count"], 1)
        self.assertEqual(len(m["mismatches"]), 1)

    def test_block_401_not_expected_in_baseline(self):
        # 七模式基线（JWT 关闭）下 JWT 攻击样本期望 PASS：放行不构成漏报
        recs = [self._rec("A-JWT-01", "attack", False, "PASS", "PASS")]
        m = compute_truth_metrics(recs, "waf_protect")
        self.assertEqual(m["detection_miss"]["denominator"], 0)
        self.assertEqual(m["block_miss"]["denominator"], 0)
        self.assertEqual(m["mismatches"], [])


class TestErrorClassification(unittest.TestCase):
    def test_expected_security_separate(self):
        self.assertEqual(classify_error(403, []), "expected_security")
        self.assertEqual(classify_error(429, []), "expected_security")
        self.assertEqual(classify_error(200, []), "ok")
        self.assertEqual(classify_error(500, []), "unexpected_error")
        self.assertEqual(classify_error(None, []), "connection_error")
        self.assertEqual(classify_error(404, [404]), "expected")


if __name__ == "__main__":
    unittest.main()
