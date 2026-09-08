"""分位数算法与检测/处置分离指标（P0-02 任务书 §5/§6.1，验收 BENCH-05/06）。

铁律：
- 跨运行分位数禁止简单平均。合并必须连接原始样本后重算最近秩，
  或合并 bin 完全一致的直方图后按累计计数取分位。
- 检测与处置分开计算；无适用分母显示 "N/A"，不输出 0%。
- OBSERVE 模式下正确放行攻击不是拦截漏报。
"""

from __future__ import annotations

import math

NA = "N/A"

# 观测动作（与语料 expected_action 同枚举，另加运行时可能出现的异常标记）
OBSERVED_ACTIONS = (
    "PASS",
    "DETECT_PASS",
    "BLOCK_403",
    "BLOCK_401",
    "RATE_LIMIT_429",
    "UNEXPECTED_ERROR",
)
# 实断类期望动作（BLOCK_401 为 JWT 信任链 PROTECT 认证失败处置）
_BLOCK_EXPECTED = ("BLOCK_403", "BLOCK_401")
# 正常样本的实断观测（拦截误报口径）
_BLOCK_OBSERVED = ("BLOCK_403", "BLOCK_401", "RATE_LIMIT_429")


def nearest_rank_quantile(samples, q: float):
    """最近秩分位数。samples 为原始样本序列；无样本返回 None。

    rank = ceil(q * n)，1-based；q 取值 (0, 1]。
    """
    if not 0 < q <= 1:
        raise ValueError("q 必须在 (0,1]")
    vals = sorted(float(s) for s in samples)
    n = len(vals)
    if n == 0:
        return None
    rank = max(1, math.ceil(q * n))
    return vals[rank - 1]


def merged_samples_quantile(sample_groups, q: float):
    """跨重复运行合并：连接原始样本后重算，绝不对各组分位数取平均。"""
    merged: list[float] = []
    for group in sample_groups:
        merged.extend(group)
    return nearest_rank_quantile(merged, q)


def merge_histograms(histograms: list[dict]) -> dict:
    """合并 bin 完全一致的直方图。bin 定义不一致即拒绝（不能伪装合并）。"""
    if not histograms:
        raise ValueError("无直方图可合并")
    ref_bins = tuple(histograms[0].get("bins") or ())
    if not ref_bins:
        raise ValueError("直方图缺 bins 定义")
    for h in histograms[1:]:
        if tuple(h.get("bins") or ()) != ref_bins:
            raise ValueError("直方图 bin 定义不一致，禁止合并")
    counts = [0] * len(ref_bins)
    for h in histograms:
        h_counts = h.get("counts") or []
        if len(h_counts) != len(ref_bins):
            raise ValueError("直方图 counts 与 bins 长度不一致")
        for i, c in enumerate(h_counts):
            if not isinstance(c, int) or c < 0:
                raise ValueError("直方图计数必须为非负整数")
            counts[i] += c
    return {"bins": list(ref_bins), "counts": counts}


def histogram_quantile(hist: dict, q: float):
    """直方图最近秩分位：返回所在 bin 的上界值；总样本为 0 返回 None。"""
    if not 0 < q <= 1:
        raise ValueError("q 必须在 (0,1]")
    bins = hist.get("bins") or []
    counts = hist.get("counts") or []
    if len(bins) != len(counts):
        raise ValueError("bins 与 counts 长度不一致")
    total = sum(counts)
    if total == 0:
        return None
    rank = max(1, math.ceil(q * total))
    acc = 0
    for b, c in zip(bins, counts):
        acc += c
        if acc >= rank:
            # bin 定义形如 {"lower": x, "upper": y}，取上界作为保守估计
            if isinstance(b, dict) and "upper" in b:
                return b["upper"]
            raise ValueError("bin 必须含 upper 字段")
    return None


def _rate(num: int, denom: int):
    """零分母返回 "N/A"（BENCH-05：不输出 0% 冒充无问题）。"""
    if denom == 0:
        return NA
    return num / denom


def compute_truth_metrics(case_results: list[dict], profile: str) -> dict:
    """逐样本真值结果 → 检测/处置分离指标。

    case_results 元素字段：
      case_id, label("normal"/"attack"), deferred(bool),
      detected(bool),            是否产生安全检测证据
      observed_action,           OBSERVED_ACTIONS 之一
      expected_action,           该 profile 下的期望动作
      valid(bool)                请求/响应是否有效（源站正确性预检通过）
    返回的 rate 字段在零分母时为字符串 "N/A"。
    """
    result = {
        "profile": profile,
        "detection_false_positive": {"count": 0, "denominator": 0, "rate": NA},
        "block_false_positive": {"count": 0, "denominator": 0, "rate": NA},
        "detection_miss": {"count": 0, "denominator": 0, "rate": NA},
        "block_miss": {"count": 0, "denominator": 0, "rate": NA},
        "confusion": {"TP": 0, "FP": 0, "TN": 0, "FN": 0},
        "skipped_deferred": 0,
        "invalid_samples": 0,
        "mismatches": [],
    }

    for rec in case_results:
        if rec.get("deferred"):
            result["skipped_deferred"] += 1
            continue
        if not rec.get("valid", True):
            result["invalid_samples"] += 1
            continue
        label = rec.get("label")
        detected = bool(rec.get("detected"))
        observed = rec.get("observed_action")
        expected = rec.get("expected_action")

        if label == "normal":
            result["detection_false_positive"]["denominator"] += 1
            result["block_false_positive"]["denominator"] += 1
            if detected:
                result["detection_false_positive"]["count"] += 1
                result["confusion"]["FP"] += 1
            else:
                result["confusion"]["TN"] += 1
            if observed in _BLOCK_OBSERVED:
                result["block_false_positive"]["count"] += 1
            if observed != expected:
                result["mismatches"].append(
                    {"case_id": rec.get("case_id"), "expected": expected, "observed": observed}
                )
        elif label == "attack":
            detection_expected = expected in ("DETECT_PASS",) + _BLOCK_EXPECTED
            if detection_expected:
                result["detection_miss"]["denominator"] += 1
                if detected:
                    result["confusion"]["TP"] += 1
                else:
                    result["detection_miss"]["count"] += 1
                    result["confusion"]["FN"] += 1
            # 拦截漏报只在期望实断（403/401）的模式计入分母；
            # OBSERVE 期望 DETECT_PASS 的攻击正确放行不构成拦截漏报。
            if expected in _BLOCK_EXPECTED:
                result["block_miss"]["denominator"] += 1
                if observed != expected:
                    result["block_miss"]["count"] += 1
            if observed != expected:
                result["mismatches"].append(
                    {"case_id": rec.get("case_id"), "expected": expected, "observed": observed}
                )

    for key in ("detection_false_positive", "block_false_positive", "detection_miss", "block_miss"):
        m = result[key]
        m["rate"] = _rate(m["count"], m["denominator"])
    return result


def classify_error(status_code: int | None, expected_statuses) -> str:
    """错误分类（§6.1）：安全策略预期 403/429 单列，不计入非预期错误率。"""
    if status_code is None:
        return "connection_error"
    if status_code in set(expected_statuses or ()):
        return "expected"
    if status_code in (403, 429):
        return "expected_security"
    if 200 <= status_code < 400:
        return "ok"
    return "unexpected_error"
