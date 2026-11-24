#!/usr/bin/env python3
"""聚信压测工具 RFC 2544 自动二分无损容量搜索编排器（纯 Python 3 标准库）。

通过迭代调用 l7bench，自动在 [min_rate, max_rate] 区间二分收敛，找到满足：
  - 错误率 <= max_err_pct（严格无损默认 0.0%）
  - TTLB P99 <= max_p99_ms
  - 发压端背压丢弃率 <= max_drop_pct（防止把压测机饱和误判为网关达标）
的最大稳态容量点，并可选在收敛点执行一次长稳态确认（如 180s）。
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Tuple


def evaluate_trial(
    report: Dict[str, object],
    mode: str,
    target_val: float,
    max_err_pct: float,
    max_p99_ms: float,
    max_drop_pct: float,
    min_achieved_ratio: float = 0.90,
) -> Tuple[bool, List[str]]:
    """按 RFC 2544 / 聚信压测工具无损门槛判定单轮试验是否通过。"""
    reasons: List[str] = []
    summary = report.get("summary") or {}
    latency = report.get("latency") or {}
    ttlb = latency.get("ttlb") or {}

    completed = int(summary.get("completed") or 0)
    err_pct = float(summary.get("error_rate_pct") or 0.0)
    drop_pct = float(summary.get("backpressure_drop_pct") or 0.0)
    p99_ms = float(ttlb.get("p99_ms") or 0.0)
    achieved_rps = float(summary.get("achieved_rps") or 0.0)
    achieved_cps = float(summary.get("achieved_cps") or 0.0)

    if completed <= 0:
        reasons.append("completed=0")
    if err_pct > max_err_pct:
        reasons.append(f"error_rate={err_pct}% > {max_err_pct}%")
    if max_p99_ms > 0 and p99_ms > max_p99_ms:
        reasons.append(f"ttlb_p99={p99_ms}ms > {max_p99_ms}ms")
    if drop_pct > max_drop_pct:
        reasons.append(f"backpressure_drop={drop_pct}% > {max_drop_pct}%")

    if mode in ("tps", "emix"):
        if target_val > 0 and achieved_rps < target_val * min_achieved_ratio:
            reasons.append(f"achieved_rps={achieved_rps} < {min_achieved_ratio*100:.0f}% of target {target_val}")
    elif mode == "cps":
        if target_val > 0 and achieved_cps < target_val * min_achieved_ratio:
            reasons.append(f"achieved_cps={achieved_cps} < {min_achieved_ratio*100:.0f}% of target {target_val}")
    elif mode == "cc":
        cc = report.get("concurrent_connections") or {}
        steady_min = int(cc.get("steady_min_conns") or 0)
        if target_val > 0 and steady_min < target_val * min_achieved_ratio:
            reasons.append(f"steady_min_conns={steady_min} < {min_achieved_ratio*100:.0f}% of target {target_val}")

    return len(reasons) == 0, reasons


def run_binary_search(
    trial_fn: Callable[[int, float, str], Dict[str, object]],
    mode: str,
    min_val: float,
    max_val: float,
    tolerance_pct: float,
    max_iterations: int,
    max_err_pct: float,
    max_p99_ms: float,
    max_drop_pct: float,
    cooldown_sec: float = 0.0,
    confirm_fn: Optional[Callable[[float], Dict[str, object]]] = None,
) -> Dict[str, object]:
    """执行 RFC 2544 风格二分搜索并记录全部收敛轨迹。"""
    if min_val <= 0 or max_val < min_val:
        raise ValueError("min_val must be > 0 and max_val >= min_val")

    trials: List[Dict[str, object]] = []
    best_pass_val: Optional[float] = None
    best_pass_report: Optional[Dict[str, object]] = None

    def exec_and_record(step_idx: int, val: float, phase: str) -> Tuple[bool, Dict[str, object]]:
        nonlocal best_pass_val, best_pass_report
        rep = trial_fn(step_idx, val, phase)
        ok, reasons = evaluate_trial(rep, mode, val, max_err_pct, max_p99_ms, max_drop_pct)
        summary = rep.get("summary") or {}
        ttlb = (rep.get("latency") or {}).get("ttlb") or {}
        trials.append(
            {
                "step": step_idx,
                "phase": phase,
                "target": round(val, 2),
                "passed": ok,
                "reasons": reasons,
                "achieved_rps": summary.get("achieved_rps"),
                "achieved_cps": summary.get("achieved_cps"),
                "goodput_gbps": summary.get("goodput_gbps"),
                "error_rate_pct": summary.get("error_rate_pct"),
                "backpressure_drop_pct": summary.get("backpressure_drop_pct"),
                "ttlb_p99_ms": ttlb.get("p99_ms"),
            }
        )
        if ok and (best_pass_val is None or val > best_pass_val):
            best_pass_val = val
            best_pass_report = rep
        if cooldown_sec > 0:
            time.sleep(cooldown_sec)
        return ok, rep

    step = 1
    # 1. 先探上界（如直接通过即无需继续往下二分）
    hi_ok, _ = exec_and_record(step, max_val, "probe_upper")
    if hi_ok:
        low, high = max_val, max_val
    else:
        step += 1
        # 2. 探下界（若下界都失败，标记 LOWER_BOUND_FAILED 停止）
        lo_ok, _ = exec_and_record(step, min_val, "probe_lower")
        if not lo_ok:
            return {
                "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "mode": mode,
                "status": "LOWER_BOUND_FAILED",
                "converged_max_lossless": None,
                "thresholds": {
                    "max_err_pct": max_err_pct,
                    "max_p99_ms": max_p99_ms,
                    "max_drop_pct": max_drop_pct,
                    "tolerance_pct": tolerance_pct,
                },
                "trials": trials,
                "confirmation": None,
            }
        low, high = min_val, max_val

        # 3. 正式二分收敛
        while step < max_iterations and (high - low) / max(low, 1.0) * 100.0 > tolerance_pct:
            mid = round((low + high) / 2.0, 2)
            if mode == "cc":
                mid = float(int(round(mid)))
            if mid <= low or mid >= high:
                break
            step += 1
            ok, _ = exec_and_record(step, mid, "bisect")
            if ok:
                low = mid
            else:
                high = mid

    confirmation = None
    final_status = "CONVERGED"
    if best_pass_val is not None and confirm_fn is not None:
        conf_rep = confirm_fn(best_pass_val)
        conf_ok, conf_reasons = evaluate_trial(conf_rep, mode, best_pass_val, max_err_pct, max_p99_ms, max_drop_pct)
        confirmation = {
            "target": round(best_pass_val, 2),
            "passed": conf_ok,
            "reasons": conf_reasons,
            "report": conf_rep,
        }
        if not conf_ok:
            final_status = "CONFIRMATION_FAILED"

    return {
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "mode": mode,
        "status": final_status,
        "converged_max_lossless": round(best_pass_val, 2) if best_pass_val is not None else None,
        "best_trial_summary": (best_pass_report or {}).get("summary"),
        "best_trial_latency": (best_pass_report or {}).get("latency"),
        "thresholds": {
            "max_err_pct": max_err_pct,
            "max_p99_ms": max_p99_ms,
            "max_drop_pct": max_drop_pct,
            "tolerance_pct": tolerance_pct,
        },
        "trials": trials,
        "confirmation": confirmation,
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="聚信压测工具 RFC 2544 自动二分无损容量搜索")
    parser.add_argument("--l7bench", default="./dist/l7bench-linux-amd64", help="l7bench 二进制路径")
    parser.add_argument("--mode", required=True, choices=["tps", "cps", "cc", "emix"], help="压测模式")
    parser.add_argument("--url", required=True, help="目标基础 URL（如 https://10.10.1.10）")
    parser.add_argument("--host", default="bench.wdsp.local", help="Host 头与 TLS SNI")
    parser.add_argument("--path", default="/static/256b.txt", help="请求路径")
    parser.add_argument("--emix-preset", default="netsecopen")
    parser.add_argument("--local-ips", default="", help="多源 IP 池，如 10.10.1.101-10.10.1.132")
    parser.add_argument("--tls-version", default="auto")
    parser.add_argument("--tls-cipher", default="")
    parser.add_argument("--tls-resume", action="store_true")
    parser.add_argument("--http2", action="store_true")
    parser.add_argument("--min", dest="min_val", type=float, required=True, help="二分搜索下界（RPS/CPS/连接数）")
    parser.add_argument("--max", dest="max_val", type=float, required=True, help="二分搜索上界（RPS/CPS/连接数）")
    parser.add_argument("--tolerance-pct", type=float, default=5.0, help="收敛精度百分比（默认 5%%）")
    parser.add_argument("--max-iterations", type=int, default=10, help="最大二分轮次（默认 10）")
    parser.add_argument("--max-err-pct", type=float, default=0.0, help="允许最大错误率%%（严格无损默认 0.0）")
    parser.add_argument("--max-p99-ms", type=float, default=50.0, help="允许最大 TTLB P99 延迟 ms（0 不限）")
    parser.add_argument("--max-drop-pct", type=float, default=1.0, help="允许最大发压端背压丢弃率%%")
    parser.add_argument("--ramp-up", default="10s")
    parser.add_argument("--steady", default="30s", help="二分每轮稳态时长（推荐 30s-60s）")
    parser.add_argument("--ramp-down", default="5s")
    parser.add_argument("--confirm-steady", default="", help="可选：在收敛点执行的最终长稳态确认时长（如 180s）")
    parser.add_argument("--cooldown-sec", type=float, default=5.0, help="每轮之间冷却等待秒数")
    parser.add_argument("--max-inflight", type=int, default=4096)
    parser.add_argument("--out-dir", required=True, help="输出目录（保存每轮 JSON 与 binary-search-result.json）")
    args = parser.parse_args(argv)

    os.makedirs(args.out_dir, exist_ok=True)

    def invoke_l7bench(val: float, steady_dur: str, tag: str) -> Dict[str, object]:
        out_path = os.path.join(args.out_dir, f"trial-{tag}.json")
        cmd = [
            args.l7bench,
            "-mode", args.mode,
            "-url", args.url,
            "-host", args.host,
            "-path", args.path,
            "-emix-preset", args.emix_preset,
            "-ramp-up", args.ramp_up,
            "-steady", steady_dur,
            "-ramp-down", args.ramp_down,
            "-max-inflight", str(args.max_inflight),
            "-tls-version", args.tls_version,
            "-out-json", out_path,
        ]
        if args.mode == "cc":
            cmd += ["-conns", str(int(round(val)))]
        else:
            cmd += ["-rate", str(val)]
        if args.local_ips:
            cmd += ["-local-ips", args.local_ips]
        if args.tls_cipher:
            cmd += ["-tls-cipher", args.tls_cipher]
        if args.tls_resume:
            cmd += ["-tls-resume"]
        if args.http2:
            cmd += ["-http2"]

        print(f"[binary-search] 启动 {tag}: mode={args.mode} target={val} steady={steady_dur}", file=sys.stderr)
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL)
        with open(out_path, "r", encoding="utf-8") as f:
            return json.load(f)

    confirm_fn = None
    if args.confirm_steady:
        confirm_fn = lambda v: invoke_l7bench(v, args.confirm_steady, f"confirm-{int(round(v))}")

    result = run_binary_search(
        trial_fn=lambda step, val, phase: invoke_l7bench(val, args.steady, f"{step:02d}-{phase}-{int(round(val))}"),
        mode=args.mode,
        min_val=args.min_val,
        max_val=args.max_val,
        tolerance_pct=args.tolerance_pct,
        max_iterations=args.max_iterations,
        max_err_pct=args.max_err_pct,
        max_p99_ms=args.max_p99_ms,
        max_drop_pct=args.max_drop_pct,
        cooldown_sec=args.cooldown_sec,
        confirm_fn=confirm_fn,
    )

    out_summary = os.path.join(args.out_dir, "binary-search-result.json")
    with open(out_summary, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["status"] == "CONVERGED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
