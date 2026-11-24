#!/usr/bin/env python3
"""聚信压测工具「带压安全效能评分卡（Security under Load，遵循 RFC 9411 / NetSecOPEN）」工具。

功能：
  1. 可选在后台并行启动 l7bench 施加 70%~80% 背景满载吞吐；
  2. 同步多轮回放自研合规安全语料（基础攻击 + 编码逃逸 + 高易误报正常样本）；
  3. 通用兼容九章 WDSP 及任意反向代理 WAF：支持自定义拦截状态码（如 401,403,406,444）及将 TCP Reset 计为拦截；
  4. 输出完整安全效能评分卡：
       - Attack Catch Rate（基础攻击拦截率）
       - Evasion Catch Rate（编码逃逸拦截率）
       - False Positive Rate（正常流量误拦截率）
       - 分类别明细与逐样本 TP/FN/TN/FP 审计证据。
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse
from collections import defaultdict
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Set, Tuple


def classify_sample(
    group: str,
    status: int,
    transport_err: str,
    block_statuses: Set[int],
    treat_reset_as_block: bool,
) -> Tuple[str, bool, bool]:
    """返回 (outcome: TP/FN/TN/FP/ERR, is_blocked, is_unexpected_err)。"""
    is_reset = transport_err in ("connection_reset", "remote_closed")
    is_blocked = (status in block_statuses) or (treat_reset_as_block and is_reset)
    is_transport_err = bool(transport_err) and not (treat_reset_as_block and is_reset)
    is_5xx = status >= 500

    if group in ("attack", "evasion"):
        if is_blocked:
            return "TP", True, False
        if is_transport_err or is_5xx:
            return "ERR", False, True
        return "FN", False, False

    # benign
    if is_blocked:
        return "FP", True, False
    if is_transport_err or is_5xx or status < 200 or status >= 400:
        return "ERR", False, True
    return "TN", False, False


def send_http_sample(
    target_base_url: str,
    host_header: str,
    case: Dict[str, object],
    timeout: float = 5.0,
    insecure: bool = True,
) -> Tuple[int, str, float]:
    """发送单条语料样本（不自动转义路径，保留编码逃逸原貌），返回 (status, transport_err, latency_ms)。"""
    parsed = urllib.parse.urlparse(target_base_url)
    scheme = parsed.scheme.lower()
    netloc_host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if scheme == "https" else 80)

    method = str(case.get("method") or "GET").upper()
    path = str(case.get("path") or "/")
    body_str = str(case.get("body") or "")
    body_bytes = body_str.encode("utf-8") if body_str else None
    headers = {"Host": host_header or parsed.netloc, "Connection": "close"}
    extra_headers = case.get("headers") or {}
    if isinstance(extra_headers, dict):
        for k, v in extra_headers.items():
            headers[str(k)] = str(v)

    t0 = time.monotonic()
    conn = None
    try:
        if scheme == "https":
            ctx = ssl.create_default_context()
            if insecure:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(netloc_host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(netloc_host, port, timeout=timeout)
        conn.request(method, path, body=body_bytes, headers=headers)
        resp = conn.getresponse()
        resp.read()
        dur_ms = round((time.monotonic() - t0) * 1000.0, 3)
        return resp.status, "", dur_ms
    except ConnectionResetError:
        return 0, "connection_reset", round((time.monotonic() - t0) * 1000.0, 3)
    except http.client.RemoteDisconnected:
        return 0, "remote_closed", round((time.monotonic() - t0) * 1000.0, 3)
    except socket.timeout:
        return 0, "timeout", round((time.monotonic() - t0) * 1000.0, 3)
    except Exception as exc:
        return 0, f"error:{type(exc).__name__}", round((time.monotonic() - t0) * 1000.0, 3)
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def evaluate_corpus(
    cases: List[Dict[str, object]],
    sender: Callable[[Dict[str, object]], Tuple[int, str, float]],
    rounds: int,
    block_statuses: Set[int],
    treat_reset_as_block: bool,
) -> Dict[str, object]:
    """多轮回放全部语料并生成带压安全效能评分卡。"""
    results: List[Dict[str, object]] = []
    by_group = defaultdict(lambda: {"total": 0, "TP": 0, "FN": 0, "TN": 0, "FP": 0, "ERR": 0})
    by_category = defaultdict(lambda: {"group": "", "total": 0, "TP": 0, "FN": 0, "TN": 0, "FP": 0, "ERR": 0})

    for r_idx in range(1, rounds + 1):
        for case in cases:
            group = str(case.get("group") or "benign")
            cat = str(case.get("category") or "other")
            status, err, lat_ms = sender(case)
            outcome, blocked, unexpected = classify_sample(
                group, status, err, block_statuses, treat_reset_as_block
            )
            by_group[group]["total"] += 1
            by_group[group][outcome] += 1
            by_category[cat]["group"] = group
            by_category[cat]["total"] += 1
            by_category[cat][outcome] += 1

            results.append(
                {
                    "round": r_idx,
                    "case_id": case.get("case_id"),
                    "group": group,
                    "category": cat,
                    "status": status,
                    "transport_err": err,
                    "latency_ms": lat_ms,
                    "blocked": blocked,
                    "unexpected_err": unexpected,
                    "outcome": outcome,
                }
            )

    def pct(num: int, den: int) -> Optional[float]:
        if den <= 0:
            return None
        return round(num / den * 100.0, 2)

    atk = by_group["attack"]
    eva = by_group["evasion"]
    ben = by_group["benign"]
    threat_tp = atk["TP"] + eva["TP"]
    threat_tot = atk["total"] + eva["total"]

    scorecard = {
        "attack_total": atk["total"],
        "attack_blocked_tp": atk["TP"],
        "attack_missed_fn": atk["FN"],
        "attack_catch_rate_pct": pct(atk["TP"], atk["total"]),
        "evasion_total": eva["total"],
        "evasion_blocked_tp": eva["TP"],
        "evasion_missed_fn": eva["FN"],
        "evasion_catch_rate_pct": pct(eva["TP"], eva["total"]),
        "overall_threat_catch_rate_pct": pct(threat_tp, threat_tot),
        "benign_total": ben["total"],
        "benign_passed_tn": ben["TN"],
        "benign_false_positive_fp": ben["FP"],
        "benign_unexpected_err": ben["ERR"],
        "false_positive_rate_pct": pct(ben["FP"], ben["total"]),
        "benign_unexpected_err_pct": pct(ben["ERR"], ben["total"]),
    }

    return {
        "scorecard": scorecard,
        "by_category": dict(by_category),
        "samples": results,
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="聚信压测工具 — 带压安全效能评分卡测试（RFC 9411 / NetSecOPEN）")
    parser.add_argument("--url", required=True, help="目标基础 URL（如 https://10.10.1.10）")
    parser.add_argument("--host", default="bench.wdsp.local", help="Host 请求头")
    parser.add_argument(
        "--corpus",
        default=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "corpus", "owasp-security-corpus.json"),
        help="合成合规语料 JSON 路径",
    )
    parser.add_argument("--rounds", type=int, default=3, help="语料回放轮次（默认 3）")
    parser.add_argument("--block-statuses", default="401,403,406,444", help="视为有效拦截的 HTTP 状态码列表")
    parser.add_argument("--treat-reset-as-block", action="store_true", help="将对端 TCP Reset/断连视为有效拦截（部分 WAF 形态）")
    parser.add_argument("--timeout", type=float, default=5.0)

    # 可选并行背景满载流量（l7bench）
    parser.add_argument("--bg-l7bench", default="", help="可选：同时启动 l7bench 在后台施加 70%%~80%% 满载背景流量")
    parser.add_argument("--bg-mode", default="emix", choices=["tps", "emix", "cps"])
    parser.add_argument("--bg-rate", type=float, default=1000.0, help="背景吞吐速率（推荐为二分收敛容量的 75%%）")
    parser.add_argument("--bg-steady", default="60s", help="背景流量稳态时长")
    parser.add_argument("--bg-ramp-up", default="10s", help="背景爬坡等待时长（爬坡完成后开始安全语料回放）")
    parser.add_argument("--bg-local-ips", default="")

    parser.add_argument("--out-json", required=True, help="输出结构化安全评分卡 JSON")
    args = parser.parse_args(argv)

    with open(args.corpus, "r", encoding="utf-8") as f:
        corpus_doc = json.load(f)
    cases = corpus_doc.get("cases") or []
    block_statuses = {int(x.strip()) for x in args.block_statuses.split(",") if x.strip().isdigit()}

    bg_proc = None
    bg_json_path = ""
    if args.bg_l7bench:
        bg_json_path = os.path.splitext(args.out_json)[0] + ".bg-load.json"
        cmd = [
            args.bg_l7bench,
            "-mode", args.bg_mode,
            "-url", args.url,
            "-host", args.host,
            "-rate", str(args.bg_rate),
            "-ramp-up", args.bg_ramp_up,
            "-steady", args.bg_steady,
            "-ramp-down", "5s",
            "-out-json", bg_json_path,
        ]
        if args.bg_local_ips:
            cmd += ["-local-ips", args.bg_local_ips]
        print(f"[security-under-load] 启动背景负载: mode={args.bg_mode} rate={args.bg_rate} steady={args.bg_steady}", file=sys.stderr)
        bg_proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # 等待背景流量进入稳态窗口再回放安全语料
        wait_s = 12
        if args.bg_ramp_up.endswith("s") and args.bg_ramp_up[:-1].isdigit():
            wait_s = int(args.bg_ramp_up[:-1]) + 2
        time.sleep(wait_s)

    try:
        eval_res = evaluate_corpus(
            cases=cases,
            sender=lambda c: send_http_sample(args.url, args.host, c, timeout=args.timeout, insecure=True),
            rounds=max(1, args.rounds),
            block_statuses=block_statuses,
            treat_reset_as_block=args.treat_reset_as_block,
        )
    finally:
        bg_report = None
        if bg_proc is not None:
            bg_proc.wait()
            if os.path.isfile(bg_json_path):
                with open(bg_json_path, "r", encoding="utf-8") as f:
                    bg_report = json.load(f)

    out_doc = {
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "methodology": "聚信压测工具 (JuXin Bench) — RFC 9411 / NetSecOPEN Security-under-Load Evaluation",
        "target_url": args.url,
        "target_host": args.host,
        "corpus_version": corpus_doc.get("corpus_version"),
        "rounds": args.rounds,
        "block_statuses": sorted(block_statuses),
        "treat_reset_as_block": args.treat_reset_as_block,
        "under_background_load": bg_proc is not None,
        "background_load_summary": (bg_report or {}).get("summary"),
        "background_load_latency": (bg_report or {}).get("latency"),
        **eval_res,
    }

    os.makedirs(os.path.dirname(os.path.abspath(args.out_json)), exist_ok=True)
    with open(args.out_json, "w", encoding="utf-8") as f:
        json.dump(out_doc, f, ensure_ascii=False, indent=2)

    print(json.dumps({"scorecard": out_doc["scorecard"], "under_background_load": out_doc["under_background_load"]}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
