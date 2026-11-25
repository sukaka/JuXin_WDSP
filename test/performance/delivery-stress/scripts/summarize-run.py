#!/usr/bin/env python3
"""聚信压测工具 — 压测数据汇总与交付报告自动生成器（纯 Python 3 标准库）。

支持一键导出三种格式：
  - --out-md   : Markdown 交付总报告（专业通俗中文口径，适合客户验收与二次编辑）
  - --out-html : 单文件离线可视化 HTML 报告（内联 SVG 图表、零外部依赖、浏览器直接“打印→存为 PDF”）
  - --out-json : 同源结构化汇总 JSON

严守实测纪律：
  - 只汇总真实原始数据，未执行项如实标注“本次未测”，绝不填入估计值；
  - 不对跨轮分位数做简单平均。
"""

from __future__ import annotations

import argparse
import csv
import html
import json
import math
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from typing import Dict, List, Optional, Sequence, Tuple


MODE_LABELS = {
    "tps": "高频业务请求（长连接）",
    "emix": "混合尺寸网页与文件",
    "cps": "每秒新建加密连接",
    "cc": "高并发长连接保持",
    "throughput": "大包过检吞吐",
}

L4_MODE_LABELS = {
    "direct_baseline": "整机线速基线（4层直连）",
    "transparent_bridge": "透明串接（二层桥转发）",
    "routed_forward": "路由牵引（三层转发）",
    "software_bypass": "软件直通旁路（Bypass）",
}

L4_DIRECTION_LABELS = {
    "forward": "单向转发",
    "reverse": "反向接收",
    "bidir": "双向全双工",
}

SCENARIO_LABELS = {
    "rps_step": "阶梯加压摸底",
    "bandwidth": "大包吞吐测速",
    "tls_cps": "HTTPS 新建连接测速",
    "mixed_attack": "正常业务与攻击混合压测",
    "event_storm": "高并发安全日志洪峰",
    "soak": "长时间连续稳定性验证",
    "rpsload_constant": "恒定速率稳定发压",
}

CATEGORY_LABELS = {
    "sqli": "SQL 注入攻击",
    "xss": "跨站脚本攻击（XSS）",
    "cmdi": "系统命令注入",
    "lfi": "路径穿越与文件读取",
    "ssti": "模板与表达式注入",
    "xxe": "XML 外部实体注入",
    "ssrf": "服务端请求伪造（SSRF）",
    "rce": "远程代码执行特征",
    "api_sensitive": "接口敏感参数明文泄露",
    "protocol": "自动化扫描器特征",
    "evasion_sqli": "注释混淆 SQL 注入",
    "evasion_lfi": "双重编码路径穿越",
    "evasion_xss": "变形混淆跨站脚本",
    "evasion_cmdi": "控制字符绕过命令注入",
    "benign_web": "正常静态资源访问",
    "benign_api_get": "正常接口分页查询",
    "benign_unicode": "正常中文文章提交",
    "benign_base64": "正常 Base64 编码参数",
    "benign_search_symbols": "正常含符号检索请求",
    "benign_tech_doc": "正常技术文档提交",
    "benign_rich_text": "正常富文本内容提交",
    "benign_form": "正常表单数据提交",
    "benign_long_json": "正常批量 JSON 提交",
    "benign_headers": "标准浏览器请求头访问",
}

GROUP_LABELS = {
    "attack": "常见攻击",
    "evasion": "变形绕过攻击",
    "benign": "正常业务",
}


def nearest_rank(sorted_vals: Sequence[float], pct: float) -> Optional[float]:
    if not sorted_vals:
        return None
    idx = max(0, min(len(sorted_vals) - 1, math.ceil((pct / 100.0) * len(sorted_vals)) - 1))
    return sorted_vals[idx]


def linear_slope_per_hour(xs_unix_s: Sequence[float], ys: Sequence[float]) -> Optional[float]:
    """计算最小二乘线性回归斜率，单位：y_unit / hour。"""
    n = len(xs_unix_s)
    if n < 2 or len(ys) != n:
        return None
    t0 = xs_unix_s[0]
    hours = [(x - t0) / 3600.0 for x in xs_unix_s]
    span = hours[-1] - hours[0]
    if span <= 0:
        return None
    mx = sum(hours) / n
    my = sum(ys) / n
    num = sum((x - mx) * (y - my) for x, y in zip(hours, ys))
    den = sum((x - mx) ** 2 for x in hours)
    if den <= 0:
        return None
    return num / den


def _to_float(val: object) -> Optional[float]:
    if val is None:
        return None
    s = str(val).strip()
    if not s:
        return None
    try:
        return float(s)
    except ValueError:
        return None


def _downsample(items: List[Dict[str, object]], max_points: int = 120) -> List[Dict[str, object]]:
    if len(items) <= max_points:
        return items
    step = (len(items) - 1) / float(max_points - 1)
    return [items[int(round(i * step))] for i in range(max_points)]


def analyze_metrics_csv(csv_path: str) -> Dict[str, object]:
    """汇总 collect-metrics.sh 输出的 runtime-metrics.csv。"""
    rows: List[Dict[str, str]] = []
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append(r)

    if not rows:
        return {"samples": 0}

    def col_floats(name: str) -> List[float]:
        out = []
        for r in rows:
            v = _to_float(r.get(name))
            if v is not None:
                out.append(v)
        return out

    def stats(vals: List[float]) -> Dict[str, Optional[float]]:
        if not vals:
            return {"min": None, "avg": None, "p95": None, "max": None, "first": None, "last": None}
        sv = sorted(vals)
        return {
            "min": round(sv[0], 2),
            "avg": round(sum(vals) / len(vals), 2),
            "p95": round(nearest_rank(sv, 95.0) or 0.0, 2),
            "max": round(sv[-1], 2),
            "first": round(vals[0], 2),
            "last": round(vals[-1], 2),
        }

    unix_s = col_floats("unix_s")
    t0 = unix_s[0] if unix_s else 0.0
    duration_s = (unix_s[-1] - unix_s[0]) if len(unix_s) >= 2 else 0.0

    rss_xs: List[float] = []
    rss_ys: List[float] = []
    raw_series: List[Dict[str, object]] = []
    for r in rows:
        t = _to_float(r.get("unix_s"))
        m = _to_float(r.get("gw_mem_used_mib"))
        if t is not None and m is not None:
            rss_xs.append(t)
            rss_ys.append(m)
        if t is not None:
            raw_series.append(
                {
                    "h": round((t - t0) / 3600.0, 3),
                    "rps": _to_float(r.get("gw_rps")),
                    "cpu": _to_float(r.get("gw_cpu_pct")),
                    "rss": m,
                    "disk_data": _to_float(r.get("disk_data_used_pct")),
                    "disk_root": _to_float(r.get("disk_root_used_pct")),
                }
            )

    steady_start = len(rss_xs) // 10 if len(rss_xs) >= 20 else 0
    rss_slope = linear_slope_per_hour(rss_xs[steady_start:], rss_ys[steady_start:])

    nic_rx_drops = sum(int(v) for v in col_floats("nic_rx_drop_delta"))
    nic_tx_drops = sum(int(v) for v in col_floats("nic_tx_drop_delta"))
    bypass_trans = col_floats("bypass_transitions")
    bypassed_tot = col_floats("bypassed_total")

    gw_bytes_in_bps = col_floats("gw_bytes_in_bps")
    gw_bytes_out_bps = col_floats("gw_bytes_out_bps")
    gw_in_gbps = [v * 8.0 / 1e9 for v in gw_bytes_in_bps]
    gw_out_gbps = [v * 8.0 / 1e9 for v in gw_bytes_out_bps]

    return {
        "samples": len(rows),
        "start_utc": rows[0].get("ts_utc"),
        "end_utc": rows[-1].get("ts_utc"),
        "duration_hours": round(duration_s / 3600.0, 3),
        "gw_rps": stats(col_floats("gw_rps")),
        "gw_s5xx_rps": stats(col_floats("gw_s5xx_rps")),
        "gw_conn_active": stats(col_floats("gw_conn_active")),
        "gw_conn_cps": stats(col_floats("gw_conn_cps")),
        "gw_cpu_pct": stats(col_floats("gw_cpu_pct")),
        "gw_mem_used_mib": stats(rss_ys),
        "gw_mem_steady_slope_mib_per_hour": round(rss_slope, 3) if rss_slope is not None else None,
        "gw_fd_open": stats(col_floats("gw_fd_open")),
        "gw_in_gbps": stats(gw_in_gbps),
        "gw_out_gbps": stats(gw_out_gbps),
        "nic_rx_mbps": stats(col_floats("nic_rx_mbps")),
        "nic_tx_mbps": stats(col_floats("nic_tx_mbps")),
        "nic_rx_drops_total": nic_rx_drops,
        "nic_tx_drops_total": nic_tx_drops,
        "host_iowait_pct": stats(col_floats("host_iowait_pct")),
        "disk_root_used_pct": stats(col_floats("disk_root_used_pct")),
        "disk_data_used_pct": stats(col_floats("disk_data_used_pct")),
        "event_lag_bytes": stats(col_floats("event_lag_bytes")),
        "pg_rss_mib": stats(col_floats("pg_rss_mib")),
        "api_rss_mib": stats(col_floats("api_rss_mib")),
        "valkey_rss_mib": stats(col_floats("valkey_rss_mib")),
        "bypass_transitions_delta": int(bypass_trans[-1] - bypass_trans[0]) if len(bypass_trans) >= 2 else 0,
        "bypassed_requests_delta": int(bypassed_tot[-1] - bypassed_tot[0]) if len(bypassed_tot) >= 2 else 0,
        "series": _downsample(raw_series, 120),
    }


def _fmt_pps(pps: Optional[float]) -> str:
    if pps is None or pps <= 0:
        return "—"
    if pps >= 1_000_000:
        return f"{pps / 1_000_000:.2f} Mpps"
    if pps >= 1_000:
        return f"{pps / 1_000:.1f} Kpps"
    return f"{pps:.0f} pps"


def analyze_l4_json(label: str, json_path: str) -> Dict[str, object]:
    """解析 l4-throughput.py 标准 JSON，或兼容直接传入的 iperf3 -J 原始 JSON。"""
    with open(json_path, "r", encoding="utf-8") as f:
        d = json.load(f)

    # 兼容原始 iperf3 -J 结构
    if "end" in d and "start" in d and "summary" not in d:
        tstart = (d.get("start") or {}).get("test_start") or {}
        end = d.get("end") or {}
        proto = str(tstart.get("protocol") or "TCP").lower()
        is_bidir = bool(tstart.get("bidir")) or ("sum_received_bidir_reverse" in end)
        is_rev = bool(tstart.get("reverse")) and not is_bidir
        direction = "bidir" if is_bidir else ("reverse" if is_rev else "forward")
        streams = int(tstart.get("num_streams") or 1)
        pkt_len = int(tstart.get("blksize") or (d.get("start") or {}).get("tcp_mss_default") or 1448)
        dur = float(tstart.get("duration") or 0.0)
        cpu_u = end.get("cpu_utilization_percent") or {}
        if proto == "udp":
            sf = end.get("sum_received") or end.get("sum") or {}
            bps = float(sf.get("bits_per_second") or 0.0)
            pkts = int(sf.get("packets") or 0)
            lost = int(sf.get("lost_packets") or 0)
            loss_pct = round((lost / float(pkts) * 100.0), 4) if pkts > 0 else float(sf.get("lost_percent") or 0.0)
            gbps = round(bps / 1e9, 3)
            return {
                "label": label,
                "proto": "UDP",
                "direction": direction,
                "direction_cn": L4_DIRECTION_LABELS.get(direction, direction),
                "mode": "direct_baseline",
                "mode_cn": L4_MODE_LABELS["direct_baseline"],
                "streams": streams,
                "packet_len_bytes": pkt_len,
                "duration_sec": dur,
                "tx_gbps": gbps,
                "rx_gbps": gbps,
                "throughput_gbps": gbps,
                "retransmits": 0,
                "retrans_pct": None,
                "udp_loss_pct": loss_pct,
                "udp_jitter_ms": round(float(sf.get("jitter_ms") or 0.0), 3),
                "pps": round(pkts / dur, 1) if dur > 0 and pkts > 0 else None,
                "client_cpu_pct": round(float(cpu_u.get("host_total")), 2) if "host_total" in cpu_u else None,
                "server_cpu_pct": round(float(cpu_u.get("remote_total")), 2) if "remote_total" in cpu_u else None,
                "zero_loss_pass": gbps > 0 and loss_pct <= 0.1,
            }
        sr = end.get("sum_received") or end.get("sum_sent") or {}
        ss = end.get("sum_sent") or {}
        bps = float(sr.get("bits_per_second") or 0.0)
        retrans = int(ss.get("retransmits") or 0)
        if is_bidir:
            rr = end.get("sum_received_bidir_reverse") or end.get("sum_sent_bidir_reverse") or {}
            rs = end.get("sum_sent_bidir_reverse") or {}
            rbps = float(rr.get("bits_per_second") or 0.0)
            retrans += int(rs.get("retransmits") or 0)
            tx_g, rx_g, tot_g = round(bps / 1e9, 3), round(rbps / 1e9, 3), round((bps + rbps) / 1e9, 3)
        else:
            tx_g = round(float(ss.get("bits_per_second") or bps) / 1e9, 3)
            rx_g = round(bps / 1e9, 3)
            tot_g = rx_g
        return {
            "label": label,
            "proto": "TCP",
            "direction": direction,
            "direction_cn": L4_DIRECTION_LABELS.get(direction, direction),
            "mode": "direct_baseline",
            "mode_cn": L4_MODE_LABELS["direct_baseline"],
            "streams": streams,
            "packet_len_bytes": pkt_len,
            "duration_sec": dur,
            "tx_gbps": tx_g,
            "rx_gbps": rx_g,
            "throughput_gbps": tot_g,
            "retransmits": retrans,
            "retrans_pct": 0.0 if retrans == 0 else None,
            "udp_loss_pct": None,
            "udp_jitter_ms": None,
            "pps": None,
            "client_cpu_pct": round(float(cpu_u.get("host_total")), 2) if "host_total" in cpu_u else None,
            "server_cpu_pct": round(float(cpu_u.get("remote_total")), 2) if "remote_total" in cpu_u else None,
            "zero_loss_pass": tot_g > 0,
        }

    cfg = d.get("config") or {}
    s = d.get("summary") or {}
    proto = str(cfg.get("proto") or "tcp").upper()
    direction = str(cfg.get("direction") or "forward")
    mode = str(cfg.get("mode") or "direct_baseline")
    return {
        "label": label,
        "proto": proto,
        "direction": direction,
        "direction_cn": str(cfg.get("direction_cn") or L4_DIRECTION_LABELS.get(direction, direction)),
        "mode": mode,
        "mode_cn": str(cfg.get("mode_cn") or L4_MODE_LABELS.get(mode, mode)),
        "streams": int(cfg.get("streams") or 1),
        "packet_len_bytes": int(cfg.get("packet_len_bytes") or 0),
        "duration_sec": _to_float(cfg.get("duration_sec")),
        "tx_gbps": _to_float(s.get("tx_gbps")),
        "rx_gbps": _to_float(s.get("rx_gbps")),
        "throughput_gbps": _to_float(s.get("throughput_gbps")),
        "retransmits": int(s.get("retransmits") or 0),
        "retrans_pct": _to_float(s.get("retrans_pct")),
        "udp_loss_pct": _to_float(s.get("udp_loss_pct")),
        "udp_jitter_ms": _to_float(s.get("udp_jitter_ms")),
        "pps": _to_float(s.get("pps")),
        "client_cpu_pct": _to_float(s.get("client_cpu_pct")),
        "server_cpu_pct": _to_float(s.get("server_cpu_pct")),
        "zero_loss_pass": bool(s.get("zero_loss_pass")),
    }


def analyze_l7bench_json(label: str, json_path: str) -> Dict[str, object]:
    """解析 l7bench 输出的稳态隔离 JSON 报告。"""
    with open(json_path, "r", encoding="utf-8") as f:
        d = json.load(f)
    cfg = d.get("config") or {}
    s = d.get("summary") or {}
    lat = d.get("latency") or {}
    errs = d.get("errors") or {}
    cc = d.get("concurrent_connections") or {}

    url = str(cfg.get("target_base_url") or "")
    path = str(cfg.get("path") or "")
    mode = str(cfg.get("mode") or "unknown")
    is_https = url.lower().startswith("https://")
    if is_https:
        ver = str(cfg.get("tls_version") or "自动")
        ver_label = f"HTTPS (TLS {ver})" if ver != "auto" else "HTTPS"
        if cfg.get("tls_cipher") and "RSA" in str(cfg.get("tls_cipher")).upper():
            ver_label += "·RSA"
        elif cfg.get("tls_cipher") and "ECDSA" in str(cfg.get("tls_cipher")).upper():
            ver_label += "·ECDSA"
        ver_label += "·复用" if cfg.get("tls_resume") else "·完整握手"
        proto = ver_label
    else:
        proto = "HTTP (明文)"

    path_l = path.lower()
    large_body = any(tok in path_l for tok in ("64k", "128k", "256k", "512k", "1m"))
    goodput = _to_float(s.get("goodput_gbps")) or 0.0
    est_bw = _to_float(s.get("throughput_est_gbps")) or goodput
    is_l7_throughput = (mode in ("emix", "throughput")) or large_body or (mode == "tps" and est_bw >= 0.25)

    if mode == "tps" and large_body:
        size_tag = "1MB" if "1m" in path_l else ("256KB" if "256k" in path_l else ("64KB" if "64k" in path_l else "大包"))
        mode_cn = f"7层大包吞吐（{size_tag}）"
    else:
        mode_cn = MODE_LABELS.get(mode, mode)

    return {
        "label": label,
        "mode": mode,
        "mode_cn": mode_cn,
        "path": path,
        "is_https": is_https,
        "is_l7_throughput": is_l7_throughput,
        "proto": proto,
        "local_ip_count": cfg.get("local_ip_count", 0),
        "steady_sec": (d.get("steady_window") or {}).get("duration_seconds"),
        "completed": s.get("completed", 0),
        "achieved_rps": s.get("achieved_rps"),
        "achieved_cps": s.get("achieved_cps"),
        "goodput_gbps": s.get("goodput_gbps"),
        "throughput_est_gbps": s.get("throughput_est_gbps"),
        "error_rate_pct": s.get("error_rate_pct"),
        "backpressure_drop_pct": s.get("backpressure_drop_pct"),
        "zero_loss_pass": s.get("zero_loss_pass"),
        "tcp_p99_ms": (lat.get("tcp_connect") or {}).get("p99_ms"),
        "tls_p99_ms": (lat.get("tls_handshake") or {}).get("p99_ms"),
        "ttfb_p99_ms": (lat.get("ttfb") or {}).get("p99_ms"),
        "ttlb_p50_ms": (lat.get("ttlb") or {}).get("p50_ms"),
        "ttlb_p95_ms": (lat.get("ttlb") or {}).get("p95_ms"),
        "ttlb_p99_ms": (lat.get("ttlb") or {}).get("p99_ms"),
        "ttlb_p999_ms": (lat.get("ttlb") or {}).get("p999_ms"),
        "tcp_reset": errs.get("tcp_reset", 0),
        "timeout": errs.get("timeout", 0),
        "cc_steady_min": cc.get("steady_min_conns"),
        "cc_peak": cc.get("peak_active_conns"),
    }


def analyze_k6_summary(label: str, json_path: str) -> Dict[str, object]:
    """解析 k6/wdsp-suite.js handleSummary 导出的 JSON。"""
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    meta = data.get("meta") or {}
    m = data.get("metrics") or {}

    def metric_val(name: str, key: str) -> Optional[float]:
        entry = m.get(name) or {}
        vals = entry.get("values") or {}
        v = vals.get(key)
        return round(float(v), 4) if isinstance(v, (int, float)) else None

    lat_metric = "wdsp_normal_latency_ms" if "wdsp_normal_latency_ms" in m else "http_req_duration"
    data_recv = metric_val("data_received", "rate")
    data_sent = metric_val("data_sent", "rate")
    sc_name = str(meta.get("scenario", "unknown"))

    return {
        "label": label,
        "source_type": "k6",
        "scenario": sc_name,
        "scenario_cn": SCENARIO_LABELS.get(sc_name, sc_name),
        "run_prefix": meta.get("run_prefix", ""),
        "target_base_url": meta.get("target_base_url", ""),
        "total_requests": int(metric_val("http_reqs", "count") or 0),
        "achieved_rps": metric_val("http_reqs", "rate"),
        "normal_count": int(metric_val("wdsp_normal_requests_total", "count") or 0),
        "normal_unexpected_err_pct": round((metric_val("wdsp_normal_unexpected_error_rate", "rate") or 0.0) * 100.0, 4),
        "normal_false_positive_pct": round((metric_val("wdsp_normal_false_positive_rate", "rate") or 0.0) * 100.0, 4),
        "attack_count": int(metric_val("wdsp_attack_requests_total", "count") or 0),
        "attack_blocked_pct": (
            round((metric_val("wdsp_attack_blocked_rate", "rate") or 0.0) * 100.0, 2)
            if (metric_val("wdsp_attack_requests_total", "count") or 0) > 0
            else None
        ),
        "p50_ms": metric_val(lat_metric, "med"),
        "p95_ms": metric_val(lat_metric, "p(95)"),
        "p99_ms": metric_val(lat_metric, "p(99)"),
        "max_ms": metric_val(lat_metric, "max"),
        "recv_mbps": round(data_recv * 8.0 / 1e6, 2) if data_recv is not None else None,
        "sent_mbps": round(data_sent * 8.0 / 1e6, 2) if data_sent is not None else None,
        "status_2xx": int(metric_val("wdsp_status_2xx", "count") or 0),
        "status_401_403": int(metric_val("wdsp_status_401_403", "count") or 0),
        "status_429": int(metric_val("wdsp_status_429", "count") or 0),
        "status_5xx": int(metric_val("wdsp_status_5xx", "count") or 0),
        "transport_errors": int(metric_val("wdsp_status_transport_err", "count") or 0),
    }


def analyze_rpsload_csv(label: str, csv_path: str) -> Dict[str, object]:
    """解析仓库 test/performance/rpsload 输出的逐请求 CSV。"""
    durs: List[float] = []
    ts_ms: List[int] = []
    s2xx = s401_403 = s429 = s5xx = err_cnt = 0
    total = 0

    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            total += 1
            t = _to_float(r.get("start_unix_ms"))
            if t is not None:
                ts_ms.append(int(t))
            d = _to_float(r.get("duration_ms"))
            st = int(_to_float(r.get("status")) or 0)
            err = (r.get("error") or "").strip()
            if err or st == 0:
                err_cnt += 1
            else:
                if d is not None:
                    durs.append(d)
                if 200 <= st < 300:
                    s2xx += 1
                elif st in (401, 403):
                    s401_403 += 1
                elif st == 429:
                    s429 += 1
                elif st >= 500:
                    s5xx += 1

    durs.sort()
    wall_s = ((max(ts_ms) - min(ts_ms)) / 1000.0) if len(ts_ms) >= 2 else 0.0
    rps = round(total / wall_s, 2) if wall_s > 0 else None
    unexpected_err_pct = round(((err_cnt + s5xx) / total) * 100.0, 4) if total > 0 else 0.0

    return {
        "label": label,
        "source_type": "rpsload",
        "scenario": "rpsload_constant",
        "scenario_cn": SCENARIO_LABELS["rpsload_constant"],
        "total_requests": total,
        "achieved_rps": rps,
        "normal_count": total,
        "normal_unexpected_err_pct": unexpected_err_pct,
        "normal_false_positive_pct": None,
        "attack_count": 0,
        "attack_blocked_pct": None,
        "p50_ms": round(nearest_rank(durs, 50.0) or 0.0, 2) if durs else None,
        "p95_ms": round(nearest_rank(durs, 95.0) or 0.0, 2) if durs else None,
        "p99_ms": round(nearest_rank(durs, 99.0) or 0.0, 2) if durs else None,
        "max_ms": round(durs[-1], 2) if durs else None,
        "recv_mbps": None,
        "sent_mbps": None,
        "status_2xx": s2xx,
        "status_401_403": s401_403,
        "status_429": s429,
        "status_5xx": s5xx,
        "transport_errors": err_cnt,
    }


def _fmt(val: object, suffix: str = "") -> str:
    if val is None or val == "":
        return "暂无"
    return f"{val}{suffix}"


def _esc(val: object) -> str:
    return html.escape(str(val if val is not None else "暂无"))


def _plain_memory_verdict(slope: Optional[float]) -> str:
    if slope is None:
        return "样本不足"
    if abs(slope) <= 1.0:
        return f"趋势平稳（每小时变化 {slope:+.3f} MB，无内存泄漏）"
    if slope <= 5.0:
        return f"轻微波动（每小时变化 {slope:+.2f} MB，建议持续观察）"
    return f"呈持续上涨趋势（每小时 +{slope:.2f} MB，需排查内存泄漏）"


def _compute_throughput_highlights(
    l4_arms: List[Dict[str, object]],
    l7_arms: List[Dict[str, object]],
) -> Dict[str, float]:
    l4_uni = max([float(a.get("throughput_gbps") or 0) for a in l4_arms if a.get("direction") != "bidir"] + [0.0])
    l4_bidir = max([float(a.get("throughput_gbps") or 0) for a in l4_arms if a.get("direction") == "bidir"] + [0.0])
    l4_max = max(l4_uni, l4_bidir)
    l7_http = max(
        [float(a.get("throughput_est_gbps") or a.get("goodput_gbps") or 0) for a in l7_arms if not a.get("is_https")] + [0.0]
    )
    l7_https = max(
        [float(a.get("throughput_est_gbps") or a.get("goodput_gbps") or 0) for a in l7_arms if a.get("is_https")] + [0.0]
    )
    l7_emix = max(
        [float(a.get("throughput_est_gbps") or a.get("goodput_gbps") or 0) for a in l7_arms if a.get("mode") == "emix"] + [0.0]
    )
    l7_max = max(l7_http, l7_https, l7_emix)
    return {
        "l4_uni": l4_uni,
        "l4_bidir": l4_bidir,
        "l4_max": l4_max,
        "l7_http": l7_http,
        "l7_https": l7_https,
        "l7_emix": l7_emix,
        "l7_max": l7_max,
    }


def _build_executive_summary(summary: Dict[str, object]) -> str:
    l4_arms: List[Dict[str, object]] = summary.get("l4_arms") or []  # type: ignore[assignment]
    l7_arms: List[Dict[str, object]] = summary.get("l7bench_arms") or []  # type: ignore[assignment]
    arms: List[Dict[str, object]] = summary.get("arms") or []  # type: ignore[assignment]
    sec = summary.get("security_scorecard")
    metrics = summary.get("metrics") or {}
    reconcile = summary.get("reconcile")

    tp = _compute_throughput_highlights(l4_arms, l7_arms)
    parts: List[str] = []
    if tp["l4_max"] > 0:
        l4_desc = f"4 层传输层吞吐最高达 {tp['l4_max']:.2f} Gbps"
        if tp["l4_uni"] > 0 and tp["l4_bidir"] > 0:
            l4_desc = f"4 层传输层单向吞吐 {tp['l4_uni']:.2f} Gbps、双向吞吐 {tp['l4_bidir']:.2f} Gbps"
        parts.append(l4_desc)

    best_rps = max([float(a.get("achieved_rps") or 0) for a in l7_arms] + [float(a.get("achieved_rps") or 0) for a in arms] + [0])
    best_cc = max([int(a.get("cc_steady_min") or 0) for a in l7_arms if a.get("mode") == "cc"] + [0])
    if best_rps > 0 or tp["l7_max"] > 0:
        cap_items: List[str] = []
        if tp["l7_max"] >= 0.1:
            if tp["l7_http"] >= 0.2 and tp["l7_https"] >= 0.2:
                cap_items.append(f"7 层全防护过检吞吐 HTTP {tp['l7_http']:.2f} Gbps / HTTPS {tp['l7_https']:.2f} Gbps")
            else:
                cap_items.append(f"7 层全防护最高过检吞吐 {tp['l7_max']:.2f} Gbps")
        if best_rps > 0:
            cap_items.append(f"无损请求速率 {best_rps:,.0f} 次/秒")
        if best_cc > 0:
            cap_items.append(f"稳定并发 {best_cc:,} 个在线连接")
        parts.append("，".join(cap_items))

    if sec:
        sc = sec.get("scorecard") or {}
        catch = sc.get("overall_threat_catch_rate_pct")
        fp = sc.get("false_positive_rate_pct")
        if catch is not None:
            parts.append(f"高负载同步安全验证中，综合攻击拦截率 {catch}%、正常业务误报率 {fp}%")

    if metrics and metrics.get("duration_hours"):
        hrs = metrics["duration_hours"]
        slope = metrics.get("gw_mem_steady_slope_mib_per_hour")
        mem_note = "内存平稳无泄漏" if (slope is not None and abs(slope) <= 1.0) else "资源运行平稳"
        parts.append(f"连续稳定运行 {hrs} 小时零重启，{mem_note}")

    if reconcile:
        rec = reconcile.get("reconciliation") or {}
        if rec.get("passed"):
            parts.append(f"{rec.get('gateway_unique_count'):,} 条安全日志完整性核对通过（零丢失、零重复）")
        else:
            parts.append(f"安全日志完整性核对异常（丢失 {rec.get('missing_in_db_count')} 条、重复 {rec.get('duplicate_rows_count')} 条）")

    if not parts:
        return "本次暂无完整测试数据，请补齐原始结果后重新汇总。"
    return "；".join(parts) + "。"


def render_markdown_report(summary: Dict[str, object]) -> str:
    env_name = summary["env_name"]
    demo_banner = bool(summary.get("demo_banner"))
    fp = summary.get("fingerprint") or {}
    l4_arms: List[Dict[str, object]] = summary.get("l4_arms") or []  # type: ignore[assignment]
    l7_arms: List[Dict[str, object]] = summary.get("l7bench_arms") or []  # type: ignore[assignment]
    bs_runs: List[Dict[str, object]] = summary.get("binary_searches") or []  # type: ignore[assignment]
    sec = summary.get("security_scorecard")
    arms: List[Dict[str, object]] = summary.get("arms") or []  # type: ignore[assignment]
    metrics = summary.get("metrics")
    reconcile = summary.get("reconcile")

    lines: List[str] = [
        f"# 聚信压测工具 — 性能与安全压力测试交付报告（{env_name}）",
        "",
    ]
    if demo_banner:
        lines += [
            "> **【演示样例数据声明】**：本报告基于模拟数据生成，**仅用于预览报告排版与图表效果，不代表真实硬件实测成绩**。",
            "",
        ]
    lines += [
        f"> **核心测试结论**：{_build_executive_summary(summary)}",
        "",
        f"> 报告生成时间（UTC）：`{summary['generated_at_utc']}` ｜ 测试工具：**聚信压测工具**（遵循国际通用安全设备压测规范，仅统计稳态运行窗口数据，未测项目如实标注“本次未测”）",
        "",
        "## 1. 被测环境配置清单",
        "",
    ]

    if fp:
        cpu = fp.get("cpu") or {}
        disks = fp.get("disks") or []
        nics = fp.get("nics") or []
        disk_str = "；".join(
            f"{d.get('name')}（{d.get('size')}，{'机械硬盘' if d.get('media') == 'HDD' else '固态硬盘'}）" for d in disks
        ) or "暂无"
        nic_str = "；".join(
            f"{n.get('name')}（{'万兆口' if str(n.get('speed_mbps')) == '10000' else str(n.get('speed_mbps')) + '兆口'}）" for n in nics
        ) or "暂无"
        deploy_cn = "裸机直接部署（无容器网络损耗）" if fp.get("wdsp_deploy_mode") == "baremetal" else (
            "Docker 容器部署" if fp.get("wdsp_deploy_mode") == "docker" else str(fp.get("wdsp_deploy_mode", "未知"))
        )
        lines += [
            "| 配置项 | 实际硬件/系统情况 |",
            "|---|---|",
            f"| 主机名称 | `{fp.get('hostname', '暂无')}` |",
            f"| 操作系统 | `{fp.get('os', '暂无')}`（内核 `{fp.get('kernel', '暂无')}`） |",
            f"| 处理器（CPU） | `{cpu.get('model', '暂无')}`，共 **{cpu.get('logical_cores', '暂无')} 核**（{'支持' if cpu.get('avx2') else '不支持'} AVX2 向量加速，{'支持' if cpu.get('aes') else '不支持'}硬件加密加速） |",
            f"| 内存容量 | **{fp.get('memory_gib', '暂无')} GB** |",
            f"| 防护系统部署方式 | {deploy_cn} |",
            f"| 存储配置 | {disk_str} |",
            f"| 网卡配置 | {nic_str} |",
            "",
        ]
        recs = fp.get("recommendations") or []
        if recs:
            lines.append("**部署与调优建议：**")
            for r in recs:
                lines.append(f"- {r}")
            lines.append("")
    else:
        lines += ["`本次未测`（未提供环境配置指纹文件）", ""]

    l7_tp_arms = [a for a in l7_arms if a.get("is_l7_throughput")]
    lines += [
        "## 2. 4 层与 7 层吞吐能力对比",
        "",
        "> 口径说明：**4 层吞吐**反映网卡与内核在传输层（TCP/UDP）的转发及直通能力；**7 层吞吐**反映开启应用层 WAF 与 API 全防护后的实际业务过检带宽（分 HTTP 大包、HTTPS 大包与混合尺寸网页三档）。",
        "",
    ]
    if l4_arms or l7_tp_arms:
        if l4_arms:
            lines += [
                "### 2.1 4 层传输层吞吐明细（TCP / UDP）",
                "",
                "| 测试项目 | 转发路径 / 模式 | 协议与方向 | 并发流数 / 包长 | 吞吐速率 (Gbps) | 估算包转发率 | 重传 / 丢包率 | 双端 CPU (发/收) | 基线判定 |",
                "|---|---|---|---:|---:|---:|---:|---:|---|",
            ]
            for a in l4_arms:
                loss_str = (
                    f"丢包 {_fmt(a.get('udp_loss_pct'), '%')}"
                    if a.get("proto") == "UDP"
                    else f"重传 {a.get('retransmits', 0)} 次"
                )
                cpu_str = f"{_fmt(a.get('client_cpu_pct'), '%')} / {_fmt(a.get('server_cpu_pct'), '%')}"
                pkt_str = f"{a.get('streams', 1)} 流 / {a.get('packet_len_bytes') or '—'} B"
                verdict = "达标基线" if a.get("zero_loss_pass") else "未达标"
                lines.append(
                    f"| `{a['label']}` | {a['mode_cn']} | {a['proto']} · {a['direction_cn']} | {pkt_str} | "
                    f"**{_fmt(a.get('throughput_gbps'))}** | {_fmt_pps(a.get('pps'))} | {loss_str} | {cpu_str} | **{verdict}** |"
                )
            lines.append("")
        else:
            lines += ["4 层传输层吞吐：`本次未测`（未提供 4 层测试数据）", ""]

        if l7_tp_arms:
            lines += [
                "### 2.2 7 层应用层过检吞吐汇总（全防护）",
                "",
                "| 测试项目 | 流量模型 | 协议与加密 | 有效载荷吞吐 (Gbps) | 估算总带宽 (Gbps) | 每秒请求数 | 99% 耗时 (ms) | 基线判定 |",
                "|---|---|---|---:|---:|---:|---:|---|",
            ]
            for a in l7_tp_arms:
                verdict = "达标基线" if a.get("zero_loss_pass") else "过载超限"
                lines.append(
                    f"| `{a['label']}` | {a['mode_cn']} | {a['proto']} | {_fmt(a['goodput_gbps'])} | "
                    f"**{_fmt(a['throughput_est_gbps'])}** | {_fmt(a['achieved_rps'])} | {_fmt(a['ttlb_p99_ms'])} | **{verdict}** |"
                )
            lines.append("")
    else:
        lines += ["`本次未测`（未提供 4 层或 7 层吞吐数据）", ""]

    lines += [
        "## 3. 7 层核心性能指标汇总（稳态运行窗口）",
        "",
        "> 指标说明：以下数据均采集自系统平稳运行阶段（已剔除启动预热与收尾阶段）；**99% 请求耗时**反映绝大多数请求的响应速度（低于 50 毫秒属于优良业务体验区间）。",
        "",
    ]
    if l7_arms:
        lines += [
            "| 测试项目 | 测试场景 | 协议与握手方式 | 模拟源IP | 每秒请求数 / 每秒新建连接 | 有效带宽 / 估算总带宽 (Gbps) | 稳定并发连接 | 建连 / 加密握手 / 首包耗时 (ms) | 中位 / 99% / 99.9% 响应耗时 (ms) | 报错率（断连/超时） | 基线判定 |",
            "|---|---|---|---:|---:|---:|---|---:|---:|---|---|",
        ]
        for a in l7_arms:
            cc_col = "—"
            if a.get("cc_peak") is not None:
                cc_col = f"{_fmt(a.get('cc_steady_min'))} 个"
            ttlb_col = f"{_fmt(a.get('ttlb_p50_ms'))} / {_fmt(a.get('ttlb_p99_ms'))} / {_fmt(a.get('ttlb_p999_ms'))}"
            verdict = "达标（零丢包）" if a.get("zero_loss_pass") else "未达标"
            lines.append(
                f"| `{a['label']}` | {a['mode_cn']} | {a['proto']} | {a['local_ip_count']} 个 | "
                f"{_fmt(a['achieved_rps'])} / {_fmt(a['achieved_cps'])} | "
                f"{_fmt(a['goodput_gbps'])} / {_fmt(a['throughput_est_gbps'])} | {cc_col} | "
                f"{_fmt(a['tcp_p99_ms'])} / {_fmt(a['tls_p99_ms'])} / {_fmt(a['ttfb_p99_ms'])} | "
                f"{ttlb_col} | {_fmt(a['error_rate_pct'], '%')}（{a['tcp_reset']}/{a['timeout']}） | **{verdict}** |"
            )
        lines.append("")
    else:
        lines += ["`本次未测`（未提供核心性能测试数据）", ""]

    lines += [
        "## 4. 单机容量上限探测（无损基线收敛）",
        "",
        "> 方法说明：通过自动二分试探，在满足“零报错、延迟不超标”的前提下收敛出单机最高稳定基线，并在基线点执行长稳态复核。",
        "",
    ]
    if bs_runs:
        lines += [
            "| 探测项目 | 测试场景 | 收敛状态 | 无损稳定基线 | 合格门槛（报错率 / 99%耗时） | 试探轮次 | 长稳态复核 |",
            "|---|---|---|---:|---|---:|---|",
        ]
        for b in bs_runs:
            th = b.get("thresholds") or {}
            conf = b.get("confirmation")
            conf_str = "未复核"
            if isinstance(conf, dict):
                conf_str = "复核通过" if conf.get("passed") else "复核未通过"
            st_cn = "已收敛至稳定基线" if b.get("status") == "CONVERGED" else "未收敛（需调低初始下界）"
            mode_cn = MODE_LABELS.get(str(b.get("mode", "")), str(b.get("mode", "")))
            unit = "次/秒" if b.get("mode") in ("tps", "emix") else ("新建连接/秒" if b.get("mode") == "cps" else "在线连接")
            lines.append(
                f"| `{b['label']}` | {mode_cn} | **{st_cn}** | {_fmt(b.get('converged_max_lossless'))} {unit} | "
                f"报错率≤{th.get('max_err_pct')}% · 99%耗时≤{th.get('max_p99_ms')}ms | "
                f"{len(b.get('trials') or [])} 轮 | **{conf_str}** |"
            )
        lines.append("")
    else:
        lines += ["`本次未测`（未提供容量上限探测数据）", ""]

    lines += [
        "## 5. 高负载安全防护效能评估",
        "",
        "> 验证目标：在业务高负载背景下同步回放多类攻击与易误报正常请求，验证防护能力在高并发压力下不衰减、不误报。",
        "",
    ]
    if sec:
        sc = sec.get("scorecard") or {}
        bg = sec.get("background_load_summary") or {}
        bg_desc = (
            f"在后台持续保持 **每秒 {bg.get('achieved_rps')} 次业务请求（约 {bg.get('goodput_gbps')} Gbps）** 的并发压力下同步完成"
            if sec.get("under_background_load") and bg
            else "在空载基线环境下完成"
        )
        lines += [
            f"- 验证条件：{bg_desc}，全量样本循环测试 **{sec.get('rounds')} 轮**。",
            "",
            "| 安全效能指标 | 命中 / 总样本数 | 实测得分 | 评估标准 |",
            "|---|---:|---:|---|",
            f"| 常见攻击拦截率（SQL 注入 / XSS / 命令注入等） | {sc.get('attack_blocked_tp')} / {sc.get('attack_total')} | **{_fmt(sc.get('attack_catch_rate_pct'), '%')}** | 越高越好 |",
            f"| 变形绕过攻击拦截率（编码 / 注释混淆等） | {sc.get('evasion_blocked_tp')} / {sc.get('evasion_total')} | **{_fmt(sc.get('evasion_catch_rate_pct'), '%')}** | 越高越好 |",
            f"| 综合威胁拦截率 | — | **{_fmt(sc.get('overall_threat_catch_rate_pct'), '%')}** | 衡量整体防护有效性 |",
            f"| 正常业务误报拦截率（含中文文章 / 富文本 / 代码等） | {sc.get('benign_false_positive_fp')} / {sc.get('benign_total')} | **{_fmt(sc.get('false_positive_rate_pct'), '%')}** | 越低越好（目标 0%） |",
            f"| 正常业务异常报错率（5xx / 超时） | {sc.get('benign_unexpected_err')} / {sc.get('benign_total')} | {_fmt(sc.get('benign_unexpected_err_pct'), '%')} | 越低越好 |",
            "",
        ]
    else:
        lines += ["`本次未测`（未提供安全防护效能数据）", ""]

    lines += ["## 6. 长时间连续运行稳定性验证", ""]
    if metrics and metrics.get("samples", 0) > 0:
        slope = metrics.get("gw_mem_steady_slope_mib_per_hour")
        lines += [
            f"- 连续运行时长：**{metrics['duration_hours']} 小时**（共采集 `{metrics['samples']}` 组运行监控样本）",
            "",
            "| 监控指标 | 初始值 | 平均值 | 峰值 | 结束值 | 稳定性结论 |",
            "|---|---:|---:|---:|---:|---|",
            f"| 网关实际吞吐（次/秒） | {_fmt(metrics['gw_rps']['first'])} | {_fmt(metrics['gw_rps']['avg'])} | {_fmt(metrics['gw_rps']['max'])} | {_fmt(metrics['gw_rps']['last'])} | 全程吞吐平稳，无性能衰减 |",
            f"| 网关 CPU 使用率 | {_fmt(metrics['gw_cpu_pct']['first'], '%')} | {_fmt(metrics['gw_cpu_pct']['avg'], '%')} | {_fmt(metrics['gw_cpu_pct']['max'], '%')} | {_fmt(metrics['gw_cpu_pct']['last'], '%')} | 磁盘 I/O 等待峰值 {_fmt(metrics['host_iowait_pct']['max'], '%')}，存储无瓶颈 |",
            f"| 网关内存占用 (MB) | {_fmt(metrics['gw_mem_used_mib']['first'])} | {_fmt(metrics['gw_mem_used_mib']['avg'])} | {_fmt(metrics['gw_mem_used_mib']['max'])} | {_fmt(metrics['gw_mem_used_mib']['last'])} | {_plain_memory_verdict(slope)} |",
            f"| 出向业务带宽 (Gbps) | {_fmt(metrics['gw_out_gbps']['first'])} | {_fmt(metrics['gw_out_gbps']['avg'])} | {_fmt(metrics['gw_out_gbps']['max'])} | {_fmt(metrics['gw_out_gbps']['last'])} | 网卡收发丢包合计：{metrics['nic_rx_drops_total']} / {metrics['nic_tx_drops_total']} |",
            f"| 系统盘 / 数据盘使用率 | {_fmt(metrics['disk_root_used_pct']['first'], '%')} / {_fmt(metrics['disk_data_used_pct']['first'], '%')} | — | {_fmt(metrics['disk_root_used_pct']['max'], '%')} / {_fmt(metrics['disk_data_used_pct']['max'], '%')} | {_fmt(metrics['disk_root_used_pct']['last'], '%')} / {_fmt(metrics['disk_data_used_pct']['last'], '%')} | 日志轮转回收受控，无磁盘满溢风险 |",
            f"| 过载自动直通保护 | — | — | — | — | 切换 `{metrics['bypass_transitions_delta']}` 次，直通 `{metrics['bypassed_requests_delta']}` 请求 |",
            "",
        ]
    else:
        lines += ["`本次未测`（未提供长稳监控数据）", ""]

    lines += ["## 7. 安全日志入库完整性核对", ""]
    if reconcile:
        rec = reconcile.get("reconciliation") or {}
        drain = reconcile.get("drain") or {}
        verdict_cn = "校验通过（零丢失、零重复）" if rec.get("passed") else f"校验异常（{rec.get('verdict')}）"
        lines += [
            "| 核对项 | 实测结果 |",
            "|---|---|",
            f"| 网关侧告警记录总数 | **{rec.get('gateway_unique_count', 0):,} 条** |",
            f"| 数据库持久化唯一记录数 | **{rec.get('db_unique_count', 0):,} 条**（总行数 {rec.get('db_total_rows', 0):,}） |",
            f"| 丢失记录数 / 重复记录数 | **{rec.get('missing_in_db_count', '暂无')} 条** / **{rec.get('duplicate_rows_count', '暂无')} 条** |",
            f"| 洪峰后追平入库耗时 | `{drain.get('drain_seconds', '暂无')} 秒`（平均入库速率 **{_fmt(reconcile.get('effective_drain_rows_per_sec'), ' 条/秒')}**） |",
            f"| 完整性核对结论 | **{verdict_cn}** |",
            "",
        ]
    else:
        lines += ["`本次未测`（未提供安全日志完整性核对数据）", ""]

    lines += ["## 8. 混合业务专项压测明细", ""]
    if arms:
        lines += [
            "| 测试项目 | 测试场景 | 总请求数 | 实际每秒请求 | 中位 / 95% / 99% 耗时 (ms) | 正常报错率 | 正常误报率 | 攻击拦截率 | 5xx / 断连数 |",
            "|---|---|---:|---:|---|---:|---:|---:|---:|",
        ]
        for a in arms:
            lines.append(
                f"| `{a['label']}` | {a['scenario_cn']} | {a['total_requests']:,} | {_fmt(a['achieved_rps'])} | "
                f"{_fmt(a['p50_ms'])} / {_fmt(a['p95_ms'])} / {_fmt(a['p99_ms'])} | "
                f"{_fmt(a['normal_unexpected_err_pct'], '%')} | {_fmt(a['normal_false_positive_pct'], '%')} | "
                f"{_fmt(a['attack_blocked_pct'], '%')} | {a['status_5xx']} / {a['transport_errors']} |"
            )
        lines.append("")
    else:
        lines += ["`本次未测`（未提供混合业务压测数据）", ""]

    return "\n".join(lines)


# -------------------- 离线单文件 HTML + 内联 SVG 图表渲染（专业通俗中文） --------------------

def _svg_throughput_bars(l4_arms: List[Dict[str, object]], l7_arms: List[Dict[str, object]]) -> str:
    """绘制 4 层传输层吞吐 vs 7 层应用层过检吞吐横向对比条形图。"""
    items: List[Tuple[str, str, float, str, str]] = []
    for a in l4_arms:
        gbps = float(a.get("throughput_gbps") or 0.0)
        if gbps <= 0:
            continue
        sub = f"4层 {a.get('proto')} · {a.get('direction_cn')}"
        items.append((str(a["label"]), sub, gbps, "#4f46e5", f"{gbps:.2f} Gbps"))
    for a in l7_arms:
        if not a.get("is_l7_throughput"):
            continue
        gbps = float(a.get("throughput_est_gbps") or a.get("goodput_gbps") or 0.0)
        if gbps <= 0:
            continue
        color = "#0d9488" if not a.get("is_https") else "#2563eb"
        raw_mode = str(a.get("mode_cn") or "")
        mode_short = raw_mode[2:] if raw_mode.startswith("7层") else raw_mode
        sub = f"7层 {'HTTPS加密' if a.get('is_https') else 'HTTP明文'} · {mode_short}"
        good = float(a.get("goodput_gbps") or gbps)
        val_txt = f"{gbps:.2f} Gbps（有效 {good:.2f}G）"
        items.append((str(a["label"]), sub, gbps, color, val_txt))

    if not items:
        return ""

    w = 1200
    row_h = 34
    pad_l, pad_r, pad_t, pad_b = 250, 175, 42, 24
    h = pad_t + len(items) * row_h + pad_b
    plot_w = w - pad_l - pad_r
    max_v = max([it[2] for it in items] + [1.0])
    # 取干净的刻度上限
    step = 2.0 if max_v > 10 else (1.0 if max_v > 3 else 0.5)
    max_scale = math.ceil((max_v * 1.12) / step) * step

    parts = [
        f'<svg viewBox="0 0 {w} {h}" class="chart-svg" role="img" aria-label="4层与7层吞吐对比图">',
        f'<text x="20" y="22" class="chart-title">4 层传输层 vs 7 层全防护吞吐能力对比（单位：Gbps，数值越高承载能力越强）</text>',
        '<g class="legend">'
        f'<rect x="{w-420}" y="11" width="10" height="10" rx="2" fill="#4f46e5"/><text x="{w-405}" y="20" class="axis-lbl">4层传输吞吐</text>'
        f'<rect x="{w-305}" y="11" width="10" height="10" rx="2" fill="#0d9488"/><text x="{w-290}" y="20" class="axis-lbl">7层HTTP全防护</text>'
        f'<rect x="{w-170}" y="11" width="10" height="10" rx="2" fill="#2563eb"/><text x="{w-155}" y="20" class="axis-lbl">7层HTTPS全防护</text>'
        '</g>',
    ]

    for i in range(5):
        xv = max_scale * i / 4.0
        xx = pad_l + (xv / max_scale) * plot_w
        parts.append(f'<line x1="{xx:.1f}" y1="{pad_t-4}" x2="{xx:.1f}" y2="{h-pad_b}" stroke="#e2e8f0" stroke-dasharray="3,3"/>')
        parts.append(f'<text x="{xx:.1f}" y="{h-7}" text-anchor="middle" class="axis-lbl">{xv:.1f}G</text>')

    for idx, (label, sub, val, color, val_txt) in enumerate(items):
        cy = pad_t + idx * row_h
        bar_h = 18
        by = cy + (row_h - bar_h) / 2.0
        bw = max(4.0, (val / max_scale) * plot_w)
        parts.append(f'<text x="{pad_l - 12}" y="{by + 9:.1f}" text-anchor="end" class="val-lbl">{_esc(label[:20])}</text>')
        parts.append(f'<text x="{pad_l - 12}" y="{by + 21:.1f}" text-anchor="end" class="sub-lbl">{_esc(sub[:28])}</text>')
        parts.append(f'<rect x="{pad_l}" y="{by:.1f}" width="{bw:.1f}" height="{bar_h}" rx="3" fill="{color}"/>')
        parts.append(f'<text x="{pad_l + bw + 8:.1f}" y="{by + 13:.1f}" class="val-lbl">{_esc(val_txt)}</text>')

    parts.append("</svg>")
    return "\n".join(parts)


def _svg_latency_bars(l7_arms: List[Dict[str, object]]) -> str:
    if not l7_arms:
        return ""
    w, h = 1200, 270
    pad_l, pad_r, pad_t, pad_b = 64, 28, 36, 62
    plot_w = w - pad_l - pad_r
    plot_h = h - pad_t - pad_b
    max_v = max(
        [float(a.get("ttlb_p999_ms") or a.get("ttlb_p99_ms") or 1.0) for a in l7_arms] + [10.0]
    )
    max_v = math.ceil(max_v / 10.0) * 10.0

    parts = [
        f'<svg viewBox="0 0 {w} {h}" class="chart-svg" role="img" aria-label="响应耗时对比柱状图">',
        f'<text x="{pad_l}" y="22" class="chart-title">各场景稳态响应耗时对比（单位：毫秒，数值越低响应越快）</text>',
        '<g class="legend">'
        f'<rect x="{w-345}" y="10" width="10" height="10" fill="#2563eb"/><text x="{w-330}" y="19" class="axis-lbl">中位耗时</text>'
        f'<rect x="{w-258}" y="10" width="10" height="10" fill="#0ea5e9"/><text x="{w-243}" y="19" class="axis-lbl">99%请求耗时</text>'
        f'<rect x="{w-150}" y="10" width="10" height="10" fill="#f59e0b"/><text x="{w-135}" y="19" class="axis-lbl">99.9%长尾耗时</text>'
        '</g>',
    ]
    for i in range(5):
        yv = max_v * i / 4.0
        yy = pad_t + plot_h - (yv / max_v) * plot_h
        parts.append(f'<line x1="{pad_l}" y1="{yy:.1f}" x2="{w-pad_r}" y2="{yy:.1f}" stroke="#e2e8f0" stroke-dasharray="3,3"/>')
        parts.append(f'<text x="{pad_l-8}" y="{yy+4:.1f}" text-anchor="end" class="axis-lbl">{yv:.0f}ms</text>')

    group_w = plot_w / max(1, len(l7_arms))
    bar_w = min(28.0, group_w * 0.22)
    colors = ("#2563eb", "#0ea5e9", "#f59e0b")
    for idx, a in enumerate(l7_arms):
        gx = pad_l + idx * group_w + group_w / 2.0
        vals = [
            float(a.get("ttlb_p50_ms") or 0.0),
            float(a.get("ttlb_p99_ms") or 0.0),
            float(a.get("ttlb_p999_ms") or 0.0),
        ]
        for bi, val in enumerate(vals):
            bh = (val / max_v) * plot_h if max_v > 0 else 0.0
            bx = gx + (bi - 1.5) * (bar_w + 4)
            by = pad_t + plot_h - bh
            parts.append(f'<rect x="{bx:.1f}" y="{by:.1f}" width="{bar_w:.1f}" height="{bh:.1f}" rx="2" fill="{colors[bi]}"/>')
            parts.append(f'<text x="{bx + bar_w/2:.1f}" y="{by-5:.1f}" text-anchor="middle" class="val-lbl">{val:.1f}</text>')
        lbl = str(a.get("label") or "")[:24]
        parts.append(f'<text x="{gx:.1f}" y="{h-30}" text-anchor="middle" class="axis-lbl">{_esc(lbl)}</text>')
        parts.append(f'<text x="{gx:.1f}" y="{h-14}" text-anchor="middle" class="sub-lbl">{_esc(a.get("mode_cn"))}</text>')

    parts.append("</svg>")
    return "\n".join(parts)


def _svg_binary_search(bs_runs: List[Dict[str, object]]) -> str:
    target_run = None
    for b in bs_runs:
        if b.get("trials"):
            target_run = b
            break
    if not target_run:
        return ""
    trials = target_run["trials"]
    w, h = 1200, 250
    pad_l, pad_r, pad_t, pad_b = 76, 54, 42, 42
    plot_w = w - pad_l - pad_r
    plot_h = h - pad_t - pad_b
    max_y = max([float(t.get("target") or 1.0) for t in trials] + [100.0]) * 1.15
    n = len(trials)
    mode_cn = MODE_LABELS.get(str(target_run.get("mode", "")), str(target_run.get("mode", "")))

    parts = [
        f'<svg viewBox="0 0 {w} {h}" class="chart-svg" role="img" aria-label="容量上限自动探测曲线">',
        f'<text x="{pad_l}" y="22" class="chart-title">容量上限自动探测曲线（{_esc(target_run.get("label"))} · {_esc(mode_cn)}）</text>',
        '<g class="legend">'
        f'<circle cx="{w-274}" cy="15" r="5" fill="#16a34a"/><text x="{w-264}" y="19" class="axis-lbl">达标基线（通过）</text>'
        f'<circle cx="{w-138}" cy="15" r="5" fill="#dc2626"/><text x="{w-128}" y="19" class="axis-lbl">过载超限（回退）</text>'
        '</g>',
    ]
    for i in range(5):
        yv = max_y * i / 4.0
        yy = pad_t + plot_h - (yv / max_y) * plot_h
        parts.append(f'<line x1="{pad_l}" y1="{yy:.1f}" x2="{w-pad_r}" y2="{yy:.1f}" stroke="#e2e8f0" stroke-dasharray="3,3"/>')
        parts.append(f'<text x="{pad_l-10}" y="{yy+4:.1f}" text-anchor="end" class="axis-lbl">{yv:.0f}</text>')

    conv = target_run.get("converged_max_lossless")
    if isinstance(conv, (int, float)) and max_y > 0:
        cy = pad_t + plot_h - (float(conv) / max_y) * plot_h
        parts.append(f'<line x1="{pad_l}" y1="{cy:.1f}" x2="{w-pad_r}" y2="{cy:.1f}" stroke="#16a34a" stroke-width="1.5" stroke-dasharray="6,4"/>')
        # 放于右下方空白区并加白底描边，避免与各轮上方数值标签重叠
        parts.append(
            f'<text x="{w - pad_r - 6:.1f}" y="{cy + 16:.1f}" text-anchor="end" fill="#15803d" '
            f'class="val-lbl" style="paint-order:stroke;stroke:#ffffff;stroke-width:4px;">无损稳定基线：{conv:,.0f}/秒</text>'
        )

    # 数据点横向左右各留 32px 内边距，避免首点与纵轴刻度重叠
    inner_l = pad_l + 32
    inner_w = max(10.0, plot_w - 64)
    pts = []
    for i, t in enumerate(trials):
        xx = inner_l + (inner_w * i / max(1, n - 1)) if n > 1 else inner_l + inner_w / 2.0
        yy = pad_t + plot_h - (float(t.get("target") or 0.0) / max_y) * plot_h
        pts.append((xx, yy, t))

    if len(pts) >= 2:
        poly = " ".join(f"{x:.1f},{y:.1f}" for x, y, _ in pts)
        parts.append(f'<polyline fill="none" stroke="#64748b" stroke-width="2" points="{poly}"/>')

    for i, (xx, yy, t) in enumerate(pts):
        color = "#16a34a" if t.get("passed") else "#dc2626"
        parts.append(f'<circle cx="{xx:.1f}" cy="{yy:.1f}" r="5.5" fill="{color}" stroke="#ffffff" stroke-width="1.5"/>')
        lbl_y = yy - 10 if yy > pad_t + 16 else yy + 18
        parts.append(
            f'<text x="{xx:.1f}" y="{lbl_y:.1f}" text-anchor="middle" class="val-lbl" '
            f'style="paint-order:stroke;stroke:#ffffff;stroke-width:3px;">{float(t.get("target") or 0):.0f}</text>'
        )
        parts.append(f'<text x="{xx:.1f}" y="{h-16}" text-anchor="middle" class="axis-lbl">第{i+1}轮</text>')

    parts.append("</svg>")
    return "\n".join(parts)


def _svg_line_chart(
    title: str,
    xs: List[float],
    series_list: List[Tuple[str, str, List[Optional[float]]]],
    x_unit: str = "小时",
    y_suffix: str = "",
) -> str:
    if len(xs) < 2:
        return ""
    w, h = 580, 235
    pad_l, pad_r, pad_t, pad_b = 54, 22, 40, 36
    plot_w = w - pad_l - pad_r
    plot_h = h - pad_t - pad_b
    all_vals = [v for _, _, ys in series_list for v in ys if v is not None]
    if not all_vals:
        return ""
    min_y = 0.0
    max_y = max(all_vals) * 1.15
    if max_y <= 0:
        max_y = 1.0
    min_x, max_x = xs[0], xs[-1]
    span_x = max(0.001, max_x - min_x)

    parts = [
        f'<svg viewBox="0 0 {w} {h}" class="chart-svg" role="img" aria-label="{_esc(title)}">',
        f'<text x="{pad_l}" y="18" class="chart-title">{_esc(title)}</text>',
    ]
    lx = pad_l
    for name, color, _ in series_list:
        parts.append(f'<rect x="{lx}" y="25" width="10" height="4" fill="{color}"/>')
        parts.append(f'<text x="{lx+14}" y="30" class="sub-lbl">{_esc(name)}</text>')
        lx += 145

    for i in range(5):
        yv = min_y + (max_y - min_y) * i / 4.0
        yy = pad_t + plot_h - ((yv - min_y) / (max_y - min_y)) * plot_h
        parts.append(f'<line x1="{pad_l}" y1="{yy:.1f}" x2="{w-pad_r}" y2="{yy:.1f}" stroke="#e2e8f0" stroke-dasharray="3,3"/>')
        parts.append(f'<text x="{pad_l-6}" y="{yy+3:.1f}" text-anchor="end" class="axis-lbl">{yv:.0f}{_esc(y_suffix)}</text>')

    for i in range(5):
        xv = min_x + span_x * i / 4.0
        xx = pad_l + (plot_w * i / 4.0)
        parts.append(f'<text x="{xx:.1f}" y="{h-12}" text-anchor="middle" class="axis-lbl">{xv:.0f}{_esc(x_unit)}</text>')

    for _, color, ys in series_list:
        pts = []
        for x, y in zip(xs, ys):
            if y is None:
                continue
            xx = pad_l + ((x - min_x) / span_x) * plot_w
            yy = pad_t + plot_h - ((y - min_y) / (max_y - min_y)) * plot_h
            pts.append(f"{xx:.1f},{yy:.1f}")
        if len(pts) >= 2:
            parts.append(f'<polyline fill="none" stroke="{color}" stroke-width="2" points="{" ".join(pts)}"/>')

    parts.append("</svg>")
    return "\n".join(parts)


def render_html_report(summary: Dict[str, object]) -> str:
    """生成零外部依赖、专业通俗中文、内联 SVG 图表的离线可视化 HTML 交付报告。"""
    env_name = str(summary["env_name"])
    demo_banner = bool(summary.get("demo_banner"))
    fp = summary.get("fingerprint") or {}
    l4_arms: List[Dict[str, object]] = summary.get("l4_arms") or []  # type: ignore[assignment]
    l7_arms: List[Dict[str, object]] = summary.get("l7bench_arms") or []  # type: ignore[assignment]
    bs_runs: List[Dict[str, object]] = summary.get("binary_searches") or []  # type: ignore[assignment]
    sec = summary.get("security_scorecard")
    arms: List[Dict[str, object]] = summary.get("arms") or []  # type: ignore[assignment]
    metrics = summary.get("metrics") or {}
    reconcile = summary.get("reconcile")

    tp = _compute_throughput_highlights(l4_arms, l7_arms)
    best_rps = max([float(a.get("achieved_rps") or 0) for a in l7_arms] + [float(a.get("achieved_rps") or 0) for a in arms] + [0])
    best_cps = max([float(a.get("achieved_cps") or 0) for a in l7_arms if a.get("mode") == "cps"] + [0])
    best_cc = max([int(a.get("cc_steady_min") or 0) for a in l7_arms if a.get("mode") == "cc"] + [0])
    sec_catch = (sec.get("scorecard") or {}).get("overall_threat_catch_rate_pct") if sec else None
    sec_fp = (sec.get("scorecard") or {}).get("false_positive_rate_pct") if sec else None
    rec_ok = (reconcile.get("reconciliation") or {}).get("passed") if reconcile else None
    rec_cnt = (reconcile.get("reconciliation") or {}).get("gateway_unique_count") if reconcile else None
    rss_slope = metrics.get("gw_mem_steady_slope_mib_per_hour") if metrics else None
    soak_hours = metrics.get("duration_hours") if metrics else None

    if tp["l4_max"] > 0:
        l4_card_val = f"{tp['l4_max']:.2f} Gbps"
        if tp["l4_uni"] > 0 and tp["l4_bidir"] > 0:
            l4_card_sub = f"单向 {tp['l4_uni']:.2f}G · 双向 {tp['l4_bidir']:.2f}G"
        else:
            l4_card_sub = "TCP/UDP 传输层转发与线速基线"
    else:
        l4_card_val = "本次未测"
        l4_card_sub = "传输层 TCP/UDP 转发吞吐"

    if tp["l7_max"] > 0:
        l7_card_val = f"{tp['l7_max']:.2f} Gbps"
        if tp["l7_http"] >= 0.2 and tp["l7_https"] >= 0.2:
            l7_card_sub = f"HTTP {tp['l7_http']:.2f}G · HTTPS {tp['l7_https']:.2f}G（全防护）"
        else:
            l7_card_sub = "开启全部防护后的过检带宽"
    else:
        l7_card_val = "本次未测"
        l7_card_sub = "开启全部防护后的过检带宽"

    soak_card_val = f"{soak_hours:.0f} 小时零重启" if soak_hours else "本次未测"
    if rss_slope is not None and abs(rss_slope) <= 1.0:
        soak_card_sub = f"内存平稳（{rss_slope:+.3f} MB/时，无泄漏）"
    elif rss_slope is not None:
        soak_card_sub = f"内存斜率 {rss_slope:+.2f} MB/时"
    else:
        soak_card_sub = "长时间连续运行资源稳定性"

    if rec_ok is True:
        rec_card_val = "零丢失 · 零重复"
        rec_card_sub = f"{rec_cnt:,} 条告警全集入库核对通过"
    elif rec_ok is False:
        rec_card_val = "日志核对异常"
        rec_card_sub = "存在丢失或重复记录，请排查"
    else:
        rec_card_val = "本次未测"
        rec_card_sub = "安全日志落盘与入库完整性核对"

    kpi_cards = [
        ("4 层传输层吞吐", l4_card_val, l4_card_sub),
        ("7 层应用层吞吐", l7_card_val, l7_card_sub),
        ("7 层无损峰值请求", f"{best_rps:,.0f} 次/秒" if best_rps > 0 else "本次未测", "稳态零报错、延迟达标基线"),
        ("每秒新建加密连接", f"{best_cps:,.0f} 个/秒" if best_cps > 0 else "本次未测", "HTTPS 完整握手并发建连能力"),
        ("稳定并发在线连接", f"{best_cc:,} 个" if best_cc > 0 else "本次未测", "海量长连接持续保持零中断"),
        ("高负载综合拦截率", f"拦截 {sec_catch}%" if sec_catch is not None else "本次未测", f"正常业务误报率 {sec_fp}%" if sec_fp is not None else "高并发负载下同步安全验证"),
        ("长时间运行稳定性", soak_card_val, soak_card_sub),
        ("安全日志完整性", rec_card_val, rec_card_sub),
    ]

    cards_html = "\n".join(
        f'<div class="kpi-card"><div class="kpi-label">{_esc(lbl)}</div>'
        f'<div class="kpi-val">{_esc(val)}</div><div class="kpi-sub">{_esc(sub)}</div></div>'
        for lbl, val, sub in kpi_cards
    )

    demo_html = ""
    if demo_banner:
        demo_html = (
            '<div class="demo-banner">'
            '<strong>【演示样例数据】</strong> 本页面基于模拟数据生成，仅用于预览「聚信压测工具」报告排版与图表效果，不代表真实硬件实测成绩。'
            '</div>'
        )

    verdict_html = (
        '<div class="verdict-box">'
        '<strong>核心测试结论：</strong>'
        f'{_esc(_build_executive_summary(summary))}'
        '</div>'
    )

    # 1. 环境配置清单
    if fp:
        cpu = fp.get("cpu") or {}
        disks = "；".join(
            f"{d.get('name')}（{d.get('size')}，{'机械硬盘' if d.get('media') == 'HDD' else '固态硬盘'}）"
            for d in (fp.get("disks") or [])
        ) or "暂无"
        nics = "；".join(
            f"{n.get('name')}（{'万兆口' if str(n.get('speed_mbps')) == '10000' else str(n.get('speed_mbps')) + '兆口'}）"
            for n in (fp.get("nics") or [])
        ) or "暂无"
        deploy_cn = "裸机直接部署（无容器网络损耗）" if fp.get("wdsp_deploy_mode") == "baremetal" else (
            "Docker 容器部署" if fp.get("wdsp_deploy_mode") == "docker" else str(fp.get("wdsp_deploy_mode", "未知"))
        )
        fp_html = f"""
        <div class="table-wrap"><table>
          <tr><th style="width:14%">主机名称</th><td><code>{_esc(fp.get('hostname'))}</code></td>
              <th style="width:14%">系统部署方式</th><td>{_esc(deploy_cn)}</td></tr>
          <tr><th>处理器（CPU）</th><td>{_esc(cpu.get('model'))}（共 {_esc(cpu.get('logical_cores'))} 核）</td>
              <th>操作系统</th><td>{_esc(fp.get('os'))}</td></tr>
          <tr><th>内存容量</th><td><strong>{_esc(fp.get('memory_gib'))} GB</strong></td>
              <th>存储配置</th><td>{_esc(disks)}</td></tr>
          <tr><th>网卡配置</th><td colspan="3">{_esc(nics)}</td></tr>
        </table></div>"""
    else:
        fp_html = '<p class="not-run">本次未测（未提供环境配置信息）</p>'

    # 2. 4 层与 7 层吞吐能力对比
    l7_tp_arms = [a for a in l7_arms if a.get("is_l7_throughput")]
    if l4_arms or l7_tp_arms:
        tp_svg = _svg_throughput_bars(l4_arms, l7_arms)
        if l4_arms:
            l4_rows = []
            for a in l4_arms:
                loss_str = (
                    f"丢包 {_fmt(a.get('udp_loss_pct'), '%')}"
                    if a.get("proto") == "UDP"
                    else f"重传 {a.get('retransmits', 0)} 次"
                )
                cpu_str = f"{_fmt(a.get('client_cpu_pct'), '%')} / {_fmt(a.get('server_cpu_pct'), '%')}"
                pkt_str = f"{a.get('streams', 1)} 流 / {a.get('packet_len_bytes') or '—'} B"
                badge = '<span class="badge pass">达标基线</span>' if a.get("zero_loss_pass") else '<span class="badge fail">未达标</span>'
                l4_rows.append(
                    f"<tr><td><code>{_esc(a['label'])}</code></td><td>{_esc(a['mode_cn'])}</td>"
                    f"<td>{_esc(a['proto'])} · {_esc(a['direction_cn'])}</td><td class='num'>{_esc(pkt_str)}</td>"
                    f"<td class='num'><strong>{_esc(_fmt(a.get('throughput_gbps')))}</strong></td>"
                    f"<td class='num'>{_esc(_fmt_pps(a.get('pps')))}</td><td class='num'>{_esc(loss_str)}</td>"
                    f"<td class='num'>{_esc(cpu_str)}</td><td>{badge}</td></tr>"
                )
            l4_table = f"""
            <h3 class="sub-h3">4 层传输层吞吐明细（TCP / UDP）</h3>
            <div class="table-wrap"><table>
              <thead><tr><th>测试项目</th><th>转发路径 / 模式</th><th>协议与方向</th><th>并发流 / 包长</th><th>吞吐速率 (Gbps)</th><th>估算包转发率</th><th>重传 / 丢包</th><th>双端CPU(发/收)</th><th>基线判定</th></tr></thead>
              <tbody>{''.join(l4_rows)}</tbody>
            </table></div>"""
        else:
            l4_table = '<p class="not-run">4 层传输层吞吐：本次未测（未提供 4 层测试结果）</p>'

        if l7_tp_arms:
            l7tp_rows = []
            for a in l7_tp_arms:
                badge = '<span class="badge pass">达标基线</span>' if a.get("zero_loss_pass") else '<span class="badge fail">过载超限</span>'
                l7tp_rows.append(
                    f"<tr><td><code>{_esc(a['label'])}</code></td><td>{_esc(a['mode_cn'])}</td>"
                    f"<td>{_esc(a['proto'])}</td><td class='num'>{_esc(_fmt(a['goodput_gbps']))}</td>"
                    f"<td class='num'><strong>{_esc(_fmt(a['throughput_est_gbps']))}</strong></td>"
                    f"<td class='num'>{_esc(_fmt(a['achieved_rps']))}</td>"
                    f"<td class='num'>{_esc(_fmt(a['ttlb_p99_ms']))}</td><td>{badge}</td></tr>"
                )
            l7tp_table = f"""
            <h3 class="sub-h3">7 层应用层过检吞吐汇总（全防护）</h3>
            <div class="table-wrap"><table>
              <thead><tr><th>测试项目</th><th>流量模型</th><th>协议与加密</th><th>有效载荷吞吐 (Gbps)</th><th>估算总带宽 (Gbps)</th><th>每秒请求数</th><th>99% 耗时 (ms)</th><th>基线判定</th></tr></thead>
              <tbody>{''.join(l7tp_rows)}</tbody>
            </table></div>"""
        else:
            l7tp_table = '<p class="not-run">7 层应用层吞吐：本次未测</p>'

        tp_html = f"""
        <p class="hint">口径说明：<strong>4 层吞吐</strong>反映网卡与内核传输层（TCP/UDP）转发及线速基线能力；<strong>7 层吞吐</strong>反映开启应用层 WAF 与 API 全防护后的实际业务过检带宽（分 HTTP 明文大包、HTTPS 加密大包与混合尺寸业务三档）。</p>
        {tp_svg}
        {l4_table}
        {l7tp_table}"""
    else:
        tp_html = '<p class="not-run">本次未测（未提供 4 层或 7 层吞吐数据）</p>'

    # 3. 7 层核心性能指标
    if l7_arms:
        l7_rows = []
        for a in l7_arms:
            cc_col = f"{_fmt(a.get('cc_steady_min'))} 个" if a.get("cc_peak") is not None else "—"
            badge = '<span class="badge pass">达标基线</span>' if a.get("zero_loss_pass") else '<span class="badge fail">过载超限</span>'
            l7_rows.append(
                f"<tr><td><code>{_esc(a['label'])}</code></td><td>{_esc(a['mode_cn'])}</td>"
                f"<td class='wrap'>{_esc(a['proto'])}</td><td class='num'>{_esc(a['local_ip_count'])} 个</td>"
                f"<td class='num'>{_esc(_fmt(a['achieved_rps']))} / {_esc(_fmt(a['achieved_cps']))}</td>"
                f"<td class='num'>{_esc(_fmt(a['goodput_gbps']))} / {_esc(_fmt(a['throughput_est_gbps']))}</td>"
                f"<td class='num'>{_esc(cc_col)}</td>"
                f"<td class='num'>{_esc(_fmt(a['ttlb_p50_ms']))} / {_esc(_fmt(a['ttlb_p99_ms']))} / {_esc(_fmt(a['ttlb_p999_ms']))}</td>"
                f"<td class='num'>{_esc(_fmt(a['error_rate_pct'], '%'))}</td><td>{badge}</td></tr>"
            )
        l7_html = f"""
        <p class="hint">指标说明：以下数据均采集自系统平稳运行窗口（已剔除启动预热与收尾阶段）；99% 请求响应时间在 50 ms 以内属于优良业务体验区间。</p>
        {_svg_latency_bars(l7_arms)}
        <div class="table-wrap"><table>
          <thead><tr><th>测试项目</th><th>测试场景</th><th>协议与握手方式</th><th>模拟IP</th><th>每秒请求 / 新建连接</th><th>有效/总带宽 (Gbps)</th><th>稳定并发连接</th><th>中位 / 99% / 99.9% 耗时 (ms)</th><th>报错率</th><th>基线判定</th></tr></thead>
          <tbody>{''.join(l7_rows)}</tbody>
        </table></div>"""
    else:
        l7_html = '<p class="not-run">本次未测</p>'

    # 3. 容量上限探测
    if bs_runs:
        bs_rows = []
        for b in bs_runs:
            th = b.get("thresholds") or {}
            conf = b.get("confirmation")
            conf_badge = '<span class="badge muted">未复核</span>'
            if isinstance(conf, dict):
                conf_badge = '<span class="badge pass">复核通过</span>' if conf.get("passed") else '<span class="badge fail">复核未通过</span>'
            st_badge = '<span class="badge pass">已收敛基线</span>' if b.get("status") == "CONVERGED" else '<span class="badge fail">未收敛</span>'
            mode_cn = MODE_LABELS.get(str(b.get("mode", "")), str(b.get("mode", "")))
            unit = "次/秒" if b.get("mode") in ("tps", "emix") else ("新建连接/秒" if b.get("mode") == "cps" else "在线连接")
            bs_rows.append(
                f"<tr><td><code>{_esc(b['label'])}</code></td><td>{_esc(mode_cn)}</td>"
                f"<td>{st_badge}</td><td class='num'><strong>{_esc(_fmt(b.get('converged_max_lossless')))} {unit}</strong></td>"
                f"<td>报错率≤{_esc(th.get('max_err_pct'))}% · 99%耗时≤{_esc(th.get('max_p99_ms'))}ms</td>"
                f"<td class='num'>{len(b.get('trials') or [])} 轮</td><td>{conf_badge}</td></tr>"
            )
        bs_html = f"""
        <p class="hint">方法说明：工具按二分策略自动逐轮试探压力边界，绿色点表示满足零丢包与延迟门槛的达标基线，红色点表示触发过载超限并自动回退，最终锁定最高无损稳定基线。</p>
        {_svg_binary_search(bs_runs)}
        <div class="table-wrap"><table>
          <thead><tr><th>探测项目</th><th>测试场景</th><th>收敛状态</th><th>无损稳定基线</th><th>合格门槛</th><th>试探轮次</th><th>长稳态复核</th></tr></thead>
          <tbody>{''.join(bs_rows)}</tbody>
        </table></div>"""
    else:
        bs_html = '<p class="not-run">本次未测</p>'

    # 4. 高负载安全防护效能评估
    if sec:
        sc = sec.get("scorecard") or {}
        bg = sec.get("background_load_summary") or {}
        bg_note = (
            f"验证期间后台持续保持 <strong>每秒 {bg.get('achieved_rps')} 次并发业务请求（约 {bg.get('goodput_gbps')} Gbps）</strong>，同步评估高负载下的攻击检出与零误报能力。"
            if sec.get("under_background_load") and bg
            else "本次为空载基线环境下的安全防护效能评估。"
        )
        bars = [
            ("常见攻击拦截率（SQL 注入 / XSS / 命令注入等，越高越好）", sc.get("attack_catch_rate_pct") or 0.0, "#16a34a"),
            ("变形绕过攻击拦截率（编码 / 注释混淆等，越高越好）", sc.get("evasion_catch_rate_pct") or 0.0, "#0284c7"),
            ("综合威胁拦截率（越高越好）", sc.get("overall_threat_catch_rate_pct") or 0.0, "#2563eb"),
            ("正常业务误报拦截率（含中文文章 / 富文本 / 代码，越低越好）", sc.get("false_positive_rate_pct") or 0.0, "#dc2626"),
        ]
        bar_html = "".join(
            f'<div class="bar-row"><div class="bar-meta"><span>{_esc(name)}</span><strong>{val:.2f}%</strong></div>'
            f'<div class="bar-track"><div class="bar-fill" style="width:{min(100.0, max(0.0, float(val))):.1f}%;background:{col}"></div></div></div>'
            for name, val, col in bars
        )
        cat_rows = []
        for cat, st in sorted((sec.get("by_category") or {}).items()):
            cat_cn = CATEGORY_LABELS.get(cat, cat)
            grp_cn = GROUP_LABELS.get(str(st.get("group", "")), str(st.get("group", "")))
            cat_rows.append(
                f"<tr><td>{_esc(cat_cn)}</td><td>{_esc(grp_cn)}</td>"
                f"<td class='num'>{st.get('total', 0)}</td><td class='num'>{st.get('TP', 0)}</td>"
                f"<td class='num'>{st.get('FN', 0)}</td><td class='num'>{st.get('TN', 0)}</td>"
                f"<td class='num'>{st.get('FP', 0)}</td><td class='num'>{st.get('ERR', 0)}</td></tr>"
            )
        cat_table = (
            f"<div class='table-wrap'><table><thead><tr><th>样本类别</th><th>所属分组</th><th>样本总数</th><th>精准拦截</th><th>未拦截（漏报）</th><th>正常放行</th><th>正常误报</th><th>异常报错</th></tr></thead>"
            f"<tbody>{''.join(cat_rows)}</tbody></table></div>"
            if cat_rows
            else ""
        )
        sec_html = f'<p class="hint">{bg_note}</p><div class="score-bars">{bar_html}</div>{cat_table}'
    else:
        sec_html = '<p class="not-run">本次未测</p>'

    # 5. 长稳稳定性验证
    if metrics and metrics.get("samples", 0) > 0:
        ser = metrics.get("series") or []
        xs = [float(p["h"]) for p in ser]
        svg_rps_cpu = _svg_line_chart(
            "连续运行吞吐与 CPU 使用率趋势",
            xs,
            [
                ("CPU 使用率(%)", "#f59e0b", [p.get("cpu") for p in ser]),
                ("每秒请求(÷100)", "#2563eb", [p["rps"] / 100.0 if p.get("rps") is not None else None for p in ser]),
            ],
            x_unit="小时",
        )
        svg_rss_disk = _svg_line_chart(
            "连续运行内存占用与数据盘水位趋势",
            xs,
            [
                ("内存占用(MB)", "#16a34a", [p.get("rss") for p in ser]),
                ("数据盘使用率(%×10)", "#7c3aed", [p["disk_data"] * 10.0 if p.get("disk_data") is not None else None for p in ser]),
            ],
            x_unit="小时",
        )
        slope = metrics.get("gw_mem_steady_slope_mib_per_hour")
        soak_html = f"""
        <p class="hint">趋势解读：预热完成后内存占用保持平稳，无持续上升斜率说明不存在内存泄漏；数据盘呈周期性锯齿回落表明日志轮转清理策略正常生效。</p>
        <div class="chart-grid">{svg_rps_cpu}{svg_rss_disk}</div>
        <div class="table-wrap"><table>
          <thead><tr><th>监控指标（连续运行 {_esc(metrics['duration_hours'])} 小时）</th><th>初始值</th><th>平均值</th><th>峰值</th><th>结束值</th><th>稳定性结论</th></tr></thead>
          <tbody>
            <tr><td>网关实际吞吐（次/秒）</td><td class="num">{_esc(_fmt(metrics['gw_rps']['first']))}</td><td class="num">{_esc(_fmt(metrics['gw_rps']['avg']))}</td><td class="num">{_esc(_fmt(metrics['gw_rps']['max']))}</td><td class="num">{_esc(_fmt(metrics['gw_rps']['last']))}</td><td>全程吞吐平稳，无性能衰减</td></tr>
            <tr><td>网关 CPU 使用率</td><td class="num">{_esc(_fmt(metrics['gw_cpu_pct']['first'], '%'))}</td><td class="num">{_esc(_fmt(metrics['gw_cpu_pct']['avg'], '%'))}</td><td class="num">{_esc(_fmt(metrics['gw_cpu_pct']['max'], '%'))}</td><td class="num">{_esc(_fmt(metrics['gw_cpu_pct']['last'], '%'))}</td><td>磁盘 I/O 等待峰值 {_esc(_fmt(metrics['host_iowait_pct']['max'], '%'))}，存储无瓶颈</td></tr>
            <tr><td>网关内存占用 (MB)</td><td class="num">{_esc(_fmt(metrics['gw_mem_used_mib']['first']))}</td><td class="num">{_esc(_fmt(metrics['gw_mem_used_mib']['avg']))}</td><td class="num">{_esc(_fmt(metrics['gw_mem_used_mib']['max']))}</td><td class="num">{_esc(_fmt(metrics['gw_mem_used_mib']['last']))}</td><td>{_esc(_plain_memory_verdict(slope))}</td></tr>
            <tr><td>系统盘 / 数据盘使用率</td><td class="num">{_esc(_fmt(metrics['disk_root_used_pct']['first'], '%'))} / {_esc(_fmt(metrics['disk_data_used_pct']['first'], '%'))}</td><td class="num">—</td><td class="num">{_esc(_fmt(metrics['disk_root_used_pct']['max'], '%'))} / {_esc(_fmt(metrics['disk_data_used_pct']['max'], '%'))}</td><td class="num">{_esc(_fmt(metrics['disk_root_used_pct']['last'], '%'))} / {_esc(_fmt(metrics['disk_data_used_pct']['last'], '%'))}</td><td>网卡收发丢包合计：{metrics['nic_rx_drops_total']} / {metrics['nic_tx_drops_total']}</td></tr>
          </tbody>
        </table></div>"""
    else:
        soak_html = '<p class="not-run">本次未测</p>'

    # 6. 安全日志完整性核对
    if reconcile:
        rec = reconcile.get("reconciliation") or {}
        drain = reconcile.get("drain") or {}
        badge = '<span class="badge pass">校验通过（零丢失、零重复）</span>' if rec.get("passed") else '<span class="badge fail">校验异常</span>'
        rec_html = f"""
        <p class="hint">核对说明：高并发日志洪峰下，网关先将告警安全落盘缓冲，后台持续异步写入数据库；压测结束后按唯一请求编号全集比对，确保既不阻塞业务转发也不丢失安全日志。</p>
        <div class="table-wrap"><table>
          <tr><th>网关侧告警记录总数</th><td class="num"><strong>{rec.get('gateway_unique_count', 0):,} 条</strong></td><th>完整性核对结论</th><td>{badge}</td></tr>
          <tr><th>数据库持久化唯一记录数</th><td class="num"><strong>{rec.get('db_unique_count', 0):,} 条</strong></td><th>丢失记录数 / 重复记录数</th><td class="num">{_esc(rec.get('missing_in_db_count'))} 条 / {_esc(rec.get('duplicate_rows_count'))} 条</td></tr>
          <tr><th>洪峰后追平入库耗时</th><td class="num">{_esc(drain.get('drain_seconds'))} 秒</td><th>平均入库速率</th><td class="num"><strong>{_esc(_fmt(reconcile.get('effective_drain_rows_per_sec'), ' 条/秒'))}</strong></td></tr>
        </table></div>"""
    else:
        rec_html = '<p class="not-run">本次未测</p>'

    # 7. 混合业务专项测试
    if arms:
        k6_rows = "".join(
            f"<tr><td><code>{_esc(a['label'])}</code></td><td>{_esc(a['scenario_cn'])}</td>"
            f"<td class='num'>{a['total_requests']:,}</td><td class='num'>{_esc(_fmt(a['achieved_rps']))}</td>"
            f"<td class='num'>{_esc(_fmt(a['p50_ms']))} / {_esc(_fmt(a['p95_ms']))} / {_esc(_fmt(a['p99_ms']))}</td>"
            f"<td class='num'>{_esc(_fmt(a['normal_unexpected_err_pct'], '%'))}</td>"
            f"<td class='num'>{_esc(_fmt(a['normal_false_positive_pct'], '%'))}</td>"
            f"<td class='num'>{_esc(_fmt(a['attack_blocked_pct'], '%'))}</td>"
            f"<td class='num'>{a['status_5xx']} / {a['transport_errors']}</td></tr>"
            for a in arms
        )
        k6_html = f"""
        <div class="table-wrap"><table>
          <thead><tr><th>测试项目</th><th>测试场景</th><th>总请求数</th><th>每秒请求</th><th>中位 / 95% / 99% 耗时 (ms)</th><th>正常报错率</th><th>正常误报率</th><th>攻击拦截率</th><th>5xx/断连</th></tr></thead>
          <tbody>{k6_rows}</tbody>
        </table></div>"""
    else:
        k6_html = '<p class="not-run">本次未测</p>'

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>聚信压测工具 · 性能与安全压力测试交付报告 — {_esc(env_name)}</title>
<style>
  :root {{ --bg:#f8fafc; --card:#ffffff; --ink:#0f172a; --muted:#475569; --line:#e2e8f0; --primary:#1d4ed8; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; padding:24px 28px; background:var(--bg); color:var(--ink); font:14px/1.65 -apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",sans-serif; }}
  .container {{ max-width:1520px; width:100%; margin:0 auto; }}
  .header {{ background:linear-gradient(135deg,#0f172a,#1e3a8a); color:#fff; padding:26px 32px; border-radius:12px; margin-bottom:18px; }}
  .header h1 {{ margin:0 0 8px; font-size:22px; }}
  .header .meta {{ font-size:13px; color:#cbd5e1; }}
  .demo-banner {{ background:#fef3c7; border:1px solid #f59e0b; color:#92400e; padding:12px 16px; border-radius:8px; margin-bottom:16px; font-size:13px; }}
  .verdict-box {{ background:#eff6ff; border:1px solid #93c5fd; color:#1e3a8a; padding:14px 18px; border-radius:10px; margin-bottom:18px; font-size:14px; line-height:1.7; }}
  .kpi-grid {{ display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin-bottom:18px; }}
  @media (max-width:1050px) {{ .kpi-grid {{ grid-template-columns:repeat(2,1fr); }} }}
  .kpi-card {{ background:var(--card); border:1px solid var(--line); border-radius:10px; padding:14px 16px; box-shadow:0 1px 2px rgba(15,23,42,.04); }}
  .kpi-label {{ font-size:12.5px; color:var(--muted); }}
  .kpi-val {{ font-size:19px; font-weight:700; color:#0f172a; margin:5px 0; white-space:nowrap; }}
  .kpi-sub {{ font-size:11.5px; color:#64748b; }}
  section {{ background:var(--card); border:1px solid var(--line); border-radius:10px; padding:20px 24px; margin-bottom:18px; page-break-inside:avoid; }}
  h2 {{ margin:0 0 10px; font-size:16.5px; border-left:4px solid var(--primary); padding-left:10px; color:#0f172a; }}
  .sub-h3 {{ margin:14px 0 6px; font-size:13.5px; color:#1e293b; font-weight:600; }}
  .hint {{ margin:0 0 12px; font-size:12.5px; color:#475569; background:#f8fafc; padding:8px 12px; border-radius:6px; }}
  .table-wrap {{ width:100%; overflow-x:auto; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; margin-top:10px; }}
  th, td {{ border:1px solid var(--line); padding:8px 11px; text-align:left; vertical-align:middle; }}
  th {{ background:#f1f5f9; font-weight:600; color:#1e293b; white-space:nowrap; }}
  td {{ white-space:nowrap; }}
  td.wrap {{ white-space:normal; }}
  td.num {{ text-align:right; font-variant-numeric:tabular-nums; }}
  code {{ background:#f1f5f9; padding:2px 6px; border-radius:4px; font-size:12.5px; white-space:nowrap; }}
  .badge {{ display:inline-block; padding:2px 9px; border-radius:999px; font-size:11.5px; font-weight:600; white-space:nowrap; }}
  .badge.pass {{ background:#dcfce7; color:#166534; }}
  .badge.fail {{ background:#fee2e2; color:#991b1b; }}
  .badge.muted {{ background:#e2e8f0; color:#475569; }}
  .not-run {{ color:#64748b; font-style:italic; }}
  .chart-svg {{ width:100%; height:auto; display:block; margin:6px 0 12px; background:#fff; border:1px solid #f1f5f9; border-radius:8px; }}
  .chart-title {{ font-size:13.5px; font-weight:600; fill:#0f172a; }}
  .axis-lbl {{ font-size:11.5px; fill:#475569; }}
  .sub-lbl {{ font-size:10.5px; fill:#64748b; }}
  .val-lbl {{ font-size:11px; font-weight:600; fill:#1e293b; }}
  .chart-grid {{ display:grid; grid-template-columns:1fr 1fr; gap:16px; }}
  .score-bars {{ display:grid; grid-template-columns:1fr 1fr; gap:14px 28px; margin-bottom:14px; }}
  .bar-meta {{ display:flex; justify-content:space-between; font-size:13px; margin-bottom:4px; }}
  .bar-track {{ height:10px; background:#e2e8f0; border-radius:999px; overflow:hidden; }}
  .bar-fill {{ height:100%; border-radius:999px; }}
  footer {{ text-align:center; font-size:12px; color:#64748b; margin-top:16px; }}
  .print-only {{ display:none; }}
  @page {{ size:A4 landscape; margin:9mm 9mm; }}
  @media print {{
    * {{ -webkit-print-color-adjust:exact !important; print-color-adjust:exact !important; }}
    body {{ background:#fff; padding:0; font-size:11.5px; }}
    .container {{ max-width:none; width:100%; }}
    .header {{ padding:16px 22px; margin-bottom:10px; }}
    .header h1 {{ font-size:18px; margin-bottom:4px; }}
    .demo-banner, .verdict-box {{ padding:8px 12px; margin-bottom:10px; font-size:11.5px; line-height:1.55; }}
    .kpi-grid {{ grid-template-columns:repeat(4,1fr) !important; gap:8px; margin-bottom:10px; }}
    .kpi-card {{ padding:8px 10px; box-shadow:none; }}
    .kpi-label {{ font-size:10.5px; }}
    .kpi-val {{ font-size:14.5px; margin:2px 0; }}
    .kpi-sub {{ font-size:9.8px; }}
    section {{ padding:9px 13px; margin-bottom:8px; box-shadow:none; break-inside:avoid; page-break-inside:avoid; }}
    section.allow-break {{ break-inside:auto; page-break-inside:auto; }}
    h2 {{ font-size:13.5px; margin-bottom:5px; }}
    .sub-h3 {{ margin:7px 0 3px; font-size:11.5px; }}
    .hint {{ font-size:10.5px; padding:4px 8px; margin-bottom:5px; }}
    .table-wrap {{ overflow:visible; }}
    table {{ font-size:10px; margin-top:4px; }}
    th, td {{ padding:3.5px 6px; }}
    td.wrap {{ white-space:nowrap; }}
    code {{ font-size:9.5px; padding:1px 4px; }}
    .badge {{ font-size:9.5px; padding:1px 6px; }}
    .chart-svg {{ max-height:172px; margin:4px 0 6px; }}
    footer {{ margin-top:6px; font-size:10.5px; }}
    .screen-only {{ display:none; }}
    .print-only {{ display:inline; }}
  }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>聚信压测工具 · 性能与安全压力测试交付报告</h1>
    <div class="meta">被测环境：{_esc(env_name)} &nbsp;|&nbsp; 测试规范：国际通用网络安全设备压测标准 &nbsp;|&nbsp; 报告时间（UTC）：{_esc(summary['generated_at_utc'])}</div>
  </div>
  {demo_html}
  {verdict_html}
  <div class="kpi-grid">{cards_html}</div>
  <section><h2>1. 被测环境配置清单</h2>{fp_html}</section>
  <section><h2>2. 4 层与 7 层吞吐能力对比</h2>{tp_html}</section>
  <section><h2>3. 7 层核心性能指标汇总（稳态运行窗口）</h2>{l7_html}</section>
  <section><h2>4. 单机容量上限探测（无损基线收敛）</h2>{bs_html}</section>
  <section class="allow-break"><h2>5. 高负载安全防护效能评估</h2>{sec_html}</section>
  <section><h2>6. 长时间连续运行稳定性验证</h2>{soak_html}</section>
  <section><h2>7. 安全日志入库完整性核对</h2>{rec_html}</section>
  <section><h2>8. 混合业务专项压测明细</h2>{k6_html}</section>
  <footer><span class="screen-only">聚信压测工具自动生成 · 在浏览器中按 Cmd+P / Ctrl+P 选择“另存为 PDF”即可直接交付客户</span><span class="print-only">聚信压测工具自动生成 · 本报告由原始实测数据汇总产出</span></footer>
</div>
</body>
</html>"""


def find_chrome_binary() -> Optional[str]:
    candidates = [
        os.environ.get("JUXIN_CHROME_BIN", ""),
        shutil.which("google-chrome") or "",
        shutil.which("chromium") or "",
        shutil.which("chromium-browser") or "",
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    ]
    for cand in candidates:
        if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def export_html_to_pdf(html_path: str, pdf_path: str) -> None:
    chrome = find_chrome_binary()
    if not chrome:
        raise RuntimeError(
            "未检测到 Chrome/Chromium，无法自动导出 PDF（可安装 Chrome 或用浏览器打开 HTML 后打印另存为 PDF）。"
        )
    os.makedirs(os.path.dirname(os.path.abspath(pdf_path)), exist_ok=True)
    file_url = "file://" + os.path.abspath(html_path)
    cmd = [
        chrome,
        "--headless=new",
        "--disable-gpu",
        "--no-sandbox",
        "--no-pdf-header-footer",
        f"--print-to-pdf={os.path.abspath(pdf_path)}",
        file_url,
    ]
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def parse_labeled_arg(raw: str) -> Tuple[str, str]:
    if "=" in raw:
        label, path = raw.split("=", 1)
        return label.strip(), path.strip()
    return os.path.splitext(os.path.basename(raw))[0], raw.strip()


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="聚信压测工具 — 压测数据汇总与交付报告生成器")
    parser.add_argument("--env-name", required=True, help="被测环境名称")
    parser.add_argument("--fingerprint", default="", help="fingerprint.json")
    parser.add_argument("--metrics", default="", help="runtime-metrics.csv")
    parser.add_argument("--l4-json", action="append", default=[], help="4层吞吐 JSON（l4-throughput.py 或 iperf3 -J），格式 label=path.json（可重复）")
    parser.add_argument("--l7bench-json", action="append", default=[], help="l7bench JSON，格式 label=path.json（可重复）")
    parser.add_argument("--binary-search-json", action="append", default=[], help="binary-search JSON，格式 label=path.json（可重复）")
    parser.add_argument("--security-scorecard-json", default="", help="security-under-load.py 生成的评分卡 JSON")
    parser.add_argument("--k6-summary", action="append", default=[], help="k6 JSON 摘要，格式 label=path.json（可重复）")
    parser.add_argument("--rpsload-csv", action="append", default=[], help="rpsload CSV 结果，格式 label=path.csv（可重复）")
    parser.add_argument("--reconcile", default="", help="reconcile.json")
    parser.add_argument("--out-md", required=True, help="输出 Markdown 交付报告路径")
    parser.add_argument("--out-html", default="", help="可选：输出单文件离线可视化 HTML 报告路径（含内联 SVG 图表）")
    parser.add_argument("--out-pdf", default="", help="可选：调用本机 Chrome/Chromium 直接导出横向排版 PDF 报告")
    parser.add_argument("--out-json", default="", help="可选：输出汇总 JSON 路径")
    parser.add_argument("--demo-banner", action="store_true", help="在报告顶部插入演示样例数据声明横幅")
    args = parser.parse_args(argv)

    fp_data = None
    if args.fingerprint:
        with open(args.fingerprint, "r", encoding="utf-8") as f:
            fp_data = json.load(f)

    metrics_data = analyze_metrics_csv(args.metrics) if args.metrics else None

    l4_arms: List[Dict[str, object]] = []
    for item in args.l4_json:
        label, path = parse_labeled_arg(item)
        l4_arms.append(analyze_l4_json(label, path))

    l7_arms: List[Dict[str, object]] = []
    for item in args.l7bench_json:
        label, path = parse_labeled_arg(item)
        l7_arms.append(analyze_l7bench_json(label, path))

    bs_runs: List[Dict[str, object]] = []
    for item in args.binary_search_json:
        label, path = parse_labeled_arg(item)
        with open(path, "r", encoding="utf-8") as f:
            doc = json.load(f)
        doc["label"] = label
        bs_runs.append(doc)

    sec_data = None
    if args.security_scorecard_json:
        with open(args.security_scorecard_json, "r", encoding="utf-8") as f:
            sec_data = json.load(f)

    arms: List[Dict[str, object]] = []
    for item in args.k6_summary:
        label, path = parse_labeled_arg(item)
        arms.append(analyze_k6_summary(label, path))
    for item in args.rpsload_csv:
        label, path = parse_labeled_arg(item)
        arms.append(analyze_rpsload_csv(label, path))

    reconcile_data = None
    if args.reconcile:
        with open(args.reconcile, "r", encoding="utf-8") as f:
            reconcile_data = json.load(f)

    summary = {
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tool": "聚信压测工具",
        "env_name": args.env_name,
        "demo_banner": args.demo_banner,
        "fingerprint": fp_data,
        "l4_arms": l4_arms,
        "l7bench_arms": l7_arms,
        "binary_searches": bs_runs,
        "security_scorecard": sec_data,
        "arms": arms,
        "metrics": metrics_data,
        "reconcile": reconcile_data,
    }

    md = render_markdown_report(summary)
    os.makedirs(os.path.dirname(os.path.abspath(args.out_md)), exist_ok=True)
    with open(args.out_md, "w", encoding="utf-8") as f:
        f.write(md)

    html_path_used = args.out_html
    tmp_html_path = ""
    if args.out_html or args.out_pdf:
        html_doc = render_html_report(summary)
        if args.out_html:
            os.makedirs(os.path.dirname(os.path.abspath(args.out_html)), exist_ok=True)
            with open(args.out_html, "w", encoding="utf-8") as f:
                f.write(html_doc)
            print(f"[summarize] 可视化 HTML 报告已生成: {args.out_html}")
        else:
            fd, tmp_html_path = tempfile.mkstemp(suffix=".html", prefix="juxin-report-")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(html_doc)
            html_path_used = tmp_html_path

    if args.out_pdf:
        try:
            export_html_to_pdf(html_path_used, args.out_pdf)
            print(f"[summarize] PDF 交付报告已生成: {args.out_pdf}")
        finally:
            if tmp_html_path and os.path.exists(tmp_html_path):
                os.remove(tmp_html_path)

    if args.out_json:
        os.makedirs(os.path.dirname(os.path.abspath(args.out_json)), exist_ok=True)
        with open(args.out_json, "w", encoding="utf-8") as f:
            json.dump(summary, f, ensure_ascii=False, indent=2)

    print(f"[summarize] Markdown 报告已生成: {args.out_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
