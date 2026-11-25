#!/usr/bin/env python3
"""聚信压测工具 — 4 层传输层（TCP/UDP）吞吐压测封装与标准化解析器（纯 Python 3 标准库）。

适用场景：
  1. 透明串接（transparent）/ 路由牵引（routed）模式下，实测设备 4 层 TCP/UDP 转发吞吐与包转发率；
  2. 反向代理（reverse_proxy）模式下，实测整机网卡/内核 4 层线速基线或软件直通（Bypass）吞吐，
     与 7 层 HTTP/HTTPS 全防护过检吞吐形成完整对照。

特性：
  - 基于系统已安装的 iperf3 -J（支持单向发送、反向接收、双向全双工、多并发流、预热剔除 -O）；
  - 也支持 --parse-raw-json 离线解析已有 iperf3 JSON 产物；
  - 产出统一结构化 JSON，可直接传给 summarize-run.py --l4-json 汇总至 Markdown / HTML / PDF 报告。
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from typing import Dict, List, Optional


L4_MODE_LABELS = {
    "direct_baseline": "整机线速基线（4层直连）",
    "transparent_bridge": "透明串接（二层桥转发）",
    "routed_forward": "路由牵引（三层转发）",
    "software_bypass": "软件直通旁路（Bypass）",
}

DIRECTION_LABELS = {
    "forward": "单向（客户端→服务端）",
    "reverse": "反向（服务端→客户端）",
    "bidir": "双向全双工（发+收合计）",
}


def _safe_float(val: object, default: float = 0.0) -> float:
    try:
        if val is None or val == "":
            return default
        return float(val)
    except (TypeError, ValueError):
        return default


def _safe_int(val: object, default: int = 0) -> int:
    try:
        if val is None or val == "":
            return default
        return int(round(float(val)))
    except (TypeError, ValueError):
        return default


def parse_iperf3_json(
    raw: Dict[str, object],
    mode: str = "direct_baseline",
    direction_override: str = "",
    target_override: str = "",
    max_loss_pct: float = 0.1,
    max_retrans_pct: float = 0.1,
) -> Dict[str, object]:
    """将 iperf3 -J 原始 JSON 转换为聚信压测工具标准 4 层吞吐结果。"""
    if raw.get("error"):
        raise RuntimeError(f"iperf3 执行报错: {raw['error']}")

    start = raw.get("start") or {}
    if not isinstance(start, dict):
        start = {}
    tstart = start.get("test_start") or {}
    if not isinstance(tstart, dict):
        tstart = {}
    end = raw.get("end") or {}
    if not isinstance(end, dict):
        end = {}

    proto = str(tstart.get("protocol") or "TCP").lower()
    if proto not in ("tcp", "udp"):
        proto = "udp" if "sum" in end and "lost_percent" in (end.get("sum") or {}) else "tcp"

    is_bidir = bool(tstart.get("bidir")) or ("sum_sent_bidir_reverse" in end) or ("sum_received_bidir_reverse" in end)
    is_reverse = bool(tstart.get("reverse")) and not is_bidir
    direction = direction_override or ("bidir" if is_bidir else ("reverse" if is_reverse else "forward"))

    streams = _safe_int(tstart.get("num_streams"), 1)
    duration_sec = _safe_float(tstart.get("duration"), 0.0)
    omit_sec = _safe_int(tstart.get("omit"), 0)
    blksize = _safe_int(tstart.get("blksize"), 0)
    mss = _safe_int(start.get("tcp_mss_default"), 1448)

    connected = start.get("connected") or []
    target = target_override
    port = 5201
    if isinstance(connected, list) and connected and isinstance(connected[0], dict):
        if not target:
            target = str(connected[0].get("remote_host") or "")
        port = _safe_int(connected[0].get("remote_port"), 5201)

    cpu_util = end.get("cpu_utilization_percent") or {}
    if not isinstance(cpu_util, dict):
        cpu_util = {}
    client_cpu = round(_safe_float(cpu_util.get("host_total"), 0.0), 2) if "host_total" in cpu_util else None
    server_cpu = round(_safe_float(cpu_util.get("remote_total"), 0.0), 2) if "remote_total" in cpu_util else None

    tx_gbps = 0.0
    rx_gbps = 0.0
    total_gbps = 0.0
    total_bytes = 0
    retransmits = 0
    retrans_pct: Optional[float] = None
    udp_lost = 0
    udp_total_pkts = 0
    udp_loss_pct: Optional[float] = None
    udp_jitter_ms: Optional[float] = None
    pps: Optional[float] = None
    zero_loss_pass = False

    if proto == "udp":
        s_fwd = end.get("sum_received") or end.get("sum") or {}
        if not isinstance(s_fwd, dict):
            s_fwd = {}
        fwd_bps = _safe_float(s_fwd.get("bits_per_second"), 0.0)
        fwd_bytes = _safe_int(s_fwd.get("bytes"), 0)
        fwd_pkts = _safe_int(s_fwd.get("packets"), 0)
        fwd_lost = _safe_int(s_fwd.get("lost_packets"), 0)
        fwd_jitter = _safe_float(s_fwd.get("jitter_ms"), 0.0)
        eff_dur = _safe_float(s_fwd.get("seconds"), duration_sec)

        if is_bidir:
            s_rev = end.get("sum_received_bidir_reverse") or end.get("sum_bidir_reverse") or {}
            if not isinstance(s_rev, dict):
                s_rev = {}
            rev_bps = _safe_float(s_rev.get("bits_per_second"), 0.0)
            rev_bytes = _safe_int(s_rev.get("bytes"), 0)
            rev_pkts = _safe_int(s_rev.get("packets"), 0)
            rev_lost = _safe_int(s_rev.get("lost_packets"), 0)
            rev_jitter = _safe_float(s_rev.get("jitter_ms"), 0.0)
            tx_gbps = round(fwd_bps / 1e9, 3)
            rx_gbps = round(rev_bps / 1e9, 3)
            total_gbps = round((fwd_bps + rev_bps) / 1e9, 3)
            total_bytes = fwd_bytes + rev_bytes
            udp_total_pkts = fwd_pkts + rev_pkts
            udp_lost = fwd_lost + rev_lost
            udp_jitter_ms = round(max(fwd_jitter, rev_jitter), 3)
        else:
            gbps = round(fwd_bps / 1e9, 3)
            tx_gbps = gbps if direction == "forward" else 0.0
            rx_gbps = gbps if direction == "reverse" else gbps
            total_gbps = gbps
            total_bytes = fwd_bytes
            udp_total_pkts = fwd_pkts
            udp_lost = fwd_lost
            udp_jitter_ms = round(fwd_jitter, 3)

        if udp_total_pkts > 0:
            udp_loss_pct = round((udp_lost / float(udp_total_pkts)) * 100.0, 4)
        else:
            udp_loss_pct = round(_safe_float(s_fwd.get("lost_percent"), 0.0), 4)
        if eff_dur > 0 and udp_total_pkts > 0:
            pps = round(udp_total_pkts / eff_dur, 1)
        zero_loss_pass = total_gbps > 0 and (udp_loss_pct <= max_loss_pct)
    else:
        sum_sent = end.get("sum_sent") or {}
        sum_recv = end.get("sum_received") or {}
        if not isinstance(sum_sent, dict):
            sum_sent = {}
        if not isinstance(sum_recv, dict):
            sum_recv = {}

        fwd_recv_bps = _safe_float(sum_recv.get("bits_per_second"), _safe_float(sum_sent.get("bits_per_second"), 0.0))
        fwd_bytes = _safe_int(sum_recv.get("bytes"), _safe_int(sum_sent.get("bytes"), 0))
        fwd_retrans = _safe_int(sum_sent.get("retransmits"), 0)
        eff_dur = _safe_float(sum_recv.get("seconds"), _safe_float(sum_sent.get("seconds"), duration_sec))

        if is_bidir:
            rev_sent = end.get("sum_sent_bidir_reverse") or {}
            rev_recv = end.get("sum_received_bidir_reverse") or {}
            if not isinstance(rev_sent, dict):
                rev_sent = {}
            if not isinstance(rev_recv, dict):
                rev_recv = {}
            rev_recv_bps = _safe_float(rev_recv.get("bits_per_second"), _safe_float(rev_sent.get("bits_per_second"), 0.0))
            rev_bytes = _safe_int(rev_recv.get("bytes"), _safe_int(rev_sent.get("bytes"), 0))
            rev_retrans = _safe_int(rev_sent.get("retransmits"), 0)
            tx_gbps = round(fwd_recv_bps / 1e9, 3)
            rx_gbps = round(rev_recv_bps / 1e9, 3)
            total_gbps = round((fwd_recv_bps + rev_recv_bps) / 1e9, 3)
            total_bytes = fwd_bytes + rev_bytes
            retransmits = fwd_retrans + rev_retrans
        else:
            gbps = round(fwd_recv_bps / 1e9, 3)
            tx_gbps = round(_safe_float(sum_sent.get("bits_per_second"), fwd_recv_bps) / 1e9, 3)
            rx_gbps = gbps
            total_gbps = gbps
            total_bytes = fwd_bytes
            retransmits = fwd_retrans

        est_pkts = (total_bytes / float(max(64, mss))) if total_bytes > 0 else 0.0
        if eff_dur > 0 and est_pkts > 0:
            pps = round(est_pkts / eff_dur, 1)
        retrans_pct = round((retransmits / est_pkts) * 100.0, 5) if est_pkts > 0 else 0.0
        zero_loss_pass = total_gbps > 0 and (retrans_pct <= max_retrans_pct)

    return {
        "tool": "聚信压测工具",
        "layer": "L4",
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "config": {
            "target": target,
            "port": port,
            "proto": proto,
            "direction": direction,
            "direction_cn": DIRECTION_LABELS.get(direction, direction),
            "mode": mode,
            "mode_cn": L4_MODE_LABELS.get(mode, mode),
            "streams": streams,
            "duration_sec": round(duration_sec, 1),
            "omit_sec": omit_sec,
            "packet_len_bytes": blksize if blksize > 0 else mss,
        },
        "summary": {
            "tx_gbps": tx_gbps,
            "rx_gbps": rx_gbps,
            "throughput_gbps": total_gbps,
            "total_bytes": total_bytes,
            "retransmits": retransmits,
            "retrans_pct": retrans_pct,
            "udp_lost_packets": udp_lost,
            "udp_total_packets": udp_total_pkts,
            "udp_loss_pct": udp_loss_pct,
            "udp_jitter_ms": udp_jitter_ms,
            "pps": pps,
            "client_cpu_pct": client_cpu,
            "server_cpu_pct": server_cpu,
            "zero_loss_pass": zero_loss_pass,
        },
    }


def build_iperf3_cmd(args: argparse.Namespace) -> List[str]:
    iperf_bin = args.iperf3_bin or shutil.which("iperf3")
    if not iperf_bin:
        raise RuntimeError("未检测到 iperf3，请先运行 setup-loadgen-centos7.sh 或安装 iperf3。")

    cmd = [
        iperf_bin,
        "-c", args.target,
        "-p", str(args.port),
        "-P", str(args.streams),
        "-t", str(args.duration),
        "-O", str(args.omit),
        "-J",
    ]
    if args.bind:
        cmd += ["-B", args.bind]
    if args.proto == "udp":
        cmd += ["-u", "-b", args.udp_bitrate]
    if args.packet_len:
        cmd += ["-l", args.packet_len]
    if args.direction == "reverse":
        cmd.append("-R")
    elif args.direction == "bidir":
        cmd.append("--bidir")
    return cmd


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="聚信压测工具 — 4 层传输层（TCP/UDP）吞吐压测与解析器")
    parser.add_argument("--target", default="", help="iperf3 服务端 IP 或主机名（实时压测必填）")
    parser.add_argument("--port", type=int, default=5201, help="iperf3 服务端端口（默认 5201）")
    parser.add_argument("--proto", choices=("tcp", "udp"), default="tcp", help="传输层协议：tcp 或 udp（默认 tcp）")
    parser.add_argument(
        "--direction",
        choices=("forward", "reverse", "bidir"),
        default="forward",
        help="发压方向：forward 单向 / reverse 反向 / bidir 双向全双工",
    )
    parser.add_argument(
        "--mode",
        choices=tuple(L4_MODE_LABELS.keys()),
        default="direct_baseline",
        help="被测 4 层路径模式（用于报告口径标注）",
    )
    parser.add_argument("--streams", type=int, default=16, help="并发 TCP/UDP 流数量（默认 16）")
    parser.add_argument("--duration", type=int, default=30, help="稳态测试时长（秒，默认 30）")
    parser.add_argument("--omit", type=int, default=5, help="剔除前期预热秒数（默认 5）")
    parser.add_argument("--udp-bitrate", default="10G", help="UDP 目标发包速率（如 10G / 5G / 0，默认 10G）")
    parser.add_argument("--packet-len", default="", help="可选：包长/缓冲区大小（如 UDP 用 1400，TCP 用 64K）")
    parser.add_argument("--bind", default="", help="可选：绑定本地源 IP（多万兆网口定向发压时使用）")
    parser.add_argument("--max-loss-pct", type=float, default=0.1, help="UDP 达标最大丢包率门槛（单位 %% ，默认 0.1）")
    parser.add_argument("--max-retrans-pct", type=float, default=0.1, help="TCP 达标最大重传率门槛（单位 %% ，默认 0.1）")
    parser.add_argument("--iperf3-bin", default="", help="可选：显式指定 iperf3 可执行文件路径")
    parser.add_argument("--parse-raw-json", default="", help="可选：离线解析已有 iperf3 -J 原始 JSON 文件，不发起实时发压")
    parser.add_argument("--save-raw-json", default="", help="可选：同时保留 iperf3 原始 JSON 输出路径")
    parser.add_argument("--out-json", required=True, help="输出标准化 4 层吞吐 JSON 路径")
    args = parser.parse_args(argv)

    if args.parse_raw_json:
        with open(args.parse_raw_json, "r", encoding="utf-8") as f:
            raw = json.load(f)
    else:
        if not args.target:
            parser.error("实时压测必须指定 --target，或使用 --parse-raw-json 离线解析")
        cmd = build_iperf3_cmd(args)
        print(f"[l4-throughput] 执行 4 层压测: {' '.join(cmd)}")
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if not proc.stdout.strip():
            raise RuntimeError(f"iperf3 无 JSON 输出（exit={proc.returncode}）: {proc.stderr.strip()}")
        if args.save_raw_json:
            os.makedirs(os.path.dirname(os.path.abspath(args.save_raw_json)), exist_ok=True)
            with open(args.save_raw_json, "w", encoding="utf-8") as f:
                f.write(proc.stdout)
        raw = json.loads(proc.stdout)

    result = parse_iperf3_json(
        raw,
        mode=args.mode,
        direction_override="" if args.parse_raw_json else args.direction,
        target_override=args.target,
        max_loss_pct=args.max_loss_pct,
        max_retrans_pct=args.max_retrans_pct,
    )

    os.makedirs(os.path.dirname(os.path.abspath(args.out_json)), exist_ok=True)
    with open(args.out_json, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    s = result["summary"]
    cfg = result["config"]
    print(
        f"[l4-throughput] 完成: {cfg['proto'].upper()} {cfg['direction_cn']} | "
        f"吞吐={s['throughput_gbps']} Gbps | 达标={'PASS' if s['zero_loss_pass'] else 'FAIL'} -> {args.out_json}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
