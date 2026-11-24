#!/usr/bin/env python3
"""WDSP 事件入库追平监控与零丢失精确对账工具（纯 Python 3 标准库）。

功能：
  1. 扫描网关 api-runtime-events.log（支持宿主机路径或 docker exec），按 RUN_PREFIX 提取唯一 request_id 与 final_action 分布；
  2. 可选轮询等待 collector checkpoint 追平文件末尾，测量追平耗时与有效入库速率（行/s）；
  3. 查询 PostgreSQL api_runtime_events（支持本地 psql 或 docker exec），比对唯一 request_id 集合，
     精确计算：永久丢失数（missing_in_db）、重复入库数（duplicate_rows）、对账状态（PASS/FAIL）；
  4. 输出机器可读 reconcile.json（供 summarize-run.py 自动渲染客户交付报告）与终端摘要。
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Set, Tuple


def parse_checkpoint_offset(raw: str) -> Optional[int]:
    """解析 collector checkpoint 文件中的字节偏移量（兼容 JSON 与纯数字格式）。"""
    text = (raw or "").strip()
    if not text:
        return None
    if text.isdigit():
        return int(text)
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            for key in ("offset", "Offset", "byte_offset", "file_offset"):
                if key in obj and obj[key] is not None:
                    return int(obj[key])
    except Exception:
        return None
    return None


def scan_gateway_log_lines(lines: Iterable[str], run_prefix: str) -> Dict[str, object]:
    """扫描网关 JSONL 事件日志行，按 run_prefix 统计唯一 request_id 与动作分布。"""
    total_matched_lines = 0
    parse_errors = 0
    req_ids: Set[str] = set()
    duplicate_log_ids = 0
    actions: Counter = Counter()

    for line in lines:
        if run_prefix and run_prefix not in line:
            continue
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except Exception:
            parse_errors += 1
            continue
        if not isinstance(rec, dict):
            parse_errors += 1
            continue
        endpoint_key = str(rec.get("endpoint_key") or "")
        req_path = str(rec.get("request_path") or rec.get("path") or "")
        if run_prefix and (run_prefix not in endpoint_key and run_prefix not in req_path and run_prefix not in line):
            continue
        total_matched_lines += 1
        rid = str(rec.get("request_id") or "").strip()
        if rid:
            if rid in req_ids:
                duplicate_log_ids += 1
            else:
                req_ids.add(rid)
        act = str(rec.get("final_action") or rec.get("action") or "UNKNOWN")
        actions[act] += 1

    return {
        "matched_lines": total_matched_lines,
        "unique_request_ids": req_ids,
        "unique_count": len(req_ids),
        "duplicate_log_ids": duplicate_log_ids,
        "parse_errors": parse_errors,
        "action_breakdown": dict(actions),
    }


def reconcile_id_sets(
    gateway_ids: Set[str],
    db_ids: Set[str],
    db_total_rows: int,
    drained: bool,
    sample_limit: int = 20,
) -> Dict[str, object]:
    """核心对账计算：判定零丢失与零重复。"""
    missing_in_db = sorted(gateway_ids - db_ids)
    extra_in_db = sorted(db_ids - gateway_ids)
    duplicate_rows = max(0, db_total_rows - len(db_ids))

    if len(gateway_ids) == 0:
        verdict = "FAIL_NO_GATEWAY_EVENTS"
    elif not drained:
        verdict = "FAIL_DRAIN_TIMEOUT"
    elif len(missing_in_db) > 0:
        verdict = "FAIL_DATA_LOSS"
    elif duplicate_rows > 0:
        verdict = "FAIL_DUPLICATE_PRIMARY_EVENTS"
    else:
        verdict = "PASS"

    return {
        "verdict": verdict,
        "passed": verdict == "PASS",
        "drained": drained,
        "gateway_unique_count": len(gateway_ids),
        "db_total_rows": db_total_rows,
        "db_unique_count": len(db_ids),
        "missing_in_db_count": len(missing_in_db),
        "missing_sample_ids": missing_in_db[:sample_limit],
        "extra_in_db_count": len(extra_in_db),
        "duplicate_rows_count": duplicate_rows,
    }


def read_log_and_checkpoint_status(
    log_path: str,
    docker_container: Optional[str] = None,
) -> Tuple[int, Optional[int]]:
    """读取事件日志文件大小与 checkpoint 偏移。"""
    if docker_container:
        script = (
            f'p="{log_path}"; '
            'if [ -f "$p" ]; then stat -c %s "$p" 2>/dev/null || wc -c < "$p"; else echo 0; fi; '
            'echo "---CKPT---"; '
            'if [ -f "${p}.checkpoint" ]; then cat "${p}.checkpoint"; fi'
        )
        out = subprocess.check_output(
            ["docker", "exec", docker_container, "sh", "-c", script],
            text=True,
            stderr=subprocess.DEVNULL,
        )
        parts = out.split("---CKPT---", 1)
        size = int(parts[0].strip()) if parts[0].strip().isdigit() else 0
        offset = parse_checkpoint_offset(parts[1]) if len(parts) > 1 else None
        return size, offset

    size = os.path.getsize(log_path) if os.path.isfile(log_path) else 0
    ckpt_path = log_path + ".checkpoint"
    offset = None
    if os.path.isfile(ckpt_path):
        with open(ckpt_path, "r", encoding="utf-8", errors="ignore") as f:
            offset = parse_checkpoint_offset(f.read())
    return size, offset


def wait_for_drain(
    log_path: str,
    timeout_sec: int,
    poll_sec: int = 3,
    docker_container: Optional[str] = None,
) -> Dict[str, object]:
    """等待 collector checkpoint 追平到当前文件大小。"""
    t0 = time.monotonic()
    start_size, start_off = read_log_and_checkpoint_status(log_path, docker_container)
    last_size, last_off = start_size, start_off
    drained = False

    while True:
        last_size, last_off = read_log_and_checkpoint_status(log_path, docker_container)
        elapsed = time.monotonic() - t0
        lag = (last_size - last_off) if last_off is not None else None
        if last_off is not None and last_off >= last_size:
            drained = True
            break
        if elapsed >= timeout_sec:
            break
        print(
            f"[reconcile] 等待事件追平: elapsed={elapsed:.0f}s size={last_size}B "
            f"offset={last_off if last_off is not None else 'N/A'}B lag={lag if lag is not None else 'N/A'}B",
            file=sys.stderr,
        )
        time.sleep(max(1, poll_sec))

    elapsed = round(time.monotonic() - t0, 2)
    progressed_bytes = 0
    if start_off is not None and last_off is not None and last_off >= start_off:
        progressed_bytes = last_off - start_off
    bytes_per_sec = round(progressed_bytes / elapsed, 2) if elapsed > 0 and progressed_bytes > 0 else 0.0

    return {
        "drained": drained,
        "drain_seconds": elapsed,
        "start_size_bytes": start_size,
        "start_offset_bytes": start_off,
        "end_size_bytes": last_size,
        "end_offset_bytes": last_off,
        "remaining_lag_bytes": max(0, last_size - last_off) if last_off is not None else None,
        "drain_bytes_per_sec": bytes_per_sec,
    }


def iter_gateway_log_lines(log_path: str, docker_container: Optional[str] = None) -> Iterable[str]:
    if docker_container:
        proc = subprocess.Popen(
            ["docker", "exec", docker_container, "cat", log_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="ignore",
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            yield line
        proc.wait()
        return

    # 同时兼容可能已轮转的同名文件（如 api-runtime-events.log.*，排除 .checkpoint）
    files = [log_path] if os.path.isfile(log_path) else []
    for cand in sorted(glob.glob(log_path + ".*")):
        if cand.endswith(".checkpoint") or cand.endswith(".gz"):
            continue
        if os.path.isfile(cand):
            files.append(cand)

    for fp in files:
        with open(fp, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                yield line


def query_postgres_events(
    run_prefix: str,
    pg_container: Optional[str],
    pg_dsn: Optional[str],
    pg_user: str,
    pg_db: str,
    pg_host: str,
    pg_port: int,
) -> Tuple[int, Set[str]]:
    """查询 PostgreSQL api_runtime_events 中匹配 run_prefix 的总行数与唯一 request_id 集合。"""
    # 校验 run_prefix 仅含安全字符，防止 SQL 注入
    safe_prefix = "".join(ch for ch in run_prefix if ch.isalnum() or ch in "-_./")
    if safe_prefix != run_prefix or not safe_prefix:
        raise ValueError(f"run_prefix 包含非法字符: {run_prefix!r}")

    sql_count = (
        f"SELECT COUNT(*) FROM api_runtime_events "
        f"WHERE endpoint_key LIKE '%{safe_prefix}%';"
    )
    sql_ids = (
        f"SELECT DISTINCT request_id FROM api_runtime_events "
        f"WHERE endpoint_key LIKE '%{safe_prefix}%';"
    )

    def run_psql(sql: str) -> str:
        if pg_container:
            cmd = [
                "docker", "exec", pg_container,
                "psql", "-U", pg_user, "-d", pg_db, "-t", "-A", "-c", sql,
            ]
        elif pg_dsn:
            cmd = ["psql", pg_dsn, "-t", "-A", "-c", sql]
        else:
            cmd = [
                "psql", "-h", pg_host, "-p", str(pg_port),
                "-U", pg_user, "-d", pg_db, "-t", "-A", "-c", sql,
            ]
        return subprocess.check_output(cmd, text=True)

    total_raw = run_psql(sql_count).strip()
    total_rows = int(total_raw) if total_raw.isdigit() else 0
    ids_raw = run_psql(sql_ids)
    db_ids = {line.strip() for line in ids_raw.splitlines() if line.strip()}
    return total_rows, db_ids


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="WDSP 事件入库追平与零丢失对账工具")
    parser.add_argument("--run-prefix", required=True, help="本次压测唯一 URL 前缀（如 ky-evt-01）")
    parser.add_argument("--event-log", required=True, help="api-runtime-events.log 路径")
    parser.add_argument("--log-container", default="", help="可选：从该 Docker 容器内读取事件日志与 checkpoint")
    parser.add_argument("--wait-drain", action="store_true", help="先轮询等待 collector checkpoint 追平日志末尾")
    parser.add_argument("--drain-timeout", type=int, default=1800, help="等待追平最大超时秒数（默认 1800）")
    parser.add_argument("--poll-interval", type=int, default=3, help="追平轮询间隔秒数（默认 3）")
    parser.add_argument("--pg-container", default="", help="Docker PostgreSQL 容器名（与本地 psql 二选一）")
    parser.add_argument("--pg-dsn", default="", help="PostgreSQL 连接串（密码建议通过 PGPASSWORD 环境变量注入）")
    parser.add_argument("--pg-host", default="127.0.0.1")
    parser.add_argument("--pg-port", type=int, default=5432)
    parser.add_argument("--pg-user", default="jiuzhang")
    parser.add_argument("--pg-db", default="jiuzhang_waf")
    parser.add_argument("--out-json", default="", help="可选：输出结构化 JSON 对账结果")
    args = parser.parse_args(argv)

    log_ctr = args.log_container or None
    pg_ctr = args.pg_container or None

    drain_info: Dict[str, object]
    if args.wait_drain:
        drain_info = wait_for_drain(args.event_log, args.drain_timeout, args.poll_interval, log_ctr)
    else:
        sz, off = read_log_and_checkpoint_status(args.event_log, log_ctr)
        drain_info = {
            "drained": (off is not None and off >= sz),
            "drain_seconds": 0.0,
            "start_size_bytes": sz,
            "start_offset_bytes": off,
            "end_size_bytes": sz,
            "end_offset_bytes": off,
            "remaining_lag_bytes": max(0, sz - off) if off is not None else None,
            "drain_bytes_per_sec": 0.0,
        }

    gw_scan = scan_gateway_log_lines(iter_gateway_log_lines(args.event_log, log_ctr), args.run_prefix)
    gw_ids: Set[str] = gw_scan["unique_request_ids"]  # type: ignore[assignment]

    db_total_rows, db_ids = query_postgres_events(
        args.run_prefix, pg_ctr, args.pg_dsn or None, args.pg_user, args.pg_db, args.pg_host, args.pg_port
    )

    rec = reconcile_id_sets(gw_ids, db_ids, db_total_rows, bool(drain_info["drained"]))
    drain_sec = float(drain_info.get("drain_seconds") or 0.0)
    ingest_rps = round(len(db_ids) / drain_sec, 2) if drain_sec > 0 else None

    result = {
        "reconciled_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "run_prefix": args.run_prefix,
        "event_log": args.event_log,
        "drain": drain_info,
        "gateway_log": {
            "matched_lines": gw_scan["matched_lines"],
            "unique_count": gw_scan["unique_count"],
            "duplicate_log_ids": gw_scan["duplicate_log_ids"],
            "parse_errors": gw_scan["parse_errors"],
            "action_breakdown": gw_scan["action_breakdown"],
        },
        "reconciliation": rec,
        "effective_drain_rows_per_sec": ingest_rps,
    }

    if args.out_json:
        os.makedirs(os.path.dirname(os.path.abspath(args.out_json)), exist_ok=True)
        with open(args.out_json, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)

    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if rec["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
