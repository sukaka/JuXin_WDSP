#!/usr/bin/env python3
"""P0-02 基准采集/对账 CLI（纯标准库）。

子命令：
  loadgen     解析 ab 文本 / wrk JSON 输出，写入 perf/<profile>/<file>.json
  curltsv     解析 curl -w 逐请求时序 TSV（correctness/smoke），写入 perf 或 truth 源数据
  resources   解析 docker stats --format json 快照行，写入 resources/<name>.json
  events      事件对账：eligible/generated/persisted[/dropped] request_id 清单 → reconciliation.json
  versions    采集压测器版本到 manifest（run.sh 负责实际调用 ab -V 等并传入文本）

只写本 run 目录；不访问网络；不输出环境变量或凭据。
退出码：0 成功；2 输入/结构错误。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from p0bench.collectors import (  # noqa: E402
    CollectorError,
    parse_ab_output,
    parse_docker_stats_jsonl,
    parse_proc_rss_jsonl,
    parse_wrk_json,
    summarize_curl_tsv,
)
from p0bench.reconcile import permanent_loss, reconcile_events  # noqa: E402
from p0bench.corpus import load_manifest  # noqa: E402


def _derive_observed_action(status, origin_reached, detected):
    if status is None:
        return "UNEXPECTED_ERROR"
    if status == 403:
        return "BLOCK_403"
    if status == 401:
        return "BLOCK_401"  # JWT 信任链 PROTECT 认证失败（P0-03；Bearer challenge）
    if status == 429:
        return "RATE_LIMIT_429"
    if 200 <= status < 400 and origin_reached:
        return "DETECT_PASS" if detected else "PASS"
    return "UNEXPECTED_ERROR"


def cmd_truthbuild(args) -> int:
    """合成逐样本真值结果：原始响应 + 检测证据 ID 清单 + 语料期望 → truth/<profile>.json。"""
    manifest = load_manifest(args.corpus)
    cases = {c["case_id"]: c for c in manifest.get("cases", [])}
    detected_ids = set(_read_ids(args.detected)) if args.detected else set()
    records = []
    skipped = 0
    for line in _read_ids(args.raw):
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            skipped += 1
            continue
        case = cases.get(raw.get("case_id"))
        if case is None:
            skipped += 1
            continue
        status = raw.get("status")
        origin_reached = bool(raw.get("origin_reached"))
        detected = raw.get("request_id") in detected_ids
        records.append(
            {
                "case_id": case["case_id"],
                "request_id": raw.get("request_id"),
                "label": case["label"],
                "category": case["category"],
                "deferred": bool(case.get("deferred")),
                "detected": detected,
                "observed_action": _derive_observed_action(status, origin_reached, detected),
                "expected_action": case["expected_action"][args.profile],
                "valid": status is not None,
            }
        )
    out = Path(args.run_dir) / "truth" / f"{args.profile}.json"
    _write_json(out, records)
    print(f"已写入 {out}（{len(records)} 条，跳过无法关联 {skipped} 条）")
    return 0


def _write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def _read_lines(path: str) -> list[str]:
    with open(path, "r", encoding="utf-8") as fh:
        return fh.readlines()


def _read_ids(path: str) -> list[str]:
    return [ln.strip() for ln in _read_lines(path) if ln.strip()]


def cmd_loadgen(args) -> int:
    text = Path(args.file).read_text(encoding="utf-8", errors="replace")
    try:
        if args.tool == "ab":
            rec = parse_ab_output(text)
        elif args.tool == "wrk":
            rec = parse_wrk_json(text)
        else:
            print(f"不支持的压测器: {args.tool}", file=sys.stderr)
            return 2
    except CollectorError as exc:
        print(f"采集失败: {exc}", file=sys.stderr)
        return 2
    rec.update({
        "profile": args.profile,
        "repeat": args.repeat,
        "offered_rps": args.point,
        "throughput_evidence": {
            "source": f"{args.tool}.requests_per_second",
            "scope": "end_to_end_loadgen",
            "value_rps": rec.get("requests_per_second"),
        },
    })
    out = Path(args.run_dir) / "perf" / args.profile / f"r{args.repeat}-{args.point}rps-{args.tool}.json"
    _write_json(out, rec)
    print(f"已写入 {out}")
    return 0


def cmd_curltsv(args) -> int:
    try:
        summary = summarize_curl_tsv(_read_lines(args.file), expected_statuses=args.expected_status)
    except CollectorError as exc:
        print(f"采集失败: {exc}", file=sys.stderr)
        return 2
    summary.update({"profile": args.profile, "tool": "curl"})
    out = Path(args.run_dir) / "perf" / args.profile / f"{args.name}.json"
    _write_json(out, summary)
    print(f"已写入 {out}")
    return 0


def cmd_resources(args) -> int:
    try:
        if args.source == "docker_stats":
            records = parse_docker_stats_jsonl(_read_lines(args.file))
            source = "docker_stats"
            platform_note = (
                "macOS/Windows 下 docker stats 为 Docker Desktop 虚拟机口径，"
                "与宿主真实 CPU/内存存在偏差；Linux 可用 /proc 补充。"
            )
        else:
            records = parse_proc_rss_jsonl(_read_lines(args.file))
            source = "proc_rss"
            platform_note = "Linux /proc VmRSS 进程口径；不包含容器 page cache，也不等同于容器内存上限。"
    except CollectorError as exc:
        print(f"采集失败: {exc}", file=sys.stderr)
        return 2
    out = Path(args.run_dir) / "resources" / f"{args.name}.json"
    _write_json(
        out,
        {
            "source": source,
            "platform_note": platform_note,
            "records": records,
        },
    )
    print(f"已写入 {out}")
    return 0


def cmd_events(args) -> int:
    recon = reconcile_events(
        _read_ids(args.eligible),
        _read_ids(args.generated),
        _read_ids(args.persisted),
        _read_ids(args.dropped) if args.dropped else [],
    )
    loss = permanent_loss(recon, catchup_complete=args.catchup_complete)
    out_doc = {
        "reconciliation": recon,
        "catchup_complete": args.catchup_complete,
        "permanent_loss": loss,
        "note": "catchup_complete=false 时 permanent_loss 为 null（恢复追平未完成，不判定永久丢失）",
    }
    out = Path(args.run_dir) / "reconciliation.json"
    _write_json(out, out_doc)
    print(f"已写入 {out}")
    return 0


def cmd_versions(args) -> int:
    out = Path(args.run_dir) / "manifest.json"
    doc = {}
    if out.is_file():
        doc = json.loads(out.read_text(encoding="utf-8"))
    versions = doc.get("loadgen_versions", {})
    versions[args.tool] = args.version_text.strip()
    doc["loadgen_versions"] = versions
    _write_json(out, doc)
    print(f"已记录 {args.tool} 版本到 {out}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="collect.py", description="P0-02 基准采集/对账（纯标准库）")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("loadgen", help="解析 ab/wrk 输出")
    p.add_argument("--run-dir", required=True)
    p.add_argument("--profile", required=True)
    p.add_argument("--repeat", type=int, required=True)
    p.add_argument("--point", type=int, required=True, help="offered RPS 档位")
    p.add_argument("--tool", choices=("ab", "wrk"), required=True)
    p.add_argument("--file", required=True)
    p.set_defaults(func=cmd_loadgen)

    p = sub.add_parser("curltsv", help="解析 curl -w 逐请求时序 TSV")
    p.add_argument("--run-dir", required=True)
    p.add_argument("--profile", required=True)
    p.add_argument("--name", required=True)
    p.add_argument("--file", required=True)
    p.add_argument("--expected-status", type=int, action="append", default=[])
    p.set_defaults(func=cmd_curltsv)

    p = sub.add_parser("resources", help="解析 docker stats 或 Linux /proc RSS JSON 快照行")
    p.add_argument("--run-dir", required=True)
    p.add_argument("--name", required=True)
    p.add_argument("--file", required=True)
    p.add_argument("--source", choices=("docker_stats", "proc_rss"), default="docker_stats")
    p.set_defaults(func=cmd_resources)

    p = sub.add_parser("events", help="事件对账")
    p.add_argument("--run-dir", required=True)
    p.add_argument("--eligible", required=True)
    p.add_argument("--generated", required=True)
    p.add_argument("--persisted", required=True)
    p.add_argument("--dropped")
    p.add_argument("--catchup-complete", action="store_true")
    p.set_defaults(func=cmd_events)

    p = sub.add_parser("versions", help="登记压测器版本到 manifest")
    p.add_argument("--run-dir", required=True)
    p.add_argument("--tool", required=True)
    p.add_argument("--version-text", required=True)
    p.set_defaults(func=cmd_versions)

    p = sub.add_parser("truthbuild", help="合成逐样本真值结果 truth/<profile>.json")
    p.add_argument("--run-dir", required=True)
    p.add_argument("--profile", required=True)
    p.add_argument("--raw", required=True, help="逐请求原始响应 JSONL")
    p.add_argument("--corpus", required=True, help="语料 manifest 路径")
    p.add_argument("--detected", help="产生检测证据的 request_id 清单（每行一个）")
    p.set_defaults(func=cmd_truthbuild)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
