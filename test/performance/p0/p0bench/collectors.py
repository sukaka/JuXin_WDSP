"""压测器输出、curl 时序与资源时序解析（P0-02 任务书 §6.1）。

纯标准库。支持：
- ab（ApacheBench 2.3，闭环并发；须如实报告协调遗漏限制）
- curl --write-out TSV（correctness / smoke 逐请求时序）
- wrk --json（可选；wrk 不存在时相关路径不启用）
- docker stats --no-stream --format json 快照行（macOS/Windows 下 docker stats
  反映的是 Docker Desktop 虚拟机口径，内存/CPU 与宿主真实值存在偏差，
  报告必须注明平台限制；Linux 下可用 /proc 作为补充来源）

所有解析函数对畸形输入返回错误或跳过该行，绝不静默吞掉解析失败。
"""

from __future__ import annotations

import json
import re

from .metrics import classify_error

_AB_PERCENTILE_RE = re.compile(r"^\s*(\d+)%\s+(\d+)\s*$")
_MEMORY_RE = re.compile(r"^\s*(?P<value>[0-9]+(?:\.[0-9]+)?)\s*(?P<unit>[KMGTPE]?i?B)\s*$", re.I)
_MEMORY_UNITS = {
    "b": 1,
    "kb": 1000,
    "mb": 1000**2,
    "gb": 1000**3,
    "tb": 1000**4,
    "pb": 1000**5,
    "kib": 1024,
    "mib": 1024**2,
    "gib": 1024**3,
    "tib": 1024**4,
    "pib": 1024**5,
}


class CollectorError(Exception):
    """采集输入不可解析或结构不完整。"""


def parse_ab_output(text: str) -> dict:
    """解析 ab 文本输出。保留原始百分位表，不做任何跨段平均。"""
    if not isinstance(text, str) or "Requests per second" not in text:
        raise CollectorError("不是可识别的 ab 输出（缺 Requests per second 行）")
    out: dict = {
        "tool": "ab",
        "complete_requests": None,
        "failed_requests": None,
        "non_2xx_responses": None,
        "requests_per_second": None,
        "time_per_request_ms_mean": None,
        "transfer_rate_kbps": None,
        "percentile_table_ms": {},
    }
    in_pct = False
    for line in text.splitlines():
        if line.startswith("Complete requests:"):
            out["complete_requests"] = int(line.split(":", 1)[1])
        elif line.startswith("Failed requests:"):
            out["failed_requests"] = int(line.split(":", 1)[1])
        elif line.startswith("Non-2xx responses:"):
            out["non_2xx_responses"] = int(line.split(":", 1)[1])
        elif line.startswith("Requests per second:"):
            out["requests_per_second"] = float(line.split(":", 1)[1].split()[0])
        elif line.startswith("Time per request:") and "(mean, across all" not in line:
            out["time_per_request_ms_mean"] = float(line.split(":", 1)[1].split()[0])
        elif line.startswith("Transfer rate:"):
            out["transfer_rate_kbps"] = float(line.split(":", 1)[1].split()[0])
        elif line.startswith("Percentage of the requests served"):
            in_pct = True
        elif in_pct:
            m = _AB_PERCENTILE_RE.match(line)
            if m:
                out["percentile_table_ms"][int(m.group(1))] = int(m.group(2))
            elif line.strip() and not line.startswith(" "):
                in_pct = False
    if out["complete_requests"] is None or out["requests_per_second"] is None:
        raise CollectorError("ab 输出缺关键字段（complete_requests / requests_per_second）")
    return out


def parse_wrk_json(text: str) -> dict:
    """解析 wrk --json 输出（可选工具链；保留原始直方图，不平均）。"""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CollectorError(f"wrk JSON 解析失败: {exc}") from exc
    latency = data.get("latency")
    if not isinstance(latency, dict) or "percentiles" not in latency:
        raise CollectorError("wrk JSON 缺 latency.percentiles")
    return {
        "tool": "wrk",
        "requests": data.get("requests"),
        "requests_per_second": data.get("requests_per_second"),
        "errors": data.get("errors", {}),
        "latency_percentiles_us": latency["percentiles"],
        "latency_histogram": latency.get("histogram"),
    }


def parse_curl_tsv_line(line: str) -> dict:
    """curl -w 逐请求时序行：request_id<TAB>http_code<TAB>time_total_s<TAB>remote_ip。

    http_code 000 表示连接/协议失败（status 记为 None）。
    """
    parts = line.rstrip("\n").split("\t")
    if len(parts) < 3:
        raise CollectorError(f"curl TSV 行字段不足: {line!r}")
    request_id, http_code, time_total = parts[0], parts[1], parts[2]
    try:
        code = int(http_code)
    except ValueError as exc:
        raise CollectorError(f"curl TSV http_code 非整数: {http_code!r}") from exc
    try:
        seconds = float(time_total)
    except ValueError as exc:
        raise CollectorError(f"curl TSV time_total 非数值: {time_total!r}") from exc
    return {
        "request_id": request_id,
        "status": None if code == 0 else code,
        "latency_ms": seconds * 1000.0,
    }


def _memory_bytes(value: str) -> float | None:
    if not value:
        return None
    match = _MEMORY_RE.match(value)
    if match is None:
        raise CollectorError(f"docker stats 内存用量不可解析: {value!r}")
    unit = match.group("unit").lower()
    return float(match.group("value")) * _MEMORY_UNITS[unit]


def summarize_curl_tsv(lines, expected_statuses=None) -> dict:
    """逐请求时序汇总：offered/completed、延迟样本、错误分类（预期 403/429 单列）。"""
    expected = set(expected_statuses or ())
    latencies: list[float] = []
    classes: dict[str, int] = {}
    offered = completed = 0
    bad_lines = 0
    for line in lines:
        if not line.strip():
            continue
        offered += 1
        try:
            rec = parse_curl_tsv_line(line)
        except CollectorError:
            bad_lines += 1
            continue
        if rec["status"] is None:
            classes["connection_error"] = classes.get("connection_error", 0) + 1
            continue
        completed += 1
        latencies.append(rec["latency_ms"])
        cls = classify_error(rec["status"], expected)
        classes[cls] = classes.get(cls, 0) + 1
    return {
        "offered": offered,
        "completed": completed,
        "unparseable_lines": bad_lines,
        "latency_ms_samples": latencies,
        "error_classes": classes,
    }


def parse_docker_stats_jsonl(lines) -> list[dict]:
    """docker stats --format json 快照行 → 规范化资源时序。

    输入每行为 docker stats 单行 JSON（字段名以 docker CLI 输出为准）。
    只提取白名单字段，绝不透传完整 inspect 数据。
    """
    records: list[dict] = []
    for i, line in enumerate(lines):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise CollectorError(f"docker stats 第 {i + 1} 行 JSON 解析失败: {exc}") from exc
        cpu_raw = str(row.get("CPUPerc", "")).rstrip("%")
        mem_usage = str(row.get("MemUsage", ""))
        mem_raw = str(row.get("MemPerc", "")).rstrip("%")
        try:
            cpu = float(cpu_raw)
            mem = float(mem_raw)
        except ValueError as exc:
            raise CollectorError(f"docker stats 第 {i + 1} 行数值字段解析失败: {exc}") from exc
        records.append(
            {
                "seq": i,
                "container": row.get("Name") or row.get("Container"),
                "cpu_percent": cpu,
                "mem_percent": mem,
                "mem_usage": mem_usage.split("/")[0].strip() if mem_usage else None,
                # docker stats exposes container memory usage, not a process RSS
                # value. Keep the numeric value for peak reporting without
                # relabeling it as host/process RSS.
                "mem_usage_bytes": _memory_bytes(mem_usage.split("/")[0].strip()) if mem_usage else None,
                "net_io": row.get("NetIO"),
                "block_io": row.get("BlockIO"),
                "pids": row.get("PIDs"),
            }
        )
    return records


def parse_proc_rss_jsonl(lines) -> list[dict]:
    """Parse normalized Linux ``/proc/<pid>/status`` RSS samples.

    The runner emits one JSON object per sample after reading ``VmRSS`` from
    the target process.  Keeping this source separate from docker stats makes
    the report's container-memory and process-RSS scopes auditable.
    """
    records: list[dict] = []
    for i, line in enumerate(lines):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise CollectorError(f"/proc RSS 第 {i + 1} 行 JSON 解析失败: {exc}") from exc
        container = row.get("container")
        pid = row.get("pid")
        rss_kib = row.get("rss_kib")
        if not isinstance(container, str) or not container:
            raise CollectorError(f"/proc RSS 第 {i + 1} 行缺少 container")
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            raise CollectorError(f"/proc RSS 第 {i + 1} 行 pid 无效")
        if isinstance(rss_kib, bool) or not isinstance(rss_kib, (int, float)) or rss_kib < 0:
            raise CollectorError(f"/proc RSS 第 {i + 1} 行 rss_kib 无效")
        records.append(
            {
                "seq": i,
                "container": container,
                "pid": pid,
                "rss_kib": rss_kib,
                "rss_bytes": rss_kib * 1024,
            }
        )
    return records
