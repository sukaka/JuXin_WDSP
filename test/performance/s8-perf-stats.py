#!/usr/bin/env python3
"""S8 批次 B 样本统计（最近秩百分位，与既有 stage8-performance-tests.sh 同口径）。

用法：s8-perf-stats.py <样本文件> [列形态]
  样本行两种形态自动识别：
    curl 臂: "<time_total 秒> <http_code>"
    go 臂:   "seq,duration_ms,<status|code>"（首行表头自动跳过）
输出一行：n bad p50 p95 p99 min max（秒；bad=000/429/5xx/非OK）。
"""
import math
import sys


def load(path):
    vals, bad, n = [], 0, 0
    dur_idx, st_idx = 1, 2  # 旧 go 形态: seq,duration_ms,status
    for line in open(path):
        line = line.strip()
        if not line:
            continue
        if line.startswith("seq"):
            cols = [c.strip() for c in line.split(",")]
            if "duration_ms" in cols:
                dur_idx = cols.index("duration_ms")
            if "status" in cols:
                st_idx = cols.index("status")
            elif "code" in cols:
                st_idx = cols.index("code")
            continue
        n += 1
        if "," in line:
            parts = line.split(",")
            ms = parts[dur_idx] if len(parts) > dur_idx else ""
            st = parts[st_idx] if len(parts) > st_idx else ""
            try:
                v = float(ms) / 1000.0
            except ValueError:
                continue
            if st not in ("200", "OK"):
                bad += 1
        else:
            parts = line.split()
            try:
                v = float(parts[0])
            except ValueError:
                continue
            st = parts[1] if len(parts) > 1 else ""
            if st == "000" or st == "429" or st.startswith("5"):
                bad += 1
        vals.append(v)
    return vals, bad, n


def pct(vals, q):
    if not vals:
        return -1.0
    k = max(0, min(len(vals) - 1, math.ceil(q * len(vals)) - 1))
    return vals[k]


def main():
    vals, bad, n = load(sys.argv[1])
    vals.sort()
    print(f"n={n} bad={bad} "
          f"p50={pct(vals,0.50)*1000:.2f}ms p95={pct(vals,0.95)*1000:.2f}ms "
          f"p99={pct(vals,0.99)*1000:.2f}ms min={vals[0]*1000 if vals else -1:.2f}ms "
          f"max={vals[-1]*1000 if vals else -1:.2f}ms")


if __name__ == "__main__":
    main()
