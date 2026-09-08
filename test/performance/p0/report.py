#!/usr/bin/env python3
"""P0-02 基准报告生成器（只读 run 目录 → report.md）。

用法：
  python3 test/performance/p0/report.py --run-dir <run-directory> [--repo-root <仓库根>]

只读取 run 目录内已采集数据与仓库内语料（用于哈希核对），不填入估计值冒充实测。
退出码：0 报告已生成（含 NOT_PASSED 判定）；2 run 目录缺失等结构错误。
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from p0bench.report_core import ReportError, write_report  # noqa: E402


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="report.py", description="P0-02 基准报告生成器")
    parser.add_argument("--run-dir", required=True, help="运行目录（含 plan.json/status.json 等）")
    parser.add_argument(
        "--repo-root",
        default=str(Path(__file__).resolve().parents[3]),
        help="仓库根（用于语料哈希核对），默认按脚本位置推导",
    )
    args = parser.parse_args(argv)
    try:
        out = write_report(args.run_dir, args.repo_root)
    except ReportError as exc:
        print(f"报告生成失败: {exc}", file=sys.stderr)
        return 2
    print(f"已生成 {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
