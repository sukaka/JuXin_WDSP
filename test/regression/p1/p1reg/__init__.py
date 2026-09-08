"""P1-04 规则与模型持续回归共享库（纯 Python 标准库，R1/S1 交付）。

模块划分：
- vocab:       状态/原因词表（复用 p0bench.report_core 词表，S0 冻结契约 1）
- profiles:    OBSERVE/PROTECT profile 定义加载与校验
- corpus:      P1 语料 manifest schema v1 校验器（不复用 p0bench.corpus，
               其与 P0 语料 v1 硬绑定；S0 冻结契约 2）
- runplan:     回归 run-plan（kind=p1_regression_run_plan）结构校验
- replayplan:  确定性回放计划生成（seed 驱动，绑定语料与用例内容哈希）
- judge:       逐例判定器骨架（规则命中/HTTP 结果/源站副作用分离判定；
               ABORTED/ERROR/UNKNOWN 不默认转通过）
- compare:     前后版本逐例配对比较（新增命中/新增误报/丢失检测/动作变化/
               源站变化/不可比较原因；只读证据目录，不重新执行、不猜测期望）
- report:      回归 run 目录只读汇总与 report.md 渲染（零分母 N/A）
- cli:         p1reg 命令行入口（供 test/performance/p0/run.sh 增量子命令调用）

复用边界：isolation（run_id/目标允许表）、plan（正则与 sha256_file）、
report_core（状态词表）来自 p0bench，经 sys.path 导入；不修改其校验口径。

约束：不使用第三方包；不输出凭据、环境变量全集或原始 Authorization。
"""

from __future__ import annotations

# p0bench 复用引导：优先依赖调用方（run.sh / 测试）设置的 PYTHONPATH；
# 未设置时按仓库相对位置兜底，保证 p1reg 可独立导入。
try:
    import p0bench  # noqa: F401
except ImportError:  # pragma: no cover - 取决于调用方 PYTHONPATH
    import sys
    from pathlib import Path

    _P0_DIR = Path(__file__).resolve().parents[3] / "performance" / "p0"
    if _P0_DIR.is_dir() and str(_P0_DIR) not in sys.path:
        sys.path.insert(0, str(_P0_DIR))
