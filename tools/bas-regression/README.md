# BAS 回归覆盖工具（bas-regression）

> 将 BAS（入侵攻击模拟）测试报告转化为「攻击类别 → 自建规则包/规则 ID 段 → go-ftw 回归测试」的覆盖矩阵，并报告「有规则无测试」缺口。

## 背景与口径

- BAS 报告（4553 用例，工作表 `结果详情`，列为 标签信息/用例名称/概述/修复建议/阻断状态 等）**不含原始 payload**——执行步骤列只有状态码与判定结论，无法逐 payload 重放。
- 因此本工具做的是**覆盖代理验证**，不是逐用例复放：按 标签信息+用例名称 归一化聚类得到 BAS 攻击类别，静态映射到承担检测的 CUSTOM_PACK 规则包/ID 段（映射表内置于 `extract.py`，依据 `gateway/rules/contrib/CUSTOM_PACK/` 现状维护），再关联各类别已有的 go-ftw 回归测试。每个类别用自建 ftw 用例代表该类典型 payload 形态做回归。
- **BAS 判定只认带防御特征的 403**（拦截页面/拦截响应头特征）。仅产生安全事件但未返回 403（如 DetectionOnly 观察模式）在 BAS 口径下记为「未阻断」。回归复测时须确保网关处于 PROTECT（阻断）模式且 `post-contrib-blocking.conf` 为指令链最后一条 Include（见 docs/RULE_PACKS.md）。
- 规则数与 ID 范围由脚本动态扫描规则库得到；脚本**只读规则库**，不写仓库内任何文件，输出到 stdout 或 `tools/bas-regression/out/`，多次运行结果一致（幂等）。

## 用法

```bash
# 生成覆盖矩阵（默认读取内置 xlsx 路径，输出 tools/bas-regression/out/coverage-matrix.md）
python3 tools/bas-regression/extract.py

# 指定 BAS 报告路径 / 输出到 stdout
python3 tools/bas-regression/extract.py --xlsx /path/to/报告.xlsx --stdout

# 只跑「有规则无 ftw 测试」缺口报告（CI 可用 --strict，存在缺口时退出码 1）
tools/bas-regression/check-coverage.sh
tools/bas-regression/check-coverage.sh --strict
```

依赖：Python 3.9+，`openpyxl`（仅解析 xlsx 时需要；`--check` 模式只用标准库）。建议在虚拟环境中安装：`pip install openpyxl`。

xlsx 缺失时脚本不报错退出：矩阵仍生成，仅省略「BAS 报告统计」与聚类节，映射与缺口节不受影响。

## 输出说明

`out/coverage-matrix.md` 三节：

1. **BAS 报告统计**：类别分布与报告侧阻断/未阻断计数（历史基线，非本网关实测）。
2. **类别 → 规则覆盖矩阵**：每个 BAS 类别的承担规则包（文件、实际规则数与 ID 范围为动态扫描值）、CRS 兜底组、已存在的 ftw 测试文件链接、归一化聚类 Top 20。
3. **规则-测试缺口**：CUSTOM_PACK 全部规则的 ftw 测试覆盖情况与缺测 ID 清单，随各规则包分片补齐测试后重跑即可收敛。

## 与其他分片的关系

各规则包分片在 `test/waf/ftw/crs-tests/` 下新建 `<规则ID>.yaml`（一条规则一个文件）后，本工具无需改动，重跑即自动反映最新覆盖。类别映射表（`CATEGORY_COVERAGE`）仅在新增规则包文件或 BAS 类别口径变化时需人工维护。
