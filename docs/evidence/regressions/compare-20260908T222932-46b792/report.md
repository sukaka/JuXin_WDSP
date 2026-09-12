# P1-04 前后版本回归对比报告

- baseline: `20260908T222305-798cfb`（cases.sha256 `14f8e386feb863b7…`）
- candidate: `20260908T222701-b7f86d`（cases.sha256 `d78c22e73258d927…`）
- 比较方式：只读两个已完成证据目录逐例配对；不重新执行、不猜测期望

## 总判定

**FAIL**
- 新增失败 1 条（baseline 通过→候选失败）: ['WAF-ATK-WEBSHELL-001']
- 丢失检测 1 条（强制 1）: ['WAF-ATK-WEBSHELL-001']

## 汇总

| 指标 | 值 |
|---|---|
| 可配对有效样本（分母） | 42 |
| 其中正常样本 | 18 |
| 其中攻击样本 | 24 |
| 前后一致且通过 | 41 |
| 新增失败（baseline 通过→候选失败） | 1（2.38%） |
| 新增正确命中 | 0 |
| 新增误报（率） | 0（0.00%） |
| 其中新增误拦截 | 0 |
| 丢失检测（率） | 1（4.17%） |
| 动作变化 | 0 |
| 源站变化 | 0 |
| 修复的历史误报 | 0 |
| 持续存在的历史缺陷 | 0 |
| 不可比较（强制） | 6（0） |

## 新增失败（回归）

| case_id | profile | truth | criticality |
|---|---|---|---|
| WAF-ATK-WEBSHELL-001 | OBSERVE | ATTACK | MANDATORY |

## 新增正确命中

无

## 新增误报

无

## 丢失检测

| case_id | profile | truth | criticality |
|---|---|---|---|
| WAF-ATK-WEBSHELL-001 | OBSERVE | ATTACK | MANDATORY |

## 动作变化

无

## 源站变化

无

## 持续存在的历史缺陷（前后相同不算通过）

无

## 不可比较样本

| case_id | profile | truth | criticality | 变化 |
|---|---|---|---|---|
| BOT-UNK-SCRIPT-001 | OBSERVE | None | None | TRUTH_UNKNOWN_EXCLUDED |
| BOT-UNK-SCRIPT-001 | PROTECT | None | None | TRUTH_UNKNOWN_EXCLUDED |
| BOT-UNK-TOMB-001 | OBSERVE | None | None | TRUTH_UNKNOWN_EXCLUDED |
| BOT-UNK-TOMB-001 | PROTECT | None | None | TRUTH_UNKNOWN_EXCLUDED |
| WAF-ATK-XXE-001 | OBSERVE | None | None | TRUTH_UNKNOWN_EXCLUDED |
| WAF-ATK-XXE-001 | PROTECT | None | None | TRUTH_UNKNOWN_EXCLUDED |
