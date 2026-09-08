# P1-04 规则/模型回归（R1 / S1 工具层）

规则、模型、引擎变更前后的**逐例行为回归**：固定语料 + 确定性回放计划 +
判定口径 + 前后版本配对比较。目标是回答一个问题——同一份语料，改动前后
每个用例的检测/处置是否如预期变化，且只如预期变化。

本阶段（S1）交付工具层与首批语料契约；**执行层尚未接入隔离栈，真实网关
回放属于 R2**。工具层对任何执行请求一律返回 `BLOCKED /
ENVIRONMENT_UNAVAILABLE`，绝不伪造 PASS。

## 目录

| 路径 | 内容 |
|------|------|
| `p1reg/` | 回归工具包（纯标准库）：`corpus.py` 语料校验、`replayplan.py` 确定性回放计划、`judge.py` 判定口径、`compare.py` 前后版本配对比较、`report.py` 报告生成、`cli.py` 子命令入口 |
| `adapters/` | 回放适配器。`http_replay.py` 只做请求计划构建（敏感头/body 仅留 sha256 指纹）与 reset 计划审查（拒绝 FLUSHALL/FLUSHDB）；`HttpReplayAdapter` 在 `environment=None` 时恒返回 BLOCKED |
| `profiles/` | 处置档：`observe.json`（只观察）、`protect.json`（阻断）。语料每例给出分档预期 |
| `corpus/` | 语料。`manifest.json`（schema v1，含每例 `content_sha256`）+ `cases/*.json`（18 条 WAF 用例） |
| `tests/` | 单元测试（`python3 -m unittest discover -s test/regression/p1/tests`，174 例） |
| `run-plan.example.json` | 回归 run-plan 示例（`kind=p1_regression_run_plan`），登记语料哈希与 seed |

## 与 P0-02（test/performance/p0）的复用边界

- **复用**：状态词表（PASS/FAIL/SKIP/BLOCKED/NOT_RUN/NOT_APPLICABLE，取自
  `p0bench.report_core.TEST_STATUSES`）、run_id 格式
  （`YYYYMMDDTHHMMSS-xxxxxx`）、证据纪律（plan.json 0444 冻结、
  status.json 机器可读、report 只读生成）、目标隔离分类
  （`p0bench.isolation.classify_target`）。
- **不复用/不改动**：`p0bench/corpus.py` 与 `plan.py` 是 P0 性能语料契约，
  P1 语料 schema v1 由本目录 `p1reg/corpus.py` 独立校验；`p0bench/cli.py`
  未新增子命令，P1 工具自带 CLI（`python3 -m p1reg.cli`）。
- **运行入口**：`test/performance/p0/run.sh` 严格增量新增 `regression` 与
  `compare` 两个子命令；既有六子命令（preflight/smoke/correctness/
  matrix/soak/recovery）语义不变。

## 运行入口

```bash
# 回归运行（当前为工具层：生成冻结计划后执行层 BLOCKED，退出码 3）
bash test/performance/p0/run.sh regression --plan test/regression/p1/run-plan.example.json

# 前后版本逐例比较（只读两个已完成证据目录，不需要 --plan）
bash test/performance/p0/run.sh compare --baseline <run-id> --candidate <run-id>

# 工具层自检（不需要隔离环境）
PYTHONPATH=test/regression/p1:test/performance/p0 python3 -m p1reg.cli \
    validate-corpus --manifest test/regression/p1/corpus/manifest.json \
    --profiles-dir test/regression/p1/profiles
```

| 入口 | 是否需要隔离环境 | 说明 |
|------|------------------|------|
| `run.sh regression` | 当前否（执行层 BLOCKED） | 校验 run-plan 与语料、核对哈希、冻结 plan/replay-plan、生成 NOT_RUN 骨架，随后如实 BLOCKED |
| `run.sh compare` | 否 | 只读 `docs/evidence/regressions/` 下两个证据目录，输出到新的 `compare-<run-id>/` |
| `p1reg.cli` 全部子命令 | 否 | 纯工具层：校验/哈希/计划/骨架/报告/比较 |

## 语料与判定口径要点

- manifest 顶层：`schema_version(=1)/corpus_id/created_at/description/cases`；
  用例含 `case_id/case_version/content_sha256/family/tags/criticality/
  truth(BENIGN|ATTACK|UNKNOWN)/source/license/authorization/scope/steps/
  expectations_by_profile/dataset_partition(TRAIN|VALIDATION|HOLDOUT)` 等。
- 校验拒绝：未知主版本、重复 ID、`content_sha256` 与文件实际不符、引用
  路径越出 `corpus/cases/`、无法解析的断言、真值与期望矛盾（BENIGN 不得
  期望检测、ATTACK 不得全无检测期望、deferred/UNKNOWN 不得为 MANDATORY）。
- `UNKNOWN` 与 `deferred` 用例不进分母；判定 `ABORTED/ERROR/PENDING_
  CORRELATION` 一律不转通过；缺证据即 FAIL。
- 退出码非零覆盖：FAIL / BLOCKED / NOT_RUN / 非法 SKIP / 数量不足 /
  证据校验失败。compare：PASS=0，FAIL/NOT_PASSED=1，结构错误=2。

## 已知限制

- 执行层未接隔离栈：`HttpReplayAdapter(environment=None)` 恒 BLOCKED，
  `run.sh regression` 恒以退出码 3 结束（这是 S1 的预期行为，不是缺陷）。
- 攻击样本的分档预期基于 CUSTOM_PACK/CRS 声明范围编写，未经真实网关
  验证；首次真实执行若暴露误报/漏报，正是回归要发现的内容，届时修正
  语料预期需升 `case_version` 并记录变更原因。
- API/JWT/例外/Bot/Agent/APM 类用例本阶段不造样本（manifest
  `description` 已标注待补充）；detection/final_decision 事件对账层属 R2。
- compare 的期望快照取自逐例行 `expectation` 字段；同 `case_version` 而
  期望不同会报 `EXPECTATION_CHANGED_SAME_VERSION` 完整性告警并使结论
  NOT_PASSED（期望漂移必须升版本号，禁止原地改）。
