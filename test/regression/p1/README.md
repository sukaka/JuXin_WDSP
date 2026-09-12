# P1-04 规则/模型回归（R1 工具层 + R2 真实回放 + R4b 门禁演练）

规则、模型、引擎变更前后的**逐例行为回归**：固定语料 + 确定性回放计划 +
判定口径 + 前后版本配对比较。目标是回答一个问题——同一份语料，改动前后
每个用例的检测/处置是否如预期变化，且只如预期变化。

R2 已完成：执行层接入 stage5 隔离栈（`stage5/stack-up.sh`），24 条语料
（18 WAF + 6 Bot）× 双处置档共 48 例真实回放全绿，并完成一次规则变更
（禁用自定义规则 7100001）前后对比——候选轮唯一变化（WAF-ATK-WEBSHELL-001
OBSERVE 检出归属丢失）被 compare 如实捕获。证据见
`docs/evidence/regressions/`（基线 `20260908T222305-798cfb`、候选
`20260908T222701-b7f86d`、对比 `compare-20260908T222932-46b792`）。

## 目录

| 路径 | 内容 |
|------|------|
| `p1reg/` | 回归工具包（纯标准库）：`corpus.py` 语料校验、`replayplan.py` 确定性回放计划、`judge.py` 判定口径、`compare.py` 前后版本配对比较、`report.py` 报告生成、`cli.py` 子命令入口、`reconcile.py` 事件对账（按响应头 `X-Jiuzhang-Request-ID` 关联安全事件取 matches/final_decision）、`executor.py` 真实回放执行器 |
| `adapters/` | 回放适配器。`http_replay.py` 构建请求计划（敏感头/body 仅留 sha256 指纹）并执行真实 HTTPS 回放（SNI=站点名、拨号 `resolve_to`、自签不验证、每用例 Cookie jar、Bot PoW 求解、逐请求 perf 记录）；`environment=None` 时恒返回 BLOCKED |
| `profiles/` | 处置档：`observe.json`（只观察）、`protect.json`（阻断）。语料每例给出分档预期 |
| `corpus/` | 语料。`manifest.json`（schema v1，含每例 `content_sha256`）+ `cases/*.json`（24 条：18 WAF + 6 Bot） |
| `stage5/` | `stack-up.sh` / `stack-down.sh`：stage5 隔离栈一键搭建/拆除（双应用 OBSERVE/PROTECT、自签证书、5 条自定义规则、Bot 策略、GeoIP mmdb 注入、发布与冒烟），产出环境描述符 JSON（0600） |
| `tests/` | 单元测试（`python3 -m unittest discover -s test/regression/p1/tests`，201 例） |
| `run-plan.example.json` | 回归 run-plan 示例（`kind=p1_regression_run_plan`，工具层 BLOCKED 路径），登记语料哈希与 seed |
| `run-plan.stage5.example.json` | R2 真实回放 run-plan 示例：`environment.stage5_env_descriptor` 指向 stack-up 产出的描述符，触发真实执行 |
| `tools/pack_evidence.py` | R3/R4b 证据打包器：回归证据目录 → CASES_CHUNK 分块 + manifest（case@PROFILE 组合键），供 regsign 签名与服务端导入 |
| `stage5/r4b-drill.sh` | R4b 发布门禁与回退演练固化脚本（P0/P1 主链自动化 + P2-P4 原语），演练报告见 `docs/evidence/regressions/P1-04-R4B-DRILL-REPORT.md` |

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
# 工具层回归运行（无 stage5_env_descriptor：冻结计划后执行层 BLOCKED，退出码 3）
bash test/performance/p0/run.sh regression --plan test/regression/p1/run-plan.example.json

# R2 真实回放：先起隔离栈（产出描述符 /tmp/p1reg-env.json，路径可自定义）
bash test/regression/p1/stage5/stack-up.sh /tmp/p1reg-env.json
# run-plan 的 environment.stage5_env_descriptor 指向该描述符即走真实执行
bash test/performance/p0/run.sh regression --plan test/regression/p1/run-plan.stage5.example.json
# 用毕拆栈
bash test/regression/p1/stage5/stack-down.sh /tmp/p1reg-env.json

# 前后版本逐例比较（只读两个已完成证据目录，不需要 --plan）
bash test/performance/p0/run.sh compare --baseline <run-id> --candidate <run-id>

# 工具层自检（不需要隔离环境）
PYTHONPATH=test/regression/p1:test/performance/p0 python3 -m p1reg.cli \
    validate-corpus --manifest test/regression/p1/corpus/manifest.json \
    --profiles-dir test/regression/p1/profiles
```

| 入口 | 是否需要隔离环境 | 说明 |
|------|------------------|------|
| `run.sh regression` | 视 run-plan 而定 | 无 `stage5_env_descriptor`：校验/冻结计划后如实 BLOCKED（退出码 3）；有描述符：经 `p1reg execute` 真实回放，48 例全 PASS 退出码 0，有 FAIL 为 1，执行不完整为 3 |
| `run.sh compare` | 否 | 只读 `docs/evidence/regressions/` 下两个证据目录，输出到新的 `compare-<run-id>/` |
| `p1reg.cli` 子命令 | `execute` 需要 | 纯工具层：校验/哈希/计划/骨架/报告/比较；`execute` 接隔离栈描述符执行真实回放 |

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

- run-plan 无 `environment.stage5_env_descriptor` 时执行层仍恒 BLOCKED
  （退出码 3），这是工具层预期行为，不是缺陷。
- 事件关联键是响应头 `X-Jiuzhang-Request-ID`：网关配置生成器用 set 覆盖
  入站 `X-Request-Id`，客户端注入的关联键进不了事件管道。
- OBSERVE 档的 Bot `BOT_CHALLENGE_OFFERED(action=OBSERVE)` 是假设性流程
  记录，不算检出；墓碑（bot 关闭后 verify 404/405）为响应派生检测，无
  事件对账。
- 已实证产品事实（本次未改产品代码，详见终验报告）：`escapeSecLangArg`
  反斜杠双重转义致反斜杠正则不命中；CRS 949110 相位中断抢占同相位后续
  自定义规则；Coraza v3.7 无 XML 体处理器（原始 application/xml XXE 无
  检出，语料中该例 truth=UNKNOWN 作行为绊线不进分母）；apigeo Sweeper
  在 mmdb 缺失时 nil panic 崩 API（stack-up 已注入 mmdb 规避）。
- JWT/Agent/APM 类用例语料仍缺（manifest `description` 已标注待补充）。
- compare 的期望快照取自逐例行 `expectation` 字段；同 `case_version` 而
  期望不同会报 `EXPECTATION_CHANGED_SAME_VERSION` 完整性告警并使结论
  NOT_PASSED（期望漂移必须升版本号，禁止原地改）。
