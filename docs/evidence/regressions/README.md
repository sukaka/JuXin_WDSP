# P1-04 回归运行证据目录

每个 `<run-id>/` 子目录由 `test/performance/p0/run.sh regression` 创建
（run_id 格式 `YYYYMMDDTHHMMSS-xxxxxx`），包含：

- `plan.json`：冻结的回归 run-plan 副本（0444，运行后不可原地修改；
  `kind=p1_regression_run_plan`，登记语料 manifest 路径、sha256 与 seed）
- `manifest.json`：运行标识、宿主、git commit、Python 版本
- `status.json`：机器可读验收记录（PASS/FAIL/SKIP/BLOCKED/NOT_RUN +
  reason；环境不可用记 `BLOCKED / ENVIRONMENT_UNAVAILABLE`）
- `corpus-validation.txt`：语料 schema v1 校验输出（含逐例内容哈希自校验）
- `replay-plan.json`：seed 驱动的确定性回放计划（0444 冻结）
- `cases.jsonl`：逐例状态（执行层填充前全部为 NOT_RUN 骨架）
- `report.md`：由 `p1reg write-report` 只读生成

`compare-<run-id>/` 子目录由 `run.sh compare` 创建，包含前后版本逐例配对
比较结果；compare 只读两个输入证据目录，不改动其中任何文件。

证据目录一律保留、只增不改；plan 与 replay-plan 冻结后不得原地编辑，
语料预期变更必须升 `case_version`。执行层未就绪的阶段以
`status=BLOCKED / reason=ENVIRONMENT_UNAVAILABLE` 记录，不得以缺失目录
或假 PASS 冒充完成。
