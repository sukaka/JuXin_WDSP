# P0-02 基准运行证据目录

每个 `<run-id>/` 子目录由 `test/performance/p0/run.sh` 创建，包含：

- `plan.json`：冻结的预登记计划副本（0444，运行后不可原地修改）
- `manifest.json`：运行标识、宿主/构建/压测器版本
- `status.json`：机器可读验收记录（PASS/FAIL/SKIP/BLOCKED/NOT_RUN + reason）
- `perf/`、`truth/`、`resources/`、`soak/`：采集原始数据
- `reconciliation.json`、`recovery.json`：事件对账与恢复记录
- `report.md`：由 `report.py` 只读生成

环境文件（含本 run 生成的密码）在运行结束时删除，不入库。
环境不可用的阶段以 `status=BLOCKED / reason=ENVIRONMENT_UNAVAILABLE` 记录，
不得以缺失目录冒充完成。
