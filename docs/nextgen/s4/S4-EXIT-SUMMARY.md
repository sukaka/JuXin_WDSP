# S4 阶段小结（NG-FLOW 强流程：响应确认型业务流程防护 —— 阶段关闭）

日期：2026-10-06 ｜ 设计冻结：`docs/nextgen/NG-FLOW-strong-flow.md`（实现状态 §7/§8/§8.6/§9 逐批追加）
出口记录：[`S4-FLOW02-EXIT-NOTE.md`](S4-FLOW02-EXIT-NOTE.md) ｜ [`S4-FLOW03-EXIT-NOTE.md`](S4-FLOW03-EXIT-NOTE.md)（含裁决闭环追记）｜ [`S4-FLOW04-EXIT-NOTE.md`](S4-FLOW04-EXIT-NOTE.md)

## FLOW-01~04 状态一览

| 批次 | 范围 | 状态 | 关键交付 |
|---|---|---|---|
| FLOW-01 定义与隔离 | 定义/步骤两表版本化（000176）+实例五态机与 `sflow:v1:` 物理隔离（000177）+旧观察态零导入 | **PASS（含于 FLOW-02 联合验收）** | server `strongflow`（CRUD/版本冻结/activate 端点归属核对/同名 RETIRED+发布触发）、gateway `flowguard`（定义解析校验 registry (id,version) 多版本并存） |
| FLOW-02 原子操作与实断 | Valkey Lua reserve+fencing+幂等、pipeline 接入、PROTECT 403 统一体、能力门 flow/1、事件数组落 PG | **PASS** | 双轨（`flowguard/reserve.go`、apiprotect 403 链、`guardconfig` 下发+能力门聚合）；F1/F03/F02 并发/F07 故障/C08/越权 stage5 全过 |
| FLOW-03 确认与恢复 | 响应回程成功判定 commit、202 受理、INDETERMINATE 标记（不自动回滚）、实例详情/resolve 恢复（000178 RESOLVE 词表） | **PASS（含两条联调裁决闭环）** | gateway `finalize.go`+`success.go`、server `resolve.go`+详情双档裁剪；F01 完整流/F04 超时对账/F05 迟到 fencing/F06 版本切换/F08 边界/202 全过；裁决①育龄窗下发（F06 闭环）、裁决②事件 token 语义（碰撞消解闭环） |
| FLOW-04 管理恢复与运行观测 | 流程基线页三 Tab 增强 + 指标内嵌 metrics 通道 | **PASS** | web `StrongFlowDefinitionsTab/StrongFlowInstancesTab`（警示条逐字/轨迹双档/恢复面板/越权整页拒绝）、server `metrics/strongflow.go`（per-app 五态分桶/积压/滞留/冲突率）；指标冒烟+Playwright 五场景全绿 |

## NG-T-F01~F08 覆盖对照表

| 用例 | 断言（设计 §4） | 覆盖位置与结论 |
|---|---|---|
| F01 正常流程与合法并行 | 步骤按序 CONFIRMED；同 parallel_group 并行不违规；判定式命中才确认 | FLOW-03 stage5：order-f3-1 两步 COMMIT OK→INSTANCE_CONFIRMED（组合判定读数在册）；v11 并行组 seq3 先行全链 CONFIRMED ✓ |
| F02 双节点同一步 | 并发同实例键同步骤：恰一 reserve 成功，另一冲突事件；无重复放行 | FLOW-02 stage5 双网关 overlay 6 轮并发全部恰一 200 一 403（共享 Valkey 原子域互证）✓ |
| F03 幂等重试与同键异参 | 同键同摘要幂等返回；同键异摘要冲突拒绝（裁决采 403）；不同键重走已完成步骤 PROTECT 403 | FLOW-02 stage5：3 连幂等重放 OK；同键异摘要 403+IDEMPOTENT-CONFLICT-001；§4「409」与 §1.6「403」不一致**已裁决采 403**（设计 §7.2-3）✓ |
| F04 超时但源站已成功 | 超时→INDETERMINATE 不自动回滚；对账后 CONFIRMED；源站记录型证据 | FLOW-03 stage5：慢端点 504→INDETERMINATE（Valkey 槽 PENDING 保持）+SLOW_PAY_EXECUTED 日志+resolve CONFIRM_SUCCEEDED 收口+HIGH 审计 ✓ |
| F05 迟到响应与旧 fencing | lease 过期新 reserve 得新 token；旧 token commit 拒绝不覆盖；事件链两 fencing 值 | FLOW-03 stage5：接管 f=2→3+旧 token COMMIT REJECTED FENCE-001；**裁决②修复后** PG 事件链 COMMIT OK f=3 与 REJECTED f=2 双行在册 ✓ |
| F06 取消后新实例、定义升级 | 取消/终态后同主体新实例可开始；定义激活新版本后旧实例按旧版本走完，新实例用新版本 | FLOW-03 初验发现「仅 ACTIVE 下发」不满足→**裁决①育龄窗**：发布面 ACTIVE∪有非终态实例 RETIRED；复验 order-w1 按 v13（RETIRED）走完 CONFIRMED、order-w3 definition_retired 拒新+v14 创建、order-w2 v14 全程 ✓ |
| F07 Valkey 故障/网关重启 | 停 Valkey 恒 UNKNOWN 放行+dependency_unavailable 不切本地；重启后热状态读回；PG 可对账 | FLOW-02 stage5 实证（D8 no local fallback 日志+恢复后 fence 1→2 延续）；FLOW-03 复验（PROTECT 定义停机 UNKNOWN 放行+恢复后 INDETERMINATE 经 resolve 收口 FAILED）✓ |
| F08 人工恢复越权/重复恢复 | jiuzhang_admin 403；expected_version 冲突 409；终态重复恢复 409；审计 HIGH 在册 | FLOW-03 server 单测+PG 契约+stage5（409 两态精确消息/HIGH 审计 JSON 全值）；FLOW-04 Playwright ⑤ 页面路由守卫整页拒绝互证 ✓ |

**NG-T-C01 缺省零变化**：各批均实证（无定义应用回归 40/40+13/13 不回退；无强流程活动请求事件形状零变化；无实例时指标段整段省略）。

## S4 完成证据（§15.2 NG-FLOW-01~04 要求项）

- **权限/审计/E2E**：权限零新增（api_flow.read/manage 复用 + evidence_read 复用授权域）；写操作 HIGH 审计（definitions create/activate/retire + instances resolve 全值 JSON 在册，jiuzhang_admin 全 403 对照单测+E2E 双证）；E2E——stage5 三批联调（FLOW-02 七组/FLOW-03 八组+两裁决复验/FLOW-04 指标冒烟）+Playwright 五场景两轮稳定全绿。
- **持久化恢复报告**：Valkey=热状态/PG=事实源边界实证——停 Valkey 恒 UNKNOWN 不切本地（caddy.log D8 日志）、恢复+网关重启后 fence 单调延续读回、Valkey 键清理与育龄窗自然掉出、PG 事件溯源逐条可对账（含 RESOLVE 管理对账留痕与审计链 request_id 溯源）。

## 移交项（后续批次）

1. **多 ACTIVE 定义绑定同端点的 CONFIRMED 语义**：finalize 一请求一预留只消费首个，其余绑定恒 PENDING——多绑定 commit 语义需设计明确（设计 §9.2-1）。
2. **实例键加 definition_id 分量评估**：消除同版本号不同名定义撞键缝隙（线契约裁决，设计 §9.2-2）。
3. **超时语义映射**：步骤 timeout_seconds 不下发不消费，超时判定由 upstream response_header_timeout 承载——步骤级超时与传输层超时映射关系待明确（设计 §8.4-3）。
4. **指标增量聚合**：step_events 24h 窗口扫描在表量大后改增量聚合（与既有全表 count 指标同批优化，设计 §9 口径注释）。
5. **业务签名回执与源站自动回查对账、流程定义可视化编辑器、定义激活确认单化评审**（设计 §3/§6 原定移交）；ha-lab 双节点分区强流程演练矩阵（与 AZ-02/03 移交项合并编排）。

## S4 关闭声明

NG-FLOW-01~04 全部批次出口判定 PASS，NG-T-F01~F08 全覆盖（含两条联调裁决闭环），回归零回退（stage5 40/40、custom-pack 13/13、server/gateway/web 全量测试绿、reconcile 700 双向零差集、gofmt/prettier 干净），现场已还原。S4 阶段关闭。
