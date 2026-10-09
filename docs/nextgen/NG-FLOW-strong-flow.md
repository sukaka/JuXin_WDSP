# NG-FLOW 强流程（响应确认型业务流程防护）阶段级冻结设计（S4 设计稿，2026-10-05）

> 依据：`docs/WDSP_API_WAF_NEXTGEN_RD_PLAN.md` §9 全节（方向四：为什么不能直接把现有流程观察改阻断 / 状态与原子操作 / 成功判定与流程语义 / 发布管理与验收）+ §14.3（outbox 原子提交、时钟漂移禁止严格保护、不静默降级）+ §15.2 NG-FLOW-01~04（完成证据列）+ §16.3 NG-T-F01~F08 测试矩阵。
> 阶段级冻结：FLOW-01~04 共享同一状态机与存储，不可分割设计；本文一次冻结契约与决策点，按 §5 拆分分批实施。
> 前置事实（inventory 复核 2026-10-05）：
> - **现有流程观察**（阶段8 §44）：`gateway/dynamic_security/detectors/flow.go`——发布通道下发 `api_flow_baselines`（步骤序列/前置约束/state_from·state_to/cancels_flow/max_per_window/幂等键），网关在会话窗口（`FlowSessionTTL=10min`）内重建主体步骤轨迹，产出七类 **OBSERVE 级**信号（step_skip/duplicate_submit/out_of_order/illegal_state_transition/rapid_batch/post_cancel_operation/anonymous_late_entry，Category=OBSERVE 只 AddMatch 不定案）；存储为进程内会话追踪器（LRU 定容）+ 可插拔 `StoreOverrides.FlowSession`（装配层可注入 Valkey 消除多节点盲区）；**无实例概念、无原子预留、无成功确认、无持久化**；fail-open（存储降级不判定）。
> - **Valkey 使用现状**：`behaviorstore`（行为观测计数）走 Lua 脚本，Valkey 故障 **fail-open** 内存回退（观测类允许）；该纪律对强流程**不适用**（§9.4 严格流程不得静默切换本地内存）。
> - **发布链**：`api_flow_baselines` 随整站快照下发（`guardconfig/flow_baselines.go`，纳入 api_policy_version 版本戳）；能力门 `detectors.<name>=<ns>/<N>` 序数比较（NG-COV-04/NG-AZ-03 az/3 先例）。
> - **覆盖账本**：管线检测器五态（SKIPPED/FULL/PARTIAL）接入点 `pipeline.go` 检测器调用段。
> - **审计/确认单**：AZ-04 确认单生命周期与 HIGH 审计链可直接复用纪律；本批不重复建确认单（定义激活用 manage 权限+审计，见 D9）。

## 1. 冻结契约

### 1.1 强流程定义模型（FLOW-01）

表（迁移 000176）：`api_strong_flow_definitions` + `api_strong_flow_steps`（外键级联）。

```
api_strong_flow_definitions：
  id / application_id（FK CASCADE）/ name / version（单调递增，激活即冻结）
  status（DRAFT/ACTIVE/RETIRED）/ binding_path_prefix（端点组前缀）/ instance_key_param
  （实例引用来源：批准的参数提取器键，如 "query:order_id" / "path:3"）
  mode（OBSERVE|PROTECT，缺省 OBSERVE）/ created_by/created_at/activated_at

api_strong_flow_steps：
  id / definition_id（FK CASCADE）/ step_key / endpoint_key / sequence
  success_rule JSONB（成功判定式，见 D4）/ timeout_seconds（15~600 夹紧）
  retry_semantics（IDEMPOTENT|NOT_RETRYABLE|REQUIRES_REVIEW）
  parallel_group（同组步骤可合法并行；空=串行）/ lease_seconds（步骤预留租约，15~300 夹紧）
  allows_202（异步受理：202=已受理进待完成，不自动完成）
```

定义校验规则（冻结）：step_key 唯一；sequence 单调；endpoint_key 必须属于绑定前缀下已 CONFIRMED 端点；success_rule 词表校验（状态码集合/JSONPath 等值/GraphQL errors 为空三形态之一，可组合与）；parallel_group 内步骤 sequence 相邻；首步必须 sequence 最小且唯一；timeout/lease 夹紧边界外 400。定义更新语义（NG-T-F06）：编辑即 version+1 新草稿，**激活的版本不可变**；新实例用激活版本，存量实例固定创建时版本（实例行冻结 definition_version，绝不强行换图；旧版本 RETIRED 后存量实例继续按旧版本走完）。

### 1.2 状态机与命名空间隔离（FLOW-01；NG-T-F06）

实例状态枚举（冻结）：`ACTIVE`（进行中）→ `CONFIRMED`（全部步骤确认完成）/ `INDETERMINATE`（未知待对账）/ `CANCELLED`（显式取消）/ `FAILED`（明确业务失败——仅由明确证据进入）。步骤状态：`CONFIRMED(state)` / `PENDING(A→B, lease, fencing)` / `RELEASED`。

实例键（§9.2 冻结）：`应用 + 可信租户 + 可信主体 + 流程定义版本 + 实例引用`，实例引用值经域隔离 HMAC（与 authz objref 同一 HMAC 域纪律，键名空间 `sflow` 独立域）。

物理隔离形态（冻结）：PG 新表 `api_strong_flow_instances` / `api_strong_flow_step_events`（迁移 000177）；Valkey 键前缀 **`sflow:v1:`**（版本化命名空间——v1 嵌入键前缀，与观察态 `flow:` 会话键物理隔离）。

**旧观察状态不可导入（写明理由）**：① 观察轨迹是「会话窗口内见过某步骤」——无源站成功证据、无原子预留、无 fencing token，导入等于把「看到过」伪造成「做成了」（§9.1 明文禁止）；② 实例键含流程定义版本维度，观察态无此维度，映射不存在；③ 观察态会话随 10min TTL 蒸发，本身就是易失观测不是事实。物理上两表两键前缀，**不建任何导入路径**。

### 1.3 原子预留/提交/释放（FLOW-02；NG-T-F02/F03/F05）

选型结论：**Valkey Lua 脚本（共享原子域）+ PG 事件溯源兜底**，不用 PG 行锁做热路径。

- 理由：多节点竞态（F02）需要跨网关共享原子域，Valkey 已在线且有 Lua 先例（behaviorstore）；PG `SELECT FOR UPDATE` 在步骤热点行上竞争时延不可控且把网关热路径绑死在 PG 可用性上；PG 承担事件溯源与实例持久化（D8），不承担热路径原子判定。
- fencing（F05 冻结）：实例级单调序号——Lua 内 `INCR sflow:v1:{instance}:fence`，reserve 成功返回 token=序号；commit/release 必须携带 token 且 `token == 当前 fencing` 才接受；lease 过期后新 reserve 得更大 token，**旧 token 提交一律拒绝**（迟到响应不覆盖新状态）。
- 幂等（F03 冻结）：operation_id + 幂等键绑定「实例+步骤+主体+参数摘要（SHA-256）」；同键同摘要重试 = 幂等返回既有结果；**同键异摘要 = 冲突拒绝**（不变成合法重试）；不同键重走已完成步骤 = 违规（D6 处置）。
- Valkey 集群：相关键（实例状态/fence/步骤槽）必须以实例键为 hash tag（`{...}` 同槽）处于同一原子操作域（§9.2）。

### 1.4 业务成功判定（FLOW-03；NG-T-F04）

管理员为每步配置成功判定式（success_rule，三形态可组合与）：① 响应状态码集合（如 `[200]`）；② body JSONPath 受限字段等值（如 `$.status == "PAID"`，JSONPath 子集冻结：仅点路径+等值）；③ GraphQL `errors` 为空。**HTTP 2xx 不是通用成功证据**（§9.3）——判定式必须显式配置，无配置该步骤不产出 CONFIRMED（恒 UNKNOWN，如实呈现）。

网关执行点在响应回程判定：判定式命中 → commit（带 fencing token）；**超时/连接失败/判定式不命中/形态无法解析 → UNKNOWN**——标记未知进入对账，**不自动 release 为可重试**（F04：超时但源站可能已成功，自动回滚会诱导重复扣款）。业务签名回执（源站 HMAC 回执头）、可信源站连接状态证据列为**本批不做**（移交，§6）。

### 1.5 未知恢复与管理对账（FLOW-03/04；NG-T-F04/F08）

- UNKNOWN 实例进入 `INDETERMINATE`，实例详情页展示「未知，不显示安全通过」（§9.4 红线）。
- 管理恢复端点：`POST /api-security/strong-flows/instances/{id}/resolve`，action ∈ `CONFIRM_SUCCEEDED` / `CONFIRM_NOT_EXECUTED` / `KEEP_UNKNOWN`；**reason 必填**、manage 权限、HIGH 审计、`expected_version` 乐观锁（F08 版本冲突 409）、终态实例（CONFIRMED/CANCELLED/FAILED）拒绝重复恢复（409 幂等不误伤）。
- 202 异步受理：步骤 `allows_202=true` 时 202 → 步骤进「已受理待完成」，实例保持 ACTIVE 等待后续步骤或人工对账；不把 202 自动记完成。
- 源站自动回查契约（定义可配对查端点）列为**本批不做**（移交）。

### 1.6 实断动作语义（FLOW-02；延续 AZ-03 纪律）

- 定义级 `mode`：OBSERVE（缺省，NG-T-C01 零变化）/ PROTECT。
- PROTECT 下违规动作：无有效预留执行依赖步骤 / 重复执行已 CONFIRMED 步骤 / 非法并行（不在同 parallel_group）/ fencing 过期提交 → 403 统一 JSON `{"code":"FLOW_VIOLATION_DENIED","message":"流程状态不允许该操作","request_id":"…"}`（不泄露实例细节，防探测——AZ-03 同形态）。
- **UNKNOWN 恒不阻断**（红线）：Valkey 故障/判定不确定/证据不足 → 放行 + INDETERMINATE/UNKNOWN 标记 + 事件如实披露（dependency_unavailable 同 AZ-02 先例）；任何形态不把 UNKNOWN 映射为 403。
- 决策与证据：检测器 `flowguard` 产决策组（ALLOW/VIOLATION/UNKNOWN + reason code 词表 FLOW-RESERVE-001/FENCE-001/IDEMPOTENT-CONFLICT-001/UNKNOWN-001…），证据随 final_decision 内嵌（AZ-03 §1.4 同纪律：不建新表）。

### 1.7 多节点正确性与实例租约（FLOW-02；NG-T-F02）

- 双节点实证方法（冻结）：stage5 compose overlay 加第二网关实例（独立节点名、独立 sidecar 卷、共享 Valkey），同一 Host 双端口并发同实例键同步骤请求 → 断言恰一个 reserve 成功（另一个 FENCE/RESERVE 冲突），事件链可核对。
- 实例租约**独立实现**（结论）：步骤预留租约（lease_seconds，15~300 夹紧，读侧夹紧先例）是实例执行语义，与 AZ-02 快照租约（快照时效）不同域——不挂接、不混用；时钟漂移沿用 AZ-02 纪律（skew 超上限时 PROTECT 判定恒 UNKNOWN，禁止启用依赖时效的严格保护并展示原因，§14.3）。

### 1.8 故障策略与持久化边界（FLOW-02/03；NG-T-F07）

- Valkey 不可用：**不切换本地内存**（严格流程不静默降级，保持分布式唯一事实源）；期间强流程判定恒 UNKNOWN（放行+披露，D6 红线）；恢复后状态从 Valkey 读回，PG 事件可对账（可追溯）。
- 网关重启：实例热状态在 Valkey（fence/lease/步骤槽）不受影响；重启节点从 Valkey 读回继续——状态恢复正确性优先于时延（§14.2）。
- 持久化边界（冻结）：**Valkey = 热状态**（实例当前步/fence/lease/幂等键槽）；**PG = 事实源**（实例行创建与终态、步骤事件溯源逐条、`INDETERMINATE` 持久待对账）；步骤事件经 outbox 纪律落 PG（§14.3：事件先入 PG 事件表，传递失败可重试且去重——复用既有事件上报链幂等键）。
- Valkey 数据丢失（flush/重建）≠ 实例消失：实例行在 PG，热状态缺失按 UNKNOWN 披露并对账，不伪造恢复。

### 1.9 管理恢复与运行观测（FLOW-04）

- 恢复端点（§1.5）+ 实例列表 `GET /api-security/strong-flows/instances`（按应用/状态/时间过滤分页，read 权限）+ 实例详情 `GET .../instances/{id}`（步骤轨迹+事件+证据，evidence_read 裁剪明细）。
- 定义管理 `GET/POST/PUT/POST .../definitions{/{id},/{id}/activate,/{id}/retire}`（manage 权限；activate 即冻结版本；HIGH 审计）。
- 运行指标：实例计数按状态、INDETERMINATE 率与积压、对账时延、reserve 冲突率——进既有 metrics 通道（api-security/metrics 同形态）。
- 页面：复用流程基线页面（§9.4）增强——定义版本/状态图/允许转换/成功条件/异常策略/实例恢复记录；实例管理区块（列表/详情/恢复操作）。

### 1.10 迁移与 OpenAPI 预估（基线 691）

- 迁移 **000176**（definitions+steps 两表）、**000177**（instances+step_events 两表）——定义与实例拆两个迁移号（定义先行可独立评审）。
- OpenAPI 增量预估 **+8 → 699**：definitions CRUD/activate/retire（4）+ instances list/detail/resolve（3）+ 运行指标并入既有 metrics 端点（0 新增）+ 实例事件查询（1）。逐一 reconcile 双向零差集。

## 2. 冻结决策点（D1~D12）

| # | 结论（一句话） | 理由要点 |
|---|---|---|
| D1 定义模型 | 定义/步骤两表版本化（迁移 000176），激活即冻结、编辑产新草稿，版本单调；绑定=应用+路径前缀+实例引用参数提取器 | 版本不可变是「存量不换图」（F06）的唯一可靠承载；定义即配置，校验在管理面入库边界 |
| D2 状态机与隔离 | 实例五态+步骤三态冻结；PG 新表 + Valkey `sflow:v1:` 键前缀物理隔离；旧观察态不可导入（三无：无成功证据/无预留/无版本维度） | §9.1 明文禁止导入；物理隔离杜绝任何「顺手迁移」路径 |
| D3 原子操作选型 | Valkey Lua（hash tag 同槽）+ fencing=实例级 INCR 单调序号；PG 只做溯源不做热路径行锁 | 多节点共享原子域 + 有界时延；迟到提交按 token 过期拒绝（F05） |
| D4 成功判定 | 显式判定式（状态码集合/JSONPath 等值/GraphQL errors 空，可组合与）；无配置恒 UNKNOWN；超时/失败/不命中恒 UNKNOWN 不自动回滚 | 2xx≠成功（§9.3）；F04 红线：超时可能已成功，回滚即诱导重复扣款 |
| D5 未知恢复 | INDETERMINATE 待对账 + 管理恢复端点（reason/权限/审计/乐观锁/终态拒重复）；202=已受理待完成不自动完成；自动回查移交 | §9.4「不显示安全通过」+ F08 审计与冲突拒绝 |
| D6 实断语义 | 定义级 OBSERVE（缺省）/PROTECT；PROTECT 违规 403 统一体不泄露细节；UNKNOWN 恒不阻断任何形态 | AZ-03 纪律延续（实断可证、UNKNOWN 不误断） |
| D7 多节点 | stage5 双网关 overlay 实证 F02；实例租约独立实现（不挂快照租约），skew 超上限恒 UNKNOWN | 两租约不同域；§14.3 时钟纪律 |
| D8 故障策略 | Valkey 故障不静默本地降级，恒 UNKNOWN 放行+披露；热状态 Valkey/事实 PG 边界冻结；Valkey 丢数据按 UNKNOWN 对账不伪造 | §9.4 严格流程禁本地降级 + AZ-02 依赖不可用披露先例 |
| D9 管理恢复与观测 | 恢复端点（乐观锁+reason+HIGH 审计+终态拒重复）+ 实例列表/详情 + 指标入既有 metrics；页面复用流程基线页增强 | §9.4 明文要求；权限沿用 read/manage/evidence_read 零新增 |
| D10 迁移/OpenAPI | 000176（定义）+000177（实例）两号；OpenAPI +8 预估 699 | 定义与实例分开评审；对账纪律延续 |
| D11 测试计划 | NG-T-F01~F08 逐条映射（见 §4）；双节点 compose overlay 编排 | 每条有断言与编排方法 |
| D12 拆分与顺序 | FLOW-01（定义+隔离）先行串行 → FLOW-02（原子操作+实断）→ FLOW-03（确认+恢复）→ FLOW-04（页面+观测）；能力门升 `detectors.flowguard=flow/1`（含 PROTECT 定义的快照要求）；缺省关闭零变化（NG-T-C01） | 状态机与存储共享不可分割；能力门与 az/3 同纪律防旧节点漏断 |

## 3. 本批不做（范围外，如实标注）

- 业务签名回执（源站 HMAC 回执头）与可信源站连接状态证据通道。
- 源站自动回查对账契约（定义级对查端点）——首批人工恢复。
- 流式/超大响应/跨系统补偿流程（§9.3 明示不支持或需业务回执）。
- 流程定义前端可视化编辑器（首批表单+JSON 视图；编辑器后续批评估）。
- 确认单机制复用到流程定义激活（首批 manage 权限+审计；业务确认单式签署若需要另评）。
- 多 Valkey 集群跨地域原子域（单 Valkey/同槽为前提；跨地域强流程不支持）。
- 既有流程观察（flow.go 七类 OBSERVE 信号）行为不变——强流程与其并行共存，互不消费。

## 4. 测试计划（NG-T-F01~F08 逐条映射）

| 用例 | 断言 | 实施位置 |
|---|---|---|
| F01 正常流程与合法并行 | 步骤按序 CONFIRMED；同 parallel_group 并行不违规；成功判定式命中才确认（无命中不确认） | server+gateway 集成（stage5 双步骤定义：注册→支付模拟） |
| F02 双节点同一步 | 并发同实例键同步骤：恰一 reserve 成功，另一 RESERVE 冲突事件；无重复放行 | stage5 双网关 overlay（compose 第二实例+共享 Valkey）+ 并发 curl |
| F03 幂等重试与同键异参 | 同键同摘要重试幂等返回；同键异摘要 409 冲突；不同键重走已完成步骤 PROTECT 下 403 | 集成 + 单测（摘要构造矩阵） |
| F04 超时但源站已成功 | 超时 → INDETERMINATE 入对账（不自动回滚、不可直接重试同键）；对账确认后 CONFIRMED；源站记录型证据证明业务已执行 | stage5 源站延迟注入（testorigin 延迟端点或故障注入） |
| F05 迟到响应与旧 fencing | lease 过期后新 reserve 得新 token；旧 token commit 拒绝不覆盖；事件链含两次 fencing 值 | 单测（fencing 序列）+ 集成（lease 短窗注入） |
| F06 取消后新实例、定义升级 | 取消后同主体新实例可开始；定义激活新版本后旧实例按旧版本走完，新实例用新版本 | 集成（版本切换前后双实例） |
| F07 Valkey 故障/网关重启 | 停 Valkey：PROTECT 定义请求恒 UNKNOWN 放行+dependency_unavailable 披露（不切本地内存）；重启网关后实例状态从 Valkey 读回继续；PG 事件可对账 | stage5 故障注入（停 valkey/重启 gateway 容器） |
| F08 人工恢复越权/重复恢复 | jiuzhang_admin 403；expected_version 冲突 409；终态实例重复恢复 409；审计 HIGH 在册 | server 单测 + Playwright（页面恢复操作） |

另：NG-T-C01 缺省零变化（无定义时管线零行为、快照无段、能力需求空）；集成四断言沿用 AZ-03 口径（客户端响应/源站到达/决策记录/运行态事件）。

## 5. 实现拆分与顺序（文件级边界预估，实施批再冻结）

**FLOW-01 定义与隔离（先行串行）**
- server：`migrations/000176_strong_flow_definitions.{up,down}.sql`、新包 `internal/strongflow/`（定义 CRUD/校验/版本冻结）；`guardconfig/` 发布段（`api_strong_flows` 随快照下发，版本戳覆盖）；OpenAPI 登记。
- gateway：`dynamic_security/detectors/flowguard/`（定义解析+校验同口径）；`modules/jiuzhang_guard` 装配（段缺失零行为）。

**FLOW-02 原子操作与实断（依赖 01）**
- gateway：`flowguard/reserve.go`（Valkey Lua 预留/提交/释放+fencing）、pipeline 接入（API 管线内、授权评估之后）；`capability_report.go` 自报 `flowguard=flow/1`；server `gatewayconfig/capability_gate.go` 需求聚合（含 PROTECT 定义 → required flow/1）。
- 迁移 000177（instances+step_events）；server 事件采集扩展（实例/步骤事件落 PG）。

**FLOW-03 确认与恢复（依赖 02）**
- gateway：成功判定式评估（响应回程）；server：`strongflow/instances.go`（列表/详情/resolve）、对账查询；OpenAPI 增量。

**FLOW-04 管理恢复与观测（依赖 03）**
- web：流程基线页增强（版本/状态图/实例管理区块）；指标接入；Playwright E2E（定义激活/正常流/违规 403/INDETERMINATE 对账/越权）。

并行可行性：FLOW-01 内 server/gateway 可并行（共享契约为定义 JSON 形状，本文 §1.1 已冻结）；FLOW-02/03 串行依赖；FLOW-04 的页面可在 03 的 API 契约冻结后提前起步（mock）。

## 6. 移交项（后续批次）

- 业务签名回执与源站自动回查对账；流程定义可视化编辑器；定义激活确认单化评审。
- 跨 Valkey 集群/跨地域强流程；流式与超大响应形态。
- 强流程与 Bot 挑战/身份行为窗口的信号互通评审（当前互不消费，后续评估降噪联动）。
- ha-lab 双节点分区下的强流程演练矩阵（与 AZ-02/03 移交项合并编排）。

## 7. 实现状态（FLOW-01/02 批，2026-10-05 联调验收批补记；本节为实施记录，不改上文契约）

**状态：FLOW-01（定义与隔离）+ FLOW-02（原子操作与实断）已落地并经 stage5 联调验收。** server/gateway 双轨按 §5 边界实施；出口判定与逐项证据见 `docs/nextgen/s4/S4-FLOW02-EXIT-NOTE.md`。FLOW-03（确认与恢复：响应回程 commit、instances 详情/resolve）与 FLOW-04（页面+观测）未开工，本批不宣称覆盖。

### 7.1 契约映射（§1 冻结契约/D1~D12 → 实现位置）

| 契约 | 实现 |
|---|---|
| §1.1 定义模型（D1） | 迁移 000176（definitions+steps 两表，FK 级联）；server `internal/strongflow/`（CRUD/校验/版本冻结：Create 同名 version=max+1 新草稿、Update 仅 DRAFT 原地、Activate 同事务 RETIRED 同名义旧 ACTIVE、RETIRED 单向终态）；gateway `detectors/flowguard/{definition,validate,registry}.go` 同口径解析校验（success_rule 白名单键严格解码、体量上限两侧同边界 4096B） |
| §1.2 状态机与隔离（D2） | 迁移 000177（instances+step_events 两表：实例五态 CHECK、事件 action/result 词表 CHECK、`uq_strong_flow_instance`(definition_id,definition_version,instance_key) 与 `uq_strong_flow_step_event`(instance_id,step_key,action,fencing_token) 幂等去重）；Valkey 键前缀 `sflow:v1:`（`flowguard.KeyPrefix`，hash tag `{instance_id}` 同槽）；实例键 `sfref:`+域隔离 HMAC（`instancekey.go` 域 `jiuzhang-wdsp-strongflow-sfref-v1\x00`，与 server 侧同算法同输入线契约）；旧观察态零导入路径 |
| §1.3 原子预留/提交/释放（D3） | `flowguard/reserve.go`：Valkey Lua 单次原子往返（reserve/commit/release 三脚本），fencing=实例级 `INCR ...:fence`，commit/release 须 token==当前 fence；lease 判定一律 Valkey 服务端 TIME（不消费网关本地时钟）；lease 过期仅被争夺时生效（持 token 的 commit 仍接受，F04 语义）；PG 只做事件溯源（server `strongflow/instance_events.go`：resolveInstance upsert + 事件 ON CONFLICT 去重） |
| §1.6 实断动作语义（D6） | `flowguard/evaluate.go`：定义级 mode OBSERVE（缺省）/PROTECT；违规（REJECTED/CONFLICT）产 `flowguard.violation` 明细——定义 PROTECT 且引擎 PROTECT 双闸全真 Category=BLOCK，经 `apiprotect.flowguardBlockMatched` 子分支 `writeAPIStrongFlowDeniedResponse` 403 统一 JSON `{"code":"FLOW_VIOLATION_DENIED","message":"流程状态不允许该操作","request_id":"…"}`（committed 直出不走 Caddy 错误链阻断页，不泄露实例/步骤/fencing 细节）；**UNKNOWN 恒不阻断**（`flowguard.unknown` OBSERVE 明细，infra 故障附 `dependency_unavailable=true`）；动作事实（含 ALLOW）经请求上下文 `sflow.actions` 留存挂到运行时主事件 `strong_flow` 数组 |
| §1.7 多节点（D7） | stage5 双网关 overlay（`deployment/docker-compose.stage5-f02.yml` 临时编排，验收后移除）：第二实例独立节点名 gateway-stage5-02/独立 admin·config·logs 卷/共享 Valkey，配置经主节点 autosave 复制 --resume 同源；6 轮并发同实例键同步骤（异参数摘要）全部恰一 RESERVE OK 另一 CONFLICT `reserve_conflict` |
| §1.8 故障策略（D8） | `flowguard.Store`：cli 为 nil/Eval 故障/协议异常恒 UNKNOWN（`warnf` 每分钟节流告警）；装配层 `apiprotect.buildStrongFlowRuntime` 对 Valkey 缺席/HMAC 密钥缺席均 Warn 不拒载；**无任何本地内存回退路径**（包内无进程内权威态——stage5 停 Valkey 实证恒 UNKNOWN 放行+披露，网关日志 `D8: no local fallback`）；网关重启 --resume 后热状态从 Valkey 读回（实证同实例 EXPIRE fence=1→RESERVE fence=2 延续） |
| §1.9 管理面（D9，FLOW-02 最小面） | definitions CRUD/activate/retire（manage 权限，写操作 HIGH 审计）+ instances 列表（read 权限，application_id/status/created_since 过滤分页）；activate/retire 触发整站发布（`SetPublishFunc` 挂既有发布链）；instances 详情/resolve/指标/页面属 FLOW-03/04 未实施 |
| §1.10 迁移/OpenAPI（D10） | 迁移 000176/000177 两号如预估；OpenAPI +7（definitions 5 端点 + instances 列表 + 强流程事件查询并入既有运行时事件面）实收 **698** 双向零差集（预估 699 差 1：实例详情端点随 FLOW-03 登记） |
| D12 能力门 | 网关 `capability_report` 自报 `detectors.flowguard=flow/1`；server `gatewayconfig/capability_gate.go` 聚合：含 PROTECT 定义的快照 required flow/1（全 OBSERVE 零需求，旧节点兼容滚动升级）——stage5 篡改 flow/0 实证 `CAP_MISSING:detectors.flowguard(required=flow/1,actual=flow/0)` fail-closed 不发送 /load |
| NG-T-C01 零变化 | `apiStrongFlows==nil` → Runtime nil 零行为；无定义应用（waf-s5.local 等）stage5 回归 40/40 不回退 |

### 7.2 联调新发现与修正（联调验收批，2026-10-05）

1. **`strong_flow` 事件为数组（A/B 契约修正，已落地）**：一请求可携带多动作（首步 INSTANCE_NEW+RESERVE 同拍、过期接管 EXPIRE+RESERVE 同拍），单对象形状无法承载。线契约定为 `strong_flow` JSON **数组**（`dsevents.StrongFlowAction` 冻结形状，`apievents.Record.StrongFlow` / server `collector.go` 消费侧同形）；归属字段（application_id/tenant_ref/principal_ref/request_id）由采集侧从宿主主事件注入，数组元素不重复携带。旧版网关事件缺该键为 nil，采集全程容忍。
2. **strong-flow-only 应用对象 HMAC 密钥下发缺口（已修正）**：实例键化复用 `api_authz_object_hmac_key_hex`（§1.2 冻结同域纪律不同域），但发布侧 `guardconfig/provider.go` needsKey 原仅覆盖授权模型在场场景——无授权模型仅有强流程定义的应用快照缺 key，网关侧恒 UNKNOWN（`hmac_key_unavailable`）。修正：needsKey 增 `len(cfg.APIStrongFlows)>0` 分支；应下发而缺失 fail-hard（不静默降级）。
3. **F03 冲突响应码裁决（设计内部不一致，采 403）**：§4 测试矩阵 F03 行写「同键异摘要 **409** 冲突」，与 §1.6 冻结的「PROTECT 违规 403 统一 JSON」内部不一致。裁决采 **403 统一体**：冲突类型（IDEMPOTENT-CONFLICT-001/reserve_conflict/already_confirmed）只落事件与决策明细，客户端统一 `FLOW_VIOLATION_DENIED` 不泄露状态细节（与 AZ-03 防探测同纪律；若按 409 则响应码本身即泄露「槽已占用」语义）。§4 矩阵行以本裁决为准（FLOW-03 批修订设计稿时回写）。
4. **instances/{id} 详情端点未注册（范围如实登记）**：越权对照中 jiuzhang_admin `GET instances/{id}` 返回 404——该端点属 FLOW-03（§5），本批未注册路由，404 为路由不存在而非权限语义；已注册端点（definitions 全部 + instances 列表）jiuzhang_admin 全 403。

### 7.3 覆盖边界（本批未覆盖，如实移交 FLOW-03/04）

- **commit 不接运行时**：`Store.Commit/Release` 已实现并有单测（fencing/幂等重放/实例完成判定），但响应回程成功判定（§1.4）属 FLOW-03——本批运行时只做 RESERVE。推论：带前置的步骤在本批恒 `predecessor_unconfirmed`（前置只 RESERVE 未 CONFIRMED），§4 F01「步骤按序 CONFIRMED」断言移交 FLOW-03 验收；本批 F01 覆盖=按序两步放行+决策组（register ALLOW / pay VIOLATION-OBSERVE 如实呈现）+事件链完整。
- instances 详情/管理恢复 resolve 端点、运行指标、页面增强（FLOW-03/04）。
- F04（超时 INDETERMINATE 对账）依赖 FLOW-03 的 UNKNOWN 标记落地，本批未覆盖。

### 7.4 E2E 证据摘要（stage5，2026-10-05；逐项原文见出口记录）

- F1 按序两步（order-f1-1）：register 200+源站到达，`[INSTANCE_NEW OK fence=1, RESERVE OK fence=1]`；pay 200+源站到达（OBSERVE 放行），`RESERVE REJECTED FLOW-RESERVE-001` + `flowguard.violation OBSERVE predecessor_unconfirmed`；PG 事件链落库一致。
- 违规两态：OBSERVE 直接 pay 放行+记录；切 PROTECT（v2 草稿激活语义）同场景 403 精确体+源站零到达+final_action=BLOCK；PROTECT 合法首步 register 放行不误断；v3 恢复 OBSERVE。
- F03：同键同摘要 3 连发全 200，后两次 `RESERVE OK fence=1` 幂等重放（无 INSTANCE_NEW/无冲突）；同键异摘要 PROTECT 403+`IDEMPOTENT-CONFLICT-001 digest_mismatch`。
- F02：双网关 6 轮并发全部恰一 200 一 403（A 侧 `CONFLICT FLOW-RESERVE-001 fence=1 final=BLOCK`，B 侧 `INSTANCE_NEW+RESERVE OK fence=1`），Valkey `sflow:v1:` 键族在册。
- F07：停 Valkey 后 PROTECT 请求（含违规形态）恒 200+源站到达，`UNKNOWN-001 valkey_error dependency_unavailable=true`，caddy.log `strong flow valkey op failed, UNKNOWN fail-open (D8: no local fallback)`；恢复+重启网关后同实例 `EXPIRE fence=1 → RESERVE fence=2`（热状态读回，fence 单调延续），新实例正常 INSTANCE_NEW。
- C08：capability.json 篡改 flow/0 → 发布 FAILED `CAPABILITY_MISSING` / `CAP_MISSING:detectors.flowguard(required=flow/1,actual=flow/0)` 不发送 /load；恢复 flow/1 后全 OBSERVE 快照发布成功。
- 越权：jiuzhang_admin 对已注册 7 端点全 403（instances/{id} 404=路由未注册，见 7.2-4）。
- 审计：definitions create/activate 全 HIGH 在册（sec_admin_s5，request_id 可溯源）。
- 回归：stage5 40/40、custom-pack 13/13、server 四包 ok、gateway build+34 包 ok、reconcile 698 零差集、本批文件 gofmt 干净。

## 8. 实现状态（FLOW-03 批，2026-10-05 联调验收批补记；本节为实施记录，不改上文契约）

**状态：FLOW-03（确认与恢复）已落地并经 stage5 联调验收。** gateway 轨（响应回程成功判定 commit/202 受理/INDETERMINATE 标记）+ server 轨（实例详情/管理恢复 resolve/迁移 000178）双轨按 §5 边界实施；出口判定与逐项证据见 `docs/nextgen/s4/S4-FLOW03-EXIT-NOTE.md`。FLOW-04（页面+运行观测）未开工。

### 8.1 契约映射（§1.4/§1.5/§1.9 → 实现位置）

| 契约 | 实现 |
|---|---|
| §1.4 成功判定（D4） | gateway `flowguard/success.go`（三形态可组合与求值：状态码集合/body JSONPath 受限等值/GraphQL errors 空；无配置恒 UNKNOWN）；`finalize.go FinalizeResponse`（响应回程收口：判定命中→Commit 携带 fencing token；不命中/超时/连接失败/形态无法解析→UNKNOWN 进 INDETERMINATE **不自动 release**）；装配 `apistrongflow.go`（ResponseWriter 包装先例——仅成功预留请求包装，体样本仅 body 判定式步骤采集 ≤64KB，挂点在脱敏/水印/签名改写之前面向源站事实） |
| §1.4 202 异步受理 | `Store.MarkAccepted`（槽位 accepted_202 标记）+ finalize markAccepted：步骤 allows_202 且响应 202 → RESERVE OK 条目 reason_code=`FLOW-ACCEPTED-202`，实例保持 ACTIVE 不自动记完成 |
| §1.5 INDETERMINATE 标记 | `Store.MarkIndeterminate`（Lua：仅 ACTIVE→INDETERMINATE；热状态缺失 UNKNOWN state_missing 不伪造；终态/已 INDETERMINATE 幂等重放）；实例 INDETERMINATE 后新 reserve 恒 UNKNOWN（instance_indeterminate 不可服务，不重放成功语义） |
| §1.5 管理恢复 | server `strongflow/resolve.go`（`POST .../instances/{id}/resolve`：action 三词 CONFIRM_SUCCEEDED→CONFIRMED / CONFIRM_NOT_EXECUTED→FAILED / KEEP_UNKNOWN 不推进；reason 必填；expected_version 乐观锁 409；终态拒重复 409；单事务推进+事件落行（reason_code=FLOW-RESOLVE-001）+version+1；HIGH 审计 after JSON 全值） |
| §1.9 实例详情 | server `strongflow/instances.go GetInstance`（`GET .../instances/{id}`：实例行+步骤轨迹按 occurred_at 全链+`status_semantics`/`status_message` 语义词表——INDETERMINATE=`UNKNOWN_NOT_CONFIRMED`+「未知，不显示安全通过」逐字不美化 §9.4 红线；证据明细档 fencing_token/reason_code/request_id 仅 evidence_read 带出，无权限键缺席） |
| §1.9 对账查询 | instances 列表 status=INDETERMINATE 过滤+分页（FLOW-02 已建，零新端点） |
| D10 迁移/OpenAPI | 迁移 000178（step_events action CHECK 放宽 +RESOLVE，管理面专属词表）；OpenAPI +2 → **700** 双向零差集 |

### 8.2 server 轨偏差登记（6 条，均有注释落码）

1. **RESOLVE 新动作词表**（任务书预案路径）：CONFIRM_* 推进复用词表内 INSTANCE_CONFIRMED/INSTANCE_FAILED+reason_code=FLOW-RESOLVE-001 区分管理面来源；KEEP_UNKNOWN 无词表内承载，按预案走迁移 000178 放宽 CHECK（管理面专属，网关不产出；采集侧事件校验词表不动）。
2. **CONFIRM_NOT_EXECUTED→FAILED 而非 CANCELLED**：§1.2 FAILED=「明确业务失败——仅由明确证据进入」，人工对账确认未执行即明确证据；INDETERMINATE→FAILED 在冻结转换表内；CANCELLED=显式取消语义不符。
3. **审计摘要 JSON 形态**：既有审计脱敏器 MaskSensitiveJSON 对非 JSON 摘要整段遮蔽（AZ-04 已登记同现象）——为保 D5「after 含 action/reason/前后状态」可读，resolve 摘要用 JSON 对象形态（键均非敏感键白名单，全值保留）。
4. **evidence_read 复用 `api_authorization.evidence_read`**（000136 已种）：api_flow 域无该权限点，D9「零新增」以此承载，与 apiauthz 决策详情裁剪同构。
5. **KEEP_UNKNOWN 重复重申事件唯一键去重**（同实例同形态重申=同一事实），审计仍逐条在册；状态/version 均不消费。
6. **ErrVersionConflict 文案实例语境化**（该哨兵 FLOW-01/02 定义路径未使用）+ 176 契约测试 down 链随 178 加入加一步。

### 8.3 gateway 轨偏差登记（7 条，实现注释在码）

1. 体样本仅当步骤配置 body 判定式（JSONPath/GraphQL）才采集（status-codes-only 零体开销）；≤64KB 有界，超限直通外发不截断响应、判定按不命中 UNKNOWN 如实。
2. 响应采样挂点在响应脱敏/水印/签名改写**之前**（业务成功判定面向源站事实，不面向交付产物）。
3. 下游错误不细分（拨号失败/写后断连/响应头超时统一 downstreamErr → F04 UNKNOWN——网关未获得源站执行证据，宁可对账不伪造）。
4. 连接 Hijack 升级按 downstreamErr 同支处理（升级后响应脱离记录）。
5. FENCE-001 拒绝的实例**不入** INDETERMINATE（新预留持有活的事实，迟到拒绝如实记录不扩大对账面）。
6. 无判定式配置步骤恒 UNKNOWN 运行期防御分支（FLOW-01 装配校验已保证必填——双层防线，防御分支不消音）。
7. commit/202/INDETERMINATE 与 OBSERVE/PROTECT 实断解耦（违规判定已在 reserve 路径完成；确认链只产 INFO/OBSERVE 明细不定案）。

### 8.4 联调新发现与修正（联调验收批，2026-10-05）

1. **F06 设计-实现不一致（重大，需设计裁决）**：§1.1「旧版本 RETIRED 后存量实例继续按旧版本走完」与发布面「仅 ACTIVE 定义下发」（`guardconfig/strongflow.go`）不一致。stage5 实证：v6 activate v7 后（v6 RETIRED），order-f6-old（v6 下 register 已 CONFIRMED）的 pay 请求命中 v7 绑定，按 definition_version=7 实例键**另起新实例**，因新实例无 register 前置被 REJECTED FLOW-RESERVE-001（predecessor_unconfirmed，OBSERVE 放行）；v6 旧实例停留「register CONFIRMED」中途态，无法经原 ref 走完。**成立的部分**：实例行 definition_version 冻结（不换图）；新实例用新版本；终态后同主体新实例可开始。裁决路径建议：①发布面含「存量 ACTIVE 实例引用的旧版本定义」（下发育龄窗）或②修订 §1.1 该句为「RETIRED 即旧版本停止服务，存量实例经管理对账收口」——两案均需设计批回写。
2. **PG 事件唯一键碰撞（两实例，如实登记）**：`uq_strong_flow_step_event(instance_id,step_key,action,fencing_token)` 对「同 fencing 同动作不同结果」事件去重——①F05 场景 COMMIT REJECTED FENCE-001 事件 fencing_token 携带**当前 fence 读数**（=3）与 COMMIT OK（fence=3）同键，REJECTED 行 PG 缺席（网关 api-runtime-events.log 在册）；②202 受理第二条 RESERVE OK（reason_code=FLOW-ACCEPTED-202，fence=2）与首条 RESERVE OK 同键，受理 reason_code PG 缺席。建议后续批评估：FENCE-001/202 受理事件的 fencing_token 语义（如 FENCE-001 改携被拒 token 即避让碰撞）——线契约变更需设计裁决。
3. **超时语义承载层登记**：设计 §1.4「超时→UNKNOWN」在 stage5 由应用 upstream `response_header_timeout_ms`（10s）承载（504 downstreamErr 分支）；步骤 `timeout_seconds` 字段当前不下发不消费（Reservation 无该字段）——步骤级超时与传输层超时的映射关系留待 FLOW-04/后续批设计明确。F05（lease 15s 内 hold 响应）实证需临时上调 upstream 超时至 20s（用完已还原 10s）。
4. **evidence_read 双档实证口径**：自建角色经用户创建 API 拒收（「无效的角色」——角色目录缓存口径）；改为 SECURITY_ADMIN 临时摘除/恢复 `api_authorization.evidence_read` 映射完成双档实证（权限每请求实时查库无缓存，即用即生效），用完已恢复。
5. **custom-pack 回归与 stage5 回归并发跑登录竞态**（验证码/CSRF 轮换冲突致首跑 sysadmin login failed）：串行重跑 13/13 通过——非产品问题，回归脚本并发纪律登记。

### 8.5 E2E 证据摘要（stage5，2026-10-05；逐项原文见出口记录）

- **F01 完整确认流**：register `[INSTANCE_NEW,RESERVE,COMMIT OK f=1]`+step_confirmed INFO（status=200）；pay `[RESERVE,COMMIT OK,INSTANCE_CONFIRMED f=2]`+组合判定读数（rule_forms=status_codes,body_jsonpath_equals / jsonpath_path=$.status expect=ok actual=ok）；PG 实例 CONFIRMED terminated 落、事件链 6 行完整。并行组（v11 三步 g1）：settle(seq3) 先于 pay(seq2) 不违规，全链 CONFIRMED。
- **F04 超时但源站已成功**：pay 打慢端点（12s>10s 超时）→ 504；网关 `pay INSTANCE_INDETERMINATE UNKNOWN UNKNOWN-001`+step_unknown（detail=downstream_error，indeterminate_marked=true）；Valkey pay 槽保持 PENDING（**不自动 release**）；源站日志 `SLOW_PAY_EXECUTED order_id=order-f4-1`（记录型证据）；同键重试 `RESERVE UNKNOWN instance_indeterminate` 不重放成功语义；resolve CONFIRM_SUCCEEDED → CONFIRMED v=3 + INSTANCE_CONFIRMED FLOW-RESOLVE-001 事件 + HIGH 审计全值。
- **F05 迟到 fencing**：pay#1（hold 16s）reserve f=2 → lease 15s 过期 → pay#2 接管 `EXPIRE f=2 + RESERVE f=3 + COMMIT OK f=3 + INSTANCE_CONFIRMED`；pay#1 响应迟到 → `COMMIT REJECTED FENCE-001`（携带当前 fence=3 读数）不覆盖；事件链两 fencing 值在册（PG 侧 REJECTED 行因 8.4-2 碰撞缺席，网关日志在册）。
- **F06**：终态后同主体新实例正常（order-f6-new v7 完整 CONFIRMED）；版本切换实证见 8.4-1（「旧实例按旧版本走完」不成立，设计裁决待回写）。
- **allows_202**：pay → 202，`RESERVE OK FLOW-ACCEPTED-202`+step_accepted_202 INFO，实例保持 ACTIVE 不自动完成；人工 resolve CONFIRM_SUCCEEDED 收口 CONFIRMED。
- **F08**：jiuzhang_admin 详情/resolve 全 403；expected_version 失配 409 精确消息；终态重复恢复 409；KEEP_UNKNOWN 不推进（RESOLVE 留痕+HIGH 审计）；详情 INDETERMINATE 语义逐字（`UNKNOWN_NOT_CONFIRMED`+「未知，不显示安全通过」）；evidence_read 双档（无权限仅摘要四键/有权限七键全出席）。
- **F07 复验**：停 Valkey → PROTECT 定义请求（含违规形态）恒 UNKNOWN 放行+dependency_unavailable（reserve 路径），caddy.log `D8: no local fallback`；恢复+重启网关后 PROTECT 正常流恢复（热状态读回），INDETERMINATE 实例经 resolve CONFIRM_NOT_EXECUTED 收口 FAILED。
- 回归：stage5 40/40、custom-pack 13/13（串行）、server strongflow/apiruntime/guardconfig/gatewayconfig/app 全 ok、gateway dynamic_security 17 包+jiuzhang_guard 17 包 ok 无 FAIL、reconcile 700 零差集、本批 gofmt 干净。

### 8.6 联调裁决闭环（2026-10-06；§8.4-1/8.4-2 两条设计-实现不一致已裁决并修复，stage5 复验闭环）

**裁决 1（§8.4-1，F06）：采「育龄窗下发」案——发布面 ACTIVE ∪ 存在非终态实例的 RETIRED 版本。**
- server 修复：`guardconfig/strongflow.go` 查询扩为 `status='ACTIVE' OR (status='RETIRED' AND EXISTS(非终态实例 ACTIVE/INDETERMINATE))`（方法改名 `ListPublishableStrongFlows`）；线契约 `GuardStrongFlowDefinition` 增 `status` 透传；版本戳内容哈希自然覆盖；RETIRED 无非终态实例后自然掉出发布面。PG 契约 `guardconfig/strongflow_pg_test.go`（ACTIVE 恒入/DRAFT 不入/RETIRED 无实例掉出/终态实例不带回/走后自然掉出五态）。
- gateway 修复：`flowguard/definition.go` 增 `StatusRetired` 词表；`validate.go` status 词表放宽 ACTIVE|RETIRED（DRAFT 仍快照异常）；`reserve.go Reserve` 增 `allowNewInstance` 参数——Lua 原子域内判实例状态键存在性，RETIRED 版本对全新实例键 `definition_retired` 拒入（**新实例必须按 ACTIVE 版本键**），存量实例续跑正常；`evaluate.go` 按 `def.Status` 映射传参。单测/Valkey IT（`TestStrongFlowITRetiredPublishWindow`：存量续跑 OK + 新键 definition_retired + ACTIVE 对照）。
- stage5 复验（v13→v14 同名升级）：autosave `api_strong_flows` 含 v13(status=RETIRED)+v14(ACTIVE) 双版本；order-w1（v13 下 register CONFIRMED）pay 按 v13 续跑走完 `[RESERVE,COMMIT OK,INSTANCE_CONFIRMED f=2]`（实例行 v13 CONFIRMED）；新 ref order-w3 在 v13 上 `RESERVE REJECTED FLOW-RESERVE-001 definition_retired`、在 v14 上正常 INSTANCE_NEW；order-w2 v14 新实例全程 CONFIRMED。**F06 语义完整成立。**

**裁决 2（§8.4-2，事件唯一键碰撞）：fencing_token 恒为本事件自己持有的 token（REJECTED=被拒旧 token），当前 fence 读数移 evidence `fence_current`。**
- gateway 修复：commitLua/releaseLua/markAcceptedLua 的 FENCE-001 返回 token 位改携被拒 token（ARGV）、当前 fence 读数移 auxToken（`OpResult.FenceCurrent`，finalize evidence `fence_current` 承载）；**markAcceptedLua 受理即预留轮换**（INCR fence 取新 token，槽 token/lease 随新 token 刷新——202 受理 RESERVE 事件携新 token 与首 RESERVE 不再同键碰撞）；`MarkAccepted` 签名加 leaseSeconds。Valkey IT 更新（`TestStrongFlowITFenceExpiry` REJECTED 携 f=1/FenceCurrent=2；`TestStrongFlowITMarkAccepted` 轮换 token=2 + 旧 token commit FENCE-001 + 新 token commit OK）。
- server 核对：采集消费不变（按事件自 token 落库）；PG 契约 `TestStrongFlowEventTokenSemanticsPostgresContract`（F05 形态 COMMIT OK f=3 + COMMIT REJECTED f=1 双行在册；202 双 RESERVE f=2/f=3 双行含 FLOW-ACCEPTED-202 在册）。
- stage5 复验（v15 重跑 F05 时序）：PG 事件链 9 行——`pay COMMIT f=3 OK` 与 `pay COMMIT f=2 REJECTED FENCE-001` **双行在册**（碰撞消解）；网关事件 `COMMIT REJECTED FENCE-001 fence=2` + `fence_current=3` evidence。

## 9. 实现状态（FLOW-04 批，2026-10-06 联调验收批补记；本节为实施记录，不改上文契约）

**状态：FLOW-04（管理恢复与运行观测）已落地并经 stage5+Playwright 联调验收，S4 阶段关闭。** web 轨（流程基线页三 Tab 增强）+ server 指标轨（metrics 内嵌 strong_flow 段）双轨按 §5 边界实施；出口判定见 `docs/nextgen/s4/S4-FLOW04-EXIT-NOTE.md`，S4 阶段小结见 `docs/nextgen/s4/S4-EXIT-SUMMARY.md`。

### 9.1 契约映射（§1.9 → 实现位置）

| 契约 | 实现 |
|---|---|
| 页面：定义版本/状态图/允许转换/成功条件/异常策略 | web `ApiFlowBaselinesPage` 三 Tab（流程基线（观察）/强流程定义/强流程实例——与观察态并行共存互不消费）：`StrongFlowDefinitionsTab`（列表（应用/状态过滤）+新建/编辑（DRAFT 原地 PUT）/复制新草稿（同名 POST）/激活（确认弹窗 PROTECT 警示）/停用（Popconfirm）+详情抽屉（Steps 步骤序列图+成功条件 successRuleText+超时/租约/重试语义+允许转换与异常策略 Alert（UNKNOWN 恒不阻断逐字））；权限 `api_flow.manage` 控操作入口） |
| 页面：实例管理区块（列表/详情/恢复操作） | `StrongFlowInstancesTab`（列表（应用/状态/created_since 过滤）+详情抽屉（**INDETERMINATE 固定警示条「未知，不显示安全通过」逐字**+status_semantics 码+Descriptions（乐观锁版本/定义版本不换图/sfref 实例键）+步骤轨迹 Timeline（摘要档/明细档按服务端 evidence_read 裁剪如实带出，无权限提示文案）+「实例恢复记录」区块（RESOLVE/FLOW-RESOLVE-001 管理对账条目紫色 Tag）+恢复面板（三 action Radio+reason 必填 512 上限+乐观锁版本随行+409 分类提示（版本冲突/终态/其他）））；权限 read 进门、manage 控恢复面板 |
| 运行指标进既有 metrics 通道 | server `metrics/strongflow.go` 内嵌 `GET /api-security/metrics` 第 13 采集源（零新端点，权限随端点 `api_runtime.read`）：per-app labeled 序列——`strong_flow_instances{application_id,status}` 五态分桶（缺省态补 0）、`strong_flow_indeterminate_backlog/_ratio`（积压与占比）、`strong_flow_indeterminate_age_avg/max_seconds`（对账滞留=采集时刻-updated_at 的 avg/max，无积压=0）、`strong_flow_reserve_conflict_ratio`（近 24h RESERVE 动作 CONFLICT+REJECTED 占比，无样本=0 不外推）；无强流程实例整段省略（Prometheus absent，NG-T-C01 观测面零变化）；采集失败保留上一轮行集 |
| OpenAPI | `/api-security/metrics` description 补 strong_flow 段说明（schema 零变化）；reconcile 700 持平零差集 |

### 9.2 联调新发现与登记（联调验收批，2026-10-06）

1. **多 ACTIVE 定义绑定同端点时 finalize 只消费首个成功预留（产品语义登记）**：一请求一预留（`sflow.reservation` 先到先得不覆盖）——同请求命中多个绑定（多定义/多版本同端点）时仅首个预留进响应回程 commit，**其余绑定实例恒 PENDING 不可 CONFIRMED**（Playwright 场景②实证：v25 register 有 RESERVE 无 COMMIT、v8 先赢后 v25 pay 恒 predecessor_unconfirmed）。设计未冻结多绑定 commit 语义——多 ACTIVE 定义绑定同端点的 CONFIRMED 语义留待后续设计明确；本批 E2E 以「发布面单定义」编排（`retireAllE2EDefs`+settle）规避。
2. **实例键 HMAC 输入不含 definition_id（设计缝隙登记）**：§1.2 冻结实例键=应用+可信租户+可信主体+**定义版本**+实例引用——不同名定义同版本号+同引用即撞键（跨定义串实例：Valkey 热状态 24h TTL 跨轮残留时，历史同版本号定义的 CONFIRMED 键使新定义同 ref 请求 `instance_terminal` 拒入——Playwright 跨轮实证）。E2E 以每轮唯一 ref 规避；设计侧建议后续批评估实例键加入 definition_id 分量（线契约变更需裁决）。
3. **E2E 清理纪律（采集延迟+育龄窗）**：REJECTED 实例事件经网关日志→server 采集有数秒延迟，立即清理漏在途事件（延迟落库经 resolveInstance upsert 重建实例行，跨轮累积滞留育龄窗致 RETIRED PROTECT 窗内仍实断）——`cleanupStrongFlowSettled` 两遍清理夹采集窗+两遍发布（先清存量、再清在途、最终掉出发布面）；Valkey 热状态（24h TTL）不清只随版本/re ref 更迭自然过期。
4. **RETIRED PROTECT 定义育龄窗内仍按 mode 实断**（裁决 1 语义正确延伸）：场景④实证 v20（场景③ PROTECT ACTIVE）对场景④新 ref 跳步请求 BLOCK 403（predecessor_unconfirmed）——E2E 编排纪律：跨场景先 retire 旧 PROTECT+settle 再建新定义。
5. **登录限流键无 TTL 可致永久 429**（`middleware/ratelimit.go:52` 既有注释坑：计数键 PTTL=-1）——global-setup 已含 `jiuzhang:ratelimit:*` 清理纪律；排查中清键恢复。
6. **发布冒烟探针非干扰源**：探针路径固定 `/_wdsp/bot/v1/publish-smoke`（Bot 保留命名空间），不撞业务端点绑定——多版本绑定下的 INSTANCE_NEW/REJECTED 噪音实为历史残留键与多绑定语义（见 1/2），非探针所为。

### 9.3 E2E 证据摘要（stage5+Playwright，2026-10-06；逐项原文见出口记录）

- **指标冒烟**（定义 activate→正常流/判定不命中/PROTECT 违规）：`strong_flow_instances` 五态分桶 ACTIVE=1/CONFIRMED=1、积压 1→0、比率 0.333、`indeterminate_age_avg/max=25.99s`（滞留实测）、`reserve_conflict_ratio=0.333`（1/3 冲突实测）——per-app label 与五态补 0 序列逐行在册。
- **Playwright 五场景全绿（两轮稳定，chromium，`web/e2e/strong-flow-admin.spec.ts`）**：① 页面新建草稿→activate→ACTIVE→详情步骤序列图；② API 完整流→实例 CONFIRMED→详情轨迹 COMMIT OK+INSTANCE_CONFIRMED；③ PROTECT 跳步 403（源站零到达）→轨迹 REJECTED/FLOW-RESERVE-001 页面可见；④ 判定不命中→INDETERMINATE+警示条「未知，不显示安全通过」逐字→页面恢复 CONFIRM_SUCCEEDED+reason→CONFIRMED+恢复记录「管理对账」区块；⑤ jiuzhang_admin 端点三处 403+路由守卫整页「无访问权限」。
- 回归：stage5 40/40、custom-pack 13/13、server metrics/strongflow/apiruntime/app 全 ok、gateway dynamic_security 17 包+jiuzhang_guard 17 包 ok、web vitest 1045/1045+build 绿、reconcile 700 零差集、gofmt/prettier 干净。
