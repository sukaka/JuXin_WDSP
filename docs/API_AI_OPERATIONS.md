# API AI 自动运营设计（规划稿）

> **当前状态：未实现（NOT_IMPLEMENTED）**。
> 本文档是 API 安全能力补全（对应《WDSP_API_SECURITY_COMPLETION_PLAN》§233，下称"补全任务书"）要求的
> **设计规划稿**，描述 AI 自动运营能力的目标架构与落地方案。
>
> 现状口径（以代码为准，详见 `docs/API_SECURITY_CURRENT_STATE.md` §3 P1-02、§6.6）：
> - **已实现**：阶段7 AI 编排器/Agent/证据引用/审计/配额全链路，阶段8 API 域
>   **10 个 READ_ONLY Tool**（`server/internal/aitools/api_tools.go`）闭环；
> - **未实现**：AI 自动运营任务、AI 定时任务（`ai*` 各包无 Ticker/cron）、
>   AI 分类推荐写入方（`source='AI'` 全库零命中）、补全任务书 §146 清单中的
>   多个 API 域 Tool（`api_weakness.search` / `api_runtime_policy.get` / `api_spec.get/diff` /
>   `api_sensitive.search` / `api_audit.search` / `api_scan.get` 等）。
>
> 本文档所有"拟新增"内容均不存在于当前代码，不得作为功能已完成的依据；
> 引用既有代码处均给出真实路径。

## 一、目的与范围

### 1.1 定位

AI 自动运营是把阶段7 已验证的"人机对话式 AI 分析"延伸为**面向 API 安全域的
例行化、批量化运营能力**：定时巡检资产/模型/风险/学习健康度，产出摘要、建议与草稿，
把运营人员从重复翻阅中解放出来。

定位纪律（红线先行，详见 §八）：

- AI 的产出上限是**建议与草稿**——确认、发布、封禁、关停永远是人工动作
  （阶段8 任务书 §48"AI 不得"清单、补全任务书禁止事项 #13/#14）；
- 自动运营**不是**自治运营：所有批处理产物的终点是"待人工处理的工作台"，
  不是生产配置；
- 与防护内核解耦：AI 链路任何故障不影响 WAF/API 防护与发布链路
  （阶段7 编排器既有原则延续）。

### 1.2 范围

覆盖：API 域 Tool 增补规划、运营工作流（Workflows）、定时任务（Schedules）、
人工审批衔接（Human Approval）、安全边界（Safety Boundaries）。
不覆盖：模型训练/微调、LLM 网关自身选型（见 `docs/AI_MODEL_GATEWAY.md`）、
WAF 域既有对话式能力（见 `docs/AI_ORCHESTRATOR_DESIGN.md` / `docs/AI_TOOL_DESIGN.md`）。

## 二、现状基础（已实现，设计直接依赖）

| 能力 | 位置 | 要点 |
|------|------|------|
| Tool 注册中心 | `server/internal/aitools/registry.go` | 统一契约；Execute 管线固定顺序：查找→启停（实时查 `ai_tools.status`）→权限（每次以调用者真实权限点重查，不缓存）→超时→审计；风险等级仅 `READ_ONLY`/`DRAFT_ONLY` 两级开放注册 |
| API 域 Tool ×10 | `server/internal/aitools/api_tools.go` | 全部 READ_ONLY：`api_asset.search` / `api_asset.get` / `api_model.get` / `api_model.diff` / `api_parameter.get` / `api_graph.query` / `api_runtime.statistics` / `api_risk.search` / `api_learning.status` / `api_classification.explain`；入参枚举白名单校验，`api_risk.search` 输出经 `audits.MaskSensitiveJSON` 脱敏 |
| 阶段7 Tool ×45 | `aitools/event_tools.go`（5）、`noise_tools.go`（2）、`log_tools.go`（7）、`asset_tools.go`（14）、`access_tools.go`（12）、`draft_tools.go`（5） | 其中草稿类 5 个为 `DRAFT_ONLY` |
| 草稿 Tool 纪律 | `server/internal/aitools/draft_tools.go` | 草稿一律默认 DRAFT/停用、`[AI草稿]` 前缀、记录来源任务与证据；创建走与人机相同的 `ValidateInput`/`Store.Create` 路径，AI 侧无"接受/发布/直接生效"路径 |
| 编排器 | `server/internal/aiorchestrator/` | 意图分类为确定性正则（`intent.go`，12 类 TaskType）；Plan 摘要可展示；Agent 调度上限 `MaxAgents=4`、`MaxToolCalls=20`、`MaxDuration=120s`、token 上限 12000/4096；事实确定性优先、证据引用 `[En]` 校验；LLM 仅受约束润色且可降级 |
| 专业 Agent ×7 | `server/internal/aiagents/` | `security_event` / `waf_policy` / `log_analysis` / `asset` / `ops_diagnostic` / `report` / `knowledge` |
| AI 审计 | `server/internal/aiaudit/aiaudit.go` | Tool 调用全留痕（状态/耗时/入参摘要/错误码），入参摘要截断脱敏 |
| 成本与配额 | `server/internal/aicost/aicost.go` | `CheckQuota` 请求前预估拦截（超限 429）、`RecordUsage` 落账、`Overview` 总览 |
| 推荐落库 | `ai_recommendations`（迁移 000013） | DRAFT 状态、证据引用、`created_by_ai=TRUE` |
| 周期任务模板 | `server/internal/learningjobs/janitor.go` | `SweepOnce`（可独立单测）+ `Run`（ticker）+ settings 读取间隔与阈值——Schedules 的直接结构模板 |
| 弱点/敏感周期派生 | `server/internal/apiweakness/sweep.go`、`server/internal/apidata`（SweepOnce） | 证明"周期派生 + 人工流转"模式已在 API 域落地 |

**关键现状事实**：以上全部为"人在环中"形态——没有任何一个包含定时器驱动的
AI 任务；`ai_classification_dimensions.source='AI'` 词表值存在但无写入方。
本文档的 Schedules/Workflows 就是要补这一层，且必须保持"人工确认收口"不变。

## 三、总体架构（规划）

```text
触发源
  ├─ 人机对话（已实现：POST /api/v1/ai/sessions/{id}/messages）
  ├─ 运营工作台手动触发（规划：POST /api/v1/api-security/ai-ops/run）
  └─ 定时调度器（规划：apiaijobs janitor，SweepOnce + ticker）
        │
        ▼
工作流定义（Workflow，确定性编排脚本，见 §五）
  步骤 = Tool 调用 / 纯函数加工 / LLM 受约束总结（可降级）
        │
        ▼
Tool 执行 ── 统一走 aitools.Registry.Execute（权限/启停/超时/审计不变）
        │
        ▼
产物（三选一，全部不直接生效）
  ├─ 运营摘要/报告（ai_ops_reports，只读展示）
  ├─ 推荐（ai_recommendations DRAFT，人工采纳路径已实现）
  └─ 业务草稿（DRAFT_ONLY Tool，默认停用，走既有人工审核发布）
        │
        ▼
人工审批（Human Approval，§七）→ 既有人工确认/发布流程（不改一字）
```

设计要点：

- **复用不重建**：调度结构抄 `learningjobs` janitor；执行走既有 Registry；
  审批走既有草稿/确认/发布链路；审计走既有 aiaudit + audits 哈希链；
- **确定性优先**：工作流步骤、触发条件、产物模板全部是代码与配置，
  LLM 只做语言润色（与编排器"事实确定性优先"原则一致）；LLM 不可用时
  工作流照样产出事实性摘要（降级而非失败）；
- **自动化的终点是工作台**：所有产物进"待处理"队列，由持相应权限点的人处置。

## 四、工具体系（Tools）

### 4.1 分层与现状

```text
已实现                                规划增补（依赖后端能力就绪）
─────────────────────────────       ─────────────────────────────
API 域 READ_ONLY ×10（api_tools.go）  api_weakness.search      ← apiweakness（已实现，可直接补）
WAF/运维域 READ_ONLY ×40              api_sensitive.search     ← apidata（已实现，可直接补）
草稿 DRAFT_ONLY ×5                    api_runtime_policy.get   ← apimodels runtime_policy（已实现，可直接补）
                                      api_spec.get / api_spec.diff   ← apisecurity spec（已实现，可直接补）
                                      api_audit.search         ← audits 导出/查询（需只读适配）
                                      api_scan.get / api_scan.findings ← 主动扫描（未实现，依赖扫描分片）
                                      api_posture.get          ← GetPosture（已实现，可直接补）
```

### 4.2 增补 Tool 登记纪律（规划）

1. **风险等级封顶**：API 域新增 Tool 只允许 `READ_ONLY`；确需产出业务对象时
   走 `DRAFT_ONLY` 草稿模式（复用 draft_tools 纪律：默认停用 + `[AI草稿]` 前缀 +
   同人校验路径）；`REQUIRES_CONFIRMATION`/`PROHIBITED` 两级维持不开放注册；
2. **权限点一一对应**：每个 Tool 声明独立权限点（如 `api_weakness.read`），
   执行前由 Registry 以调用者真实权限重查——定时任务场景以"任务属主"的权限
   构造 Principal（见 §6.3 权限衰减规则）；
3. **入参白名单**：枚举入参一律词表校验（api_tools.go 既有模式），拒绝即
   `ErrInvalidInput` 并落审计；
4. **输出脱敏**：凡可能含主体/证据信息的输出经 `audits.MaskSensitiveJSON` 或
   同标准处理；参数原始值、完整凭据永不进入 Tool 输出；
5. **注册即同步**：代码 registry 经 `SyncRegistry` upsert 进 `ai_tools` 表，
   管理面可停用，停用立即生效（既有机制，新增 Tool 自动继承）。

## 五、运营工作流（Workflows）

### 5.1 工作流定义（规划）

工作流 = 命名的确定性编排单元：`trigger × steps × product × template`。
步骤只由三类原语组成：

| 原语 | 说明 | 例 |
|------|------|----|
| `tool_call` | 经 Registry.Execute 调 Tool（权限/审计全继承） | `api_risk.search(status=OPEN)` |
| `transform` | 纯函数加工（聚合/排序/阈值判定/模板渲染），不触库不触网 | 按 severity 分桶计数 |
| `llm_summarize` | LLM 受约束总结（可选，超时/失败即降级为纯事实文本） | 生成一段中文运营摘要 |

### 5.2 首批工作流清单（规划）

对应阶段8 任务书 §48"AI 可以"清单的批处理化：

| 工作流 | 触发 | 步骤概要 | 产物 |
|--------|------|----------|------|
| `asset_digest` 资产运营摘要 | 定时/手动 | `api_asset.search`（DISCOVERED 未确认）+ `api_classification.explain` 抽样 → 分桶 → 摘要 | 运营报告：新增/未确认/Shadow 线索清单 |
| `model_review_advice` 模型确认建议 | 定时/手动 | `api_learning.status` + `api_model.get/diff`（IN_REVIEW 候选）→ 差异解读 → 建议文本 | `ai_recommendations` DRAFT（建议确认/退回，附证据）；**确认动作人工** |
| `risk_triage` 风险研判分流 | 定时 | `api_risk.search(OPEN)` → 按 finding_type/severity 聚合 → 关联 `api_runtime.statistics` | 运营报告 + 高优先 findings 清单（不自动流转状态） |
| `weakness_nudge` 弱点整改提醒 | 定时 | `api_weakness.search`（规划 Tool；NEW/TO_FIX 超期）→ 负责人分桶 | 提醒摘要（对接既有通知渠道前先进工作台） |
| `learning_health` 学习健康巡检 | 定时 | `api_learning.status` 批量 + 失败/超期任务筛出 | 运营报告：停滞任务、样本异常API |
| `posture_daily` API 态势日报 | 定时 | `api_posture.get`（规划）+ `api_runtime.statistics` → 模板渲染 | 日报（复用阶段7 report Agent 模板纪律） |
| `shadow_zombie_brief` 影子/僵尸简报 | 定时/手动 | `api_risk.search(SHADOW/ZOMBIE)` → 摘要 | 简报（阶段8 任务书 §48"总结 Shadow 和 Zombie API"） |

纪律：工作流清单是**代码内注册表**（同 Tool registry 模式），不是自由文本
提示词；新增工作流必须带单测（transform 纯函数可测、tool_call 以 fake
Registry 断言调用序列）。

### 5.3 与对话式编排的关系

工作流与既有 Orchestrator 并存：对话入口（12 类 TaskType）处理即兴分析；
工作流处理例行批量。二者共享同一 Registry/审计/配额，但工作流**不经过
意图分类**——它本身就是确定性计划，避免把定时批量任务交给正则命中。

## 六、定时任务（Schedules）

### 6.1 调度器（规划）

拟新增包 `server/internal/apiaijobs/`，结构逐项对齐 `learningjobs` janitor：

```text
Sweeper.SweepOnce(ctx)        // 取一个到期 ENABLED 计划执行一轮，可独立单测
Sweeper.Run(ctx)              // ticker 周期驱动，间隔经 settings 读取（默认 60s 检查）
```

拟新增表 `api_ai_schedules`（规划）：

| 列 | 说明 |
|----|------|
| `id` / `workflow` | 计划与所触发工作流（§5.2 注册表词表校验） |
| `cron_expr` 或 `interval_seconds` | 调度周期（二选一；实现期择一从简） |
| `owner_id` | 任务属主（执行 Principal 来源，见 §6.3） |
| `params_json` | 工作流入参（时间窗/过滤条件，词表校验） |
| `status` | `ENABLED` / `DISABLED`（停用立即生效，下轮不再触发） |
| `last_run_at` / `last_status` / `last_error` | 执行轨迹（失败原因落列，不静默吞错） |
| `next_run_at` | 到期游标（SweepOnce 选取依据，防重入） |

执行记录拟新增表 `api_ai_schedule_runs`（规划）：每次触发的状态、耗时、
产物引用（report_id/recommendation_ids）、Tool 调用计数、token 用量——
与 `ai_tool_calls` 审计互补：一个回答"做了什么"，一个回答"花了多少"。

### 6.2 成本与熔断（规划）

- 每计划独立配额：单次运行 `MaxToolCalls` / token 上限（默认沿用
  `DefaultLimits` 量级，经 settings 可调）；`aicost.CheckQuota` 对属主账号
  照常生效，**定时任务不享受配额豁免**；
- 熔断：同一计划连续 N 次失败（默认 3）自动置 `DISABLED` 并写审计 +
  系统告警（复用 `systemalerts` 通道），防止故障计划空转烧钱；
- 全局开关：`api_ai_schedules.enabled`（settings，默认关）+ 产品形态开关
  `API_DYNAMIC_PROTECTION_ENABLED` 双重门控。

### 6.3 定时任务的权限模型（规划）

定时触发没有在线用户，权限不能"借用系统身份裸奔"：

- 执行 Principal = 计划属主（`owner_id`）的**实时权限快照**——每轮执行前
  重新读取该用户当前权限点，用户被降权/禁用后计划自动失去相应 Tool 能力
  （体现为 DENIED 审计，而非悄悄成功）；
- 属主离职/禁用 → 计划在下一轮置 `DISABLED` + 审计 + 告警，不产生孤儿任务；
- 计划可触达的 Tool 集合 = 工作流声明 ∩ 属主持有权限点，双重收敛。

## 七、人工审批（Human Approval）

### 7.1 收口原则

AI 一切产出物进入**既有人工流程**，本设计不新增任何"AI 直通生效"路径：

```text
AI 产物                                  人工收口（全部为既有能力）
─────────────────────────────           ─────────────────────────────
模型确认建议（recommendation DRAFT）  →   模型评审页人工确认/退回（apimodels Confirm/SubmitReview）
策略/例外/黑名单草稿（DRAFT_ONLY）    →   草稿默认停用 → 人工审核启用 → 既有发布通道
分类/用途解释（报告文本）             →   人工分类 PUT（classification_locked 保护，AUTO/AI 不得覆盖）
弱点整改提醒                          →   弱点中心人工流转（apiweakness 状态机）
扫描复测建议（依赖扫描分片）           →   人工发起复测（扫描授权模型约束）
```

### 7.2 推荐状态机（规划，在既有 `ai_recommendations` 上扩展）

现状：`RecordRecommendation` 写入即 `DRAFT`（draft_store.go）。
规划补齐流转接口：`DRAFT → ADOPTED（人工采纳，跳转到对应人工操作）/
DISMISSED（人工驳回，需填原因）`，流转写操作审计；**ADOPTED 不等于生效**——
采纳只是把人带到对应业务操作页，生效仍走该业务既有的确认/发布路径。

### 7.3 审批留痕

- 每条 AI 产物携带证据引用（`evidence_references`，`[En]` 机制）与来源
  计划/任务 ID，审计可完整回放"AI 依据什么数据得出该建议"；
- 人工处置（采纳/驳回/确认/发布）进既有操作审计哈希链，与 AI 审计互补成链；
- 前端展示纪律：AI 产物一律带"AI 生成"标识（沿用 `[AI草稿]` 前缀与
  `created_by_ai` 标记），不得与人工作品混排无标。

## 八、安全边界（Safety Boundaries）

### 8.1 AI 不得清单（硬约束，与任务书逐条对应）

对应阶段8 任务书 §48 与补全任务书禁止事项 #13/#14/#15/#16，以下行为
**在任何入口（对话/工作流/定时任务）都被结构性禁止**——不是提示词约束，
而是没有代码路径：

| 禁止项 | 结构性保障 |
|--------|-----------|
| 自动确认/冻结模型 | `apimodels` Confirm/Activate 仅挂人工 HTTP 路由，无 Tool 注册 |
| 自动发布策略/配置 | 发布通道（`guardconfig`→Publisher）无 Tool 触达；草稿默认停用 |
| 自动修改分类/用途 | `classification_locked` 人工锁；`source='AI'` 仅允许低置信标签建议，落库走人工接口 |
| 自动关闭/下线 API | 资产生命周期接口无 Tool 注册 |
| 自动封禁身份/IP | 封禁/黑名单仅有 DRAFT_ONLY 草稿 Tool |
| 自动认定 BOLA/BFLA 结论 | 检测侧纪律为"辅助信号不直接认定"（detectors/resource.go），AI 侧只做疑似分析 |
| 自动处置风险/弱点状态 | findings/weakness 流转接口无 Tool 注册 |
| 保存/输出完整凭据与敏感原值 | 身份仅存 HMAC 指纹；Tool 输出脱敏；审计入参截断脱敏 |
| 无人工确认自动推断字段权限 | 字段权限能力本身未实现（P0-17），AI 无从驱动 |

### 8.2 运行时防线（已实现 + 规划继承）

1. **权限每次重查**（已实现：Registry.Execute 执行前 `HasPermission`，
   不缓存、不委托模型判断）；定时任务叠加 §6.3 属主权限衰减；
2. **Tool 启停实时生效**（已实现：`ai_tools.status` 每轮查库）；
3. **审计全覆盖**（已实现：aiaudit 记录每次调用；规划扩展：计划触发/熔断/
   禁用同样写审计）；
4. **成本熔断**（规划：§6.2 连续失败熔断 + 配额不豁免）；
5. **提示注入防护**（规划）：工作流 `transform` 步骤把 Tool 输出当**数据**处理，
   拼入 LLM 的内容经模板槽位隔离；LLM 输出只用于展示文本，不作为任何
   后续 Tool 入参来源（防"数据→指令"越权转换）；证据引用经 `ValidateCitations`
   校验（已实现）；
6. **降级纪律**（已实现模式继承）：LLM 超时/失败 → 省略润色输出事实文本；
   编排落库失败不阻断；AI 全链路故障零影响防护与发布；
7. **不存储私有思维链**（已实现原则继承）：计划与产物可展示，推理过程不落库。

### 8.3 监控（规划）

- `runtimehealth` 增补 AI 运营探针：调度器存活、最近一轮 SweepOnce 结果、
  熔断中计划数（现状盘点 §6.6 指出 AI 服务探针缺失，本分片一并规划）；
- 指标（规划，对齐补全任务书 §158/§159 口径）：计划执行次数/失败率、
  Tool 调用量按 code 分布、token 用量与成本、产物采纳率（ADOPTED/(ADOPTED+DISMISSED)）。

## 九、实施分期建议（规划）

| 期 | 内容 | 依赖 |
|----|------|------|
| A1 | Tool 增补第一批：`api_weakness.search` / `api_sensitive.search` / `api_runtime_policy.get` / `api_spec.get` / `api_posture.get`（后端均已实现，纯 Tool 层）+ 注册同步 + 单测 | 无 |
| A2 | 工作流框架（注册表 + 三类原语 + 降级）+ 首批 3 个工作流（asset_digest / risk_triage / learning_health）+ 运营报告表 | A1 |
| A3 | `apiaijobs` 调度器（SweepOnce/Run + 两表 + 熔断 + 属主权限模型） | A2 |
| A4 | `ai_recommendations` 流转接口（ADOPTED/DISMISSED）+ 前端运营工作台（报告列表/建议处置/计划管理） | A2/A3 |
| A5 | 监控探针与指标、E2E（计划→执行→产物→人工采纳链路）、OpenAPI 收录 | A3/A4 |
| A6 | Tool 增补第二批（`api_audit.search` 只读适配、`api_scan.*`） | 扫描分片落地后 |

每期验收底线：Tool 单测（权限拒绝/词表校验/超时/审计断言）；工作流单测
（fake Registry 断言调用序列 + transform 纯函数矩阵）；调度器单测
（SweepOnce 各分支：到期/未到期/熔断/属主失权）；不得为通过测试删除权限
校验、参数校验、审计与脱敏（AGENTS.md 安全底线）。

## 十、明确不做（与任务书口径一致）

- 不做 AI 自动确认模型、自动发布、自动修改用途、自动关闭 API、自动封禁身份
  （阶段8 任务书 §48"AI 不得"清单全量继承）；
- 不做 AI 自动认定入侵成功 / BOLA / BFLA（任务书验收红线）；
- 不做自由文本驱动的定时任务（工作流必须代码注册、可测试、可审计）；
- 不做"系统超级身份"执行定时任务（属主权限实时快照，失权即失效）；
- 不引入新第三方依赖（调度器/工作流全部基于现有 go.mod 能力）；
- 不以 Mock 数据冒充运营产物（产物必须可回放证据链）。

---

*本文档为规划稿，描述目标设计而非现状；实施完成后应更新
`docs/API_SECURITY_CURRENT_STATE.md` P1-02 与 §6.6 状态列。*
