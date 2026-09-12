# AI 编排器设计（阶段7）

本文档描述九章 WAF V2.0 AI 安全运营中心的编排器（AI Orchestrator）设计，与实现代码严格一致：

- 编排器核心：`server/internal/aiorchestrator/`（`orchestrator.go` 调度主循环、`intent.go` 意图分类、`evidence.go` 证据聚合与引用校验、`session.go` 会话与消息持久化、`task_store.go` 任务落库、`context.go` 上下文预算与压缩）
- 接口层（SSE 流式输出、配额、审计、落库）：`server/internal/aihandlers/chat_handler.go`、`handler.go`
- Agent 实现：`server/internal/aiagents/`（7 个专业 Agent）
- 装配：`server/internal/app/app.go`；表结构：迁移 `000013_stage7.up.sql`

## 1. 设计目标与原则

编排器负责一轮对话的完整生命周期：意图识别、任务计划（Plan）、Agent 调度、证据聚合、引用校验、最终回答生成、任务落库与降级。设计遵循四条底线（对应任务书 `docs/tasks/STAGE_7_AI_SECURITY_OPERATIONS.md` 第五节）：

1. **事实确定性优先**：回答主体是 Tool/数据库产出的确定性事实文本，所有事实必须带证据编号（`[E1]`…`[En]`），证据不足时明确输出「当前数据不足，无法确认。」，不得把推测写成事实；
2. **LLM 最小化使用**：意图分类、Plan 生成、ID 提取、引用校验、上下文压缩全部是确定性规则代码；LLM 只在事实之前加一段受约束的语言总结，失败即省略（降级）；
3. **与防护内核解耦**：编排器落库失败只记日志不阻断主流程；AI 模块异常不影响 WAF 防护链路；
4. **不保存私有思维链**：前端只展示 Plan 摘要（任务类型 + 调度 Agent + 风险等级），不产出、不存储模型思维链。

## 2. 一轮对话的总体流程

```text
POST /api/v1/ai/sessions/{id}/messages（权限 ai.chat.use，属主隔离）
        │
        ▼
chat_handler.runStream
  配额检查（EstimateTokens(content)+512，超限 429）→ 用户消息落库 → SSE 响应头
        │
        ▼
Orchestrator.Run（ctx 带 MaxDuration=120s 超时）
  ① Classify(message) → Plan（确定性规则）
  ② ai_tasks 落库（RUNNING；失败仅告警不阻断）
  ③ emit plan 事件
  ④ 加载上下文：会话 ContextSummary + 最近 10 条消息
  ⑤ Agent 调度循环（MaxAgents=4，启停校验，失败降级 PARTIAL_SUCCESS 继续）
  ⑥ 组装事实文本 → composeAnswer（LLM 受约束总结，可降级）
  ⑦ ValidateCitations 引用校验 → 追加证据块 → emit answer 事件
  ⑧ ctx 取消（停止/断连/超时）→ 任务置 CANCELLED
        │
        ▼
defer 回写 ai_tasks 结束状态（独立 5s 超时上下文，客户端断连不丢记录）
        │
        ▼
chat_handler：assistant 消息落库（独立 10s ctx）→ 用量记录 →
  MaybeCompress（超阈值自动压缩，发 compressed 事件）→ AI 审计 → emit done 事件
```

## 3. 确定性意图分类（intent.go）

### 3.1 设计理由

意图分类不使用 LLM。默认模型为本地 Ollama 部署的 `qwen2.5:3b`（`aihandlers/handler.go` 中 `defaultModelCode`），3B 量级小模型在分类、决策类任务上输出不稳定、难以约束；而安全运营场景要求分类结果**可测试、可复现、可审计**。因此 `Classify` 采用按优先级排序的正则规则表，纯函数、无 IO 依赖。

### 3.2 TaskType 全集（12 类）

| TaskType 常量 | 值 | 中文名 | 风险等级 |
|---------------|-----|--------|----------|
| `TaskEventAnalysis` | `EVENT_ANALYSIS` | 安全事件分析 | LOW |
| `TaskFalsePositive` | `FALSE_POSITIVE_ANALYSIS` | 误报研判 | MEDIUM |
| `TaskRuleExplanation` | `RULE_EXPLANATION` | 规则解释 | LOW |
| `TaskAttackProfile` | `ATTACK_PROFILE` | 攻击画像 | LOW |
| `TaskAttackChain` | `ATTACK_CHAIN` | 攻击链关联 | LOW |
| `TaskRootCause` | `ROOT_CAUSE_ANALYSIS` | 根因分析 | LOW |
| `TaskLogQuery` | `LOG_QUERY` | 日志查询 | LOW |
| `TaskStatistics` | `STATISTICS_QUERY` | 统计问答 | LOW |
| `TaskPolicyRec` | `POLICY_RECOMMENDATION` | 策略优化建议 | MEDIUM |
| `TaskWhatIf` | `WHAT_IF_ANALYSIS` | What-If 策略模拟 | MEDIUM |
| `TaskReportSummary` | `REPORT_SUMMARY` | 报告总结 | LOW |
| `TaskGeneralQA` | `GENERAL_SECURITY_QA` | 通用安全问答 | LOW |

风险等级由 `riskOf` 决定：误报研判、策略优化建议、What-If 模拟三类涉及策略变更语义，判 `MEDIUM`，其余 `LOW`。任务书还枚举了 `DRAFT_*` 四类草稿任务；当前实现中草稿能力由草稿类 Tool（`aitools.NewDraftTools`）承担，不作为编排器独立 TaskType。

### 3.3 规则表（按优先级排序，先匹配先得）

`Classify` 先将消息转小写，再逐条匹配 `intentRules`：

| # | 匹配模式（摘要） | TaskType | 调度 Agent |
|---|------------------|----------|------------|
| 1 | `误报`、`false positive` | FALSE_POSITIVE_ANALYSIS | waf_policy, security_event |
| 2 | `规则…(解释/什么意思/干什么/用途)`、6~7 位数字…(规则/解释) | RULE_EXPLANATION | waf_policy, knowledge |
| 3 | `攻击链`、`攻击过程`、`入侵过程`、`chain` | ATTACK_CHAIN | security_event, log_analysis |
| 4 | `为什么…(延迟/失败/异常/升高/不足/错误/慢/积压/崩溃)`、`根因`、`root cause`、`怎么回事`、`排查` | ROOT_CAUSE_ANALYSIS | ops_diagnostic, log_analysis |
| 5 | `画像`、`谁在攻击`、`哪个ip`、`来源`、`攻击者` | ATTACK_PROFILE | security_event, log_analysis |
| 6 | `误杀`、`误拦`、`误阻断` | FALSE_POSITIVE_ANALYSIS | waf_policy, security_event |
| 7 | `事件…分析`、`分析…事件`、`这条事件`、`这个事件`、`分析一下` | EVENT_ANALYSIS | security_event |
| 8 | `策略…(建议/优化/调整/推荐)`、`优化…策略`、`调优`、`建议…规则` | POLICY_RECOMMENDATION | waf_policy |
| 9 | `what if`、`如果…(关掉/关闭/启用/改成/切换/调整)`、`模拟`、`假设` | WHAT_IF_ANALYSIS | waf_policy |
| 10 | `(日报/周报/月报/总结/汇总)` 与 `(安全/攻击/运营)` 组合 | REPORT_SUMMARY | report |
| 11 | `日志`、`log`、`查询…请求`、`请求…记录` | LOG_QUERY | log_analysis |
| 12 | `统计`、`趋势`、`排行`、`top`、`多少`、`数量`、`分布` | STATISTICS_QUERY | security_event, log_analysis |

两级兜底：

- 规则全部未命中，但消息含 UUID 前缀（`[0-9a-f]{8}-[0-9a-f]{4}`）或 6~7 位数字 → `EVENT_ANALYSIS`（security_event），LOW，说明「识别到事件/规则标识，执行安全事件分析」；
- 否则 → `GENERAL_SECURITY_QA`（knowledge, security_event），LOW。

### 3.4 ID 提取（ExtractIDs）

`ExtractIDs` 从原始消息中提取三类结构化标识，供各 Agent 的 `AnalyzeInput` 使用，每类最多 5 个：

- **eventIDs**：完整 UUID（8-4-4-4-12 段）；
- **ruleIDs**：`91/92/93/94/95/96` 开头的 6 位、或 `7100/8000` 开头的 7 位规则号，转整数；
- **ips**：IPv4 点分四段，逐段校验 ≤255，非法地址丢弃。

## 4. Plan 生成

`Classify` 输出 `Plan`，是前端可展示的任务计划摘要（非思维链）：

| 字段 | 类型 | 说明 |
|------|------|------|
| `task_type` | TaskType | 见 3.2 |
| `agents` | []string | 待调度 Agent code 列表 |
| `risk_level` | string | LOW / MEDIUM |
| `summary` | string | `summaryOf` 生成，格式「{中文名}（调度: agent1, agent2）」 |

Plan 同时作为 `plan` SSE 事件的 payload 推送前端，并以 `plan_summary` 字段随任务落库（`ai_tasks`），满足任务书「前端可展示计划摘要，但不得展示模型私有思维链」的要求。

## 5. Agent 调度循环

### 5.1 Agent 接口与注册

```go
type Agent interface {
    Code() string
    Analyze(ctx context.Context, in *AnalyzeInput) (*AnalyzeResult, error)
}
```

`AnalyzeResult` 含 `FactsText`（确定性事实文本，内嵌 `[Ex]` 引用标记）与 `Facts`（结构化事实，前端渲染用）。`AnalyzeInput` 携带 Principal（用户身份与权限集）、TaskID/SessionID、TaskType、原始消息、提取的 eventIDs/ruleIDs/IPs、ToolContext（带审计的 Tool 调用入口）、共享 EvidenceSet 与 `LLMCompose` 回调。

`app.go` 启动时注册 7 个专业 Agent：

| code | 展示名 | 实现 |
|------|--------|------|
| `security_event` | 安全事件 Agent | `aiagents.NewSecurityEventAgent` |
| `log_analysis` | 日志分析 Agent | `aiagents.NewLogAnalysisAgent` |
| `waf_policy` | WAF策略 Agent | `aiagents.NewWafPolicyAgent` |
| `asset` | 资产 Agent | `aiagents.NewAssetAgent` |
| `ops_diagnostic` | 运维诊断 Agent | `aiagents.NewOpsDiagnosticAgent` |
| `report` | 报告 Agent | `aiagents.NewReportAgent` |
| `knowledge` | 知识库 Agent | `aiagents.NewKnowledgeAgent` |

总调度（`dispatcher`）不注册为独立 Agent，由编排器内置承担（`app.go` 注释「注册 7 个专业 Agent（总调度由编排器内置承担）」）；`agentLabel` 中保留其展示名映射。

### 5.2 调度循环（Run 第 3 步）

按 `plan.Agents` 顺序逐个调度：

1. **MaxAgents 上限**：已调度数达到 `MaxAgents`（默认 4）即 `break`，剩余 Agent 不再执行；
2. **未注册跳过**：`o.agents[code]` 不存在直接 `continue`（不发事件）；
3. **启停校验（停用跳过）**：`agentEnabled` 回调（启动时由 `SetAgentEnabledChecker` 注入，查 `ai_agents` 表 `status='ENABLED'`）返回 false 时，发出 `agent_done` 事件「{Agent} 已停用，跳过」并继续；`dispatcher` 恒启用；DB 查询异常时默认放行（视为启用）；
4. **执行**：发 `agent_start` 事件 → 调用 `Analyze` → 非空 `FactsText` 追加到事实列表 → 发 `agent_done` 事件「{Agent} 完成」；
5. **失败降级**：单个 Agent 返回错误时，任务状态降级为 `PARTIAL_SUCCESS`，发 `error` 事件「{Agent} 执行失败: …」，继续调度后续 Agent——已获得的证据不丢弃。

所有 Agent 共享同一个 `EvidenceSet`，Agent 内每次 Tool 调用成功后用 `Evidence.Add(toolCode, 摘要, 结果)` 登记证据并获得编号（见第 6 节）。

### 5.3 执行限制（TaskLimits）

| 限制项 | 默认值 | 强制方式 |
|--------|--------|----------|
| `MaxAgents` | 4 | 调度循环计数 `break`（强制） |
| `MaxDuration` | 120s | `Run` 入口 `context.WithTimeout`，超时后 ctx 取消、任务置 CANCELLED（强制） |
| `MaxToolCalls` | 20 | 预留字段，当前编排循环未强制 |
| `MaxInputTokens` | 12000 | 预留字段，当前编排循环未强制 |
| `MaxOutputTokens` | 4096 | 预留字段，当前编排循环未强制 |

预留字段对应任务书 8.4「执行限制」的完整集合；当前版本输入侧由消息长度（≤4000 字）、`MaxDuration` 与 LLM 调用参数（`MaxTokens=1024`）实际控制。超限时按任务书要求「停止并返回已经完成的结果」：超时/停止不中断已得事实的输出，任务落库为 `CANCELLED`。

## 6. 证据聚合与 [Ex] 引用校验（evidence.go）

### 6.1 证据模型

| 字段 | 说明 |
|------|------|
| `id` | 引用编号 `E1..En`，`EvidenceSet.Add` 按追加顺序生成 |
| `source` | 来源（Tool code / 查询描述） |
| `summary` | 一句话摘要 |
| `detail` | 结构化明细（可选，Tool 原始结果） |

`EvidenceSet` 提供 `Add / Items / ContainsID / Count / ValidateCitations / ComposeEvidenceBlock`；`Items` 返回副本。证据随 `RunResult.Evidence` 返回给接口层。

### 6.2 引用格式与校验

回答中的引用标注形如 `[E1]`、`[E1,E2]`（分隔符支持 `,`，`、`），由正则 `\[((?:E\d+)(?:\s*[,，、]\s*E\d+)*)\]` 识别。

`ValidateCitations(answer)` 在回答发出前逐处校验：

- 引用编号存在于证据集 → 保留；同处多个有效编号按字典序重排；
- 引用编号不存在 → 从标注中剔除；若该处标注全部无效则整体移除标注（**只移除标注符号，不删除正文内容**）；
- 返回清理后回答与无效引用列表 `invalid`；
- 存在无效引用时，回答尾部追加不确定性声明：「> 说明：回答中部分引用未能对应到本次查询证据，请以证据列表为准。」

这是对小模型幻觉引用的兜底：即使 LLM 总结段编造了 `[E99]`，也会在发出前被剥除并显式告知用户。无效引用列表同时经 `RunResult.InvalidCites` 返回。

### 6.3 证据块

`ComposeEvidenceBlock` 生成回答尾部的证据列表（无证据时为空串）：

```text
**证据引用**
- [E1] get_security_event：事件 ...（摘要）
- [E2] query_access_logs：...
```

## 7. 回答组装与 LLM 受约束总结（降级）

### 7.1 组装顺序（composeAnswer）

回答主体是**事实优先**的拼接：

```text
[LLM 引导性总结]（可选，成功时才有）
{确定性事实文本（含 [Ex] 引用；多 Agent 事实以空行分隔）}
[无效引用不确定性声明]（有无效引用时）
[证据引用块]（有证据时）
```

事实为空时统一替换为降级文案「当前数据不足，无法确认。」（对应任务书 5.2 的证据不足声明）。组装完成后经 `ValidateCitations` 清理，再拼接证据块，以 `answer` 事件发出（payload 含 `evidence_count`）。

### 7.2 LLM 仅做受约束总结的设计理由

默认模型为本地 `qwen2.5:3b`（经 Ollama 部署；Ollama 为 MIT 许可证，Qwen2.5 为 Apache-2.0 许可证）。3B 量级模型的事实性输出不可靠：可能编造事件 ID、数字与规则号，无法保证分类/决策的正确性。因此实现上把它严格限制为「复读机」：

- LLM **不参与**意图分类、Plan 生成、Agent 选择、引用校验、压缩——全部为确定性代码；
- LLM 唯一职责是在事实文本之前生成一段不超过 6 句的中文引导总结，且系统提示词硬性约束：

```text
你是企业WAF安全助手的总结器。规则：
1) 只能复述给定事实中的信息，禁止编造任何数字、事件、规则、IP、时间；
2) 事实中的[Ex]为证据编号，复述时可保留引用；
3) 不超过6句；4) 中文；
5) 若事实写'数据不足'，直接说明无法确认，不得推测。
```

- 输入侧：用户问题 + 截断至 3000 字符的事实文本（标注「唯一可信来源」）；
- 调用参数（`llmCompose`）：经模型网关 `ComplexityStandard` 档位路由，`MaxTokens=1024`、`Temperature=0.2`（低温抑制发散）。

### 7.3 降级路径

| 场景 | 行为 |
|------|------|
| LLM 调用失败或返回空 | 省略总结段，回答 = 纯事实文本（功能不中断） |
| 全部 Agent 无事实产出 | 事实文本 = 「当前数据不足，无法确认。」，不再调用 LLM |
| LLM 编造引用编号 | `ValidateCitations` 剥除标注 + 追加不确定性声明 |
| 模型路由配置缺失/加载失败 | 网关回退默认本地模型（`qwen2.5:3b`），AI 调用降级但不致命 |

## 8. 任务落库与状态机（task_store.go）

### 8.1 ai_tasks 表（迁移 000013）

| 字段 | 类型 | 说明 |
|------|------|------|
| `id` | UUID PK | 编排器生成（`uuid.New()`） |
| `session_id` | UUID FK → ai_sessions，ON DELETE CASCADE | 所属会话 |
| `task_type` | VARCHAR(40) | TaskType 值 |
| `status` | VARCHAR(20)，DEFAULT 'PENDING' | 见状态机 |
| `risk_level` | VARCHAR(20)，DEFAULT 'LOW' | LOW / MEDIUM |
| `plan_summary` | TEXT | Plan 摘要 |
| `started_at` / `finished_at` | TIMESTAMPTZ | Create 时写 `started_at=now()`；Finish 时写 `finished_at=now()` |
| `failure_code` / `failure_message` | VARCHAR(50) / VARCHAR(500) | 失败信息（Finish 截断至 500 字节） |
| `created_at` | TIMESTAMPTZ | 创建时间 |

索引：`(session_id, created_at DESC)`、`(status, created_at DESC)`。

### 8.2 状态机

迁移注释中预留的状态全集为 `PENDING/PLANNING/RUNNING/WAITING_TOOL/COMPOSING/SUCCESS/PARTIAL_SUCCESS/FAILED/CANCELLED`；当前编排器实际使用的流转为：

```text
Create（直接以 RUNNING 插入，started_at=now()）
   │
   ├─ 全部 Agent 成功          → SUCCESS（默认）
   ├─ 任一 Agent 执行失败       → PARTIAL_SUCCESS（仍返回已得结果）
   ├─ plan 事件推送失败         → FAILED（failure_message=错误信息）
   └─ ctx.Err()≠nil（停止/断连/120s 超时）→ CANCELLED（「任务被取消或超时」，优先级最高）
```

`TaskStore.Create` 失败仅 `slog.Warn` 不阻断对话（AI 落库异常不影响防护与对话主流程）。结束状态通过 `defer` + 独立 5 秒超时的 `context.Background()` 回写：客户端中途断连导致请求 ctx 取消时，任务记录仍能正确关闭，不会停留在 RUNNING。

### 8.3 查询

`TaskStore.List`（按 status/task_type 过滤、分页）与 `TaskStore.Get` 均 `JOIN ai_sessions` 按 `s.user_id` 过滤——任务记录严格属主隔离，接口层对应 `GET /api/v1/ai/tasks`（`TaskList`，仅本人）。

## 9. SSE 步骤事件模型

### 9.1 Step 与事件格式

编排器通过 `StepFunc` 回调向接口层推送流式步骤：

```go
type Step struct {
    Kind    string      `json:"kind"`    // plan / agent_start / tool / agent_done / answer / evidence / error / done / compressed
    Text    string      `json:"text"`
    Payload interface{} `json:"payload,omitempty"`
}
```

接口层包装为 `sseEvent{Type, Text, Payload}`，每个事件一行 JSON，按 SSE 规范写出并立即 flush：

```text
data: {"type":"plan","text":"安全事件分析（调度: security_event）","payload":{...}}

data: {"type":"agent_start","text":"安全事件 Agent"}

data: {"type":"answer","text":"...","payload":{"evidence_count":2}}

data: {"type":"done","payload":{"task_id":"...","message_id":"...","finish_reason":"stop"}}
```

### 9.2 事件种类

| kind | 发出方 | 时机 / 内容 |
|------|--------|-------------|
| `plan` | 编排器 | 意图分类后，payload 为完整 Plan |
| `agent_start` | 编排器 | Agent 开始执行，Text 为展示名 |
| `agent_done` | 编排器 | Agent 完成，或「已停用，跳过」 |
| `answer` | 编排器 | 最终回答全文，payload 含 `evidence_count` |
| `error` | 编排器 / 接口层 | 单 Agent 失败（不中断）；或整体执行失败「分析执行失败，请稍后重试」 |
| `done` | 接口层 | 正常结束（payload 含 task_id/message_id/finish_reason）或用户停止（`finish_reason=cancelled`） |
| `compressed` | 接口层 | 本轮结束后上下文自动压缩触发 |
| `tool` / `evidence` | 预留 | `Step.Kind` 注释枚举中声明，当前编排循环未发出（Tool 调用明细经审计与证据块体现） |

`StepFunc` 返回错误可中断 `Run`（写 SSE 失败即客户端断连，编排随之终止，任务经 defer 置 CANCELLED）。

### 9.3 连接管理

- 响应头：`Content-Type: text/event-stream; charset=utf-8`、`Cache-Control: no-cache`、`Connection: keep-alive`、`X-Accel-Buffering: no`（禁反向代理缓冲）；
- 经 `http.NewResponseController` 将写期限放宽至 10 分钟，覆盖服务器默认 30s WriteTimeout（防止 LLM 推理长静默期连接被掐断）；
- 每个会话同时仅一个运行中任务：`chat.register(sessionID, cancel)` 登记取消函数，同会话新任务注册时先取消旧任务；`POST .../stop` 触发取消。

## 10. 上下文加载与自动压缩（session.go / context.go）

`Run` 第 2 步加载：会话记录（含 `ContextSummary` 历史摘要）+ 最近 10 条消息（`RecentMessages`，正序）。总结器可见事实 + 摘要，但当前实现中 `recent`/`summary` 仅传入 `composeAnswer` 供引导总结参考，事实文本仍是唯一可信来源。

上下文压缩由接口层在每轮结束后触发（`MaybeCompress`），编排器不直接调用：

- 阈值（按上下文窗口比例，窗口缺省 8192）：预警 0.70 / 自动压缩 0.80 / 强制裁剪 0.90；
- 触发时取最近 100 条消息，`Compress` 保留最近 8 条原文，旧消息生成确定性摘要（「【此前会话摘要】用户问N：…」，上限 1500 字符）并**保留全部 `[Ex]` 证据引用**（去重后写入摘要与 `preserved_references`）；
- 事务内更新 `ai_sessions.context_summary/context_token_count`、写入 `ai_context_compressions` 审计记录（含压缩前后 token 与触发原因）、删除已摘要旧消息（保留最近 8 条）；
- 压缩成功后向前端发 `compressed` 事件；失败仅记日志不阻断。

Token 数为估算值（`EstimateTokens`：CJK 字符 ×2/3 + 其他 ×1/4 + 1），非精确 tokenizer 计数。

## 11. 权限、配额与审计挂钩

- 会话/消息接口全部要求 `ai.chat.use` 权限，会话严格属主隔离（`loadOwnedSession`）；任务类型由服务端意图分类判定，不采信前端声明的 `task_type` 字段；
- 配额服务端强制：每轮按 `EstimateTokens(content)+512` 预检（`Cost.CheckQuota`），超限返回 429；
- Agent 内 Tool 调用统一走 `ToolContext.CallTool → Registry.Execute`，携带 Principal 权限集与审计器，Tool 层权限校验与审计在 `aitools` 完成（另见 Tool/权限设计）；
- 每轮对话由接口层写一条 AI 审计（`aiaudit`，含会话/任务 ID、任务类型、估算 token、耗时、请求与结果摘要）；
- 消息与用量由接口层落库（`AppendMessage` + `RecordUsage`，本地模型成本记 0），编排器不重复记账——这是 `Run` 注释「消息保存与压缩由调用方 sessions 层处理」的职责边界。

## 12. 验证

- 接口层：`server/internal/aihandlers/handler_test.go`（路由注册冒烟 `TestRegisterRoutesNoPanic`）；
- 编排器核心函数（`Classify` / `ExtractIDs` / `ValidateCitations` / `Compress` / `CheckBudget` / `EstimateTokens`）均为无 IO 依赖的纯函数，确定性规则表支持逐条用例覆盖；当前包内尚无独立 `*_test.go`，单测补齐列入阶段7 质量项（任务书「测试先行」要求）；
- 任务书验收对应：意图分类规则覆盖 3.3 全部 TaskType；证据引用经 `ValidateCitations` 强制校验，无证据场景输出「当前数据不足，无法确认。」，不产生无证据结论。

## 13. 关联文档

- [阶段7 任务书：AI 安全运营中心](tasks/STAGE_7_AI_SECURITY_OPERATIONS.md)
- [架构设计](ARCHITECTURE.md)
- [数据库设计](DATABASE_DESIGN.md)
- [接口设计](API_DESIGN.md)
- [安全设计](SECURITY_DESIGN.md)
- [审计设计](AUDIT_DESIGN.md)
- [监控告警设计](MONITORING_ALERTING_DESIGN.md)
- [开源合规](OPEN_SOURCE_COMPLIANCE.md)（Ollama MIT、Qwen2.5 Apache-2.0 许可说明）
- [开发状态](DEVELOPMENT_STATUS.md)
