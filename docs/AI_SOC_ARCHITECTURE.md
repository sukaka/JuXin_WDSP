# AI 安全运营中心总体架构（阶段7）

本文档描述九章 WAF V2.0 阶段7 AI 安全运营中心（AI SOC）的总体架构，与实现代码严格一致：

- 编排器：`server/internal/aiorchestrator/`（orchestrator.go / intent.go / evidence.go / session.go / context.go / task_store.go）
- 模型网关：`server/internal/aimodel/`（gateway.go / client.go / store.go）
- Tool 体系：`server/internal/aitools/`（registry.go / event_tools.go / log_tools.go / asset_tools.go / access_tools.go / draft_tools.go / draft_store.go）
- 专业 Agent：`server/internal/aiagents/`（event_agent.go / policy_agent.go / misc_agents.go）
- 接口层：`server/internal/aihandlers/`（chat / analyze / models / agents_tools / drafts / prompts / memories / audits / usage / tasks / evaluations 各 handler）
- 支撑包：`server/internal/aiaudit/`、`server/internal/aicost/`、`server/internal/aimemory/`、`server/internal/aiprompts/`
- 装配：`server/internal/app/app.go` 阶段7装配块（`aiDeps.RegisterRoutes` 统一挂载路由）
- 数据迁移：`server/migrations/000013_stage7.up.sql`（20 张 ai_* 表）、`000014_seed_stage7_perms.up.sql`（31 个权限点）、`000015_seed_stage7_model.up.sql`（本地模型种子）
- 前端：`web/src/pages/ai/`（assistant / event-analysis / attack-profile / attack-chain / policy-recommendation / report-summary / tasks / admin）

## 1. 定位与目标

阶段7 在阶段1-6 已完成的网关防护、身份认证、应用接入、WAF 策略、安全事件、访问控制、CC 防护、统计报表、运行监控、备份恢复能力之上，建设 AI 安全运营中心（任务书：`docs/tasks/STAGE_7_AI_SECURITY_OPERATIONS.md`）。系统定位升级为「企业级 WAF + 安全事件运营平台 + AI 安全分析助手 + 受控多 Agent 协同平台」。

核心目标（与代码一一对应）：

1. AI 安全助手多轮对话（SSE 流式，停止/重试/继续/反馈）；
2. 8 类一次性 AI 分析（事件/误报/画像/攻击链/根因/策略建议/What-If/报告总结）；
3. 确定性意图分类与任务规划，多 Agent 协同调度；
4. 受控 Tool 体系：只读查询 + 草稿生成，权限逐次校验、全程审计；
5. 证据引用与幻觉抑制：回答中的事实必须可追溯到 Tool 结果，引用编号逐条校验；
6. 模型网关：OpenAI 兼容协议、按复杂度路由、主备切换、熔断降级、密钥加密存储；
7. 模型/Agent/Tool/Prompt/记忆/审计/用量/评估的管理面；
8. 成本配额控制与 AI 独立审计链（哈希链）。

设计底线（任务书第五章，代码中的落地方式）：

- **AI 只做辅助决策**：Tool 仅 `READ_ONLY` 与 `DRAFT_ONLY` 两类风险等级（`aitools` 包注释），不存在任何直接发布、封禁、改配置、执行 SQL/Shell 的 Tool；
- **所有事实必须有证据**：Agent 产出的主体是确定性 SQL/Tool 结果文本，LLM 仅做受约束的语言总结，证据不足时输出「当前数据不足，无法确认。」；
- **AI 与防护内核解耦**：AI 模块为管理面进程内模块，模型路由加载失败、LLM 不可用、加密服务不可用均不致命（降级而非阻断，见 §4、§8）；
- **最小权限**：每个 Tool 声明独立权限点，每次执行前按当前用户真实权限重新校验；
- **全程可审计**：对话、分析、Tool 调用、草稿、模型/Prompt 管理全部落审计；
- **不保存私有思维链**：审计只记录任务计划摘要（`Plan`）、证据、回答摘要、Token 与成本。

## 2. 角色与权限模型

阶段7 新增 31 个 `ai.*` 权限点（`module='ai'`，迁移 000014），沿用阶段2 三权分立角色（详见 `docs/RBAC_DESIGN.md`）。路由层经 `middleware.RequirePermission` 逐接口强制校验；多角色只读场景用 `requireAnyPerm`（任一权限满足即放行）。

### 2.1 31 个权限点与角色分配

| 权限点 | 名称 | SECURITY_ADMIN | SYSTEM_ADMIN | AUDIT_ADMIN |
|--------|------|:---:|:---:|:---:|
| ai.chat.use | 使用AI安全助手 | ✓ | ✓ | |
| ai.event_analysis.use | 安全事件AI分析 | ✓ | | |
| ai.false_positive_analysis.use | 误报AI分析 | ✓ | | |
| ai.attack_profile.use | 攻击画像 | ✓ | | |
| ai.attack_chain.use | 攻击链分析 | ✓ | | |
| ai.root_cause.use | 根因分析 | ✓ | ✓ | |
| ai.policy_recommendation.use | 策略优化建议 | ✓ | | |
| ai.what_if.use | What-If模拟 | ✓ | | |
| ai.report_summary.use | AI报告总结 | ✓ | | |
| ai.draft.exception | 生成例外草稿 | ✓ | | |
| ai.draft.blacklist | 生成黑名单草稿 | ✓ | | |
| ai.draft.cc_policy | 生成CC策略草稿 | ✓ | | |
| ai.draft.custom_rule | 生成自定义规则草稿 | ✓ | | |
| ai.sessions.read_own | 查看本人AI会话 | ✓ | ✓ | |
| ai.sessions.delete_own | 删除本人AI会话 | ✓ | ✓ | |
| ai.memories.read_own | 查看本人AI记忆 | ✓ | ✓ | |
| ai.memories.manage_own | 管理本人AI记忆 | ✓ | ✓ | |
| ai.models.read | 查看AI模型 | ✓ | ✓ | |
| ai.models.manage | 管理AI模型 | | ✓ | |
| ai.agents.read | 查看Agent | ✓ | ✓ | |
| ai.agents.manage | 管理Agent | | ✓ | |
| ai.tools.read | 查看Tool | ✓ | ✓ | |
| ai.tools.manage | 管理Tool | | ✓ | |
| ai.prompts.read | 查看Prompt | ✓ | ✓ | |
| ai.prompts.create | 创建Prompt | | ✓ | |
| ai.prompts.test | 测试Prompt | | ✓ | |
| ai.prompts.publish | 发布Prompt | | ✓ | |
| ai.prompts.rollback | 回滚Prompt | | ✓ | |
| ai.audits.read | 查看AI审计 | ✓ | ✓ | ✓ |
| ai.usage.read | 查看AI用量 | ✓ | ✓ | ✓ |
| ai.evaluations.run | 运行AI评估 | | ✓ | |

分配原则（迁移 000014 注释）：安全管理员获得 AI 分析与草稿全量能力（23 点，不含模型/Agent/Tool/Prompt 管理）；系统管理员获得 AI 运维诊断与模型/Agent/Tool/Prompt/评估管理（20 点）；审计管理员仅 AI 审计与用量只读（2 点）。

### 2.2 两层权限校验

1. **能力权限（路由层）**：`ai.*` 权限点决定能否调用接口。注意：多轮对话入口仅要求 `ai.chat.use`；`ai.event_analysis.use` 等 8 个能力点约束的是 `/api/v1/ai/analyze/*` 一次性分析端点。
2. **数据权限（Tool 层）**：对话内实际能查到哪些数据，由 Tool 声明的业务权限点决定（如 Tool `security_event.search` 要求 `security_events.read`），`Registry.Execute` 每次执行前以当前用户真实权限重新校验，越权调用记 `DENIED` 审计并拒绝——AI 不能借对话绕过阶段2-6 既有权限体系。

### 2.3 属主隔离

会话与记忆严格属主隔离：`loadOwnedSession` 对非属主一律返回 404（不泄露会话存在性）；记忆接口按 `user_id` 过滤；任务记录（`ai_tasks`）经会话归属过滤，仅本人可查。

## 3. 总体架构

```text
┌────────────────────────────────────────────────────────────────────┐
│ 浏览器前端  web/src/pages/ai（助手/分析/画像/攻击链/策略/报告/管理）   │
└──────────────┬─────────────────────────────────────────────────────┘
               │ HTTPS（会话 Cookie + CSRF；SSE 流式）
               ▼
┌────────────────────────────────────────────────────────────────────┐
│ aihandlers 接口层（authChain 认证 + RequirePermission 权限点）        │
│  chat_handler（SSE 对话/停止/重试/继续/反馈）                          │
│  analyze_handler（8 类一次性分析，一次性会话用完即删）                   │
│  models / agents_tools / prompts / memories / drafts / audits /      │
│  usage / tasks / evaluations handlers（管理面）                        │
└──────────────┬─────────────────────────────────────────────────────┘
               ▼
┌────────────────────────────────────────────────────────────────────┐
│ aiorchestrator.Orchestrator 编排器                                  │
│  意图分类 Classify（确定性正则） → 任务计划 Plan → Agent 调度（≤4）     │
│  上下文加载（会话摘要+最近10条） → 证据聚合 EvidenceSet → 引用校验      │
│  → LLM 受约束总结（可降级） → 任务落库 ai_tasks                        │
└───────┬───────────────────────┬──────────────────┬─────────────────┘
        ▼                       ▼                  ▼
┌───────────────┐   ┌────────────────────┐   ┌────────────────────────┐
│ aiagents      │   │ aimodel.Gateway    │   │ aicost / aiaudit /     │
│ 7 个专业 Agent │   │ 模型网关            │   │ aimemory / aiprompts   │
│ （确定性分析）  │   │ 路由档位/主备/熔断   │   │ 配额/审计链/记忆/Prompt │
└───────┬───────┘   └─────────┬──────────┘   └───────────┬────────────┘
        ▼                     │                          │
┌────────────────────┐        │                          │
│ aitools.Registry   │        │                          │
│ 31 个 Tool          │        │                          │
│ 权限校验→超时→审计   │        │                          │
└───────┬────────────┘        │                          │
        ▼                     ▼                          ▼
┌────────────────────────────────────────────────────────────────────┐
│ PostgreSQL 16：业务表只读查询（事件/日志/策略/资产/监控）+ 20 张 ai_* 表 │
│ Ollama 容器（默认 qwen2.5:3b，OpenAI 兼容 /v1/chat/completions）      │
└────────────────────────────────────────────────────────────────────┘
```

关键结构决策：

- **总调度不设独立 Agent 进程**：任务书"总调度 Agent"由编排器内置承担（`app.go` 注释），`ai_agents` 表中 `dispatcher` 行仅作展示且标注"编排器内置，不可停用"；代码注册表实际调度 7 个专业 Agent。
- **意图分类不用 LLM**：`Classify` 为确定性正则规则（可测试、无额外 Token 成本、无注入面），LLM 只出现在最终总结环节。
- **证据优先于生成**：`composeAnswer` 把 LLM 总结放在确定性事实文本之前作为引导段，事实为主体；LLM 失败时直接省略总结段，回答仍然成立。

## 4. 请求处理链路（用户消息 → SSE）

以多轮对话 `POST /api/v1/ai/sessions/{id}/messages` 为例（`chat_handler.runStream` + `Orchestrator.Run`）：

```text
用户消息
  │ 1. 路由层：authChain 认证 + ai.chat.use 校验 + 属主隔离（非属主 404）
  │ 2. 入参校验：非空、≤4000 字；会话必须 ACTIVE（已归档 409）
  │ 3. 配额检查：CheckQuota（估算 Token = EstimateTokens(content)+512，
  │    用户 200000/日、角色 500000/日，超限 429）
  │ 4. 用户消息落库 ai_messages
  │ 5. SSE 响应头（text/event-stream，X-Accel-Buffering: no，
  │    写期限放宽至 10 分钟）；chatRuntime 注册（同会话单任务，新任务取消旧任务）
  ▼
Orchestrator.Run（整体超时 MaxDuration=120s）
  │ 6. 意图分类 Classify：12 类任务类型确定性正则匹配（优先级有序），
  │    产出 Plan{task_type, agents, risk_level, summary}；含 UUID/规则号兜底
  │    为 EVENT_ANALYSIS，均不匹配为 GENERAL_SECURITY_QA
  │ 7. 任务落库 ai_tasks（RUNNING；失败不阻断主流程）
  │ 8. emit plan → SSE
  │ 9. 上下文加载：ai_sessions.context_summary + 最近 10 条消息
  │ 10. ExtractIDs：提取事件 UUID（≤5）、规则 ID（91x-96x/7100xx/8000xx，≤5）、
  │     IPv4（逐段校验 ≤255，≤5）
  │ 11. Agent 调度循环（上限 MaxAgents=4）：
  │     管理面启停校验（ai_agents.status，停用则跳过并 emit agent_done 说明）
  │     → emit agent_start → Agent.Analyze（确定性 SQL + CallTool）
  │       → Registry.Execute：启停校验 → 权限校验 → 超时控制（Tool 声明秒数，
  │         默认 30s）→ 执行 → 审计 ai_tool_calls（SUCCESS/FAILED/TIMEOUT/DENIED）
  │       → EvidenceSet.Add 登记证据（编号 E1..En）
  │     → 单 Agent 失败不中断：任务置 PARTIAL_SUCCESS，emit error，继续下一个
  │ 12. 事实组装：各 Agent 的 FactsText 拼接（含 [Ex] 引用标记）；
  │     无事实时「当前数据不足，无法确认。」
  │ 13. LLM 受约束总结（composeAnswer）：system 提示词禁止编造数字/事件/规则/
  │     IP/时间，≤6 句，事实截断 3000 字；走 standard 路由档（MaxTokens=1024，
  │     Temperature=0.2）；失败则省略总结段，仅返回事实文本（降级）
  │ 14. 引用校验 ValidateCitations：回答中 [Ex] 逐一对照证据集，无效引用标记
  │     移除并追加「部分引用未能对应到本次查询证据」说明；尾部追加证据列表块
  │ 15. emit answer → SSE
  ▼
chat_handler 收尾（独立短超时 ctx，客户端断连不丢记录）
  16. assistant 消息落库 ai_messages；用量落库 ai_usage_records
      （本地模型单价 0，Token 为估算值）
  17. MaybeCompress：context_token_count/上下文窗口 ≥0.80 时自动压缩
      （保留最近 8 条，旧消息生成确定性摘要并保留全部证据引用，
      落 ai_context_compressions，删除已摘要旧消息），emit compressed
  18. recordAIAudit：ai_audit_records 哈希链（action=chat，含任务类型/
      Token/耗时/请求与结果摘要）
  19. emit done（task_id/message_id/finish_reason）
  20. ai_tasks 终态回写：SUCCESS / PARTIAL_SUCCESS / FAILED / CANCELLED
      （ctx 取消或超时 → CANCELLED）
```

SSE 事件类型（`Step.Kind` 枚举：plan / agent_start / tool / agent_done / answer / evidence / error / done / compressed）。当前实现实际发射：编排器发 `plan` / `agent_start` / `agent_done` / `error` / `answer`；接口层发 `done` / `compressed` / `error`；`tool` 与 `evidence` 两种类型为预留，暂无发射点。

停止/重试/继续：`POST .../stop` 经 `chatRuntime` 取消运行中任务；`POST .../retry` 取最后一条用户消息重跑（不重复落库）；`POST .../continue` 仅当最后一条为 assistant 消息时以「请继续」续跑（否则 409）；`POST /api/v1/ai/messages/{id}/feedback` 反馈（rating ±1，类型 GENERAL/WRONG_FACT/MISSING_EVIDENCE/HALLUCINATION/OTHER，落 ai_feedback）。

一次性分析链路（`POST /api/v1/ai/analyze/*`）：同一编排器，差异在于——非流式（收集 ≤100 条步骤随响应返回）、创建一次性会话（标题 `[一次性分析] xxx`，响应后删除，审计保留 session_id）、按端点要求对应 `ai.*.use` 能力权限、事件 ID 做 UUID 形态校验防注入。

## 5. 模块清单与职责

### 5.1 后端包

| 包 | 职责 | 关键实现 |
|----|------|----------|
| aiorchestrator | 意图分类、任务规划、Agent 调度、证据聚合与引用校验、上下文预算与压缩、任务记录 | `Classify`/`ExtractIDs`（intent.go）、`Orchestrator.Run`（orchestrator.go）、`EvidenceSet`（evidence.go）、`SessionStore`（session.go）、`Compress`/`CheckBudget`（context.go）、`TaskStore`（task_store.go） |
| aimodel | 模型网关与持久化 | `Gateway` 路由/熔断/健康检查（gateway.go）、`OpenAIClient`（client.go）、`Store` 供应商/模型/密钥（store.go） |
| aitools | Tool 统一契约与注册中心、31 个 Tool、草稿落库 | `Registry.Execute`（registry.go）、查询 Tool 26 个 + 草稿 Tool 5 个、`DraftStore` |
| aiagents | 7 个专业 Agent（确定性分析 + 证据引用 + 可选 LLM 受约束总结） | event_agent.go / policy_agent.go / misc_agents.go |
| aihandlers | HTTP 接口层、SSE、属主隔离、配额前置、用量/审计落库、注册表同步 | handler.go（路由）、chat_handler.go、analyze_handler.go 等 12 个文件 |
| aiaudit | AI 独立审计链（哈希链） | `Service.Record` / `VerifyChain` |
| aicost | 配额与用量 | `Recorder.CheckQuota` / `RecordUsage` / `DefaultQuotas` |
| aimemory | 用户记忆 CRUD（SESSION/PROJECT/LONG_TERM 三种范围） | `Store` |
| aiprompts | Prompt 与不可变版本管理（创建/测试/发布/回滚） | `Store`（DRAFT/TESTING/ACTIVE/DISABLED/ARCHIVED 状态机） |

### 5.2 专业 Agent（7 个，编排器调度）

| code | 名称 | 职责 |
|------|------|------|
| security_event | 安全事件 Agent | 单事件/批量事件分析、攻击画像、攻击链关联、统计问答 |
| log_analysis | 日志分析 Agent | 访问控制/CC 事件、操作审计摘要、Request ID 链路追踪 |
| waf_policy | WAF策略 Agent | 误报研判、规则解释、策略优化建议、What-If 模拟 |
| asset | 资产 Agent | 应用、证书（30 天内到期）、网关配置版本盘点 |
| ops_diagnostic | 运维诊断 Agent | 组件健康、未关闭系统告警、发布失败、采集滞后，原因分级（已确认/高概率/待验证） |
| report | 报告 Agent | 近 7 天安全运营总结（事件/攻击类型/攻击源/误报/CC/异常组件，均来自真实统计） |
| knowledge | 知识库 Agent | OWASP CRS 与产品文档知识问答（明确标注"非当前运行事实"） |

另有 `dispatcher`（总调度）为编排器内置，不在代码注册表中。Agent 启停由 `ai_agents.status` 控制，调度前逐次查库（`AgentEnabledChecker`）。

### 5.3 Tool 注册中心（31 个 Tool）

风险等级仅两类：`READ_ONLY`（26 个查询 Tool）、`DRAFT_ONLY`（5 个草稿 Tool）。统一契约：`Code/Name/Description/Version/RiskLevel/RequiredPermission/TimeoutSeconds/MaxResults/InputSchema/Run`。

| Tool code | 名称 | 风险 | 所需权限 |
|-----------|------|------|----------|
| security_event.search | 安全事件查询 | READ_ONLY | security_events.read |
| security_event.get | 安全事件详情 | READ_ONLY | security_events.read |
| security_event.related | 关联事件 | READ_ONLY | security_events.read |
| security_event.statistics | 事件统计 | READ_ONLY | security_events.read |
| security_event.disposition_summary | 事件处置摘要 | READ_ONLY | security_events.read |
| access_control_log.search | 访问控制/CC事件查询 | READ_ONLY | access_control_events.read |
| audit_log.search | 操作审计查询 | READ_ONLY | audits.read |
| request_trace.get | Request ID 链路追踪 | READ_ONLY | security_events.read |
| system_log.search | 系统告警查询 | READ_ONLY | system_alerts.read |
| access_rule.search | 黑白名单查询 | READ_ONLY | access_rules.read |
| temporary_block.search | 临时封禁查询 | READ_ONLY | temporary_blocks.read |
| rate_limit_policy.search | CC策略查询 | READ_ONLY | rate_limits.read |
| trusted_proxy.get_summary | 可信代理摘要 | READ_ONLY | trusted_proxies.read |
| statistics.security_overview | 安全概览统计 | READ_ONLY | analytics.security.read |
| statistics.attack_trend | 攻击趋势统计 | READ_ONLY | analytics.security.read |
| statistics.top_source_ips | 攻击源IP排行 | READ_ONLY | analytics.security.read |
| statistics.top_rules | 规则命中排行 | READ_ONLY | analytics.security.read |
| statistics.runtime | 运行统计 | READ_ONLY | dashboard.runtime.read |
| application.search | 应用查询 | READ_ONLY | applications.read |
| application.get | 应用详情 | READ_ONLY | applications.read |
| certificate.get_metadata | 证书元数据 | READ_ONLY | certificates.read |
| gateway.get_status | 网关状态 | READ_ONLY | gateway_status.read |
| policy.get | 防护策略查询 | READ_ONLY | protection_policies.read |
| rule.search | WAF规则查询 | READ_ONLY | waf_rules.read |
| rule.get | WAF规则详情 | READ_ONLY | waf_rules.read |
| exception.search | 例外策略查询 | READ_ONLY | exceptions.read |
| draft.exception.create | 例外策略草稿 | DRAFT_ONLY | ai.draft.exception |
| draft.blacklist.create | 黑名单草稿 | DRAFT_ONLY | ai.draft.blacklist |
| draft.cc_policy.create | CC策略草稿 | DRAFT_ONLY | ai.draft.cc_policy |
| draft.custom_rule.create | 自定义规则草稿 | DRAFT_ONLY | ai.draft.custom_rule |
| draft.report_summary.create | 报告总结草稿 | DRAFT_ONLY | ai.report_summary.use |

执行约束（`Registry.Execute`）：未登记报 `ErrToolNotFound`；DB 禁用报 `ErrToolDisabled`（`ToolEnabledChecker` 逐次查 `ai_tools.status`）；越权记 DENIED；超时按 Tool 声明（10-30s）；入参摘要截断 400 字符入审计；返回数量受 `MaxResults` 约束。

### 5.4 模型网关（aimodel）

- **统一协议**：OpenAI 兼容客户端（Ollama / vLLM / 兼容网关通用），`POST {base_url}/v1/chat/completions`，支持流式（SSE 解析）与非流式，HTTP 超时 5 分钟，健康检查为短对话（"ping"，MaxTokens=5，15s 超时）。
- **路由档位**：`simple / standard / high` 三档，档位→model_code 存 `system_settings`（组 `ai`，键 `route_simple/route_standard/route_high`），启动与变更时 `ReloadRoutes` 热生效；同档多模型按 `priority` 排序逐个尝试（主备切换）；档位无路由回退 standard，standard 为空时全部启用模型兜底；无任何可用模型报 `ErrNoModel`。
- **熔断**：单模型连续失败 3 次熔断 60 秒（`circuitThreshold`/`circuitCooldown`），期间跳过该模型。
- **密钥**：供应商密钥经 `encryption.Service`（AES-256-GCM，主密钥 `JIUZHANG_MASTER_KEY`）加密存 `ai_provider_secrets`，仅在服务端调用前解密（`DecryptSecret` 实现 `KeyResolver`），不回传前端、不写日志、不进 Prompt；加密服务不可用时仅密钥相关操作降级，本地无密钥模型不受影响。

### 5.5 任务与资源限制

| 限制项 | 值（代码位置） |
|--------|----------------|
| 单任务 Agent 上限 | 4（`DefaultLimits.MaxAgents`） |
| 单任务 Tool 调用上限 | 20（`DefaultLimits.MaxToolCalls` / 配额同名项） |
| 单任务总时长 | 120s（`DefaultLimits.MaxDuration`） |
| 输入/输出 Token 上限 | 12000 / 4096（`DefaultLimits`） |
| 用户每日 Token | 200000（`DefaultQuotas.UserDailyTokens`） |
| 角色每日 Token | 500000（`DefaultQuotas.RoleDailyTokens`） |
| 单次请求输入 | 12000（`DefaultQuotas.PerRequestTokens`） |
| 并发任务 / 高成本任务每日 | 10 / 20（`DefaultQuotas`） |
| 上下文压缩阈值 | 预警 0.70 / 压缩 0.80 / 强制裁剪 0.90（`DefaultThresholds`，窗口缺省 8192） |
| 压缩保留 | 最近 8 条消息 + 全部证据引用（`MaybeCompress`） |
| 对话消息长度 | ≤4000 字；会话标题 ≤200 字（chat_handler） |
| Token 估算 | CJK 字符 ×2/3 + 其他 ×1/4 + 1（`EstimateTokens`，流式无 usage 时兜底） |

## 6. 数据流与数据存储

### 6.1 读路径（AI → 业务数据）

Agent 的事实来源只有两条通道，均为只读：

1. **Tool 查询**（经权限校验与审计）：安全事件、访问控制/CC 事件、操作审计、系统告警、运行健康快照、黑白名单/临时封禁/CC 策略/可信代理、应用/证书/网关状态/防护策略/规则/例外、安全统计；
2. **Agent 内联只读 SQL**（`aiagents` 直接 SELECT，如攻击链时间线、误报率、发布失败计数、checkpoint 滞后），不经 Tool 但同样是只读查询，结果经 `EvidenceSet.Add` 登记引用。

### 6.2 写路径（AI → 数据）

| 写入 | 说明 |
|------|------|
| 会话/消息/任务 | `ai_sessions` / `ai_messages` / `ai_tasks`（接口层与编排器落库） |
| 用量与审计 | `ai_usage_records`、`ai_audit_records`（哈希链）、`ai_tool_calls`（Tool 执行审计） |
| 上下文压缩 | `ai_context_compressions` + 旧消息删除 |
| 反馈 | `ai_feedback` |
| 草稿 | 草稿 Tool 写业务表（默认停用态）+ `ai_recommendations` 登记 |
| 管理面 | `ai_model_providers` / `ai_models` / `ai_provider_secrets` / `ai_agents` / `ai_tools` / `ai_prompts` / `ai_prompt_versions` / `ai_memories` / `ai_evaluation_sets` / `ai_evaluation_runs` |

### 6.3 草稿数据流（DRAFT_ONLY）

草稿是 AI 唯一触达业务配置的通道，全部默认停用、标记 AI 生成、回挂证据，进入既有人工流程：

| 草稿 Tool | 写入目标 | 初始状态 | 后续流程 |
|-----------|----------|----------|----------|
| draft.exception.create | `exception_policies` | `DISABLED` | 复用阶段4例外仓储，例外页面人工审核启用 |
| draft.blacklist.create | `ip_access_rules`（DENY，TEMPORARY） | `DRAFT` | IP 黑白名单页面人工审核启用 |
| draft.cc_policy.create | `rate_limit_policies` | `DISABLED` | CC 策略页面人工审核启用 |
| draft.custom_rule.create | `custom_rules` | `DISABLED` | 自定义规则页面人工审核启用 |
| draft.report_summary.create | `ai_recommendations` + 报告总结草稿 | `DRAFT` | 人工查阅 |

每次生成同时 `RecordRecommendation` 写 `ai_recommendations`（`created_by_ai=TRUE`、`status='DRAFT'`、`evidence_references` 存证据编号、`draft_reference` 回挂草稿 ID）；黑名单草稿复用阶段5保护地址检查（`ProtectedChecker`）防误封保护地址。草稿查询/废弃接口要求任一 `ai.draft.*` 权限。

### 6.4 ai_* 表清单（20 张，迁移 000013）

| 分组 | 表 |
|------|----|
| 模型（3） | ai_model_providers、ai_provider_secrets、ai_models |
| 对话（2） | ai_sessions、ai_messages |
| 任务与调度（3） | ai_tasks、ai_agent_runs（已建表预留，当前无写入方）、ai_tool_calls |
| 注册（2） | ai_agents、ai_tools |
| Prompt（2） | ai_prompts、ai_prompt_versions |
| 记忆（1） | ai_memories |
| 推荐/压缩/反馈（3） | ai_recommendations、ai_context_compressions、ai_feedback |
| 评估（2） | ai_evaluation_sets、ai_evaluation_runs |
| 用量与审计（2） | ai_usage_records、ai_audit_records |

启动时 `SyncRegistry` 将代码注册表中的 7 个 Agent 与 31 个 Tool upsert 到 `ai_agents`/`ai_tools`（code 唯一，更新元数据但保留启停状态），管理面启停即时生效。

## 7. 与阶段6 监控/审计的关系

**AI 消费阶段6 数据（只读）**：

| 阶段6 能力 | AI 侧消费方式 |
|------------|---------------|
| 运行健康快照 `system_health_snapshots`（runtimehealth） | `statistics.runtime` Tool（权限 `dashboard.runtime.read`）；`ops_diagnostic` Agent 根因分析读组件状态；`report` Agent 统计异常组件数 |
| 系统告警 `system_alerts`（systemalerts） | `system_log.search` Tool（权限 `system_alerts.read`），运维诊断取未关闭告警 |
| 事件采集 checkpoint 滞后 | `ops_diagnostic` Agent 内联查询 `event_collector_checkpoints`，滞后 >120s 列为高概率原因（与阶段6 降级阈值一致） |
| 发布任务 | `ops_diagnostic` Agent 统计近 7 天 `gateway_publish_tasks` 失败数 |
| 阶段6 安全统计（概览/趋势/TOP） | `statistics.*` 5 个 Tool（权限 `analytics.security.read`），供统计问答与报告总结 |
| 操作审计 `operation_audits`（阶段2） | `audit_log.search` Tool（权限 `audits.read`），日志分析 Agent 输出审计摘要 |

**审计相互独立**：AI 审计是独立链路 `ai_audit_records`（字段含 `previous_hash`/`record_hash`，`computeHash` 对 occurredAt|username|action|objectID|previousHash 做 SHA-256 链接，`VerifyChain` 校验，接口 `POST /api/v1/ai/audits/verify`），不复用 `operation_audits` 表；`ai_audit_records` 记录请求/结果摘要而非完整思维链。AI 管理面操作（模型/Agent/Tool/Prompt 变更）当前写入 AI 审计链，不写入 `operation_audits`。

**监控现状（如实说明）**：阶段6 `runtimehealth` 的 10 类组件探针不包含 Ollama/AI 组件，AI 调用失败不触发 `system_alerts`；AI 可用性保障依赖模型网关熔断 + 主备切换 + 回答层降级（LLM 失败回退纯事实文本）+ 启动失败不致命（路由加载失败仅告警日志）。

**故障解耦**：AI 模块整体内嵌于管理 API 进程，无独立 worker；Ollama 不可用或模型熔断期间，WAF 防护、事件采集、监控告警、备份恢复等阶段1-6 链路不受影响，AI 入口表现为分析失败或降级回答。

## 8. 部署拓扑

```text
┌──────────────────────── Docker 宿主机（内网） ───────────────────────┐
│  stage5-net（bridge，deployment/docker-compose.stage5.yml）          │
│                                                                      │
│  jiuzhang-stage5-postgres   jiuzhang-stage5-valkey                   │
│  jiuzhang-stage5-server（管理API，内嵌 AI 模块）                       │
│      │ 经服务名访问 http://ollama:11434（种子供应商 ollama-local）      │
│      ▼                                                               │
│  jiuzhang-stage5-ollama（ollama/ollama:0.9.6，默认模型 qwen2.5:3b）    │
│      端口绑定 127.0.0.1:${OLLAMA_PORT:-11434}:11434                   │
│      数据卷 stage5-ollama-data:/root/.ollama                          │
└──────────────────────────────────────────────────────────────────────┘
        │ 管理面 HTTPS（经网关/Caddy）
        ▼
      管理员浏览器
```

部署要点（与 `deployment/docker-compose.stage5.yml` 一致）：

1. **Ollama 容器化**：镜像锁定 `ollama/ollama:0.9.6`（不用 `latest`）；`no-new-privileges:true`；健康检查 `ollama list`；模型持久化在命名卷；
2. **内网隔离**：Ollama 端口仅绑定宿主机 `127.0.0.1`，不暴露公网；服务端经 Docker 内部网络按服务名访问（迁移 000015 种子 `base_url=http://ollama:11434`）；首次使用需拉取模型：`docker exec jiuzhang-stage5-ollama ollama pull qwen2.5:3b`；
3. **默认零成本**：种子模型 `qwen2.5:3b`（上下文 32768、最大输出 2048、超时 120s、优先级 1、单价 0），三个路由档位默认全部指向它（配置缺失时 `defaultModelCode` 兜底，不致命）；
4. **外部模型可选**：可登记任意 OpenAI 兼容供应商（`openai_compatible` 类型），密钥 AES-256-GCM 加密入库，支持轮换（`POST /api/v1/ai/models/providers/{id}/rotate-key`）；敏感场景可只用本地模型（路由档位全部指向本地模型即不出内网）；
5. **许可证**：Ollama（MIT）、Qwen2.5（Apache-2.0），均为宽松许可证，符合项目第三方组件约束；
6. **密钥底线**：文档与代码均不含任何明文密钥；`JIUZHANG_MASTER_KEY` 由环境变量注入，仅驻留服务端进程内存。

## 9. 关联文档

- 任务书：[STAGE_7_AI_SECURITY_OPERATIONS.md](tasks/STAGE_7_AI_SECURITY_OPERATIONS.md)
- 总体架构：[ARCHITECTURE.md](ARCHITECTURE.md)
- 权限设计（三权分立）：[RBAC_DESIGN.md](RBAC_DESIGN.md)
- 操作审计与哈希链思想：[AUDIT_DESIGN.md](AUDIT_DESIGN.md)
- 阶段6 监控告警：[MONITORING_ALERTING_DESIGN.md](MONITORING_ALERTING_DESIGN.md)
- 安全设计：[SECURITY_DESIGN.md](SECURITY_DESIGN.md)
- 部署：[DEPLOYMENT.md](DEPLOYMENT.md)
- 开源合规：[OPEN_SOURCE_COMPLIANCE.md](OPEN_SOURCE_COMPLIANCE.md)
