# AI Agent 设计（阶段7）

本文档描述九章 WAF V2.0 AI 安全运营中心的 Agent 设计，与实现代码严格一致：

- Agent 实现：`server/internal/aiagents/`（event_agent.go / policy_agent.go / misc_agents.go）
- 编排器（总调度）：`server/internal/aiorchestrator/`（orchestrator.go / intent.go / evidence.go）
- Tool 注册中心：`server/internal/aitools/`（registry.go 及各类 Tool）
- 管理面：`server/internal/aihandlers/agents_tools_handler.go`
- 表结构：`server/migrations/000013_stage7.up.sql`（`ai_agents`）、`000015_seed_stage7_model.up.sql`（8 个 Agent 注册行）

## 1. 设计目标与基本原则

`aiagents` 包头注释即设计纲领：**专业 Agent = 确定性分析 + 证据引用 + 可选 LLM 受约束总结；事实一律来自 Tool/数据库，LLM 只复述，不允许编造**。

1. **事实先行**：Agent 产出的是确定性事实文本（数字、事件、规则、IP 均来自 Tool 结果或数据库只读查询），不允许 LLM 生成事实；
2. **证据可追溯**：每条关键事实附带证据引用编号 `[Ex]`，最终回答经引用校验后才输出；
3. **只读与草稿**：Agent 只能调用 `READ_ONLY` / `DRAFT_ONLY` 两类 Tool，不得执行发布、封禁、删改等生产变更；涉及变更的建议一律以"草稿需人工确认"表述；
4. **数据不足明示**：证据不足时输出"当前数据不足，无法确认"，不得推测；
5. **知识与事实分离**：知识解释（CRS/文档）不得冒充当前运行事实；
6. **最小权限**：Tool 调用按当前用户真实权限点逐次校验。

## 2. 总体架构与调度链路

系统共 8 个 Agent：**7 个专业 Agent**（代码实现于 `aiagents` 包）+ **1 个总调度 Agent**（`dispatcher`，编排器内置能力，非独立实现）。装配代码见 `server/internal/app/app.go`（注册 7 个专业 Agent 并设置启停检查）。

```text
用户消息 / 一次性分析请求
        │
        ▼
┌──────────────────────────────────────────────────────────┐
│ Orchestrator.Run（dispatcher 总调度，编排器内置）           │
│  1. Classify 意图分类（确定性正则规则）→ Plan              │
│  2. 任务落库 ai_tasks（失败不阻断主流程）                   │
│  3. ExtractIDs 提取事件ID/规则ID/IP                        │
│  4. 按 Plan.Agents 顺序调度专业 Agent：                    │
│       ├─ DB 启停检查（ai_agents.status，停用则跳过）        │
│       ├─ Agent.Analyze(ctx, AnalyzeInput)                 │
│       │     ├─ ToolCtx.CallTool ──► aitools.Registry      │
│       │     │     （启停检查→权限校验→超时→审计）            │
│       │     └─ Evidence.Add ──► 证据集（E1..En）           │
│       └─ 收集 AnalyzeResult.FactsText                     │
│  5. composeAnswer：事实为主体，LLM 仅加受约束引导总结       │
│     （失败/为空则省略，回退纯事实文本）                      │
│  6. ValidateCitations 引用校验 + 证据列表追加               │
└──────────────────────────────────────────────────────────┘
        │
        ▼
最终回答（事实文本 + [Ex] 引用 + 证据列表）
```

单个 Agent 执行失败不中断整体：任务状态置 `PARTIAL_SUCCESS`，错误经流式步骤 `error` 透出，继续调度后续 Agent。客户端取消/超时时任务标记 `CANCELLED`。

## 3. Agent 接口契约

### 3.1 Agent 接口

定义于 `aiorchestrator/orchestrator.go`：

```go
type Agent interface {
    Code() string
    Analyze(ctx context.Context, in *AnalyzeInput) (*AnalyzeResult, error)
}
```

- `Code()` 返回 Agent 唯一编码（小写，如 `security_event`），同时是注册键、`ai_agents.code` 与意图路由中的调度名；
- `Analyze()` 执行确定性分析，返回事实文本；返回 `error` 表示本次分析失败（编排器记为 `PARTIAL_SUCCESS` 并继续）；
- 所有专业 Agent 内嵌 `aiagents.base` 基座（持有 `code` 与 `*pgxpool.Pool`），经 `Orchestrator.RegisterAgent` 注册。

### 3.2 AnalyzeInput / AnalyzeResult

`AnalyzeInput` 字段（编排器统一构造，Agent 只读使用）：

| 字段 | 类型 | 说明 |
|------|------|------|
| `Principal` | `*aitools.Principal` | 调用者身份（UserID/Username/Permissions），Tool 权限校验用 |
| `TaskID` | `uuid.UUID` | 本次任务 ID（Tool 审计关联） |
| `SessionID` | `uuid.UUID` | 会话 ID |
| `TaskType` | `TaskType` | 意图分类结果，Agent 据此分派内部分析函数 |
| `Message` | `string` | 用户原始消息 |
| `EventIDs` | `[]string` | 消息中提取的 UUID（事件 ID 或 Request ID，最多 5 个） |
| `RuleIDs` | `[]int` | 消息中提取的规则 ID（91-96 号段等，最多 5 个） |
| `IPs` | `[]string` | 消息中提取的合法 IPv4（逐段 ≤255 校验，最多 5 个） |
| `ToolCtx` | `*ToolContext` | Tool 执行上下文（见 §3.3） |
| `Evidence` | `*EvidenceSet` | 任务级共享证据集（见 §3.4） |
| `LLMCompose` | `func(...)` | 受约束 LLM 总结回调；**当前 7 个 Agent 均未使用**，LLM 总结统一由编排器 `composeAnswer` 完成 |

`AnalyzeResult` 字段：

| 字段 | 类型 | 说明 |
|------|------|------|
| `FactsText` | `string` | 确定性事实文本（Markdown，含 `[Ex]` 引用标记） |
| `Facts` | `interface{}` | 结构化事实（前端渲染用；当前 Agent 均未填充，留作扩展） |

### 3.3 ToolContext 与 Tool 调用

`ToolContext` 持有 `Registry`（Tool 注册中心）、`Auditor`（AI 审计）、`TaskID`。Agent 不直接实例化 Tool，统一经 `ToolCtx.CallTool(ctx, principal, code, input)` 调用，内部走 `Registry.Execute` 固定链路：

```text
DB 启停检查（ai_tools.status）→ 权限点校验（RequiredPermission，每次执行前重查）
→ 超时控制（tool 级 TimeoutSeconds）→ 执行 → 审计（ai_audit_records，DENIED/TIMEOUT/FAILED 同样记录）
```

`aiagents.callTool` 是 Agent 侧的便捷封装：**调用 Tool → 成功即把结果登记进证据集 → 返回 `(结果, 证据编号, 错误)`**，保证"凡 Tool 数据必有证据"。Tool 权限拒绝时返回错误，Agent 按分支容错（多数分支容错跳过并继续，主分支失败则整体返回 error）。

### 3.4 Evidence 证据写入与引用校验

证据机制实现于 `aiorchestrator/evidence.go`：

- **写入**：`EvidenceSet.Add(source, summary, detail)` 追加一条证据并返回编号 `E1..En`；`source` 为 Tool code 或查询描述，`summary` 为一句话摘要，`detail` 为 Tool 原始结果（可为 `nil`）。证据集任务级共享，多个 Agent 的证据统一编号；
- **正文引用**：Agent 在事实文本中以 `- 证据：[E3]` 形式标注；
- **引用校验**：`ValidateCitations` 用正则 `\[((?:E\d+)(?:\s*[,，、]\s*E\d+)*)\]` 扫描最终回答，剔除不存在于证据集的引用编号（不静默删除内容，追加"部分引用未能对应到本次查询证据"的不确定性声明）；
- **证据列表**：`ComposeEvidenceBlock` 在回答尾部追加 `**证据引用**` 清单（编号 + 来源 + 摘要）。

## 4. 总调度 Agent（dispatcher，编排器内置）

### 4.1 职责

`dispatcher` 不是独立代码实现，而是 `Orchestrator` 的内置能力集合：意图识别与任务规划（`intent.go`）、专业 Agent 调度、证据聚合与引用校验、最终回答组装（`orchestrator.go`）。因其承载调度主干，**管理面禁止停用**（详见 §6）。

### 4.2 意图分类与任务类型

`Classify(message)` 为**确定性正则规则**（非 LLM），按优先级首条命中返回 `Plan{TaskType, Agents, RiskLevel, Summary}`；`Plan` 是可展示的计划摘要，不保存私有思维链。任务类型共 12 种：

| 任务类型 | 触发模式（摘要） | 调度 Agent | 风险等级 |
|----------|------------------|------------|----------|
| `FALSE_POSITIVE_ANALYSIS` | "误报/false positive/误杀/误拦/误阻断" | `waf_policy`, `security_event` | MEDIUM |
| `RULE_EXPLANATION` | "规则 解释/什么意思/干什么/用途"、6-7 位规则号+解释 | `waf_policy`, `knowledge` | LOW |
| `ATTACK_CHAIN` | "攻击链/攻击过程/入侵过程/chain" | `security_event`, `log_analysis` | LOW |
| `ROOT_CAUSE_ANALYSIS` | "为什么…延迟/失败/异常/升高/不足/错误/慢/积压/崩溃"、"根因/排查"等 | `ops_diagnostic`, `log_analysis` | LOW |
| `ATTACK_PROFILE` | "画像/谁在攻击/哪个ip/来源/攻击者" | `security_event`, `log_analysis` | LOW |
| `EVENT_ANALYSIS` | "事件…分析/分析一下"等 | `security_event` | LOW |
| `POLICY_RECOMMENDATION` | "策略 建议/优化/调整/推荐"、"调优"等 | `waf_policy` | MEDIUM |
| `WHAT_IF_ANALYSIS` | "what if/如果…关闭/启用/改成/切换/调整"、"模拟/假设" | `waf_policy` | MEDIUM |
| `REPORT_SUMMARY` | "日报/周报/月报/总结/汇总" × "安全/攻击/运营" | `report` | LOW |
| `LOG_QUERY` | "日志/log/请求记录" | `log_analysis` | LOW |
| `STATISTICS_QUERY` | "统计/趋势/排行/top/多少/数量/分布" | `security_event`, `log_analysis` | LOW |
| `GENERAL_SECURITY_QA` | 兜底（未命中任何规则） | `knowledge`, `security_event` | LOW |

兜底前还有一条标识规则：消息含 UUID 形态或 6-7 位数字（规则号形态）时直接按 `EVENT_ANALYSIS` 调度 `security_event`。

### 4.3 标识提取（ExtractIDs）

`ExtractIDs` 从消息文本提取三类标识作为 Agent 输入：UUID（事件 ID/Request ID，≤5）、规则 ID（`91-96` 开头 6 位、`7100xx`、`8000xx` 开头 7 位号段，≤5）、IPv4（逐段数值校验，≤5）。一次性分析API（`analyze_handler.go`）把事件 ID/规则 ID/IP 拼进模板消息，同样经 `ExtractIDs` 进入 Agent。

### 4.4 执行限制与降级

`DefaultLimits()`：`MaxAgents=4`（单任务最多调度 4 个 Agent，`Run` 中强制）、`MaxDuration=120s`（整体超时，`context.WithTimeout` 强制）、`MaxToolCalls=20`、`MaxInputTokens=12000`、`MaxOutputTokens=4096`（后三项当前为保留配置项，`Run` 路径未做硬性计数拦截；`aicost.CheckQuota` 实际强制的是单次/用户日/角色日 Token 配额）。最终回答组装时，LLM 系统提示明确"只能复述给定事实、禁止编造数字/事件/规则/IP/时间、事实写数据不足时直接说明无法确认"，且 `MaxTokens=1024`、`Temperature=0.2`；LLM 调用失败或返回为空时直接输出纯事实文本。

## 5. 七个专业 Agent

所有 Agent 产出统一为 `FactsText`（Markdown 事实文本）：标题行 + `- 键：值` 条目 + `- 证据：[Ex]` 标注 + 必要的不确定性/免责说明。下表"直接 SQL"指 Agent 代码中固定的参数化只读查询（确定性服务端代码，非 LLM 自由执行 SQL；LLM 不接触数据库）。

### 5.1 安全事件 Agent（security_event）

- **意图**：单事件分析、批量事件归纳、攻击画像、攻击链关联、统计问答（`event_agent.go`）；
- **任务分派**：`EVENT_ANALYSIS`/`GENERAL_SECURITY_QA`→单事件/批量归纳；`ATTACK_PROFILE`→画像；`ATTACK_CHAIN`→攻击链；`STATISTICS_QUERY`/`LOG_QUERY`→统计问答；未识别类型默认走事件分析；

| 分析分支 | 调用的 Tool | 直接 SQL | 产出事实格式要点 |
|----------|-------------|----------|------------------|
| 单事件分析（含 ID，≤3 个） | `security_event.get`、`security_event.related` | - | 攻击类型/严重级别/动作/客户端IP/目标/异常评分/响应状态/Request ID/处置状态/命中规则/是否被阻断（`BLOCK`=已阻断未到达源站，否则提示观察模式可能到达）+ 关联事件数 |
| 批量归纳（无 ID） | `security_event.statistics`（attack_type 维度）、`statistics.top_source_ips`（TOP5） | - | 24h 攻击类型分布、攻击源 IP TOP5（次数/阻断数） |
| 攻击画像 | `security_event.search`、`temporary_block.search`（有 IP 时）；`statistics.top_source_ips`（TOP10，无 IP 时） | `security_events`（首次/最近出现、攻击类型分布） | 画像对象、30 天事件总数、首末出现时间、攻击类型、封禁记录数 |
| 攻击链关联 | 证据手工登记 `security_event.search` | `security_events`（按时间线 ≤20 步；无 IP 时先按事件反查 client_ip） | 逐步时间线（时间/类型/路径/级别/动作）、关联置信度（<3 步 `LOW_CONFIDENCE`、≥3 `MEDIUM_CONFIDENCE`、≥5 `HIGH_CONFIDENCE`）、成功迹象（全部阻断/存在未阻断步骤） |
| 统计问答 | `statistics.security_overview` | - | 今日请求/事件/阻断/CC/黑名单命中/临时封禁/未处置高危 |

事件分析尾部固定声明：攻击是否成功不依据规则命中判断，需综合 WAF 动作、响应状态与 Request ID 链路。攻击链尾部声明：MITRE ATT&CK 阶段映射为参考映射，非确认事实。

### 5.2 日志分析 Agent（log_analysis）

- **意图**：访问控制/CC 事件、操作审计日志与 Request ID 链路追踪（`misc_agents.go`）；
- **任务分派**：无内部分支，按输入统一执行三段查询；

| 调用的 Tool | 权限点 | 产出事实格式要点 |
|-------------|--------|------------------|
| `request_trace.get`（输入含 ID 时，取 `EventIDs[0]` 作 Request ID） | `security_events.read` | 该 Request ID 关联的 WAF 事件数、访问控制事件数 |
| `access_control_log.search` | `access_control_events.read` | 最近访问控制/CC 事件总数与前 5 条（时间/类型/IP/动作） |
| `audit_log.search` | `audits.read` | 最近操作审计总数与前 5 条（时间/用户/模块/动作） |

### 5.3 WAF策略 Agent（waf_policy）

- **意图**：误报研判、规则解释、策略优化建议、What-If 历史模拟（`policy_agent.go`）；任务书"策略建议"场景对应本 Agent（code 为 `waf_policy`）；
- **任务分派**：`FALSE_POSITIVE_ANALYSIS`→误报研判；`RULE_EXPLANATION`→规则解释；`POLICY_RECOMMENDATION`→策略建议；`WHAT_IF_ANALYSIS`→What-If 模拟；未识别类型默认规则解释；

| 分析分支 | 调用的 Tool | 直接 SQL | 产出事实格式要点 |
|----------|-------------|----------|------------------|
| 误报研判 | `security_event.get`、`rule.get`、`exception.search` | `security_event_matches`⨝`security_events`（近 30 天命中率/误报率） | 事件概要、命中规则（名称/级别/类型）、累计命中、历史误报标记、近 30 天误报率、当前生效例外数；**研判建议**（草稿需人工确认）：精确例外（应用+URI+规则，禁止全局关闭）、先 24h 临时观察、重放验证方法；提示可经 `draft.exception.create` 生成 DRAFT 草稿（Agent 自身不调用草稿 Tool） |
| 规则解释 | `rule.get` | `waf_rules`（CRS 版本） | 规则号/来源/名称/攻击类型/严重级别/检测阶段/命中次数/误报标记；声明不复制上游规则源代码、解释不等同于当前正遭受该类攻击 |
| 策略建议 | `policy.get`、`security_event.statistics`、`statistics.top_rules` | - | 前 3 条策略（模式/PL/入出站阈值/是否内置）、近 7 天攻击类型分布（TOP5）、规则命中与误报 TOP5；建议项：误报高先例外收敛而非停用、新应用先 OBSERVE 1-2 周、阈值每次调整 ≤±2、变更须走策略编辑+配置发布流程 |
| What-If 模拟 | `rule.get` | `security_event_matches`⨝`security_events`（近 30 天） | 关闭指定规则的历史回放估算：受影响请求数、可能减少的误报、可能漏拦的攻击（`action='BLOCK'` 计数）、模拟风险等级（有漏拦 `HIGH`，否则 `MEDIUM`）；声明基于历史数据不代表未来确定结果 |

### 5.4 资产 Agent（asset）

- **意图**：应用、证书、网关配置版本等资产盘点（`misc_agents.go`）；

| 调用的 Tool | 权限点 | 产出事实格式要点 |
|-------------|--------|------------------|
| `application.search` | `applications.read` | 受保护应用数与前 5 条（名称/编码/防护模式） |
| `certificate.get_metadata`（30 天内到期） | `certificates.read` | 临期证书数与前 5 条（CommonName/剩余天数）；仅元数据，不含私钥 |
| `gateway.get_status` | `gateway_status.read` | 当前配置版本 |

### 5.5 运维诊断 Agent（ops_diagnostic）

- **意图**：运行异常根因分析（`misc_agents.go`）；

| 数据来源 | 类型 | 产出事实格式要点 |
|----------|------|------------------|
| `statistics.runtime` | Tool（`dashboard.runtime.read`） | 组件健康快照：异常组件清单或"全部 UP" |
| `system_log.search`（status=OPEN） | Tool（`system_alerts.read`） | 未关闭告警数与前 5 条（级别/标题/组件） |
| `gateway_publish_tasks` | 直接 SQL | 近 7 天发布次数与失败数 |
| `event_collector_checkpoints` | 直接 SQL | 事件采集滞后秒数（>120s 超阈值时列出） |

结论按三级输出：**已确认 / 高概率 / 待验证**——采集滞后超阈值、发布失败计入"高概率"；无直接证据时"已确认"明示"暂无直接证据确认的具体原因"。尾部固定声明：不执行重启/升级/恢复/配置修改等操作，仅为诊断建议。

### 5.6 报告 Agent（report）

- **意图**：安全运营报告总结（日报/周报/月报场景），仅使用真实统计数据，时间范围固定近 7 天（`misc_agents.go`）；

| 数据来源 | 类型 | 产出事实格式要点 |
|----------|------|------------------|
| `security_events` | 直接 SQL | 事件总数、阻断/观察分布、攻击类型 TOP5、误报标记数、未处置事件数 |
| `statistics.top_source_ips`（start_time=7 天前） | Tool（`analytics.security.read`） | 主要攻击源 TOP5 |
| `access_control_events` | 直接 SQL | CC 事件数（`event_type LIKE 'CC%'`） |
| `system_health_snapshots` | 直接 SQL | 当前异常组件数（各组件最新快照非 UP 计数） |

尾部输出固定运营建议：优先处置未处置高危事件、误报率高的规则做精确例外收敛、关注异常组件并复核告警。

### 5.7 知识库 Agent（knowledge）

- **意图**：OWASP CRS 与产品文档知识问答，明确"知识≠当前运行事实"（`misc_agents.go`）；

| 数据来源 | 类型 | 产出事实格式要点 |
|----------|------|------------------|
| `rule.get`（输入含规则 ID 时） | Tool（`waf_rules.read`） | 规则元数据（名称/攻击类型/严重级别）+ 证据引用 |
| `waf_rules` | 直接 SQL（消息关键词 ≤50 字符 ILIKE 匹配 name/message，≤5 条） | 相关规则清单；未命中时提示提供更具体的规则 ID 或攻击类型 |

尾部固定声明：知识解释不代表当前系统正发生对应攻击；当前运行事实以事件与统计查询为准。

## 6. ai_agents 表与启停管理

### 6.1 表结构

`ai_agents`（迁移 `000013_stage7.up.sql`）：

| 列 | 类型 | 说明 |
|----|------|------|
| `id` | UUID PK | 种子数据使用固定 UUID（`f7a10001-…-101` 至 `-108`）保证幂等 |
| `code` | VARCHAR(50) UNIQUE | Agent 编码，与代码 registry 一致 |
| `name` | VARCHAR(100) | 展示名 |
| `description` | VARCHAR(500) | 职责说明 |
| `prompt_id` | UUID | 预留（当前未使用） |
| `allowed_tool_ids` | JSONB | 允许的 Tool 集（默认 `[]`；**现状：可经管理面配置存储，执行路径暂不强制**，执行路径实际强制的是 Tool 自身启停与权限点） |
| `status` | VARCHAR(20) | `ENABLED` / `DISABLED`，默认 `ENABLED` |
| `version` | INTEGER | 默认 1（当前配置变更只更新 `updated_at`，不自增 version） |
| `created_at` / `updated_at` | TIMESTAMPTZ | 时间戳 |

8 个注册行（种子 `000015`，与 `aihandlers.AgentCatalog` 一致）：`dispatcher`（总调度）、`security_event`、`log_analysis`、`waf_policy`、`asset`、`ops_diagnostic`、`report`、`knowledge`。

### 6.2 启动同步与启停检查

设计决策：**代码 registry 是能力来源，`ai_agents` 表只存启停与配置**；列表接口为 DB 左联代码 registry（`in_registry` 标记），管理面无法造出代码中不存在的 Agent。

- **启动同步**（`SyncRegistry`，app.go 启动时执行）：把 `AgentCatalog` 与 Tool registry 按 `code` 唯一 upsert 入库（`ON CONFLICT DO UPDATE` 名称/描述等元数据，**保留既有启停状态**）；
- **调度侧检查**（`AgentEnabledChecker`）：编排器每次调度前实时查库，`status != 'ENABLED'` 的 Agent 跳过并经流式步骤提示"已停用，跳过"；`dispatcher` 恒返回启用；未入库的 code 默认启用（容错，防同步失败导致全不可用）；
- **执行侧联动**：Agent 被禁用只是不被调度；Tool 层另有独立的 `ai_tools` 启停检查，两层互不替代。

### 6.3 管理面 API

| 能力 | API | 权限 |
|------|-----|------|
| Agent 列表 | `GET /api/v1/ai/agents` | `ai.agents.read` |
| Agent 配置（启停/允许 Tool 集） | `PATCH /api/v1/ai/agents/{id}` | `ai.agents.manage` |
| Tool 列表 | `GET /api/v1/ai/tools` | `ai.tools.read` |
| Tool 配置（启停/超时/最大返回数） | `PATCH /api/v1/ai/tools/{id}` | `ai.tools.manage` |

`PATCH` 对 `dispatcher` 下发 `enabled=false` 返回 400（"总调度 Agent 为编排器内置能力，不可停用"）；Tool 超时限 1-300 秒、最大返回数限 1-1000。

## 7. 扩展新 Agent 指南

新增一个专业 Agent 的步骤（以现有 7 个为范式）：

1. **实现契约**：在 `server/internal/aiagents/` 新建文件，定义结构体内嵌 `base`，实现 `Code()` 与 `Analyze(ctx, *aiorchestrator.AnalyzeInput) (*aiorchestrator.AnalyzeResult, error)`；code 取唯一小写标识（与将来的 `ai_agents.code` 一致）；
2. **只产出确定性事实**：数据一律来自 `callTool`（自动登记证据）或固定的参数化只读 SQL（手工 `in.Evidence.Add` 登记证据）；事实文本用 `fmtKV` 统一 `- 键：值` 格式并标注 `- 证据：[Ex]`；证据不足必须输出"当前数据不足，无法确认"；禁止在 Agent 内编造数字或直接生成配置变更；
3. **接入路由**：如需被对话调度，在 `aiorchestrator/intent.go` 的 `intentRules` 增加意图规则（注意规则按优先级首条命中），或在既有 Agent 的 `TaskType` 分派中挂接；
4. **注册装配**：在 `server/internal/app/app.go` 的 Agent 注册列表追加 `New<你的Agent>(db)`；
5. **登记目录**：在 `aihandlers.AgentCatalog` 增加 `{code, 名称, 描述}`（供 `SyncRegistry` 入库与 `orchestrator.agentLabel` 展示名映射同步维护）；
6. **启停即生效**：无需额外代码——入库后调度侧 `AgentEnabledChecker` 自动尊重 `ai_agents.status`；
7. **Tool 依赖**：优先复用现有 Tool；确需新 Tool 时按 `aitools.Tool` 契约实现并注册（声明 `RequiredPermission`、超时、最大返回数、输入 Schema），不得绕过 `ToolCtx.CallTool` 直接访问业务数据；
8. **自检**：`go build ./...` 通过；启动日志无 `sync ai agent/tool registry failed`；`GET /api/v1/ai/agents` 可见新 Agent 且 `in_registry=true`；`PATCH` 停用后提问对应意图，流式步骤应出现"已停用，跳过"。

## 8. 安全与合规约束

1. Agent/Tool 只能查询与生成草稿：不得发布、封禁、解封、删除、修改生产配置，不得执行 Shell、升级、恢复，不得访问 Docker Socket 与 Caddy 管理 Socket；
2. Tool 权限点每次执行前按当前用户真实权限重查，拒绝、超时、失败均落 `ai_audit_records` 审计；
3. 模型供应商密钥经 `ai_provider_secrets` AES-256-GCM 加密存储，永不回传前端，本文档及 Agent 输出均不含任何密钥；
4. 本地默认模型链路：Ollama（MIT 许可证）+ Qwen2.5（Apache-2.0 许可证），符合项目宽松许可证要求；
5. 知识类输出与模拟类输出必须带"非当前运行事实 / 不代表未来确定结果"声明；置信度分级（LOW/MEDIUM/HIGH_CONFIDENCE）仅依据确定性指标（如攻击链步数）。

## 9. 关联文档

- [阶段7任务书：AI 安全运营中心](tasks/STAGE_7_AI_SECURITY_OPERATIONS.md)
- [架构设计](ARCHITECTURE.md)
- [数据库设计](DATABASE_DESIGN.md)
- [接口设计](API_DESIGN.md)
- [安全设计](SECURITY_DESIGN.md)
- [RBAC 权限设计](RBAC_DESIGN.md)
- [监控告警设计（阶段6）](MONITORING_ALERTING_DESIGN.md)
- [备份恢复设计](BACKUP_RESTORE_DESIGN.md)
- [WAF 策略设计](WAF_POLICY_DESIGN.md)
- [审计设计](AUDIT_DESIGN.md)
- [开源合规](OPEN_SOURCE_COMPLIANCE.md)
