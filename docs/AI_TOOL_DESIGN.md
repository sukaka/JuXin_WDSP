# AI Tool 设计（阶段7）

本文档描述九章 WAF V2.0 阶段7（AI 安全运营中心）的 Tool 工具体系设计，与实现代码严格一致：

- Tool 契约与注册中心：`server/internal/aitools/registry.go`
- 只读 Tool：`server/internal/aitools/event_tools.go`（安全事件）、`log_tools.go`（日志/链路）、`asset_tools.go`（资产与策略）、`access_tools.go`（访问控制与统计）
- 草稿 Tool：`server/internal/aitools/draft_tools.go`（生成）、`draft_store.go`（查询/废弃）
- 装配与启停检查：`server/internal/app/app.go`、`server/internal/aihandlers/agents_tools_handler.go`
- 审计实现：`server/internal/aiaudit/aiaudit.go`
- 表结构：`server/migrations/000013_stage7.up.sql`（`ai_tools` / `ai_tool_calls` / `ai_recommendations` 等）

## 1. 设计目标与安全底线

1. 阶段7只允许两类风险等级的 Tool：`READ_ONLY`（只读查询）与 `DRAFT_ONLY`（只生成草稿）；任务书中定义的 `REQUIRES_CONFIRMATION` / `PROHIBITED` 两级在阶段7不开放注册（`registry.go` 仅声明 `RiskReadOnly` / `RiskDraftOnly` 两个常量）。任何最终生产操作必须进入既有人工确认/发布流程。
2. **草稿 DRAFT 不生效**：草稿 Tool 写入的业务对象一律默认停用（`DISABLED`）或草稿（`DRAFT`）状态，名称带 `[AI草稿]` 前缀，AI 侧不提供任何"接受/发布/直接生效"路径。
3. 权限每次执行前以当前用户真实权限点重新校验，不缓存、不委托模型判断。
4. Tool 可被管理面单独停用，执行路径实时查库，停用立即生效。
5. 全部 Tool 调用留痕（状态、耗时、入参摘要、错误码），审计记录写入哈希链，密钥/密码/私钥等敏感信息不进入审计正文。
6. 不静默吞错：权限不足、停用、超时、执行失败均返回明确错误并落审计。

## 2. Tool 统一契约与元数据

### 2.1 Tool 接口

所有 Tool 实现 `aitools.Tool` 接口（`registry.go`），方法即元数据契约：

| 方法 | 含义 | 说明 |
|------|------|------|
| `Code()` | Tool 编码 | 全局唯一，点分命名（如 `security_event.search`），即 `ai_tools.code` |
| `Name()` | 名称 | 中文展示名 |
| `Description()` | 功能说明 | 供模型选择 Tool 与人工查阅 |
| `Version()` | 版本 | 当前均为 `1.0` |
| `RiskLevel()` | 风险等级 | `READ_ONLY` / `DRAFT_ONLY` |
| `RequiredPermission()` | 所需权限点 | 空字符串表示仅需登录；当前全部 Tool 均声明了权限点 |
| `TimeoutSeconds()` | 超时秒数 | 执行超时上限；≤0 时执行管线回退默认 30s |
| `MaxResults()` | 最大返回数量 | 元数据声明值（详见 §3.4 现状说明） |
| `InputSchema()` | 输入 JSON Schema | `{"type":"object","properties":{...}}`，由 `obj()`/`sch()` 简写构造 |
| `Run(ctx, input)` | 执行 | 入参为 JSON（`json.RawMessage`），出参为可 JSON 序列化结构 |

元数据通过内嵌 `baseTool`（持有 `toolMeta`）提供，各 Tool 只需声明元数据并实现 `Run`：

```text
Tool（接口）
 └── baseTool（元数据基座：Code/Name/.../InputSchema 全部委托 toolMeta）
      ├── eventSearch / eventGet / eventRelated / eventStats / eventDisposition   （event_tools.go）
      ├── acEventSearch / auditSearch / requestTrace / systemLogSearch            （log_tools.go）
      ├── appSearch / appGet / certMeta / gatewayStatus / policyGet
      │    / ruleSearch / ruleGet / exceptionSearch                               （asset_tools.go）
      ├── accessRuleSearch / tempBlockSearch / ccPolicySearch / trustedProxySummary
      │    / securityOverview / attackTrend / topSourceIPs / topRules / runtimeStats（access_tools.go）
      └── draftException / draftBlacklist / draftCCPolicy / draftCustomRule
           / draftReportSummary                                                   （draft_tools.go）
```

### 2.2 统一错误

`registry.go` 声明的哨兵错误：

| 错误 | 触发场景 |
|------|----------|
| `ErrToolNotFound` | 编码未注册 |
| `ErrToolDisabled` | 管理面（`ai_tools.status`）已停用 |
| `ErrPermission` | 调用者缺少 `RequiredPermission` 声明的权限点 |
| `ErrInvalidInput` | 入参 JSON 非法或字段校验失败（各 Tool `Run` 内复用） |
| `ErrTimeout` | `Run` 超过超时上限（`context.DeadlineExceeded`） |
| `ErrTooManyResults` | 已声明预留，当前执行管线未触发（各 Tool 以 `LIMIT` 自控返回量） |

### 2.3 调用者身份（Principal）

```text
Principal { UserID uuid, Username string, Permissions map[string]bool }
HasPermission(perm)：perm 为空或无该权限点返回 false
```

`Principal` 由编排器/处理器基于当前登录用户的真实权限构造，`Registry.Execute` 每次执行前调用 `HasPermission` 重新校验——即使 Agent 规划阶段已选定 Tool，执行时仍独立检查，防止越权调用。

### 2.4 元数据与管理面表 ai_tools

代码 registry 是能力来源，`ai_tools` 表（迁移 `000013_stage7.up.sql`）存启停与配置：

| 列 | 类型 | 说明 |
|----|------|------|
| id | UUID PK | - |
| code | VARCHAR(100) UNIQUE | 与 `Tool.Code()` 一致 |
| name / description | VARCHAR(100) / VARCHAR(500) | 展示用 |
| version | VARCHAR(20)，默认 `1.0` | - |
| risk_level | VARCHAR(20)，默认 `READ_ONLY` | `READ_ONLY` / `DRAFT_ONLY` |
| required_permission | VARCHAR(100)，默认 `''` | 权限点 |
| input_schema / output_schema | JSONB | 输入由代码同步；输出 schema 当前未填充（`'{}'`） |
| timeout_seconds | INTEGER，默认 30 | 见 §3.4 现状说明 |
| max_results | INTEGER，默认 100 | 同上 |
| status | VARCHAR(20)，默认 `ENABLED` | `ENABLED` / `DISABLED` |

启动时 `aihandlers.SyncRegistry`（`app.go` 启动流程调用）将代码 registry 元数据按 `code` upsert 进 `ai_tools`（`ON CONFLICT (code) DO UPDATE`），保留既有 `status` 启停状态；管理面列表为 DB 数据左联代码 registry。

## 3. Registry 执行管线

### 3.1 调用路径

Tool 不直接暴露 HTTP 接口，统一由编排器内 Agent 经 `ToolContext.CallTool`（`server/internal/aiorchestrator/orchestrator.go`）发起，最终进入 `Registry.Execute`：

```text
用户消息/分析请求
  → Orchestrator（意图识别、任务规划、调度 Agent）
    → Agent.Analyze 内需要事实数据时
      → ToolContext.CallTool(code, input)
        → Registry.Execute(ctx, principal, taskID, agentRunID, code, input, auditor)
```

### 3.2 Execute 管线

`Registry.Execute` 按固定顺序执行（`registry.go`）：

```text
┌──────────────────────────────────────────────────────────────┐
│ 1. 查找 Tool：code 未注册 → ErrToolNotFound（不审计）          │
├──────────────────────────────────────────────────────────────┤
│ 2. 启停检查：EnabledChecker 实时查 ai_tools.status，           │
│    DISABLED → ErrToolDisabled（不审计）                        │
├──────────────────────────────────────────────────────────────┤
│ 3. 构造 AuditRecord：tool_code/version/risk_level +            │
│    InputSummary（入参截断 400 字符）                            │
├──────────────────────────────────────────────────────────────┤
│ 4. 权限校验：RequiredPermission 非空且用户无该权限点            │
│    → 审计 DENIED/PERMISSION_DENIED → ErrPermission            │
├──────────────────────────────────────────────────────────────┤
│ 5. 超时控制：context.WithTimeout(TimeoutSeconds，≤0 回退 30s)  │
├──────────────────────────────────────────────────────────────┤
│ 6. 执行 t.Run(ctx, input)：                                    │
│    - 正常返回        → 审计 SUCCESS                            │
│    - DeadlineExceeded → 审计 TIMEOUT  → ErrTimeout             │
│    - 其他错误        → 审计 FAILED/RUN_ERROR → 返回原始错误     │
└──────────────────────────────────────────────────────────────┘
```

审计状态枚举：`SUCCESS / FAILED / TIMEOUT / DENIED`。每次执行（含被拒绝的 DENIED）都产生一条审计记录，记录耗时（毫秒）、错误码与入参摘要；`auditor` 为 nil 时跳过审计写入（防御性分支，生产装配恒非 nil）。审计写入失败不阻断 Tool 结果返回（`RecordToolCall` 返回错误被忽略）。

### 3.3 启停检查（EnabledChecker）

`Registry.SetEnabledChecker` 在启动时装配一次（`app.go`），实现为 `aihandlers.ToolEnabledChecker`：执行路径每次实时 `SELECT status FROM ai_tools WHERE code=$1`，仅 `ENABLED` 放行；查无记录（未入库）默认启用。管理面 `PATCH /api/v1/ai/tools/{id}`（权限 `ai.tools.manage`）停用后，下一次调用即被 `ErrToolDisabled` 拒绝，无需重启。

### 3.4 超时与最大返回数现状说明

- 超时：`Execute` 使用代码 registry 中声明的 `TimeoutSeconds()`（≤0 回退 30s）包裹 `context.WithTimeout`；DB 中 `ai_tools.timeout_seconds` 可由 `ToolPatch` 修改（1–300s），当前执行管线不读取该值，以代码声明为准。
- 最大返回数：`MaxResults()` 为元数据声明并同步入库；实际返回量由各 Tool `Run` 内的 SQL `LIMIT` 与分页自控（查询类固定每页 20 条，统计类 `LIMIT 20/30/50` 等，均不超过各自 `max_results` 声明值）。`ToolPatch` 对 `max_results` 的修改（1–1000）同样仅落库，不改变运行行为。

## 4. 只读 Tool 清单（READ_ONLY）

共 26 个只读 Tool，全部版本 `1.0`。时间范围统一经 `parseTimeRange` 校验：RFC3339 格式、默认最近 24 小时、`start_time` 必须早于 `end_time`、最大跨度 90 天；分页参数 `page` 从 1 开始。所有 SQL 使用参数化查询，IP 过滤按 `::inet` 转换。

### 4.1 安全事件 Tool（event_tools.go，5 个）

权限点均为 `security_events.read`。

| code | 名称 | 超时/上限 | 输入要点 | 数据来源与说明 |
|------|------|-----------|----------|----------------|
| `security_event.search` | 安全事件查询 | 20s / 50 | 时间范围、attack_type、severity、client_ip、action、rule_id、page | `security_events`（rule_id 经 `security_event_matches` 子查询），每页 20 条，按 `occurred_at DESC` |
| `security_event.get` | 安全事件详情 | 10s / 1 | event_id | 事件全字段 + 匹配规则（`security_event_matches` 最多 20 条），匹配载荷 `data` 经 `audits.MaskSensitiveJSON` 脱敏 |
| `security_event.related` | 关联事件 | 15s / 20 | event_id | 同 `request_id` 的其他事件，最多 20 条 |
| `security_event.statistics` | 事件统计 | 30s / 100 | 时间范围、dimension（attack_type/severity/action/client_ip/application） | 维度白名单映射列表达式，非法维度报 `ErrInvalidInput`；每组 Top 20 |
| `security_event.disposition_summary` | 事件处置摘要 | 15s / 10 | 时间范围 | 按 `disposition_status` 分组计数 |

### 4.2 日志与链路 Tool（log_tools.go，4 个）

| code | 名称 | 权限点 | 超时/上限 | 数据来源与说明 |
|------|------|--------|-----------|----------------|
| `access_control_log.search` | 访问控制/CC事件查询 | `access_control_events.read` | 20s / 50 | `access_control_events`；按 event_type/client_ip/policy_id/request_id 过滤，每页 20 条 |
| `audit_log.search` | 操作审计查询 | `audits.read` | 20s / 50 | `operation_audits`；按 username/module/action 过滤 |
| `request_trace.get` | Request ID 链路追踪 | `security_events.read` | 15s / 30 | 按 `request_id` 聚合 `security_events`（≤10）与 `access_control_events`（≤10）两侧链路 |
| `system_log.search` | 系统告警查询 | `system_alerts.read` | 15s / 50 | `system_alerts`，按 `last_seen_at` 时间窗过滤（alert_type/severity/status），最多 30 条 |

### 4.3 资产与策略 Tool（asset_tools.go，8 个）

| code | 名称 | 权限点 | 超时/上限 | 数据来源与说明 |
|------|------|--------|-----------|----------------|
| `application.search` | 应用查询 | `applications.read` | 15s / 50 | `applications`（未删除），keyword 对 code/name 模糊匹配，每页 20 条 |
| `application.get` | 应用详情 | `applications.read` | 10s / 1 | 应用 + 域名（`application_domains`）+ 源站（`upstreams`） |
| `certificate.get_metadata` | 证书元数据 | `certificates.read` | 10s / 50 | `certificates` 元数据（不含私钥），支持 `expiring_days` 到期过滤，附 `days_remaining` |
| `gateway.get_status` | 网关状态 | `gateway_status.read` | 15s / 1 | 当前配置版本（`gateway_config_versions.is_current`）+ 应用/域名/源站计数；无已发布配置时返回 `online=false` |
| `policy.get` | 防护策略查询 | `protection_policies.read` | 10s / 50 | `protection_policies`（`ACTIVE` 未删除），含内置模板，返回防护模式/PL/出入站阈值 |
| `rule.search` | WAF规则查询 | `waf_rules.read` | 20s / 50 | `waf_rules`（CRS 与自定义），按 rule_id/keyword/attack_type 过滤 |
| `rule.get` | WAF规则详情 | `waf_rules.read` | 15s / 1 | 规则详情 + 命中数（`security_event_matches`）+ 已确认误报数（`disposition_status='CONFIRMED_FALSE_POSITIVE'`） |
| `exception.search` | 例外策略查询 | `exceptions.read` | 15s / 50 | `exception_policies`（未删除），按 status/scope_type 过滤 |

### 4.4 访问控制与统计 Tool（access_tools.go，9 个）

| code | 名称 | 权限点 | 超时/上限 | 数据来源与说明 |
|------|------|--------|-----------|----------------|
| `access_rule.search` | 黑白名单查询 | `access_rules.read` | 15s / 50 | `ip_access_rules`，按 rule_type（ALLOW/DENY）/scope_type/status 过滤，按 priority 排序 |
| `temporary_block.search` | 临时封禁查询 | `temporary_blocks.read` | 15s / 50 | `temporary_blocks`，按 status/client_ip 过滤 |
| `rate_limit_policy.search` | CC策略查询 | `rate_limits.read` | 15s / 50 | `rate_limit_policies`，按 scope_type/status/action 过滤 |
| `trusted_proxy.get_summary` | 可信代理摘要 | `trusted_proxies.read` | 10s / 10 | `trusted_proxies` 总数与 `ENABLED` 数 |
| `statistics.security_overview` | 安全概览统计 | `analytics.security.read` | 30s / 1 | 今日（UTC 零点起）请求量（`metric_minute_aggregates`）、WAF 事件/阻断、CC 事件、黑名单命中、生效中临时封禁、未处置高危事件 |
| `statistics.attack_trend` | 攻击趋势统计 | `analytics.security.read` | 30s / 200 | `date_trunc(hour|day)` 时间桶事件数与阻断数序列 |
| `statistics.top_source_ips` | 攻击源IP排行 | `analytics.security.read` | 30s / 20 | limit 默认 10（1–50），含事件数与阻断数 |
| `statistics.top_rules` | 规则命中排行 | `analytics.security.read` | 30s / 20 | 规则命中与误报（`CONFIRMED_FALSE_POSITIVE`）排行 |
| `statistics.runtime` | 运行统计 | `dashboard.runtime.read` | 20s / 20 | 各组件最新健康快照（`system_health_snapshots`）+ 近 30 天发布任务成功率（`gateway_publish_tasks`） |

## 5. 草稿 Tool 清单（DRAFT_ONLY）

共 5 个草稿 Tool（`draft_tools.go`），版本 `1.0`，超时均 15s，`max_results=1`。统一行为：

- 业务对象名称加 `[AI草稿] ` 前缀，默认 `DISABLED`/`DRAFT` 状态；
- 同步在 `ai_recommendations` 落一条推荐记录（`DraftStore.RecordRecommendation`）：`status='DRAFT'`、`created_by_ai=TRUE`，记录来源 `task_id`（可选）、摘要、证据引用列表（`evidence`，单条 ≤200 字符）、风险等级与 `draft_reference`（`类型:UUID` 回链业务对象）；
- 返回 `{draft_id, recommendation_id, status:"DRAFT", message}`，message 明确提示需人工审核启用。

| code | 名称 | 权限点 | 落库表（默认状态） | draft_reference | 关键校验与默认值 |
|------|------|--------|--------------------|-----------------|------------------|
| `draft.exception.create` | 例外策略草稿 | `ai.draft.exception` | `exception_policies`（`DISABLED`） | `exception:{id}` | 经 `exceptions.Store.Create` 创建（复用阶段4仓储校验）；`IsBroad()` 为真即拒绝——草稿必须为精确例外（应用/域名/URI/规则ID/参数至少其一）；按 rule_ids/attack_types 推导 `REMOVE_RULE`/`REMOVE_RULE_TAG`；临时例外 `duration_hours` 必填且 1–720 |
| `draft.blacklist.create` | 黑名单草稿 | `ai.draft.blacklist` | `ip_access_rules`（`DRAFT`，`validity_type=TEMPORARY`，`source_type=MANUAL`） | `access_rule:{id}` | 地址经 `accessrules.NormalizeAddress` 严格规范化（仅单 IP/CIDR）；命中保护地址（`ProtectedChecker.IsProtected`）直接拒绝；`duration_hours` 默认 24、上限 720 |
| `draft.cc_policy.create` | CC策略草稿 | `ai.draft.cc_policy` | `rate_limit_policies`（`DISABLED`） | `rate_limit_policy:{id}` | dimension 枚举校验（CLIENT_IP/APPLICATION/CLIENT_IP_AND_URI/CLIENT_IP_AND_APPLICATION）；requests_limit 1–1000000、window_seconds 1–86400；action 默认 `OBSERVE`（此时 `observe_only=true`）；`TEMP_BLOCK` 要求 block_duration_seconds 60–2592000 |
| `draft.custom_rule.create` | 自定义规则草稿 | `ai.draft.custom_rule` | `custom_rules`（`DISABLED`，`scope_type=GLOBAL`） | `custom_rule:{id}` | rule_id 限定 7100000–7199999（自定义号段）；经 `customrules.ValidateInput` 生成 `generated_rule`（操作符白名单校验）；标签固定 `jiuzhang/custom/ai-draft`；severity 默认 `WARNING`、action 默认 `OBSERVE` |
| `draft.report_summary.create` | 报告总结草稿 | `ai.report_summary.use` | 仅 `ai_recommendations`（不产生业务配置） | `ai_summary:{uuid}` | summary 20–8000 字符；与固定模板报告分开保存，返回 `ai_assisted=true`，可人工编辑 |

草稿记录的风险等级（`ai_recommendations.risk_level`）：例外/CC策略 `MEDIUM`，黑名单/自定义规则 `HIGH`，报告总结 `LOW`。

## 6. 草稿 DRAFT 不生效原则

```text
AI 草稿 Tool（DRAFT_ONLY）
  → 业务对象：[AI草稿] 前缀 + DISABLED/DRAFT（网关配置不含该对象，不生效）
  → ai_recommendations：DRAFT 记录（证据、来源任务、回链）
        │
        ├─ 人工废弃：POST /api/v1/ai/drafts/{id}/discard → REJECTED（逻辑废弃，不删除）
        │
        └─ 人工采纳：到对应业务页面人工核对 → 启用/发布
             （例外策略 / IP黑白名单 / CC防护 / 自定义规则 各自既有流程，
               含既有的校验、审计与配置发布管线）
```

- AI 侧不提供"接受/发布"接口：`DraftStore` 仅有 `List` / `Get` / `Discard` 三个方法；`Discard` 仅允许 `DRAFT`/`PENDING_REVIEW` → `REJECTED`，记录审核人与时间，不删除记录（`draft_store.go` 包注释明确"任何'接受/发布'均不在此处生效"）。
- 草稿 Tool 入参中的 `task_id` 仅作来源登记，AI 不能通过构造输入绕过上述状态约束——所有状态值由服务端代码写死，不接受入参控制。
- 黑名单草稿即便内容为 DENY 规则，也因 `status='DRAFT'` 不参与网关配置生成；保护地址检查在草稿阶段即拦截，双重防线。

草稿管理接口（`aihandlers/handler.go`，持有任一草稿权限 `ai.draft.exception` / `ai.draft.blacklist` / `ai.draft.cc_policy` / `ai.draft.custom_rule` 即可访问）：

| 接口 | 说明 |
|------|------|
| `GET /api/v1/ai/drafts` | 草稿分页列表（recType/status 过滤） |
| `GET /api/v1/ai/drafts/{id}` | 草稿详情（含证据引用） |
| `POST /api/v1/ai/drafts/{id}/discard` | 逻辑废弃草稿 |

## 7. Tool 调用记录与审计

### 7.1 ai_tool_calls 表

迁移 `000013_stage7.up.sql` 定义了 `ai_tool_calls` 表：

| 列 | 类型 | 说明 |
|----|------|------|
| id | UUID PK | - |
| task_id | UUID NOT NULL → `ai_tasks(id)` | 来源任务，级联删除 |
| agent_run_id | UUID | 来源 Agent 运行（可空） |
| tool_id | VARCHAR(100) | Tool 编码 |
| tool_version | VARCHAR(20)，默认 `1.0` | - |
| risk_level | VARCHAR(20)，默认 `READ_ONLY` | - |
| input_summary | VARCHAR(500) | 入参摘要 |
| output_reference | VARCHAR(100) | 输出引用 |
| status | VARCHAR(20)，默认 `SUCCESS` | `SUCCESS / FAILED / TIMEOUT / DENIED` |
| duration_ms | INTEGER | 耗时 |
| error_code | VARCHAR(50) | 错误码 |
| created_at | TIMESTAMPTZ | - |

实现现状说明：该表已建（含 `(task_id, created_at)` 索引），但当前代码无写入路径——Tool 调用记录经审计链路写入 `ai_audit_records`（见 §7.2），`ai_tool_calls` 为预留表。

### 7.2 审计链路（aiaudit）

`Registry.Execute` 通过 `aitools.Auditor` 接口回调审计，由 `aiaudit.Service.RecordToolCall` 实现：

- 每次调用（含 DENIED）在 `ai_audit_records` 写入一条 `action='tool_call'` 记录：`tool_code`、`request_summary`（入参摘要）、`result_summary`（`status=... err=...`）、`duration_ms`，并返回输出引用 `toolcall:{code}:{8位hex}`；
- 审计表为哈希链结构：`previous_hash` / `record_hash`（SHA-256，内容含发生时间/用户名/动作/对象/前序哈希），写入经 advisory lock 串行化，可用 `VerifyChain` 校验完整性；
- 脱敏：审计正文写入前经敏感词遮蔽（`api_key` / `password` / `secret` / `private_key` / `token` 等关键词命中的长串按 `前6位+***` 遮蔽）并按长度截断；入参摘要在 `Registry` 侧先截断 400 字符。不保存模型思维链与敏感信息。

管理面查询：`GET /api/v1/ai/audits` 与 `POST /api/v1/ai/audits/verify`（链校验），权限 `ai.audits.read`。

### 7.3 证据引用

草稿 Tool 的 `evidence` 入参（字符串数组，单条 ≤200 字符）落入 `ai_recommendations.evidence_references`（JSONB），供人工审核时回溯事件 ID、规则 ID、Request ID 等事实来源；该列表由 AI 生成内容声明，不构成生效依据。

## 8. 第三方组件许可说明

Tool 层本身不直接依赖模型；模型接入层（`server/internal/aimodel`）以 OpenAI 兼容协议对接本地/远端推理端点（含 `ollama` 供应商类型）。相关组件许可证：Ollama（MIT）、Qwen2.5 系列模型（Apache-2.0），均符合项目宽松许可证要求。详见 [开源合规](OPEN_SOURCE_COMPLIANCE.md)。

## 9. 关联文档

- [阶段7任务书](tasks/STAGE_7_AI_SECURITY_OPERATIONS.md)（Tool 工具体系与数据表需求来源）
- [AI 编排器设计](AI_ORCHESTRATOR_DESIGN.md)（Tool 调用方与任务限额）
- [AI Tool 安全设计](AI_TOOL_SECURITY.md)（注入防护与脱敏策略）
- [AI 审计设计](AI_AUDIT_DESIGN.md)（审计哈希链）
- [AI 模型网关设计](AI_MODEL_GATEWAY.md)（模型接入层）
- [架构设计](ARCHITECTURE.md)
- [数据库设计](DATABASE_DESIGN.md)
- [接口设计](API_DESIGN.md)
- [RBAC 设计](RBAC_DESIGN.md)（权限点体系）
- [审计设计](AUDIT_DESIGN.md)
- [WAF 策略设计](WAF_POLICY_DESIGN.md)（例外策略与自定义规则人工流程）
- [IP 访问控制设计](IP_ACCESS_CONTROL_DESIGN.md)（黑白名单与保护地址）
- [限流设计](RATE_LIMIT_DESIGN.md)（CC 防护策略）
- [监控告警设计](MONITORING_ALERTING_DESIGN.md)（`statistics.runtime` / `system_log.search` 数据来源）
- [开源合规](OPEN_SOURCE_COMPLIANCE.md)
