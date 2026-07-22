# AI 成本控制设计（阶段7）

本文档描述九章 WAF V2.0 AI 安全运营中心的用量与成本控制设计，与实现代码严格一致：

- 配额与用量记录：`server/internal/aicost/aicost.go`
- 用量统计接口：`server/internal/aihandlers/usage_handler.go`
- 表结构：`server/migrations/000013_stage7.up.sql`（`ai_usage_records`、`ai_models`）
- 权限与种子：`server/migrations/000014_seed_stage7_perms.up.sql`、`server/migrations/000015_seed_stage7_model.up.sql`
- 接线：`server/internal/app/app.go`（`aicost.NewRecorder(db, aicost.DefaultQuotas())`）

## 1. 设计目标与原则

1. **服务端强制**：配额在服务端按真实用户、角色统计，不依赖前端计数（`aicost` 包注释即为此约束），前端任何计数展示都不作为放行依据；
2. **超限拒新不扰旧**：配额超限只拒绝新的 AI 请求，已建立的任务不受影响，且 AI 模块超限完全不影响 WAF 核心防护功能；
3. **本地零成本**：默认部署使用本地 Ollama 模型，单价为 0，成本记 0；接入外部计费模型时按 `ai_models` 单价字段计价；
4. **不静默吞错**：用量/审计落库失败记 `slog.Error` 日志，但不阻断已完成的对话主流程。

## 2. 总体链路

```text
用户请求（对话/分析）
   │
   ├─ 认证 + 权限点校验（如 ai.chat.use）
   ├─ Token 估算：est = EstimateTokens(content) + 512
   ├─ aicost.CheckQuota ── 超限 ──→ 429 RATE_LIMITED（不落用量）
   │        │ 通过
   ├─ 编排器执行（aiorchestrator.Run）
   ├─ aicost.RecordUsage → INSERT ai_usage_records（独立短超时 ctx）
   └─ 写 AI 审计（aiaudit，含 input/output tokens）

统计侧：
ai_usage_records ─┬─ Recorder.Overview → GET /api/v1/ai/usage/overview
                  └─ Recorder.ByUser   → GET /api/v1/ai/usage/by-user
```

## 3. 配额模型

### 3.1 配额维度与默认值

配额配置为 `aicost.Quotas` 结构，启动时由 `DefaultQuotas()` 注入（当前为代码常量，无管理面配置入口）：

| 字段 | 默认值 | 含义 |
|------|--------|------|
| `UserDailyTokens` | 200000 | 用户每日 Token（输入+输出合计） |
| `RoleDailyTokens` | 500000 | 角色每日 Token（输入+输出合计） |
| `PerRequestTokens` | 12000 | 单次请求输入 Token 上限 |
| `MaxToolCalls` | 20 | 单次任务 Tool 调用上限（见 §3.4） |
| `ConcurrentTasks` | 10 | 并发任务上限（见 §3.4） |
| `HighCostTaskDaily` | 20 | 高成本任务每日次数（见 §3.4） |

### 3.2 CheckQuota 检查顺序与统计口径

`Recorder.CheckQuota(ctx, userID, roleCode, estimatedInput)` 按固定顺序检查，任一不通过即返回包装后的 `ErrQuotaExceeded`：

1. **单次输入上限**：`estimatedInput > PerRequestTokens` 直接拒绝（错误信息含实际值与上限）；
2. **用户每日配额**：统计 `ai_usage_records` 中该 `user_id` 当日 `SUM(input_tokens + output_tokens)`，加上本次 `estimatedInput` 后超过 `UserDailyTokens` 则拒绝；
3. **角色每日配额**：按 `roleCode` 经 `users → user_roles → roles` 联表汇总该角色全体用户当日 Token，加上 `estimatedInput` 后超过 `RoleDailyTokens` 则拒绝。

口径说明：

- "当日"按 **UTC 自然日**切分（`time.Now().UTC().Truncate(24h)`），不是北京时间零点；
- 日用量统计包含输入与输出 Token 之和（`COALESCE(SUM(...), 0)`），与 `RecordUsage` 的写入口径一致；
- `roleCode` 取当前用户首个角色编码（`firstRole(p) = p.Roles[0]`，无角色时为空串，角色段查询命中 0 行按 0 计）；
- 检查为"已用量 + 本次估算"的事前预判，通过后才真正执行。

### 3.3 配额检查生效范围

`CheckQuota` 在两个入口强制执行，估算值均为 `EstimateTokens(用户输入) + 512`（512 为系统提示与编排开销的固定余量）：

| 入口 | 覆盖接口 | 权限点 |
|------|----------|--------|
| `chat_handler.go runStream` | `POST /api/v1/ai/sessions/{id}/messages`、`.../retry`、`.../continue` | `ai.chat.use` |
| `analyze_handler.go runAnalyze` | `POST /api/v1/ai/analyze/{event|false-positive|attack-profile|attack-chain|policy-recommendation|what-if|root-cause|report-summary}` | 各分析对应 `ai.*.use` |

评估运行（`POST /api/v1/ai/evaluations/run`）当前**不做**事前配额检查，仅在结束后归集用量（见 §8）。

### 3.4 已声明未强制的配额维度（现状说明）

`Quotas` 中 `MaxToolCalls` / `ConcurrentTasks` / `HighCostTaskDaily` 三个字段已声明并赋默认值，但 `CheckQuota` 当前不引用它们，代码中亦无其他检查点。编排层的 `aiorchestrator.TaskLimits`（`DefaultLimits()`：MaxAgents 4、MaxToolCalls 20、MaxDuration 120s、MaxInputTokens 12000、MaxOutputTokens 4096）当前实际生效的只有 `MaxDuration`（任务整体超时）与 `MaxAgents`（单任务 Agent 数上限），其余为保留字段。本文档按实现现状记录，后续版本补强时以代码为准更新。

## 4. 用量记录（ai_usage_records）

### 4.1 表结构

`ai_usage_records`（迁移 000013），每次 AI 调用一行：

| 列 | 类型 | 说明 |
|----|------|------|
| `id` | UUID PK | 默认 `gen_random_uuid()` |
| `user_id` | UUID NOT NULL | 发起用户 |
| `session_id` | UUID NULL | 关联会话（对话/一次性分析/评估会话） |
| `task_id` | UUID NULL | 关联编排任务（评估运行为 NULL） |
| `model_id` | UUID NULL | 模型（当前各记录点均传 NULL） |
| `input_tokens` | INTEGER | 输入 Token（估算值） |
| `output_tokens` | INTEGER | 输出 Token（估算值） |
| `tool_calls` | INTEGER | Tool 调用数（当前各记录点均传 0，见 §4.2） |
| `estimated_cost` | NUMERIC(12,8) | 估算成本（本地模型记 0） |
| `created_at` | TIMESTAMPTZ | 默认 `now()` |

索引：`idx_ai_usage_user_time (user_id, created_at DESC)`（按用户日统计）、`idx_ai_usage_time (created_at DESC)`（全量日统计）。

### 4.2 记录点与记录内容

`Recorder.RecordUsage(ctx, userID, sessionID, taskID, modelID, inTok, outTok, toolCalls, cost)` 实现 `aiorchestrator.CostRecorder` 接口，当前有三个调用点，均在主流程结束后以**独立短超时 context** 落库（客户端断连不丢记录）：

| 记录点 | 文件 | task_id | tool_calls / cost |
|--------|------|---------|-------------------|
| 流式对话完成 | `chat_handler.go runStream` | `result.TaskID` | 0 / 0 |
| 一次性分析完成 | `analyze_handler.go runAnalyze` | `result.TaskID` | 0 / 0 |
| 评估运行完成 | `evaluations_handler.go EvalRun` | NULL | 0 / 0 |

设计决策：默认部署为本地零成本模型，记录时 `estimated_cost` 直接记 0（代码注释"本地模型单价为 0，成本记 0；Token 为估算值"）；`model_id`、`tool_calls` 列已在表结构与接口签名中预留，按用户/日期的配额与统计链路不依赖这两列即可运转。

### 4.3 Token 估算

`aiorchestrator.EstimateTokens(s)` 为粗估算：逐 rune 扫描，CJK 字符（`r > 0x2E7F`）按 2/3 Token 计、其余按 1/4 计，结果 +1。采用估算而非真实 tokenizer 的理由：本地模型无统一 tokenizer 依赖、估算口径在配额检查与用量记录两侧一致、偏差对日配额量级（20 万）不敏感。

### 4.4 记录失败策略

`RecordUsage` 失败仅 `slog.Error`（"record ai usage failed"），不向用户报错、不回滚已生成内容——用量丢失可事后从 AI 审计的 Token 字段旁证，而阻断对话会损害主流程可用性。该取舍符合"不静默吞错"底线：错误全部进入服务端日志。

## 5. 成本计价与模型单价配置

### 5.1 单价字段与计算公式

`ai_models` 表携带计费单价（迁移 000013，均 `NUMERIC(12,8) NOT NULL DEFAULT 0`）：

| 列 | 说明 |
|----|------|
| `cost_input_unit` | 每千输入 Token 成本 |
| `cost_output_unit` | 每千输出 Token 成本 |

计算公式实现于 `aimodel/client.go` 的 `ChatResult.UsageCost(m *Model)`：

```text
cost = input_tokens / 1000 × cost_input_unit + output_tokens / 1000 × cost_output_unit
```

### 5.2 本地模型零成本

种子数据（迁移 000015）注册本地供应商 `ollama-local`（`provider_type=ollama`，`base_url=http://ollama:11434`，无密钥）与默认模型 `qwen2.5:3b`（上下文 32768，`cost_input_unit=0`、`cost_output_unit=0`）。本地推理不产生货币成本，故单价为 0、用量记录成本为 0，成本控制的实际抓手是 §3 的 Token 配额（防本地算力被耗尽）而非预算。

第三方组件许可：Ollama 为 MIT 许可证，Qwen2.5 为 Apache-2.0 许可证，均符合项目宽松许可证要求（详见 docs/OPEN_SOURCE_COMPLIANCE.md）。

### 5.3 单价维护

接入外部计费模型时，单价经模型管理接口维护（权限 `ai.models.manage`，默认仅系统管理员持有）：

| 接口 | 说明 |
|------|------|
| `POST /api/v1/ai/models` | 创建模型，`cost_input_unit` / `cost_output_unit` 随请求提交 |
| `PUT /api/v1/ai/models/{id}` | 更新模型（含单价；不含状态与密钥） |
| `GET /api/v1/ai/models` | 列表回显单价字段（`ai.models.read`） |

入参经 `normalizeModel` 归一：负单价一律钳为 0，杜绝负成本记录。模型创建/更新均写 AI 审计（`model_create` 等 action）。

## 6. 用量统计接口

两个只读接口（`usage_handler.go`），权限点均为 `ai.usage.read`（种子授予安全管理员、系统管理员、审计管理员三个角色）：

| 接口 | 内容 | 响应 |
|------|------|------|
| `GET /api/v1/ai/usage/overview` | 今日总览：输入/输出 Token、模型调用次数（用量行数）、Tool 调用次数、成本合计（UTC 当日） | `{"usage": {today_input_tokens, today_output_tokens, today_model_calls, today_tool_calls, today_cost}}` |
| `GET /api/v1/ai/usage/by-user` | 按用户统计近 7 天：输入/输出 Token、调用次数、成本，按成本降序取前 20 | `{"items": [{username, input_tokens, output_tokens, model_calls, cost}]}` |

前端经 `web/src/api/ai.ts` 的 `overview()` / `byUser()` 消费这两个接口。所有聚合在 SQL 侧完成（`SUM`/`COUNT` + `COALESCE`），空结果返回 0 而非 NULL。

## 7. 超限行为（429）

任一配额维度超限：

- HTTP 状态 `429 Too Many Requests`，错误码 `RATE_LIMITED`（`response.CodeRateLimited`）；
- 统一提示文案："AI 用量配额超限，请明日再试或联系管理员"——明确恢复时间（UTC 次日）与处置路径；
- 请求在执行前被拒绝：不创建任务、不调用模型、**不写入** `ai_usage_records`（被拦截的请求不占配额）；
- 与全局限流中间件（`middleware/ratelimit.go`，同错误码、文案为"请求过于频繁，请稍后重试"）相互独立：前者按 AI Token 配额，后者按请求频率。

非配额类错误（如数据库异常）走 `response.InternalError`，不返回 429。

## 8. 评估运行的用量归集

评估运行（`POST /api/v1/ai/evaluations/run`，权限 `ai.evaluations.run`）串行执行评估集全部用例，用量**聚合后一次性归集**：

1. 创建标题为 `[评估运行] {评估集编码}` 的一次性会话（用完即删，不污染会话列表）；
2. 逐用例累加 `inTok += EstimateTokens(question)`、`outTok += EstimateTokens(answer)`；
3. 运行结束调用一次 `RecordUsage(userID, sessionID=评估会话, taskID=nil, modelID=nil, inTok, outTok, 0, 0)`——整个评估运行计为一条用量记录；
4. 同时写 AI 审计（`action=evaluation_run`，含累计 Token 与得分摘要）。

因此评估用量计入发起用户的当日配额统计（§3.2 的用户/角色日额度按 `ai_usage_records` 汇总，评估记录同样在列），但评估运行本身当前不做事前 `CheckQuota` 拦截（见 §3.4 现状说明）。

## 9. 防绕过与安全要求

1. 配额统计完全基于服务端 `authz.Principal`（`p.UserID`、`p.Roles`）与数据库汇总，客户端提交的任何 Token/计数字段都不被信任；
2. 会话属主隔离（非属主 404）与配额统计正交：即使用户创建多个会话，用量仍归集到同一 `user_id` 统一限额；
3. 角色配额按角色编码联表汇总该角色全体用户，换会话、换入口（对话/分析/评估）均不可绕开；
4. 统计接口仅暴露聚合数据，不回显任何消息内容；模型密钥经 `ai_provider_secrets` 加密存储、任何接口不回传（单价字段可回显，密钥不可）；
5. 配额常量当前硬编码于 `DefaultQuotas()`，调整需改代码并重新发布，避免运行期被低权限账号篡改。

## 关联文档

- [阶段7任务书](tasks/STAGE_7_AI_SECURITY_OPERATIONS.md)（第二十七章 成本和配额控制）
- [架构设计](ARCHITECTURE.md)
- [数据库设计](DATABASE_DESIGN.md)
- [接口设计](API_DESIGN.md)
- [安全设计](SECURITY_DESIGN.md)
- [RBAC 设计](RBAC_DESIGN.md)（`ai.usage.read` 等权限点与角色授予）
- [AI 审计设计](AI_AUDIT_DESIGN.md)（审计记录携带 Token/成本字段，与用量链路互为旁证）
- [AI 质量评估体系指南](AI_EVALUATION_GUIDE.md)（评估运行的用量归集见本文 §8）
- [开源合规](OPEN_SOURCE_COMPLIANCE.md)（Ollama MIT、Qwen2.5 Apache-2.0）
- [开发状态](DEVELOPMENT_STATUS.md)
