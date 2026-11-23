# AI 审计设计（阶段7）

本文档描述九章 WAF V2.0 阶段7（AI 安全运营中心）的 AI 审计设计，与实现代码严格一致：

- 审计服务：`server/internal/aiaudit/aiaudit.go`（独立审计链路，哈希链完整性）
- 查询与校验接口：`server/internal/aihandlers/audits_handler.go`（路由注册见 `server/internal/aihandlers/handler.go`）
- 表结构：`server/migrations/000013_stage7.up.sql`（`ai_audit_records`）
- 权限种子：`server/migrations/000014_seed_stage7_perms.up.sql`（`ai.audits.read`）

AI 审计记录模型、Agent、Tool、Prompt、草稿与评估等 AI 相关操作的摘要信息；不保存模型私有思维链与敏感信息（密钥/密码/私钥/完整载荷，见 `aiaudit` 包注释）。底层模型运行时涉及第三方组件：本地推理默认使用 Ollama（MIT 许可证），默认模型 `qwen2.5:3b`（Qwen2.5，Apache-2.0 许可证）。

## 1. 设计目标与安全底线

1. AI 相关操作全程留痕：谁在何时对哪个会话/任务执行了什么动作、用了哪个模型/Prompt 版本、消耗多少 Token 与成本、结果如何；
2. 审计记录不可被静默篡改：全表构成一条哈希链，提供完整性校验接口；
3. 与操作审计（`operation_audits`）相互独立：独立表、独立链、独立串行化锁，互不影响；
4. 审计正文不含密钥材料：写入前强制脱敏与截断，模型 API 密钥绝不进入审计正文；
5. 审计失败不阻断业务：写审计失败只记错误日志，不影响 AI 主流程返回。

## 2. 表结构 ai_audit_records

`ai_audit_records`（迁移 000013，表注释：AI 审计，独立链路，复用哈希链思想）：

| 列 | 类型 | 说明 |
|----|------|------|
| id | UUID PK，默认 gen_random_uuid() | 记录主键 |
| occurred_at | TIMESTAMPTZ NOT NULL DEFAULT now() | 发生时间（写入时由服务层取 UTC 并截断到微秒） |
| user_id | UUID 可空 | 操作人用户 ID |
| username | VARCHAR(64) NOT NULL DEFAULT '' | 操作人用户名（进入哈希计算） |
| role_codes | VARCHAR(100) NOT NULL DEFAULT '' | 操作人角色编码（逗号拼接） |
| session_id | UUID 可空 | AI 会话 ID |
| task_id | UUID 可空 | AI 任务 ID（作为哈希计算的对象标识） |
| action | VARCHAR(40) NOT NULL | 动作（表注释示例：chat / tool_call / draft_create / model_test / prompt_publish / ...） |
| task_type | VARCHAR(40) NOT NULL DEFAULT '' | 任务类型 |
| agent_code | VARCHAR(50) NOT NULL DEFAULT '' | Agent 编码 |
| tool_code | VARCHAR(100) NOT NULL DEFAULT '' | Tool 编码 |
| model_code | VARCHAR(100) NOT NULL DEFAULT '' | 模型编码 |
| prompt_version | VARCHAR(20) NOT NULL DEFAULT '' | Prompt 版本号 |
| input_tokens | INTEGER NOT NULL DEFAULT 0 | 输入 Token |
| output_tokens | INTEGER NOT NULL DEFAULT 0 | 输出 Token |
| duration_ms | INTEGER NOT NULL DEFAULT 0 | 总耗时（毫秒） |
| estimated_cost | NUMERIC(12,8) NOT NULL DEFAULT 0 | 估算成本 |
| request_summary | VARCHAR(500) NOT NULL DEFAULT '' | 请求摘要（脱敏+截断后落库） |
| result_summary | VARCHAR(1000) NOT NULL DEFAULT '' | 结果摘要（脱敏+截断后落库） |
| draft_reference | VARCHAR(100) NOT NULL DEFAULT '' | 草稿引用 |
| confirm_result | VARCHAR(30) NOT NULL DEFAULT '' | 人工确认结果 |
| previous_hash | VARCHAR(64) NOT NULL DEFAULT '' | 上一条记录的 record_hash（链首为空串） |
| record_hash | VARCHAR(64) NOT NULL DEFAULT '' | 本记录哈希（SHA-256 十六进制，64 字符） |

索引：

| 索引 | 列 |
|------|----|
| idx_ai_audit_time | (occurred_at DESC) |
| idx_ai_audit_user | (user_id, occurred_at DESC) |
| idx_ai_audit_session | (session_id) |

## 3. 哈希链结构

### 3.1 哈希计算

`computeHash`（`aiaudit.go`）对每条记录计算：

```text
record_hash = SHA256_HEX( occurred_at(UTC, RFC3339Nano) | username | action | objectID | previous_hash )
```

- 五个字段以 `|` 连接后取 SHA-256，输出十六进制编码（64 字符）；
- `occurred_at` 由服务层取 `time.Now().UTC()` 并截断到微秒，按 UTC 的 RFC3339Nano 格式化，保证校验时可重放；
- `objectID` 取 `task_id`（无任务时为空串）；
- 链首记录的 `previous_hash` 为空串 `""`。

链式结构：

```text
┌─────────────┐   ┌─────────────┐   ┌─────────────┐
│ 记录 1       │   │ 记录 2       │   │ 记录 N       │
│ prev = ""   │──▶│ prev = H1   │──▶│ prev = H(N-1)│
│ hash = H1   │   │ hash = H2   │   │ hash = HN    │
└─────────────┘   └─────────────┘   └─────────────┘
  任意一条记录的 occurred_at/username/action/task_id
  或前后链接关系被篡改，VerifyChain 重算即出现 mismatch
```

### 3.2 串行化写入（pg_advisory_xact_lock 93847562）

`Service.Record` 在单个事务内完成「取链头 → 计算哈希 → 插入」：

```text
BEGIN
  → SELECT pg_advisory_xact_lock(93847562)          -- 事务级咨询锁，串行化所有并发写入
  → SELECT record_hash FROM ai_audit_records
      ORDER BY occurred_at DESC, id DESC LIMIT 1     -- 取链头（空表时 previous_hash = ""）
  → computeHash(...)                                 -- 计算本记录哈希
  → INSERT INTO ai_audit_records (...22 列...)
COMMIT                                               -- 锁随事务结束自动释放
```

设计决策：

- 使用 `pg_advisory_xact_lock`（事务级咨询锁）而非应用层互斥锁，保证同一数据库内多实例并发写入时链头读取与插入的原子性，不会产生分叉；
- 锁 ID 固定为 **93847562**，与操作审计 `operation_audits` 写入使用的 **93847561**（`server/internal/audits/audits.go`）明确区分，两条链互不阻塞；
- 写入失败整体回滚（`defer tx.Rollback`），不会留下半截记录。

### 3.3 与 operation_audits 的关系

| 维度 | operation_audits（操作审计） | ai_audit_records（AI 审计） |
|------|------------------------------|------------------------------|
| 实现 | `server/internal/audits/` | `server/internal/aiaudit/` |
| 审计对象 | 管理面全部操作（登录、配置、发布等） | AI 会话/任务/Tool/模型/Prompt/草稿/评估 |
| 串行化锁 | pg_advisory_xact_lock(93847561) | pg_advisory_xact_lock(93847562) |
| 哈希链 | 独立一条链 | 独立一条链（复用同一哈希链思想） |
| 校验接口 | POST /api/v1/audits/verify-chain（权限 `audits.read`） | POST /api/v1/ai/audits/verify（权限 `ai.audits.read`） |

两条链的哈希输入字段不同（AI 链以 `task_id` 为对象标识），不可交叉校验。

## 4. 审计记录字段与写入点

### 4.1 Record 结构

`aiaudit.Record` 与表列一一对应：`UserID / Username / RoleCodes / SessionID / TaskID / Action / TaskType / AgentCode / ToolCode / ModelCode / PromptVersion / InputTokens / OutputTokens / DurationMs / EstimatedCost / RequestSummary / ResultSummary / DraftReference / ConfirmResult`（`occurred_at`、`previous_hash`、`record_hash` 由服务层生成，不由调用方传入）。

### 4.2 写入辅助 recordAIAudit

接口层统一经 `Deps.recordAIAudit`（`aihandlers/handler.go`）写审计：

- 自动从登录主体注入 `UserID`、`Username`、`RoleCodes`（角色编码逗号拼接）；
- 使用独立的 5 秒超时上下文（`context.Background()` 派生），请求中途取消不会丢失审计；
- 写审计失败只记 `slog.Error` 日志，不影响主流程响应（安全底线第 5 条）。

### 4.3 action 取值与实际产生点

代码中实际产生的 action（按 `Action: "..."` 字面量统计）：

| action | 产生点 | 关键字段 |
|--------|--------|----------|
| chat | 会话消息执行完成/失败/用户停止（chat_handler.go） | session_id、task_id、task_type、input/output_tokens、duration_ms、请求摘要 trunc(消息,400)、结果摘要 trunc(回答,800) |
| analyze | 一次性分析完成/失败（analyze_handler.go） | 同上 |
| tool_call | Tool 统一执行器（经 `aitools.Auditor` 接口） | task_id、tool_code、duration_ms、结果摘要 `status=… err=…` |
| model_provider_create / model_provider_update | 模型供应商创建/更新（models_handler.go） | 请求摘要含供应商名 |
| model_key_rotate | 供应商密钥轮换 | 审计摘要不包含任何密钥材料（代码注释明示） |
| model_create / model_update / model_delete / model_status / model_test / model_route_update | 模型管理与健康检查 | model_code、结果 SUCCESS/FAILED |
| prompt_create / prompt_version_create / prompt_test / prompt_publish / prompt_rollback | Prompt 与版本管理（prompts_handler.go） | prompt_version |
| evaluation_set_create / evaluation_run | 评估集创建与运行（evaluations_handler.go） | 运行记录含 score/passed、input/output_tokens |
| draft_discard | 废弃草稿（drafts_handler.go） | draft_reference=草稿ID、结果 REJECTED |

说明：表注释中的 `draft_create` 为示例取值，当前代码未产生该 action；草稿创建动作由 `ai_recommendations` 表承载，AI 审计现有写入点如上表。

### 4.4 Tool 调用审计

`aiaudit.Service` 实现 `aitools.Auditor` 接口（`RecordToolCall`），由 Tool 注册表 `Registry.Execute` 在每次 Tool 执行后回调：

- 生成引用号 `toolcall:{tool_code}:{8位uuid}` 作为返回值供调用链引用；
- 落一条 `action=tool_call` 审计：`task_id`、`tool_code`、`duration_ms`，请求摘要为 Tool 输入摘要，结果摘要为 `status={SUCCESS/FAILED/TIMEOUT/DENIED} err={错误码}`。

## 5. 敏感信息脱敏

写入前对 `request_summary`（上限 500 字符）与 `result_summary`（上限 1000 字符）执行 `mask()` 处理，顺序为「先掩码、后截断」：

1. **密钥类关键词遮蔽**：关键词表 `sensitiveKeys = ["api_key", "apikey", "password", "secret", "private_key", "begin", "token"]`（全小写，与转小写后的摘要匹配）。将摘要整体转小写后做子串匹配，命中任一关键词即触发长 token 掩码（粗粒度：命中即对整段摘要执行掩码，而非仅替换关键词）。
2. **长 token 掩码**（`maskLongTokens`）：按空白字符分词，长度 ≥24 的字段替换为「前 6 字符 + `***`」，再按单空格拼回。例如疑似密钥/Token 的长串只保留前缀。
3. **rune 安全截断**：按 `[]rune` 截断到上限（请求 500、结果 1000），超出部分以 `...` 结尾；按 rune 而非按字节截断，避免截断多字节字符产生非法 UTF-8。

另外两层防护：

- 接口层在构造摘要时已先行截断（chat/analyze 的请求摘要 `trunc(内容,400)`、结果摘要 `trunc(回答,800)`，`trunc` 同样按 rune 截断，见 `aihandlers/handler.go`）；
- 模型密钥相关操作（创建供应商、密钥轮换）的审计摘要只含操作对象名称/ID，不包含任何密钥材料（`models_handler.go` 注释明示）。

不进入审计的内容（包注释与任务书 26.2 节）：模型私有思维链、密钥/密码/私钥、完整载荷。

## 6. 链完整性校验（VerifyChain）

`Service.VerifyChain(ctx, limit)` 算法：

```text
limit <= 0 时取默认 10000（服务层）；接口层另将上限钳制到 100000
按 occurred_at ASC, id ASC 取链头起前 limit 条
prev := ""
逐条：
  ① previous_hash != prev                → mismatches + 1   （链接关系断裂）
  ② computeHash(occurred_at, username, action, COALESCE(task_id,''), previous_hash) != record_hash
                                          → mismatches + 1   （内容被篡改）
  prev := record_hash
返回 mismatches
```

- 校验始终从链首开始（升序取最早 limit 条），两种异常分别计数（断链与内容篡改可叠加）；
- 校验为只读操作，不在数据库层面对记录做任何修复或删除。

## 7. 查询接口与权限

路由注册（`aihandlers/handler.go`），两个接口均挂在认证链 `authChain`（会话解析 → 认证检查 → CSRF 防护，见 `server/internal/app/app.go`）之后，并由 `middleware.RequirePermission` 强制权限点：

| 接口 | 权限 | 说明 |
|------|------|------|
| GET /api/v1/ai/audits | `ai.audits.read` | AI 审计分页查询 |
| POST /api/v1/ai/audits/verify | `ai.audits.read` | 哈希链完整性校验（请求体上限 4096 字节） |

查询接口参数（`AuditList`）：

| 参数 | 格式 | 说明 |
|------|------|------|
| user_id | UUID | 可选，非法值 400「无效的用户ID」 |
| session_id | UUID | 可选，非法值 400「无效的会话ID」 |
| action | 字符串 | 可选，精确匹配 |
| task_type | 字符串 | 可选，精确匹配 |
| start_time / end_time | RFC3339 | 可选，分别按 `occurred_at >=` / `occurred_at <` 过滤，格式错误 400 |
| page / page_size | 整数 | 默认 1 / 20；page<1 归一为 1；page_size ≤0 或 >100 归一为 20 |

过滤条件全部参数化（`$n` 占位），结果按 `occurred_at DESC` 返回，响应为标准分页结构（`response.Page`：items + total + page + page_size）。列表返回列为：`id, occurred_at, user_id, username, role_codes, session_id, task_id, action, task_type, agent_code, tool_code, model_code, prompt_version, input_tokens, output_tokens, duration_ms, estimated_cost, request_summary, result_summary, draft_reference, confirm_result`（与 `GET /api/v1/ai/audits/{id}` 详情口径一致，不回传 `previous_hash`、`record_hash` 哈希字段）。

校验接口（`AuditVerify`）：请求体 `{"limit": N}`（N≤0 取 10000，>100000 钳制为 100000），响应：

```json
{ "checked": 10000, "mismatches": 0, "ok": true }
```

`checked` 为实际检查条数（`min(limit, 全表记录数)`），`ok = (mismatches == 0)`。

权限点与角色（种子迁移 000014）：

| 角色 | ai.audits.read |
|------|----------------|
| SECURITY_ADMIN（安全管理员） | ✔（含 AI 审计与用量只读） |
| SYSTEM_ADMIN（系统管理员） | ✔ |
| AUDIT_ADMIN（审计管理员） | ✔（仅 `ai.audits.read` + `ai.usage.read`，AI 审计只读） |

前端 API 客户端已就绪：`web/src/api/ai.ts` 的 `aiAuditsApi`（`list` / `get` / `verify`）。AI 审计查询与校验均为只读操作，自身不再写入 `operation_audits`。

## 8. 实现现状说明（已知限制）

以下为按代码现状如实记录的限制/差异，后续版本处理：

1. 任务书 26.4 节要求的保留期限清理，当前未实现（无 `ai_audit_records` 的定期清理逻辑）；链校验无后台周期任务，仅提供手动触发接口。
2. `Record` 结构含 `occurred_at`（JSON 字段）与全部 snake_case JSON tag，列表查询列与扫描目标一一对应（曾存在列错位缺陷，已随阶段7联调修复并回归验证）。
3. `mask` 仅遮蔽 ≥24 字符的空白分隔字段，`password=123` 这类短秘密会原样进入审计摘要（粗粒度设计，调用方应避免把秘密写入摘要）。

## 9. 关联文档

- [操作审计设计](AUDIT_DESIGN.md)（operation_audits 哈希链，锁 93847561）
- [监控告警设计](MONITORING_ALERTING_DESIGN.md)（阶段6，含审计完整性类告警）
- [备份恢复设计](BACKUP_RESTORE_DESIGN.md)（审计归档段导出不恢复）
- [数据库设计](DATABASE_DESIGN.md)
- [RBAC 设计](RBAC_DESIGN.md)（三权角色与权限点）
- [安全设计](SECURITY_DESIGN.md)
- [接口设计](API_DESIGN.md)
- [阶段7 任务书](tasks/STAGE_7_AI_SECURITY_OPERATIONS.md)（二十六、AI审计）
