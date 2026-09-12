# AI 上下文压缩设计（阶段7）

本文档描述九章 WAF V2.0 阶段7（AI 安全运营中心）的会话上下文预算管理与自动压缩设计，与实现代码严格一致：

- 阈值模型、Token 估算与压缩算法：`server/internal/aiorchestrator/context.go`
- 压缩执行与审计落库：`server/internal/aiorchestrator/session.go`（`MaybeCompress`）
- 对话调用点：`server/internal/aihandlers/chat_handler.go`（`runStream`）
- 编排侧上下文加载：`server/internal/aiorchestrator/orchestrator.go`（`Run`）
- 表结构：`server/migrations/000013_stage7.up.sql`（`ai_context_compressions` / `ai_sessions` / `ai_models`）
- 需求来源：`docs/tasks/STAGE_7_AI_SECURITY_OPERATIONS.md` 第二十二章「上下文管理与自动压缩」

## 1. 设计目标

1. 长会话不爆窗：会话估算 Token 达到阈值时自动压缩，保证多轮对话可以持续进行；
2. 压缩不丢关键信息：最近消息原文保留、历史用户问题留痕、证据引用完整保留（`preserved_references`）；
3. 全程可审计：每次压缩落库 `ai_context_compressions`，记录压缩前后 Token、摘要、保留引用与触发原因；
4. 确定性优先：Token 估算与压缩算法均为确定性文本处理，不调用 LLM，不引入外部依赖（本地模型推理，Ollama + Qwen2.5，零成本）；
5. 失败不阻断对话：压缩在对话完成后异步触发，失败仅记 `slog.Warn`（含会话 ID 与错误），不影响已完成的回答，不静默吞错。

## 2. 上下文数据链路与 Token 计数

会话上下文占用以 `ai_sessions.context_token_count` 为唯一权威计数，随消息写入累加，压缩后重置：

```text
用户消息 ─▶ EstimateTokens(content) + 512 ─▶ CheckQuota（单次 ≤ 12000）─▶ AppendMessage(input_tokens)
                                                                              │
AI 回答  ─▶ EstimateTokens(answer)         ────────────────────────────▶ AppendMessage(output_tokens)
                                                                              │
                                              context_token_count += (input_tokens + output_tokens)
                                                                              │
                                                                              ▼
                                        MaybeCompress：CheckBudget(count, window, 阈值)
                                                  │ usage ≥ 0.80
                                                  ▼
                            Compress ─▶ 写 ai_context_compressions ─▶ 删旧消息 ─▶ 重置计数
```

| 时机 | 代码位置 | 计数规则 |
|------|----------|----------|
| 用户消息落库 | `chat_handler.go:313` | `EstimateTokens(content) + 512`（512 为系统提示等固定开销的估算余量） |
| AI 回答落库 | `chat_handler.go:380` | `EstimateTokens(result.Answer)` |
| 会话累计 | `session.go` `AppendMessage` | `context_token_count += inTok + outTok` |
| 压缩后重置 | `session.go` `MaybeCompress` | `context_token_count = AfterTokens`（不是递减，是重置为压缩后实测值） |
| 分析接口 | `analyze_handler.go:212` | 与用户消息相同的 `+512` 规则 |

前端可见性：会话 DTO 暴露 `context_token_count`（`chat_handler.go:26-30`），供前端做上下文使用量展示；压缩成功时 SSE 推送 `{type:"compressed", text:"会话上下文已自动压缩"}` 事件。

## 3. Token 估算（EstimateTokens，中英混排）

`EstimateTokens`（`context.go:51-61`）为粗略估算器，不调用模型真实 tokenizer：

- 逐 rune 分类：`r > 0x2E7F` 判为 CJK 字符（覆盖 CJK 统一表意文字及其扩展区起点），其余（拉丁字母、数字、ASCII 标点、空白）为其他字符；
- 公式：`tokens = cjk*2/3 + other/4 + 1`（整数除法；`+1` 保底，空字符串估算为 1）；
- 经验比例：中文约 1.5 字符 / Token，英文约 4 字符 / Token，与安全运营场景的中英混排日志、规则描述相匹配；
- 估算值即配额扣减与压缩判定的依据。本地模型（qwen2.5:3b）推理零成本，估算偏差只影响压缩触发时点的早晚，无费用后果；
- 输入上界：单条消息内容 ≤ 4000 字（`chat_handler.go:184` 参数校验）。

估算示例：

| 输入 | cjk | other | 估算 Token |
|------|-----|-------|-----------|
| 纯中文 300 字 | 300 | 0 | 201 |
| 纯英文 400 字符 | 0 | 400 | 101 |
| 混排（中文 150 字 + 英文 200 字符） | 150 | 200 | 151 |

## 4. 预算阈值模型（70% / 80% / 90%）

阈值按模型上下文窗口比例定义（`CompressionThresholds`，`context.go:9-18`）：

| 字段 | 默认值 | 含义 | 当前消费方 |
|------|--------|------|-----------|
| `Warn` | 0.70 | 预警 | `CheckBudget` 输出 `NeedWarn`（模型内预留，当前无消费方） |
| `Compress` | 0.80 | 自动压缩 | `MaybeCompress` 唯一实际生效的档位 |
| `ForceTrim` | 0.90 | 强制裁剪 | `CheckBudget` 输出 `NeedTrim`（模型内预留，当前无消费方） |

`CheckBudget(tokens, contextWindow, th)`（`context.go:37-48`）：

- `usage = tokens / contextWindow`；`contextWindow ≤ 0` 时回退为 8192（与 `ai_models.context_window` 列默认值一致）；
- 三个标志独立计算（`usage ≥ 0.90` 时三者同时为真），因此当前达到 90% 的会话仍走 80% 档的标准压缩路径，无独立强制裁剪行为；
- `SessionStore` 构造时固定使用 `DefaultThresholds()`（`session.go:26`），当前无管理面配置入口（与任务书 22.3「阈值必须可配置」的差异见第 9 节）。

`context.go` 还定义了 `ContextState`（摘要 / 最近保留数 / 当前 Token / 已压缩次数），为预留的会话上下文状态视图，当前无消费方；已压缩次数可由 `ai_context_compressions` 行数推导。

## 5. 压缩算法（Compress）

`Compress(messages, keepRecent, maxSummaryLen)`（`context.go:75-125`）为确定性压缩，不调用 LLM：

```text
messages（按时间正序，共 N 条）
   ├── old    = 前 (N - keepRecent) 条 ──▶ 生成摘要 + 提取证据引用
   └── recent = 最近 keepRecent 条     ──▶ 原文完整保留
```

- `keepRecent ≤ 0` 时取默认值 6；`MaybeCompress` 固定传 `8`，摘要上限传 `1500`（rune）；
- 消息总数 ≤ `keepRecent` 时不压缩（`BeforeTokens = AfterTokens`，`DroppedMessages = 0`）；
- 摘要结构（`strings.Builder` 顺序拼接）：
  1. 固定前缀「【此前会话摘要】」；
  2. 旧消息中每条 `role = "user"` 的消息追加「用户问{序号}：{内容前 80 rune}；」——历史用户明确要求留痕；
  3. 旧消息（全部角色）中经 `citationRe` 提取的证据引用去重后追加「涉及证据：[E1] [E2] …」；
- 引用格式（`evidence.go:55`）：`\[((?:E\d+)(?:\s*[,，、]\s*E\d+)*)\]`，匹配 `[E1]`、`[E1,E2]`、`[E12]`，分隔符支持中英文逗号与顿号；`PreservedRefs` 保留完整括号形式（如 `[E1,E2]`），按整串去重；
- 摘要整体按 rune 截断至 `maxSummaryLen`，超出补「…」（`truncateRunes`）；
- `AfterTokens = EstimateTokens(摘要) + Σ EstimateTokens(recent 各条)`；`BeforeTokens` 仅统计被压缩的 old 部分。

`CompressResult` 字段：

| 字段 | 说明 |
|------|------|
| `Summary` | 本轮生成的摘要（已截断） |
| `BeforeTokens` / `AfterTokens` | 压缩前（old 部分）/ 压缩后（摘要 + recent）估算 Token |
| `PreservedRefs` | 去重后的证据引用列表 |
| `DroppedMessages` | 被摘要替换的旧消息数（= len(old)） |
| `RetainedMessages` | 原文保留的最近消息数（= keepRecent） |

任务书 22.4「不得丢失」清单与实现机制的对应关系：

| 不得丢失 | 实现机制 |
|----------|----------|
| 用户明确要求 | 旧 user 消息逐条 80 rune 摘录进摘要 |
| 关键证据引用 | `citationRe` 全量提取、去重、写入摘要与 `preserved_references` |
| 当前任务目标 / 未完成步骤 / 时间范围 / 已确认事实 / 权限安全约束 | 最近 8 条消息原文保留，不参与压缩 |

## 6. 压缩执行（MaybeCompress）

`MaybeCompress(ctx, sessionID, contextWindow)`（`session.go:171-225`）在每次对话完成后由 `runStream` 调用（`chat_handler.go:390`）：

```text
SSE 对话完成（assistant 消息已落库、用量已记录）
   │
   ▼
MaybeCompress(pctx, sess.ID, contextWindow)
   │ 1. Get 会话 → CheckBudget(context_token_count, window, thresholds)
   │    NeedCompress=false ──────────────▶ 返回 (false, nil)
   │ 2. RecentMessages(sessionID, 100) → Compress(msgs, 8, 1500)
   │    DroppedMessages=0（消息 ≤ 8 条）─▶ 返回 (false, nil)
   │ 3. 事务：
   │    a. UPDATE ai_sessions
   │       SET context_summary = 旧摘要 + "\n" + 新摘要（截断 8000 rune）,
   │           context_token_count = AfterTokens
   │    b. INSERT ai_context_compressions（本轮审计，见第 7 节）
   │    c. DELETE FROM ai_messages（仅保留最近 RetainedMessages=8 条）
   │ 4. 提交；任一步失败整体回滚
   ▼
压缩成功 → SSE 推送 {type:"compressed"} 事件
压缩失败 → slog.Warn（含 session_id 与 error），不影响已完成的对话
```

关键行为：

- **摘要累积**：多轮压缩时新摘要以 `\n` 拼接在既有 `context_summary` 之后，会话级摘要统一截断至 8000 rune，防止无限增长；
- **计数重置**：`context_token_count` 直接重置为 `AfterTokens`，与旧消息删除同事务提交，避免「消息已删但计数未重置」的中间态；
- **执行上下文**：压缩在独立的 10 秒超时上下文（`pctx`）中执行，客户端断连也能完成落库；
- **触发窗口**：当前调用点传 `contextWindow = 0`，经 `CheckBudget` 回退按 8192 窗口判定，即 `context_token_count ≥ 6554`（8192 × 0.80）时触发压缩（与 `ai_models.context_window` 的关系见第 8、9 节）；
- **压缩后上下文的使用**：`Orchestrator.Run` 每轮加载 `sess.ContextSummary` 与最近 10 条消息（`orchestrator.go:183-190`）传入回答组装（`orchestrator.go:238`）；压缩后旧消息已物理删除，会话摘要是历史上下文的唯一留存形式。

## 7. 压缩审计（ai_context_compressions）

表结构（`server/migrations/000013_stage7.up.sql`）：

| 列 | 类型 | 说明 |
|----|------|------|
| `id` | UUID PK | 默认 `gen_random_uuid()` |
| `session_id` | UUID NOT NULL | `REFERENCES ai_sessions(id) ON DELETE CASCADE`，会话删除时级联清除 |
| `before_tokens` | INTEGER NOT NULL | 压缩前旧消息（old 部分）估算 Token 合计 |
| `after_tokens` | INTEGER NOT NULL | 压缩后（摘要 + 最近 8 条）估算 Token，同时写回 `ai_sessions.context_token_count` |
| `summary` | TEXT NOT NULL DEFAULT '' | 本轮生成的摘要（写入截断 2000 rune；不含历史累积部分） |
| `preserved_references` | JSONB NOT NULL DEFAULT '[]' | 保留的证据引用数组（如 `["[E1]","[E2,E3]"]`） |
| `compression_reason` | VARCHAR(50) NOT NULL DEFAULT '' | 触发原因，格式 `usage %.2f >= threshold %.2f`（示例：`usage 0.83 >= threshold 0.80`） |
| `created_at` | TIMESTAMPTZ NOT NULL | 压缩时间，默认 `now()` |

索引：`idx_ai_compressions_session (session_id, created_at DESC)`，支持按会话倒序查阅压缩历史。

查询入口：当前无独立的压缩记录查询 API；运维侧可直接查表核对，前端通过 SSE `compressed` 事件与会话 `context_token_count` 变化感知压缩发生。

## 8. 上下文窗口与输出预算分配

上下文窗口（`context_window`）与输出预算（`max_output_tokens`）在系统中有多个层次的取值，分配如下：

| 配置项 | 取值 | 位置 | 作用 |
|--------|------|------|------|
| `ai_models.context_window` | 列默认 8192；种子模型 qwen2.5:3b = **32768** | `000013` 建表 / `000015` 种子 / `ai.models.manage` 接口维护 | 模型元数据，声明模型窗口能力 |
| `ai_models.max_output_tokens` | 列默认 **2048**（种子同） | 同上 | 模型元数据，声明单次输出上限 |
| `CheckBudget` 回退窗口 | 8192 | `context.go:38-40` | `contextWindow ≤ 0` 时的压缩判定窗口 |
| `MaybeCompress` 实际判定窗口 | 8192（调用点传 0 回退） | `chat_handler.go:390` | 当前压缩按 8192 判定，80% ≈ 6554 Token 触发 |
| `aicost` 单次输入配额 | 12000（`PerRequestTokens`） | `aicost.go:30` | 服务端强制，`est = 消息估算 + 512` 超限即拒绝（429） |
| `aicost` 日配额 | 用户 200000 / 角色 500000 | `aicost.go:30` | 日累计 Token 上限 |
| `TaskLimits.MaxInputTokens` / `MaxOutputTokens` | 12000 / 4096 | `orchestrator.go:88` | 编排限制字段（当前未消费，预留） |
| `llmCompose` 输出上限 | 1024（`MaxTokens`） | `orchestrator.go:275` | 单次 LLM 引导总结的实际输出封顶 |
| 单条消息内容 | ≤ 4000 字 | `chat_handler.go:184` | 接口参数校验 |

分配要点：

- **输入侧三重约束**：单条消息 4000 字 → 单次请求 ≤ 12000 Token（配额强制）→ 会话窗口 80% 自动压缩，层层收紧；
- **输出侧**：模型元数据声明 2048，LLM 总结调用实际封顶 1024，编排层预留 4096；回答主体为确定性事实文本（不受 LLM 输出预算约束）；
- **32768 与 8192 的关系**：种子模型元数据声明 32768 窗口，但压缩判定当前使用 8192 回退值，即以更保守的窗口提前压缩、为输出与安全提示预留充足余量；`ai_models.context_window` 尚未接入 `MaybeCompress` 传参（见第 9 节）。

## 9. 现状边界（与任务书第二十二章的差异）

以下为实现现状与任务书 22.3 / 22.5 的已知差异，文档其余章节均以代码现状为准：

1. **阈值配置化**：任务书要求「阈值必须可配置」，当前 `SessionStore` 固定使用 `DefaultThresholds()`，无管理面配置入口；
2. **70% / 90% 档位**：`NeedWarn` / `NeedTrim` 已由 `CheckBudget` 计算输出，但无消费方；达到 90% 时仍走 80% 档标准压缩，无独立的「强制裁剪和重新规划」路径；
3. **窗口来源未打通**：`MaybeCompress` 调用点传 `contextWindow = 0`，压缩判定窗口固定回退 8192，未读取 `ai_models.context_window`（种子模型为 32768）；
4. **审计字段**：任务书 22.5 要求记录「摘要版本、是否强制裁剪」，当前 `ai_context_compressions` 无此两个字段；
5. **审计查询入口**：压缩记录暂无独立查询 API；
6. **压缩算法形态**：摘要为确定性文本摘录（用户问题截录 + 引用保留），非 LLM 归纳摘要。

## 10. 安全与合规

- **密钥**：压缩链路不接触任何密钥；本地 Ollama 供应商无密钥（`api_key_reference` 为空）；
- **第三方组件许可证**：Ollama（MIT）、Qwen2.5（Apache-2.0），均为宽松许可证，本地推理零成本（模型单价配置为 0）；
- **权限点**：触发压缩的对话接口受 `ai.chat.use` 保护；会话读取 `ai.sessions.read_own`；模型窗口 / 输出预算配置受 `ai.models.manage` 保护（`handler.go:68-107`）；
- **数据归属**：摘要含用户问题片段与证据编号，归属会话维度，会话删除时消息与压缩记录级联删除（`ON DELETE CASCADE`）；
- **错误处理**：压缩失败记录 `slog.Warn`（含 `session_id` 与 `error`），事务整体回滚，不留半截状态，不静默吞错。

## 关联文档

- [阶段7任务书：AI 安全运营中心](tasks/STAGE_7_AI_SECURITY_OPERATIONS.md)（第二十二章 上下文管理与自动压缩）
- [架构设计](ARCHITECTURE.md)
- [数据库设计](DATABASE_DESIGN.md)
- [接口设计](API_DESIGN.md)
- [安全设计](SECURITY_DESIGN.md)
- [RBAC 设计](RBAC_DESIGN.md)
- [开源合规](OPEN_SOURCE_COMPLIANCE.md)
