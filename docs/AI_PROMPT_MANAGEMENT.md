# Prompt 管理设计（阶段7）

本文档描述九章 WAF V2.0 阶段7（AI 安全运营中心）的 Prompt 管理设计，与实现代码严格一致：

- 仓储层：`server/internal/aiprompts/aiprompts.go`（`Store` + `ValidateContent`）
- 接口层：`server/internal/aihandlers/prompts_handler.go`；路由注册见 `server/internal/aihandlers/handler.go`
- 表结构：`server/migrations/000013_stage7.up.sql`（`ai_prompts` / `ai_prompt_versions`）；权限种子：`server/migrations/000014_seed_stage7_perms.up.sql`

Prompt 供 AI 运行时（编排器/Agent）使用；本系统默认经本地 Ollama（MIT 许可证）运行 Qwen2.5（Apache-2.0 许可证）系列模型，Prompt 内容不出本机部署边界。

## 1. 设计目标与安全底线

1. **版本不可变**：每次修改生成新的不可变版本（版本号递增 + 内容 SHA-256 哈希），历史版本永不改写，可审计、可回溯；
2. **禁止内容写入时即拦截**：密钥/Shell/越权/私有思维链类模式在 `CreatePrompt` / `CreateVersion` 写入前强制静态检查（`ValidateContent`），命中即拒绝，不依赖调用方自觉；
3. **未通过测试不得发布**：仅 `test_result = 'PASSED'` 的版本可发布，该门禁在仓储层 `Publish` 内强制执行（接口层只做友好错误映射）；
4. **职责分离**：查看/创建/测试/发布/回滚为 5 个独立权限点，由路由层强制校验；
5. **全程审计**：创建、建版、测试、发布、回滚均写入 AI 审计（`ai_audit_records`），只记摘要不记完整载荷。

## 2. 数据模型（不可变版本）

### 2.1 ai_prompts 表

建表见 `000013_stage7.up.sql`：

| 列 | 类型 | 默认 | 说明 |
|----|------|------|------|
| id | UUID PK | gen_random_uuid() | Prompt ID |
| code | VARCHAR(50) NOT NULL UNIQUE | - | 编码（全局唯一，运行时按 code 消费） |
| name | VARCHAR(100) NOT NULL | - | 名称 |
| prompt_type | VARCHAR(20) NOT NULL | - | 类型：`SYSTEM` / `ORCHESTRATOR` / `AGENT` / `TOOL` / `TASK` / `SAFETY` / `EVALUATION` |
| status | VARCHAR(20) NOT NULL | `'DRAFT'` | 状态（DDL 注释声明 `DRAFT` / `TESTING` / `ACTIVE` / `DISABLED` / `ARCHIVED`） |
| current_version_id | UUID | NULL | 当前发布版本指针（未加外键，由发布/回滚事务维护） |
| created_by / updated_by | UUID | NULL | 创建人 / 最近操作人 |
| created_at / updated_at | TIMESTAMPTZ NOT NULL | now() | 创建 / 更新时间 |

Go 结构体 `aiprompts.Prompt` 与上表对应（接口返回字段：id / code / name / prompt_type / status / current_version_id / created_at）。

### 2.2 ai_prompt_versions 表

| 列 | 类型 | 默认 | 说明 |
|----|------|------|------|
| id | UUID PK | gen_random_uuid() | 版本 ID |
| prompt_id | UUID NOT NULL REFERENCES ai_prompts(id) | - | 所属 Prompt |
| version_number | INTEGER NOT NULL | - | 版本号（Prompt 内单调递增，见 §2.3） |
| content | TEXT NOT NULL | - | 版本内容（不可变） |
| content_hash | VARCHAR(64) NOT NULL | - | 内容 SHA-256 十六进制（`hashContent`，插入时计算） |
| change_summary | VARCHAR(500) NOT NULL | `''` | 变更摘要（接口层按字符截断至 500） |
| test_result | VARCHAR(20) NOT NULL | `''` | 测试结果：`''`（未测试）/ `PASSED` / `FAILED` |
| created_by | UUID | NULL | 版本创建人 |
| created_at | TIMESTAMPTZ NOT NULL | now() | 创建时间 |
| published_by | UUID | NULL | 发布人（首次发布时写入） |
| published_at | TIMESTAMPTZ | NULL | 发布时间（首次发布时写入；回滚的"曾发布"判据） |
| is_current | BOOLEAN NOT NULL | FALSE | 当前版本标记 |

约束与索引：`UNIQUE (prompt_id, version_number)`；索引 `idx_ai_prompt_versions_prompt (prompt_id, version_number DESC)`。

### 2.3 不变式

- **内容不可变**：仓储层对 `ai_prompt_versions` 只有 `INSERT`（`CreatePrompt` / `CreateVersion`）与状态类 `UPDATE`（`is_current` / `test_result` / `published_*`），不存在任何修改 `content` / `content_hash` / `version_number` 的路径；要改内容只能创建新版本；
- **版本号递增**：`CreateVersion` 以子查询 `(SELECT COALESCE(MAX(version_number),0)+1 FROM ai_prompt_versions WHERE prompt_id=$2)` 生成下一个版本号，数据库唯一约束 `(prompt_id, version_number)` 兜底防并发重号；
- **哈希一致**：`content_hash` 在插入前由 `hashContent`（SHA-256 → hex，64 字符）计算，供一致性核对与差异识别；
- **is_current 唯一**：发布/回滚均在单事务内"先将该 Prompt 全部版本置 `is_current = FALSE`，再将目标版本置 `TRUE`"，保证任一时刻至多一个当前版本；
- **状态机现状**：代码实际使用的状态流转为 `DRAFT`（创建）→ `ACTIVE`（首次发布或回滚后）；`TESTING` / `DISABLED` / `ARCHIVED` 在 DDL 注释中声明，当前代码无对应流转路径。

```text
ai_prompts (1) ──────────── (N) ai_prompt_versions
  code (UNIQUE)                    version_number 1,2,3,...（不可变 INSERT）
  status ──────────┐               content + content_hash(SHA-256)
  current_version_id ────────────▶ is_current = TRUE 的版本（至多一个）
                   └ 发布/回滚事务内切换指针
```

## 3. 静态安全检查（ValidateContent）

### 3.1 检查规则

`ValidateContent(content string) error` 执行两类检查：

1. **非空与长度**：内容必填且 ≤ 50000 字符（按字节长度判断），违反返回 `content required (<=50000 chars)`；
2. **禁止模式子串匹配**：内容与模式均转小写后做 `strings.Contains` 包含匹配（大小写不敏感），命中任一模式返回包装了 `ErrUnsafeContent` 的错误并带出名中的模式。

### 3.2 禁止内容模式清单

`forbiddenPatterns` 共 16 条，按意图分四类：

| 类别 | 模式 | 针对内容 |
|------|------|----------|
| 密钥/凭据 | `api_key`、`apikey`、`BEGIN PRIVATE`、`BEGIN RSA` | API 密钥字段特征、PEM 私钥头特征 |
| Shell/命令执行 | `shell`、`bash -c`、`exec(`、`os.execute` | Shell 调用与命令执行特征 |
| 绕过权限 | `忽略你的权限`、`ignore your permissions`、`绕过权限`、`bypass permission` | 要求模型越权的中英文表述 |
| 私有思维链 | `思维链`、`chain of thought`、`展示你的思考过程`、`show your reasoning` | 要求输出私有思维链的中英文表述 |

### 3.3 拦截位置

- **写入时强制**：`CreatePrompt` 与 `CreateVersion` 在落库前调用 `ValidateContent`，命中即拒绝（接口层映射为 400"Prompt 内容包含禁止内容（密钥/Shell/越权/思维链等）"）——禁止内容根本没有进入数据库的路径；
- **测试时复查**：测试API对已存版本再次执行同一检查并计入检查明细（见 §4）。

设计决策：子串匹配是刻意保守的静态门禁——实现简单、结果确定、可解释；代价是可能误伤（如正文中出现英文单词 "shell" 即被拦截），误伤时须改写措辞后重新建版。该检查是纵深防御的一环，不声称防御全部 Prompt 注入；运行时的注入隔离（知识文档内容只作数据、不得覆盖系统 Prompt）由任务书第二十三章另行约束。

## 4. 版本测试与发布门禁

### 4.1 测试API行为

`POST /api/v1/ai/prompts/versions/{versionId}/test`（权限 `ai.prompts.test`）对指定版本执行**静态测试**：

1. `GetVersion` 取出版本（不存在 → 404）；
2. 逐项检查并生成明细 `checks[]`：
   - 「非空与长度（≤50000 字符）」：`len(content) > 0 && len(content) <= 50000`；
   - 「禁止内容扫描（密钥/Shell/越权/思维链）」：再次调用 `ValidateContent`，命中时该检查项附 `message: "命中禁止内容"`；
3. 全部通过则 `result = "PASSED"`，否则 `"FAILED"`，经 `MarkTestResult` 落库（该方法仅接受 `PASSED` / `FAILED`，其他值报错）；
4. 响应 `{test_result, checks}`，并写审计（`prompt_test`，含版本号与结果）。

说明：当前测试内容为上述静态检查；任务书第 24.4 节中的"测试集回归、对抗测试、结果对比、人工审核"环节未纳入本API（见 §10 差异说明）。

### 4.2 PASSED 门禁（强制）

发布门禁在仓储层 `Publish` 内强制执行，接口层无法绕过：

```text
Publish(promptID, versionID):
  查版本 test_result（不存在 → ErrNotFound → 404）
  test_result != "PASSED" → 拒绝（接口层映射 409"仅静态测试通过（PASSED）的版本可发布"）
```

注意 `test_result` 默认值为空串 `''`：**从未测试过的版本同样会被门禁拒绝**（错误信息中会带出当前值）。测试结果为版本级状态，重新测试可翻转 `PASSED` / `FAILED`，发布时以库中当前值为准。

## 5. 发布与回滚

### 5.1 发布流程

`POST /api/v1/ai/prompts/{id}/publish`（权限 `ai.prompts.publish`，请求体 `{"version_id": "<uuid>"}`）在单事务内执行：

```text
创建 Prompt（status=DRAFT）+ 版本1（is_current=FALSE, test_result=''）
      │  可继续 CreateVersion 产生版本 2,3,...（均不可变）
      ▼
版本静态测试（test → MarkTestResult PASSED/FAILED）
      │  仅 PASSED 可过门禁
      ▼
Publish 事务：
  1. 校验版本归属该 Prompt 且 test_result='PASSED'
  2. 该 Prompt 全部版本 is_current = FALSE
  3. 目标版本 is_current = TRUE, published_by = 操作人, published_at = now()
  4. ai_prompts: status='ACTIVE', current_version_id=目标版本, updated_by/updated_at
      ▼
ACTIVE（消费方按 code 经 CurrentContent 读到新当前版本，见 §8）
```

### 5.2 回滚流程

`POST /api/v1/ai/prompts/{id}/rollback`（权限 `ai.prompts.rollback`，请求体同发布）在单事务内执行：

1. 校验目标版本属于该 Prompt 且 `published_at IS NOT NULL`——**仅可回滚到曾经发布过的版本**（从未发布的版本报"can only rollback to a previously published version"，接口层映射 409"仅可回滚到已发布过的版本"；不存在 → 404）；
2. 该 Prompt 全部版本 `is_current = FALSE`；
3. 目标版本 `is_current = TRUE`（**不刷新** `published_by` / `published_at`，保留首次发布记录；也**不重新校验** `test_result`）；
4. `ai_prompts`：`status='ACTIVE'`、`current_version_id=目标版本`、`updated_by/updated_at`。

设计决策：回滚复用"曾发布"作为唯一判据——能发布过的版本历史上必然通过过 PASSED 门禁，因此回滚路径不再重复测试要求，保证可快速恢复；版本内容不可变使回滚无需复制数据，仅切换标记与指针。

## 6. 权限模型

权限点定义于 `000014_seed_stage7_perms.up.sql`（module = `ai`），路由层由 `middleware.RequirePermission` 逐API强制校验（`handler.go` 注册）：

| 权限码 | 名称 | 覆盖接口 |
|--------|------|----------|
| `ai.prompts.read` | 查看Prompt | `GET /api/v1/ai/prompts`、`GET .../{id}/versions` |
| `ai.prompts.create` | 创建Prompt | `POST /api/v1/ai/prompts`、`POST .../{id}/versions` |
| `ai.prompts.test` | 测试Prompt | `POST .../versions/{versionId}/test` |
| `ai.prompts.publish` | 发布Prompt | `POST .../{id}/publish` |
| `ai.prompts.rollback` | 回滚Prompt | `POST .../{id}/rollback` |

种子角色分配：

| 角色 | 权限 |
|------|------|
| `SECURITY_ADMIN` | 仅 `ai.prompts.read`（只读查看） |
| `SYSTEM_ADMIN` | 全量 5 个权限点 |
| `AUDIT_ADMIN` | 不授予任何 Prompt 权限（仅 `ai.audits.read` / `ai.usage.read`） |

设计决策：创建/测试/发布/回滚分离，使"谁写 Prompt、谁验证、谁上线、谁恢复"可拆给不同管理员，满足任务书最小权限与职责分离要求；例如可授予测试权限而不授予发布权限，发布动作始终需要独立授权。

## 7. API 清单

| 能力 | API | 权限 | 关键行为 |
|------|-----|------|----------|
| Prompt 列表 | `GET /api/v1/ai/prompts`（query：`prompt_type`、`status` 可选） | `ai.prompts.read` | 非法 `prompt_type` → 400；按 `code` 排序 |
| 创建 Prompt + 首版本 | `POST /api/v1/ai/prompts`（`code` / `name` / `prompt_type` / `content` / `change_summary`） | `ai.prompts.create` | 见下方校验规则 |
| 版本列表 | `GET /api/v1/ai/prompts/{id}/versions` | `ai.prompts.read` | `ORDER BY version_number DESC LIMIT 50` |
| 创建新版本 | `POST /api/v1/ai/prompts/{id}/versions`（`content` / `change_summary`） | `ai.prompts.create` | 版本号 MAX+1；写入前 `ValidateContent` |
| 版本静态测试 | `POST /api/v1/ai/prompts/versions/{versionId}/test` | `ai.prompts.test` | 返回 `{test_result, checks}`；落库 PASSED/FAILED |
| 发布 | `POST /api/v1/ai/prompts/{id}/publish`（`version_id`） | `ai.prompts.publish` | PASSED 门禁（§4.2） |
| 回滚 | `POST /api/v1/ai/prompts/{id}/rollback`（`version_id`） | `ai.prompts.rollback` | 仅曾发布版本（§5.2） |

校验与错误映射（`prompts_handler.go`）：

- 请求体上限：创建/建版 65536 字节，发布/回滚 4096 字节（`decodeJSON`）；
- `code` 必填且 ≤50 字符、`name` 必填且 ≤100 字符；`prompt_type` 须在 7 类白名单内；`change_summary` 按字符截断至 500（`trunc`）；
- 创建时做 `code` 唯一性预检查，重复返回 409"Prompt 编码已存在"（避免唯一索引冲突报 500）；
- `ErrUnsafeContent` → 400"Prompt 内容包含禁止内容（密钥/Shell/越权/思维链等）"；`ErrNotFound` → 404"Prompt 或版本不存在"；测试门禁/回滚判据不满足 → 409；路径参数非法 UUID → 400；其余 → 500。

## 8. 运行时消费（CurrentContent）

`Store.CurrentContent(ctx, code) (string, error)` 是 Prompt 内容的**唯一运行时读取入口**：

```sql
SELECT v.content FROM ai_prompts p
JOIN ai_prompt_versions v ON v.id = p.current_version_id
WHERE p.code = $1
```

消费契约：

- 调用方只按 `code` 读取，永远得到 `current_version_id` 指向的当前发布版本内容；发布/回滚切换指针后**下一次读取即生效**，无需通知消费方；
- 无缓存层：每次调用直连数据库，内容一致性与发布动作同事务保证；
- `code` 不存在或该 Prompt 尚无当前版本（从未发布）时返回 `ErrNotFound`，消费方须自行决定降级策略（不得静默吞错）。

实现现状说明：`CurrentContent` 当前由仓储层提供，仓库内尚无运行时调用方（全仓 grep 无其他包引用）——编排器当前的 system 提示词为代码内联（如 `aiorchestrator/orchestrator.go` 的 `composeAnswer`），尚未切换到按 `code` 从 `ai_prompts` 读取；本模块交付的是管理面能力与消费接口，运行时接入在后续迭代完成。管理面已完整落地：前端 `web/src/api/ai.ts` 的 `aiPromptsApi` 客户端与 §7 一一对应，管理页面 `web/src/pages/ai/admin/prompts/AiPromptsPage.tsx`（列表 + 版本管理抽屉：查看/新建版本/测试/发布/回滚）已挂载于路由 `ai/admin/prompts`（`RequirePermission ai.prompts.read` 守卫），页面内按钮按 `ai.prompts.create` / `test` / `publish` / `rollback` 逐权限点显隐，与后端权限模型一致。

## 9. AI 审计

全部写操作经 `recordAIAudit` 写入 AI 审计（表 `ai_audit_records`，哈希链完整性，见 `aiaudit` 包）：

| 动作 action | 触发 | 记录要点 |
|-------------|------|----------|
| `prompt_create` | 创建 Prompt | `PromptVersion="1"`，摘要含 code |
| `prompt_version_create` | 创建新版本 | `PromptVersion=新版本号` |
| `prompt_test` | 版本测试 | `PromptVersion=版本号`，结果 PASSED/FAILED |
| `prompt_publish` | 发布 | 摘要含 Prompt 与版本 ID |
| `prompt_rollback` | 回滚 | 摘要含 Prompt 与版本 ID |

行为要点：`recordAIAudit` 自动补齐 `UserID` / `Username` / `RoleCodes`；使用独立 5 秒超时上下文（请求取消不丢审计）；审计写入失败只记日志、不影响主流程；审计正文只存 `RequestSummary` / `ResultSummary` 摘要，且经 `aiaudit` 敏感词脱敏（`api_key` / `password` / `secret` / `private_key` / `token` 等），**不保存 Prompt 完整内容与模型私有思维链**。

## 10. 与任务书的差异说明

任务书 `docs/tasks/STAGE_7_AI_SECURITY_OPERATIONS.md` 第二十四章为本模块的需求来源，实现与其存在以下有意识的差异（以代码为准）：

1. **API 形态**：任务书列出 `GET/PUT /api/v1/ai/prompts/{id}`、`GET .../{id}/diff`、`POST .../{id}/test`；实际实现为 §7 的 7 个路由——因版本不可变，无 `PUT` 更新API；版本详情/差异查看未单独开放（版本列表已返回全部字段）；测试API按版本定位（`POST .../versions/{versionId}/test`）；
2. **测试深度**：当前测试为静态检查（§4.1），任务书的"测试集回归、对抗测试"未纳入 Prompt 测试API；
3. **状态枚举**：DDL 注释声明 5 态，当前代码仅流转 `DRAFT` / `ACTIVE`（§2.3）；
4. **运行时接入**：编排器尚未从 `ai_prompts` 读取提示词（§8）。

## 11. 验证

- 构建与静态检查：`cd server && go build ./...` 通过；`go vet ./internal/aiprompts/ ./internal/aihandlers/` 通过；
- 测试现状：`server/internal/aiprompts/` 无 `*_test.go`（`go test` 报 `[no test files]`）；`server/internal/aihandlers/handler_test.go` 仅含路由注册冒烟用例 `TestRegisterRoutesNoPanic`；当前无针对本模块的单元测试与接口测试用例；
- 文档一致性：本文所述表结构、权限码、路由、函数名均与 `000013_stage7.up.sql` / `000014_seed_stage7_perms.up.sql` / `aiprompts.go` / `prompts_handler.go` / `handler.go` 逐条 grep 核对。

## 12. 关联文档

- [阶段7任务书：AI 安全运营中心](tasks/STAGE_7_AI_SECURITY_OPERATIONS.md)（第二十四章 Prompt 管理、第二十五章 AI 权限模型）
- [AI 记忆设计](AI_MEMORY_DESIGN.md)
- [AI 模型网关设计](AI_MODEL_GATEWAY.md)
- [数据库设计](DATABASE_DESIGN.md)
- [接口设计](API_DESIGN.md)
- [安全设计](SECURITY_DESIGN.md)
- [RBAC 权限设计](RBAC_DESIGN.md)
- [总体架构设计](ARCHITECTURE.md)
