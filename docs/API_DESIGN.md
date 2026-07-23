# 接口设计文档

## 接口规范

### 统一前缀

```text
/api/v1
```

### 统一返回格式

```json
{
  "code": "SUCCESS",
  "message": "操作成功",
  "data": {},
  "request_id": "uuid"
}
```

### 分页格式

```json
{
  "items": [],
  "page": 1,
  "page_size": 20,
  "total": 0
}
```

### 错误码

HTTP 状态码与业务错误码必须同时正确使用。

| HTTP 状态码 | 业务错误码示例 | 说明 |
|------------|---------------|------|
| 200 | SUCCESS | 成功 |
| 400 | INVALID_PARAM | 参数错误 |
| 401 | UNAUTHORIZED | 未认证 |
| 403 | FORBIDDEN | 无权限 |
| 404 | NOT_FOUND | 资源不存在 |
| 409 | CONFLICT | 资源冲突 |
| 500 | INTERNAL_ERROR | 服务器内部错误 |

## 主要接口

### 认证

```text
POST   /api/v1/auth/login
POST   /api/v1/auth/logout
GET    /api/v1/auth/me
POST   /api/v1/auth/change-password
GET    /api/v1/auth/sessions
DELETE /api/v1/auth/sessions/{id}
```

### 用户与角色

```text
GET    /api/v1/users
POST   /api/v1/users
GET    /api/v1/users/{id}
PUT    /api/v1/users/{id}
DELETE /api/v1/users/{id}
POST   /api/v1/users/{id}/reset-password
GET    /api/v1/roles
GET    /api/v1/permissions
```

### 应用

```text
GET    /api/v1/applications
POST   /api/v1/applications
GET    /api/v1/applications/{id}
PUT    /api/v1/applications/{id}
DELETE /api/v1/applications/{id}
POST   /api/v1/applications/{id}/enable
POST   /api/v1/applications/{id}/disable
POST   /api/v1/applications/{id}/test-origin
GET    /api/v1/applications/{id}/status
GET    /api/v1/applications/{id}/events
```

### 源站

```text
GET    /api/v1/applications/{id}/upstreams
POST   /api/v1/applications/{id}/upstreams
PUT    /api/v1/upstreams/{id}
DELETE /api/v1/upstreams/{id}
POST   /api/v1/upstreams/{id}/health-check
```

### 证书

```text
GET    /api/v1/certificates
POST   /api/v1/certificates
GET    /api/v1/certificates/{id}
DELETE /api/v1/certificates/{id}
GET    /api/v1/certificates/{id}/applications
POST   /api/v1/certificates/{id}/bind
POST   /api/v1/certificates/{id}/unbind
POST   /api/v1/certificates/validate
```

### 防护策略

```text
GET    /api/v1/protection-policies
POST   /api/v1/protection-policies
GET    /api/v1/protection-policies/{id}
PUT    /api/v1/protection-policies/{id}
DELETE /api/v1/protection-policies/{id}
```

### 规则和例外

```text
GET    /api/v1/waf-rules
GET    /api/v1/waf-rules/{rule_id}
PUT    /api/v1/waf-rules/{rule_id}/override
GET    /api/v1/custom-rules
POST   /api/v1/custom-rules
PUT    /api/v1/custom-rules/{id}
DELETE /api/v1/custom-rules/{id}
POST   /api/v1/custom-rules/{id}/test

GET    /api/v1/exceptions
POST   /api/v1/exceptions
PUT    /api/v1/exceptions/{id}
DELETE /api/v1/exceptions/{id}
```

### 黑白名单和CC

```text
GET    /api/v1/access-rules
POST   /api/v1/access-rules
PUT    /api/v1/access-rules/{id}
DELETE /api/v1/access-rules/{id}
POST   /api/v1/access-rules/import
GET    /api/v1/access-rules/export

GET    /api/v1/rate-limit-policies
POST   /api/v1/rate-limit-policies
PUT    /api/v1/rate-limit-policies/{id}
DELETE /api/v1/rate-limit-policies/{id}
```

### 安全事件

```text
GET    /api/v1/security-events
GET    /api/v1/security-events/{id}
PUT    /api/v1/security-events/{id}/disposition
POST   /api/v1/security-events/{id}/notes
POST   /api/v1/security-events/{id}/add-to-blacklist
POST   /api/v1/security-events/{id}/create-exception
GET    /api/v1/security-events/export
```

### 配置发布

```text
POST   /api/v1/gateway/config/preview
POST   /api/v1/gateway/config/validate
POST   /api/v1/gateway/config/publish
GET    /api/v1/gateway/config/versions
GET    /api/v1/gateway/config/versions/{id}
POST   /api/v1/gateway/config/versions/{id}/rollback
GET    /api/v1/gateway/publish-tasks/{id}
```

### 首页、审计和报表

```text
GET    /api/v1/dashboard/overview
GET    /api/v1/dashboard/trends
GET    /api/v1/dashboard/distributions
GET    /api/v1/audits
GET    /api/v1/audits/export
GET    /api/v1/reports
POST   /api/v1/reports
GET    /api/v1/reports/{id}
GET    /api/v1/reports/{id}/download
```

### 访问控制与CC防护（阶段5）

```text
# 可信代理
GET    /api/v1/trusted-proxies
POST   /api/v1/trusted-proxies
GET    /api/v1/trusted-proxies/{id}
PUT    /api/v1/trusted-proxies/{id}
DELETE /api/v1/trusted-proxies/{id}
POST   /api/v1/trusted-proxies/{id}/enable
POST   /api/v1/trusted-proxies/{id}/disable
POST   /api/v1/trusted-proxies/test

# 保护地址
GET    /api/v1/protected-addresses
POST   /api/v1/protected-addresses
DELETE /api/v1/protected-addresses/{id}
POST   /api/v1/protected-addresses/refresh

# IP黑白名单
GET    /api/v1/access-rules
POST   /api/v1/access-rules
GET    /api/v1/access-rules/{id}
PUT    /api/v1/access-rules/{id}
DELETE /api/v1/access-rules/{id}
POST   /api/v1/access-rules/{id}/enable
POST   /api/v1/access-rules/{id}/disable
POST   /api/v1/access-rules/{id}/extend
POST   /api/v1/access-rules/{id}/release
POST   /api/v1/access-rules/{id}/copy
POST   /api/v1/access-rules/import
GET    /api/v1/access-rules/export
POST   /api/v1/access-rules/validate
POST   /api/v1/access-rules/publish

# CC防护策略
GET    /api/v1/rate-limit-policies
POST   /api/v1/rate-limit-policies
GET    /api/v1/rate-limit-policies/{id}
PUT    /api/v1/rate-limit-policies/{id}
DELETE /api/v1/rate-limit-policies/{id}
POST   /api/v1/rate-limit-policies/{id}/enable
POST   /api/v1/rate-limit-policies/{id}/disable
POST   /api/v1/rate-limit-policies/{id}/validate
POST   /api/v1/rate-limit-policies/{id}/test
POST   /api/v1/rate-limit-policies/publish

# 临时封禁
GET    /api/v1/temporary-blocks
GET    /api/v1/temporary-blocks/{id}
POST   /api/v1/temporary-blocks/{id}/release
POST   /api/v1/temporary-blocks/{id}/extend
POST   /api/v1/temporary-blocks/{id}/convert-to-permanent

# 访问控制事件
GET    /api/v1/access-control-events
GET    /api/v1/access-control-events/{id}
GET    /api/v1/access-control-events/export

# 访问控制配置版本
GET    /api/v1/access-control/versions
GET    /api/v1/access-control/versions/{id}
GET    /api/v1/access-control/versions/{id}/diff
POST   /api/v1/access-control/versions/{id}/rollback
```

### AI 安全运营中心（阶段7）

阶段7 接口统一以 `/api/v1/ai/` 为前缀，路由注册见 `server/internal/aihandlers/handler.go` 的 `RegisterRoutes`。统一约定：

- 所有接口强制身份认证，并在路由层按权限点强制校验；草稿查询与评估集/运行记录查询采用"任一权限满足即放行"；
- 统一响应信封与 `page`/`page_size` 分页格式沿用前文约定；
- 会话、任务记录、记忆严格属主隔离：非属主访问一律返回 404（NOT_FOUND），不泄露资源存在性；
- 发送消息与一次性分析前服务端强制配额检查（单次输入 Token、用户/角色每日 Token），超限返回 429；
- SSE 流式与长耗时请求放宽连接写期限，见末节"流式输出（SSE）与长连接"。

**会话与消息**

| 方法 | 路径 | 权限点 | 说明 |
|------|------|--------|------|
| GET | /api/v1/ai/sessions | ai.sessions.read_own | 本人会话分页列表；`include_archived` 可选含归档 |
| POST | /api/v1/ai/sessions | ai.chat.use | 创建会话（`title` 可选，≤200 字） |
| GET | /api/v1/ai/sessions/{id} | ai.sessions.read_own | 会话详情（属主隔离） |
| PATCH | /api/v1/ai/sessions/{id} | ai.chat.use | 重命名会话（`title` 必填，≤200 字） |
| DELETE | /api/v1/ai/sessions/{id} | ai.sessions.delete_own | 删除会话（先停止运行中任务，消息级联删除） |
| POST | /api/v1/ai/sessions/{id}/archive | ai.chat.use | 归档会话（归档后不可继续对话） |
| GET | /api/v1/ai/sessions/{id}/messages | ai.sessions.read_own | 消息列表（`limit` 默认 50，超限（>100）回退为 10，正序） |
| POST | /api/v1/ai/sessions/{id}/messages | ai.chat.use | 发送消息，SSE 流式输出（`content` 必填 ≤4000 字；`task_type` 为预留字段，任务类型由服务端意图分类判定，不采信前端声明） |
| POST | /api/v1/ai/sessions/{id}/stop | ai.chat.use | 停止当前会话正在运行的任务 |
| POST | /api/v1/ai/sessions/{id}/retry | ai.chat.use | 取最后一条用户消息重跑（SSE） |
| POST | /api/v1/ai/sessions/{id}/continue | ai.chat.use | 最后一条助手回复后以"请继续"续跑（SSE） |
| POST | /api/v1/ai/messages/{id}/feedback | ai.chat.use | 消息反馈（`rating` 1/-1；`feedback_type`：GENERAL/WRONG_FACT/MISSING_EVIDENCE/HALLUCINATION/OTHER） |

**任务记录**

| 方法 | 路径 | 权限点 | 说明 |
|------|------|--------|------|
| GET | /api/v1/ai/tasks | ai.sessions.read_own | 本人任务分页列表（`status`/`task_type` 可选过滤） |
| GET | /api/v1/ai/tasks/{id} | ai.sessions.read_own | 任务详情（非属主一律 404） |

**一次性 AI 分析**

8 个端点共用请求体字段 `event_id`（UUID 形态校验）、`rule_id`、`ip`（net.ParseIP 校验）、`question`、`period`，各端点按需取用；均为非流式执行，响应 200 返回 `{task_id, answer, plan, steps, evidence}`（`steps` 为执行步骤，上限 100 条），执行失败返回 500 且不暴露内部错误细节；均使用一次性会话（用完即删，不污染会话列表）。

| 方法 | 路径 | 权限点 | 说明 |
|------|------|--------|------|
| POST | /api/v1/ai/analyze/event | ai.event_analysis.use | 安全事件分析；`event_id` 或 `question` 二选一 |
| POST | /api/v1/ai/analyze/false-positive | ai.false_positive_analysis.use | 误报研判；`event_id` 或 `rule_id` 至少其一 |
| POST | /api/v1/ai/analyze/attack-profile | ai.attack_profile.use | 攻击画像；`ip` 或 `question` 二选一 |
| POST | /api/v1/ai/analyze/attack-chain | ai.attack_chain.use | 攻击链关联分析；`ip` 或 `event_id` 二选一 |
| POST | /api/v1/ai/analyze/policy-recommendation | ai.policy_recommendation.use | 策略优化建议；`question` 可选关注点 |
| POST | /api/v1/ai/analyze/what-if | ai.what_if.use | What-If 策略模拟；`rule_id` 必填 |
| POST | /api/v1/ai/analyze/root-cause | ai.root_cause.use | 根因分析；`question` 可选（默认"当前系统运行状态"） |
| POST | /api/v1/ai/analyze/report-summary | ai.report_summary.use | 报告总结；`period` 可选（默认"近7天"） |

**草稿**

以下 3 条接口权限为任一 `ai.draft.exception` / `ai.draft.blacklist` / `ai.draft.cc_policy` / `ai.draft.custom_rule`。草稿数据源为 `ai_recommendations`，本组接口绝不执行发布/生效操作。

| 方法 | 路径 | 权限点 | 说明 |
|------|------|--------|------|
| GET | /api/v1/ai/drafts | 任一草稿权限 | 草稿分页列表（`recommendation_type`/`status` 可选过滤，均有白名单校验） |
| GET | /api/v1/ai/drafts/{id} | 任一草稿权限 | 草稿详情 |
| POST | /api/v1/ai/drafts/{id}/discard | 任一草稿权限 | 废弃草稿（逻辑标记 REJECTED，不删除记录、不触碰草稿指向的业务配置） |

**模型供应商 / 模型 / 路由档位**

供应商密钥仅在创建与轮换时以明文入参，加密存储于 `ai_provider_secrets`，任何响应不回传明文或密文（供应商输出仅含引用名 `api_key_reference`）。路由档位持久化在 `system_settings`（组 `ai`，键 `route_simple`/`route_standard`/`route_high`），变更后热生效。

| 方法 | 路径 | 权限点 | 说明 |
|------|------|--------|------|
| GET | /api/v1/ai/models/providers | ai.models.read | 供应商列表（不含密钥） |
| POST | /api/v1/ai/models/providers | ai.models.manage | 创建供应商（`provider_type` 白名单 openai_compatible/anthropic/ollama/local；`api_key` 可选） |
| PATCH | /api/v1/ai/models/providers/{id} | ai.models.manage | 更新供应商（名称/类型/BaseURL/状态；密钥走 rotate-key） |
| DELETE | /api/v1/ai/models/providers/{id} | ai.models.manage | 删除供应商（下无关联模型时才允许；同步清理密钥密文） |
| POST | /api/v1/ai/models/providers/{id}/rotate-key | ai.models.manage | 轮换供应商密钥（`api_key` 必填，加密覆盖存储） |
| GET | /api/v1/ai/models | ai.models.read | 模型列表 |
| POST | /api/v1/ai/models | ai.models.manage | 创建模型（`provider_id`/`model_code` 必填；参数默认值与边界服务端归一） |
| PUT | /api/v1/ai/models/{id} | ai.models.manage | 更新模型（不含状态与密钥） |
| DELETE | /api/v1/ai/models/{id} | ai.models.manage | 删除模型 |
| POST | /api/v1/ai/models/{id}/enable | ai.models.manage | 启用模型 |
| POST | /api/v1/ai/models/{id}/disable | ai.models.manage | 停用模型 |
| POST | /api/v1/ai/models/{id}/test | ai.models.read | 连通性健康检查（只读探测，返回 `{ok, message}`，失败亦 200） |
| GET | /api/v1/ai/models/routes | ai.models.read | 读取路由档位（simple/standard/high → model_code，含 `loaded_models`） |
| PUT | /api/v1/ai/models/routes | ai.models.manage | 更新路由档位（校验模型编码存在；未提供的档位保持现状） |

**Agent / Tool 管理**

代码 registry 是能力来源，`ai_agents`/`ai_tools` 表存启停与配置，列表为 DB 左联代码 registry（含 `in_registry` 标记）；启停即时生效。

| 方法 | 路径 | 权限点 | 说明 |
|------|------|--------|------|
| GET | /api/v1/ai/agents | ai.agents.read | Agent 列表（8 个目录项，dispatcher 为编排器内置总调度） |
| PATCH | /api/v1/ai/agents/{id} | ai.agents.manage | 配置 Agent（`enabled`/`allowed_tool_ids`；dispatcher 不可停用） |
| GET | /api/v1/ai/tools | ai.tools.read | Tool 列表（含风险等级、所需权限点、输入 schema） |
| PATCH | /api/v1/ai/tools/{id} | ai.tools.manage | 配置 Tool（`enabled`/`timeout_seconds` 1-300/`max_results` 1-1000） |

**Prompt 管理**

版本不可变；Prompt 与版本内容经禁止内容静态扫描（密钥/Shell/越权/思维链等）；仅静态测试 PASSED 的版本可发布。

| 方法 | 路径 | 权限点 | 说明 |
|------|------|--------|------|
| GET | /api/v1/ai/prompts | ai.prompts.read | Prompt 列表（`prompt_type` 白名单 SYSTEM/ORCHESTRATOR/AGENT/TOOL/TASK/SAFETY/EVALUATION；`status` 可选过滤） |
| POST | /api/v1/ai/prompts | ai.prompts.create | 创建 Prompt 及首版本（`code` 唯一 ≤50 字符） |
| GET | /api/v1/ai/prompts/{id}/versions | ai.prompts.read | 版本列表 |
| POST | /api/v1/ai/prompts/{id}/versions | ai.prompts.create | 创建新版本（版本不可变） |
| POST | /api/v1/ai/prompts/versions/{versionId}/test | ai.prompts.test | 静态测试（非空与长度 ≤50000 + 禁止内容扫描；记录 PASSED/FAILED） |
| POST | /api/v1/ai/prompts/{id}/publish | ai.prompts.publish | 发布版本（`version_id` 必填；仅测试 PASSED 可发布，store 层强制） |
| POST | /api/v1/ai/prompts/{id}/rollback | ai.prompts.rollback | 回滚到已发布过的版本（`version_id` 必填） |

**记忆**

严格属主隔离；写入/更新经敏感内容拦截（密码/密钥/私钥特征及疑似凭据长随机串）。

| 方法 | 路径 | 权限点 | 说明 |
|------|------|--------|------|
| GET | /api/v1/ai/memories | ai.memories.read_own | 本人记忆列表（`scope` 过滤：SESSION/PROJECT/LONG_TERM；`include_disabled` 可选） |
| POST | /api/v1/ai/memories | ai.memories.manage_own | 新增记忆（`content` ≤4000 字符；`confidence_type` 默认 USER_CONFIRMED） |
| PUT | /api/v1/ai/memories/{id} | ai.memories.manage_own | 修改记忆内容 |
| DELETE | /api/v1/ai/memories/{id} | ai.memories.manage_own | 删除记忆 |
| POST | /api/v1/ai/memories/{id}/disable | ai.memories.manage_own | 禁用记忆（禁用后不再进入上下文） |

**AI 审计**

| 方法 | 路径 | 权限点 | 说明 |
|------|------|--------|------|
| GET | /api/v1/ai/audits | ai.audits.read | 审计分页查询（`user_id`/`session_id`/`action`/`task_type`/`start_time`/`end_time` 可选过滤，时间为 RFC3339） |
| POST | /api/v1/ai/audits/verify | ai.audits.read | 哈希链完整性校验（`limit` 默认 10000、上限 100000；返回 `{checked, mismatches, ok}`） |

**用量与成本**

| 方法 | 路径 | 权限点 | 说明 |
|------|------|--------|------|
| GET | /api/v1/ai/usage/overview | ai.usage.read | 今日用量总览（Token/调用次数/成本） |
| GET | /api/v1/ai/usage/by-user | ai.usage.read | 按用户统计（近 7 天，前 20） |

**评估**

评估集与运行记录查询无独立 read 权限点：任一 `ai.evaluations.run` / `ai.usage.read` / `ai.audits.read` 可读。

| 方法 | 路径 | 权限点 | 说明 |
|------|------|--------|------|
| GET | /api/v1/ai/evaluation-sets | 评估执行或用量/审计只读 | 评估集列表 |
| POST | /api/v1/ai/evaluation-sets | ai.evaluations.run | 创建评估集（`code` 唯一；`cases` 1-50 条，字段 `question` + `expected_contains`） |
| GET | /api/v1/ai/evaluation-runs | 评估执行或用量/审计只读 | 评估运行记录分页 |
| POST | /api/v1/ai/evaluations/run | ai.evaluations.run | 执行评估（逐条过编排器，按 `expected_contains` 包含匹配计分；单次上限 20 用例、整体 10 分钟超时） |

**流式输出（SSE）与长连接**

`POST /api/v1/ai/sessions/{id}/messages`、`/retry`、`/continue` 三个端点以 SSE 流式输出执行过程与结果：

- 响应头：`Content-Type: text/event-stream; charset=utf-8`、`Cache-Control: no-cache`、`Connection: keep-alive`、`X-Accel-Buffering: no`；
- 事件格式：每条事件为单行 JSON 加空行，逐条 flush：

```text
data: {"type":"plan|agent_start|agent_done|answer|error|compressed|done","text":"...","payload":{...}}

```

- 事件类型：
  - `plan`：任务计划，`payload` 为 Plan（task_type、调度 Agent 列表等）；
  - `agent_start` / `agent_done`：专业 Agent 开始/完成，`text` 为展示名；Agent 已停用跳过、单个 Agent 执行失败（`error` 事件）均不中断整体流程；
  - `answer`：最终回答（含证据区），`payload` 含 `evidence_count`；
  - `compressed`：会话上下文超阈值已自动压缩；
  - `error`：整轮执行失败（`text` 为通用提示，不暴露内部错误细节）；
  - `done`：结束事件，正常完成时 `payload` 含 `task_id`、`message_id`、`finish_reason`；用户主动停止时 `finish_reason=cancelled`。
- 长连接处理：服务器默认 WriteTimeout（30s）会掐断 LLM 推理期间的长静默流，上述 SSE 端点与一次性分析端点将本连接写期限放宽至 10 分钟，评估运行放宽至 15 分钟；编排本身单任务上限 120 秒。

## 安全要求

1. 所有接口执行身份认证；
2. 所有写接口执行权限校验和 CSRF 校验；
3. 登录和高风险接口限速；
4. 接口错误不返回堆栈信息；
5. 生产环境关闭调试接口。

## OpenAPI 3

正式接口实现后，使用 OpenAPI 3 规范生成接口文档，存放于 `docs/openapi.yaml`。

---

## 阶段8 / WDSP：API 动态防护接口（/api/v1/api-security）

> 仅在 `PRODUCT_EDITION=wdsp` 且 `API_DYNAMIC_PROTECTION_ENABLED=true` 时注册；纯 WAF 形态下整组路由不存在（404）。统一响应信封、分页参数（`page`/`page_size`）、错误码与既有接口一致；全部写操作记录操作审计。OpenAPI 定义见 `server/openapi/openapi.yaml`（tag: `api-security`）。

### 端点资产与学习

| 方法与路径 | 权限点 | 说明 |
|---|---|---|
| `GET /api/v1/api-security/endpoints` | `api_asset.read` | 端点列表（asset_status/learning_status/keyword/application_id 过滤） |
| `POST /api/v1/api-security/endpoints/confirm` | `api_asset.confirm` | 批量确认为正式资产 `{ids:[]}` |
| `GET /api/v1/api-security/endpoints/{id}` | `api_asset.read` | 端点详情（含 api_assets 扩展字段） |
| `PATCH /api/v1/api-security/endpoints/{id}` | `api_asset.edit` | 编辑资产属性（用途/暴露面/负责人/标签） |
| `POST /api/v1/api-security/endpoints/{id}/merge` | `api_asset.merge` | 合并端点（别名归档、命中累加，事务） |
| `POST /api/v1/api-security/endpoints/{id}/split` | `api_asset.split` | 拆分端点 |
| `POST /api/v1/api-security/endpoints/{id}/ignore` | `api_asset.ignore` | 标记忽略 |
| `POST /api/v1/api-security/endpoints/{id}/classify` | `api_asset.edit` | 触发自动分类（source=AUTO） |
| `GET /api/v1/api-security/endpoints/{id}/lifecycle-events` | `api_asset.read` | 生命周期事件（合并/拆分/状态变更轨迹） |
| `POST /api/v1/api-security/endpoints/{id}/learning/start` | `api_learning.start` | 启动学习（已有 RUNNING 任务返回 409） |
| `POST /api/v1/api-security/endpoints/{id}/learning/stop` | `api_learning.stop` | 停止学习 |
| `GET /api/v1/api-security/endpoints/{id}/learning/status` | `api_learning.read` | 学习任务与样本统计 |
| `GET /api/v1/api-security/endpoints/{id}/learning/samples` | `api_learning.read` | 学习样本列表（不落敏感明文） |

### 模型版本与参数

| 方法与路径 | 权限点 | 说明 |
|---|---|---|
| `GET /api/v1/api-security/endpoints/{id}/models` | `api_model.read` | 端点模型版本列表 |
| `POST /api/v1/api-security/endpoints/{id}/models` | `api_model.edit` | 创建候选版本 |
| `GET /api/v1/api-security/models/{id}` | `api_model.read` | 版本详情 |
| `GET /api/v1/api-security/models/{id}/diff/{other_id}` | `api_model.read` | 版本差异（added/removed/type_changed） |
| `POST /api/v1/api-security/models/{id}/submit-review` | `api_model.review` | 提交评审（CANDIDATE→IN_REVIEW） |
| `POST /api/v1/api-security/models/{id}/confirm` | `api_model.confirm` | 确认冻结（FORMAL，旧版 SUPERSEDED，事务） |
| `POST /api/v1/api-security/models/{id}/reject` | `api_model.review` | 评审拒绝 |
| `POST /api/v1/api-security/models/{id}/activate` | `api_model.activate` | 激活（端点 current_model_version_id） |
| `POST /api/v1/api-security/models/{id}/archive` | `api_model.archive` | 归档 |
| `GET /api/v1/api-security/models/{id}/parameters` | `api_parameter.read` | 版本参数列表 |
| `GET /api/v1/api-security/parameters/{id}` | `api_parameter.read` | 参数详情 |
| `PATCH /api/v1/api-security/parameters/{id}` | `api_parameter.edit` | 修改确认约束 |
| `POST /api/v1/api-security/parameters/{id}/confirm` | `api_parameter.edit` | 采纳推荐约束为确认约束 |

状态机：`CANDIDATE → IN_REVIEW → FORMAL / REJECTED`；`FORMAL → SUPERSEDED / ARCHIVED`；FORMAL 内容不可变。冻结模型经配置发布通道下发网关（`api_formal_schemas`）。

### 分类、图谱与规范

| 方法与路径 | 权限点 | 说明 |
|---|---|---|
| `GET /api/v1/api-security/classifications` | `api_classification.read` | 内置 + 自定义分类 |
| `POST /api/v1/api-security/classifications` | `api_classification.manage` | 新增自定义分类 |
| `PUT /api/v1/api-security/endpoints/{id}/classification` | `api_classification.manage` | 设置端点分类维度（source=MANUAL 并锁定） |
| `GET /api/v1/api-security/graph` | `api_graph.read` | 图谱（节点 + 调用边） |
| `GET /api/v1/api-security/topology` | `api_graph.read` | 拓扑（按应用分组 + 调用边） |
| `POST /api/v1/api-security/specs/import` | `api_spec.import` | 导入 OpenAPI 3（JSON），生成与运行时的差异 |
| `GET /api/v1/api-security/specs` | `api_spec.read` | 规范列表 |
| `GET /api/v1/api-security/specs/{id}/diff` | `api_spec.read` | 规范差异（MISSING_IN_RUNTIME / MISSING_IN_SPEC） |

### 风险、运行时与策略

| 方法与路径 | 权限点 | 说明 |
|---|---|---|
| `GET /api/v1/api-security/findings` | `api_runtime.read` | 风险发现（类型/级别/状态过滤） |
| `GET /api/v1/api-security/violations` | `api_runtime.read` | Schema 违例记录 |
| `GET /api/v1/api-security/posture` | `api_runtime.read` | 安全态势聚合（覆盖率/冻结率/开放发现） |
| `GET /api/v1/api-security/runtime/statistics` | `api_runtime.read` | 运行时统计（动作/风险分布、热点端点） |
| `GET /api/v1/api-security/runtime/events` | `api_runtime.read` | 统一运行时主事件（request_id 幂等） |
| `GET /api/v1/api-security/sensitive-fields` | `api_runtime.read` | 敏感字段识别结果 |
| `GET /api/v1/api-security/policy` | `api_policy.read` | 当前策略（模式/来源/解析限制） |
| `PUT /api/v1/api-security/policy` | `api_policy.edit` | 修改防护模式（OFF/OBSERVE/PROTECT，settings 覆盖） |
| `POST /api/v1/api-security/policy/publish` | `api_policy.publish` | 同步发布到网关（高风险操作） |

专项设计文档：`docs/UNIFIED_DYNAMIC_SECURITY_ARCHITECTURE.md`、`docs/REQUEST_CONTEXT_DESIGN.md`、`docs/API_DISCOVERY_DESIGN.md`、`docs/API_PATH_NORMALIZATION.md`、`docs/API_PARAMETER_MODEL.md`、`docs/API_LEARNING_SECURITY.md`、`docs/API_MODEL_VERSIONING.md`、`docs/API_CLASSIFICATION_DESIGN.md`、`docs/API_SCHEMA_PROTECTION.md`、`docs/API_IDENTITY_SECURITY.md`、`docs/API_AUTHORIZATION_ANALYSIS.md`、`docs/API_SENSITIVE_DATA.md`、`docs/API_BEHAVIOR_ANALYSIS.md`、`docs/API_SECURITY_GRAPH.md`、`docs/API_PRODUCT_SEPARATION.md`。
