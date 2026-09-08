# AI 模型网关设计（阶段7）

本文档描述九章 WAF V2.0 阶段7（AI 安全运营中心）的模型网关设计，与实现代码严格一致：

- 模型网关：`server/internal/aimodel/`（client.go / gateway.go / store.go）
- 管理接口：`server/internal/aihandlers/handler.go`、`server/internal/aihandlers/models_handler.go`
- 数据表：`server/migrations/000013_stage7.up.sql`（`ai_model_providers` / `ai_provider_secrets` / `ai_models`）
- 种子数据：`server/migrations/000015_seed_stage7_model.up.sql`（本地 Ollama 供应商、默认模型、路由档位默认值）

## 1. 设计目标与安全底线

1. AI 业务不直接绑定单一供应商：所有模型调用统一经 `aimodel.Gateway` 路由，供应商/模型以配置形式注册；
2. 密钥绝不外泄：API 密钥经 AES-256-GCM 加密落库，任何接口响应不回传明文或密文，不写日志、不进 Prompt、不进 AI 审计正文；
3. 按复杂度路由：简单/标准/高能力三档任务路由到不同模型，档位配置持久化于 `system_settings` 且变更热生效，无需重启；
4. 故障可降级：单模型连续失败自动熔断，同档候选按优先级主备切换，档位无路由时回退标准档兜底；
5. 默认零外联：出厂种子指向本地 Ollama 运行时（`qwen2.5:3b`），不配置任何外部密钥即可工作。

## 2. 总体架构

```text
┌──────────────────────────────────────────────────────────────┐
│ 管理前端：系统设置 → AI 模型（供应商/模型/路由档位/测试）        │
└──────────────────────────┬───────────────────────────────────┘
                           │ REST（认证 + 权限点）
┌──────────────────────────▼───────────────────────────────────┐
│ aihandlers（models_handler.go）                               │
│   供应商 CRUD / rotate-key / 模型 CRUD / 启停 / test / routes │
└───────────┬───────────────────────────────┬──────────────────┘
            │ 读写                           │ 变更后 ReloadRoutes
┌───────────▼─────────────┐      ┌──────────▼─────────────────┐
│ aimodel.Store（store.go）│      │ aimodel.Gateway（gateway.go）│
│  供应商/模型持久化        │      │  内存路由表 + 熔断状态        │
│  密钥加解密（KeyResolver）│◄─────│  Chat / ChatStream          │
└───────────┬─────────────┘      └──────────┬─────────────────┘
            │ ai_model_providers            │ OpenAI 兼容协议
            │ ai_models / ai_provider_secrets▼
┌───────────▼─────────────┐      ┌─────────────────────────────┐
│ PostgreSQL 16           │      │ aimodel.OpenAIClient         │
│ （密钥仅存密文）          │      │ （client.go）                 │
└─────────────────────────┘      └──────────┬─────────────────┘
                                            │ POST {base_url}/v1/chat/completions
                              ┌─────────────▼──────────────┐
                              │ 模型运行时                   │
                              │ 本地 Ollama（ollama:11434）  │
                              │ 或任意 OpenAI 兼容API        │
                              └────────────────────────────┘
```

装配关系（`server/internal/app/app.go`）：`aimodel.NewStore(db, encSvc)` 创建仓储；`aimodel.NewGateway(aiModelStore)` 创建网关——`Store` 实现 `KeyResolver` 接口，密钥解密不出服务端进程；启动时调用 `aiDeps.ReloadRoutes` 从数据库加载路由表（加载失败仅记日志，不阻断启动）；`aiDeps.RegisterRoutes` 挂载全部管理路由。

## 3. 数据模型

### 3.1 ai_model_providers（模型供应商）

| 列 | 类型 | 说明 |
|----|------|------|
| id | UUID PK | 默认 `gen_random_uuid()` |
| name | VARCHAR(100) | 供应商名称，唯一索引 `ux_ai_model_providers_name` |
| provider_type | VARCHAR(30) | `openai_compatible` / `anthropic` / `ollama` / `local`（接口层白名单校验） |
| base_url | VARCHAR(255) | OpenAI 兼容API根地址（不含 `/v1/...` 路径） |
| api_key_reference | VARCHAR(100) | 密钥引用名，密文存 `ai_provider_secrets`；本地供应商为空串 |
| status | VARCHAR(20) | `ENABLED` / `DISABLED`，默认 `ENABLED` |
| created_at / updated_at | TIMESTAMPTZ | 创建/更新时间 |

### 3.2 ai_provider_secrets（供应商密钥，永不回传）

| 列 | 类型 | 说明 |
|----|------|------|
| id | UUID PK | 默认 `gen_random_uuid()` |
| reference | VARCHAR(100) UNIQUE | 引用名（对应供应商的 `api_key_reference`，如 `provider-{id前8位}`） |
| encrypted_key | TEXT | AES-256-GCM 密文（base64，含 nonce） |
| created_at | TIMESTAMPTZ | 创建时间 |
| rotated_at | TIMESTAMPTZ | 最近一次写入/轮换时间 |

### 3.3 ai_models（模型）

| 列 | 类型 | 默认值 | 说明 |
|----|------|--------|------|
| id | UUID PK | - | - |
| provider_id | UUID FK → ai_model_providers | - | 所属供应商 |
| model_code | VARCHAR(100) | - | 供应商侧模型编码（如 `qwen2.5:3b`）；`(provider_id, model_code)` 唯一 |
| display_name | VARCHAR(100) | - | 展示名 |
| context_window | INTEGER | 8192 | 上下文窗口 |
| max_output_tokens | INTEGER | 2048 | 最大输出 Token |
| supports_tools | BOOLEAN | FALSE | 是否支持 Tool 调用 |
| supports_streaming | BOOLEAN | TRUE | 是否支持流式（决定走 `ChatStream` 还是 `Chat`） |
| supports_structured_output | BOOLEAN | FALSE | 结构化输出能力标记（当前建模型置 FALSE） |
| supports_embeddings | BOOLEAN | FALSE | 嵌入能力标记（当前建模型置 FALSE） |
| priority | INTEGER | 100 | 同档路由优先级，小值优先 |
| timeout_seconds | INTEGER | 60 | 单次调用超时（接口层归一范围 1–600s） |
| cost_input_unit / cost_output_unit | NUMERIC(12,8) | 0 | 每千输入/输出 Token 成本单位（本地模型为 0） |
| status | VARCHAR(20) | ENABLED | `ENABLED` / `DISABLED` |

### 3.4 system_settings 路由档位

路由档位复用通用配置表 `system_settings`，`setting_group='ai'`，三个键（种子迁移 000015 预置，值均为 `"qwen2.5:3b"`）：

| setting_key | 档位 | 说明 |
|-------------|------|------|
| route_simple | simple | 分类/简单问答 → 低成本模型 |
| route_standard | standard | 单事件分析 → 标准模型 |
| route_high | high | 攻击链/复杂根因 → 高能力模型 |

档位值为 `model_code` 字符串（JSONB 存储）。更新走 `upsertRouteSetting`（`ON CONFLICT ... version+1`），读取经 `settings.Service.GetString`，缺省回退常量 `defaultModelCode = "qwen2.5:3b"`（配置缺失不致命）。

## 4. OpenAI 兼容客户端（client.go）

`OpenAIClient` 封装 OpenAI 兼容协议，Ollama / vLLM / 各类 OpenAI 兼容网关通用；底层 `http.Client` 超时 5 分钟（长生成上限），单次调用实际超时由模型 `timeout_seconds` 经 context 控制。

### 4.1 统一请求/响应模型

- 请求 `ChatRequest`：`Messages`（role/content）、`MaxTokens`、`Temperature`、`Stream`、`JSONMode`（置 `response_format={"type":"json_object"}`）；
- 结果 `ChatResult`：`Content`、`FinishReason`（归一化为 `stop` / `length`，`max_tokens` 并入 `length`）、`InputTokens`、`OutputTokens`、`ModelCode`；
- 成本：`ChatResult.UsageCost(m)` = `InputTokens/1000 × cost_input_unit + OutputTokens/1000 × cost_output_unit`。

### 4.2 Chat（非流式）

`POST {base_url}/v1/chat/completions`（`base_url` 尾部 `/` 先裁剪）；`Authorization: Bearer <key>` 仅在密钥非空时设置（本地 Ollama 无密钥）；响应体上限 4MiB；非 200、`error` 字段非空、`choices` 为空、连接失败均归一包装为 `ErrModelDown`（错误串截断至 200 字符，避免异常长响应冲刷日志）。

### 4.3 ChatStream（SSE 流式）

请求头加 `Accept: text/event-stream`，`stream=true`。解析逻辑：

- 按 `\n\n` 切事件、按行匹配 `data:` 前缀，`[DONE]` 跳过；
- 逐 chunk 提取 `choices[].delta.content` 拼接全文，并经 `StreamCallback(delta, done=false)` 实时外推；`finish_reason` 归一化记录；
- 部分实现（含 Ollama 兼容API）在末尾 chunk 携带 `usage`，客户端予以采纳；
- 流式无 `usage` 时按字符估算 Token：`estimateTokens` 中 CJK 字符按 2/3 token/字、其余按 1/4 token/字符近似（粗略估算，仅用于用量兜底）；
- 结束时回调 `cb("", true, result)` 送出聚合结果；错误响应读取上限 1MiB。

### 4.4 HealthCheck（健康检查）

`HealthCheck` 以 15s 超时发送一条短对话（`user: "ping"`，`max_tokens=5`），验证连通性 + 鉴权 + 基本生成能力，供管理面"测试模型"与全量巡检使用。

### 4.5 错误语义

| 错误 | 语义 |
|------|------|
| `ErrNoModel` | 目标档位（含 standard 兜底）无任何候选模型 |
| `ErrModelDown` | 模型不可达 / 非 200 / 返回 error / 空 choices |
| `ErrInvalidRequest` | 请求参数非法（预留） |
| `ErrNotFound`（store.go） | 供应商/模型不存在（接口层映射 404） |

## 5. 模型路由与热生效（gateway.go + store.go）

### 5.1 复杂度档位

`TaskComplexity` 三档：`simple` / `standard` / `high`（常量 `ComplexitySimple` / `ComplexityStandard` / `ComplexityHigh`）。调用方按任务复杂度选择档位：

- `Gateway.Chat(ctx, complexity, req)`：路由式非流式对话；
- `Gateway.ChatStream(ctx, complexity, req, cb)`：路由式流式对话（仅当模型 `supports_streaming=true` 时真正走 SSE，否则回落非流式）。

### 5.2 路由表加载（LoadRoutes）

`Store.LoadRoutes(ctx, simpleCode, standardCode, highCode)` 从数据库构建路由表：

1. 三个档位各按 `model_code` 匹配 `status=ENABLED` 且供应商 `ENABLED` 的模型入档；
2. 未配置 standard 档时，**全部启用模型进入 standard 档兜底**，保证"有模型即可用"；
3. `Gateway.SetRoutes` 将各档候选按 `priority` 升序排序（小值优先 = 主模型，其余为备模型）。

### 5.3 调用过程（chatWith）

```text
按档位取候选 → 为空则取 standard 档 → 仍为空返回 ErrNoModel
  └─ 遍历候选（priority 升序）：
       熔断中 → 跳过
       按 model.timeout_seconds（≤0 时默认 60s）起超时 context
       流式回调且支持流式 → ChatStream，否则 Chat
       成功 → recordResult 清零失败计数，返回结果
       失败 → recordResult 计入熔断，切换下一候选
  └─ 全部失败 → 返回最后一次错误
```

### 5.4 持久化 + 热生效

路由档位持久化在 `system_settings`（见 §3.4）。以下管理操作成功后均调用 `Deps.ReloadRoutes`（重新 `LoadRoutes` + `SetRoutes`），**变更即时热生效，无需重启服务**：

- 更新供应商（状态/BaseURL 影响候选资格）；
- 创建/更新/删除模型、启用/停用模型；
- 更新路由档位（`PUT /api/v1/ai/models/routes`）。

服务启动时同样执行一次 `ReloadRoutes`（app.go），失败仅告警不阻断启动。

## 6. 熔断器（gateway.go）

熔断状态保存在网关进程内存（`map[modelID]*circuitState`，RWMutex 保护）：

| 参数 | 值 | 说明 |
|------|-----|------|
| 熔断阈值 `circuitThreshold` | 3 | 同一模型连续失败 3 次即打开熔断 |
| 冷却时长 `circuitCooldown` | 60s | 打开后 60 秒内该模型被跳过 |
| 恢复方式 | 成功即复位 | 任一次调用成功清零失败计数并解除熔断 |

设计决策：熔断为**进程内存态**，重启后重新计数（可接受的近似，与监控告警的 `flapTracker` 同思路）；熔断按模型粒度而非供应商粒度，同一供应商的其他模型不受影响；熔断到期后下一次调用自然试探，成功即恢复，无需人工干预。

## 7. 多供应商与多模型管理

### 7.1 管理接口清单

全部接口强制认证 + 权限点校验（`ai.models.read` 查看 / `ai.models.manage` 管理），注册于 `aihandlers.RegisterRoutes`：

| 能力 | 接口 | 权限 |
|------|------|------|
| 供应商列表 | `GET /api/v1/ai/models/providers` | `ai.models.read` |
| 创建供应商 | `POST /api/v1/ai/models/providers`（`api_key` 可选，明文入参即加密存储） | `ai.models.manage` |
| 更新供应商 | `PATCH /api/v1/ai/models/providers/{id}`（名称/类型/BaseURL/状态；**密钥走 rotate-key**） | `ai.models.manage` |
| 删除供应商 | `DELETE /api/v1/ai/models/providers/{id}`（仍有关联模型时 409） | `ai.models.manage` |
| 轮换密钥 | `POST /api/v1/ai/models/providers/{id}/rotate-key` | `ai.models.manage` |
| 模型列表 | `GET /api/v1/ai/models` | `ai.models.read` |
| 创建模型 | `POST /api/v1/ai/models` | `ai.models.manage` |
| 更新模型 | `PUT /api/v1/ai/models/{id}`（不含状态与密钥） | `ai.models.manage` |
| 删除模型 | `DELETE /api/v1/ai/models/{id}` | `ai.models.manage` |
| 启用/停用 | `POST /api/v1/ai/models/{id}/enable`、`POST /api/v1/ai/models/{id}/disable` | `ai.models.manage` |
| 测试模型 | `POST /api/v1/ai/models/{id}/test`（单模型健康检查，只读探测） | `ai.models.read` |
| 读路由档位 | `GET /api/v1/ai/models/routes`（含 `loaded_models` 已加载模型数） | `ai.models.read` |
| 改路由档位 | `PUT /api/v1/ai/models/routes`（未提供的档位保持现状） | `ai.models.manage` |

权限点种子见 `server/migrations/000014_seed_stage7_perms.up.sql`（`ai.models.read` 查看AI模型、`ai.models.manage` 管理AI模型）。

### 7.2 参数校验与归一

- 供应商：名称必填 ≤100 字符；`provider_type` 白名单四值；`base_url` 必填 ≤255 字符；状态仅 `ENABLED/DISABLED`；
- 模型：`provider_id` 必须存在；`model_code` 必填 ≤100 字符；`normalizeModel` 归一边界——context_window ≤0 取 8192、max_output_tokens ≤0 取 2048、timeout_seconds 超出 1–600 取 60、priority ≤0 取 100、成本负值取 0；display_name 为空取 model_code；
- 路由档位：目标 `model_code` 必须已存在，空串档位视为"不修改"，全部为空报 400。

## 8. 密钥安全

### 8.1 加密存储

- 算法：AES-256-GCM（`server/internal/encryption`，与备份加密同一服务）；密文 base64 输出（nonce 随密文），主密钥来自环境变量 `JIUZHANG_MASTER_KEY`，未配置时加密服务不可用（`ErrNoMasterKey`）；
- 写入路径：`Store.saveSecret` 对 `ai_provider_secrets` 做 `INSERT ... ON CONFLICT (reference) DO UPDATE`（创建与轮换同一路径），`rotated_at` 每次更新；
- 引用名：供应商创建/轮换时若 `api_key_reference` 为空，自动生成 `provider-{供应商ID前8位}` 并回写供应商行；
- 读取路径：仅 `Gateway.apiKey` 经 `KeyResolver.DecryptSecret` 在调用瞬间解密，**绝不记录日志**；解密失败按无密钥处理（空串），不向外传递错误细节。

### 8.2 响应永不回传

- 供应商 DTO（`providerDTO`）只含 `api_key_reference` 引用名，不含明文或密文；`ListProviders` / `GetProvider` 的 SQL 均不查询 `ai_provider_secrets`；
- 密钥只出现于两处入参：创建供应商（`api_key` 可选）与 rotate-key（`api_key` 必填非空）；更新供应商接口不接受密钥字段；
- AI 审计摘要（如 `轮换供应商密钥 {id}`）不含任何密钥材料。

### 8.3 轮换（rotate-key）

`POST /api/v1/ai/models/providers/{id}/rotate-key`（`ai.models.manage`）：明文仅作入参，`Store.RotateKey` 校验非空 → 取/生成引用名 → 加密覆盖落库。由于网关每次调用实时解密，**轮换即刻生效**，无需重载路由或重启。操作记 AI 审计（action `model_key_rotate`）。

## 9. 本地 Ollama 运行时

默认部署不依赖任何外部模型服务：种子迁移 000015 预置本地供应商与模型。

| 项 | 值 |
|----|-----|
| 供应商 | `ollama-local`（type `ollama`，`http://ollama:11434`，无密钥，ENABLED） |
| 默认模型 | `qwen2.5:3b`（Qwen2.5 3B（本地）；context 32768，max_output 2048，支持流式，priority 1，timeout 120s，成本 0） |
| 容器 | `ollama/ollama:0.9.6`（`deployment/docker-compose.stage5.yml`，容器名 `jiuzhang-stage5-ollama`） |
| 网络 | 仅接入内网 bridge（`stage5-net`），服务端经内网 DNS `ollama:11434` 访问；宿主机端口绑定 `127.0.0.1:${OLLAMA_PORT:-11434}`，不暴露公网 |
| 数据卷 | `stage5-ollama-data` → `/root/.ollama`（模型文件持久化） |
| 加固 | `no-new-privileges:true`；健康检查 `ollama list`（15s 间隔） |
| 首次拉取 | `docker exec jiuzhang-stage5-ollama ollama pull qwen2.5:3b` |

许可证：Ollama 为 MIT，Qwen2.5 为 Apache-2.0，均符合项目宽松许可证要求。

设计决策：三档路由默认值全部指向 `qwen2.5:3b`——开箱即用、零成本、数据不出内网；需要更高能力时，注册外部 OpenAI 兼容供应商（如 vLLM/商业 API 网关）后调整档位即可，切换即时生效。小模型能力边界由编排器侧的提示词与评估机制约束，不在本文档范围。

## 10. AI 审计

模型管理操作全部写入 AI 审计链路（`ai_audit_records`，独立哈希链，见关联文档）：

| Action | 触发 |
|--------|------|
| `model_provider_create` / `model_provider_update` | 创建/更新供应商 |
| `model_key_rotate` | 轮换密钥 |
| `model_create` / `model_update` / `model_delete` / `model_status` | 模型增改删/启停 |
| `model_test` | 健康检查（结果记 SUCCESS/FAILED） |
| `model_route_update` | 更新路由档位 |

## 11. 验证

- 接口测试：`server/internal/aihandlers/handler_test.go` 覆盖阶段7 接口层（含模型/供应商/路由档位管理与权限校验）；
- 集成验证路径：种子加载后 `GET /api/v1/ai/models/routes` 三档均为 `qwen2.5:3b` 且 `loaded_models ≥ 1`；`POST /api/v1/ai/models/{id}/test` 返回连通性正常；停用模型后路由候选自动剔除；连续 3 次失败后该模型 60s 内被跳过、候选切换。

## 12. 关联文档

- [阶段7 任务书（AI 安全运营中心）](tasks/STAGE_7_AI_SECURITY_OPERATIONS.md)
- [数据库设计](DATABASE_DESIGN.md)
- [接口设计](API_DESIGN.md)
- [安全设计](SECURITY_DESIGN.md)
- [备份恢复设计](BACKUP_RESTORE_DESIGN.md)（加密服务同源）
- [监控告警设计](MONITORING_ALERTING_DESIGN.md)
- [审计设计](AUDIT_DESIGN.md)
- [开源合规](OPEN_SOURCE_COMPLIANCE.md)
