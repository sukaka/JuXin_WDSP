# 知识库与 RAG 安全设计（阶段7）

本文档描述九章 WAF V2.0 AI 安全运营中心的知识库与 RAG 安全设计，与实现代码严格一致：

- 知识库 Agent：`server/internal/aiagents/misc_agents.go`（`KnowledgeAgent`）
- 编排与回答生成：`server/internal/aiorchestrator/`（`orchestrator.go` / `intent.go` / `evidence.go`）
- 知识工具：`server/internal/aitools/asset_tools.go`（`rule.get` / `rule.search`）
- 规则元数据：`server/internal/wafrules/`（同步）+ `waf_rules` 表（`server/migrations/000006_stage4.up.sql`）
- 任务书依据：`docs/tasks/STAGE_7_AI_SECURITY_OPERATIONS.md` §23（知识库与RAG）、§32.3（知识库防护）

## 1. 设计目标与安全底线

1. 知识内容一律作为**数据**处理，不得覆盖系统 Prompt 与安全 Prompt（任务书 §23.4、§32.3，验收项 58）；
2. 知识 ≠ 当前运行事实：知识解释不得冒充系统正在发生的攻击或状态（Agent 注册描述与输出声明均明确）；
3. 文档文件名、元数据、正文中的指令性内容（如"忽略之前规则""执行工具""泄露密钥""直接发布"）不执行；
4. 引用必须可追溯：回答中的证据引用经校验，无效引用被移除并显式声明，不静默通过；
5. 用户私人文档不自动进入企业正式知识库，进入必须经管理员审核（任务书 §23.5）；
6. 知识问答全程只读：不产生配置变更、不生成草稿、不触发发布。

## 2. 当前实现边界

**当前 `KnowledgeAgent` 为"规则内置知识"实现，完整 RAG 检索为后续演进。** 具体边界：

| 维度 | 当前实现 | 后续演进 |
|------|----------|----------|
| 知识载体 | `waf_rules` 表规则元数据（`rule_source` ∈ `OWASP_CRS` / `JIUZHANG_BUILTIN` / `USER_CUSTOM`）+ `rule.get` 命中统计 | 独立知识文档库（文档/章节/片段表） |
| 检索方式 | 规则 ID 精确查询 + 关键字 `ILIKE` 检索（最多 5 条） | 向量化语义检索（`ai_models.supports_embeddings` 字段已预留，默认 `FALSE`） |
| 文档接入 | 无文档上传/审核入口；数据库迁移中无 knowledge/RAG/embedding 类表 | 文档上传、分级、管理员审核流 |
| 问答输出 | 确定性事实文本 + 证据编号 + LLM 受约束总结 | 同左，事实来源扩展为文档片段 |

本文档 §3/§6/§7/§8 同时给出目标设计（任务书 §23）与当前实现的对应关系，未实现部分均显式标注。

## 3. 知识来源与文档分级

### 3.1 知识来源

任务书 §23.1 规定的知识来源及当前接入状态：

| 知识来源 | 目标级别 | 当前接入状态 |
|----------|----------|--------------|
| OWASP CRS 文档 | SYSTEM_OFFICIAL | **已接入**：CRS 规则元数据经 `wafrules` 同步入 `waf_rules`（`rule_source='OWASP_CRS'`，`crs_version` 记录版本，`file_name` 记录来源规则文件） |
| Coraza 文档 | SYSTEM_OFFICIAL | 未接入（后续） |
| 九章产品文档 | SYSTEM_OFFICIAL | 部分体现：Agent 输出中的产品说明为代码内置文案；文档库未接入 |
| 管理员手册 | SYSTEM_OFFICIAL | 未接入（后续） |
| 运维手册 | SYSTEM_OFFICIAL | 未接入（后续） |
| 安全事件处置指南 | ENTERPRISE_APPROVED | 未接入（后续） |
| 企业审核通过的文档 | ENTERPRISE_APPROVED | 未接入（后续） |

### 3.2 文档分级

任务书 §23.2 定义四级分级，正式回答优先使用 `SYSTEM_OFFICIAL` 和 `ENTERPRISE_APPROVED`：

```text
SYSTEM_OFFICIAL       系统官方知识（随系统版本发布，如 CRS 规则元数据、产品文档）
ENTERPRISE_APPROVED   企业审核通过的文档
USER_PRIVATE          用户私人文档（仅本人可参考）
UNVERIFIED            未验证文档（不得用于正式回答）
```

当前映射：`waf_rules` 中 `OWASP_CRS` 与 `JIUZHANG_BUILTIN` 属系统内置数据，相当于 `SYSTEM_OFFICIAL`；`USER_CUSTOM` 为管理面创建的自定义规则元数据，经权限管控后入库，语义上接近 `ENTERPRISE_APPROVED`。`USER_PRIVATE` / `UNVERIFIED` 两级在文档库落地前暂无对应载体。

## 4. 知识问答处理流程（当前实现）

```text
用户消息（POST /api/v1/ai/sessions/{id}/messages，权限 ai.chat.use）
   │
   ▼
Classify 意图分类（intent.go，确定性正则，非模型判断）
   │  TaskRuleExplanation（规则解释） → 调度 [waf_policy, knowledge]
   │  TaskGeneralQA（默认通用问答）   → 调度 [knowledge, security_event]
   ▼
KnowledgeAgent.Analyze（misc_agents.go）
   │
   ├─ 消息含规则 ID（ExtractIDs 提取 91x-96x/7100xxx/8000xxx 号段，取第 1 个）
   │     → callTool("rule.get")：只读工具，权限 waf_rules.read，超时 15s
   │     → Evidence.Add 登记证据，返回引用编号 [Ex]
   │
   └─ 无规则 ID → 关键字检索
         → 关键字 = 用户消息 TrimSpace 后截取前 50 字符
         → 参数化查询 waf_rules（name/message ILIKE $1，ORDER BY rule_id LIMIT 5）
         → 未命中：明示"本地规则库未找到直接相关内容，建议提供更具体的规则 ID 或攻击类型"
   ▼
FactsText（确定性事实文本，含 [Ex] 引用标记）
   ▼
composeAnswer：LLM 受约束总结（服务端固定 system Prompt）+ 事实正文
   ▼
ValidateCitations 引用校验 → 追加证据引用块 → 最终回答
```

输出侧两条固定声明（代码内置，非模型生成）：

- 开头：`**知识解答**（基于 OWASP CRS 与产品文档，非当前运行事实）`；
- 结尾：`说明：知识解释不代表当前系统正发生对应攻击；当前运行事实请以事件与统计查询为准。`

实现要点：

1. **未命中不编造**：关键字检索无结果时输出固定提示语，回答止于"无法确认"，不推测；
2. **参数化查询**：关键字经 `$1` 占位传入，无 SQL 拼接；
3. **关键字路径直查数据库**：该路径为 Agent 内直接查询 `waf_rules`（系统内置只读元数据），未经过 Tool 注册表权限校验；规则 ID 路径经 `rule.get` 工具，由注册表校验 `waf_rules.read`；
4. **Agent 可停用**：`knowledge` 在 `ai_agents` 表有注册行（`000015` 种子，默认 `ENABLED`），管理面停用后编排器跳过调度；
5. **规则详情内容**：`rule.get` 返回 `rule_id / name / severity / attack_type / rule_source / file / message / phase / hit_count / false_positive_count`（命中数取自 `security_event_matches`，误报数取自处置状态为 `CONFIRMED_FALSE_POSITIVE` 的关联事件），KnowledgeAgent 展示其中规则号、名称、攻击类型与严重级别。

## 5. 知识只作数据：不覆盖系统 Prompt

### 5.1 原则

知识文档中的"忽略之前规则""执行工具""泄露密钥""直接发布"等内容只能作为数据，不得覆盖系统和安全 Prompt（任务书 §23.4）；知识文档中的指令性内容不得执行（§32.3）。

### 5.2 当前落实点

| 机制 | 实现位置 | 作用 |
|------|----------|------|
| 系统 Prompt 服务端固定 | `composeAnswer` 内嵌总结器 system 文案；回答生成路径不读取任何库表或文档（`ai_prompts` 版本化管理目前仅为管理面功能，`Store.CurrentContent` 未被生成路径调用） | 知识内容没有进入 system 角色的通道 |
| 知识仅以 user 消息事实段出现 | `已核实事实（唯一可信来源）：` + `truncateRunes(factText, 3000)` | 注入面受限、长度受限（3000 字符） |
| 事实优先、LLM 仅总结 | 回答主体为 FactsText；LLM 只在其前加引导性总结，失败则降级为纯事实文本 | 即使模型被诱导，事实主体不变 |
| 总结器硬约束 | system 文案："只能复述给定事实中的信息，禁止编造任何数字、事件、规则、IP、时间"；`Temperature=0.2`、`MaxTokens=1024` | 抑制模型发挥 |
| 引用校验 | `ValidateCitations` 移除不存在的 `[Ex]` 引用，并追加"部分引用未能对应到本次查询证据"声明 | 防止伪造证据编号 |
| 只读工具链 | `rule.get` 为 `RiskReadOnly` + `waf_rules.read`；KnowledgeAgent 无任何写操作 | 知识问答不触发配置变更 |

现状说明：当前**没有独立的知识内容注入检测器**，注入防护依赖上述结构性约束（知识无 system 通道、只读、引用校验、长度截断）。任务书验收项 58（知识库内容不能覆盖系统指令）与 61（知识库注入测试通过）依赖对抗测试集验证，见任务书 §35.6。

## 6. 文档注入防护

威胁面（任务书 §35.6 测试清单与风险清单）：知识库文档注入、**文件名和文档元数据注入**、恶意知识库文件。典型载荷为在文件名、作者/标题等元数据或正文中嵌入"忽略之前规则""执行某工具""输出密钥"等指令性文本。

当前状态：系统**尚无文档上传入口**，上述攻击面尚不存在；现有知识载体 `waf_rules` 的 `name`/`message` 字段来源于 CRS 规则文件同步与管理面自定义规则创建，在回答中仅经文本格式化作为数据展示，不会被解析为指令执行。

文档库落地时必须满足（目标要求）：

1. 文件名、元数据、正文一律按不可信数据处理，入库与检索全链路不执行其中任何指令性内容；
2. 片段进入 LLM 上下文前以保持现状的"事实段"方式注入（user 角色），并标注为外部数据；
3. 文件名仅作展示字段，不参与路径拼接、不作为命令或 Prompt 片段解释；
4. 配套 §35.6 对抗测试：知识库文档注入、文件名与元数据注入用例必须通过方可上线。

## 7. 引用格式

目标格式（任务书 §23.3）：引用应包含**文档名、章节、版本和片段引用 ID**。

当前实现为证据编号机制（`evidence.go`）：

- 每条证据由 `EvidenceSet.Add(source, summary, detail)` 登记，编号 `E1..En`；
- `Source` 为来源标识（如 tool code `rule.get`），`Summary` 为一句话摘要，`Detail` 为工具返回内容；
- 回答中引用格式 `[E1]` / `[E1,E2]`（`citationRe` 校验），回答尾部自动生成 `**证据引用**` 列表块；
- `ValidateCitations` 校验全部引用编号，无效引用移除并显式声明。

目标要素与当前对应：

| 目标要素 | 当前对应物 |
|----------|-----------|
| 文档名 | 规则来源文件（`waf_rules.file_name`，如 CRS 规则文件）与规则名（`name`） |
| 章节 | 无直接对应（规则元数据以 `attack_type` / `phase` 标注分类与阶段）；文档库落地后由章节字段承载 |
| 版本 | `waf_rules.crs_version`（表约束 `UNIQUE(rule_id, rule_source, crs_version)` 保证版本维度唯一） |
| 片段引用 ID | 证据编号 `[Ex]` + 规则 ID（`rule_id`） |

## 8. 用户私人文档与企业知识库隔离

原则（任务书 §23.5）：用户私人文档只能作为该用户的个人参考资料，**不自动进入企业正式知识库**；进入企业知识库必须经过管理员审核。

当前实现：文档功能尚未落地，无私人文档载体。既有隔离先例可沿用——AI 会话与 Memory 已按用户隔离，权限点为 `*_own` 系列（`ai.sessions.read_own` / `ai.sessions.delete_own` / `ai.memories.read_own` / `ai.memories.manage_own`，见 `000014_seed_stage7_perms.up.sql`）。文档库落地时须满足：

1. 私人文档默认 `USER_PRIVATE` 级，仅本人会话可检索；
2. 私人文档 → 企业库必须经管理员审核并转为 `ENTERPRISE_APPROVED`，审核动作记录操作审计；
3. 跨用户隔离与越权访问纳入水平/垂直越权测试（任务书验收项 64/65 同标准）。

## 9. 权限与第三方组件许可

权限点：

| 能力 | 权限点 |
|------|--------|
| AI 会话创建/消息发送/停止/重试/反馈 | `ai.chat.use` |
| 规则详情工具 `rule.get` | `waf_rules.read` |
| 规则检索工具 `rule.search` | `waf_rules.read` |

第三方组件许可（知识来源与模型运行相关）：

| 组件 | 用途 | 许可证 |
|------|------|--------|
| OWASP CRS | 规则知识来源（规则元数据同步入库） | Apache-2.0 |
| Coraza WAF | 网关检测引擎（其文档为后续知识来源） | Apache-2.0 |
| Ollama | 本地模型运行时的默认供应商（`provider_type='ollama'`，OpenAI 兼容协议接入） | MIT |
| Qwen2.5 | 默认本地模型（种子 `qwen2.5:3b`） | Apache-2.0 |

## 10. 后续演进（完整 RAG 落地清单）

1. 文档接入：知识文档表（文档/章节/片段三级）、分级字段与管理员审核流（`USER_PRIVATE` → `ENTERPRISE_APPROVED`）；
2. 片段化与片段引用 ID，引用格式升级为"文档名+章节+版本+片段 ID"（§7）；
3. 向量化语义检索：`ai_models.supports_embeddings` 标志已预留，嵌入模型接入后启用；
4. 知识内容注入检测器与对抗测试集（任务书 §35.6：知识库文档注入、文件名和元数据注入）；
5. 上下文 Token 预算中为知识库设置独立预算（任务书 §22.2）。

## 关联文档

- [阶段7任务书：AI 安全运营中心](tasks/STAGE_7_AI_SECURITY_OPERATIONS.md)（§22 上下文预算、§23 知识库与RAG、§32 安全防护、§35 测试）
- [WAF 策略设计](WAF_POLICY_DESIGN.md)（规则库与 `waf_rules` 元数据来源）
- [RBAC 设计](RBAC_DESIGN.md)（权限点体系）
- [安全设计](SECURITY_DESIGN.md)
- [开源合规](OPEN_SOURCE_COMPLIANCE.md)（第三方组件许可证清单）
- [监控告警设计](MONITORING_ALERTING_DESIGN.md)（阶段6 基座，知识问答引用的运行事实来源之一）
