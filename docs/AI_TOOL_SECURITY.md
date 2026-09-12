# AI Tool 安全设计（阶段7）

本文档描述九章 WAF V2.0 阶段7 AI 安全运营中心 Tool 体系的安全设计，与实现代码严格一致：

- Tool 注册中心与统一执行链：`server/internal/aitools/registry.go`
- 只读 Tool（26 个）：`server/internal/aitools/event_tools.go`、`log_tools.go`、`asset_tools.go`、`access_tools.go`
- 草稿 Tool（5 个）：`server/internal/aitools/draft_tools.go`、`draft_store.go`
- 管理面（启停/同步/配置）：`server/internal/aihandlers/agents_tools_handler.go`
- 审计落库（哈希链）：`server/internal/aiaudit/aiaudit.go`
- 装配点：`server/internal/app/app.go`（注册 Tool、`SetEnabledChecker`、启动同步 `SyncRegistry`）

Tool 层与具体大模型解耦：模型侧为 Ollama（MIT 许可证）运行的 Qwen2.5（Apache-2.0 许可证），模型只能"提议"调用哪个 Tool 并给出入参，能否执行完全由本文档描述的服务端控制链决定。

## 1. 设计目标与安全原则

1. **AI 不直接改变生产防护状态**：阶段7只允许 `READ_ONLY`（只读查询）与 `DRAFT_ONLY`（生成草稿）两类 Tool；任何影响防护效果的动作（启用规则、封禁、发布配置等）必须经人工在对应业务模块完成。
2. **权限点强制**：每个 Tool 在代码中绑定 `required_permission`，每次执行前以当前用户真实权限重新校验，拒绝即留痕。
3. **危险操作不入 Tool**：`shell.execute`、`database.raw_query`、`gateway.publish_direct` 等高危能力根本不实现为 Tool（见第 9 节），模型无从发起。
4. **草稿绝不自动发布/生效**：所有草稿落库即为 `DRAFT`/`DISABLED` 状态、标记 AI 生成、记录来源与证据，发布走既有人工校验发布流程。
5. **审计留痕且脱敏**：每次 Tool 调用（含被拒绝、超时、失败）写入 AI 审计哈希链，入参只留摘要，密钥/密码/私钥不进入审计正文。
6. **Tool 可独立启停**：管理面可停用任一 Tool，执行路径每次实时查库强制生效。

## 2. Tool 统一契约与注册中心

每个 Tool 实现 `Tool` 接口（registry.go），元数据经内嵌 `baseTool` 暴露：

| 契约方法 | 含义 | 安全用途 |
|----------|------|----------|
| `Code()` | Tool 编码（如 `security_event.search`） | 注册键、审计键、启停键 |
| `Name()` / `Description()` / `Version()` | 名称/说明/版本 | 管理面展示、审计记录 `tool_version` |
| `RiskLevel()` | `READ_ONLY` / `DRAFT_ONLY` | 风险分级（第 3 节） |
| `RequiredPermission()` | 所需权限点（空表示仅需登录；当前 31 个 Tool 全部非空） | 执行前强制校验 |
| `TimeoutSeconds()` | 超时秒数（≤0 时按 30s 兜底） | `context.WithTimeout` 强制中断 |
| `MaxResults()` | 最大返回数量声明 | 输出规模上限（第 5 节） |
| `InputSchema()` | 输入 JSON Schema | 展示与入参约定；服务端另有强制校验 |
| `Run(ctx, input)` | 执行（入参 JSON，出参可序列化结构） | 各 Tool 自行完成参数校验与查询 |

`Registry.Execute` 是唯一执行入口，顺序固定（`aiorchestrator` 以当前会话用户构建 `Principal{UserID, Username, Permissions}` 后调用）：

```text
查找 Tool（不存在 → ErrToolNotFound）
  → 启停校验（ai_tools.status != ENABLED → ErrToolDisabled）
  → 组装审计记录（含 summarizeInput 入参摘要）
  → 权限校验（无权限 → 记 DENIED 审计 + ErrPermission）
  → context.WithTimeout 包裹 Run
      ├─ 正常返回 → 记 SUCCESS
      ├─ 截止超限 → 记 TIMEOUT + ErrTimeout
      └─ 其他错误 → 记 FAILED + 原始错误
```

设计决策：启停校验放在计时与权限校验之前——被停用的 Tool 立即拒绝且不消耗查询资源；权限校验放在审计记录组装之后——拒绝调用本身也进入审计链（`DENIED / PERMISSION_DENIED`），越权试探可见。

## 3. 风险分级模型

任务书定义四级风险：`READ_ONLY / DRAFT_ONLY / REQUIRES_CONFIRMATION / PROHIBITED`。**阶段7只实现前两级**（registry.go 仅定义 `RiskReadOnly`、`RiskDraftOnly` 两个常量），后两级不开放：需要确认级动作一律降级为"草稿 + 人工在业务模块审批"，禁止级动作不实现为 Tool。

| 等级 | 数量 | 语义 | 实现约束 |
|------|------|------|----------|
| `READ_ONLY` | 26 | 只读查询：事件/日志/资产/策略/统计 | 只执行 SELECT；固定列白名单；时间范围、页大小、返回数量受限 |
| `DRAFT_ONLY` | 5 | 生成草稿：例外/黑名单/CC策略/自定义规则/报告总结 | 落库即 `DRAFT`/`DISABLED`；标记 AI 生成；不触碰任何发布链路 |
| `REQUIRES_CONFIRMATION` | 0（不开放） | 任务书预留 | 由"DRAFT_ONLY 草稿 + 既有业务模块人工审批"替代 |
| `PROHIBITED` | 0（不开放） | 直接生效的高危操作 | 不实现为 Tool（第 9 节禁止清单） |

### 3.1 只读 Tool 清单（26 个，全部 `READ_ONLY`）

| Code | 权限点 | 超时(s) | MaxResults |
|------|--------|---------|-----------|
| security_event.search | security_events.read | 20 | 50 |
| security_event.get | security_events.read | 10 | 1 |
| security_event.related | security_events.read | 15 | 20 |
| security_event.statistics | security_events.read | 30 | 100 |
| security_event.disposition_summary | security_events.read | 15 | 10 |
| access_control_log.search | access_control_events.read | 20 | 50 |
| audit_log.search | audits.read | 20 | 50 |
| request_trace.get | security_events.read | 15 | 30 |
| system_log.search | system_alerts.read | 15 | 50 |
| application.search | applications.read | 15 | 50 |
| application.get | applications.read | 10 | 1 |
| certificate.get_metadata | certificates.read | 10 | 50 |
| gateway.get_status | gateway_status.read | 15 | 1 |
| policy.get | protection_policies.read | 10 | 50 |
| rule.search | waf_rules.read | 20 | 50 |
| rule.get | waf_rules.read | 15 | 1 |
| exception.search | exceptions.read | 15 | 50 |
| access_rule.search | access_rules.read | 15 | 50 |
| temporary_block.search | temporary_blocks.read | 15 | 50 |
| rate_limit_policy.search | rate_limits.read | 15 | 50 |
| trusted_proxy.get_summary | trusted_proxies.read | 10 | 10 |
| statistics.security_overview | analytics.security.read | 30 | 1 |
| statistics.attack_trend | analytics.security.read | 30 | 200 |
| statistics.top_source_ips | analytics.security.read | 30 | 20 |
| statistics.top_rules | analytics.security.read | 30 | 20 |
| statistics.runtime | dashboard.runtime.read | 20 | 20 |

只读 Tool 复用既有业务模块的读权限点，不为 AI 单独开设数据通道——用户在前端看不到的数据，AI 同样查不到。

### 3.2 草稿 Tool 清单（5 个，全部 `DRAFT_ONLY`）

| Code | 权限点 | 目标表（初始状态） | 超时(s) |
|------|--------|--------------------|---------|
| draft.exception.create | ai.draft.exception | exception_policies（`DISABLED`） | 15 |
| draft.blacklist.create | ai.draft.blacklist | ip_access_rules（`DRAFT`） | 15 |
| draft.cc_policy.create | ai.draft.cc_policy | rate_limit_policies（`DISABLED`） | 15 |
| draft.custom_rule.create | ai.draft.custom_rule | custom_rules（`DISABLED`） | 15 |
| draft.report_summary.create | ai.report_summary.use | ai_recommendations（`DRAFT`，仅登记总结） | 15 |

草稿权限点为 AI 专有（种子迁移 `000014_seed_stage7_perms.up.sql`）：安全管理员（SECURITY_ADMIN）拥有全部草稿权限；系统管理员拥有 `ai.tools.manage` 等管理权限但不拥有草稿权限。

## 4. 权限点强制

- **绑定在代码里**：每个 Tool 的 `permission` 在注册时硬编码（如 `draft.blacklist.create → ai.draft.blacklist`），启动时由 `SyncRegistry` 同步到 `ai_tools.required_permission`（code 唯一 upsert，仅更新元数据，保留启停状态）。
- **每次执行重新校验**：`Execute` 内 `if req := t.RequiredPermission(); req != "" && !p.HasPermission(req)` 拒绝执行。权限不缓存、不随模型会话"继承"——`Principal.Permissions` 由编排器在当轮对话开始时从当前登录用户的真实权限集构建，管理员在 AI 会话进行中收回权限，下一次 Tool 调用立即被拒绝。
- **拒绝即留痕**：权限不足时先写审计（`Status=DENIED`、`ErrorCode=PERMISSION_DENIED`），再返回 `ErrPermission`。
- **空权限语义**：`RequiredPermission()` 返回空表示"仅需登录"；`HasPermission("")` 恒为 false 防止空串误判为"有权限"。当前 31 个 Tool 全部声明了非空权限点。

## 5. 输入校验与输出截断

### 5.1 输入校验与长度限制

统一辅助函数（registry.go）：`Decode`（非法 JSON → `ErrInvalidInput`）、`StrField(m, key, maxLen)`（超长按字节截断）、`IntField`、`BoolField`。各 Tool 在 `Run` 内做业务级校验，典型限制：

| 校验项 | 实现 | 位置 |
|--------|------|------|
| 时间范围 | 默认最近 24h；`start_time < end_time`；跨度 >90 天拒绝 | `parseTimeRange`（event_tools.go，日志 Tool 复用） |
| 名称/原因长度 | name ≤200、reason ≤500、summary ≤8000、operator_value ≤512 | `StrField` 截断 |
| 证据引用 | 单项 ≤200 字符、非字符串丢弃 | `evidenceList`（draft_tools.go） |
| 数值范围 | CC：`requests_limit` 1-1000000、`window_seconds` 1-86400；`TEMP_BLOCK` 要求 `block_duration_seconds` 60-2592000 | draftCCPolicy.Run |
| 枚举白名单 | CC `dimension` 仅 CLIENT_IP/APPLICATION/CLIENT_IP_AND_URI/CLIENT_IP_AND_APPLICATION | draftCCPolicy.Run |
| 规则ID段 | 自定义规则 `rule_id` 必须 7100000-7199999；复用 `customrules.ValidateInput`（操作符白名单等） | draftCustomRule.Run |
| 地址规范化 | `accessrules.NormalizeAddress`（IP/CIDR），保护地址经 `ProtectedChecker.IsProtected` 检查后**拒绝封禁** | draftBlacklist.Run |
| 宽泛例外拦截 | `Exception.IsBroad()` 为真即拒绝：草稿必须指定 应用/域名/URI/规则ID/参数 之一 | draftException.Run |
| 临时时长 | 临时例外/黑名单 `duration_hours` 1-720 | draftException/draftBlacklist.Run |
| 必填约束 | APPLICATION 范围必须给 `application_id`；报告总结正文 ≥20 字符 | 各 Run |

所有查询使用参数化 SQL（`$n` 占位）；`client_ip` 过滤显式 `$n::inet` 转换，非法地址直接报错。

### 5.2 输出截断（MaxResults 与字段白名单）

- **数量上限**：`MaxResults` 在元数据中声明（1~200，见 3.1/3.2 表）并同步入库。实际返回量由各 Tool `Run` 内的 SQL `LIMIT` 与分页硬控：搜索类固定每页 20 条（`pageSize = 20`），事件详情的关联命中 `LIMIT 20`、关联事件 `LIMIT 20`、证书/策略列表 `LIMIT 50`、`system_log.search` 固定 30 条、排行类 `limit` 入参钳制 1-50（默认 10，越界回退默认）——均不超过各自 `max_results` 声明值。
- **MaxResults/超时的管理面调整现状**：`ToolPatch` 允许修改 `max_results`（1-1000）与 `timeout_seconds`（1-300s），但**仅落库**；当前执行管线以代码声明的 `TimeoutSeconds()` 为准、返回量以上述 SQL 自控为准，DB 修改不改变运行行为（与 `AI_TOOL_DESIGN.md` 3.4 节一致）。
- **字段白名单**：SELECT 列固定写死，不存在 `SELECT *`；如 `security_event.search` 仅返回 id/时间/攻击类型/等级/动作/客户端IP/域名/应用/方法/路径/评分，`request_path` 经 `left(request_path,255)` 截断。
- **敏感字段不出库**：`certificate.get_metadata` 只选 `id, name, common_name, issuer, not_before, not_after, status`——**不读取、更不返回私钥字段**（任务书"证书 Tool 只能返回元数据"）。
- **命中详情脱敏**：`security_event.get` 的 `matches.data`（CRS 命中数据）一律经 `audits.MaskSensitiveJSON` 脱敏后返回，敏感键值替换为 `********`，非法 JSON 返回固定占位、绝不原样放行。

## 6. 草稿绝不自动发布/生效

五个草稿 Tool 的共同纪律（draft_tools.go 文件头注释即约定）：

1. **初始状态不生效**：例外/CC策略/自定义规则落库 `status='DISABLED'`；黑名单落库 `status='DRAFT'`（`validity_type='TEMPORARY'`）；报告总结只登记 `ai_recommendations`，与固定模板报告分开保存。
2. **明确标记 AI 生成**：业务对象名称统一加 `[AI草稿] ` 前缀；自定义规则 tags 含 `ai-draft`；`ai_recommendations.created_by_ai=TRUE`。
3. **来源与证据可追溯**：每个草稿同步写 `ai_recommendations`（`RecordRecommendation`）：记录 `task_id`（来源任务）、`recommendation_type`（EXCEPTION/BLACKLIST/CC_POLICY/CUSTOM_RULE/REPORT_SUMMARY）、`evidence_references`（证据引用）、`draft_reference`（如 `exception:{uuid}`）、草稿风险标注（例外/CC 为 MEDIUM，黑名单/自定义规则为 HIGH，报告总结为 LOW）。
4. **发布只能走既有流程**：Tool 返回值固定带指引文案（如"请在例外策略页面人工审核后启用"）；`draft_store.go` 只提供列表/详情/逻辑废弃（`Discard`：DRAFT/PENDING_REVIEW → REJECTED，记录审核人，**不删除记录**），不存在任何"接受即发布"路径——草稿的启用/生效由对应业务模块（例外策略、IP黑白名单、CC防护、自定义规则页面）的既有人工校验发布流程完成，那里的权限校验、参数校验、操作审计照常生效。

```text
AI 提议 → draft.*.create → 业务表（DRAFT/DISABLED）+ ai_recommendations（DRAFT）
                                   │
                                   ▼
                管理员在对应业务模块人工审核 → 启用/发布（既有流程、既有权限、既有审计）
                                   │
                或 AI草稿管理界面 Discard → REJECTED（逻辑废弃，留痕）
```

## 7. 审计留痕与脱敏

每次通过启停校验的 `Execute` 调用产生一条 `AuditRecord{TaskID, AgentRunID, ToolCode, ToolVersion, RiskLevel, InputSummary, Status, DurationMs, ErrorCode}`，经 `Auditor` 接口由 `aiaudit.Service.RecordToolCall` 写入 `ai_audit_records`（`action='tool_call'`）。审计表为**哈希链**：每条记录含 `previous_hash`/`record_hash`（SHA-256，advisory lock 串行化写入），`VerifyChain` 可校验完整性。

- **四种终态全留痕**：`SUCCESS / FAILED / TIMEOUT / DENIED`——被拒绝与失败的调用同样是审计对象。
- **入参只留摘要**：`summarizeInput` 将入参 JSON 截断至 400 字符后入库，不保存完整载荷。
- **摘要再脱敏**：`aiaudit.mask` 对含敏感词（`api_key/apikey/password/secret/private_key/BEGIN/token`）的摘要先执行长令牌遮蔽（≥24 字符的字段保留前 6 位 + `***`），再按 rune 截断（request_summary ≤500、result_summary ≤1000），避免截断产生非法 UTF-8；密钥、密码、私钥不进入审计正文。
- **不落思维链**：审计只记 Tool 调用与摘要，不保存模型私有思维链。

## 8. Tool 启停强制

- **状态存库**：`ai_tools` 表（迁移 `000013_stage7.up.sql`）`status ENABLED/DISABLED`；启动时 `SyncRegistry` 把代码 registry 中的 31 个 Tool upsert 入库（`ON CONFLICT (code)` 仅更新元数据，**保留既有启停状态**）。
- **执行路径强制**：`app.go` 装配 `aiRegistry.SetEnabledChecker(aihandlers.ToolEnabledChecker(db))`；checker **每次执行实时查库**，`status != 'ENABLED'` 即拒绝（`ErrToolDisabled`），停用即时生效、无需重启；未入库的 Tool 默认启用（新注册 Tool 的过渡态）。
- **管理接口**：`GET /api/v1/ai/tools`（权限 `ai.tools.read`）、`PATCH /api/v1/ai/tools/{id}`（权限 `ai.tools.manage`），可配置启停、超时（1-300s）、最大返回数（1-1000；后两项运行生效现状见 5.2）。列表为 DB 左联代码 registry，`in_registry` 标识代码中仍存在的 Tool。
- **Agent 侧同理**：`ai_agents.status` 经 `AgentEnabledChecker` 在调度时检查；内置总调度 `dispatcher` 不可停用（PATCH 显式拒绝）。

## 9. 危险操作不入 Tool

任务书明确禁止提供的 Tool，代码中**不存在**对应实现：

```text
shell.execute            database.raw_query     database.write
docker.execute           gateway.publish_direct  policy.publish_direct
firewall.block_direct    system.upgrade_direct   backup.restore_direct
audit.delete
```

设计决策：这类能力不是"加了权限校验的 Tool"，而是**根本不在 registry 注册**。AI 无法直接发布网关配置、无法直接封禁、无法执行 Shell/任意 SQL、无法恢复备份、无法删除审计；它所能触达的最高影响面就是第 6 节的草稿。即使提示词被注入诱导调用上述能力，`Execute` 也只会在注册表中查无此 Tool（`ErrToolNotFound`）。

## 10. 关联文档

- [AI Tool 设计](AI_TOOL_DESIGN.md)（Tool 契约、执行管线与全量清单，本文档为其安全专项）
- [AI 审计设计](AI_AUDIT_DESIGN.md)（ai_audit_records 哈希链与查询接口）
- [阶段7任务书](tasks/STAGE_7_AI_SECURITY_OPERATIONS.md)（十、Tool工具体系；29.9 ai_tools 表结构）
- [AI 模型网关设计](AI_MODEL_GATEWAY.md)
- [AI 记忆设计](AI_MEMORY_DESIGN.md)
- [架构设计](ARCHITECTURE.md)
- [数据库设计](DATABASE_DESIGN.md)
- [安全设计](SECURITY_DESIGN.md)
- [备份恢复设计](BACKUP_RESTORE_DESIGN.md)
- [监控告警设计](MONITORING_ALERTING_DESIGN.md)
