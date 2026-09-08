# AUTHZ-01：对象授权关系确认与 BOLA/BFLA 网关 OBSERVE 决策开发任务书

日期：2026-09-08。状态：待实施。优先级：产品 P1（独立任务线，不属于 wdsp-p0/p1 竞品任务包）。

前置：设计基线 [../API_BOLA_BFLA_MULTI_TENANT_AUTHORIZATION_DESIGN.md](../API_BOLA_BFLA_MULTI_TENANT_AUTHORIZATION_DESIGN.md)（下称"设计文档"，章节引用如"设计 §15"）；[P0-03 JWT 信任链](wdsp-p0/P0-03_JWT_TRUST_CHAIN.md)已落地，提供 `verified_principal_id` / `verified_tenant_id`；P0-15/16/17 的 `server/internal/apiauthz` 角色基线、对象权属、字段权限已存在。

编写标记沿用 wdsp-p1 总纲：**现有** / **新增约定** / **建议默认值** / **待复现**。

## 1. 问题与目标

现状三个断点（设计 §1、§4）：

1. 对象权属只在 server 侧离线评估（`apiauthz` evaluate 五档结论），从未编译下发，网关热路径无法实时判断 BOLA；
2. 网关 BFLA 观察（`authzcheck.go`）的角色取自**未验签** JWT claims，只能作为观察信号，设计安全不变量 1 禁止其进入保护级决策；
3. 现有 `api_object_ownership` 是"谁访问过哪个对象"的观测证据，缺少来源、置信度、确认状态，直接当下发依据会把"访问过"误当"拥有"（安全不变量 3）。

目标（全部 OBSERVE，本任务**不实现任何阻断**）：

- 把对象权属升级为带 `来源 / 置信度 / 确认状态 / 有效期` 的授权关系模型，历史访问数据迁移为候选，不自动成为 confirmed owner；
- 提供候选确认 / 拒绝工作流（人工审批 + 操作审计），确认后的关系与对象模型一起经现有配置发布链编译为签名快照下发网关；
- 网关在 API 动态防护管线内独立执行实时 BOLA / BFLA 决策：只有 JWT 状态为 `VERIFIED` 且 `verified_principal_id` 非空的身份才参与可信授权判定；身份未验证、可信主体缺失、关系缺失、策略语义不完整或证据不足统一输出 `UNKNOWN`，只记录，不得包装成高置信越权（安全不变量 6）；
- 每条决策带 `decision_id`、原因码、策略版本，事件脱敏，可在管理面查询。

本任务完成后，WDSP 对水平越权（BOLA）和垂直越权（BFLA）具备**基于可信身份的实时检测与证据链**；阻断能力（OBSERVE→PROTECT 发布、灰度、回退）属于后续任务书，本任务不得宣称 PROTECT 已完成。

## 2. 明确不做（等待设计 §41 待决策事项或后续任务书）

- Session / API Key / 受信上游 Header 验证器（设计 §9，待决策 1）；
- 租户层级、多租户主体的活动租户选择（设计 §10.3，待决策 2）；本任务仅做单层租户：verified tenant 与对象归属租户的一致性观察；
- owner 权威源同步连接器（待决策 3）；本任务仅支持创建绑定候选与人工导入/确认；
- 共享、委托、客服代查关系类型（待决策 5）；数据模型预留枚举，不开放配置入口；
- 列表接口过滤、批量对象检查（设计 §15.3、§18，待决策 6）；
- 响应字段 MASK/REMOVE/DENY（设计 §17.3，待决策 7）；
- 失败开放/关闭分级策略（待决策 8）：本任务一律 OBSERVE，不存在失败关闭；
- GraphQL / gRPC 对象提取、策略模拟工作台、SHADOW/CANARY 发布。

## 3. 现有代码与集成位置

| 现有位置 | 现状/使用方式 |
|---|---|
| `server/internal/apiauthz/` | 角色基线、`api_object_ownership` sweep（access_count/last_seen）、对象模型、字段权限、evaluate 五档 BOLA 结论；doc.go 明确权属是观测证据而非定罪 |
| `server/internal/apiauthz/evaluate.go` | 离线五档评估规则；"不仅凭 ID 变化定罪"纪律本任务继续沿用 |
| `server/internal/guardconfig/authz_rules.go` | 角色基线 + 字段权限向网关的发布通道（现有契约不得破坏） |
| `server/internal/gatewayconfig/` | 编译、不可变版本、发布、节点回执、回退的现有机制，复用，不新建发布通道 |
| `server/internal/jwttrust/` | JWT 信任策略、`VerificationResult`、主体指纹；事件已带 `verified_principal_id` / `verified_tenant_id` |
| `gateway/dynamic_security/jwtverify/` | 网关本地验签；当前在身份 HMAC 密钥缺失时可能返回 `StatusVerified` 但 `VerifiedPrincipalID` 为空，因此授权可信身份必须同时检查状态与非空主体 ID |
| `gateway/dynamic_security/detectors/authzcheck.go` | BFLA 角色基线观察 + 字段权限观察；现有未验签角色提取仅保留为旧观察信号，不得进入本任务的可信授权决策 |
| `gateway/dynamic_security/detectors/resource.go` | 对象 ID 提取（path/query）、连续数字 ID 枚举检测；仅辅助信号 |
| `gateway/dynamic_security/events/event.go` | 事件已含 verified 身份字段；本任务扩展授权决策字段 |
| `gateway/modules/jiuzhang_guard/module.go`、`apiprotect.go` | 请求顺序与 API 动态管线挂接点；新增决策不得改变既有防护先后关系 |
| `server/migrations/000043_*`、`000044_*` | 现有基线表迁移；新表编号先核对最新迁移号，不得猜测 |
| `server/openapi/fragments/07-api-security.yaml`、`CONTRACT.md` | OpenAPI 片段与契约约束 |

**新增包建议（待创建路径）**：`server/internal/apiauthz` 内新增 `relations.go`、`candidates.go`（不新建包，避免拆分现有装配）；`gateway/dynamic_security/detectors/` 内新增 `authzdecide.go`。共用枚举按现有模块边界放置，网关不得跨 Go 模块导入 server internal 包。

## 4. 数据模型契约（新增约定）

### 4.1 对象关系与候选

新建 `api_object_relations` 与 `api_object_relation_candidates`（设计 §26.2），关键字段契约：

| 字段 | 契约 |
|---|---|
| `application_id`、`object_type`、`object_ref` | `object_ref` 为带域分隔的 HMAC 引用（域前缀 `objref:`），与身份指纹密钥/域不同；不落明文对象 ID（设计 §12.3、§33） |
| `principal_id` | confirmed 关系中非空且仅接受 `verified_principal_id` 形态的主体；未验证身份不得写入关系 |
| `relation` | 首期开放 `OWNER`；`SHARED_WITH` / `DELEGATED_TO` / `SUPPORT_ACCESS` 枚举预留但不可配置 |
| `tenant_id` | 可空；来源为已验证 tenant claim 或人工指定，不得来自客户端请求参数 |
| `source` | `MANUAL` / `IMPORT` / `CREATE_BINDING`；`OBSERVED_ACCESS` 只允许出现在候选表 |
| `status` | `CONFIRMED` / `REVOKED` / `EXPIRED`；confirmed 关系物理或逻辑隔离于候选（设计 §26.3） |
| `valid_from` / `valid_until` | 有效期随关系下发；网关按本地可信时钟逐请求校验 `valid_from <= now < valid_until`（空 `valid_until` 表示无截止时间），后端任务置 `EXPIRED` 仅用于状态维护与触发重发布，不能替代热路径校验 |
| `evidence_ref`、`confirmed_by`、`confirmed_at`、`reason` | 证据引用与审批留痕；`reason` 非空进操作审计 |

候选表增加可空 `principal_id`、独立的 `legacy_identity_fingerprint`、`source_count`、`first_seen`、`last_seen`、`confidence_inputs`（来源多样性聚合，设计 §13.3）。只有由 VERIFIED 流量生成且 `principal_id` 非空的候选可进入确认流程；历史身份指纹与 `verified_principal_id` 属于不同信任域，禁止互相复制或转换。所有候选均不参与网关决策。

### 4.2 历史数据迁移

- `api_object_ownership` 现有行**整体迁移为候选**（`source=OBSERVED_ACCESS`、未确认）：对象 ID 由应用迁移任务使用对象引用专用密钥计算 `object_ref`，旧 `identity_fingerprint` 只写入 `legacy_identity_fingerprint`，`principal_id=NULL`，并标记为不可直接确认；不得直接转为 confirmed（设计 §36.2、安全不变量 3）；
- 对象引用密钥不可用时迁移任务必须失败并保留待迁移状态，不得落明文或用身份指纹密钥代替；迁移幂等、可重跑；保留原表只读一段时间，不硬删除历史审计能力；
- 切换到新候选采集器后停止旧 `api_object_ownership` sweep 写入，避免同一访问在新旧信任域重复累计；历史候选如需转正，必须由管理员通过手工关系/导入流程绑定一个经过校验的 `verified_principal_id`，原候选只作为证据引用；
- `api_role_baselines` 现有 confirmed 行打标 `identity_assurance=OBSERVED`：它们基于未验签角色学习，本任务中网关对 VERIFIED 身份执行 BFLA 判定时不直接复用（见 §7.3）。

### 4.3 对象模型下发范围

`api_object_models`（现有）补充发布标记与授权语义：只有 `publishable=TRUE`、端点归一化模板唯一、`required_relation=OWNER` 且 `owner_exclusive=TRUE` 的模型才能产生 `AUTHZ-BOLA-001`。缺少或冲突的授权语义只能输出 `UNKNOWN(policy)` / `AUTHZ-POLICY-001`，不能由“他人是 OWNER”推导当前主体必然越权。复合键、BODY 位置提取本期不下发（设计 §12.2 裁剪为 path + query）；共享、委托等模型待后续任务开放。

## 5. 管理接口契约（新增约定）

统一挂在 `server/internal/apiauthz` 现有路由前缀下，OpenAPI 片段不重复 `/api/v1` 前缀：

| 方法与路径 | 权限 | 用途 |
|---|---|---|
| GET `/authz/relations/candidates` | `api_authorization.read` | 候选关系分页列表（来源、次数、时间跨度、脱敏引用） |
| POST `/authz/relations/candidates/{id}/confirm` | `api_authorization.relation_manage` | 仅确认 `principal_id` 非空的候选为 CONFIRMED 关系；body 带 `relation`、`reason`，409 防并发；历史不可确认候选返回 409 并引导手工绑定/导入 |
| POST `/authz/relations/candidates/{id}/reject` | `api_authorization.relation_manage` | 拒绝并记录原因，候选不再浮现 |
| GET/POST `/authz/relations` | read / `relation_manage` | 查询/手工维护 confirmed 关系（含 IMPORT 录入） |
| GET `/authz/decisions` | `api_authorization.read` | 授权决策事件查询（decision_id、原因码、策略版本、脱敏证据） |
| GET `/authz/coverage` | `api_authorization.read` | 覆盖率：VERIFIED 身份占比、对象模型覆盖、confirmed 关系占比、UNKNOWN 率 |

权限点新增 `api_authorization.relation_manage` 与 `api_authorization.evidence_read`（查看脱敏证据详情），种子迁移登记；确认/拒绝与手工维护进操作审计（字段差异摘要，不含明文对象 ID 与主体）。不存在 ID 404、字段错误 400/422 按仓库统一规范，列表执行应用范围校验。

防投毒纪律（设计 §13.3，必须在实现中强制执行）：

- 单次访问永不生成 confirmed；候选确认必须人工或走 IMPORT 审批；
- 高权限运维、测试机器人、服务账号身份类型不参与候选生成（复用 identity_type 判定）；
- 一个对象在短窗口内出现超过阈值的不同主体候选时，冻结该对象自动浮现并标记异常；
- 同一来源的重复弱信号不得无限抬高候选排序。

## 6. 编译与下发契约（新增约定）

复用 `gatewayconfig` 现有发布机制，新增授权决策策略分片（与 `authz_rules.go` 平级，不混入现有分片破坏契约）：

- 编译内容：对象模型（path/query 提取规则 + 端点模板 + OWNER-only 授权语义）、confirmed 关系索引（含 `valid_from` / `valid_until`，按 application + object_type 分桶）、`identity_assurance=VERIFIED` 的 confirmed 角色基线、发布版本与摘要；快照带最大有效期（设计 §27.2）；
- 建议默认值：单分片 confirmed 关系 ≤ 200,000 条，超过按 object_type 拆分并在编译期告警；单端点模型唯一键冲突在编译期报错拒绝发布；
- 原子替换：网关先整体校验再切换，禁止加载半份；发布失败保留上一有效版本并报告节点水位；
- 关系变更（确认/撤销/过期）触发增量重编译与再发布，走同一版本链，不得绕过审核直推；
- 快照不含明文对象 ID、明文主体；HMAC 密钥与 JWT 信任链指纹密钥分离，轮换走双密钥窗口。

## 7. 网关决策契约（新增约定）

### 7.1 判定顺序（对应设计 §15.1，裁剪版）

```text
1. 独立定位两类基线：BOLA 对象模型、BFLA 端点角色基线；两者均未命中才无行为，BFLA 不以命中对象模型为前提
2. 构造可信身份上下文：仅 `jwtverify StatusVerified` 且 `VerifiedPrincipalID` 非空才是 VERIFIED；状态非 VERIFIED 或主体 ID 为空时，各个已命中分支分别输出 UNKNOWN(identity)
3. BFLA 分支：直接按 §7.3 的可信角色与 VERIFIED confirmed 角色基线比对；管理员端点没有对象 ID 时仍必须执行
4. BOLA 分支：仅在命中对象模型时提取对象标识（path 占位段 + query，复用 resource.go 提取纪律，raw 不出内存）；提取缺失/歧义 → UNKNOWN(object)
5. BOLA 策略前提：模型必须显式声明 `required_relation=OWNER` 且 `owner_exclusive=TRUE`；缺失/冲突 → UNKNOWN(policy) / AUTHZ-POLICY-001
6. BOLA 关系有效性：网关先按本地当前时间过滤非 CONFIRMED、尚未生效或已过期关系，再做主体与租户匹配；后端状态尚未改为 EXPIRED 不得使过期关系继续生效
7. 租户一致性：双方 tenant 均非空且不同 → AUTHZ-TENANT-001；仅一方为空 → UNKNOWN(tenant)；双方为空表示该模型不启用租户维度，不得使用请求参数补齐
8. BOLA 关系结论：自身命中有效 OWNER → ALLOW；存在他人有效 OWNER、自身无有效 OWNER 且 OWNER-only 前提成立 → AUTHZ-BOLA-001；没有足够关系数据 → UNKNOWN(relation)
9. 输出一个请求级决策组（全部 OBSERVE，请求一律放行）
```

### 7.2 决策输出

复用/扩展现有事件结构：新增请求级 `authz_decision` 字段组，包含共享的 `decision_id`、`policy_version` 与 `checks[]`。每个 BOLA/BFLA 检查项独立携带 `type`、`decision`（ALLOW/OBSERVE_VIOLATION/UNKNOWN）、`reason_code`（取设计 §25 子集：`AUTHZ-BOLA-001/002`、`AUTHZ-BFLA-001`、`AUTHZ-TENANT-001`、`AUTHZ-CONTEXT-001`、`AUTHZ-POLICY-001/002`）、`confidence`、`relation_state`；请求级结论按 `OBSERVE_VIOLATION > UNKNOWN > ALLOW` 聚合，不能让一个分支覆盖另一个分支的证据。证据只含结构信息与 HMAC 引用，不落原始对象 ID、Token、claims 值。`UNKNOWN` 在页面和统计中与违规明确分开（设计 §14.3）。

### 7.3 BFLA 可信角色来源

- JWT 信任策略的 issuer 配置新增显式 `role_claims` 映射（声明名列表，不自动猜测）；管理端校验声明名、数量与长度，发布时进入 JWT 信任配置；未配置映射时 BFLA 输出 UNKNOWN(role)，不得回退读取未验签 claims；
- `jwtverify.VerificationResult` 新增 `VerifiedRoles`：只在签名、issuer/audience/时间等校验全部通过后从 `role_claims` 读取，仅接受字符串或字符串数组，拒绝把数字、对象等类型隐式转成字符串，再经去重、限量、限长后写入；随后通过 `jiuzhang_guard` 请求上下文传给授权决策器。非 VERIFIED 或 `VerifiedPrincipalID` 为空时必须清空可信角色；日志和事件不得记录原始 claims 值；
- 现有基于未验签 claims 的 BFLA 检测器只保留为独立的 legacy 观察信号，标记 `role_source=OBSERVED`，不得写入本任务的 `authz_decision.checks[]`，也不得生成/确认 `identity_assurance=VERIFIED` 基线；新决策路径固定标记 `role_source=VERIFIED`；
- VERIFIED 流量的角色学习只生成 `identity_assurance=VERIFIED`、`source=OBSERVED`、`confirmed=false` 的候选行；沿用现有 `/api-security/authz/role-baselines` 列表和 `/{id}/confirm` 接口完成筛选与确认，无额外“重新生成”占位接口。`identity_assurance=OBSERVED` 的旧基线不与 VERIFIED 角色比对出违规，只显示“基线待重校准”（设计 §16.3、§36.3）。

### 7.4 性能与故障

- 热路径零网络 IO、零 PostgreSQL；本地索引查找 + 对象提取的 P95 增量目标 ≤ 2 ms（设计 §32.1），纳入 P0-02 配对基准；
- 单请求对象引用数量、关系索引内存、决策事件采样均设上限；事件异步批量写，存储不可用本地限量缓冲并告警，不影响请求放行；
- 快照过期：继续加载上一有效版本中的模型与索引并产生 `AUTHZ-POLICY-002` 观察与告警，但每条关系仍必须按自身 `valid_from` / `valid_until` 实时过滤；快照过期不得复活已过期关系，也不得因清空索引制造全量 UNKNOWN 事件洪峰。

## 8. UI / UX 与事件

- 应用下新增"对象授权"面板：候选列表（待确认数）、确认/拒绝操作、confirmed 关系视图、覆盖率卡片（VERIFIED 身份占比、模型覆盖、UNKNOWN 率）、决策事件时间线（身份验证 → 租户 → BOLA → BFLA → 结论）；
- 候选与 confirmed 在视觉上明确区分（虚线/徽标），禁止混淆展示（设计 §31.3）；对象引用默认脱敏，详情需 `evidence_read` 权限；
- 状态完整：加载、空数据、部分节点未生效、发布失败、无权限、保存/发布失败均有可恢复入口；不能只 Toast；
- 事件详情扩展授权决策字段，历史无字段事件显示"当时未记录"；UNKNOWN 不得渲染成"越权"。

## 9. 实施步骤

1. 核对 `apiauthz`、`guardconfig`、`jwtverify` 当前代码与最新迁移号；冻结表结构、枚举、事件字段与 OpenAPI 增量；
2. 先写迁移与防投毒单测：历史行→候选、单次访问不确认、冻结阈值、来源多样性；
3. 实现候选/关系存储、确认工作流、权限与审计，接口测试覆盖越权与并发；
4. 实现编译分片、快照校验、原子下发与节点水位，发布失败/回退测试；
5. 实现网关 `authzdecide.go` 决策与事件扩展，先单测判定矩阵，再接管线做真实网关集成测试（含 JWT OFF / 未配置应用 / 旧版本节点）；
6. 实现管理页面与事件详情，补 E2E（候选→确认→发布→攻击流量→决策可见）；
7. 跑 P0-02 配对基准（决策开/关），更新能力清单与 DEVELOPMENT_STATUS，WORKLOG 记录证据。

## 10. 必须通过的验收用例

| ID | 条件 | 预期 |
|---|---|---|
| AZ-01 | 历史 ownership 数据迁移 | 全部成为 `principal_id=NULL`、保留独立 legacy 指纹且不可直接确认的候选；对象引用用专用密钥计算；无一行自动 confirmed；迁移可重跑幂等 |
| AZ-02 | 单次/多次访问产生新的 ownership 证据 | 只生成候选；候选本身不改变网关结论，缺少既有 confirmed 关系时仍为 UNKNOWN(relation) |
| AZ-03 | 候选确认→编译→发布 | 仅 VERIFIED 流量产生且 `principal_id` 非空的候选可确认并进入快照；legacy 候选确认返回 409；未确认候选从不出现在快照 |
| AZ-04 | VERIFIED 用户访问本人 confirmed 对象 | 决策 ALLOW 证据，请求放行，事件含 decision_id |
| AZ-05 | VERIFIED 用户 A 访问 confirmed 属于 B 的对象 | 仅模型显式 `required_relation=OWNER`、`owner_exclusive=TRUE` 时产生 `AUTHZ-BOLA-001`；未声明或允许共享时为 UNKNOWN(policy)，请求均放行 |
| AZ-06 | 未验签/无凭据，或 `StatusVerified` 但 `VerifiedPrincipalID` 为空 | BOLA/BFLA 已命中分支只出 UNKNOWN(identity)；可信角色为空，不得产生授权违规结论 |
| AZ-07 | 对象无关系、模型授权语义缺失或对象提取歧义 | 分别输出 UNKNOWN(relation/policy/object)，页面与统计和违规分开展示 |
| AZ-08 | tenant 完整性矩阵 | 双方非空且不同才产生 `AUTHZ-TENANT-001`；仅一方为空为 UNKNOWN(tenant)；双方为空不启用租户维度；请求参数不得作为身份租户 |
| AZ-09 | VERIFIED 普通角色访问无对象 ID 的管理员端点基线 | 仍产生 `AUTHZ-BFLA-001`、`role_source=VERIFIED`；BFLA 不依赖对象模型；未验签同请求只走独立 legacy 观察信号 |
| AZ-10 | 角色信任链与旧 OBSERVED 基线 | 显式 `role_claims` 经验签结果和请求上下文传递；未配置映射为 UNKNOWN(role)；旧基线不出违规，VERIFIED 候选经现有确认接口确认后才参与判定 |
| AZ-11 | 伪造主体/对象投毒：多账号轮番访问同一对象 | 候选冻结并标记；confirmed 关系不被污染 |
| AZ-12 | 关系尚未生效、撤销或过期 | 即使后端状态任务/重发布尚未完成，网关也按本地时间过滤 `valid_from/valid_until`，不再把该关系作为有效命中；旧版本节点行为可解释 |
| AZ-13 | 发布失败/部分节点失败/回退 | 保留上一有效版本；节点水位可见；不静默丢失已生效配置 |
| AZ-14 | 快照过期、事件存储中断 | 按 §7.4 行为；旧快照不复活已过期关系，请求不受影响；告警与限量缓冲生效 |
| AZ-15 | 事件与日志审计 | 无明文对象 ID、Token、claims 值；reason 与字段差异进操作审计 |
| AZ-16 | 权限矩阵 | 无 `relation_manage` 不能确认；无 `evidence_read` 看不到详情；跨应用访问 404/403 |
| AZ-17 | 高并发 + 大索引基准 | P95 增量 ≤ 2 ms 目标内；无数据竞争（-race）、无无界内存/标签 |
| AZ-18 | 全流程 E2E | 创建对象→候选→确认→发布→他人访问→决策事件时间线完整可复核 |

AZ-01～14 需单元 + 真实网关组合验证；AZ-15/16 接口测试；AZ-18 E2E；AZ-17 在 P0-02 基准环境完成，不虚构性能数字。

## 11. 迁移、回退与完成定义

迁移以新表 + 可空字段为主；新候选采集器启用后停止旧 `api_object_ownership` sweep 写入，旧 evaluate 接口与原表进入只读兼容期，确认无消费者后再按设计 §36 废弃，不直接删历史数据。legacy 候选不得原地补写或推导 `principal_id`，转正必须通过手工关系/导入流程建立新的可信主体绑定并引用原证据。回退走真实发布链并保留审计；含本任务快照的系统回退到旧网关二进制前，须显式处理未知分片并提示行为变化。

完成条件：候选/关系模型、确认工作流、编译下发、网关 OBSERVE 决策、事件、UI、权限、审计、迁移、回退全部接线并通过 §10 用例。**本任务任何交付均为 OBSERVE**；宣称"越权防护已阻断"属于超出范围，PROTECT 以后续任务书为准。
