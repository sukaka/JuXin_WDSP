# NG-AZ-03 显式阻断资格 / VERIFIED_VIOLATION 冻结设计（S3 阶段 2 设计稿，2026-10-05）

> 依据：`docs/WDSP_API_WAF_NEXTGEN_RD_PLAN.md` §8.3（决策语义段：ALLOW/VERIFIED_VIOLATION/UNKNOWN/DEPENDENCY_UNAVAILABLE 四值；「只有主体可信、模型适用、关系有效且无冲突、范围一致、证据满足要求，才能认定 VERIFIED_VIOLATION」；排他所有权显式声明）/§8.4（切 PROTECT 四要素强制前置、默认 OBSERVE、集成测试四断言）/§15.2（NG-AZ-03 完成证据：**UNKNOWN 不误断、可信违规不达源站**）/§16.3（NG-T-A01~A08）。
> 本设计同时是 NG-AZ-02 D10 预留评审的落地：VERIFIED_VIOLATION 与 OBSERVE_VIOLATION 兼容映射的终态契约。
> 目标：把授权决策从「永远 OBSERVE」推进到「满足显式资格时可实断」，同时把「什么不算违规」钉死在 UNKNOWN 词表——**实断必须可证、UNKNOWN 绝不误断**。
> 前置事实（inventory 复核 2026-10-05）：
> - 决策矩阵现状（`gateway/dynamic_security/detectors/authzdecide.go`）：`EvaluateAuthorization` 产出 ALLOW / OBSERVE_VIOLATION / UNKNOWN 三值决策组，**永不改变请求动作**（头注释原文「violation and unknown are OBSERVE signals」）；已有资格输入：JWT VERIFIED 可信主体、模型 publishable/owner_exclusive/required_relation/OnLeaseExpired、关系 CONFIRMED、冲突集（D7 UNKNOWN）、lease/skew 时效（NG-AZ-02 修正后负向漂移）。
> - 事件/动作现状：`events.AuthorizationDecision`（events/authz.go）为字符串型枚举（ALLOW/OBSERVE_VIOLATION/UNKNOWN，无 DB 约束）；pipeline 动作枚举（dsctx.FinalAction）为 ALLOW/OBSERVE/BLOCK/TEMP_BLOCK/RATE_LIMIT/MASK_RESP；`api_runtime_events.final_action` 为自由文本列（INSERT 无 CHECK）。
> - 阻断响应先例：`writeAPIAdmissionDeniedResponse`（403 + `{"code":"API_ADMISSION_DENIED",...}` 统一 JSON）与 `writeGraphQLDeniedResponse`（403 + GraphQL 协议错误 JSON）——均在 apiprotect BLOCK 分支直接写出（committed=true，不经 Caddy 错误链阻断页）。
> - 资格字段管理路径已接通（集成批）：`PATCH /api/v1/api-security/object-models/{id}`（publishable/required_relation(OWNER)/owner_exclusive/on_lease_expired，apisecurity/object_models_update.go）；快照编译列于 `guardconfig/authz_decision.go listPublishableAuthzModelsQuery`。
> - 过渡决策（NG-AZ-02 D10）：枚举不更名、排除判定落 UNKNOWN——本设计即其终态升级。

## 1. 冻结契约

### 1.1 决策值与动作映射（VERIFIED_VIOLATION 的引入形态）

- **授权决策词表**（`events.AuthorizationDecision`，字符串型，无 DB 枚举约束）新增第四值 **`VERIFIED_VIOLATION`**。含义：「违规事实经显式资格判定成立」——它是**判定结论**，不是动作本身。
- **动作映射**：VERIFIED_VIOLATION 只在「端点 enforcement=PROTECT 且决策引擎 PROTECT 语义下」映射为 pipeline `BLOCK`；其余形态（OBSERVE enforcement / 决策引擎 OBSERVE）降级为 OBSERVE_VIOLATION 同语义记录（拟动作保留，不实断）。**UNKNOWN 在任何形态下都不映射为 BLOCK（红线）**。
- **历史兼容**：pipeline 动作枚举、`api_runtime_events.final_action` 词表、`api_runtime_findings`/报表的 final_action 聚合键**全部不变**（VERIFIED_VIOLATION 不进 final_action 列；final_action 恒为既有词表）。新值只出现在：authz 决策组 JSON（`authz.decision_group` 扩展 → `final_decision`/details evidence）、reason_code 与证据字段、专用查询 API 的 `decision` 列。查询侧归并（可选视图）：`verified_violation_count = count(reason_code='AUTHZ-BOLA-001' AND enforced=true)`——以「reason + enforced 标记」派生，不改写历史行。

### 1.2 阻断资格判定式（block eligibility 真值表）

VERIFIED_VIOLATION 要求**同时**满足（逐因子映射到 authzdecide 现有信号，任一不满足落 UNKNOWN 或 OBSERVE_VIOLATION（按现行 reason code），绝不阻断）：

| 因子（§8.3 原文） | 现有信号 | 不满足时的落点 |
|---|---|---|
| 主体可信 | `jwt.Status == VERIFIED` 且 `VerifiedPrincipalID != ""`（trustedIdentity） | AUTHZ-IDENTITY-001 UNKNOWN（含历史推断/未验证主体，NG-T-A02） |
| 模型适用 | 端点恰一模型匹配、publishable=true、required_relation='OWNER'、unique_endpoint_template、model 未 stale/未过期 | AUTHZ-POLICY-001/002 UNKNOWN |
| 关系有效 | 关系行 status=CONFIRMED 且 valid_from/valid_until 内 | AUTHZ-RELATION-001 UNKNOWN |
| 无冲突 | 对象不在 OPEN 冲突集（D7 索引） | AUTHZ-CONFLICT-001 UNKNOWN |
| 范围一致 | tenant 一致（identityTenant==objectTenant 或双空） | AUTHZ-TENANT-002 UNKNOWN / TENANT-001 OBSERVE_VIOLATION（mismatch 不阻断——租户形态证据不足，见 D2 注） |
| 证据满足（授权事实新鲜） | lease 未过期（strict/degraded 语义不变）、无 CLOCK_SKEW（负向漂移）、快照水位未回退 | AUTHZ-LEASE-001/002、AUTHZ-CLOCK-001 UNKNOWN |
| **违规事实本体** | OTHER_OWNER（请求主体 ≠ 任一有效 OWNER，且存在有效 OWNER） | 只有这一项成立才进入资格判定；NONE/INSUFFICIENT 为 UNKNOWN |

**排他所有权**（§8.3「有效 OWNER 是别人不代表所有共享业务都越权」）：仅当模型 `owner_exclusive=true` 时 OTHER_OWNER 才构成违规候选；owner_exclusive=false 的模型永不进资格判定（显式声明，不默认）。

### 1.3 PROTECT 开关契约（§8.4 四要素强制前置）

- 开关：`api_object_models.enforcement`（值域 `OBSERVE`（缺省）| `PROTECT`，per-endpoint——与 publishable/owner_exclusive/on_lease_expired 同列同 PATCH 通道）。BFLA（角色基线）侧：`api_role_baselines.enforcement`（同值域，per-角色基线行；无行级配置时端点继承 object model 值）。
- **切换前置校验（缺一直接 400 拒绝切换）**：enforcement→PROTECT 时服务端强制要求同请求提供：① endpoint_id（行本身，隐式满足）；② `business_owner`（业务负责人标识，非空字符串 ≤128，写入行 `enforcement_owner` 列）；③ `evidence_source`（证据来源声明，词表 `AUTHORITY_SYNC|MANUAL_CONFIRMED`）；④ `on_unknown`（UNKNOWN 处理方式声明，词表 `ALLOW_UNKNOWN`（默认，UNKNOWN 放行并记录）——首批仅此一值，明确写出 UNKNOWN 永不阻断的预期管理）。四要素落库随快照下发，网关可见可审计。
- 默认 OBSERVE：新模型/未配置恒 OBSERVE（NG-T-C01）；PROTECT 切回 OBSERVE 无前置要素要求（但保留 enforcement_owner 等历史行供审计）。

### 1.4 EnforcementEvidence 结构（「为什么被实断」的可答证据）

每次 VERIFIED_VIOLATION 实断生成一条证据记录（随该请求的 api_runtime_events 行内嵌 `authz_enforcement` 对象，不新建主表）：

```json
{
  "decision": "VERIFIED_VIOLATION",
  "reason_code": "AUTHZ-BOLA-001",
  "enforced": true,
  "endpoint_key": "GET /v1/orders/{id}",
  "model_version": "…", "policy_version": "…",
  "revocation_watermark": {"manual_seq": 7, "sources": {"<src>": 3}},
  "principal_source": "JWT_VERIFIED",
  "object_ref": "objref:…",
  "eligibility": {"trusted_identity": true, "model_applicable": true, "relation_valid": true,
                  "no_conflict": true, "tenant_consistent": true, "evidence_fresh": true,
                  "other_owner": true, "owner_exclusive": true},
  "lease_seconds": 60, "applied_at_age_seconds": 12,
  "enforcement_owner": "zhang.lei@example.com",
  "evidence_source": "AUTHORITY_SYNC",
  "recorded_at": "…"
}
```

保留期沿用 api_runtime_events 既有留存策略（管理面可配置）；查询：`GET /api/v1/api-security/authz/decisions` 既有端点扩展 `decision=VERIFIED_VIOLATION` 过滤 + 行内嵌证据原样带出（只读，api_authorization.read / api_authorization.evidence_read 既有权限）。

### 1.5 能力门升级：az/3（新增，不复用 az/2 加字段）

v3 消费语义（VERIFIED_VIOLATION 判定与实断执行）是新能力，不是 az/2 的字段扩展——az/2 节点不认识 enforcement/enforcement 资格判定与阻断执行路径，若在 az/2 上放行含 PROTECT 配置的快照等于**在看不见资格的节点上实断或漏断**（两个方向都不可接受）。发布含任一 enforcement=PROTECT 端点的快照时 required_capabilities 增加 `detectors.authzdecide=az/3`；az/1/az/2 节点被能力门 fail-closed 拒绝（NG-T-C08 同形态）。az/2 兼容面：enforcement 全 OBSERVE 的快照仍按 az/2 门放行（v2 消费语义不变）。

## 2. 冻结决策点（D1~D10）

### D1 枚举引入形态：决策词表加值、动作词表不动、落库零迁移

- **结论**：`events.AuthorizationDecision`（字符串型，无 DB 约束）加 `VERIFIED_VIOLATION`；pipeline `FinalAction` 与 `api_runtime_events.final_action` 词表**不变**（实断落 final_action=BLOCK）；决策值经 authz 决策组 JSON / reason_code / `authz_enforcement` 证据对象与查询 API 携带。历史消费者（前端/报表/导出）所见枚举集合不变——**满足 §8.3「不能直接修改历史 API 枚举而不迁移消费者」**：我们没有改历史枚举的既有值语义，新增值只出现在此前为空/新增的证据字段与决策组 JSON 中（这些位置对旧消费者是未知但可解析的数据，不是非法枚举）。查询侧归并用派生视图（reason_code+enforced 标记）而非改写历史行。
- **理由**：阻断的事实表达在 final_action=BLOCK（既有），违规的「可信判定」表达在决策层证据（新字段）——两层正交，任何一层都不破坏既有消费者。

### D2 阻断资格判定式：八因子全真值表，任一不满足不落 UNKNOWN 以外的值

- **结论**：按 §1.2 真值表实现 `evaluateBOLA` 的资格段——OTHER_OWNER 成立后再过八因子，全真才落 `VERIFIED_VIOLATION`；任一不真按既有 reason code 落 UNKNOWN（绝不用「部分满足」折算阻断）。两处显式裁决：① TENANT-001（身份租户与对象租户不一致）维持 OBSERVE_VIOLATION 不实断（租户不一致是「可疑但非排他证据」——§8.3 未把租户形态列入资格原文，选保守）；② NONE（无有效关系）与 INSUFFICIENT 恒 UNKNOWN（无 OWNER 不等于越权——可能是公共对象或模型过期）。
- **理由**：「UNKNOWN 不误断」是 NG-AZ-03 完成证据红线；真值表的每一「不满足」分支都必须有对应既有 UNKNOWN reason code 承接，没有折算空间。

### D3 PROTECT 开关：per-endpoint `enforcement` 列 + §8.4 四要素强制前置

- **结论**：挂 per-endpoint（api_object_models.enforcement + enforcement_owner/evidence_source/on_unknown 三伴随列，迁移 000174）；BFLA 侧 `api_role_baselines.enforcement`（per-角色基线行）。切换 PROTECT 必须同请求提供四要素（端点/业务负责人/证据来源/UNKNOWN 处理方式），缺一 400；默认 OBSERVE；PATCH 通道与现有 object-models PATCH 合并（同一端点、同一审计）。per-app 不做全局开关（避免一键把未知端点全部推入实断——端点级显式是 §8.4「必须选定端点」的字面要求）。
- **理由**：四要素把「谁决定、凭什么证据、UNKNOWN 怎么办」变成切换时的强制声明，切换动作本身即审计证据；列级开关与既有资格字段同生命周期（PATCH/版本戳/快照编译复用既有链）。

### D4 阻断执行：apiprotect BLOCK 分支加 authz 子分支，复用统一 JSON 形态

- **结论**：authzdecide 产出 VERIFIED_VIOLATION 且端点 enforcement=PROTECT 且决策引擎 PROTECT 语义时，finding 以 `category=BLOCK`、`rule_id=AUTHZ-BOLA-001`（BFLA 侧 `AUTHZ-BFLA-001`）、`evidence.enforced=true` 写 ctx——决策引擎按既有 BLOCK 资格定案（category=BLOCK 即资格，与其他防护域一致）；apiprotect BLOCK 分支在 admission/graphql 之后新增 `authzBlockMatched(matches)` 子分支：`writeAPIAuthzDeniedResponse`（403 + 规范 JSON `{"code":"AUTHZ_VIOLATION_DENIED","message":"无权访问该对象","request_id":"<id>"}`，与 admission 同形态、不泄露对象/主体细节——防探测）；committed=true 直接写出，不走 Caddy 错误链阻断页。源站零到达断言：集成测试断言 `X-Wdsp-Origin-Mark` 响应头缺席 + 记录型源站计数不增（§8.4 四断言之「源站到达性」）。
- **理由**：实断动作与既有防护域（admission/GraphQL/WAF）同一执行平面与响应纪律；「VERIFIED_VIOLATION 是判定、BLOCK 是执行」的分层让审计能区分「为什么拦」（authz reason）与「拦了」（final_action=BLOCK）。

### D5 EnforcementEvidence：内嵌 api_runtime_events `authz_enforcement` 对象，不建新表

- **结论**：证据结构按 §1.4 冻结，随该请求主事件行的 `final_decision` 对象内嵌（`final_decision.authz_enforcement`）——复用既有落库/留存/导出链，零新表零新迁移成本（除列级无改动）；结构含八因子逐项布尔值 + 版本/水位/租约读数 + enforcement_owner/evidence_source，可完整回答「为什么这 request 被实断」。查询走既有 `GET /api-security/authz/decisions` 扩展过滤（不新开端点，OpenAPI 增量见 D10）。
- **理由**：证据的最大风险是「与事件分离后说不清」——内嵌同一事件行天然绑定 request_id/endpoint/decision group；新表只会引入关联一致性问题而无收益。

### D6 能力门：az/3 新增（理由见 §1.5；az/2 只放行 enforcement 全 OBSERVE 快照）

- **结论**：网关自报 detectors.authzdecide 升 az/3；发布门对「快照含任一 enforcement=PROTECT 端点」计算 required `detectors.authzdecide=az/3`（门评估输入从 GuardConfig.api_authz_models 的 enforcement 字段聚合——编译期已知，无运行时探测）；az/1/az/2 节点 fail-closed `CAP_MISSING:detectors.authzdecide(required=az/3,actual=az/2)`；enforcement 全 OBSERVE 的快照不产生 az/3 需求（az/2 节点照常，滚动升级可行）。
- **理由**：NG-T-C08 要求旧节点收到新策略即拒绝——「含实断配置」与「v2 观测配置」必须分门，否则滚动升级会整体卡死或旧节点漏断。

### D7 水位/租约/冲突与 PROTECT 的交互：时效异常恒 UNKNOWN，UNKNOWN 恒不阻断

- **结论（冻结交互矩阵）**：
  | 情形 | OBSERVE enforcement | PROTECT enforcement |
  |---|---|---|
  | lease 过期 strict 端点 | UNKNOWN+DEPENDENCY_UNAVAILABLE（NG-AZ-02 现行为） | **同左**——UNKNOWN 不阻断（可用性影响如实：strict 过期端点在 PROTECT 下放行+标记，与「授权性放行禁止」的 D5 语义一致的是「不按过期事实放行」，但**不构成阻断**；需求方应缩短 lease 或接受 degraded） |
  | CLOCK_SKEW 节点 strict 端点 | UNKNOWN+AUTHZ-CLOCK-001 | **同左**（不阻断；§14.3 禁止的是「严格授权放行」不是「阻断」） |
  | OPEN 冲突对象 | UNKNOWN+AUTHZ-CONFLICT-001 | **同左**（D7 语义延续：冲突不可信，不可信不阻断） |
  | 水位回退快照 | 节点拒载（NG-AZ-02 D4-1） | 同左（与 enforcement 无关） |
- **理由**：UNKNOWN 不误断是全线红线——PROTECT 只给「已验证违规」加牙，不给任何 UNKNOWN 加牙；可用性语义逐行写清，杜绝「PROTECT 一开 strict 过期端点全 403」的误读。

### D8 权限/审计/回滚：切换沿用 api_authorization.manage，高风险审计，回滚保留证据

- **结论**：PROTECT 切换权限点沿用 `api_authorization.manage`（000048 已种，SECURITY_ADMIN；**不新增权限点**——阻断资格是授权事实管理的自然延伸；双人复核本批不做（列入不做清单，RD_PLAN §6 候选机制，后续 NG-AZ-04 向导批评估）；审计以既有 HIGH 风险级记录（object_type=api_object_model，after 摘要含 enforcement/enforcement_owner/evidence_source/on_unknown 四要素全值）。回滚（整站配置回滚到 OBSERVE 版本）：**不要求删除证据**——`authz_enforcement` 证据是历史事实（回滚不回退事实，与 NG-AZ-02 D1 同纪律）；回滚后新请求按 OBSERVE 记录拟动作。
- **理由**：权限模型稳定（不扩散权限面）；「回滚不改历史」与水位语义一致。

### D9 测试计划：NG-T-A01~A04 映射 + 集成四断言 stage5 步骤

- **结论**：
  | 用例 | 测试 |
  |---|---|
  | NG-T-A01（有效本人/可信排他） | ①OBSERVE：有效本人 ALLOW 到达源站；OTHER_OWNER 仅 OBSERVE_VIOLATION 记录不实断；②切 enforcement=PROTECT（带四要素）：同 OTHER_OWNER 请求 403 `AUTHZ_VIOLATION_DENIED` 统一 JSON，**源站零到达**（origin mark 缺席+计数不增），事件 final_action=BLOCK + authz_enforcement 八因子全真；③有效本人在 PROTECT 下仍 ALLOW 到达 |
  | NG-T-A02（未验证/历史推断） | 无 JWT / 伪造签名 / 历史推断 principal 的 OTHER_OWNER 场景：PROTECT 下恒 AUTHZ-IDENTITY-001 UNKNOWN 放行（**不阻断**）——负向样本主力 |
  | NG-T-A03/A04（跨租户/共享/过期/签名错） | 租户不一致 OBSERVE_VIOLATION 记录不实断；关系过期/冲突/快照签名错（能力门）下恒 UNKNOWN 不阻断 |
  | 集成四断言（§8.4） | 每场景同时断言：①客户端响应（403 JSON 形态精确匹配/200 到达）；②源站到达性（X-Wdsp-Origin-Mark 头有/无 + 记录型源站计数差分）；③决策记录（api_runtime_events 的 final_action 与 reason_code/enforced 标记）；④运行态事件（details_json 含 authz_enforcement 对象且八因子值正确） |
  | UNKNOWN 不误断负向样本清单（完成证据红线，逐条 PROTECT 下断言放行） | 未验证主体；伪造/过期 JWT；无有效关系（NONE）；关系已撤销；关系未生效（valid_from 未来）；OPEN 冲突对象；lease 过期 strict；lease 过期 degraded（评估+标记但放行）；CLOCK_SKEW；模型 publishable=false；owner_exclusive=false；required_relation≠OWNER；多模型匹配；快照 stale；水位回退（拒载非阻断）；租户不一致（OBSERVE_VIOLATION 但放行） |
  | NG-T-C08 能力门 | az/2 自报节点发含 PROTECT 快照 → CAP_MISSING:detectors.authzdecide(required=az/3)；az/3 正常应用；enforcement 全 OBSERVE 快照在 az/2 节点正常（滚动升级路径） |
- **理由**：「可信违规不达源站」与「UNKNOWN 不误断」两条完成证据都以负向样本为主体——测试矩阵以不阻断为主、阻断为特例。

### D10 兼容/缺省/迁移：000174 列级增量、OpenAPI 预估 688、缺省零变化

- **结论**：迁移 **000174**：`api_object_models` 加 `enforcement TEXT NOT NULL DEFAULT 'OBSERVE' CHECK (enforcement IN ('OBSERVE','PROTECT'))` + `enforcement_owner TEXT NOT NULL DEFAULT ''` + `evidence_source TEXT NOT NULL DEFAULT ''` + `on_unknown TEXT NOT NULL DEFAULT 'ALLOW_UNKNOWN'`；`api_role_baselines` 加 `enforcement` 同约束列（无伴随列）。OpenAPI 增量预估：object-models PATCH schema 扩四字段 + decisions 查询 `decision` 枚举加 VERIFIED_VIOLATION 说明 + `authz_enforcement` 证据对象 schema ——**零新端点**（操作数 686 持平），schema 级增量。NG-T-C01：新增列全默认 OBSERVE/空值——未配置应用行为逐字节不变；能力需求仅在含 PROTECT 行时产生。本批不做清单见 §3。
- **理由**：列级增量零行为变化是进入纪律；所有新语义都由显式四要素切换激活。

## 3. 本批不做（范围外，如实标注）

- 前端向导与影响评估界面（NG-AZ-04：切换前影响面/确认单/页面 E2E）。
- 双人复核机制（§6 候选；切换审批流 UI 与工作流）。
- VERIFIED_VIOLATION 在报表/风险中心层的归并展示（决策值查询侧派生视图的 UI 化）。
- TENANT-001 的阻断资格评审（本批冻结为 OBSERVE_VIOLATION 不实断，见 D2 注）。
- 共享/委托/组继承等非 OWNER 关系词的资格模型（首批不支持延续 NG-AZ-01 §5）。
- 业务在线推送通道、来源删除端点（NG-AZ-01 移交项顺延）。

## 4. 实现拆分建议（文件级边界；可双轨并行）

**A. server 快照与资格判定轨**
- 迁移 000174（object_models/role_baselines enforcement 列）；`apisecurity/object_models_update.go`（PATCH 扩 enforcement 四要素校验 + 审计）；`guardconfig/authz_decision.go`（enforcement 进模型编译与版本戳、az/3 需求聚合）；`gatewayconfig/capability_gate.go`（az/3 required 计算）；`apiauthz` decisions 查询扩展（decision 过滤 + authz_enforcement 带出）。
- 产出物：enforcement 列随快照下发、四要素校验、能力门、查询 API。

**B. 网关决策与阻断执行轨**
- `gateway/dynamic_security/detectors/authzdecide.go`（资格段真值表、VERIFIED_VIOLATION 决策值、authz_enforcement 结构生成）；`events/authz.go`（决策枚举第四值）；`modules/jiuzhang_guard/module.go`（enforcement 字段解析）+ `apiprotect.go`（authzBlockMatched 子分支 + writeAPIAuthzDeniedResponse）；`capability_report.go`（az/3 自报）。
- 产出物：决策值、实断执行、响应形态、能力自报。

**边界**：A 不动决策/事件枚举与 apiprotect；B 不动迁移/PATCH/查询 API。共享面仅两处类型：`GuardAuthzObjectModel.enforcement`（线契约，A 先冻结 B 只消费）与 `authz_enforcement` 证据 JSON 形状（B 产出、A 查询透传——在本文 §1.4 已冻结，双轨可无等待并行）。

## 5. 移交项（后续批次）

- NG-AZ-04：管理向导/影响评估/双人复核/业务确认单与全链验收。
- VERIFIED_VIOLATION 报表归并与风险中心展示。
- TENANT-001 阻断资格评审（需租户语义数据后再评）。
- stage5 ha-lab 双节点 PROTECT 分区演练（时钟偏差+分区下 strict/degraded 行为矩阵）。

## 6. 实现状态（2026-10-05 联调验收批补记；本节为实施记录，不改上文契约）

**状态：已落地并经 stage5 联调验收。** A（server 快照与资格判定）/B（网关决策与阻断执行）双轨按 §4 边界实施，联调批完成六组 E2E 与回归，出口判定见 `docs/nextgen/s3/S3-AZ03-EXIT-NOTE.md`。

### 6.1 决策点映射（D1~D10 → 实现位置）

| 决策 | 实现 |
|---|---|
| D1 枚举加值/动作不动 | 网关 `events.AuthorizationDecision` 加 `AuthorizationVerifiedViolation`；server 事件边界 `apiruntime/events.go validAuthorizationDecision` 收第四值；`api_authorization_decisions.decision` CHECK 放宽（迁移 000174）；查询词表 `apiauthz/handler.go validDecision`；final_action 词表与历史行零变更 |
| D2 八因子真值表 | 网关 `detectors/authzdecide.go evaluateBOLA` 资格段（OTHER_OWNER 后过八因子，全真才 VERIFIED_VIOLATION；TENANT-001 维持 OBSERVE_VIOLATION 不实断；NONE/INSUFFICIENT 恒 UNKNOWN） |
| D3 PROTECT 开关+四要素 | 迁移 000174（object_models 四列 + role_baselines.enforcement，全默认 OBSERVE）；`apisecurity/object_models_update.go` PATCH 四要素强制前置（缺一 400）；`gatewayconfig/guard.go` 线契约四字段 + `guardconfig/authz_decision.go` 编译下发（角色基线缺省 OBSERVE 归一空串——见 6.4 联调修正 ①）；版本戳自动覆盖 |
| D4 阻断执行 | 网关 VERIFIED_VIOLATION 以 `category=BLOCK`+`enforced=true` finding 经统一决策定案；apiprotect `authzBlockMatched` 子分支 `writeAPIAuthzDeniedResponse`（403 统一 JSON，committed 直出不走 Caddy 错误链） |
| D5 证据内嵌不建新表 | 网关 `authzAppendEnforcementEvidence` 产证 → `final_decision.authz_enforcement`；server `saveAuthorizationDecision` 提取原样写入 decisions evidence 列（只读透传不解释）；零新表 |
| D6 能力门 az/3 | 网关自报 az/3；`gatewayconfig/capability_gate.go` 聚合 models+role_baselines 任一 PROTECT → required az/3（az/2 兼容面：全 OBSERVE 零需求） |
| D7 时效交互矩阵 | 网关前置闸（skew/lease/conflict/水位）恒 UNKNOWN 不阻断——stage5 抽 lease 过期 strict 实证（窗口内 403 / 过期 200 放行+AUTHZ-LEASE-001+dependency_unavailable） |
| D8 权限/审计/回滚 | 权限沿用 `api_authorization.manage`（路由未动）；审计 HIGH 级 `objectModelSummary` after 含四要素全值；切回 OBSERVE 列值保留（PG 契约+stage5 实证）；回滚后新请求按 OBSERVE 记录拟动作（实证 final_action=OBSERVE+OBSERVE_VIOLATION） |
| D9 测试 | A 轨单测（validate 表/PG 契约/能力门两态/决策过滤/迁移 up-down/版本戳）+ B 轨 `authzdecide_az3_test.go`/`apiauthz_az3_test.go` + stage5 六组 E2E（出口记录逐项证据） |
| D10 兼容/缺省/迁移/OpenAPI | 000174 列级增量默认 OBSERVE/空值；OpenAPI schema 级增量（PATCH 四字段 + decision 枚举 + ApiSecAuthzEnforcementEvidence），操作数 686 持平零新端点，reconcile 双向零差集 |

### 6.2 A 轨偏差登记（4 条，均有注释落码）

1. 迁移 000174 额外放宽 `api_authorization_decisions.decision` CHECK（加 VERIFIED_VIOLATION）——D1「落库零迁移」语境是 events 枚举与 final_action 词表；000136 既有三值 CHECK 不放宽则新决策值落库即拒（主事件连锁失败）。词表加值非结构变更、历史行零变更；down 回缩要求无新值行。
2. `apiruntime/events.go` 两处联动（边界第四值 + evidence 透传）——数据链必经 server 边界，不改则 B 轨事件全被拒；校验用 server 侧字面常量，零编译依赖 B 轨产物（线契约字符串值为设计冻结）。
3. az/3 聚合覆盖 role_baselines（D6 字面只写 models 聚合）——仅聚合 models 会使 baselines-only PROTECT 快照漏门（az/2 节点静默忽略实断配置=§1.5 漏断方向），故聚合两集合。
4. 「全 OBSERVE 零漂移」口径：enforcement 字段随快照序列化（值 'OBSERVE' 非空，同 NG-AZ-02 OnLeaseExpired 先例），升级后首次发布版本戳漂移一次；零变化落在行为面（az/2 节点忽略未知字段 + 能力门零新需求），stage5 实证 az/2 自报收全 OBSERVE 快照成功。

### 6.3 B 轨偏差登记（按 B 轨实现回报与代码佐证）

1. BFLA eligibility 键集为 BFLA 实评键（`trusted_identity`/`baselines_applicable`/`evidence_fresh`/`role_violation`），非 BOLA 八因子——BFLA 无对象维度（关系/冲突/排他因子不适用），§1.4 形状顶层键同构、eligibility 按检测域实评。
2. BFLA 证据 `object_ref` 置空（无对象维度）；行级显式 PROTECT 的 `enforcement_owner`/`evidence_source`/`model_version` 置空（角色基线行无伴随列），仅继承端点模型时有值——stage5 两形态证据均已实证。
3. BFLA 时效前置按 strict 缺省（无端点策略标志位；D8「禁止严格授权放行」同义于基线快照事实）。
4. PreviousValid 回退保留请求级 `EngineProtect`（双闸之二为请求级输入，不随历史快照失效；authzdecide.go:215-217）。
5. VERIFIED_VIOLATION 组决策优先级最高；OBSERVE 形态降级留 `proposed_decision` 拟动作痕（§1.1），未配置零变化不留痕。
6. 实断响应复用 admission 同形态统一 JSON（`AUTHZ_VIOLATION_DENIED`，不泄露对象/主体细节防探测），committed 直出不走 Caddy 错误链阻断页。

### 6.4 联调新发现与修正（联调验收批，2026-10-05）

1. **A/B 契约缺口（已修正）**：A 轨 `ListVerifiedAuthzRoleBaselines` 原把 DB 缺省 OBSERVE 归一为非空 'OBSERVE' 下发，B 轨继承判定以「空串=未配置」为继承触发——继承链断裂（viewer denied 行在端点 PROTECT 下不放行实证先于修正）。修正：A 轨缺省 OBSERVE 归一为空串下发（omitempty 省略），网关空值继承端点模型；行级显式 PROTECT 非空下发。「显式行级 OBSERVE 覆盖端点」语义本批不表达（管理面无角色基线 enforcement 写通道）。修正后 stage5 三态实证：继承 403 / 行级显式 403（端点 OBSERVE）/ 全 OBSERVE 放行。
2. **BOLA/BFLA 端点匹配口径差异（登记，B 轨设计选择）**：BFLA 基线端点过滤为归一端点键字符串相等，BOLA 模型匹配另有 `path_template` 逐段通配兜底——不可归一形态的对象值（如字面 `t001`）请求可匹配 BOLA 模型但不匹配 BFLA 基线；可归一形态（纯数字/UUID/长 hex）两者一致。E2E 以可归一形态对象（1001）完成 BFLA 断言。
3. **发布验证对「首次 OFF 且从未启用 Bot 的应用」无墓碑**：探针路径 `/_wdsp/bot/v1/publish-smoke` 打到源站 404 判 VERIFY_FAILED_ROLLED_BACK——新应用接入发布验证需 bot `route_reservation=RESERVED_TOMBSTONE`（或历史启用过 Bot）。E2E 期间以 TOMBSTONE 保留承载，还原时 RELEASED。
4. **object_hmac_key 删除后的 PreviousValid 连锁**：当前生效快照含模型时删除 `api_authz.object_hmac_key` 设置，下一次发布因 `ensureAuthzSnapshotKey`（previous 含模型需重注入 key）fail-hard `GUARD_SNAPSHOT_FAILED`——还原顺序须「带 key 发布（新快照无模型）→ 删 key → 再发布」。

### 6.5 E2E 证据摘要（stage5，2026-10-04/05 窗口；逐项原文见出口记录）

- NG-T-A01 主链四段：OBSERVE 基准 OBSERVE_VIOLATION+到达 → PROTECT 403 精确体+源站零到达（mark 0/3）+VERIFIED_VIOLATION 八因子全真证据 → 真本人 200 到达 → 切回 OBSERVE 列值保留+拟动作恢复。
- PATCH 四要素八负向 400（缺项/空白/超长/词表外逐条精确消息）。
- UNKNOWN 不误断九负向样本全部放行（IDENTITY-001×2/RELATION-001×2/CONFLICT-001/POLICY-001×2/TENANT-001 OBSERVE_VIOLATION 放行）。
- BFLA 三态（继承/行级显式/全 OBSERVE）+ AUTHZ-BFLA-001 证据两形态。
- NG-T-C08 能力门三态（az/2+PROTECT→CAP_MISSING(az/3)；az/3+PROTECT→OK；az/2+全OBSERVE→OK）。
- D7 lease 过期 strict：窗口内 403 / 过期放行+UNKNOWN+dependency_unavailable。
- 回归：stage5-gateway-tests 40/40、custom-pack-blocking 13/13、server 6 包+gateway 全模块测试绿、reconcile 686 零差集、gofmt 干净。
