# API 运行时模型编译器（Runtime Model Compiler）设计

> 对应补全任务书 §225（P0-03/P0-21）。本文以代码为准描述第一波交付后的真实实现：
> 编译器本体、状态机、发布联动与回滚均已落地；多节点同步未实现，如实说明（见 §八）。

## 一、目的与范围

Runtime Model Compiler 把**已确认的 FORMAL 模型版本**编译为**API级运行时策略版本**
（`api_runtime_policies`），为每个API沉淀一份可溯源、可回滚、带生命周期的运行时
防护产物，并借整站发布通道联动生效。本文覆盖：

- 编译输入/输出与规范序列化（`server/internal/apimodels/compiler.go`）；
- `api_runtime_policies` 表与状态机（迁移 000037、`apimodels/runtime_policy.go`）；
- Confirm → DRAFT → Activate → VALIDATED → 发布 → ACTIVE 的联动链路；
- 发布生效校验（`gatewayconfig/publisher.go` verifyPublish 哈希比对）；
- 回滚接口与「上一已知良好版本」语义；
- 多节点同步现状（未实现）与失败处理矩阵。

网关如何消费下发内容见 `docs/API_SCHEMA_PROTECTION.md` 与
`docs/API_UNIFIED_FINDING_DECISION.md`；模型版本自身的状态机见
`docs/API_MODEL_VERSIONING.md`。

## 二、编译输入（Input）

编译器为**纯函数**（`compiler.go:84` `Compile`）：不触库、不依赖时间，同输入恒得同输出
（`content_hash` 稳定），可独立单测（`compiler_test.go`）。

`CompileInput`（compiler.go:22-34）由 Confirm 事务内组装
（`runtime_policy.go:93` `createDraftRuntimePolicyTx`）：

| 输入 | 来源 | 说明 |
|---|---|---|
| `EndpointID` / `EndpointKey` | 版本快照 / `api_model_versions.endpoint_key` | METHOD + 归一化路径 |
| `Method` / `NormalizedPath` / `ProtocolType` / `AssetStatus` | `api_endpoints` 行（事务内 `SELECT`） | API实时信息 |
| `ModelVersionID` / `ModelVersionNumber` | 版本快照 | 必须为 FORMAL（Confirm 事务保证） |
| `Schema` | `api_model_versions.schema_json` | 请求体字段路径 → 期望类型 |
| `Parameters` | `api_parameter_models`（该版本 `direction='REQUEST'` 行） | 含 confirmed 词汇，Confirm 事务刚物化 |

## 三、编译输出（Output）

产物 `CompiledEndpointPolicy`（compiler.go:53-68）落库为
`api_runtime_policies.content_json`：

```text
endpoint_key / method / normalized_path /
content_type        请求体协议（REST 或空 protocol_type → application/json；其余协议本波不约束=空串）
lifecycle           API资产生命周期（asset_status 快照）
source_model_version_id / source_model_version_number   来源模型版本溯源
compiler_version    编译器版本（当前恒 "v1"）
request_schema      请求体字段 → 期望类型
parameter_constraints[]  全量 confirmed 词汇：location/name/path/base_type/
                         semantic_type/required/nullable/empty_allowed/
                         sensitivity_level/constraints（min_length/max_length/
                         minimum/maximum/enum 等原样编入）
auth_requirement    预留占位（P0-15/16 另一波补全），本波恒 null
response_schema     预留占位（P0-06 另一波补全），本波恒 null
```

两点纪律：

- **词汇超集**：编译产物携带全量 confirmed 词汇；发布通道 `GuardParamConstraint`
  （`gatewayconfig/guard.go:70-77`）原样透传 confirmed_constraints map——执行词汇已扩至
  8 键（第三波：`min_length/max_length/minimum/maximum/enum` + `regex/nullable/empty_allowed`，
  且 `required` 在 PROTECT 模式升级为 BLOCK 类，见 `detectors/schema.go:119-129`）；
  array_size/mime/file_size 等仍不下发不执行。
- **确定性排序**：参数约束按 `(location, path, name)` 排序（compiler.go:108-116），
  保证同输入同字节流。

## 四、规范序列化与内容哈希（Serialization）

- `CanonicalJSON`（compiler.go:135）：结构体字段序固定 + map 键序由 `encoding/json`
  排序，输出确定字节流；
- `ContentHash`（compiler.go:140）：规范序列化的 **sha256 hex**，落库
  `api_runtime_policies.content_hash`；任一输入字段变化产生新 hash；
- 同一套「规范序列化 + sha256」纪律复用于发布内容版本戳 `api_policy_version`
  （`guardconfig/apiruntime.go:126-148` `computeAPIPolicyVersion`：冻结模型 + 确认参数约束
  + 脱敏规则 + 值级敏感检测规则 + 角色基线（`api_role_baselines` confirmed 行）
  + 字段权限（`api_field_permissions`）的规范序列化哈希——后三者随第三/四波陆续纳入），
  供生效校验与网关回报比对「发布内容与实际生效」。

## 五、版本模型（Version）

`api_runtime_policies`（迁移 000037）关键列：

```text
id / endpoint_id（FK api_endpoints）/ source_model_version_id（FK api_model_versions）/
runtime_version      API内自增 "vN"（非全局序号；与 api_model_versions.version_number
                     API维度语义平行；(endpoint_id, runtime_version) 唯一约束兜底并发，
                     冲突如实报错不静默重试）
compiler_version     编译器版本（编译输出结构或词汇变化时递增 CompilerVersion 常量，
                     用于区分历史产物与定位回归）
content_json         CompiledEndpointPolicy 规范序列化（JSONB）
content_hash         规范序列化 sha256
status               DRAFT/VALIDATED/PUBLISHED/ACTIVE/ROLLED_BACK/FAILED（CHECK 约束）
error                发布失败原因（status=FAILED 时）
created_at / published_at / activated_at
```

索引：`(endpoint_id, runtime_version)` 唯一、`(endpoint_id, status)`、
`(source_model_version_id)`（模型→策略溯源）、`(status)`（发布回写全量扫描）。

## 六、发布联动（Publish）

### 6.1 状态机

```text
模型 Confirm(→FORMAL) 事务内编译 ──► DRAFT        （尚未纳入发布）
模型 Activate（仅 FORMAL）       ──► VALIDATED     （「待发布」，等下次整站发布；
                                                    FAILED 随重新激活回到 VALIDATED——
                                                    发布失败后的恢复路径：重新激活+重新发布）
（PUBLISHED 为预留中间态：本波发布成功直接落 ACTIVE，保留供后续多阶段生效校验扩展，
  发布回写 SQL 将其视同待发布集合）
整站发布成功且生效校验通过       ──► ACTIVE        （同API旧 ACTIVE 同事务退 ROLLED_BACK）
曾生效后退出                     ──► ROLLED_BACK   （「已知良好版本」，供回滚溯源）
发布失败                         ──► FAILED + error（记录发布侧失败原因）
```

联动代码：

- Confirm 事务（`apimodels/store.go:183`）：旧 FORMAL 降 SUPERSEDED → 版本置 FORMAL →
  物化请求侧参数行 → `createDraftRuntimePolicyTx` 编译落 DRAFT（store.go:219）；
- Activate 事务（store.go:281）：置 `api_endpoints.current_model_version_id` →
  同事务把该版本对应策略 `DRAFT/FAILED → VALIDATED`（store.go:309-313）；
- 整站发布结果回写（`runtime_policy.go:155` `MarkRuntimePoliciesPublishResult`，由
  `guardconfig/provider.go:520` `MarkVersionResult` 注入调用）：
  - 成功——每API待发布集合（DRAFT/VALIDATED/PUBLISHED）取**最新一条** → ACTIVE
    （记 `published_at/activated_at`），同API旧 ACTIVE → ROLLED_BACK；
  - 失败——全部待发布集合 → FAILED 并记录原因。
  - 语义注释（runtime_policy.go:154）：发布内容含全部 FORMAL 模型，故回写按全量API
    执行；无待发布策略的API保持原 ACTIVE 不变。

### 6.2 下发内容的真实装配方式（诚实说明）

发布通道**不直接以编译产物 `content_json` 为下发载荷**：`BuildGuardConfig`
（`guardconfig/provider.go:336-407`）在每次整站发布时现查 FORMAL 模型装配——
`ListFormalSchemas` / `ListFormalModelVersions` / `ListFormalParameterConstraints`
（按 `endpoint_key` 取最新 FORMAL，`apimodels/store.go:536/564`）+ `api_masking_rules`
enabled 规则 + `gateway_runtime` 组设置，计算 `api_policy_version` 后整体进
GuardConfig 下发网关。编译产物与下发内容**同源**（同一份 FORMAL 模型与 confirmed 词汇），
`api_runtime_policies` 承担的是**版本化记录、溯源、状态机与回滚克隆**职责；
「以编译产物为唯一发布载荷」是后续演进方向，本波未切换。

### 6.3 生效校验（verifyPublish）

发布后验证（`gatewayconfig/publisher.go:541`）：

1. Caddy Admin 可用（Ping）；
2. 当前配置非空且包含预期 server 定义；
3. **规范化哈希比对**（P0-21）：`CanonicalConfigHash(发布内容)` 与网关实际加载配置哈希
   （`GetConfigHash`）必须一致，不一致视为未生效 → 上层触发**自动回滚到上一配置**，
   发布任务记 `VERIFY_FAILED_ROLLED_BACK`，待发布策略集合落 FAILED。

网关侧随事件回报 `policy_version`（`api_policy_version` 原样透传）与按API命中的
`model_version`（`api_formal_model_versions` 下发），采集落 `api_runtime_events`
（迁移 000035），供「命中时生效哪版模型与策略」审计比对。

## 七、回滚（Rollback）

接口：`POST /api/v1/api-security/runtime-policies/{id}/rollback`
（权限 `api_model.activate`，`apimodels/handler.go:63`）。

语义（`runtime_policy.go:307` `CreateRollbackDraft`，事务 + `FOR UPDATE`）：

1. 目标策略须处于 **ACTIVE 或 FAILED**（当前生效异常/发布失败才允许回退），否则
   `ErrInvalidTransition` → 409；
2. **上一已知良好版本** = 同API最近一个曾生效后退出的策略（`ROLLED_BACK` 且
   `activated_at` 非空，按 `activated_at` 倒序取首条）；不存在 →
   `ErrNoPreviousGoodPolicy` → 409；
3. **克隆其编译内容**创建新 DRAFT（新 `runtime_version`，`content_hash` 与原良好版本
   一致——回滚产物与历史良好版本字节级同源）；
4. Handler 随后**重触发整站发布**（`runtime_policy_handler.go:132`，app 装配接线
   `publisher.PublishSync`；未接线 → 503），发布成功经 §6.1 回写落 ACTIVE；
5. 记录高危操作审计（`audits.RiskHigh`）。

注意：这是**API级内容回滚 + 整站发布**的组合——发布载荷仍按 FORMAL 模型装配（§6.2），
故回滚的实际生效依赖「回滚 DRAFT 对应模型为API当前 FORMAL」这一前提；纯配置级回滚
（整站配置版本）走 `POST /api/v1/config-versions/{id}/rollback` 既有通道
（publisher.go:586 `Rollback`，同样过 verifyPublish）。

## 八、多节点同步（Node Sync）——未实现，如实说明

- 发布通道面向**单 Caddy 实例**：配置经 Caddy Admin API（Unix Socket，
  禁止 TCP 暴露）加载，Publisher 持单一 caddy 客户端；无多节点广播/集群同步机制。
- `api_runtime_policies` 状态机是**管理面记录**：ACTIVE/ROLLED_BACK 等状态反映
  「本管理面所管网关」的发布结果，不向多网关节点推送或对齐。
- 多网关部署现状：各节点各自运行 jiuzhang_guard、各自加载配置、各自产事件 JSONL，
  由管理面采集器汇总入库；行为计数的多节点共享走 Valkey 存储（见
  `docs/API_BEHAVIOR_DISTRIBUTED_STATE.md`），与策略分发无耦合。
- 后果：多节点下「策略版本一致性」只能靠逐节点重复发布与 `api_policy_version` 回报
  比对人工保证；自动化的多节点同步/分阶段生效（PUBLISHED 中间态的设计动机）留待后续。

## 九、失败处理（Failure Handling）

| 环节 | 失败行为 |
|---|---|
| 编译/落库（Confirm 事务内） | 整个 Confirm 事务回滚，模型不置 FORMAL，错误如实返回（store.go:219-224） |
| 并发 version 冲突 | `(endpoint_id, runtime_version)` 唯一约束兜底，如实报错不静默重试 |
| 整站发布失败 | 待发布集合（DRAFT/VALIDATED/PUBLISHED）→ FAILED + `error` 记录原因 |
| 生效校验失败 | 自动回滚上一配置；版本记 VERIFY_FAILED_ROLLED_BACK；策略落 FAILED |
| 发布失败后恢复 | 重新 Activate（FAILED → VALIDATED）+ 重新发布 |
| 回滚接口 | 策略不存在 404 / 无上一良好版本或状态非法 409 / 发布通道未接线 503 |
| `gateway_runtime` 设置读取失败或取值非法 | 中止发布，不静默回退（`guardconfig/apiruntime.go:36-45`） |
| `api_masking_rules` 读取失败 | Warn 并跳过 `api_mask_rules` 段，不阻断发布主流程（增量能力，apiruntime.go:172） |

## 十、只读接口与溯源

| 接口 | 权限 | 说明 |
|---|---|---|
| `GET /api/v1/api-security/runtime-policies?endpoint_id=&status=&page=&page_size=` | `api_model.read` | 策略版本分页列表（status 白名单校验，非法 400） |
| `GET /api/v1/api-security/models/{id}/runtime` | `api_model.read` | 模型 → 策略溯源（该模型版本编译产生的全部策略） |
| `POST /api/v1/api-security/runtime-policies/{id}/rollback` | `api_model.activate` | 回滚（§七） |

## 十一、测试证据

- `apimodels/compiler_test.go`：纯函数确定性（同输入同 hash）、排序、content_type 推导；
- `apimodels/runtime_policy_test.go`：状态机回写矩阵、回滚成功/无良好版本/非法状态/
  未接线 503、接口参数校验；
- `guardconfig/apiruntime_test.go`：`gateway_runtime` 设置写入/缺省/非法值、
  `api_policy_version` 稳定性、脱敏规则缺失容忍；
- `gatewayconfig/guard_runtime_test.go`：GuardConfig 下发键（含 `api_policy_version`
  与六键）序列化契约。
