# API 安全能力现状盘点（API Security Current State）

> 依据：《九章Web动态防护系统 API安全能力补全与产品化增强开发任务书》（WDSP_API_SECURITY_COMPLETION_PLAN.md，下称"补全任务书"）§222 / §244 第一步要求。
> 盘点基准：`develop` 分支工作树现状（含未提交改动），初盘 2026-08-16；**2026-08-20 终态刷新**（第一~十四波补全全部合入工作树，迁移至 000072；§1/§3/§4/§5/§6/§7/§8 以本次刷新为准，逐波变化明细见文末各刷新说明）。
> 盘点方法：以代码为准——逐项追溯实际调用链、数据生产者、Runtime 下发链路与自动化测试；不以"表存在 / API 存在 / 前端存在 / 文档写了"作为完成依据。
> 注意：补全任务书本身未入库（仓库内为 `docs/tasks/STAGE_8_UNIFIED_WEB_API_DYNAMIC_PROTECTION.md`），本文件按补全任务书口径盘点。

## 状态判定标准

| 状态 | 含义 |
|---|---|
| IMPLEMENTED_AND_CLOSED_LOOP | 端到端闭环：生产者→存储→下发/消费→测试证据齐全 |
| IMPLEMENTED_PARTIAL | 部分实现，链路存在断点或覆盖面不全 |
| TABLE_ONLY | 仅有表结构，无生产写入方 |
| API_ONLY | 有接口但无真实数据源/无前端消费 |
| FRONTEND_ONLY | 仅前端页面，后端无数据 |
| STUB | 占位实现（枚举/空函数/孤儿代码） |
| NOT_IMPLEMENTED | 完全不存在 |
| UNKNOWN | 无法判定 |

---

## 1. 总体结论

1. **阶段8 主干能力真实存在且质量扎实**：统一引擎挂接请求链（`serveNext` 唯一挂点）、一次解析多协议、请求侧检测器族（schema/身份/敏感/BOLA/生命周期/行为/限速/AuthZ/关系/扫描识别/LLM/MCP/gRPC/文件合规等）、统一事件流（JSONL→采集器→`api_runtime_events` 幂等）、API自动发现、模型生命周期状态机、学习样本自动采集与阈值候选、参数值脱敏观测通路、**155 条 `/api/v1/api-security/*` 接口、41 权限点+三权、30 个前端页面、15 个 READ_ONLY AI 工具**——这些有真实代码与测试，不是空壳。
2. **第一~十四波补全（2026-08-16 ~ 2026-08-20，迁移 000035-000072）全部合入**：原三大系统性断点（Finding 生产化/Runtime Compiler/响应侧）第一波即接通；第三~六波收口 Coraza 合流、AuthZ 实体层与运行时消费、响应 Schema 学习、调用边派生、API 告警静默、主动扫描 v1、AI 工具第二批；第七/八波落地数据出境、API 专项报告、敏感文件资产、AI 定时运营、扫描前端页与 E2E 扩充；第九~十一波收口扫描流量识别（学习样本排除由待命转生效）、响应偏离检测、API 态势全维度、LLM API 观测 v1、参数条件关系运行时检测、响应方向字段权限判定；第十二~十四波落地多节点版本遥测校验、MCP 内容级检测、文件水印/签名/合规 v1、gRPC 帧级校验 v1、源码 API 发现 v1（逐波明细见文末刷新说明）。
3. **P0 全 21 项终态：2 项主干闭环（P0-03/05）、19 项部分实现、0 项仅建表、0 项未实现**——十四波推进后各项均有真实生产链路与运行时消费，残余为任务书超集口径的覆盖面缺口（逐项 Known Gap 如实标注，无"宣称完成但代码未做"项）。
4. **P1 全 10 项终态：10 项全部落地为 IMPLEMENTED_PARTIAL 及以上**（第七/八波补齐 P1-03/04/06，第九/十波补齐 P1-01 态势全维度与前端页）；**P2 七项终态：7 项全部 v1 交付（均为最小可行子集，IMPLEMENTED_PARTIAL；P2-06 HTTP/3 于第二十波完成启用方式与端到端验证，QUIC 层深度解析保留为边界）**。
5. 项目文档（`docs/DEVELOPMENT_STATUS.md` 阶段8"诚实遗留"已随各波刷新、本文 §6.5）对剩余缺口的自述与代码现状一致；终态断点收敛为：多节点全量同步协议、描述符级 gRPC、HTTP/3 深度解析、生产级性能实测（见 §8）。

### P0 状态统计（终态）

| 状态 | 数量 | 条目 |
|---|---|---|
| IMPLEMENTED_AND_CLOSED_LOOP | 2 | P0-03、P0-05 |
| IMPLEMENTED_PARTIAL | 19 | P0-01/02/04/06/07/08/09/10/11/12/13/14/15/16/17/18/19/20/21 |
| TABLE_ONLY | 0 | — |
| STUB | 0 | — |
| NOT_IMPLEMENTED | 0 | — |

### P1 状态统计（终态）

| 状态 | 数量 | 条目 |
|---|---|---|
| IMPLEMENTED_PARTIAL | 10 | P1-01/02/03/04/05/06/07/08/09/10（各项交付形态见 §3） |
| NOT_IMPLEMENTED | 0 | — |

### P2 状态统计（终态）

| 状态 | 数量 | 条目 |
|---|---|---|
| IMPLEMENTED_PARTIAL | 6 | P2-01 文件水印 v1（文本族+OOXML）、P2-02 文件签名 v1、P2-03 文件合规 v1、P2-04 LLM API 安全 v1（含 MCP 内容级）、P2-05 gRPC v1（帧级）、P2-07 源码 API 发现 v1 |
| NOT_IMPLEMENTED | 0 | — |

---

## 2. P0 逐项盘点（对应补全任务书 §218 P0-01 ~ P0-21）

### P0-01 学习自动闭环

- **Status**: IMPLEMENTED_PARTIAL
- **Code Path**: 样本采集 `server/internal/apiruntime/collector.go:415` → `samples.go:66-84` 过滤 → `apiassets/learning_automation.go:54` 落库；阈值判定 `learningjobs/janitor.go:149`（SweepOnce，默认 30s 周期）；自动候选 `apimodels/candidate_builder.go` → `apimodels/store.go`；装配 `server/cmd/api/main.go`
- **Database**: `api_learning_jobs` / `api_learning_samples`（迁移 000018:88-116；000027 幂等索引）
- **Runtime Producer**: 网关全部 API 流量产事件（`gateway/modules/jiuzhang_guard/apiprotect.go:135-137`）→ JSONL → 采集器
- **Runtime Consumer**: learningjobs janitor（周期判定）；`guardconfig/provider.go:344-349`（发布时读取 FORMAL 模型）
- **Frontend**: `web/src/pages/api-learning/`、`api-endpoints`（学习启停/状态）
- **Test**: `learning_automation_test.go`、`janitor_test.go`（TestSweepOnceThresholdReached/NotReached）、`samples_test.go`（16 例过滤矩阵）
- **Known Gap**（2026-08-17 刷新；已闭环项见标注）：
  1. ~~自动候选生成条件 8 项仅 1 项~~ **已闭环（000038）**：`learningjobs/conditions.go` 多条件判定（min_valid_samples/min_unique_ips/min_unique_identities/min|max_learning_duration/minimum_success_ratio，`system_settings` 组 `api_learning` 可调，默认不改变既有行为）；minimum_stability_score / meaningful_change_detected 仍未实现；
  2. ~~自动候选为空 Schema~~ **已闭环（000038）**：`apimodels/candidate_builder.go` 以API级脱敏观测推断类型/required（出现率 ≥95%）/长度/值域生成**非空候选**（无观测回退空 Schema）；
  3. ~~CANDIDATE→IN_REVIEW 无自动提交~~ **已闭环（000038）**：达标自动候选直接提交 IN_REVIEW；确认/激活/发布仍人工；超期未达标任务置 FAILED + last_error（FAILED 有写入点）；
  4. 样本过滤 16 条规则落地约 5 条（blocked_by_decision/response_status（响应后输出后已有真实原料）/waf_hit/schema_deviation/source_ratio_cap）；高速枚举、解析失败等无识别；~~Scanner 流量无识别~~ **已闭环（第九波）**：网关识别 X-JiuZhang-Scan 签名头（有效产 `scanner.signature_valid`、伪造产 `scanner.signature_forged`、未配密钥产 `scanner.presence_only`），`detector=scanner` 明细即被样本排除规则（`apiruntime/samples.go:50`）消费——扫描流量不进学习/行为基线由待命转为生效；
  5. 防投毒 7 项落地 2 项（source_ratio_cap 硬编码不可配、sample_dedup 幂等）；
  6. 学习来源标记（TRAFFIC/SPEC/SCANNER/MANUAL）不存在；`unique_ips`/`stability_score`/`candidate_version_id` 字段不存在；
  7. 网关侧 `gateway/dynamic_security/learning/version.go` 是未接线孤儿占位。

### P0-02 参数统计真实生产

- **Status**: IMPLEMENTED_PARTIAL（核心链路真实闭环，但仅 BODY 位置参数；覆盖面远低于任务书 §4.2 字段清单）
- **Code Path**: 观测产生 `gateway/dynamic_security/detectors/paramobs.go:32` → 事件 `apievents/apievents.go:46` → 采集 `apiruntime/collector.go:361-366` → 入库 `apiruntime/paramobs.go:44-123`（UPSERT `api_parameter_value_obs`）→ 周期回填 `apimodels/statistics.go:35-188`（`RefreshParameterStatistics`，janitor 每轮触发 `janitor.go:162-168`）；参数行物化 `apimodels/parameters.go:241-267`（Confirm 事务内）
- **Database**: `api_parameter_models` / `api_parameter_statistics`（000018:122-155）、`api_parameter_value_obs`（000031:6-21）、身份唯一索引（000028:27）
- **Runtime Producer**: learningjobs Worker（30s 周期）+ Confirm API（物化）
- **Runtime Consumer**: `ListFormalParameterConstraints`（`parameters.go:285-315`）→ 发布通道 → 网关 `CheckParamConstraints`（`detectors/schema.go:126`）
- **Frontend**: `web/src/pages/api-parameters/ApiParametersPage.tsx`（不展示 observed/recommended 内容，仅 EndpointDetailDrawer 显示长度区间）
- **Test**: `server/tests/stage8_parameter_statistics_test.go`、`stage8_param_value_obs_test.go`、`recommended_test.go`；明文泄露回归 `detectors/paramobs_test.go:10`
- **Known Gap**:
  1. 任务书 §4.2 字段清单中 presence_rate / null_rate / empty_rate / avg_length / p50~p99 / format_candidate / array_size / object_fields **连列都不存在**；真实写入的仅 sample_count（API级平铺）/min_max_length/min_max_value/distinct_count（上限64）/example_hashes/base_type（人工来源）/semantic_type（启发式）；
  2. `ParameterProfile` 的 P95Length/P95Value/EnumCandidates 永久 nil（`recommended.go:38-43`）→ enum 推荐分支死代码；value_hashes 不可逆推枚举值；
  3. ~~参数行物化仅 REQUEST/BODY → QUERY/PATH 孤儿数据~~ **已闭环（000038）**：Confirm 时 QUERY/PATH 按观测物化参数行；HEADER/COOKIE 两侧无数据源暂不物化；FORM/XML/GraphQL/multipart/RESPONSE 仍不观测；
  4. sensitivity 纯人工 PATCH（无自动判定）；confidence 物化时固定 1.0 永不更新；
  5. 微模型缺口：字符串分布/charset/format/熵、数字分位数/precision、Object/Array 结构、文件参数（size/mime/magic）全部未学习；
  6. 三层结构 Observed/Recommended/Confirmed 共存（recommended 有样本量分级规则），但第四层 Runtime 视图不存在；
  7. ~~参数条件关系：CO_OCCURS 候选真实产生（`relations.go:15-49`），但无确认 API、无网关消费、前端 `listRelations` 无调用方（死代码）~~ **已闭环（第十一波，迁移 000068）**：`api_parameter_relations` 补 confirmed 列与词表 CHECK；手工新建 REQUIRES/MUTEX + confirm/reject 接口（api_parameter.edit + 操作审计，`apimodels/handler.go:62-66`）；confirmed 关系经发布通道 `api_parameter_relations` 下发并纳入 api_policy_version 哈希（`guardconfig/provider.go:462`）；网关运行时检测 `detectors/relationcheck.go:91` `CheckParamRelations`——REQUIRES 缺失/MUTEX 同现（PROTECT 升级 BLOCK、OBSERVE 仅观察）、CO_OCCURS 仅 INFO；证据不落值。

### P0-03 Runtime Model Compiler

- **Status**: IMPLEMENTED_AND_CLOSED_LOOP（2026-08-16 起；Confirm→编译→Activate→发布回写→回滚链路真实存在）
- **Code Path**: Confirm 事务内编译 FORMAL 版本为API级运行时策略 `CompiledEndpointPolicy`（compiler_version=v1，content_hash=规范序列化 sha256，runtime_version API内自增 vN）；状态机 DRAFT→（Activate）VALIDATED→（整站发布成功回写）ACTIVE，同API旧 ACTIVE→ROLLED_BACK，发布失败→FAILED；回滚接口克隆上一已知良好版本为新 DRAFT 重发布；整站发布仍经 `guardconfig/provider.go` `BuildGuardConfig` 下发（含 api_formal_model_versions / api_policy_version 版本戳）
- **Database**: `api_runtime_policies`（迁移 000037：API级策略版本、状态机列、content_hash）
- **Runtime Producer**: Confirm/Activate API + 发布回写；**Runtime Consumer**: 发布通道 → 网关（事件回报 model_version/policy_version，迁移 000035）
- **Frontend**: `GET runtime-policies` 列表、`GET models/{id}/runtime` 溯源、`POST runtime-policies/{id}/rollback` 回滚；前端运行时策略页随第二波 F3 分片交付
- **Test**: `apisecurity/policy_test.go` 等
- **Known Gap**: 编译后生效仍需整站发布动作（VALIDATED→ACTIVE 由发布成功回写，无独立API级热下发）；compiler_version 单版本 v1；~~约束下发词汇仍 5 键~~ 已扩至 8 键（第三波，见 P0-04）；多节点同步协议仍缺（见 P0-21）。

### P0-04 参数约束下发

- **Status**: IMPLEMENTED_PARTIAL（原 5 个词汇 BLOCK 级闭环；第三波扩 regex/nullable/empty_allowed + required 升级 BLOCK；确认→生效不自联动）
- **Code Path**: 下发载体 `GuardParamConstraint`（`gatewayconfig/guard.go:69-76`）；执行入口 `pipeline/pipeline.go:117-118` → `CheckParamConstraints`（`detectors/schema.go:149`）；PROTECT 模式 BLOCK → 403（`decision/engine.go:83-85` → `apiprotect.go:436-440`）
- **逐项核实**（任务书 §4.3 清单）：
  - min_length/max_length：✅ BLOCK/HIGH（schema.go:224-232）
  - min_value/max_value：✅ BLOCK（minimum/maximum，schema.go:198-221）
  - enum：✅ BLOCK（schema.go:235-242）
  - type：⚠️ 仅 BODY JSON 经 formal schema type_mismatch（BLOCK）；ParamConstraint 自带 base_type 不参与比较
  - required：✅ 已升级（第三波）——PROTECT 模式缺失升级 BLOCK 类可定案阻断，其余模式维持 OBSERVE/+5 分（schema.go:198-216）
  - object_fields：⚠️ 仅 BODY undefined_field 与 confirmed required 缺失（schema.param_required）；可选字段缺失不再产生 schema.missing_field 噪声
  - regex：✅ 已落地（第三波）——RE2、≤512 字符，编译失败/超长保守产 OBSERVE 明细（schema.param_regex，不阻断）（schema.go:124/293-305）
  - nullable / empty_allowed：✅ 已落地（第三波）——nullable 仅 BODY JSON 有 null 语义、empty_allowed 空串各位置 + 空数组仅 BODY，均显式 false 才违例（schema.go:125-129/217-232）；其余位置仅存 DB 不判定
  - array_size / mime / file_size：❌ 不下发不执行
- **Database**: `api_parameter_models.confirmed_*` 列（000028）
- **Runtime Producer**: Confirm API → 发布通道；**Runtime Consumer**: 网关 schema detector
- **Frontend**: api-parameters 页（确认/批量确认/采纳推荐）
- **Test**: `pipeline/pipeline_constraints_test.go`、`apiconstraints_test.go`、`server/tests/stage8_api_security_test.go:682-843`（DB→GuardConfig 层）
- **Known Gap**: 确认不触发发布；下发通道为 confirmed_constraints map 原样透传（`ListFormalParameterConstraints` → `guardconfig/provider.go:368-388`），server 端 `GuardParamConstraint` 注释仍写「钉死 5 词汇」为过时注释（实际已透传 regex/nullable/empty_allowed）；无 e2e 约束阻断用例。

### P0-05 ResponseContext

- **Status**: IMPLEMENTED_AND_CLOSED_LOOP（2026-08-16 起）
- **Code Path**: `context/context.go:108` `ResponseContext`（status/headers[脱敏]/content_type/body_size/body_hash/truncated/streamed/is_json/parsed_body[字段路径→类型]/sensitive_fields/error_signatures/transform_plan，不落响应明文体）；响应相位 `pipeline/response.go:67` `ProcessResponse`（JSON 解析→响应敏感字段检测→错误签名→transform plan→响应偏离检测→响应方向字段权限判定）；API 放行流量事件改为**下游响应完成后输出**（真实 response_status + latency_ms + 响应侧明细随同一主事件）；捕获上限 `api_response_capture_max_bytes`（默认 1MiB，硬上限 16MiB），流式/SSE/非 identity 编码直通不缓冲
- **Database**: 事件侧 `api_runtime_events` 六审计列（迁移 000035：client_ip/method/raw_path/latency_ms/model_version/policy_version）、response_status（000030）
- **Frontend**: 运行时事件列表/详情携带审计列；**Test**: `pipeline/response_test.go` 等
- **Known Gap**: §4.4 的 runtime_findings 由统一明细列表承载（响应相位 DetectorMatch 随主事件输出），非 ResponseContext 内嵌字段；响应 Schema 学习（P0-06）已闭环（第五波，见 P0-06 正文）。

### P0-06 Response Schema

- **Status**: IMPLEMENTED_PARTIAL（2026-08-18 第五波起学习链路闭环：生产→存储→查询→Confirm 快照→测试齐全；2026-08-19 第九波补齐运行时消费——响应偏离检测下发与执行；接口详情观测面板已接入；残余为 §48 全字段与独立聚合视图）
- **Code Path**: 网关观测 `gateway/dynamic_security/response/observe.go:29` `BuildObservation`（一级字段路径→类型 + status_code/content_type/body_size/truncated，只含路径与类型标签不落值）→ 响应相位装配（`pipeline/response.go:81`，仅完整捕获的合法 JSON 族响应，截断/流式不观测）→ `apiprotect.go:463` 挂主事件 → 事件契约 `apievents/apievents.go:57-60`（`response_observations`，omitempty 无观测零变化）→ 采集器 `apiruntime/collector.go:400-402` → 入库 `apiruntime/respschema.go:78` `RecordResponseObservations`（API×状态码合并 UPSERT 运行时学习行：字段并集、同路径类型冲突首次优先、truncated 任一为真即真、sample_count 累计；无状态码或无字段的观测跳过）；只读查询 `apimodels/response_schemas.go:94`（`GET /api/v1/api-security/endpoints/{id}/response-schemas`，api_model.read，按状态码升序）；Confirm 快照 `response_schemas.go:125` `snapshotResponseSchemas`（Confirm 事务内按版本物化快照行，model_version_id 关联版本；快照不参与运行时合并）
- **Database**: `api_response_schemas`（000018:180 建表；**000051 运行时学习列补齐**：model_version_id DROP NOT NULL + endpoint_key/first_seen/last_seen/sample_count/updated_at + 运行时行部分唯一索引 `(endpoint_key, status_code) WHERE model_version_id IS NULL`）；`api_model_versions.response_schema_set_id` 仍恒 NULL（快照经 model_version_id 可溯，response_schema_set 集合概念未建）
- **Runtime Producer**: 网关响应相位 + 采集器 UPSERT；**Runtime Consumer**: 管理面只读查询 + 模型确认版本快照；**运行时偏离检测（第九波）**：`api_response_schemas` 学习行（sample_count≥20）经发布通道 `api_response_baselines` 下发（`guardconfig/response_baselines.go`，纳入版本戳），网关响应相位 `detectors/respdeviation.go:50` `CheckResponseDeviation` 比对一级字段——基线外新字段 `response.schema_new_field`（OBSERVE/MEDIUM）、基线字段缺失 `response.schema_missing_field`（OBSERVE/LOW）、未知状态码 `response.schema_new_status`（INFO）；证据不落值；无基线零行为
- **Frontend**: 接口详情抽屉新增 `ResponseSchemaPanel`（`web/src/pages/api-endpoints/ResponseSchemaPanel.tsx`），真实查询运行时学习行，按状态码展示样本、最近观测、结构哈希与截断标记，可展开字段路径和类型；`api_model.read` 权限门控，无权限不查询
- **Test**: 网关 `apiobserve_test.go`（观测发出/非 JSON 不产生观测）、`apievents_test.go`（契约形态与 omitempty）；服务端 `apiruntime/respschema_test.go`、`apimodels/response_schemas_test.go`
- **Known Gap**: ~~响应偏离检测（对照学习基线判异）未做~~ **已落地（第九波，见上）**；§48 响应模型字段仅 field_schema/content_type 子集有数据源（status_distribution/sensitive/error_signatures 维度无）；前端仅接口详情观测面板，无独立跨接口聚合页面；`api_request_schemas` 仍零引用（请求 schema 走 model_versions.schema_json 内联）。

### P0-07 MASK_RESPONSE

- **Status**: IMPLEMENTED_PARTIAL（2026-08-16 起真实可执行；算法与覆盖面有缺口）
- **Code Path**: 决策引擎 MASK_RESPONSE 分支（`decision/engine.go:91`，transform plan 非空且 PROTECT 模式）；Response Transformer 执行字段级脱敏（`FieldTransform`：MASK 前 3 后 4 保留可配 / HASH / REMOVE，`context/context.go:70-76`）、重编码与 Content-Length 修正、ETag/Content-MD5 失效；脱敏规则经发布通道下发（`api_mask_rules`，`guardconfig/apiruntime.go`，规则源 `api_masking_rules` 表 GLOBAL<APPLICATION<ENDPOINT 优先级合并）；失败策略 `api_response_fail_policy`（FAIL_OPEN 默认 / FAIL_CLOSED 抑制为 500 空明细）
- **Database**: `api_masking_rules`（迁移 000040）；**Frontend**: 敏感数据/脱敏规则管理面（第二波 F3 前已随 000040 批接通）
- **Test**: `pipeline/response_test.go`、`decision/engine_test.go`（MASK_RESPONSE 断言）
- **Known Gap**: ENCRYPT/MAP 已实现并支持授权恢复（000213），gzip/br 有界解压与重编码、XML/text/SSE 值级检测已接入；仍不支持多重编码/deflate、压缩 SSE、表单/二进制脱敏和流式中途脱敏。请求侧日志/审计脱敏仍为固定内置规则（非在线策略）。

### P0-08 Coraza/API 统一 Finding

- **Status**: IMPLEMENTED_PARTIAL（2026-08-18 起，第三波 G2 落地：**下游哨兵归因形态**——不 fork coraza-caddy 的折中；统一事件源枚举与规则明细入上下文仍缺）
- **Code Path**: 执行顺序 guard 先于 coraza（`gatewayconfig/headers.go:253-278`，buildChainHandles 内 guard 处理器先于 waf 入链）；合流实现 `gateway/modules/jiuzhang_guard/apicoraza.go`：`corazaInterruption` 以下游返回错误中 coraza-caddy v2.5.0 未导出哨兵错误（"interruption triggered"，包装为 `caddyhttp.HandlerError{StatusCode: 中断码, ID: Coraza 事务 ID}`）识别阻断；`attributeWAFIntercept` 在统一管线未判阻断（非 BLOCK/RATE_LIMIT/TEMP_BLOCK）而下游中断时补记 `detector="waf"` 明细（rule_id `waf.downstream_intercept`，BLOCK/HIGH，Confidence 0.9，证据 `attribution=downstream_intercept`/`coraza_tx_id`/`status_code`/`uncertainty=message_matched_no_rule_detail`），事件 `final_action` 按实记 BLOCK、`response_status` 取中断码（事实记录而非引擎决策，OBSERVE 模式同样按实记录）；挂接点 `apiprotect.go:136-142`（finishAPIResponse 下游错误路径）；管线外部明细入口 `pipeline.Process(r, cfg, nil)` 第三参 externalMatches **仍恒为 nil**（`apiprotect.go:329`，合流走下游错误归因而非管线注入）；事后关联链不变：`securityevents/normalize.go:159` 从审计日志提取 x-request-id → `security_events`（event_source='coraza'）
- **Database**: 三表分立 `security_events` / `access_control_events` / `api_runtime_events`（不变）；Coraza 阻断的 API 流量事件自此 `final_action=BLOCK` 且 details 含 waf 归因明细，经采集器物化进 `api_runtime_findings`
- **Test**: `apicoraza_test.go`（哨兵识别矩阵：裸消息串/非 HandlerError/502 均不误判；归因矩阵：管线已判阻断不重复归因、非 Coraza 错误不归因、nil 上下文安全；集成用例 `TestServeNext_CorazaDownstreamIntercept`：ALLOW + 下游 403 中断 → 事件 final_action=BLOCK、response_status=403、details 含 waf 明细）
- **Known Gap（局限如实声明，见 apicoraza.go:19-23）**: ①归因依赖未导出哨兵消息串，与 coraza-caddy v2.5.0 耦合，升级 CORAZA_CADDY_VERSION 必须复核；②无法取得命中规则明细（规则 ID/分值仍在 Coraza 审计日志，经 request_id 事后关联不变）；③phase 3（响应头相位）中断不归因——无错误返回，特征与源站自返 403 不可区分；④非 API 流量事件维持响应前输出（G1 语义），事后 Coraza 阻断不回填该事件；⑤统一事件源枚举（§167）仍不存在；⑥guard 传统检查（黑白名单/ACL/L7/CC）与 Coraza 仍是引擎外决策点（见 P0-09）。

### P0-09 唯一 Decision Engine

- **Status**: IMPLEMENTED_PARTIAL（统一管线内部唯一；全网关视角三决策点并存）
- **Code Path**: `decision/engine.go:28` `Decide(ctx, Input{Mode})`；`SetFinalAction` 生产调用方仅 engine.go:37,97
- **决策逻辑**: 逐条匹配类别优先级 TEMP_BLOCK > RATE_LIMIT > BLOCK（仅 PROTECT）> OBSERVE > ALLOW；硬阻断资格硬编码 detector 白名单（engine.go:57-71）；聚合 RiskScore/RiskLevel（context.go:221-233）**仅用于展示，不参与定案**——即异常计分未实现为决策依据
- **动作可执行性**: ALLOW/OBSERVE/BLOCK/RATE_LIMIT ✅；TEMP_BLOCK 枚举存在但无产生者（不可达）；MASK_RESPONSE ✅（第一波起真实执行，见 P0-07）；CHALLENGE/LOG_ONLY 未定义
- **Known Gap**: ①guard 传统检查（module.go:651-706 封禁/ACL/L7/CC 直接 return）与下游 Coraza 是引擎外两个独立决策点（Coraza 阻断事实已归因入上下文，见 P0-08）；②Finding 结构 `DetectorMatch`（context.go:99-113）已有 confidence/model_version/policy_version 快照字段，仍缺 finding_type/recommended_action/hard_block_eligible；③决策输入无 Policy/Exceptions/RuntimeModel；④~~`api_runtime_findings` 表 TABLE_ONLY~~ 已有生产方（见 P0-13）。

### P0-10 API 资产详情与生命周期

- **Status**: IMPLEMENTED_PARTIAL（API级主干闭环；第三波补齐价值评分/服务资产/生命周期 HTTP 入口；应用/文件资产仍有缺口）
- **Code Path**: 发现 upsert `apiassets/store.go:231-254`（采集器 `collector.go:391-398`）；生命周期操作 confirm/merge/split/ignore（`handler.go:294-437`，事务+别名归档+生命周期事件+审计）；归一化 `gateway/dynamic_security/normalizer/path.go:17-56`（{id}/{uuid}/{hex} 三种段型）；**第三波新增**：deprecate/restore HTTP 入口（`handler.go:46-47`，api_asset.edit + 操作审计；restore 仅 DEPRECATED/ZOMBIE→CONFIRMED，清 zombie_since）；资产价值评分 `apiassets/value.go`（`ScoreAssetValue` 纯函数九维：业务/数据敏感度、互联网暴露、权限、写/管理/交易能力、依赖度、流量规模 → LOW/MEDIUM/HIGH/CRITICAL + 各维得分与中文理由落 `asset_value_explain`；`RefreshAssetValues` 周期回填，随资产生命周期 Sweeper 5 分钟一轮，`cmd/api/main.go:186` 装配）；服务资产聚合视图 `apiassets/service_assets.go`（upstream host:port 粒度：应用数/API数/近 7 天流量/涉敏API数/未闭环风险数），`GET /api/v1/api-security/service-assets`（api_asset.read）
- **Database**: `api_endpoints`（000016/000018/000020；000045 + asset_value/asset_value_explain/zombie_since）、`api_endpoint_aliases`、`api_lifecycle_events`、`api_endpoint_traffic_buckets`（000034）；应用复用阶段3 `applications`/`application_domains`（000004）
- **Runtime Producer**: 流量自动发现；**Runtime Consumer**: 基线下发 `ListKeyStatus`（store.go:399-414）→ lifecycle detector
- **Frontend**: api-endpoints 页（过滤/确认/忽略）；**合并/拆分无 UI（API_ONLY）**
- **Test**: `handler_stage8_test.go`、`store_stage8_test.go`、`handler_lifecycle_test.go`、`normalize_test.go`、`value_test.go`、`lifecycle_test.go`
- **Known Gap**: ①资产唯一键实际只有 method+normalized_path（跨域名/应用同键合并，归属首写胜出；~~protocol_type 恒 REST~~ **已补全（协议识别波）**：REST/GRPC/GRAPHQL/SOAP/WEBSOCKET 五值打标，GraphQL 不按 operation 拆API为遗留）；②应用资产无来源枚举/确认/合并/拆分；应用级评分聚合接口 `GET /api-security/applications/{id}/asset-value` 已落地，聚合既有接口评分并披露未评分覆盖，前端 `ApplicationAssetValueCard` 已接入应用详情，真实 PostgreSQL 验证与登录态浏览器验收待完成；③文件资产已有真实观测、台账与同内容关联，完整文件生命周期与因果溯源仍未实现；④`api_endpoint_path_segments` TABLE_ONLY；⑤~~非 API 路径也入资产表（发现不过滤 is_api）~~ **已修复（2026-11-23）**：分类器补齐静态资源后缀/MIME 过滤与在线网关轻量响应头二次定级，网关/镜像/Agent/Kafka 四条发现入口统一接入可配置 `api_discovery:filter_rules` 过滤闸门，列表/统计/配额统一按 `is_api=TRUE` 对齐，并提供存量静态/非 API 噪声预览与安全清理接口；⑥~~DEPRECATED 状态无 HTTP 入口~~ **已闭环（第三波 deprecate/restore）**；⑦资产状态（DISCOVERED/CONFIRMED/IGNORED/DEPRECATED/ZOMBIE）/学习状态/模型状态三层分离真实落地 ✅。

### P0-11 Shadow / Zombie

- **Status**: Shadow IMPLEMENTED_PARTIAL（信号→事件→Finding 链已接通）；Zombie IMPLEMENTED_PARTIAL（第三波判定落地：DEPRECATED 持续被调 → ZOMBIE 状态机与周期作业；下线计划/阻断/验证全流程未做）
- **Code Path**: Shadow 侧不变——`detectors/lifecycle.go:14-47`（未知键→`lifecycle.new_endpoint` OBSERVE；DEPRECATED 被调→`lifecycle.deprecated_api_call`）；基线下发链完整（store.go:399 → provider.go:376 → guard.go:141 → module.go:143 → apiprotect.go:113）；Finding 物化（000036）：`lifecycle.new_endpoint`→SHADOW、`lifecycle.deprecated_api_call`→DEPRECATED 语义映射（`apiruntime/findings.go:83-108`）。**Zombie 侧（第三波，迁移 000045）**：`apiassets/lifecycle.go` Sweeper `SweepOnce`（:170）——DEPRECATED API近 N 天（`DefaultZombieWindowDays`）仍有流量（`api_endpoint_traffic_buckets`）→ 条件迁移 ZOMBIE（zombie_since 落时 + 生命周期事件 actor=system，事务）；ZOMBIE 连续无流量仅保持观察，**不自动归档（归档须人工）**；`restore` 人工恢复（DEPRECATED/ZOMBIE→CONFIRMED，清 zombie_since + 生命周期事件）；与弱点/敏感/权属 Sweep 同 5 分钟周期装配（`cmd/api/main.go:186`）
- **Database**: 信号落 `api_runtime_events.details_json`；`api_runtime_findings` 已有真实生产写入方（采集器 dedup upsert，见 P0-13）；`api_endpoints.zombie_since` + asset_status 词表纳入 ZOMBIE（000045，注释口径无 CHECK，状态机由代码保证）
- **Frontend**: `ApiShadowZombiePage.tsx` 读 findings——自此有真实数据源
- **Test**: `detectors/lifecycle_test.go`（4 用例）；`apiassets/lifecycle_test.go`（Zombie 判定/恢复/状态机矩阵）
- **Known Gap**: §11 判定条件仅"不在已知基线"一项；shadow_reason/source_count/public_exposure 等字段无；§12 Zombie 全流程残余：下线计划/阻断执行/验证环节无代码（当前仅"判定+标记+人工恢复"）；Shadow 侧无 last_seen 老化判定作业。

### P0-12 Spec / Observed / Confirmed Diff

- **Status**: IMPLEMENTED_PARTIAL（第三波大幅扩充：URL 导入/SSRF 防护/Swagger2 转换/版本状态机/CHANGED diff/回写资产均已落地；YAML/Postman/GraphQL 与三方视图仍缺）
- **Code Path**: 解析 `apisecurity/spec_version.go:104` `ParseSpecDocument`（OpenAPI 3.x JSON + Swagger 2.0 经 `ConvertSwagger2ToOpenAPI3` 最小映射转换，spec_version.go:130；YAML 仍 400 拒绝——go.mod 无 yaml 依赖）；键集 diff `spec.go:81`（MISSING_IN_RUNTIME/MISSING_IN_SPEC 双向）+ 跨版本 CHANGED 级对比 `spec_version.go:515` `DiffSpecOperations`（同 path+method 的参数增删/类型变化/required 变化，`spec.go:31` DiffChanged）；粘贴导入 `handler.go:251`（16MiB 上限）与 URL 导入 `POST /api/v1/api-security/specs/import-url`（`handler.go:289` 起；SSRF 防护 `spec_version.go:750` `fetchSpecDocument`：仅 http/https、拒绝内网/保留地址，抓取函数可注入 `SetSpecFetcher` 供单测）；共享流水线 `importSpecCore`（handler.go:342：格式识别→解析→键集对比+同名跨版本 CHANGED→版本化落库→**回写资产**——仅登记运行时缺失的规范API MISSING_IN_RUNTIME 进 api_endpoints，冲突不动已有资产→操作审计）；版本激活 `POST specs/{id}/activate`（同名旧 ACTIVE 降 HISTORICAL + 审计）；任意两版本只读对比 `GET specs/{id}/version-diff`（不落库）
- **Database**: `api_import_specs` / `api_spec_diffs`（000018:362-382）；**版本状态机列（000046）**：name/version_no/status（DRAFT/ACTIVE/HISTORICAL/INVALID/ARCHIVED，CHECK 约束）/parent_id/activated_at；存量回填（file_name→info.title→unnamed-hash8；同名按导入先后编版本号、仅最新 ACTIVE）；唯一索引 (name,version_no) + 单 ACTIVE 部分唯一索引；`api_spec.manage` 权限点（仅 SECURITY_ADMIN）；**来源列（000072）**：`api_import_specs.source`（UPLOAD/URL/SOURCE_CODE 词表），源码发现产物经同一导入流水线落库并标记 SOURCE_CODE（见 P2-07）
- **Frontend**: `ApiSpecsPage.tsx`（粘贴导入/列表/diff 抽屉；版本列/激活/URL 导入/版本对比随前端分片接通）
- **Test**: `apisecurity/spec_test.go`、`spec_version_test.go`（解析矩阵/Swagger2 转换/CHANGED 对比/SSRF 拦截矩阵——本地 httptest 服务亦须拒绝/规范名解析）
- **Known Gap**: YAML/Postman/GraphQL 导入仍缺；无 Spec/Observed/Confirmed 三方视图（参数三层与规范零交集）；导入不产生 Finding；§64 违规审计词表（UNKNOWN_ROUTE/UNKNOWN_METHOD/…）在代码中不存在，实际能力等价其参数子集（required/type/length/range/enum/regex/nullable/empty_allowed + BODY 字段三类）且只落 `api_schema_violations`（detector=api_schema 过滤，`violations.go:22,45`）；~~violations 无前端页面~~ **已解除（前端 api-violations 页已注册路由）**。

### P0-13 Risk / Weakness 分离

- **Status**: IMPLEMENTED_PARTIAL（2026-08-16/17 两波落地：双中心建成、禁止项 #19 形态已解除；降噪与告警联动有缺口）
- **Code Path**: Risk 侧——生产方 `apiruntime/findings.go`（采集器物化规则 v1：severity≥MEDIUM 或 final_action 非 ALLOW；`dedup_fingerprint` 幂等 upsert，命中 count+1 不覆盖首次证据；证据白名单脱敏，主体只落指纹）；七态状态机（迁移 000042：NEW/CONFIRMED/IN_PROGRESS/FALSE_POSITIVE/IGNORED/RESOLVED/ARCHIVED，存量 OPEN→NEW、ACKNOWLEDGED→IN_PROGRESS，CHECK 约束）；处置八接口 `apisecurity/risk_handler.go`（summary/detail/confirm/start/resolve/false-positive/ignore/archive，行锁事务 + 迁移表校验 + `detail.handling` 合并 + 操作审计）；降噪聚合主体/API/类型三视图。Weakness 侧——`apiweakness` 包（迁移 000039 两表）：Sweeper 四规则派生（未认证敏感接口/已下线仍调用/敏感数据在查询串/Schema 漂移持续，5 分钟周期）、生命周期 NEW→CONFIRMED→TO_FIX→FIXED→（RETEST_PASS→ARCHIVED / RETEST_FAIL→REPRODUCED）+ IGNORE/ARCHIVE、FIXED 再命中自动 REPRODUCED、`api_weakness_actions` 只增不改（retest_history 载体）、处置八接口 + `api_weakness` 权限（000041）
- **Frontend**: ApiFindingsPage / ApiShadowZombiePage 有真实数据；findings 行内确认/解决/误报与 weaknesses 处置操作界面随第二波前端分片接通（含页面单测）
- **Known Gap**: 物化规则 v1 无例外/抑制配置（误报降噪靠 FALSE_POSITIVE/IGNORED 处置而非自动规则）；关联请求为"同API（同身份）近期请求"近似关联（dedup 只留首次 request_id，非精确回放）；~~`apiweakness/sweep.go` 仍按旧词表取数~~ **已收口（第三波：sweep.go:269 按七态词表 NEW/CONFIRMED/IN_PROGRESS 取数，测试种子同步）**；告警侧：~~`systemalerts` 与 API 安全域零接线~~ **已接线（第六波 W6-B）**：API_CRITICAL_FINDING/API_FINDING_SPIKE/API_MASK_FAILURE 三类型周期评估 api_runtime_findings + silenced_until 静默/恢复（见 P1-08）；通知渠道仍为 syslog 外发，无邮件/Webhook 扩展。

### P0-14 Identity Baseline

- **Status**: IMPLEMENTED_PARTIAL（指纹+画像链路闭环；任务书 §68 字段覆盖窄）
- **Code Path**: 指纹 `detectors/fingerprint.go:17-25`（HMAC-SHA256 截断，盐 `identity_salt`，缺盐降级+Warn）；CredentialKey/TrackingKey 分离（`authentication.go:283-317`）；画像生产线 `aggregations/identity.go:16-88`（小时级）+ 质量分 :283-307 + 详情/风险评估 :139-255
- **Database**: `api_identity_profiles`（000018:229-238，仅 fingerprint/endpoint/auth_type/request_count/first_last_seen）；事件身份列（000029）
- **Frontend**: ApiIdentityProfilesPage（+测试）
- **Test**: `stage8_identity_profiles_test.go`、`identity_test.go`、`stage8_runtime_event_identity_test.go`
- **Known Gap**: §68 的 roles/devices/ips/apis/objects/normal_time_ranges/normal_request_rate/risk_score 无持久化字段；认证识别约 1/3（bearer/basic/digest/api_key/cookie 存在性 + JWT 结构信号；OAuth/OIDC/HMAC/mTLS/自定义头未识别）；§67 身份检测中 Token 跨应用、已吊销凭据继续使用未实现；sess 指纹对整个 Cookie 头哈希（会话轮换即换身份）；凭据仅存指纹原则执行到位 ✅（未发现完整 Token/Password 落库）。

### P0-15 BOLA Baseline

- **Status**: IMPLEMENTED_PARTIAL（第三波实体层落地：Ownership 表 + 权属 Sweep 写入方 + 五档评估接口；**运行时消费在途**——网关检测侧仍是辅助信号，未消费权属基线）
- **Code Path**: 检测侧不变——对象标识 `detectors/resource.go:56-117`（路径段 {id}/{uuid}/{hex}、Query 形态、BODY semantic_type 联动）；检测 `resource.go:184-247`（无凭据+对象标识→OBSERVE；连续数字 ID+写方法→BLOCK，进程内 LRU 游标，可注入 Valkey）。**实体层（迁移 000043）**：`api_object_ownership`（API×身份指纹×对象类型×对象标识，first/last_seen/access_count）；写入方 `apiauthz/sweep.go:90` `SweepOnce`——扫 `api_runtime_events`（identity_fingerprint 非空），按API normalized_path 模板匹配 raw_path 提取路径占位符段值后 upsert（access_count++/last_seen 前移，HasMore 排空，5 分钟周期装配 `cmd/api/main.go:185-186`）；**五档评估** `apiauthz/evaluate.go:66` `decideVerdict`（POLICY_CONFIRMED 权属匹配→允许 / HIGH_CONFIDENCE 对象有属主但访问者非属主→越权 / LIKELY 身份有权属基线→倾向允许 / POSSIBLE 仅画像信号 / INSUFFICIENT_EVIDENCE——证据而非定罪），`GET /api/v1/api-security/authz/evaluate` + 权属查询接口（`apiauthz/handler.go:53/67`）
- **Database**: `api_object_ownership`（000043，有 Sweep 写入方）；`api_object_models`（000018:241-251）**仍零写入方**（maturity.go:71-72 自认）——对象模型画像与权属基线是两件事，前者未补
- **Test**: `resource_test.go`；`apiauthz/evaluate_test.go`（五档结论矩阵）、`sweep_test.go`（模板提取/upsert/水位）
- **Known Gap**: 运行时消费在途：权属基线不下发网关，resource 检测器不查权属（BOLA 阻断仍仅靠"连续数字 ID+写方法"启发式）；对象候选来源缺响应字段/前后 API 关系/人工标注；权属只覆盖路径占位符对象（Query/BODY 对象标识未入权属）；Tenant 维度无任何表。

### P0-16 BFLA Baseline

- **Status**: IMPLEMENTED_PARTIAL（实体层 + 运行时检测已贯通：基线下发网关、authzcheck 消费；OBSERVE 级为主、角色提取未验签、来源仅人工）
- **Code Path**: `api_role_baselines`（迁移 000043：API×角色×方法×动作 allowed 基线，source MANUAL/SPEC/OBSERVED/IMPORTED，confidence 0..1，confirmed=FALSE 候选→人工确认置 TRUE + 操作审计）；`apiauthz` 包 6 条角色基线接口（CRUD + confirm，`apiauthz/handler.go:40-51`，权限 `api_authorization.read/manage`，迁移 000048）；**运行时消费（第四波 W4-GW）**：`guardconfig/authz_rules.go` 读取 confirmed 行（关联 api_endpoints 解析 endpoint_key，失败 Warn 跳过）→ `api_role_baselines` 随整站发布下发（`guard.go:211-214`）并纳入 api_policy_version 哈希；网关 `module.go:469-473` 校验归组（ValidateAuthzRules/GroupRoleBaselines）→ `apiprotect.go:321` 装配 → `pipeline.go:230` → `detectors/authzcheck.go:163` `CheckRoleBaseline`：API有 confirmed 基线时，匿名访问 → `authz.bfla_anonymous`（OBSERVE/HIGH/+30）、请求角色无匹配 allowed 基线 → `authz.bfla_role_mismatch`（OBSERVE/MEDIUM/+15）；无API基线零行为（基线缺失不判）
- **Database**: `api_role_baselines`（000043，写入方为管理面 CRUD；OBSERVED/SPEC 来源枚举已预留，自动学习写入方未实现）
- **Known Gap**: BFLA 检测为 OBSERVE 级（不定案阻断）；角色提取自**未验签** JWT claims 的 role/roles 自定义 claim（与 JWT 结构级解析同一纪律：仅观察信号，不作信任决策；无 JWT 角色声明的凭据形态无角色可判）；action 随契约透传但不参与匹配（网关无法观测业务动作）；PURPOSE=ADMIN 分类标签未下发未接检测；基线来源仅人工登记（OBSERVED 自动学习、SPEC 导入联动未接线）。

### P0-17 Field Authorization（字段权限 / Mass Assignment）

- **Status**: IMPLEMENTED_PARTIAL（实体层 + 运行时检测已贯通：字段权限下发网关、Mass Assignment 专项检测落地；第十一波补齐 RESPONSE 方向运行时判定；tenant 覆盖行仍不判定）
- **Code Path**: `api_field_permissions`（迁移 000044：API×字段路径×direction（REQUEST 防 Mass Assignment / RESPONSE 防越权读取）×七属性 READABLE/WRITABLE/READ_ONLY/ADMIN_WRITABLE/SERVER_GENERATED/SENSITIVE/FORBIDDEN；role/tenant 可空覆盖行，NULL 归一唯一索引）；`apiauthz` 包 5 条字段权限接口（CRUD，`apiauthz/handler.go:56-65`）；**运行时消费（第四波 W4-GW）**：`guardconfig/authz_rules.go` 读取全行 → `api_field_permissions` 随整站发布下发（`guard.go:215-217`）并纳入 api_policy_version 哈希；网关 `pipeline.go:233` → `detectors/authzcheck.go:204` `CheckFieldPermissions`：请求 JSON BODY 字段命中 FORBIDDEN → `authz.forbidden_field`（**BLOCK 类/HIGH/+40**，PROTECT 可定案阻断）；SERVER_GENERATED → `authz.server_generated_write`（OBSERVE）；READ_ONLY / ADMIN_WRITABLE 指定角色外写入 → `authz.readonly_write`（OBSERVE）；单请求上限 20 条；角色覆盖行适用性已实现（默认行对全部角色、角色行仅行内角色；优先级 FORBIDDEN > SERVER_GENERATED > READ_ONLY > ADMIN_WRITABLE）；**RESPONSE 方向运行时判定（第十一波）**：响应相位 `detectors/authzcheck.go:362` `CheckResponseFieldPermissions`——FORBIDDEN 命中产 `authz.response_forbidden_field`（OBSERVE/MEDIUM，响应侧不定案阻断）、SENSITIVE 命中产 `authz.response_sensitive_field`（OBSERVE/LOW）；已被 REMOVE/MASK 治理的字段不重复判定（HASH 不去重）、与敏感检测器去重；role 覆盖行按未验签请求角色判定（仅观察信号）
- **Database**: `api_field_permissions`（000044，写入方为管理面 CRUD）
- **Known Gap**: 运行时请求侧仅判定 field_path 为 `json.` 前缀的行；tenant 覆盖行随契约透传但运行时跳过（无租户上下文可比对，跳过而非放行语义，REQUEST/RESPONSE 两侧同）；QUERY/HEADER/PATH 位置字段权限不判定；READABLE/WRITABLE 允许语义请求侧不产生信号。

### P0-18 Distributed Behavior State

- **Status**: IMPLEMENTED_PARTIAL（Valkey 已支持对象枚举共享窗口；默认 memory 仍为单节点，时段/UA 等部分状态尚未抽象）
- **Code Path**: 可插拔接口 `detectors/store.go`（WindowStore/ObjectCursorStore/ObjectEnumerationStore/IPSpreadStore/ConcurrencyStore 等，按请求绑定 StoreOverrides）；内存实现 `window.go` 与 `object_enumeration.go` 等；Valkey 实现 `behaviorstore/behaviorstore.go` 与 `behaviorstore/object_enumeration.go`（Lua 原子脚本、sha256 键纪律、TTL 下限、三层 Fail-open）；装配 `apiprotect.go` `buildBehaviorStores`（`behavior_store` 配置，**默认 memory**）
- **对照任务书六操作**: Increment/WindowCount/GetWindow 融合于 `AddAndCount`；DistinctCount=`AddDistinct`；对象序列通过 `ObserveObject` 统计；Expire 为内部职责非接口方法
- **Test**: `behaviorstore_test.go`（含故障注入）、`object_enumeration_test.go`、`object_enumeration_integration_test.go`（真实 Valkey 与 API 管线）、`store_test.go`、`behavior_test.go`
- **Known Gap**: ①~~发布通道不下发 behavior_store/identity_salt/阈值~~ **已闭环（第一波）**：`gateway_runtime` 组六键（behavior_store/identity_salt/behavior_store_ttl_seconds/credential_ip_spread_limit/credential_concurrency_limit/api_write_rate_per_minute）随整站发布下发（`guardconfig/apiruntime.go`），非法取值中止发布；默认仍 memory，管理面可打开；②hourHist（时段基线）与 UA 族基线两追踪器未抽象进 StoreOverrides，配了 valkey 仍单节点；③§123 A60+B60>100 场景默认配置下检测不到；④对象枚举已有真实 Valkey 集成测试（跨 Store、64 并发与真实 API 管线），仍不替代正式多主机故障与容量验收；⑤离线画像（api_behavior_profiles，学 request_rate/time_pattern/status_code_dist 三项）不回灌网关；⑥流程基线七类观察信号、强流程违规和对象枚举检测已落地，并派生 `FLOW_SEQUENCE_DEVIATION` / `FLOW_REPLAY_OR_BURST` / `OBJECT_ENUMERATION_RISK` 弱点；离线 api_sequence 画像、单次对象数量/数据量/geo/token_pattern 仍未实现，`api_call_edges` TABLE_ONLY；⑦降级状态仅 zap 日志无指标/事件上报；⑧故障降级（Fail-open、不 Fail Close）实现到位 ✅。

### P0-19 请求/响应敏感数据

- **Status**: IMPLEMENTED_PARTIAL（管理面分类分级与响应侧检测已落地；第三波补齐值级检测下发与执行（请求侧）；位置覆盖仍有缺口）
- **Code Path**: 请求侧 `detectors/sensitive.go:140` `CheckSensitiveData`（QUERY 键名命中→BLOCK/HIGH；JSON/FORM/XML 字段名→OBSERVE；**第三波追加第四参值级规则**：`scanValueLevel`（sensitive.go:186）——QUERY 值命中升级 BLOCK（sensitive.value_in_query，与键名命中同一语义）、JSON/FORM 值 OBSERVE（sensitive.value，仅留存开关开启时有值可检）、HEADER/PATH 位置扩展（cookie 整头脱敏跳过、脱敏头仅存在性、PATH 字面段名匹配 + 原始段值级匹配，证据用段序号绝不落值）；预算：单值 4096 字符截断、单请求 512 次求值、规则 ≤256 条/正则 ≤512 字符，非法规则启动期拒绝加载不静默；无规则下发时零行为变化）；响应侧：响应相位敏感字段检测（`ResponseContext.SensitiveFields`，字段路径+类型标签，不落值）+ Response Transformer 字段级脱敏（见 P0-07）；管理面（迁移 000040）：`api_sensitive_data_types`（五级分级 + 7 内置类型种子，is_builtin 禁删；**regex 列带长度与可编译校验**，`apidata/types.go:87/182-185`）+ `api_masking_rules`（GLOBAL<APPLICATION<ENDPOINT 优先级合并与排除求值）+ `api_sensitive_fields` SweepOnce 写入方（水位幂等，detection_source=RUNTIME）+ 敏感态势 overview；脱敏规则经发布通道 `api_mask_rules` 下发网关；**值级规则下发（第三波）**：`guardconfig/sensitive_rules.go` 读取 status=ENABLED 且 regex 非空的类型 → `api_sensitive_value_rules`（`GuardSensitiveValueRule`：data_type/regex/locations/level，guard.go:94）随整站发布下发并纳入 `api_policy_version` 哈希（apiruntime.go:126-148）
- **Database**: `api_sensitive_fields`（000018）**已有生产写入方**；`api_sensitive_data_types` / `api_masking_rules`（000040）
- **Frontend**: ApiSensitiveFieldsPage 有真实数据；敏感数据类型/脱敏规则管理面（`api_data.read/manage` 权限，000041；前端 api-sensitive-types/api-masking-rules 页已注册路由）
- **Test**: `sensitive_test.go`、apidata 包测试、`guardconfig` 值级规则读取/哈希稳定性测试、网关 `detectors` 值级检测测试
- **Known Gap**: §95 位置覆盖仍有缺（COOKIE/FILE；PATH/HEADER 已随值级规则开启覆盖，响应侧 RESPONSE_BODY 覆盖 JSON 族字段名级）；值级检测仅请求侧（响应侧值级未做）；validator（Luhn/身份证校验位）未实现；无 Data Exposure Weakness（§97）；无数据出境（§98-99，GeoIP/ASN 未接入敏感数据流）；请求侧字段名词表仍硬编码、与管理面词表无同步（值级 regex 与脱敏规则已有下发机制）。

### P0-20 Audit Trace

- **Status**: IMPLEMENTED_PARTIAL（操作审计闭环；请求级审计列已补齐；API 域溯源仍有断点）
- **已闭环**: 管理面操作审计哈希链（`audits/audits.go:154-198`，DB RULE 禁改删 000001:143，verify-chain，脱敏 MaskSensitiveJSON，导出）；风险处置八接口已按同一纪律接入（risk_handler.go recordAudit，object_type=api_runtime_finding）
- **请求级审计**: `api_runtime_events`（request_id 幂等 ✅）+ 迁移 000035 六审计列（client_ip/method/raw_path/latency_ms/model_version/policy_version，可空、旧版网关缺字段落 NULL 不伪造 0 值）+ 000069 `gateway_node` 落列（节点遥测，见 P0-21）+ 第十四波事件 `proto`（HTTP/1.1/2/3）与 `protocol`（GRPC 标注）字段（omitempty，采集容忍缺失）；API 放行流量事件改为响应完成后输出（真实 response_status/latency/响应侧明细）；仍只落 notable 事件（纯 ALLOW 无明细不入表）；WAF 侧全量 access_logs（000023）与 API 域无关联键
- **溯源链（§213）断点**: ①~~Finding 无生产者~~ **已通**（采集器物化，request_id 关联首次命中）；②Event→Object 无对象维度列（仍在）；③Event→SensitiveData 仅非结构化证据摘要（仍在）；④~~Event→ModelVersion 间接可达~~ **已通**（model_version 列直答"命中时生效哪版模型"）；⑤~~Event→RuntimePolicy 无策略版本列~~ **已通**（policy_version 列 = 发布内容哈希）；⑥~~Coraza 阻断不归因~~ **已通**（第三波哨兵归因：事件 final_action=BLOCK + waf 明细携 coraza_tx_id，见 P0-08；规则明细仍经 request_id 关联审计日志）
- **Known Gap**: §86 主体审计仅 Identity 单维；§87 数据审计、§90 流向图、§91 离线审计任务均不存在；§89"二次认证查看原值"不存在（值本不落库，更保守）；纯 ALLOW 请求无记录、access_logs 与 API 域无关联键（全量溯源断点）。

### P0-21 Runtime 版本 / 回滚

- **Status**: IMPLEMENTED_PARTIAL（整站配置粒度 + API级策略版本已落地；第十二波补齐多节点版本遥测校验 v1，全量同步协议仍缺）
- **Code Path**: `gateway_config_versions`（version_number/configuration_hash/publish_result/is_current，`gatewayconfig/publish_store.go`）；发布 `Publisher.PublishSync`（`gatewayconfig/publisher.go:253`）→ Caddy Admin API **Unix Socket** `/load`（caddyclient.go，符合不落 TCP 红线）；发布前快照 + 失败自动回滚（publisher.go）；手动回滚限 SUCCESS 版本（`publisher.go:605`）；API级：`api_runtime_policies`（迁移 000037，DRAFT/VALIDATED/ACTIVE/ROLLED_BACK/FAILED 状态机 + 回滚接口克隆上一已知良好版本重发布，见 P0-03）；发布内容版本戳 `api_policy_version` 随发布下发并回事件（000035）；**多节点版本遥测校验 v1（第十二波，迁移 000069）**：`api_gateway_nodes` 表 + `apinodes` SweepOnce 从 `api_runtime_events` 按 `gateway_node` 增量聚合（最近事件/最新非空 policy_version/model_version/计数，绝对值覆盖幂等，`apinodes/store.go:74`）；状态判定 ACTIVE/STALE/SILENT（5min/1h 边界，`apinodes/consistency.go:13`）；版本一致性比对（非 SILENT 且已上报版本节点参与，SILENT 离线不参与防升级期误报；未上报单列不参与，`consistency.go:36`）→ 不一致产 CONFIG_HASH_MISMATCH 告警（恢复自动 AutoRecover，`apinodes/sweeper.go:64`）；`GET /api-security/nodes` 与 `/nodes/consistency` 只读接口（api_runtime.read，`apinodes/handler.go:30-33`）
- **Known Gap**: ~~无API级 Runtime Policy 版本~~ **已闭环**（见 P0-03）；~~Hash Verify 浅~~ **已闭环（第一波）**：verifyPublish 三步含规范化哈希比对（`publisher.go:561`，CanonicalConfigHash 与 GetConfigHash 不一致即视为未生效 → 自动回滚，VERIFY_FAILED_ROLLED_BACK）；~~§200-201 多节点校验为零~~ **已缓解（第十二波遥测校验 v1，见上）**；全量节点同步协议仍缺——节点注册/心跳/主动同步未实现，当前为事件遥测驱动的只读校验（如实声明：遥测路径而非同步协议）。

---

## 3. P1 能力盘点（补全任务书 §219，终态）

| 条目 | Status | 依据摘要 |
|---|---|---|
| P1-01 API 态势 | IMPLEMENTED_PARTIAL | `GetPosture`（`apisecurity/runtime.go:175`）聚合API/学习覆盖率/模型冻结率 + findings 活动状态计数；**第九波补齐**：`GET /posture/overview` 12 项核心指标（访问量/防护量/资产/新增/Shadow/Zombie/Deprecated/涉敏/高风险/无认证/待确认模型/24h Schema 偏离，全部真实 SQL）+ `GET /posture/trends?days=N` 六条按天趋势（UTC 日界补零）；**第十波补齐**：`GET /posture/sources`（client_ip Top 脱敏/Geo 分桶与国家 Top（复用 apigeo，缺失降级 geo_enabled=false）/身份指纹 Top 截断/auth_type 分布）+ `GET /posture/targets`（请求量/findings 双口径、应用、涉敏、高风险五榜单）；前端 ApiPosturePage（指标卡+ECharts 趋势+钻取）注册为 API 防护组首屏；大屏有 API 安全屏。残余：§6 的 Shadow 趋势与 UA 族维度（api_runtime_events 无 UA 列，如实不做） |
| P1-02 AI 资产运营 | IMPLEMENTED_PARTIAL | 15 个 api_* AI 工具全部 READ_ONLY 闭环（10 个 `aitools/api_tools.go` + 5 个 `aitools/api_ops_tools.go`：api_weakness.search/api_sensitive.search/api_runtime_policy.get/api_spec.get/api_posture.get，输入枚举白名单 + 证据脱敏 + SyncRegistry 同步 ai_tools 表）；**第七/八波 AI 定时运营落地（迁移 000062/000063）**：apiops 包自研五段 cron 解析器（零新依赖）+ next_run_at 游标 claim 先行防重入；五种内置任务（API_ASSET_DIGEST/SHADOW_REVIEW/WEAKNESS_FOLLOW/RISK_DIGEST/SENSITIVE_DIGEST）纯确定性查询+模板化中文摘要，**只产报告不做任何变更**；LLM 润色 Summarizer 小接口（nil/失败回退模板）；全局开关 `api_ai_ops.schedules_enabled` 默认关；`/api-security/ai-ops` 11 接口 + api_ai.read/execute 权限。残余：AI 工作流框架/连续失败熔断/ai_recommendations 流转未做；§146 的 16 工具清单中 api_spec.diff/api_audit.search/api_scan.get 仍因后端能力缺失而不存在 |
| P1-03 数据出境 | IMPLEMENTED_PARTIAL | **第七波落地（迁移 000058）**：apigeo 包自研纯 Go 只读 MMDB 解析器（零新依赖，复用已授权 country.mmdb）；出境判定五档（HOME/FOREIGN/INTERNAL/UNKNOWN/INVALID，内网/保留地址与未收录一律不记跨境，宁漏勿误）；SweepOnce 从涉敏事件增量判定落 `api_cross_border_events`（独立水位表 + (source_event_id,direction) 唯一约束双保险幂等；风险等级经 api_sensitive_data_types.level 动态推导）；`GET /api-security/cross-border` 看板（国家×敏感类型×API聚合+趋势+明细分页，geo_enabled 降级标识）；`api_data:home_regions`（默认 CN）进设置白名单；数据文件缺失 nil 降级。残余：无 ASN 维度（前端看板页已于第十五/十六波注册路由，见 §13/§14） |
| P1-04 敏感文件 | IMPLEMENTED_PARTIAL | **第七波落地（迁移 000061）**：网关 multipart 上传/Content-Disposition 下载文件观测（文件名 basename 归一化截断 128、扩展名/mime/大小/方向，不落内容；无 filename 的 octet-stream 不判定为下载，如实声明漏报口径）经 `file_observations` 事件字段上报；采集器 UPSERT `api_file_assets`（去重键 endpoint×方向×文件名×身份指纹，transfer_count 累计、IP 脱敏）；`GET /file-assets` 与 `/file-assets/stats`（§106 双口径统计与五个 TOP）；文件风险 v1：同身份 1h 批量下载超阈（`api_data:file_bulk_download_threshold` 默认 50）→ FILE_BULK_DOWNLOAD 风险发现（dedup upsert）；**WP2-M**：完整内容 `content_sha256` 指纹进入既有 `api_file_assets.sha256`，支持精确过滤，截断/流式为空且历史指纹不被抹除；stage5 实际上传/下载与真实 PostgreSQL 历史值保留验证通过；新增 `GET /file-assets/lineage` 按同一指纹关联实际上传/下载（只读、100 条上限与截断披露）；文件验证卡片在签名有效后展示同内容传输关联（`FileLineagePanel`），关联失败不改变签名结论；新增 `/api-file-assets` 文件资产台账，真实查询资产列表与统计，支持方向、扩展名、敏感标签及 SHA-256 精确筛选，并从资产行打开上传/下载关联抽屉，沿用 `api_data.read` 权限与 WDSP 能力门控。残余：观测覆盖仅带 filename 的 Content-Disposition 响应；登录态浏览器交互验收尚未进行 |
| P1-05 高级运营（拓扑/图谱） | IMPLEMENTED_PARTIAL | 边生产方已落地（第六波 W6-A）：`aggregations/call_edges.go:154` RunCallEdges 分钟级水位增量派生（同身份相邻调用 ≤10 分钟成边，匿名排除/未解析截断/自环不成边，水位与 upsert 同事务）；graph/topology 新增 start/end/min_count 边过滤 + 节点 open_findings_count；第十一波 `api_call_edges.identity_count`（近似下界）持久化（000067）；ApiGraphPage/ApiTopologyPage 有真实数据 |
| P1-06 API 报告 | IMPLEMENTED_PARTIAL | **第七波落地（迁移 000059）**：reports 包扩展四类型——API 资产周报（新增/确认率/Shadow/Zombie/Deprecated 计数与清单）/API 风险周报（findings 新增/关闭/类型分布/Top API与主体，七态口径对齐 000042）/弱点整改报告（状态分布/超期未修/复测记录）/敏感数据报告（类型分布/涉敏API Top/按天趋势）；全部真实 SQL 采集 + 确定性结论/建议模板 + HTML/PDF 渲染，复用既有报告管线（创建→生成→预览→下载→权限继承）；零新表（report_type 词表扩展）。既有通用调度器已支持每日/每周/每月计划与到期任务生成；**000199** 增加可选 `api_report_type`，使四类 API 专项报告可直接配置到原有计划，复用权限、审计、渲染和邮件链；专项类型仅允许 API 内容范围，普通计划空值行为不变。真实数据库回放与节点部署验收尚未进行 |
| P1-07 主动扫描 | IMPLEMENTED_PARTIAL | apiscan v1（第六波，000053/000054/000056）：目标/授权（双人分离/撤销即停/时间窗/限速并发）/任务/发现 17 接口 + 6 探针集 + X-JiuZhang-Scan 隔离签名头 + 样本脱敏 + 复测桥接弱点中心；settings api_scan.enabled 默认关；**第七/八波前端页交付**：ApiScanPage 四 Tab 注册路由；**第九波隔离链收尾**：网关识别签名头（`detectors/scanner.go`：signature_valid/signature_forged/presence_only 三态），学习样本排除规则由待命转为生效。残余：非 DAST（6 探针集词表 v1）；扫描发现不产生自动弱点（确认桥接为人工） |
| P1-08 告警静默 | IMPLEMENTED_PARTIAL | 第六波 W6-B（000055）：systemalerts 三新型 API_CRITICAL_FINDING/API_FINDING_SPIKE/API_MASK_FAILURE（评估器周期扫 api_runtime_findings，api_alert 设置组六键可调）+ silenced_until 静默/恢复接口 + 列表 view 三态视图（ACTIVE/SILENCED/HISTORY）；第十二波复用 CONFIG_HASH_MISMATCH 承载节点版本不一致告警（自动恢复）。残余：通知渠道以 syslog 外发为主（notification_channels 渠道体系为并行运维分片，000057/000060）；静默为实例级时长（无周期静默计划） |
| P1-09 调用拓扑 | IMPLEMENTED_PARTIAL | 同 P1-05（边生产者 RunCallEdges 落地，topology 按应用分组 + 边过滤 + identity_count） |
| P1-10 Security Graph | IMPLEMENTED_PARTIAL | 表已有写入方（同 P1-05），graph 只读查询增强（边窗口/次数过滤 + 节点未闭环风险计数） |

## 4. P2 能力盘点（补全任务书 §220，终态）

P0 全 21 项收口后，第十二~十四波按"最小可行子集"口径启动 P2：六项交付 v1，一项未实现。

| 条目 | Status | 交付形态与依据摘要 |
|---|---|---|
| P2-01 文件水印 | IMPLEMENTED_PARTIAL | **第十二波 v1**：文本族下载（text/plain/csv/markdown、application/json）不可见水印——文本尾注释行 / JSON 顶层 `_wm` 字段（{ip}/{identity}/{time}/{domain} 占位，`response/watermark.go`）；经 `gateway_runtime.api_file_watermark_*` 四键下发（`guardconfig/file_watermark.go`，默认关闭零行为）；仅 identity 编码完整捕获体改写并修正 Content-Length，206 分段跳过，失败恒 FAIL_OPEN；先 mask 后水印顺序固定；命中产 file.watermark_applied INFO 明细；**第十四波 OOXML 扩展**：docx/xlsx/pptx 经 Go 标准库 archive/zip（零新依赖）注入 docProps/custom.xml 自定义属性水印（`response/watermark_ooxml.go`，幂等锚点跳过、OPC 三处合规登记、32MiB 护栏、加密/损坏 FAIL_OPEN，三 MIME 需显式 opt-in）。残余：pdf 需媒体库显式拒绝（配置期报错不静默） |
| P2-02 文件签名 | IMPLEMENTED_PARTIAL | **第十三波 v1**：文本族下载嵌入 `jzsig1.{kid}.{unixts}.{hmac_hex}`（HMAC-SHA256(key, kid\|filename\|content_sha256_hex\|unixts\|identity_fp)，内容哈希取脱敏/水印后最终交付体，`response/signature.go`）；密钥密文存 settings 经加密服务解密下发（Redact 脱敏覆盖）；`POST /api-security/file-signature/verify` 复算校验（max_age_days 默认 30 可配；kid 不符/伪造/过期如实结论；密钥未配置 503）+ `GET /file-signature/key`（仅 kid）+ `POST /key/rotate`（递增 kid，旧 token 即失效）；验证/轮换均审计不含密钥与完整 token。**WP2-L**：DOCX/XLSX/PPTX 以 ZIP 注释嵌入同源 HMAC 签名，原注释 Base64 封装，恢复签名前精确字节；验证接口新增可选 `content_format=ooxml_zip` + `content_base64`（≤2MiB），沿用原权限/密钥轮换/审计；加密、ZIP64、异常包不签名；stage5 实际下载签名、原始字节恢复与 HMAC 校验通过；文件合规页提供 OOXML 文件验证入口（`SignatureVerificationCard`）。残余：PDF 签名未做 |
| P2-03 文件合规 | IMPLEMENTED_PARTIAL | **第十三波 v1（迁移 000071）**：`api_file_compliance_rules` 表（direction/match_type(EXT\|MIME\|FILENAME_REGEX)/action(OBSERVE\|BLOCK)，内置种子 exe/bat/sh 上传阻断与 sql/bak 下载观察）+ CRUD 接口（`apifiles/compliance_handler.go`）；规则经发布通道下发并纳入版本戳；网关双相位执行（`detectors/filecomp.go`）——上传（multipart 观测点）与下载（Content-Disposition 观测点），BLOCK 在 PROTECT 上传 403/下载缓冲抑制 403（已直通诚实降级 file.download_block_unavailable，不冒充已阻断）；双扩展名 file.double_extension OBSERVE/LOW；**WP2-A**：下载文件真实签名与声明类型比对（`detectors/filecontent.go`），`file.content_type_mismatch` 只观察并接入弱点派生；流式/溢出明确 `file.content_not_inspected`；**WP2-B**：multipart 每文件最多 512 字节前缀签名检测（`CheckUploadFileContentTypes`），非导出字段不入事件，截断/part 数溢出如实披露；不做病毒查杀、解压审计或完整内容校验；**WP2-C**：显式 `file` 位置的值级规则识别文本/CSV 敏感内容，标签合并入既有 `api_file_assets.sensitive_types` 并派生 `SENSITIVE_FILE_CONTENT` 弱点；截断不完整行/预算耗尽明确 `file.sensitive_content_not_inspected`；**WP2-D**：JSON/JSONL 结构化敏感字段识别，证据含 JSON 路径，非法/重复键/截断文档不冒充完整检查；**WP2-E**：XML 嵌套元素/属性敏感识别，流式解析并拒绝 DTD、非法/超深文档；**WP2-F**：DOCX 主 XML 敏感识别，限制包体/条目/主 XML 大小，截断/加密/异常包明确未检查；**WP2-G**：XLSX 共享字符串/内联文本与单元格证据，非法索引/加密/截断包不冒充完整检查；**WP2-H**：PPTX 正式幻灯片 `a:p` 段落内跨 `a:t` 拼接，证据定位 `slide页码!p段落序号`，媒体不扫描，非法根元素、重复部件、加密/截断包明确未检查；stage5 双向真实链路与 XLSX 回归均通过；**WP2-I**：DOCX 页眉页脚 `word/headerN.xml`/`footerN.xml` 敏感识别，`source_part` 区分来源，主文档事件语义与资产历史标签合并保持不变；stage5 双向真实链路与 XLSX/PPTX 回归均通过；**WP2-J**：DOCX 批注/脚注/尾注固定 XML 文本识别，范围 `DOCX_ANNOTATIONS` 并保留 `source_part`，不扫描扩展评论元数据、媒体或宏；stage5 双向真实链路与页眉/XLSX/PPTX 回归均通过；**WP2-K**：PPTX 备注页 `notesSlideN.xml` 段落识别，范围 `PPTX_NOTES`，证据含 `source_part` 与 `notesSlideN!pN`，主幻灯片语义保持不变；stage5 双向真实链路与主幻灯片/DOCX/XLSX 回归均通过 |
| P2-04 LLM API 安全 | IMPLEMENTED_PARTIAL | **第十波 v1（迁移 000066）**：网关 LLM API识别（OpenAI 兼容路径词表+POST+内容形态双重确认，保守精确）；请求侧观测（model/messages 存在性/prompt 长度分桶，不落原文）+ 响应侧补全（model/usage.total_tokens，SSE 置 stream）；Prompt Injection 词表 v1（8 条中英规则，仅 OBSERVE/LOW，证据只含规则名与消息序号不落原文）与未授权模型检测（`gateway_runtime.api_llm_allowed_models` 下发名单非空时判定，OBSERVE/MEDIUM 不参与阻断）（`detectors/llm.go`）；事件 `llm_observation` 字段上报 → 采集落 `api_llm_observations`（request_id 派生 UUID 幂等）；`GET /llm/observations` 与 `/llm/stats`（`apillm/handler.go`，api_runtime.read）；**第十二波 MCP 内容级（迁移 000070）**：MCP JSON-RPC 方法词表核对（词表外 llm.mcp_unknown_method OBSERVE/LOW）与 tools/call 参数值级敏感检测（复用 SensitiveValueRules → llm.mcp_sensitive_arg OBSERVE/MEDIUM，证据只含工具名/规则名不落参数与值）（`detectors/mcp.go`），mcp_method 入观测。**WP3-C（迁移000197）**：按应用 AI 策略新增 `max_output_tokens`（0=关闭，其他取值 1～1000000），检查请求声明的 max_tokens/max_completion_tokens/max_output_tokens，OBSERVE 只记录，PROTECT 走 RATE_LIMIT/429；策略版本、发布、前端表单及真实 PostgreSQL 回滚事务验证通过。该预算不是实际 Token 用量或累计配额，stage5 尚未应用迁移或重建节点，RAG 按要求暂停。**WP3-D（迁移000198）**：新增 `input_content_enabled`，复用高置信有害内容规则检测明确 Prompt 字段，OBSERVE 记录、PROTECT 403 且不调用上游；策略版本、发布、前端表单及 Guard 脱敏测试通过。迁移默认 false，新策略默认开启；真实数据库回放与节点部署尚未进行。残余：SSE 逐 chunk 内容检测未做（前端观测页已于第十五/十六波注册路由，见 §13/§14） |
| P2-05 gRPC 深度 | IMPLEMENTED_PARTIAL | **第十四波 v1**：识别 application/grpc(+proto) 与 /package.Service/Method 路径形态（服务/方法名全保留不归一化）；5 字节前缀帧结构校验（`detectors/grpc.go`）——声明长度>剩余体或单帧超上限（`api_grpc_max_frame_bytes` 默认 4MiB 经发布下发）→ grpc.malformed_frame（PROTECT 定案 403）、压缩标志位（默认不允许）→ grpc.unexpected_compression OBSERVE；消息计数/声明体量入观测（不落内容）；API protocol_type 标注 GRPC（发现链路透传，仅首写不覆盖）；>1MiB 大体积随既有采样护栏跳过。残余：**描述符级（protobuf 消息 schema）解析未做**——无法按字段校验消息内容 |
| P2-06 HTTP/3 | IMPLEMENTED_PARTIAL | **第二十波已验证端到端**：HTTP/3 请求经 Caddy（QUIC 终止）→ guard 统一管线 → 源站正常，proto=HTTP/3.0 在 Caddy 访问日志/guard 全量日志/API 运行时事件三面正确记录（docs/HTTP3_SUPPORT.md）；编排侧 UDP 端口为注释可选块（deployment/docker-compose.wdsp.yml，默认关闭）；边界：QUIC 层 0-RTT/连接迁移/QPACK 帧解析未做（引擎仅见 QUIC 终止后的 http.Request） |
| P2-07 源码 API 发现 | IMPLEMENTED_PARTIAL | **第十四波 v1（迁移 000072）**：`tools/apisrc` 独立工具（go/ast 零依赖）扫描 Go 源码路由注册（ServeMux/chi/echo/gin 字面量形态），输出 OpenAPI3 骨架（source=SOURCE_CODE 标记）→ 规范中心导入流水线天然兼容；`api_import_specs` 加 source 列（UPLOAD/URL/SOURCE_CODE 词表），导入记录来源落库。残余：仅 Go 语言四字面量形态；动态注册（变量拼接路径）不可达 |

---

## 5. 数据库表盘点（补全任务书 §169 对照）

### 5.1 已存在且有生产写入方（闭环）

`api_endpoints`、`api_endpoint_aliases`、`api_lifecycle_events`、`api_learning_jobs`、`api_learning_samples`、`api_model_versions`、`api_parameter_models`、`api_parameter_statistics`、`api_parameter_relations`（CO_OCCURS 候选 + 第十一波 confirmed 人工确认 + 发布下发网关检测）、`api_parameter_value_obs`、`api_runtime_events`、`api_schema_violations`、`api_identity_profiles`、`api_behavior_profiles`、`api_classification_dimensions`、`api_custom_taxonomies`、`api_import_specs`、`api_spec_diffs`、`api_endpoint_traffic_buckets`、`api_response_schemas`（000051 起：采集器 UPSERT 运行时学习行 + Confirm 版本快照）、`api_call_edges`（第六波起：RunCallEdges 分钟级水位增量派生；000067 + identity_count）、`api_scan_targets`/`api_scan_authorizations`/`api_scan_jobs`（000053）、`api_scan_findings`（000054）、`api_cross_border_events`（000058：涉敏事件出境判定 SweepOnce 写入方；配套水位表 `api_cross_border_state`）、`api_file_assets`（000061：采集器 UPSERT 文件传输观测）、`api_ai_schedules`/`api_ai_schedule_runs`（000062：AI 定时运营计划与执行记录，管理面 CRUD + 调度器写入方）、`api_llm_observations`（000066：LLM 观测采集写入方；000070 + mcp_method）、`api_gateway_nodes`（000069：apinodes SweepOnce 事件遥测聚合写入方）、`api_file_compliance_rules`（000071：文件合规规则，管理面 CRUD + 内置种子，经发布通道下发）

### 5.2 已存在但无生产写入方（TABLE_ONLY）

> 2026-08-20 第十六批后：**TABLE_ONLY 表清零**——`api_object_models`/`api_endpoint_path_segments` 已有生产写入方，`api_classifications` 已有内置种子（迁移 000073）；`api_request_schemas` 经决策标注「保留不用」（请求 schema 以 `api_model_versions.schema_json` 为权威来源，避免第二套同义存储，符合任务书 §168 原则）。

| 表 | 迁移 | 说明 |
|---|---|---|
| ~~`api_runtime_findings`~~ | 000018:295 | **已移出本表（000036 起有生产写入方）**：采集器物化 + dedup upsert，见 P0-13 |
| ~~`api_response_schemas`~~ | 000018:180 | **已移出本表（000051 起有生产写入方）**：网关 response_observations → 采集器合并 UPSERT 运行时学习行 + Confirm 版本快照，见 P0-06 |
| ~~`api_request_schemas`~~ | 000018 | **已移出本表（000073 起为决策性保留）**：标注「保留不用」，权威来源为 `api_model_versions.schema_json` |
| ~~`api_object_models`~~ | 000018:241 | **已移出本表（000073 起有生产写入方）**：apiauthz SweepObjectModelsOnce 从事件 raw_path 提取对象段形态（观测列 first/last_seen/sample_count） |
| ~~`api_call_edges`~~ | 000018:267 | **已移出本表（第六波起有生产写入方）**：aggregations RunCallEdges 分钟级水位增量派生，见 P1-05/09/10 |
| ~~`api_sensitive_fields`~~ | 000018:281 | **已移出本表（000040 起有生产写入方）**：apidata SweepOnce 水位幂等写入（detection_source=RUNTIME），见 P0-19 |
| ~~`api_endpoint_path_segments`~~ | 000018:60 | **已移出本表（000073 起有生产写入方）**：发现链路首插/拆分派生段形（xmax=0 判插入），存量迁移回填 |
| ~~`api_classifications`~~ | 000018 | **已移出本表（000073 起有内置种子）**：业务领域 16 项内置分类法（ON CONFLICT 幂等） |

### 5.3 补全任务书 §169 建议表中尚不存在的

`api_applications`（复用阶段3 applications 替代中）、`api_function_groups`、`api_identity_api_baselines`、`api_identity_object_access`、`api_role_api_permissions`、`api_behavior_events`、`api_data_events`、`api_risks`、`api_audit_records`、`api_asset_changes`

> 已建表移出本清单（第三波）：`api_role_baselines` / `api_object_ownership`（000043，权属有 Sweep 写入方、角色基线有管理面写入方）、`api_field_permissions`（000044，管理面写入方）；`api_specifications`/`api_spec_versions` 以 000046 扩展 `api_import_specs`（name/version_no/status 状态机）实现，未新建同义表（符合 §168 迁移原则）。

> 已建表移出本清单（第六波）：`api_scan_targets` / `api_scan_authorizations` / `api_scan_jobs`（000053，目标/授权/任务，管理面 + Worker 写入方）、`api_scan_findings`（000054，扫描引擎写入方），见 P1-07。

> 已建表移出本清单（第七~十四波）：`api_cross_border_events`（000058，出境事件，SweepOnce 写入方）、`api_file_assets`（000061，采集器写入方）、`api_ai_schedules`/`api_ai_schedule_runs`（000062，AI 定时运营）、`api_llm_observations`（000066，LLM 观测采集）、`api_gateway_nodes`（000069，节点遥测聚合）、`api_file_compliance_rules`（000071，文件合规规则）；迁移 000067（api_call_edges + identity_count）/000068（api_parameter_relations + confirmed）/000069（api_runtime_events + gateway_node）/000070（api_llm_observations + mcp_method）/000072（api_import_specs + source）为既有表 ALTER 扩展，符合 §168 迁移原则。000057/000060（notification_channels 通知渠道体系）为并行运维分片，非 API 安全域表。

> 迁移原则提醒（任务书 §168/§224）：已有等价表优先 ALTER/EXTEND/MIGRATE，禁止创建第二套同义表——上表 5.2 的空壳表应优先补写入方而非新建。

---

## 6. 横向支撑面

### 6.1 接口与权限

- 接口：**155 条 `/api/v1/api-security/*`**（apisecurity 36 + apimodels 22 + apiassets 19 + apiscan 17 + apidata 13 + apiauthz 13 + apiops 11 + apifiles 9 + apiweakness 8 + apinodes 3 + apillm 2 + apigeo 1 + app.go 直挂 metrics 1，路由层 mux.Handle 计数），另有 ops 域 system-alerts silence/resume 2 条；管理后端全量唯一路由 504 条；路由层强制权限点+操作审计；**openapi 收录已全量对齐**：`server/openapi/wdsp-api.yaml` 合并产物 405 paths / **505 operations** / 613 schemas（0 重复 operationId、0 悬空 $ref），api-security 片段与代码路由 155/155 逐条一致（2026-08-21 补录 PATCH /nodes/{id} 与节点同步字段）。
- 对照补全任务书 §183-191：资产/学习/模型/规范接口基本具备；**风险/弱点处置接口已就位**（findings 8 条 + weaknesses 8 条，含 confirm/resolve/assign/fixed/retest 等）；敏感数据管理面接口（apidata）已交付；**授权基线接口（apiauthz 13 条）已交付（第三波）**；扫描/AI 运营/文件资产/出境/LLM/节点/文件合规与签名接口已交付（第六~十四波）；审计专用查询接口仍缺失（api_audit.search 等）。
- RBAC：27（000019）+ 4（000041）+ 2（000042 api_risk.read/handle）+ 1（000046 api_spec.manage）+ 2（000048 api_authorization.read/manage）+ 3（000056 api_scan.read/execute/manage）+ 2（000063 api_ai.read/execute）= **41 权限点**，三权分配口径一致（SECURITY_ADMIN 全量、AUDIT_ADMIN 只读、SYSTEM_ADMIN 按需不授权）；对照补全任务书 §181（api.dashboard.*/api.audit.export 等 33 点）有缺口。

### 6.2 前端

**30 个已注册路由的 api-* 页面**（2026-11-15 按 `web/src/router/index.tsx` 逐条复核）+ 大屏 API 安全屏，全部真实接通后端（无 Mock 冒充）；原"页面读空表"3 处（api-findings、api-shadow-zombie、api-sensitive-fields）已随写入方落地解除；findings/weaknesses 处置操作界面已接通；第三波起累计新增 11 页注册路由（api-weaknesses/api-sensitive-types/api-masking-rules/api-violations/api-runtime-events/api-runtime-policies + api-authz 授权基线 + api-scan 主动扫描（第七/八波）+ api-posture 态势首屏（第九波）+ api-model-maturity/api-identity-profiles 早前批次）；第十五/十六波再增 6 页（api-ai-ops/api-llm/api-cross-border/api-service-assets/api-nodes/api-file-compliance）；WP2-M 新增 api-file-assets 文件资产台账（真实列表/统计、SHA-256 检索与同内容上传/下载关联）；response-schemas 已由接口详情 `ResponseSchemaPanel` 消费（无独立路由，页面计数不变）。

### 6.3 测试资产

- Makefile 18 个 `stage8-test-*` 目标（unit/api/discovery/learning/versioning/schema/classification/identity/authorization/sensitive-data/behavior/graph/replay/e2e/performance/security/gateway/all）+ **15 个 `api-security-test-*` 命名目标**（assets/learning/models/runtime/schema/response/auth/authz/behavior/data/risk/audit/spec/e2e/all）与 `api-security-inventory` 清单目标——补全任务书 §234 建议的命名目标已落地。
- `docs/STAGE8_TEST_REPORT.md` 在档：接口 9/9、全链路 15/15、回放 10/10、安全 11/11、性能 5/5、纯 WAF 回归 40/40。
- Playwright E2E：`stage8-api-security.spec.ts` 6 用例 + **第七/八波新增 `stage8-api-security-ops.spec.ts` 8 场景**（风险处置/弱点整改/脱敏规则/敏感类型/规范中心/授权基线/主动扫描/运行时策略），真实环境全量实跑 8/8 通过；期间发现并修复服务端缺陷 `runtime_policy.go` policySelect 列歧义（JOIN 后 42702 恒 500）。
- 对照补全任务书 §204-217 缺口：学习闭环端到端真库集成测试断档（采集器→样本→janitor→候选无真库用例）；参数约束 e2e 无；统一决策测试（§207）Coraza 合流形态不存在；BOLA/BFLA 基线测试无；多节点行为测试（§210）无（节点遥测校验有 sweeper 单测）；模型投毒测试（§215）无；生产级性能实测未做（见 §8）。

### 6.4 文档

- 已有：15 篇 `docs/API_*.md` + STAGE8_TEST_REPORT + STAGE8_IMPLEMENTATION_REVIEW + UNIFIED_DYNAMIC_SECURITY_ARCHITECTURE 等，仓库内阶段8 任务书要求的文档齐全。
- 补全任务书 §225-233 要求新增 9 篇：已全部交付（2026-08-16/17 两波文档分片）：API_RUNTIME_COMPILER.md / API_RESPONSE_SECURITY.md / API_UNIFIED_FINDING_DECISION.md / API_IDENTITY_AUTHORIZATION.md / API_BEHAVIOR_DISTRIBUTED_STATE.md / API_RISK_WEAKNESS.md / API_AUDIT_TRACE.md / API_ACTIVE_SCANNING.md / API_AI_OPERATIONS.md。

### 6.5 局部过时文档（盘点中发现，后续应刷新）

- `docs/API_IDENTITY_SECURITY.md:177-179` 仍称画像表无写入方（实际增强批已落地 RunIdentityProfiles）；
- `docs/API_AUTHORIZATION_ANALYSIS.md` §7 称 BODY 字段未纳入对象标识（实际已有 semantic_type 联动）；
- `docs/DEVELOPMENT_STATUS.md` 阶段8"诚实遗留"~~中"参数值观测通路未接通"~~ **已随各波补全刷新**（观测回填、QUERY/PATH 物化、响应侧、MASK_RESPONSE、行为存储下发、Coraza 合流、AuthZ 实体层与运行时消费、响应 Schema 学习、调用边派生、API 安全告警静默、主动扫描 v1 等表述均已更新为最新状态，并先后追加"API 安全补全第一批~第十四批"段落，迁移 000035-000072；第九~十四批段落与"诚实遗留"已随 2026-08-20 终态刷新逐条核对代码修正漂移）；
- `docs/API_UNIFIED_FINDING_DECISION.md` §八 已随 G2 落地刷新（下游哨兵归因形态与局限，2026-08-18）；`docs/API_SENSITIVE_DATA.md` / `docs/API_RUNTIME_COMPILER.md` 的签名/哈希构成陈旧引用已随第三/四波修正。

### 6.6 监控指标与 AI 运营

- 补全任务书 §158 的 23 项 API 专项指标 **15 项落地（第三波）**：`server/internal/metrics/metrics.go:33-47`——api_assets_total/api_assets_new/api_learning_jobs/api_learning_samples/api_learning_excluded/api_candidates_created/api_models_confirmed/runtime_compile_total/runtime_compile_error/schema_findings/auth_findings/authz_findings/sensitive_findings/behavior_findings/mask_response_total，均为 DB 周期聚合 gauge（有真实数据源，注释逐项标注），`APICollector`（api_collector.go:48）周期采集内存快照并随 WDSP 形态装配（`cmd/api/main.go` StartAPIMetrics）；**无数据源者如实不实现**（注释声明不造假）：api_discovery_qps（网关未上报识别速率）、api_parse_latency（无分项耗时数据源）、学习延迟、事件积压、图谱边数量、AI Tool 调用量；gateway 仍无 prometheus 依赖与 metrics 出口。
- §159 组件监控：**runtimehealth 新增 API_SECURITY 组件探针（第三波）**——API 安全采集链路存活（api_last_event_at/api_event_stale_seconds/api_events_total/api_last_sample_at，默认停滞 10 分钟降级，`runtimehealth/health.go:26`、collector.go probeAPISecurity）；无 AI 服务探针（"API" 项是管理面自测探针）。
- AI 工具 15 个 READ_ONLY 闭环（原 10 个 + 第六波 5 个：api_weakness.search/api_sensitive.search/api_runtime_policy.get/api_spec.get/api_posture.get，`aitools/api_ops_tools.go`）；补全任务书 §146 的 16 个工具清单中 api_spec.diff/api_audit.search/api_scan.get 等仍因后端能力缺失而不存在；~~§147 AI 自动运营任务、§151 AI 定时任务未实现~~ **已落地（第七/八波 apiops，见 P1-02）**：五种内置定时运营任务（只产报告不做变更）+ cron 解析 + 游标防重入 + 全局开关默认关；残余：AI 工作流框架/连续失败熔断/ai_recommendations 流转。

---

## 7. 补全任务书 §241 禁止事项对照

| # | 禁止事项 | 现状 |
|---|---|---|
| 1 | 第二套 API 事件中心 | 未违反（但事件三表分立：security_events/access_control_events/api_runtime_events，靠 request_id 关联） |
| 2 | API 重复解析 HTTP | 未违反（serveNext 唯一挂点，一次解析） |
| 3 | Detector 直接决定阻断 | 未违反（统一引擎内 Decide 唯一；但 guard 传统检查与 Coraza 为引擎外决策点） |
| 4 | Candidate 依赖手工内部接口 | **已解除（000038）**：达标自动生成**非空 Schema** 候选并自动提交 IN_REVIEW；无观测API回退空 Schema |
| 5 | 只有参数表没有生产逻辑 | 未违反（生产链真实）；原"观测入库却回填不上"的 QUERY/PATH 孤儿数据变体已随 000038 物化修复 |
| 6 | Confirmed 不下发 Runtime | **已缓解**：Confirm→编译 DRAFT→Activate VALIDATED→发布成功回写 ACTIVE（000037）；约束词汇已扩至 8 键（第三波 regex/nullable/empty_allowed + required 升级 BLOCK），array_size/mime/file_size 仍不下发 |
| 7 | 只做请求侧 | **已解除**：响应侧三件套落地（ResponseContext/ProcessResponse/Response Transformer），见 P0-05/07 |
| 8 | MASK_RESPONSE 只存在枚举 | **已解除**：决策分支 + Transformer 真实执行（MASK/HASH/REMOVE/ENCRYPT/MAP），授权恢复审计已接入 |
| 9 | BOLA 仅靠 ID 变化 | 未违反字面（有所有权纪律+多信号）；实体基线已建（000043 权属表 + Sweep 写入方 + 五档评估），权属运行时消费未接——检测侧仍仅靠启发式信号 |
| 10 | BFLA 仅靠历史未见过 | 未违反；实体层已建（000043 角色基线 + 管理面确认）且运行时检测已落地（第四波 authzcheck，OBSERVE 级） |
| 11 | Behavior 仅进程内 | **默认配置下仍违反**（Valkey 实现存在，发布通道 `gateway_runtime.behavior_store` 已可下发启用，但默认 memory） |
| 12 | Scanner 污染学习 | **防护已生效（第九波）**：学习样本排除规则（details 含 detector=scanner 明细即排除，`apiruntime/samples.go:50`）+ 扫描隔离签名头 X-JiuZhang-Scan（HMAC(job_id)）+ 授权双人分离已落地（P1-07）；网关侧 scanner 流量识别已上线（`detectors/scanner.go` 三态：signature_valid/signature_forged/presence_only），排除规则由待命转为生效 |
| 13/14 | AI 自动确认/发布 | 未违反（AI 工具全部 READ_ONLY；AI 定时运营任务只产报告不做任何变更，无自动确认/发布/封禁代码路径）✅ |
| 15/16 | 保存完整 Token/Password | 未违反（HMAC 指纹+脱敏，含回归测试）✅ |
| 17 | Mock 数据冒充态势 | 未违反（posture 全维度为真实聚合；大屏 demo 数据有明确 demo 标识） |
| 18 | 复制参考产品 | 未违反 |
| 19 | Risk/Weakness 混成一类 | **已解除**：Risk（`api_runtime_findings` 生产方 + 七态处置）与 Weakness（`apiweakness` 派生 + 整改复测生命周期）双中心分离，见 P0-13 |
| 20 | P0 未完先做 P2 | 未违反：P0 全 21 项于第四~六波收口（全部 IMPLEMENTED_PARTIAL 及以上）后，P2 才于第十~十四波按最小可行子集启动（6 项 v1，P2-06 第二十波闭环），启动顺序符合纪律 |

---

## 8. 断点清单（终态，2026-08-21）

第一~二十一波补全后，原 10 项断点全部闭环或落地为 v1（闭环明细见文末各波刷新说明）：Finding 生产化（000036）、Runtime Model Compiler + API级策略版本 + 约束词汇扩充（000037/第三波）、响应侧三件套与响应 Schema 学习与偏离检测（第一波/000051/第九波）、Coraza 合流（第三波下游哨兵归因）、Risk/Weakness 双中心（000039-000042）、AuthZ 实体层与运行时消费（000043/000044/000048/第四波/第十一波 RESPONSE 方向）、行为存储发布下发（第一波）、敏感数据管理面与值级检测（000040/第三波）、事件审计列（000035/000069）、学习闭环加深（000038/第九波 scanner 识别生效）。

**终态残余断点（按依赖关系非优先级）**：

1. **多节点全量同步协议**：~~节点注册/心跳/主动同步未实现~~ 已升级为「心跳活性 + 发布扇出 + 一致性告警」——第十二波事件遥测驱动的版本一致性只读校验 v1（`api_gateway_nodes` + apinodes SweepOnce + CONFIG_HASH_MISMATCH 告警 + `/nodes`、`/nodes/consistency` 接口，见 P0-21）；第十七波网关心跳（`api_node_heartbeat_seconds`，合成心跳经单向日志采集通道上报，apinodes RecordHeartbeat 落活性，policy_version 以心跳上报为准、活性判定不再依赖业务流量）；第十八波配置面主动同步 v2（迁移 000074：节点增 admin_addr/sync_enabled/last_sync_* 六列 + `PATCH /nodes/{id}` 登记接口；`Publisher.SyncConfigToNodes`（`gatewayconfig/publisher.go:498`）在主发布成功后将同一份最终配置扇出到全部登记次要节点——/load + 规范化哈希比对、逐节点回填 last_sync_*，次要节点失败产 CONFIG_PUBLISH_FAILED/CONFIG_HASH_MISMATCH 告警且不阻断主发布）；残余：节点注册握手协议与发布配置之外的产物（规则库/证书/GeoIP 等）分发为后续工程；
2. **描述符级 gRPC**：protobuf 消息 schema 级解析未实现——第十四波已落地帧结构校验 v1（malformed_frame PROTECT 阻断/压缩标志 OBSERVE/protocol_type 标注，见 P2-05），无法按字段校验消息内容；
3. ~~HTTP/3 深度解析~~ **已部分闭环（第二十波）**：启用方式（默认开启+编排 UDP 可选块）与端到端验证（h3→管线→源站→事件 proto=HTTP/3.0）完成，见 docs/HTTP3_SUPPORT.md；残余为 QUIC 层帧级解析与治理（0-RTT/连接迁移/QPACK）——与第 2 项（protobuf 描述符级解析）同为仅剩的两项协议栈级断点；
4. **生产级性能实测**：~~多节点/大流量实测未做~~ 最小矩阵已实测（第十八波）并经第十九/二十波扩展（2026-08-20 真实数据，见 docs/evidence/api-security-performance-baseline.md §1/§10/§11）——Baseline Proxy 5337.35 QPS（p95 9ms）vs Full API Security（OBSERVE 全链路）3539.67 QPS（p95 13ms），API 动态防护开销 QPS -33.7%、p95 +4ms（+44%）、双臂 0 失败；扩展矩阵补测 PROTECT 真实阻断臂（protect-block 4405.18 QPS 比透传臂快 60.1%，403 短路省源站往返，"开阻断会更慢"不成立）与 64KiB/1KiB 大 body 分档（≈0.22µs/字节）；追补矩阵补测 **WAF Only**（Coraza DetectionOnly 全量 CRS PL1：1464.97 QPS 较纯反代 **-72.0%**、CPU 630.86%，vs API 管线 -26.2%、CPU 226.48%——**关键结论：WAF 规则评估开销约为 API 动态防护管线开销的 2.7 倍，网关水平扩展首要驱动是 Coraza 而非 API 管线**）、Multipart（体长主导 ≈68ns/字节）与 c=100 高并发观察（零失败、吞吐饱和软拐点）；单项检测器分档因检测器无独立运行期开关在架构上不可测（诚实声明不伪造）；11.5 万事件洪峰采集器约 6.5 分钟全量追平零丢失（分钟级入库时延为采集器批量化的真实依据，flush 节奏已于第二十一批修复）；残余缺口（证据文档 §8 逐项清单）：深嵌套/大数组/多API（10 万级API、百万级参数模型）规模化、WAF+API 叠加臂、高并发压垮曲线与长时稳定性、多节点大流量场景、采集器独立标定——`stage8-test-performance` 5/5 仍为基准测试而非生产级压测；
5. 各 P0/P1/P2 项正文 Known Gap 残余（任务书超集口径的覆盖面缺口，如参数微模型 §4.2 字段、BOLA 权属运行时消费、tenant 覆盖行判定、ASN 维度、报告调度器、§146 工具清单余项等）——逐项如实标注，不作为新断点跟踪。

---

## 9. 2026-08-17 补全批次刷新说明

本文件盘点基准为 2026-08-16 工作树；此后两波补全（迁移 000035-000042）已合入工作树，本节汇总状态变化口径，逐项正文已同步刷新：

**第一波（2026-08-16，迁移 000035-000041）**：

- P0-03 NOT_IMPLEMENTED → IMPLEMENTED_AND_CLOSED_LOOP（Runtime Model Compiler + `api_runtime_policies` + 发布回写 + 回滚接口）；
- P0-05 NOT_IMPLEMENTED → IMPLEMENTED_AND_CLOSED_LOOP（ResponseContext + 响应相位 ProcessResponse）；
- P0-07 STUB → IMPLEMENTED_PARTIAL（MASK_RESPONSE 决策分支 + Response Transformer MASK/HASH/REMOVE + `api_mask_rules` 下发）；
- P0-13 NOT_IMPLEMENTED → IMPLEMENTED_PARTIAL（findings 生产方 dedup upsert；`apiweakness` 弱点中心四规则派生与完整生命周期）；
- P0-01/02 Known Gap 收缩（学习多条件判定、非空候选自动提交 IN_REVIEW、FAILED 写入点、QUERY/PATH 参数物化）；
- P0-11 Shadow 的 Finding 链接通；P0-18 发布通道六键下发；P0-19 敏感数据管理面（000040）+ `api_sensitive_fields` 写入方；P0-20 事件六审计列（000035）+ 响应后输出；P0-21 API级策略版本（000037）。

**第二波（2026-08-17，迁移 000042）**：

- P0-13 Risk 侧处置闭环：`api_runtime_findings` status 升级七态 CHECK（存量 OPEN→NEW、ACKNOWLEDGED→IN_PROGRESS）、`api_risk.read/handle` 权限（SYSTEM_ADMIN 不授权）、8 条处置接口（risk_handler.go）+ 降噪聚合三视图 + 操作审计；前端 findings/weaknesses 操作界面接通；
- 已知待对齐（合波处理，详见 docs/API_RISK_WEAKNESS.md 集成注意）：`apiweakness/sweep.go:269` 仍按旧词表（OPEN/ACKNOWLEDGED）取数；`server/tests/stage8_api_security_test.go:1070-1071` findings 种子仍为 `'OPEN'`；
- P0-08 Coraza 合流分片在途（guard 捕获下游 403 补记 waf 明细方向），本文件 P0-08 维持 NOT_IMPLEMENTED 以入库代码为准。

**横向章节联动口径**（§5-§8 以此为准）：

- §5.2：`api_runtime_findings`（000036）与 `api_sensitive_fields`（000040）已移出 TABLE_ONLY 清单；§5.3 中 `api_runtime_policies`（000037）、`api_weaknesses`/`api_weakness_actions`（000039）已建表并有生产方；
- §6.2：findings/shadow-zombie/sensitive-fields 三页"读空表"问题已解除；风险/弱点操作界面已接通；§6.4：补全任务书 §225-233 要求的 9 篇文档已全部交付（API_RUNTIME_COMPILER / API_RESPONSE_SECURITY / API_UNIFIED_FINDING_DECISION / API_IDENTITY_AUTHORIZATION / API_BEHAVIOR_DISTRIBUTED_STATE / API_RISK_WEAKNESS / API_AUDIT_TRACE / API_ACTIVE_SCANNING / API_AI_OPERATIONS）；
- §7 禁止事项对照变化：#4（空 Schema 候选）已解除（非空候选 + 自动 IN_REVIEW）；#6（Confirmed 不下发）缓解为"编译→发布回写联动，约束词汇仍 5 键"；#7（只做请求侧）已解除（响应侧三件套落地）；#8（MASK_RESPONSE 仅枚举）已解除（真实可执行，算法缺 ENCRYPT/MAP）；#19（Risk/Weakness 混成一类）已解除（双中心分离 + 各自状态机）；
- §8 断点清单：第 1（Finding 生产化）、2（Runtime Compiler + API级策略版本）、3（响应侧三件套）、5（Risk/Weakness 双中心）已闭环；第 4（Coraza 合流）~~在途~~ **已落地（第三波，见下节）**；第 6-10 部分推进（行为存储下发已通、敏感数据管理面已建、审计列已补、学习闭环已加深），残余以各项正文 Known Gap 为准。

---

## 10. 2026-08-18 补全批次刷新说明（第三波 + 第四波 W4-GW）

本节汇总第三波（2026-08-17/18，迁移 000043-000046/000048；000047 空缺为并发改号所致）与第四波网关分片（W4-GW，AuthZ 基线运行时消费）状态变化口径，逐项正文已同步刷新：

- **P0-08** NOT_IMPLEMENTED → IMPLEMENTED_PARTIAL：Coraza 合流按「下游哨兵归因」形态落地（`jiuzhang_guard/apicoraza.go`：coraza-caddy v2.5.0 未导出哨兵错误识别 → 补记 waf 明细 + final_action/response_status 按实记 BLOCK）；四条局限如实声明（哨兵耦合/无规则明细/phase 3 不归因/非 API 流量不回填），externalMatches 管线注入仍为 nil；
- **P0-04** 约束词汇扩充：regex（RE2，≤512 字符，编译失败保守 OBSERVE）/nullable/empty_allowed 三键下发执行，required 在 PROTECT 升级 BLOCK 类；
- **P0-12** 规范中心增强（000046）：URL 导入 + SSRF 防护、Swagger 2.0 转换、版本状态机（DRAFT/ACTIVE/HISTORICAL/INVALID/ARCHIVED + api_spec.manage）、跨版本 CHANGED diff、导入回写资产（MISSING_IN_RUNTIME 登记API）；
- **P0-15/16/17** 实体层落地（000043/000044/000048）：`api_object_ownership`（权属 Sweep 写入方）+ `api_role_baselines`（BFLA）+ `api_field_permissions`（七属性）+ 五档 BOLA 评估 + apiauthz 13 条接口 + `api_authorization.read/manage` 权限；**BFLA/字段权限运行时消费随第四波（W4-GW）落地**：confirmed 角色基线与字段权限经 `api_role_baselines`/`api_field_permissions` 发布下发（`guardconfig/authz_rules.go`）并纳入 api_policy_version 哈希，网关 `detectors/authzcheck.go` 消费（BFLA 匿名/角色不匹配 OBSERVE；FORBIDDEN 字段 BLOCK 类可阻断；字段权限仅 REQUEST 方向 json. 前缀行可判定）；对象权属仍仅管理面评估、不下发；
- **P0-10** 价值评分（九维 → LOW/MEDIUM/HIGH/CRITICAL + 可解释明细周期回填）与服务资产聚合视图（upstream host:port 粒度）落地；deprecate/restore HTTP 入口补齐；
- **P0-11** Zombie 判定落地（000045）：DEPRECATED 近 N 天仍有流量 → ZOMBIE（zombie_since + 生命周期事件），不自动归档（归档人工），restore 恢复；
- **P0-19** 值级敏感检测落地：`api_sensitive_value_rules` 发布下发（ENABLED + regex 非空类型）+ 网关执行（QUERY 值 BLOCK 升级/JSON/FORM 值 OBSERVE/HEADER/PATH 扩展，证据不落值，预算防 CPU 放大），并纳入 api_policy_version 哈希；
- **§6.6** API 专项指标 15 项落地（DB 聚合 gauge + APICollector；无数据源者如实不实现）+ runtimehealth API_SECURITY 采集链路探针；
- **第二波遗留收口**：`apiweakness/sweep.go` 已按七态词表取数、测试种子同步（docs/API_RISK_WEAKNESS.md 集成注意解除）；
- **§5.3** `api_role_baselines`/`api_object_ownership`/`api_field_permissions` 移出缺失清单（已建表有写入方）；**§6.1** 接口 103 条 / 权限 36 点；**§6.2** 前端 20 页（新增 6 页注册路由，授权基线页在途）；
- **§7** #6 更新为"词汇 8 键"、#9 更新为"实体基线已建、权属运行时消费未接"、#10 更新为"运行时检测已落地（OBSERVE 级）"；**§8** 第 4（Coraza 合流）已落地、第 6（AuthZ 实体层）实体层闭环且 BFLA/字段权限运行时消费已通、第 2/8 残余收缩；
- **前端**：弱点/敏感数据类型/脱敏规则/违例/运行时事件/运行时策略 6 新页注册路由（`web/src/router/index.tsx:55-60`）。

---

## 11. 2026-08-18 终态刷新说明（第四~六波，P0 全 21 项收口 + P1 首批落地）

本节汇总第四波（W4-GW，AuthZ 运行时消费，无迁移）、第五波（W5，迁移 000051）与第六波（W6-A/B/C/D，迁移 000053-000056）状态变化口径，逐项正文已同步刷新：

- **P0-06** TABLE_ONLY → IMPLEMENTED_PARTIAL：响应 Schema 学习链路闭环——网关 `response/observe.go` 生成 ResponseObservation（字段路径→类型，不落值）→ `apievents` 随主事件上报 → 采集器 `apiruntime/respschema.go` 按 API×状态码 合并 UPSERT（迁移 000051 补运行时学习列与部分唯一索引）→ `GET endpoints/{id}/response-schemas` 只读查询 + Confirm 事务内版本快照；残余：响应偏离检测、§48 全字段、前端消费；
- **P1-09/10** NOT_IMPLEMENTED/TABLE_ONLY → IMPLEMENTED_PARTIAL：`aggregations/call_edges.go` RunCallEdges 分钟级水位增量派生（同身份相邻调用 ≤10 分钟成边；匿名 SQL 层排除、未解析API截断、自环不成边；水位推进与 upsert 同事务）；graph/topology 读接口新增 start/end/min_count 边过滤与节点 open_findings_count（W6-A）；`api_call_edges` 移出 TABLE_ONLY；
- **P1-08** NOT_IMPLEMENTED → IMPLEMENTED_PARTIAL（W6-B，迁移 000055）：systemalerts 三新型（API_CRITICAL_FINDING/API_FINDING_SPIKE/API_MASK_FAILURE，评估器周期扫 api_runtime_findings，`system_settings` 组 `api_alert` 六键）+ system_alerts.silenced_until 静默列 + silence/resume 接口 + 列表 view 三态视图；残余：通知渠道仅 syslog 外发、无周期静默计划；
- **P1-02** NOT_IMPLEMENTED → IMPLEMENTED_PARTIAL（W6-C）：5 个新 READ_ONLY 工具（api_weakness.search/api_sensitive.search/api_runtime_policy.get/api_spec.get/api_posture.get）；残余：AI 自动运营/定时任务；
- **P1-07** NOT_IMPLEMENTED → IMPLEMENTED_PARTIAL（W6-D，迁移 000053/000054/000056）：apiscan 包（目标/授权双人分离/撤销即停/时间窗/限速并发/6 探针集/X-JiuZhang-Scan 签名头/样本脱敏/复测桥接弱点中心）+ 17 接口 + api_scan.* 三权限点 + `api_scan.enabled` 默认关；学习样本扫描排除规则（detector=scanner）建成待命；残余：前端页未建、网关 scanner 识别未上线；
- **§5.2** `api_response_schemas`/`api_call_edges` 移出 TABLE_ONLY 清单；**§5.3** `api_scan_targets`/`api_scan_jobs`/`api_scan_findings` 移出缺失清单（000053/000054 已建表有写入方）；
- **§6.1** 接口 122 条（+apiscan 17 +response-schemas 1 +app.go 直挂 metrics 补计 1，另有 system-alerts silence/resume 2 条在 ops 域）/ 权限 39 点（+000056 三点）；openapi 收录同步刷新；**§6.6** AI 工具 15 个；**§7** #12 更新为"防护已建待生效"；**§8** 第 3 项 P0-06 部分闭环。

**六波迁移全清单（000035-000056，000047 空缺为并发改号所致）**：

| 迁移 | 内容 | 波次 |
|---|---|---|
| 000035 api_runtime_event_enrichment | 事件六审计列（client_ip/method/raw_path/latency_ms/model_version/policy_version） | 第一波（P0-20） |
| 000036 api_findings_enrichment | findings 生产化列（dedup_fingerprint 等） | 第一波（P0-13/11） |
| 000037 api_runtime_policies | API级运行时策略版本 | 第一波（P0-03/21） |
| 000038 api_learning_deepen | 学习质量维度列与多条件判定支撑 | 第一波（P0-01/02） |
| 000039 api_weaknesses | 弱点中心两表 | 第一波（P0-13） |
| 000040 api_sensitive_data | 敏感数据类型/脱敏规则/字段写入方 | 第一波（P0-19） |
| 000041 api_weakness_data_perms | api_weakness.*/api_data.* 权限种子 | 第一波 |
| 000042 api_risk_center | findings 七态 CHECK + api_risk.* 权限 | 第二波（P0-13） |
| 000043 api_authz_baselines | 角色基线 + 对象权属 | 第三波（P0-15/16） |
| 000044 api_field_permissions | 字段权限七属性 | 第三波（P0-17） |
| 000045 api_asset_lifecycle | 资产价值/Zombie/生命周期列 | 第三波（P0-10/11） |
| 000046 api_spec_versions | 规范版本状态机 | 第三波（P0-12） |
| 000048 api_authorization_perms | api_authorization.* 权限种子 | 第三波 |
| 000049 gateway_node_interfaces | 网口管理（并行网络模式分片，非 API 安全） | 并行 |
| 000050 syslog_more_kinds | syslog 外发范围扩展（并行运维分片） | 并行 |
| 000051 api_response_schema_learning | api_response_schemas 运行时学习列 | 第五波（P0-06） |
| 000052 application_deployment_mode | 应用部署模式（并行网络模式分片） | 并行 |
| 000053 api_scan_core | 扫描目标/授权/任务 | 第六波（P1-07） |
| 000054 api_scan_findings | 扫描发现 | 第六波（P1-07） |
| 000055 api_security_alerts | system_alerts.silenced_until 静默列 | 第六波（P1-08） |
| 000056 api_scan_perms | api_scan.* 权限种子 | 第六波（P1-07） |

（第四波 W4-GW 为纯网关/发布通道分片，无迁移；第六波 W6-A 图谱过滤与 W6-C AI 工具为纯代码分片，无迁移。）

---

## 12. 2026-08-20 终态刷新说明（第七~十四波，P1 全项落地 + P2 六项 v1）

本节汇总第七波（2026-08-18，迁移 000058/000059/000061）、第八波（2026-08-18，迁移 000062/000063）、第九波（2026-08-19，零新迁移）、第十波（2026-08-19，迁移 000066）、第十一波（2026-08-19，迁移 000067/000068）、第十二波（2026-08-20，迁移 000069/000070）、第十三波（2026-08-20，迁移 000071）、第十四波（2026-08-20，迁移 000072）状态变化口径，逐项正文已同步刷新（000057 通知渠道、000060 通知二期为并行运维分片，非 API 安全项）：

- **P1-03** NOT_IMPLEMENTED → IMPLEMENTED_PARTIAL（第七波，000058）：apigeo 自研 MMDB 解析 + 五档出境判定 + `api_cross_border_events` SweepOnce 写入方 + cross-border 看板接口；残余：无 ASN、前端页在途；
- **P1-06** NOT_IMPLEMENTED → IMPLEMENTED_PARTIAL（第七波，000059）：reports 四类型（API 资产周报/API 风险周报/弱点整改报告/敏感数据报告）真实 SQL + 渲染管线复用；残余：调度器未做；
- **P1-04** NOT_IMPLEMENTED → IMPLEMENTED_PARTIAL（第七波，000061）：multipart/Content-Disposition 文件观测 → `api_file_assets` 采集 UPSERT + file-assets/stats 接口 + FILE_BULK_DOWNLOAD 风险 v1；残余：下载观测仅带 filename 的 Content-Disposition、前端页在途；
- **P1-02 续**（第八波，000062/000063）：apiops 五种 AI 定时运营任务（只产报告不变更）+ cron 解析 + 全局开关默认关 + 11 接口 + api_ai.read/execute 权限；**P1-07 前端收口**：ApiScanPage 四 Tab 注册路由；Playwright E2E +8 场景实跑通过（并修复 runtime_policy.go 列歧义缺陷）；
- **P0-01/P1-07**（第九波）：网关 scanner 签名识别三态上线，学习样本排除规则由待命转为生效；**P0-06 运行时消费**：`api_response_baselines` 下发 + 响应偏离检测（new_field/missing_field/new_status）；**P1-01 补齐**：posture overview 12 指标 + trends 六曲线 + 前端 ApiPosturePage 首屏；
- **P1-01 残余收口**（第十波）：posture sources/targets 访问维度五榜单（UA 维度无数据源如实不做）；**P2-04 首批**（000066）：LLM API识别 + 观测不落原文 + Prompt Injection 词表 v1 + 未授权模型检测 + `api_llm_observations` + /llm/observations、/llm/stats；
- **P0-02 残余闭环**（第十一波，000068）：参数条件关系 confirm/reject + 发布下发 + 网关 relationcheck 运行时检测；**P0-17 残余**：响应方向字段权限运行时判定（response_forbidden_field/response_sensitive_field，OBSERVE 级不定案阻断）；**P1-05**（000067）：api_call_edges identity_count 持久化 + NULLS NOT DISTINCT 唯一索引；
- **P0-21 多节点遥测校验 v1**（第十二波，000069）：`api_gateway_nodes` + gateway_node 落列 + ACTIVE/STALE/SILENT 状态机 + 版本一致性比对 + CONFIG_HASH_MISMATCH 告警 + /nodes、/nodes/consistency 接口（如实声明：遥测校验而非同步协议）；**P2-04 续**（000070）：MCP 方法词表核对 + tools/call 参数值级敏感检测；**P2-01 v1**：文本族不可见水印（api_file_watermark_* 四键默认关，FAIL_OPEN）；
- **P2-03 v1**（第十三波，000071）：api_file_compliance_rules + 双相位执行（上传 multipart/下载 Content-Disposition；下载直通诚实降级不冒充阻断）+ 双扩展名检测；**P2-02 v1**：文本族下载 jzsig1 签名 + verify/key/rotate 接口；
- **P2-05 v1**（第十四波）：gRPC 帧结构校验（malformed_frame PROTECT 403/unexpected_compression OBSERVE/protocol_type GRPC 标注）；**P2-01 补全子集**：OOXML（docx/xlsx/pptx）custom.xml 水印；**协议版本可见性**：事件 proto（HTTP/1.1/2/3）与 protocol 字段；**P2-07 v1**（000072）：tools/apisrc 源码路由扫描 → OpenAPI3 骨架（SOURCE_CODE）→ 规范中心导入流水线；
- **协议识别波**：protocol_type 词表补全 GRAPHQL/SOAP/WEBSOCKET（classifier/protocol.go 三检测器 + 管线 api.protocol 打标；GRPC→WS→GraphQL→SOAP 互斥优先级；模型编译 GRAPHQL→application/json；前端 API_PROTOCOL_META 标签展示）；
- **§6.1** 接口 154 条 / 权限 41 点（+000063 两点）；openapi 终态补录 nodes×2/llm×2/posture sources×targets（片段与代码 154/154 对齐，合并产物 489 ops）；**§6.2** 前端 23 页注册（+api-authz/api-scan/api-posture，另有并行分片页面在途）；**§6.3** api-security-test-* 命名目标与 E2E ops spec 落地；**§6.6** AI 定时运营落地；**§7** #12 更新为"防护已生效"、#20 更新为"P0 收口后 P2 按序启动"；**§8** 终态收敛为四项：多节点全量同步协议、描述符级 gRPC、HTTP/3 深度解析、生产级性能实测。

**第七~十四波迁移全清单（000057-000072）**：

| 迁移 | 内容 | 波次 |
|---|---|---|
| 000057 notification_channels | 通知渠道体系（并行运维分片，非 API 安全） | 并行 |
| 000058 api_cross_border | 出境事件两表（P1-03） | 第七波 |
| 000059 api_reports | API 报告四类型词表扩展（P1-06，零新表） | 第七波 |
| 000060 notify_phase2 | 通知二期（并行运维分片） | 并行 |
| 000061 api_file_assets | 文件资产表（P1-04） | 第七波 |
| 000062 api_ai_schedules | AI 定时运营两表（P1-02 续） | 第八波 |
| 000063 api_ai_schedule_perms | api_ai.* 权限种子 | 第八波 |
| 000064 deployment_mode_mirror_transparent | 部署模式扩展（并行网络模式分片） | 并行 |
| 000065 node_network_configs | 节点网络配置（并行网络模式分片） | 并行 |
| 000066 api_llm_observations | LLM 观测表（P2-04 首批） | 第十波 |
| 000067 api_call_edges_identity_count | 调用边身份计数列 + NULLS NOT DISTINCT 索引 | 第十一波 |
| 000068 api_parameter_relations_confirm | 参数关系 confirmed 列与词表 CHECK（P0-02 残余） | 第十一波 |
| 000069 api_gateway_nodes | 节点遥测表 + api_runtime_events.gateway_node 落列（P0-21） | 第十二波 |
| 000070 api_llm_observations_mcp_method | LLM 观测 + mcp_method 列（P2-04 续） | 第十二波 |
| 000071 api_file_compliance | 文件合规规则表（P2-03） | 第十三波 |
| 000072 api_spec_source | api_import_specs.source 来源列（P2-07） | 第十四波 |

（第九波为零迁移纯代码分片——扫描识别/响应偏离/态势三件套均为发布通道与网关侧扩展；第十二波文件水印 v1 为发布通道+网关分片，无独立迁移。）

---

## 13. 2026-08-21 终态刷新说明（第十五~十八波，多节点心跳+扇出 + 性能基线实测）

本节汇总第十五/十六波（2026-08-20，迁移 000073）、第十七波（2026-08-20，零新迁移）、第十八波（2026-08-21，迁移 000074）状态变化口径；§8 断点清单已同步刷新（第 1、4 项升级），逐项正文以各波交付为准：

- **§8 断点第 1 项（多节点）升级**：由「遥测校验」升级为「心跳活性 + 发布扇出 + 一致性告警」——第十七波网关心跳（`api_node_heartbeat_seconds` 默认 0=关闭；网关周期产合成心跳记录（heartbeat:true + gateway_node + policy_version + 模型版本摘要数 + uptime）经单向日志采集通道上报，采集端识别后仅透传 HeartbeatRecorder、不落 api_runtime_events 业务数据；apinodes RecordHeartbeat 合并 upsert 不回退，有心跳无流量=ACTIVE、policy_version 以心跳上报为准）；第十八波配置面主动同步 v2（迁移 000074：`api_gateway_nodes` 增 admin_addr/sync_enabled/last_sync_* 六列；`PATCH /api-security/nodes/{id}` 登记接口——api_policy.publish 权限 + 操作审计，admin_addr 仅内网地址校验、拨号时 DNS 重解析复检防重绑定；`Publisher.SyncConfigToNodes`（`gatewayconfig/publisher.go:498`）主发布全链路成功后将同一份最终配置扇出到全部登记次要节点，/load + 规范化哈希比对、逐节点回填 last_sync_*，次要节点失败不阻断主发布、产 CONFIG_PUBLISH_FAILED/CONFIG_HASH_MISMATCH 告警）；残余为节点注册握手与发布配置之外的产物分发（§8 第 1 项）；
- **§8 断点第 4 项（性能实测）升级**：由「未做」改为「最小矩阵已实测」——2026-08-20 真实数据见 docs/evidence/api-security-performance-baseline.md（Baseline Proxy 5337.35 QPS/p95 9ms vs Full API Security OBSERVE 全链路 3539.67 QPS/p95 13ms，开销 -33.7% QPS、p95 +4ms，双臂 0 失败；11.5 万事件洪峰采集器约 6.5 分钟全量追平零丢失）；全矩阵其余档位（WAF Only/PROTECT/单项检测器/大 body/多节点大流量等）缺口列入证据文档 §8；
- **§5.2 TABLE_ONLY 清零**（第十五/十六波，迁移 000073）：`api_object_models` 补观测列并由 apiauthz SweepObjectModelsOnce 生产、`api_endpoint_path_segments` 由发现链路派生（存量迁移回填）、`api_classifications` 内置业务领域 16 项种子、`api_request_schemas` 注释标注「保留不用：请求 schema 以 api_model_versions.schema_json 为权威来源」；
- **§6.1 口径**（以本节为准）：api-security 接口 154 → **155**（apinodes +`PATCH /nodes/{id}`）；OpenAPI 第十七波全量对账（补录 15 个既有路由 operation）后，本波终态补录 PATCH 操作与节点 last_sync_* 字段——合并产物 **405 paths / 505 operations / 613 schemas**（0 重复 operationId、0 悬空 $ref），api-security 片段与代码路由 155/155 逐条一致；
- **§6.2 口径**：前端 6 页注册路由（第十五/十六波：AI 运营/LLM 观测/数据出境/服务资产/节点校验/文件合规），Playwright 新增 stage8-api-security-ops2.spec.ts 6 场景实跑通过；
- **P0-21 Known Gap 收缩**：心跳与配置面主动同步 v2 已落地（见上），残余同 §8 第 1 项（节点注册握手 + 发布配置外产物分发）。

---

## 14. 2026-08-21 刷新说明（第十九~二十一批，性能矩阵扩展 + HTTP/3 闭环 + 采集器 flush 修复 + proto 全链）

本节汇总第十九/二十批（2026-08-21，零新迁移）与第二十一批（2026-08-21，迁移 000075）状态变化口径；§8 断点清单已同步刷新（第 3 项部分闭环坐实、第 4 项残余收缩），逐项正文以各批交付为准：

- **性能实测结论更新（§8 第 4 项残余收缩）**：最小矩阵扩展为四臂六测量 + 追补七测量（全部真实实测、零失败，docs/evidence/api-security-performance-baseline.md §10/§11）——PROTECT 真实阻断臂（protect-block 4405.18 QPS 比 protect-pass 快 60.1%，"开阻断会更慢"不成立）、大 body 分档（64KiB vs 1KiB JSON ≈ 0.22µs/字节）、**WAF Only 档位**（应用 OBSERVE = Coraza DetectionOnly 全量 CRS PL1：1464.97 QPS 较纯反代 -72.0%、gateway CPU 630.86%，vs API 动态防护全管线 -26.2%、CPU 226.48%——**WAF 规则评估开销约为 API 管线开销的 2.7 倍，网关水平扩展首要驱动是 Coraza 规则评估而非 API 管线**）、Multipart（体长主导 ≈68ns/字节；1MiB 超解析上限截断形态符合设计）、c=100 短促高并发（零失败、吞吐饱和软拐点、延迟换吞吐）；检测器级独立分档因无运行期开关在架构上不可测，诚实声明不伪造；§202 全矩阵残余收缩为深嵌套/大数组/多API规模化、WAF+API 叠加臂、压垮曲线与长时稳定性、多节点大流量、采集器独立标定（证据文档 §8 已逐项划销）；
- **HTTP/3 部分闭环（第二十波，§8 第 3 项）**：Caddy 2.11 对 TLS 监听默认开启 h1/h2/h3（发布通道零改动），编排侧 UDP 端口为注释可选块（deployment/docker-compose.wdsp.yml，默认关闭）；旁路实测（deployment/http3-lab/）h3 请求经 Caddy → guard 统一管线 → 源站正常，proto=HTTP/3.0 在 Caddy 访问日志/guard 全量日志/API 运行时事件三面正确记录，路径归一化/检测器/真实 IP 在 h3 下全部正常（docs/HTTP3_SUPPORT.md 含证据与启用方式）；残余为 QUIC 层 0-RTT/连接迁移/QPACK 帧级解析与治理（引擎仅见 QUIC 终止后的 http.Request）——**与 §8 第 2 项（protobuf 描述符级 gRPC 解析）同为仅剩的两项协议栈级断点**；
- **采集器 flush 批量化修复（第二十一批，性能实测发现的真实缺陷，证据文档 §11.8 已标注修复）**：api 运行时事件与全量访问日志两采集器由「读到 EOF 才唯一 flush、断点仅 flush 时落盘」改为批量（默认 2000 行）/周期（默认 2s）flush 且断点同节奏落盘（`apiruntime/collector.go:474-481` 触发点、`SetFlushPolicy` collector.go:229 / `accesslogs/collector.go:58`）——崩溃/重建重扫量有界（≤2000 行 + ≤2s），中途 flush 失败断点不前移（下轮从最近成功断点重读，request_id 幂等语义不变）；`WAF_COLLECTOR_FLUSH_BATCH`/`WAF_COLLECTOR_FLUSH_INTERVAL` env 可配（`config/config.go:204-205`，main.go 接线）；顺带修正 accesslogs 断点按完整行累计错位与 EOF 落盘失败静默两处同域缺陷；测试证据：`apiruntime/collector_flush_test.go` 单测 4 项 + `tests/accesslogs_collector_flush_test.go` 真实 PG 集成 + 既有采集链路集成回归全过；
- **访问控制/CC 事件 proto 字段全链补齐（第二十一批，迁移 000075）**：guard 事件 Record 单点填充 proto（`jiuzhang_guard/events/events.go:59`，omitempty，r.Proto 原样 HTTP/1.x/2/3）→ `access_control_events` 加 proto TEXT NULL 列（分区表 ALTER 自动传播）→ 采集解析落列（`accesscontrolevents/parse.go:68/94`，缺失容忍落 NULL）→ 读接口带出 → 前端事件页协议列（HTTP/1.x/2/3 Tag 色）；全链新旧版本互通不破坏（旧版网关缺字段落 NULL，不伪造 0 值）；
- **§6.2 口径**：前端注册路由终态实测 **30 个 api-* 页面**（`web/src/router/index.tsx` 逐条复核，2026-11-15）——第十五/十六波 6 页（AI 运营/LLM 观测/数据出境/服务资产/节点校验/文件合规）注册后，原"并行分片页面在途"口径全部解除（P1-03/P2-04 正文"前端页在途"残余标注已同步解除）；WP2-M 新增文件资产台账页，页面测试与生产构建通过，登录态浏览器交互验收尚未进行；**§6.1 口径不变**：155 条接口（apinodes 3 含 `PATCH /nodes/{id}`，§13 已补录，OpenAPI 合并产物 405 paths / 505 operations 口径不变）。

*本文件为现状盘点结论，不代表后续开发承诺；补全开发完成后应更新本文件状态列。*

---

## 15. 2026-10-23 能力新增说明（API 网络暴露面判定引擎，迁移 000190）

新增 `apiexposure` 模块：综合**流量证据 + 配置证据 + 人工确认**自动判定每个 API 端点的暴露面
（INTERNAL/PARTNER/PUBLIC/UNKNOWN），结果条件写入既有 `api_classification_dimensions`
（dimension='EXPOSURE'），自动被资产价值评分消费（value.go EXPOSURE 维度优先读取，无需改动）：
UNKNOWN 落 default 计 1 分（与"未分类"同分），语义自洽。

- **证据采集（全量口径）**：apiruntime 采集器在端点发现 upsert 成功后逐事件聚合
  `api_endpoint_source_buckets`（端点×自然日×来源范围请求计数）与 `api_endpoint_source_seen`
  （去重来源明细，**只存网关上报的盐化指纹、不落明文 IP**，与 learning_samples 同纪律）；
  来源范围经 `apigeo.ClassifyIPScope`（RFC1918/回环/链路本地/ULA/CGNAT/保留段，不依赖 GeoIP 库）
  分 INTERNAL/PUBLIC，命中 `exposure_engine.partner_egress_cidrs` 合作方出口网段升级 PARTNER；
  聚合随 W22 批次事务整批提交（断点重放不重复计数），失败仅记日志 fail-open 不影响主事件链路；
  留存 30 天随评估调度清理。
- **判定规则**（`apiexposure/engine.go` 纯函数，表驱动单测覆盖全分支）：MANUAL/锁定优先
  （引擎永不覆盖人工确认，仅写评估明细）→ 流量观测（公网来源→PUBLIC；仅合作方→PARTNER；
  仅内网且达量达日→INTERNAL；置信度按自然日数/请求量分档）→ 配置回落（域名经可配置公网 DNS
  可解析到公网 IP→PUBLIC/LOW，NXDOMAIN/仅私网→INTERNAL/LOW；MIRROR/TRANSPARENT 旁路部署只记
  证据不单独出判定）→ 全不足 UNKNOWN/LOW；流量与域名解析冲突时流量优先且证据注明。
  证据明细（evidence JSONB）元素为 {type, summary}，summary 由服务端直接生成中文。
- **配置键**（system_settings 组 `exposure_engine`，白名单+校验登记于 settings/settings.go，
  种子见迁移 000190）：observation_days（默认 7）/ partner_egress_cidrs / public_dns_servers
  （默认 223.5.5.5）/ min_requests（默认 50）/ min_days（默认 2）。
- **接口**（权限零新增）：`GET /api-security/endpoints/{id}/exposure`（api_asset.read，
  当前维度+最近一次评估明细）、`POST /api-security/endpoints/{id}/exposure/reassess`
  （api_asset.edit + 操作审计，恒写评估明细，人工/锁定 applied=false）；OpenAPI 07 片段已补录。
- **前置条件与如实限制**：流量证据依赖 API 动态防护管线开启（apievents 数据流），未开启时只有
  CONFIG 级低置信判定；公网 DNS 视角取决于管理面到所配公网 DNS 的可达性，不可达时证据记
  ERROR 不伪造结论；网关网卡是否持公网 IP（监听侧补强证据）需扩展 netcollector 采集接口 IP，
  本次未做，列为后续项。

## 16. 2026-10-26 能力新增说明（API 多标签 + 可编辑资产档案，迁移 000191）

`api_assets` 扩展资产档案字段：`organization`（所属单位）、`business_system`（业务系统）、
`technical_owner` / `data_owner`（技术/数据负责人，原 `owner` 即系统负责人）、
`data_level`（CORE/IMPORTANT/GENERAL/UNKNOWN）、`api_level`（LEVEL_1/2/3/UNKNOWN）、
`auth_type`（NONE/BASIC/API_KEY/TOKEN/JWT/OAUTH2/MTLS/SESSION/OTHER，空串=未标注）。
枚举应用层校验不落 CHECK；`UpsertAsset` 入参改为 `AssetProfile` 结构体并保持全量替换语义，
`normalizeAssetProfile` 统一归一/校验，SQL 与 MemStore 共用。

- **多标签**：既有 `api_assets.tags` 多值数组能力补上前端入口——详情抽屉「资产档案」小节
  `Select mode="tags"`（回车添加、最多 32 个），列表新增「标签」列（前两个直接展示，其余 +N 折叠）。
- **档案编辑**：`PATCH /api-security/endpoints/{id}` 接收完整档案表单（api_asset.edit + 审计摘要含新字段）；
  前端 `assetProfileInput` 合并已存档案后再提交，业务标签单存不再清空其他档案字段。
- **只读派生项**：互联网暴露由暴露面判定派生（PUBLIC=是，INTERNAL/PARTNER=否，未判定=未知，
  修改走暴露面人工确认，不双写）；日均调用量由详情接口返回 `daily_requests`
  （近 7 天 `api_endpoint_traffic_buckets` 窗口和/7，与资产价值评分同口径）。
- OpenAPI 07 片段（ApiSecAsset/ApiSecEndpointUpdateRequest/ApiSecEndpointResponse/列表 tags）已补录并重新 merge。
