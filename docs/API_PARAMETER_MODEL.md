# API 参数模型设计（阶段8 / WDSP）

## 一、目的与范围

本文档描述阶段8 API 动态参数模型的数据结构与确认流程，覆盖：

- `api_parameter_models`：参数模型主表（方向 / 位置 / 结构化路径 / 三层约束）；
- `api_parameter_statistics`：参数统计画像（长度、值域、基数、样本哈希）；
- `api_parameter_relations`：参数条件关系（REQUIRES / EXCLUDES / CO_OCCURS）；
- 管理面参数接口与"采纳推荐约束"确认流程。

参数模型的设计前提是任务书第 2.7 条"字段名只是数据"：系统不对任何具体字段名编写
固定业务策略，所有字段按通用组合标识进入同一套学习与确认机制。本文档只描述已实现
的结构与流程，学习任务自动产出参数行的能力见"当前实现范围与限制"一节。

## 二、架构与数据流

```text
模型版本（api_model_versions，server/internal/apimodels/store.go）
  │  1:N（ON DELETE CASCADE）
  ▼
api_parameter_models ── 1:1 ── api_parameter_statistics（画像，RefreshParameterStatistics 离线写入，见第七节）
  │
  └── api_parameter_relations（版本内参数两两关系，当前无写入方）

管理面（server/internal/apimodels/handler.go）
  GET   /api/v1/api-security/models/{id}/parameters   按版本列出参数
  GET   /api/v1/api-security/parameters/{id}          参数详情
  PATCH /api/v1/api-security/parameters/{id}          编辑确认约束（审计）
  POST  /api/v1/api-security/parameters/{id}/confirm  采纳推荐约束（审计）
```

参数行依附于模型版本而非直接依附API：`model_version_id` 外键指向
`api_model_versions(id)` 并级联删除（迁移 000018，
`server/migrations/000018_stage8_full_schema.up.sql:125`）。任务书第十三章的通用标识
`api_endpoint_id + direction + location + structured_path + parameter_name` 因此通过
"API → 版本 → 参数"两层归属表达：同一API不同版本各自持有独立参数集合，版本归档
不影响历史版本的参数快照。

## 三、数据结构

### 3.1 api_parameter_models（任务书 50.3）

建表定义见 `server/migrations/000018_stage8_full_schema.up.sql:123-142`，Go 结构体
`Parameter` 见 `server/internal/apimodels/parameters.go:17-35`：

| 列 | 类型 | 说明 |
|----|------|------|
| `id` | UUID | 主键，`gen_random_uuid()` |
| `model_version_id` | UUID | 所属模型版本，FK 级联删除 |
| `direction` | VARCHAR(16) | `REQUEST` / `RESPONSE` |
| `location` | VARCHAR(32) | 参数位置：`PATH` / `QUERY` / `HEADER` / `COOKIE` / `BODY`（迁移注释口径） |
| `structured_path` | VARCHAR(512) | 结构化路径（如 JSON 点路径 `user.address.tel`） |
| `parameter_name` | VARCHAR(255) | 字段名 |
| `base_type` | VARCHAR(32) | 基础类型，默认 `string` |
| `semantic_type` | VARCHAR(64) | 语义类型（可空） |
| `required` / `nullable` / `empty_allowed` | BOOLEAN | 必填 / 允许 NULL / 允许空值 |
| `observed_constraints` | JSONB | 观测约束（学习侧事实） |
| `recommended_constraints` | JSONB | 推荐约束（系统建议） |
| `confirmed_constraints` | JSONB | 确认约束（人工定案，正式检测依据） |
| `sensitivity_level` | VARCHAR(32) | 敏感级别，默认 `UNKNOWN`（自动标注机制见本节末尾） |
| `confidence` | DOUBLE | 置信度 |
| `created_at` | TIMESTAMPTZ | 创建时间 |

索引：`idx_api_parameter_models_version (model_version_id, direction)`（迁移第 142 行）；
身份键索引 `ux_api_parameter_models_identity (model_version_id, direction, location,
structured_path, parameter_name)`（迁移 000028，唯一；对齐任务书第十三章组合标识，
避免嵌套同名叶字段如 `buyer.name`/`seller.name` 误合并；既有库若已有重复行则退化为
同名普通索引 `idx_api_parameter_models_identity` 并 WARNING，物化幂等不依赖索引唯一性）。
三层约束均为自由键值 JSONB，默认 `'{}'`；Go 侧统一经 `decodeConstraints` 解析，
空值按空对象处理（`parameters.go:70-76`）。

**敏感级别自动标注（2026-08 补）**：三条物化路径均不写 `sensitivity_level`（落库默认
`UNKNOWN`）。学习调度 Sweep 每轮在参数统计画像刷新后调用
`PropagateSensitivityLevels`（`server/internal/apimodels/sensitivity_propagate.go`）自动标注，
两个回写来源均只补 `UNKNOWN` 行、不覆盖人工已定级别，聚合后一次 UPDATE 保证幂等可重跑：

1. **敏感字段台账回写**：`api_sensitive_fields`（网关敏感检测落库，键为
   endpoint_id+direction+structured_path，`structured_path` 形如 `query.phone` /
   `json.user.email`）按「参数名 = 台账路径末段 + 参数位置由首段映射
   （query→QUERY，json/body/form→BODY，header→HEADER，cookie→COOKIE）」匹配
   REQUEST 参数行；`data_type` → 级别映射：`credential`/`bank_card`/`id_card` → HIGH，
   `phone`/`email` → MEDIUM，其他非空 → LOW；同名参数被多版本/多端点台账行重复
   命中时取最高级；
2. **语义兜底**：`semantic_type` 为 `secret`/`token`/`id_card`/`bank_card` → HIGH，
   `phone`/`email` → MEDIUM。

**约束词汇（已钉死，snake_case）**：`min_length` / `max_length`（字符串长度，字符数）、
`minimum` / `maximum`（数值上下界）、`enum`（字符串数组，非空）。读取侧宽容：
只认这套词汇，未知键忽略；约束值解析失败跳过该条（不致命）；空枚举按解析失败处理
（防配置笔误放大为全量误阻断）。该词汇是「管理面编辑 → 发布下发 → 网关检测 → 前端展示」
全链路的共同契约（网关侧常量见 `gateway/dynamic_security/detectors/schema.go`）。

### 3.2 api_parameter_statistics（统计画像）

建表定义见迁移第 145-156 行：`parameter_id` 唯一外键（与参数行 1:1，级联删除），
字段为 `sample_count`、`min_length`、`max_length`、`min_value`、`max_value`、
`distinct_count`、`example_hashes`（JSONB 样本哈希数组）、`updated_at`。
样本以哈希留存（`example_hashes`），不落明文敏感值，与
`api_learning_samples.sample_hash`、`api_endpoint_path_segments.sample_hashes`
同一脱敏纪律。

### 3.3 api_parameter_relations（条件关系）

建表定义见迁移第 159-169 行：`model_version_id` 限定关系在版本内闭合；
`source_parameter_id` / `target_parameter_id` 指向同版本两个参数；
`relation_type` 取值为 `REQUIRES` / `EXCLUDES` / `CO_OCCURS`（迁移注释口径）；
`condition`（JSONB）承载条件表达式，`confidence` 为置信度。
对应任务书第二十二章"条件出现关系只生成候选、人工确认后才用于正式检测"的要求，
表内不设计自动生效标记。

## 四、三层约束模型

任务书第十六章要求正式约束区分 `observed` / `recommended` / `confirmed`，且
"不得直接把观察最大值作为阻断上限"。实现将三层约束建模为同一张表上的三个 JSONB 列：

- **observed**：学习过程观察到的事实（长度区间、值域、出现率等），只增不改语义；
- **recommended**：系统基于观测给出的建议约束，供管理员一键采纳或编辑；
- **confirmed**：人工确认的正式约束。正式模型冻结后，偏离只产生风险结论，
  不反向扩大 confirmed（对应任务书 2.6"动态学习不等于自动放宽"）。

确认态的表达：000018 迁移未设独立的确认标记列，代码注释明确"确认态以
confirmed_constraints 非空为准"（`parameters.go:135-137`）。

## 五、确认流程（采纳推荐约束）

管理面两条写路径均在 `server/internal/apimodels/parameters.go`：

1. **整体采纳**：`ConfirmParameter` 执行
   `confirmed_constraints = recommended_constraints` 的整体拷贝；推荐为空时返回
   `ErrEmptyRecommended`（HTTP 400），避免「采纳成功」却仍无下发依据；
2. **编辑确认**：`UpdateParameterConfirmed` 更新 `required` / `nullable` /
   `empty_allowed` / `sensitivity_level` / `semantic_type`；`confirmed_constraints`
   仅在请求体显式携带时写入（省略保留库中既有值，显式 `{}` 清空），
   `sensitivity_level` 为空时归一为 `UNKNOWN`；`semantic_type` 用指针区分
   「省略（保留原值）」与「显式空串（清空）」。

参数行的产生（P0-2）：`Store.Confirm` 确认模型为 FORMAL 时，**同事务**由版本
`schema_json`（字段路径 → 类型）物化 `direction=REQUEST`、`location=BODY` 的
参数行（`materializeRequestParameters`，`parameters.go`）：`structured_path` 为
字段路径，`parameter_name` 取末段名（去 `[]` 标记），`base_type` 由 schema 类型
词汇映射到网关粗类型词表（`integer→number`、`boolean→bool` 等，未识别词汇小写
原样保留），三层约束均为 `'{}'`、`sensitivity_level=UNKNOWN`、`confidence=1.0`。
物化按 `structured_path` 先查后插幂等（000028 唯一索引含 structured_path+parameter_name
兜底；Confirm 持有版本行 FOR UPDATE 锁，同版本物化串行），schema 为空时跳过不报错。
QUERY/HEADER 等位置的参数行仍由学习链路写入（后续工作），本物化只覆盖请求体字段。

HTTP 层（`server/internal/apimodels/handler.go`）：

- 四个参数接口按任务书 51.3 注册（`handler.go:43-46`），读接口要求
  `api_parameter.read`，两条写路径要求 `api_parameter.edit`；
- `PATCH` 请求体上限 8192 字节（`handler.go:330`），先读后写，
  参数不存在返回 404（`handler.go:334-341`）；
- 两条写路径均写操作审计（模块 `api_security`）：`PATCH` 记录必填性、敏感级别与
  语义类型前后摘要（`handler.go:354-356`）；`POST .../confirm` 审计备注固定为
  "采纳推荐约束为确认约束"（`handler.go:382-383`）。

## 六、关键设计决策

1. **参数挂版本、不挂API**。版本是确认/冻结的最小单元，参数随版本快照，
   重新学习产生新版本时旧版本参数原样保留，支持版本差异对比与回退。
2. **三层约束同表同构**。三层约束同为 JSONB，确认即列间拷贝，数据模型上不引入
   第三张"正式约束表"；确认语义由"confirmed 非空 + 版本状态机（FORMAL 不可变）"
   共同保证。
3. **确认接口只做约束定案，不触碰观测数据**。`UpdateParameterConfirmed` 不更新
   `observed_constraints` 与 `recommended_constraints`，观测事实与人工定案分离。
4. **样本不落明文**。统计画像只保留 `example_hashes`，与任务书 50.4
   "不得默认保存完整敏感值"一致。
5. **写操作全量审计**。参数约束属于检测依据，任何变更留前后摘要，满足任务书
   第五十二章权限与审计要求。

## 七、当前实现范围与限制

以下为截至本文件撰写时的真实实现边界，逐项可对照代码核实：

- **参数行的自动生成方：FORMAL 确认物化（P0-2 已接通）**。模型版本确认
  FORMAL 时，同事务从该版本 `schema_json`（字段路径 → 类型）物化
  `api_parameter_models` 行（`materializeRequestParameters`，
  `server/internal/apimodels/parameters.go`；direction=REQUEST、
  location=BODY、base_type 取版本类型词汇、三层约束初始为空），按
  `structured_path` 幂等（迁移 000028 唯一索引含 structured_path+parameter_name）。
  学习任务本身仍不写参数行；由学习样本聚合生成 observed/recommended 约束是后续工作。
- **约束词汇已钉死（snake_case）**：`min_length`/`max_length`（字符串长度）、
  `minimum`/`maximum`（数值区间）、`enum`（字符串数组）。读取侧宽容，
  未知键忽略；历史 camelCase 造数（`maxLength` 等）不被消费。
- **参数级确认约束已接入运行时检测（P0-2）**：
  `ListFormalParameterConstraints`（`parameters.go`，与 `ListFormalSchemas`
  同语义取每API最新 FORMAL；下发条件为 `required=true` **或**
  `confirmed_constraints` 非空）→ 发布通道 `api_parameter_constraints` 字段
  （`gatewayconfig/guard.go` → Caddy /load → 网关 `module.go`）→
  网关 `CheckParamConstraints`（`gateway/dynamic_security/detectors/schema.go`），
  规则：`schema.param_required`（必填缺失，OBSERVE/LOW）、
  `schema.param_length` / `schema.param_enum` / `schema.param_range` /
  `schema.param_type`（数值约束遇到非数值，BLOCK/HIGH；OBSERVE 模式自动降级）。
  QUERY/HEADER 直接用解析值；脱敏头（authorization/cookie/x-api-key）仅做存在性校验；
  BODY 经 `walkJSON` 标量值请求内存活留存（截断 256，值不进证据/事件）。
  PATH/COOKIE 位置暂未消费。
- **Schema 违例专项落库已接通（P0-2）**：schema 类检测明细经采集器 ETL
  写入 `api_schema_violations`（`server/internal/apiruntime/violations.go`，
  request_id 幂等），`GET /api/v1/api-security/violations` 有真实数据。
- **统计画像已有离线写入方（第二批，2026-08）**。`apimodels.Store.RefreshParameterStatistics`
  （`server/internal/apimodels/statistics.go`，learningjobs 每轮 Sweep 后触发）
  聚合 accepted 学习样本，UPSERT `api_parameter_statistics` 的 `sample_count` /
  `example_hashes`（单事务幂等，可安全周期重算）。**如实限制**：参数值不出网关，
  `min_length` / `max_length` / `min_value` / `max_value` / `distinct_count`
  在服务端无真实数据源，保持 NULL 不虚构，待值观测数据通路（网关侧后续批次）
  接通后由对应写入方回填。`api_parameter_relations` 仍仅建表：关系学习
  （REQUIRES/EXCLUDES/CO_OCCURS 候选生成）未实现。
- **observed/recommended 自动生产已落地（第二批，2026-08）**。画像读回后经纯函数
  重算三层约束中的观测/推荐两层（`server/internal/apimodels/recommended.go`）：
  样本量 <100 不生成 recommended；100–999 上限取观测区间 ×2（P95×2，无 P95 用
  观测最大值 ×2），下限取观测最小值；≥1000 允许上限收紧到 P95；enum 仅在
  distinct≤20 且样本 ≥100 且有候选值时生成（去空去重排序）。缺失观测一律保守
  不生成对应约束键——当前无值观测数据源，recommended 多为空，与上一条同一限制；
  confirmed 仍靠人工编辑或一键采纳推荐值，生成方绝不触碰。
- **位置枚举为简化口径**。迁移注释列出 `PATH/QUERY/HEADER/COOKIE/BODY` 五类，
  任务书第十三章的 `JSON_BODY`/`XML_BODY`/`GRAPHQL_ARGUMENT` 等细分位置
  由 `structured_path` 承载，未落为独立枚举约束。
- **无独立确认标记列**。确认态以 `confirmed_constraints` 内容为准（见第四节），
  界面层如需"未确认/已确认"筛选需按该列判定，当前接口未提供该过滤条件。

## 八、与任务书对应章节

- 第十三章（通用参数标识）：方向 / 位置 / 结构化路径 / 字段名的组合标识，
  经"API → 版本 → 参数"归属实现；
- 第十四章（参数基础类型）：`base_type` 列；观察 / 推荐 / 确认三分由三层约束列表达；
- 第十五章（参数语义类型）：`semantic_type` 列——画像刷新时按词表启发式填充空值
  （id/uuid/email/phone/token/secret/money；2026-08 扩充 captcha、username、
  id_card（idcard/id_card/sfz）、bank_card（bank_card/card_no/cardno）及
  `%token%`/`%api_key%`/`%password%`/`%passwd%`/`%mobile%`/`%phone%` 等 LIKE 变体，
  captcha 分支先于 token/key 类），人工可经 PATCH `semantic_type` 修改或清空
  （前端编辑抽屉为 AutoComplete 自由输入 + 预设选项）；
- 第十六至二十一章（各类参数微模型）：三层约束 JSONB 为承载结构，统计画像表
  对应长度/值域/基数画像；
- 第二十二、二十三章（存在性与条件关系、字段间关联）：`api_parameter_relations`；
- 第三十章（人工确认与冻结）：确认流程见本文第五节，版本冻结语义见
  `server/internal/apimodels/store.go`（FORMAL 不可变）；
- 50.3（`api_parameter_models`）、50.4（样本脱敏口径）、51.3（参数接口）、
  第五十二章（`api_parameter.read` / `api_parameter.edit` 权限点，迁移 000019 种子）。

Copyright © 聚信得仁
All Rights Reserved.
