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
api_parameter_models ── 1:1 ── api_parameter_statistics（画像，当前无写入方）
  │
  └── api_parameter_relations（版本内参数两两关系，当前无写入方）

管理面（server/internal/apimodels/handler.go）
  GET   /api/v1/api-security/models/{id}/parameters   按版本列出参数
  GET   /api/v1/api-security/parameters/{id}          参数详情
  PATCH /api/v1/api-security/parameters/{id}          编辑确认约束（审计）
  POST  /api/v1/api-security/parameters/{id}/confirm  采纳推荐约束（审计）
```

参数行依附于模型版本而非直接依附端点：`model_version_id` 外键指向
`api_model_versions(id)` 并级联删除（迁移 000018，
`server/migrations/000018_stage8_full_schema.up.sql:125`）。任务书第十三章的通用标识
`api_endpoint_id + direction + location + structured_path + parameter_name` 因此通过
"端点 → 版本 → 参数"两层归属表达：同一端点不同版本各自持有独立参数集合，版本归档
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
| `sensitivity_level` | VARCHAR(32) | 敏感级别，默认 `UNKNOWN` |
| `confidence` | DOUBLE | 置信度 |
| `created_at` | TIMESTAMPTZ | 创建时间 |

索引：`idx_api_parameter_models_version (model_version_id, direction)`（迁移第 142 行）。
三层约束均为自由键值 JSONB，默认 `'{}'`；Go 侧统一经 `decodeConstraints` 解析，
空值按空对象处理（`parameters.go:70-76`）。

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

1. **整体采纳**：`ConfirmParameter`（`parameters.go:137-150`）执行
   `confirmed_constraints = recommended_constraints` 的整体拷贝，用于管理员认可
   推荐约束的场景；
2. **编辑确认**：`UpdateParameterConfirmed`（`parameters.go:113-133`）按输入整体
   覆盖 `required` / `nullable` / `empty_allowed` / `confirmed_constraints` /
   `sensitivity_level`；`confirmed_constraints` 为 nil 时归一为 `'{}'`，
   `sensitivity_level` 为空时归一为 `UNKNOWN`（`parameters.go:114-119`）。

HTTP 层（`server/internal/apimodels/handler.go`）：

- 四个参数接口按任务书 51.3 注册（`handler.go:43-46`），读接口要求
  `api_parameter.read`，两条写路径要求 `api_parameter.edit`；
- `PATCH` 请求体上限 8192 字节（`handler.go:330`），先读后写，
  参数不存在返回 404（`handler.go:334-341`）；
- 两条写路径均写操作审计（模块 `api_security`）：`PATCH` 记录必填性与敏感级别
  前后摘要（`handler.go:354-356`）；`POST .../confirm` 审计备注固定为
  "采纳推荐约束为确认约束"（`handler.go:382-383`）。

## 六、关键设计决策

1. **参数挂版本、不挂端点**。版本是确认/冻结的最小单元，参数随版本快照，
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

- **参数行暂无自动生成方**。`api_parameter_models` 只有读与确认两条路径
  （List/Get/PATCH/confirm）；学习任务与采样管线尚未写入参数行，
  `CreateCandidate` 只写 `api_model_versions.schema_json`（扁平"字段名 → 类型"
  映射，`server/internal/apimodels/store.go:126-141`），不产生
  `api_parameter_models` 记录。参数表的填充（由学习样本聚合生成参数行与
  observed/recommended 约束）是后续工作。
- **统计画像与条件关系仅建表**。`api_parameter_statistics` 与
  `api_parameter_relations` 已在 000018 建表，但无任何 Go 读写方；
  关系学习（REQUIRES/EXCLUDES/CO_OCCURS 候选生成）未实现。
- **三层约束的键集合未固化**。`observed_constraints` 等 JSONB 内部键
  （如任务书第十六章的 P50/P95/熵区间）当前无代码生产或消费，属预留结构。
- **位置枚举为简化口径**。迁移注释列出 `PATH/QUERY/HEADER/COOKIE/BODY` 五类，
  任务书第十三章的 `JSON_BODY`/`XML_BODY`/`GRAPHQL_ARGUMENT` 等细分位置
  由 `structured_path` 承载，未落为独立枚举约束。
- **正式检测不消费参数表**。网关侧 Schema 偏离检测使用 FORMAL 版本的扁平
  `schema_json`（`gateway/dynamic_security/detectors/schema.go:12`），
  经发布通道由 `ListFormalSchemas`（`store.go:497`）下发；参数级 confirmed
  约束（长度/值域/枚举）尚未接入运行时检测。
- **无独立确认标记列**。确认态以 `confirmed_constraints` 内容为准（见第四节），
  界面层如需"未确认/已确认"筛选需按该列判定，当前接口未提供该过滤条件。

## 八、与任务书对应章节

- 第十三章（通用参数标识）：方向 / 位置 / 结构化路径 / 字段名的组合标识，
  经"端点 → 版本 → 参数"归属实现；
- 第十四章（参数基础类型）：`base_type` 列；观察 / 推荐 / 确认三分由三层约束列表达；
- 第十五章（参数语义类型）：`semantic_type` 列（推荐语义类型，人工可改）；
- 第十六至二十一章（各类参数微模型）：三层约束 JSONB 为承载结构，统计画像表
  对应长度/值域/基数画像；
- 第二十二、二十三章（存在性与条件关系、字段间关联）：`api_parameter_relations`；
- 第三十章（人工确认与冻结）：确认流程见本文第五节，版本冻结语义见
  `server/internal/apimodels/store.go`（FORMAL 不可变）；
- 50.3（`api_parameter_models`）、50.4（样本脱敏口径）、51.3（参数接口）、
  第五十二章（`api_parameter.read` / `api_parameter.edit` 权限点，迁移 000019 种子）。

Copyright © 聚信得仁
All Rights Reserved.
