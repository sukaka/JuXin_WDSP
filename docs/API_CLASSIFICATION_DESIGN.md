# API 用途分类设计（阶段8 / WDSP）

## 一、目的与范围

本文档描述阶段8 API 用途分类体系：多维分类维度、分类来源（AUTO / MANUAL / AI）、
分类锁定机制与自动分类启发式。覆盖三张表与一个端点标记：

- `api_classifications`：内置分类目录；
- `api_classification_dimensions`：端点分类维度（多维，每端点每维度一行）；
- `api_custom_taxonomies`：企业自定义分类法；
- `api_endpoints.classification_locked`：人工分类后的覆盖保护锁。

设计前提对应任务书第 2.3 条"Web 与 API 不采用互斥分类"与第三十四章
"不得仅保存单一分类"：一个端点可同时持有多个维度的分类值，分类是标签集合而非
单选枚举。

## 二、架构与数据流

```text
自动分类（AUTO）
  POST /api/v1/api-security/endpoints/{id}/classify   （api_asset.edit）
    → apiassets.Store.AutoClassify（事务 + FOR UPDATE）
    → classifyByPath(method, normalized_path) 启发式
    → upsert api_classification_dimensions（source='AUTO'）

人工分类（MANUAL）
  PUT /api/v1/api-security/endpoints/{id}/classification   （api_classification.manage）
    → apisecurity.Store.SetEndpointClassification（单事务）
    → 逐维 upsert（source='MANUAL', confidence=1）
    → api_endpoints.classification_locked = TRUE

分类法维护
  GET  /api/v1/api-security/classifications   （api_classification.read，内置+自定义合并）
  POST /api/v1/api-security/classifications   （api_classification.manage，新增自定义维度值）
```

锁定语义：人工分类后 `classification_locked=TRUE`，此后自动分类调用返回
`ErrClassificationLocked`（HTTP 409），自动结果不得覆盖人工结论（对应任务书 8.3
"人工锁定后，自动识别不得覆盖"的同类约束在分类域的落地）。

## 三、数据结构

### 3.1 api_classifications（内置分类目录）

`server/migrations/000018_stage8_full_schema.up.sql:194-201`：
`code`（唯一）、`name`、`description`、`is_builtin`、`created_at`。
Go 结构体 `ClassificationItem` 见 `server/internal/apisecurity/store.go:29-36`。
当前迁移不含种子数据，目录行由后续数据迁移或管理面维护补充。

### 3.2 api_classification_dimensions（端点分类维度）

迁移第 204-214 行：

| 列 | 说明 |
|----|------|
| `endpoint_id` | 所属端点，FK 级联删除 |
| `dimension` | 维度名：`PURPOSE` / `DATA_TYPE` / `EXPOSURE` / `CUSTOM:*`（迁移注释口径）；实现另使用 `ACCESS`（见 4.1） |
| `value` | 维度值（如 `AUTH`、`TRADE`、`READ`） |
| `source` | 来源：`AUTO` / `MANUAL` / `AI` |
| `confidence` | 置信度（人工写入固定为 1） |
| `updated_at` | 最近更新时间 |

约束：`UNIQUE (endpoint_id, dimension)`——同一端点同一维度仅一行，重复写入即
upsert 覆盖。Go 结构体 `ClassificationDimension` 见
`server/internal/apisecurity/store.go:116-122`。

### 3.3 api_custom_taxonomies（自定义分类法）

迁移第 217-225 行：`dimension + value` 唯一，`description`、`created_by`、
`created_at`。承载企业自有维度值（任务书 34.4"新增分类/企业分类树"的最小落地）。

### 3.4 classification_locked

`api_endpoints` 列（迁移第 19 行），默认 FALSE；人工分类事务内置 TRUE
（`server/internal/apisecurity/store.go:170`）。

## 四、自动分类启发式

### 4.1 classifyByPath 规则表

启发式函数 `classifyByPath(method, path)`（`server/internal/apiassets/store.go:784-817`）
按路径小写子串匹配产出三个维度，SQL 仓储与内存仓储共用同一函数：

| 维度 | 规则 | 值（置信度） |
|------|------|--------------|
| PURPOSE | 含 `/login`、`/signin`、`/auth`、`/token`、`/captcha` | `AUTH`（0.7） |
| PURPOSE | 含 `/pay`、`/order`、`/trade`、`/billing` | `TRADE`（0.7） |
| PURPOSE | 含 `/upload`、`/file`、`/download`、`/export` | `FILE`（0.7） |
| PURPOSE | 含 `/admin`、`/manage` | `ADMIN`（0.7） |
| PURPOSE | 含 `/user`、`/account`、`/profile` | `USER_MGMT`（0.6） |
| PURPOSE | 含 `/search`、`/query`、`/list` | `QUERY`（0.6） |
| PURPOSE | 以上均未命中 | `GENERAL`（0.5） |
| EXPOSURE | 含 `/public`、`/openapi`、`/webhook`、`/callback` | `PUBLIC`（0.7） |
| EXPOSURE | 否则 | `INTERNAL`（0.5） |
| ACCESS | 方法为 GET / HEAD | `READ`（0.9） |
| ACCESS | 其余方法 | `WRITE`（0.9） |

PURPOSE 分支按 `switch` 顺序首个命中生效（`/auth` 优先于 `/user` 等）。

### 4.2 AutoClassify 事务流程

`server/internal/apiassets/store.go:565-598`：

1. 开事务，`SELECT ... FOR UPDATE` 锁定端点行，不存在返回 `ErrNotFound`；
2. `classification_locked=TRUE` 时返回 `ErrClassificationLocked`（store.go:579-581）；
3. 调 `classifyByPath` 得维度集合，逐维 upsert：`source='AUTO'`、置信度取规则表值，
   冲突时更新 `value/source/confidence/updated_at`（store.go:585-592）；
4. 提交后返回维度集合。

HTTP 层 `Classify`（`server/internal/apiassets/handler.go:373-404`）：锁冲突返回
409"分类已锁定，请先解锁后再执行自动分类"；成功写操作审计（动作 `classify`，
低风险）。内存实现 `MemStore.AutoClassify`（`mem_store.go:311-330`）与 SQL 实现
同语义，供接口测试注入（仓储接口定义见 `repository.go:26`）。

## 五、人工分类与自定义分类法

- **人工覆盖**：`PutEndpointClassification`（`server/internal/apisecurity/handler.go:110-180`）
  校验 `dimensions` 非空、维度名 1-64 字符、值 1-128 字符、同请求维度不重复；
  端点不存在返回 404；写入前后各读一次维度集合，前后 JSON 摘要写操作审计
  （`update`，中风险）。仓储 `SetEndpointClassification`
  （`server/internal/apisecurity/store.go:153-178`）在单事务内逐维 upsert
  （`source='MANUAL'`、`confidence=1`）并置 `classification_locked=TRUE`。
- **分类目录查询**：`ListClassifications`（`store.go:55-93`）合并返回内置分类
  （`is_builtin` 降序、code 升序）与自定义分类法（dimension、value 升序），
  响应形态 `{builtin: [...], custom: [...]}`。
- **自定义分类法创建**：`CreateClassification`（`handler.go:59-97`）校验
  dimension/value 必填与长度，先查重（`ExistsCustomTaxonomy`），冲突返回 409；
  记录创建人并写审计（`create`，低风险）。

## 六、关键设计决策

1. **多维标签而非单一分类**。每端点每维度一行，维度间独立 upsert，
   允许"登录接口 + 敏感接口 + 写接口"并存（任务书 2.3、第三十四章）。
2. **来源与置信度显式化**。`source` 区分 AUTO / MANUAL / AI，人工写入置信度
   固定为 1，自动结果带规则置信度，界面可据此区分展示。
3. **人工优先的锁机制**。锁定不是独立工作流，而是人工分类事务的副产物；
   自动分类在仓储层强制让位（ErrClassificationLocked），不依赖调用方自觉。
4. **启发式与存储解耦**。`classifyByPath` 为纯函数，SQL 与内存仓储共用，
   规则表变更不需要迁移。
5. **自定义分类法与端点维度解耦**。`api_custom_taxonomies` 只是可选值目录，
   不做引用完整性约束，管理员可将任意值写入端点维度。

## 七、当前实现范围与限制

- **内置分类目录无种子数据**。`api_classifications` 已建表但未随迁移插入内置行，
  `ListClassifications` 的 `builtin` 段当前恒为空数组；分类值实际来自启发式
  AUTO 写入与自定义分类法。
- **维度集合为简化口径**。实现使用 `PURPOSE` / `EXPOSURE` / `ACCESS` 三个维度
  （启发式）加任意自定义维度；任务书 34.1 的 16 个内置业务领域、34.2 的
  40 余个操作动作未落成目录数据，`DATA_TYPE` 维度暂无写入方。
- **AI 来源未接线**。`source` 枚举含 `AI`，但当前无任何代码以 AI 来源写入
  分类维度；任务书 34.3 的语义模型证据、调用顺序证据未实现，启发式仅使用
  路径词与 HTTP 方法两类证据。
- **解锁能力仅在仓储层**。`SetClassificationLocked`（`store.go:534`）已在
  Repository 接口中，但没有 HTTP 路由调用它——409 提示语中的"先解锁"
  当前无对应管理面接口，需后续补充。
- **启发式为路径子串匹配**。可能误命中（如 `/author` 命中 `/auth` 分支）；
  置信度为固定档位，不随样本演化。
- **无批量分类接口**。任务书 34.4 的批量调整、风险标签维度未实现。

## 八、与任务书对应章节

- 第三十四章（API 用途多维识别）：多维维度模型与 34.4 人工管理（修改推荐、
  新增分类、锁定分类）的落地；
- 8.3（人工操作）：锁定后自动结果不得覆盖的同类约束；
- 51.1（`POST /endpoints/{id}/classify`）、51.4（分类三个接口与图谱两个接口）；
- 第五十二章：`api_classification.read` / `api_classification.manage`、
  `api_asset.edit` 权限点（迁移 000019 种子）。

Copyright © 聚信得仁
All Rights Reserved.
