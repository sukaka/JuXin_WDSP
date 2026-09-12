# API 模型版本体系设计（阶段8 / WDSP）

## 一、目的与范围

每个 API的防护基准以**模型版本**形式管理：候选版本经人工评审确认后冻结为
正式版本（FORMAL），正式版本不可变，经发布通道下发网关作为 Schema 偏离检测的
基准。本文覆盖：

- 版本状态机与迁移规则（`server/internal/apimodels/store.go`）；
- 版本号、内容哈希、差异对比；
- 确认（Confirm）、激活（Activate）与API当前模型指针；
- 发布下发（`ListFormalSchemas` → 网关 `api_formal_schemas`）；
- 网关侧同语义的内存原型（`gateway/dynamic_security/learning/version.go`）。

运行时如何使用正式模型见 `docs/API_SCHEMA_PROTECTION.md`。

## 二、数据模型与状态机

版本记录（`api_model_versions`，迁移 000016 建、000018 对齐任务书 §50.2 扩充，
`apimodels/store.go:44-66`）：

```text
id / api_endpoint_id / endpoint_key / version_number / parent_version_id /
request_schema_id / response_schema_set_id / status / schema_json（字段→粗类型）/
content_hash / change_summary / sample_count / valid_sample_count /
excluded_sample_count / confidence / created_reason / created_by / created_at /
confirmed_by / confirmed_at / activated_at
```

状态机（`store.go:21-28`，全部迁移经事务 + `FOR UPDATE` 行锁）：

```text
                 CreateCandidate
                       ▼
                 CANDIDATE ──SubmitReview──► IN_REVIEW
                    │  ▲                        │
        Confirm     │  │ SubmitReview           │ Confirm
        (√,见下)    │  └────────────────────────┘
                    ▼
        ┌─────── FORMAL ──（新 Confirm 发生时旧 FORMAL）──► SUPERSEDED
        │           │
        │           │ Activate（仅 FORMAL）→ 置 api_endpoints.current_model_version_id
        │           ▼
        └── Archive ◄──（FORMAL / SUPERSEDED / REJECTED）──► ARCHIVED

CANDIDATE / IN_REVIEW ──Reject──► REJECTED ──Archive──► ARCHIVED
```

迁移规则与校验：

- `Confirm`（`store.go:158-199`）：仅 CANDIDATE/IN_REVIEW 可确认
  （否则 `ErrNotCandidate`）；同事务内把同API旧 FORMAL 降级 SUPERSEDED，
  `version_number` 取同API `MAX+1`，记录 `confirmed_by/confirmed_at/activated_at`；
- `SubmitReview` / `Reject`（`store.go:202-250`）：状态迁移同时写
  `api_model_reviews`（action=SUBMIT/REJECT，含评审人与评论）；
- `Activate`（`store.go:254-284`）：仅 FORMAL；刷新 `activated_at` 并把API
  `current_model_version_id` 指向本版本；
- `Archive`（`store.go:287-315`）：FORMAL/SUPERSEDED/REJECTED 可归档；
- 非法迁移统一 `ErrInvalidTransition`，HTTP 层映射 409（`handler.go:410-427`）。

## 三、版本号与内容哈希

- **版本号**：确认时按API内 `MAX(version_number)+1` 赋值（`store.go:176-180`）；
  候选期 `version_number` 为迁移默认值 1，确认后才获得真实序号——版本号表达
  「第几个被确认的正式版本」。
- **内容哈希**：`sha256(endpoint_key + 排序后的字段-类型对)`（`store.go:476-493`），
  键序排序保证同内容同哈希，可用于幂等比对与完整性校验。
- **样本统计列**（`sample_count/valid_sample_count/excluded_sample_count`）与
  `confidence` 已建，当前手工创建的候选默认 0，待学习链路接通后填充
  （见 `docs/API_LEARNING_SECURITY.md`）。

## 四、差异对比

`Diff(id, otherID)`（`store.go:341-363`）计算 `other → id` 的字段级差异：

```text
SchemaDiff{ added[], removed[], type_changed[{field, from, to}] }
```

- 纯函数计算（`computeSchemaDiff`，`store.go:366-387`），输出按字段名排序，
  结果确定；
- 差异 upsert 进 `api_model_diffs`（`(model_version_id, other_version_id)` 唯一），
  重复对比刷新结果不产生重复行；
- 接口：`GET /api/v1/api-security/models/{id}/diff/{other_id}`
  （权限 `api_model.read`，`handler.go:35`）。

## 五、FORMAL 不可变与确认操作

- **仓储层不提供任何修改 FORMAL 内容的接口**：版本内容（schema_json）只有
  `CreateCandidate` 写入；状态迁移之外的更新方法不存在，`ErrFormalImmutable`
  已定义（`store.go:35-36`）。变更只能走「新候选 → 确认」产生新版本。
- **确认留痕**：`confirmed_by/confirmed_at` 落库，操作审计记录前后状态与新版本号
  （`handler.go:177-200`，风险等级 MEDIUM）；激活为 HIGH（`handler.go:248-249`）。
- 确认接口权限 `api_model.confirm`、评审 `api_model.review`、激活
  `api_model.activate`、归档 `api_model.archive`，逐路由强制校验
  （`handler.go:28-47`；权限种子迁移 000019）。
- 创建候选：`POST /api/v1/api-security/endpoints/{id}/models`，body 为
  `{schema: {字段: 类型}, change_summary}`，schema 非空校验、请求体限 64KB
  （`handler.go:70-106`）；`created_reason` 当前恒为 `manual`。

## 六、发布下发

```text
管理员 Confirm（FORMAL 冻结）
  → （可选）Activate（API current_model_version_id 指向该版本）
  → 触发配置发布（API 策略页发布按钮 / 既有发布通道）
  → guardconfig.BuildGuardConfig 调 ListFormalSchemas（store.go:497-520）：
      SELECT DISTINCT ON (endpoint_key) endpoint_key, schema_json
      FROM api_model_versions WHERE status='FORMAL'
      ORDER BY endpoint_key, confirmed_at DESC NULLS LAST
  → Caddy JSON api_formal_schemas → 网关重载生效
  → 配置快照存 access_control_versions（含 api_* 段，RedactGuardConfig 脱敏），
    回滚时整份还原（provider.go:377-402、410-421）
```

要点：

- **下发以 status=FORMAL 为准**，与 `current_model_version_id` 指针解耦：
  Activate 影响管理面「当前模型」指向，下发取 FORMAL 集合；正常流程两者一致
  （Confirm 即置 activated_at），异常分叉时以 FORMAL 为防护基准；
- 仅 API 动态防护开启时下发（`provider.go:302-310`），关闭时 JSON 无此键；
- 同一 endpoint_key 正常至多一个 FORMAL（Confirm 事务保证）；`DISTINCT ON` +
  最近确认者优先是对脏数据的防御性兜底。

## 七、网关侧内存原型

`gateway/dynamic_security/learning/version.go` 提供同语义的进程内 `Store`
（单测与语义验证用）：

- 状态仅 `CANDIDATE / FORMAL / SUPERSEDED`（`version.go:24-28`）；
- `CreateCandidate` 以内容哈希生成候选 ID（`cand-<hash前12位>`，version.go:70-82）；
- `Confirm` 仅候选可确认、旧 FORMAL 自动 SUPERSEDED、记 `FrozenAt`
  （version.go:85-105）；
- `MutateFormal` 对 FORMAL 一律返回 `ErrFormalImmutable`（version.go:123-136），
  测试直接断言「正式模型不可变」这一不变量；
- `Observe` 当前为占位实现：只累计观测计数，不生成候选（version.go:61-67，
  如实披露：自动候选生成在演进中，见 `docs/API_LEARNING_SECURITY.md`）。

管理面（PostgreSQL 仓储）为生产实现；网关内存原型用于引擎单测表达同一组
不变量（候选可确认、正式不可变、确认即取代），两者语义对齐、实现独立。

## 八、关键设计决策

1. **确认即冻结、变更只新增版本**。FORMAL 无任何内容更新路径，满足任务书
   §2.6「动态学习不等于自动放宽」与 §30「确认后正式模型不可自动变化」；
   审计与回溯只需按版本链读取。
2. **版本号在确认时分配**。候选可以随意创建/废弃，只有被确认的才占用序号，
   版本号序列直接反映「正式基准的演进史」。
3. **状态迁移全部事务化 + 行锁**。Confirm 同时改两行（旧降级、新升级），
   并发确认同一API的两个候选不会产生双 FORMAL（`store.go:159-198`）。
4. **下发读 status 而非指针**。`ListFormalSchemas` 以 FORMAL 状态为准，
   避免指针字段被误改后直接改变网关防护基准；指针（Activate）是管理面导航
   语义，防护语义由状态保证。
5. **diff 落库且幂等**。对比结果可缓存复用、可审计；`(id, other_id)` 唯一约束
   防重复行。
6. **评审记录独立成表**。SUBMIT/REJECT 均写 `api_model_reviews`，评审轨迹
   不随版本状态覆盖而丢失。

## 九、当前实现范围与限制

1. **候选只能手工创建**：任务书 §28 的「新参数/类型变化/达到学习周期等 17 类
   自动生成条件」未实现，`created_reason` 仅使用 `manual`（列注释中的
   `learning_threshold/relearn/import` 为预留值）。
2. **重新学习分支（任务书 §31）未实现**：没有 V4-LEARNING 式的分支实体；
   现行等价做法是管理员新建候选——期间 FORMAL 继续生效（偏离检测基准不变），
   候选确认后旧 FORMAL 自动 SUPERSEDED，满足「重新学习不影响正式版本」的
   核心保证，但缺少独立的样本收集分支与对比工作流。
3. **diff 仅字段级**：任务书 §29 的基本信息/响应/行为维度对比未实现；
   响应 Schema 相关列（`response_schema_set_id`/`api_response_schemas`）已建
   无写入方。
4. **参数模型与版本脱钩**：`api_parameter_models` 可按版本查询（51.3 接口），
   但当前无写入方，候选创建不生成参数行；`parent_version_id` 列已建未回填。
5. **版本删除不存在**：废弃走 REJECTED/ARCHIVED，不提供物理删除（与审计
   纪律一致）。
6. **任务书 §27 的状态词表**（LEARNING/REVIEW_PENDING/CONFIRMED/ACTIVE）
   与本实现命名不同（CANDIDATE/IN_REVIEW/FORMAL + Activate），语义映射为：
   REVIEW_PENDING≈IN_REVIEW、CONFIRMED/ACTIVE≈FORMAL+已激活。

## 十、与任务书章节对应

| 本文章节 | 任务书 |
|----------|--------|
| 二、状态机 | §二十七 模型版本机制、§十二 学习状态 |
| 三、版本号/哈希 | §27（版本号、内容哈希） |
| 四、diff | §二十九 版本差异对比（字段级子集） |
| 五、不可变 | §三十 人工确认与冻结、§2.6 |
| 六、发布下发 | §四十七 统一策略模型、§三十二 偏离检测基准 |
| 九、限制 2 | §三十一 重新学习分支（当前等价做法说明） |

---

Copyright © 聚信得仁
All Rights Reserved.
