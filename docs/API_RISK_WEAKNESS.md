# API 风险与弱点设计（Risk / Weakness 分离，阶段8 / WDSP，补全任务书 §230 口径）

## 一、目的与范围

本文档描述 API 安全域**风险（Risk）与弱点（Weakness）双中心**的分离语义、生产链路
与生命周期。两者互不混用（对应补全任务书禁止项 #19"风险与弱点混成一类"的正面解法）：

- **Risk（`api_runtime_findings`）= 运行时异常信号**：谁、何时、命中了什么。
  由运行时事件物化而来，处置闭环为 确认→处理→解决/误报/忽略→归档；
- **Weakness（`api_weaknesses`）= 长期缺陷**：需要 确认→指派→整改→复测→关闭
  的弱点，跨天持续跟踪，由周期派生扫描从事件/风险信号中提炼。

覆盖代码：`server/internal/apiruntime/findings.go`（Risk 生产方）、
`server/internal/apisecurity/risk.go`（Risk 状态机与降噪聚合）、
`server/internal/apisecurity/runtime.go`（findings 只读列表）、
`server/internal/apiweakness/`（Weakness 领域/派生/接口）、
迁移 000018（建表）、000036（findings 物化列）、000039（弱点两表）、
000041（弱点/敏感数据权限）、000042（Risk 七态词表与权限）。

## 二、为什么分离

| 维度 | Risk（风险发现） | Weakness（弱点） |
|------|------------------|------------------|
| 语义 | 一次性运行时异常信号 | 长期存在的安全缺陷 |
| 时间尺度 | 单次/多次命中（dedup 累计） | 跨天持续跟踪 |
| 生产方 | 采集器逐事件物化（在线） | Sweeper 周期派生（离线，默认 5 分钟） |
| 闭环 | 确认→处理→解决/误报/忽略→归档 | 确认→指派→整改→复测→关闭 |
| 去向 | 不生成弱点；弱点侧只读本表不回写 | 派生自事件与本表，不回写本表 |

纪律：`apisecurity/risk.go` 只读写 `api_runtime_findings`，不写弱点表；
`apiweakness` 派生只读事件/风险表，不回写。两张表语义不互相污染。

## 三、Risk 中心（api_runtime_findings）

### 3.1 生产方：采集器物化

```text
网关统一运行时事件（JSONL，含检测明细 Details）
  ▼ apiruntime.Collector 逐事件处理（collector.go:386）
recordFindings（findings.go:155）：按物化规则 v1 筛选明细
  ▼ Store.SaveFindings（findings.go:223）
dedup_fingerprint 幂等 upsert → api_runtime_findings
```

- **物化规则 v1**（findings.go:69）：明细 severity ≥ MEDIUM，**或**事件
  final_action ≠ ALLOW（被决策拦截/限速/观察的事件，其全部明细都是风险信号）；
  INFO/LOW 且放行的事件不物化（降噪）；明细缺 severity 时按事件动作物化、
  等级保守落 INFO；
- **finding_type 生成**（findings.go:83-108）：语义覆盖表
  （`lifecycle.new_endpoint`→SHADOW、`lifecycle.deprecated_api_call`→DEPRECATED、
  `resource.unauthenticated_object_access`→BOLA_UNAUTHENTICATED_OBJECT_ACCESS），
  未覆盖规则走机械映射（rule_id 大写下划线化；rule_id 缺失或非字母开头时以
  detector 名兜底/加前缀），保证可读且稳定；
- **dedup**（findings.go:210-217 + 迁移 000036 唯一索引）：
  `dedup_fingerprint = sha256(endpoint_id + \x1f + finding_type + \x1f + subject_id)`；
  命中则 count+1 并刷新 last_seen_at/updated_at（**不覆盖首次证据与标题**），
  未命中插入新行。API未解析时以 `"key:"+endpoint_key` 兜底，保证指纹稳定非空
  （空指纹会让 ON CONFLICT 永不命中，PG NULL 互不相等）；
- **主体**（findingSubject，findings.go:112）：有身份指纹 → `IDENTITY`；
  否则有来源指纹 → `IP`；皆无 → 空。主体只落指纹，永不落明文 IP/凭据；
- **证据脱敏**（sanitizeEvidence，findings.go:133）：白名单键（field/param/name/
  type/want/got/constraint/location/object_type）附值（截断 128 字符），
  白名单外只保留键名列表——参数原始值永不落库；
- 物化失败仅记日志，不影响采集主流程（与落样同一纪律）；未注入 saver 时零开销跳过。

### 3.2 状态机与处置

迁移 000042 将 status 词表从注释约定的四态（OPEN/ACKNOWLEDGED/RESOLVED/
FALSE_POSITIVE）升级为七态 CHECK 约束（存量 OPEN→NEW、ACKNOWLEDGED→IN_PROGRESS）：

```text
NEW ──CONFIRM──▶ CONFIRMED ──START──▶ IN_PROGRESS
 │                  │ │                  │ │
 │                  │ ├──RESOLVE────────▶ │
 │                  ▼ ▼                   ▼ ▼
 │              RESOLVED ◀─────────────────┘
 ├─FALSE_POSITIVE▶ FALSE_POSITIVE        （均须填 note）
 ├─IGNORE▶ IGNORED
 └─ARCHIVE（仅 RESOLVED/FALSE_POSITIVE/IGNORED）▶ ARCHIVED（终态）
```

迁移表即代码事实（`risk.go:50-57` 的 `riskTransitions`），表外组合一律非法
（ErrInvalidRiskTransition，HTTP 400）。处置经 `TransitionFinding`（risk.go:243）
一个事务完成：行锁读当前状态 → 状态机校验 → 更新状态 + 处置记录合并进
`detail.handling`（JSONB 浅合并，保留首次命中上下文）。活动状态（未闭环）口径为
NEW/CONFIRMED/IN_PROGRESS（`IsRiskActiveStatus`，态势统计使用）。

权限点（000042 种子）：`api_risk.read` / `api_risk.handle`；SECURITY_ADMIN 全量、
AUDIT_ADMIN 只读、SYSTEM_ADMIN 不授权（风险主体含身份/来源指纹，运维角色不开放）。

接口（`apisecurity/routes.go:33-52`，统一前缀 `/api/v1/api-security`，路由层强制
权限点 + 操作审计）：

| 接口 | 权限 | 语义 |
|------|------|------|
| `GET /findings` | api_runtime.read | 只读列表（既有，finding_type/severity/status 过滤） |
| `GET /findings/summary` | api_risk.read | 降噪聚合（主体/API/类型三视图） |
| `GET /findings/{id}` | api_risk.read | 详情（含 detail.handling 处置记录与关联请求） |
| `POST /findings/{id}/confirm` | api_risk.handle | 确认（NEW→CONFIRMED） |
| `POST /findings/{id}/start` | api_risk.handle | 开始处理（CONFIRMED→IN_PROGRESS） |
| `POST /findings/{id}/resolve` | api_risk.handle | 解决（→RESOLVED，必填处置说明） |
| `POST /findings/{id}/false-positive` | api_risk.handle | 标记误报（→FALSE_POSITIVE，必填原因） |
| `POST /findings/{id}/ignore` | api_risk.handle | 忽略（→IGNORED，接受风险） |
| `POST /findings/{id}/archive` | api_risk.handle | 归档（→ARCHIVED，终态） |

领域层 `RiskRepository`（GetFinding / TransitionFinding / SummarizeFindings /
ListRelatedRequestIDs）有 SQL 与内存双实现（risk.go / risk_mem.go），便于诚实单测。

### 3.3 降噪聚合与关联

- `SummarizeFindings`（risk.go:292）：主体 / API / 类型三视图，各按
  最高严重度+累计命中排序取头部 100 桶——风险中心只看头部风险；
- `ListRelatedRequestIDs`（risk.go:374）：按 endpoint_key 点查最近事件
  （IDENTITY 主体附带身份指纹过滤），返回近似关联的近期请求 ID——dedup upsert
  只保留首次 request_id，故为"同API（同身份）近期请求"的近似关联，
  **非精确命中回放**（如实标注）。

## 四、Weakness 中心（apiweakness 包）

### 4.1 表结构（迁移 000039）

- `api_weaknesses`：endpoint_id（API删除后弱点保留为历史）、weakness_code、
  category（AUTHN/LIFECYCLE/SENSITIVE/SCHEMA）、severity、status、
  evidence_json（仅脱敏摘要：规则/计数/窗口/时间，不落原始请求数据）、
  first_seen/last_seen、trigger_count、owner/due_date/fixed_at/retested_at；
  派生 upsert 锚点：`(endpoint_id, weakness_code)` 唯一；
- `api_weakness_actions`：整改/复测历史，**只增不改**（与操作审计互补），
  action 取值 DERIVED/CONFIRM/ASSIGN/MARK_FIXED/RETEST_PASS/RETEST_FAIL/IGNORE/
  ARCHIVE/REPRODUCED。

### 4.2 生命周期状态机

```text
NEW ──CONFIRM──▶ CONFIRMED ──ASSIGN──▶ TO_FIX ──MARK_FIXED──▶ FIXED
 ▲                                                                │
 │                                                    RETEST_PASS ▼ RETEST_FAIL
 │                                              ARCHIVED ◀──┐     REPRODUCED
 └────────────── IGNORE（NEW/CONFIRMED/TO_FIX/REPRODUCED）──┼──▶ IGNORED
        ARCHIVE（CONFIRMED/TO_FIX/FIXED/REPRODUCED/IGNORED）─┘
```

迁移表见 `weakness.go:111-119`。派生扫描侧联动：同API同 code 再命中则
trigger_count+1、刷新 last_seen 与证据；**原 FIXED 状态自动回 REPRODUCED**
（复测未通过的自动发现通道，actor=system 落 REPRODUCED 动作）。

### 4.3 四规则派生（SweepOnce）

`apiweakness/sweep.go`（main.go 以 5 分钟周期挂接；数据源为
`api_runtime_events` / `api_runtime_findings`，全部API级）：

| 弱点码 | 派生规则 | 分类/严重度 |
|--------|----------|-------------|
| `UNAUTHENTICATED_SENSITIVE_API` | 近 24h 匿名（auth_type 为空）且命中 sensitive 检测器的事件 ≥ 3（可配） | AUTHN / HIGH |
| `DEPRECATED_STILL_CALLED` | 近 24h 存在 `lifecycle.deprecated_api_call` 命中 | LIFECYCLE / MEDIUM |
| `SENSITIVE_IN_QUERY` | 近 24h 存在 `sensitive.in_query` 命中 | SENSITIVE / HIGH |
| `SCHEMA_DRIFT_PERSISTENT` | 同API SCHEMA% 类 finding 首现 ≥3 天且近 24h 仍在出现（仅统计未闭环状态） | SCHEMA / MEDIUM |

写入语义：任一规则取数/落库失败即返回错误（不静默吞错），已写入部分不回滚
（幂等，可下轮重扫）；空表安全（零命中零产出）。

### 4.4 处置接口（8 条，迁移 000041 权限）

统一前缀 `/api/v1/api-security`，路由层强制权限点 + 操作审计
（`apiweakness/routes.go`）：

| 接口 | 权限 | 语义 |
|------|------|------|
| `GET /weaknesses` | api_weakness.read | 列表（status/severity/category/endpoint 过滤） |
| `GET /weaknesses/{id}` | api_weakness.read | 详情 + 整改历史 |
| `POST /weaknesses/{id}/confirm` | api_weakness.handle | 确认（NEW→CONFIRMED） |
| `POST /weaknesses/{id}/assign` | api_weakness.handle | 指派/改派（→TO_FIX，owner+due_date） |
| `POST /weaknesses/{id}/fixed` | api_weakness.handle | 标记整改完成（TO_FIX→FIXED） |
| `POST /weaknesses/{id}/retest` | api_weakness.handle | 复测（PASS→ARCHIVED / FAIL→REPRODUCED） |
| `POST /weaknesses/{id}/ignore` | api_weakness.handle | 忽略（接受风险/误报） |
| `POST /weaknesses/{id}/archive` | api_weakness.handle | 人工归档关闭 |

每次流转写一条 `api_weakness_actions`（actor=操作者用户名）+ 一条操作审计
（module=api_security，object_type=api_weakness，before/after 记录 status 变化）。
三权口径（000041）：SECURITY_ADMIN 全量、AUDIT_ADMIN 只读、SYSTEM_ADMIN 仅弱点只读。

## 五、关键设计决策

1. **dedup 只保留首次证据**：同指纹命中只计数与刷新时间，首次标题/证据/请求
   上下文不改写——保证"第一次看到什么样"可溯源，代价是详情关联为近似回放
   （见 3.3）；
2. **弱点证据只存摘要**：规则码/命中数/窗口/首末时间，不落任何原始请求数据，
   与 findings 证据白名单同一脱敏纪律；
3. **FIXED 再命中自动 REPRODUCED**：整改有效性由派生扫描持续验证，
   复测未通过不依赖人工发现；
4. **状态机即代码事实**：两侧迁移表（riskTransitions / transitions）是唯一权威，
   非法迁移 400 如实报错，不静默改写；
5. **SYSTEM_ADMIN 不开放 Risk**：风险主体含身份/来源指纹，运维角色只见弱点
   工单（000042 注释口径）。

## 六、当前实现范围与限制

1. Risk 物化规则为 v1（severity≥MEDIUM 或动作非 ALLOW），无例外/抑制配置；
   误报降噪靠 FALSE_POSITIVE/IGNORED 处置，非自动规则；
2. 弱点派生仅四条规则，全部API级；无应用级/主体级弱点；
4. 弱点指派仅 owner 文本 + due_date，无通知/工单系统集成；
5. `systemalerts` 运维告警闭环与 API 安全域仍未接线（无 API 安全告警类型/
   静默计划/通知渠道，P1-08 未实现）；
6. 前端风险/弱点操作界面已随第二波前端分片接通（findings 行内确认/解决/误报、
   weaknesses 确认/指派/整改/复测等处置操作，含页面单测）。

**集成注意（状态词表对齐）**：迁移 000042 把 status 升级为七态（OPEN→NEW、
ACKNOWLEDGED→IN_PROGRESS）。`apiruntime/findings.go`（插入 `status=NEW`）与
`apisecurity/runtime.go`（GetPosture 统计 `NEW/CONFIRMED/IN_PROGRESS`）已对齐
新词表；成稿时仍存以下旧词表代码点，合波时须由集成方统一对齐，否则 000042 的
CHECK 约束生效后查询侧恒查空、种子插入直接报错：

- `apiweakness/sweep.go:269`：SchemaDriftPersistent 仍查
  `'OPEN','ACKNOWLEDGED'`——存量被 000042 改写后该条件恒不命中，
  SCHEMA_DRIFT_PERSISTENT 规则将断流；
- `server/tests/stage8_api_security_test.go:1070-1071`：findings 种子仍用
  `'OPEN'`，CHECK 生效后插入报错。

## 七、与任务书对应章节

- 补全任务书 §230（风险弱点文档口径）：本文档；
- 补全任务书 §77-82（Risk 状态机/详情字段/降噪、Weakness 生命周期/retest_history）：
  第三、四节；
- 禁止事项 #19（Risk/Weakness 混成一类）：第二节分离语义；
- 现状盘点：docs/API_SECURITY_CURRENT_STATE.md P0-11（Shadow/Zombie）/ P0-13；
- 相邻文档：docs/API_AUDIT_TRACE.md（事件→风险→弱点溯源链）、
  docs/API_SECURITY_GRAPH.md（风险信号图谱化远景）。
