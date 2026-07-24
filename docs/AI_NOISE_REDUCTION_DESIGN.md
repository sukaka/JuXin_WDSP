# AI 自动降噪设计（阶段7 增量，WAF + WDSP）

本文档描述九章 WAF V2.0「AI 自动降噪」功能的设计与实现，与实现代码严格一致：

- 核心包：`server/internal/ainoise/`（fingerprint.go / source.go / store.go / mem_store.go / verdict.go / recommend.go / worker.go）
- Tool：`server/internal/aitools/noise_tools.go`（`noise_cluster.search` / `noise_cluster.get`，全部 READ_ONLY）
- 接口层：`server/internal/aihandlers/noise_handler.go`（9 个端点，路由注册于 `handler.go`）
- 装配：`server/internal/app/app.go`（阶段7装配块内创建 store/source/worker；worker 仅 `cfg.AI.Enabled` 时挂到 App，`StartStage6Workers` 中 `go Run`）
- 数据迁移：`server/migrations/000021_ai_noise_reduction.up.sql`（3 张表 + 2 个权限点）
- 前端：`web/src/pages/ai/noise-reduction/NoiseReductionPage.tsx`、`web/src/api/ai.ts`（`aiNoiseApi`）、路由 `/ai/noise-reduction`、菜单「智能安全运营 → 自动降噪」、事件详情抽屉（`EventDetailDrawer.tsx`）「查看降噪簇」入口

## 1. 定位与目标

安全事件运营中，同一来源对同一 URI 触发同一规则的重复告警构成主要噪音。本功能把窗口内事件按**确定性指纹**聚类为「降噪簇」，在事件列表之外提供折叠视图与计数，让运营人员聚焦新事件；对超阈值簇可选调用 LLM 做误报评分，疑似误报簇生成 DRAFT 降噪推荐进入人工审核。

与代码一一对应的目标：

1. 后台周期扫描（worker），把窗口内未处置事件聚类成簇（`ai_noise_clusters`）并幂等计数；
2. 簇列表 / 详情 / 统计 / 扫描历史查询，簇状态流转（suppress / resolve）；
3. 可选 LLM 误报评分（默认关闭），失败一律降级 UNKNOWN 不致命；
4. 疑似误报簇生成 `ai_recommendations`（DRAFT，同簇去重），供人工审核；
5. WAF / WDSP 双事件源：WAF 读 `security_events`，WDSP 追加 `api_runtime_events`。

## 2. 设计原则与边界

- **AI 只做辅助决策**：自动部分仅限「聚类 + 计数 + 折叠展示 + DRAFT 推荐」。明确不做的事：
  - 不自动修改 `security_events.disposition_status`；
  - 不自动封禁任何 IP；
  - 不自动启用任何例外 / 规则调整；
  - 涉及处置的建议一律写 `ai_recommendations`（`status='DRAFT'`），走既有人工审核流程（`recommend.go`）。
- **确定性优先**：聚类完全由 sha256 指纹决定（无 LLM、无随机性），同一事件任何时刻算出的簇归属一致；LLM 只出现在可选评分环节。
- **降级不致命**：LLM 不可用 / 超时 / 输出非法 → verdict 记 UNKNOWN 并写日志，不影响聚类与计数（`verdict.go`）；单事件源失败记 PARTIAL，单事件 upsert 失败记 PARTIAL 并跳过（`worker.go`）。
- **幂等可重扫**：窗口重叠重复扫描同一事件不重复计数（关联表 `ON CONFLICT DO NOTHING`，`store.go`）。
- **不静默吞错**：错误如实写入 `ai_noise_sweep_runs.error` 并记 slog；`recommend.go` 的写库错误如实返回。
- **最小权限**：读操作 `ai.noise_reduction.use`，手动扫描与设置 `ai.noise_reduction.manage`，逐接口 `RequirePermission` 校验。

## 3. 架构与扫描流程

降噪 worker 是 **AI 模块首个后台任务**，结构照搬 guardjanitor 模式：`Run(ctx)` 内 ticker 周期调度，`SweepOnce(ctx)` 为可独立调用的单次扫描（手动触发与单测共用）。worker 内嵌于管理 API 进程，无独立部署单元。

```text
StartStage6Workers: go Worker.Run(ctx)          （仅 cfg.AI.Enabled 时装配）
        │ 每个 tick：LoadConfig 热读 system_settings（组 ai_noise）
        │ enabled=false → 空转；interval 变更即时生效（t.Reset）
        ▼
SweepOnce（手动触发 POST /api/v1/ai/noise/sweeps 共用，不受 enabled 限制）
  1. 拉取事件（窗口 [now-window, now)，每源上限 5000 条）
     ├─ FetchWAF：security_events，disposition_status IN (UNPROCESSED, ANALYZING)
     └─ FetchAPI：api_runtime_events（仅 WDSP；纯 WAF 形态恒返回空）
     → 两源都失败 = FAILED；单源失败 = PARTIAL
  2. 指纹聚类 UpsertEvent（单事件失败记 PARTIAL，不中断本批）
     → 新建簇 or 幂等关联计数（重复扫描不重复计数）
  3. 可选 LLM 误报评分（llm_verdict_enabled=true 时）
     → ACTIVE 且 event_count ≥ 阈值且 verdict=UNKNOWN 的簇，单次最多 20 个
     → standard 档，JSON 输出；失败降级 UNKNOWN，不致命
  4. 生成 DRAFT 降噪推荐（疑似误报且超阈值的簇，单次最多 20 个）
     → 同簇已有 DRAFT/PENDING_REVIEW 推荐则跳过
  5. 扫描统计落 ai_noise_sweep_runs（SUCCESS / PARTIAL / FAILED）
```

装配要点（`app.go`）：

- `noiseStore = ainoise.NewStore(db)`（SQLStore）；
- `noiseSource = ainoise.NewEventSource(db, cfg.Product.APIDynamicProtectionEnabled())`（WDSP 开关决定 API 源是否生效）；
- `noiseWorker = ainoise.NewWorker(noiseStore, noiseSource, settingsSvc, aiGateway, aitools.NewDraftStore(db))`；
- `aitools.NewNoiseTools(aiRegistry, noiseStore)` 注册 2 个 Tool；
- `if cfg.AI.Enabled { a.noiseWorker = noiseWorker }`——AI 模块整体停用时 worker 不启动。

## 4. 指纹与聚类算法（fingerprint.go）

### 4.1 URI 归一化 `NormalizeURI`

- 去除查询串与 fragment（`?` / `#` 起截断）；空路径归一为 `/`；
- 逐段替换：纯数字段 → `{n}`；UUID 段 → `{uuid}`；≥16 位 hex/hash 段 → `{h}`；
- 幂等：对已归一化的输入再次调用结果不变（占位符不匹配任何替换规则）。

### 4.2 指纹 `Fingerprint`

```text
sha256( source | host(小写,去空白) | normalized_uri | 判别键 | client_ip(去空白) )
判别键：rule_id 存在 → "rule:<id>"；否则 detector_code 非空 → "detector:<code>"；否则空串
```

`rule_id` 优先于 `detector_code`，同一事件只取一个判别维度。指纹 hex 编码 64 字符，与 `source` 组成唯一索引 `ux_ai_noise_clusters_fingerprint`。

### 4.3 聚类写入 `Store.UpsertEvent`（事务内）

1. 按 `(source, fingerprint_hash)` 查簇，不存在则新建（`event_count=1`，`first_seen=last_seen=occurred_at`）；
2. 关联事件 `INSERT ... ON CONFLICT (cluster_id, event_id, source) DO NOTHING`——同一事件重复扫描直接跳过，不重复计数；首个关联事件自动成为代表事件（`is_representative`）；
3. 仅新关联且非新建簇时 `event_count+1`、`last_seen=GREATEST(last_seen, occurred_at)`。

### 4.4 双事件源（source.go）

| | WAF 源 `FetchWAF` | API 源 `FetchAPI`（仅 WDSP） |
|---|---|---|
| 表 | `security_events` | `api_runtime_events` |
| 窗口 | `occurred_at ∈ [start, end)` | 同左 |
| 过滤 | `disposition_status IN ('UNPROCESSED','ANALYZING')` | 无处置状态过滤（窗口内全量） |
| host | `domain` | 空（表无该列） |
| URI | `request_path`（再归一化） | `endpoint_key`（本身已归一化，仍过 `NormalizeURI`） |
| 判别键 | 异常分最高的命中规则 `rule_id`（`security_event_matches` 按 anomaly_score DESC, rule_id 取 1） | `details_json` 中 score_delta 最高的 detector（并列取首个），格式 `detector` 或 `detector:rule_id`，截断 64 字符 |
| client_ip | `client_ip` | 空（表无该列） |

单源单次扫描上限 `sweepFetchLimit = 5000` 条（防长窗口拉爆内存）。

## 5. LLM 误报评分与降级（verdict.go）

- 候选：ACTIVE、`event_count ≥ min_events_threshold`、`ai_verdict='UNKNOWN'`，按事件数倒序，单次扫描最多 `defaultLLMVerdictBatch = 20` 个（成本兜底）；
- 调用：`aimodel.Gateway.Chat`，`ComplexityStandard` 档，`MaxTokens=256`，`Temperature=0`，`JSONMode=true`；
- 证据输入（`Evidence`，全部数据库事实）：簇属性（来源/主机/归一化 URI/规则或检测器/客户端 IP/事件数/首末次时间/频率）、代表事件的 attack_type/severity/action（WAF）或 risk_level/final_action（API）、代表事件前 5 条规则命中；
- system prompt 约束：只输出 `{"verdict":"TRUE_POSITIVE|LIKELY_FALSE_POSITIVE|UNKNOWN","confidence":0.0-1.0,"reason":"≤100字"}`，只能基于给定证据判断，证据不足必须 UNKNOWN，禁止编造；
- 解析（`ParseVerdict`）：容忍 ```json 代码围栏与首尾杂文本；verdict 白名单校验；confidence 钳制 [0,1]；reason 截断 200 字；
- 降级：LLM 错误 / 输出无法解析 → verdict=UNKNOWN，reason 记「LLM 不可用 / LLM 输出无法解析」，slog 告警，不返回错误；`gw=nil` 时全部 UNKNOWN。

## 6. 降噪推荐（recommend.go）

- 候选：ACTIVE、`ai_verdict='LIKELY_FALSE_POSITIVE'`、`event_count ≥ min_events_threshold`，单次最多 `defaultRecommendBatch = 20` 个；
- 去重：同簇已有 `recommendation_type='NOISE_REDUCTION'` 且 `status IN ('DRAFT','PENDING_REVIEW')` 的推荐则跳过（`HasOpenRecommendation`）；
- 写入：`ai_recommendations`，`recommendation_type='NOISE_REDUCTION'`、`target_type='NOISE_CLUSTER'`、`target_id=簇ID`、`risk='LOW'`、`draft_reference='noise:<簇ID>'`、`status='DRAFT'`、证据引用 `cluster:<id>` + `event:<代表事件ID>`；summary 截断 900 字；
- 推荐绝不自动生效，人工在推荐审核流程中 accept/reject。

## 7. 数据模型（迁移 000021）

### 7.1 `ai_noise_clusters`（降噪簇）

| 字段 | 类型 | 说明 |
|------|------|------|
| id | UUID PK | `gen_random_uuid()` |
| source | VARCHAR(8) | `WAF` / `API` |
| fingerprint_hash | VARCHAR(64) | sha256 hex，见 §4.2 |
| application_id | UUID NULL | WAF 事件的关联应用 |
| host | VARCHAR(255) | 默认 `''` |
| normalized_uri | TEXT | 默认 `''` |
| rule_id | INTEGER NULL | WAF 判别键 |
| detector_code | VARCHAR(64) NULL | API 判别键 |
| client_ip | INET NULL | |
| event_count | INTEGER | 簇内事件计数（幂等） |
| first_seen / last_seen | TIMESTAMPTZ | 首次 / 最近出现 |
| status | VARCHAR(16) | `ACTIVE`（默认）/ `SUPPRESSED` / `RESOLVED` |
| ai_verdict | VARCHAR(32) | `UNKNOWN`（默认）/ `TRUE_POSITIVE` / `LIKELY_FALSE_POSITIVE` |
| ai_confidence | NUMERIC(4,3) NULL | UNKNOWN 时不写 |
| ai_summary | TEXT | LLM 理由，默认 `''` |
| created_at / updated_at | TIMESTAMPTZ | 默认 `now()` |

索引：`ux_ai_noise_clusters_fingerprint (source, fingerprint_hash)` 唯一；`idx_ai_noise_clusters_status (status, last_seen DESC)`；`idx_ai_noise_clusters_verdict (ai_verdict, last_seen DESC)`。

### 7.2 `ai_noise_cluster_events`（簇内事件关联）

| 字段 | 类型 | 说明 |
|------|------|------|
| id | UUID PK | |
| cluster_id | UUID FK → ai_noise_clusters(id) | `ON DELETE CASCADE` |
| event_id | UUID | `security_events.id` / `api_runtime_events.id`（前者为分区表无法建外键，仅逻辑关联） |
| source | VARCHAR(8) | `WAF` / `API` |
| is_representative | BOOLEAN | 首个关联事件为代表事件 |
| created_at | TIMESTAMPTZ | |

索引：`ux_ai_noise_cluster_events (cluster_id, event_id, source)` 唯一（幂等基石）；`idx_ai_noise_cluster_events_cluster (cluster_id, created_at)`。

### 7.3 `ai_noise_sweep_runs`（扫描运行记录）

| 字段 | 类型 | 说明 |
|------|------|------|
| id | UUID PK | |
| started_at / finished_at | TIMESTAMPTZ | finished_at 可空 |
| scanned_events / new_clusters / updated_clusters | INTEGER | 扫描统计 |
| llm_calls / tokens_used | INTEGER | LLM 调用与 token 消耗（输入+输出） |
| status | VARCHAR(16) | `SUCCESS`（默认）/ `FAILED` / `PARTIAL` |
| error | TEXT | 失败原因，默认 `''` |
| created_at | TIMESTAMPTZ | |

索引：`idx_ai_noise_sweep_runs_time (started_at DESC)`。

## 8. 权限点（迁移 000021 种子）

| 权限点 | 名称 | SECURITY_ADMIN | SYSTEM_ADMIN | AUDIT_ADMIN |
|--------|------|:---:|:---:|:---:|
| ai.noise_reduction.use | 使用AI自动降噪（簇/统计/扫描历史查询 + 簇状态流转） | ✓ | ✓ | |
| ai.noise_reduction.manage | 管理AI自动降噪（手动触发扫描 + 修改降噪设置） | | ✓ | |

AI 权限点总数由阶段7 的 31 个增至 33 个（`module='ai'`）。

## 9. API 端点清单（`aihandlers/noise_handler.go`，9 个）

全部走 `authChain + RequirePermission`；写操作落 `ai_audit_records`。

| 方法与路径 | 权限 | 说明 | 审计 action |
|-----------|------|------|------------|
| GET `/api/v1/ai/noise/clusters` | use | 簇分页查询（source/status/verdict/start_time/end_time 筛选，非法枚举 400，时间须 RFC3339） | — |
| GET `/api/v1/ai/noise/clusters/{id}` | use | 簇详情 + 簇内事件（≤20 条，代表事件在前）；非法 ID 400，不存在 404 | — |
| POST `/api/v1/ai/noise/clusters/{id}/suppress` | use | ACTIVE → SUPPRESSED；状态不允许 409 | `noise_suppress` |
| POST `/api/v1/ai/noise/clusters/{id}/resolve` | use | ACTIVE/SUPPRESSED → RESOLVED；状态不允许 409 | `noise_resolve` |
| GET `/api/v1/ai/noise/stats` | use | 面板统计（活跃簇数/折叠事件总数/疑似误报簇数/已抑制簇数） | — |
| POST `/api/v1/ai/noise/sweeps` | manage | 手动触发一次扫描（同步执行返回统计，不受 enabled 限制） | `noise_sweep` |
| GET `/api/v1/ai/noise/sweeps` | use | 扫描历史分页（started_at 倒序） | — |
| GET `/api/v1/ai/noise/settings` | manage | 读取生效设置（含默认值回退） | — |
| PUT `/api/v1/ai/noise/settings` | manage | 更新设置（指针字段区分未提供/零值；先全量校验再落库） | `noise_settings_update` |

suppress / resolve 只改簇状态，不触碰事件处置、封禁、例外（`store.go Transition`）。模块未装配（`d.Noise` / `d.NoiseWorker` 为 nil）时返回 503。

## 10. 设置项（system_settings，组 `ai_noise`，全部按字符串存取）

| 键 | 默认值 | 取值范围 | 说明 |
|----|--------|----------|------|
| enabled | false | true/false | 总开关；false 时 worker ticker 空转 |
| interval_seconds | 300 | 30–86400 | 扫描间隔（秒） |
| sweep_window_minutes | 15 | 1–1440 | 单次扫描回溯窗口（分钟） |
| min_events_threshold | 10 | 1–100000 | LLM 评分与推荐的簇最小事件数 |
| llm_verdict_enabled | false | true/false | LLM 误报评分开关；false 时零 LLM 成本 |

`LoadConfig` 每 tick 重读（热更新，interval 变更即时生效）；非法值回退默认值，不静默沿用旧值。接口层 PUT 先做范围校验再逐项 `UpsertString` 落库，避免部分写入。

## 11. AI Tool（`aitools/noise_tools.go`，2 个，全部 READ_ONLY）

| Tool code | 名称 | 超时 | MaxResults | 所需权限 |
|-----------|------|------|-----------|----------|
| noise_cluster.search | 降噪簇查询 | 15s | 50 | ai.noise_reduction.use |
| noise_cluster.get | 降噪簇详情 | 10s | 1 | ai.noise_reduction.use |

source/status/verdict 入参走枚举白名单，非法值直接拒绝（`ErrInvalidInput`）。AI 可解释聚类结果，但 Tool 层不提供 suppress/resolve——簇状态流转只走人工接口（包注释明示）。

## 12. 前端

- 页面 `web/src/pages/ai/noise-reduction/NoiseReductionPage.tsx`：统计卡片（活跃簇/折叠事件/疑似误报/已抑制）、簇列表（source/status/verdict 筛选 + 分页）、簇详情抽屉（含代表事件）、扫描历史、设置面板（manage 权限可见）；操作：抑制 / 解决 / 手动扫描；
- API 封装 `web/src/api/ai.ts` `aiNoiseApi`（类型与 `ainoise.Cluster` / `SweepRun` / 设置响应对齐）；
- 路由 `/ai/noise-reduction`（`web/src/router/index.tsx`），菜单「智能安全运营 → 自动降噪」（`web/src/utils/menu.ts`，角色 SECURITY_ADMIN / SYSTEM_ADMIN）；
- 事件详情抽屉（`EventDetailDrawer.tsx`）提供「查看降噪簇」跳转入口（`canNoiseReduction` 权限门控）。

## 13. 双产品线（WAF / WDSP）行为差异

| | 纯 WAF 形态 | WDSP 形态（`APIDynamicProtectionEnabled()`） |
|---|---|---|
| 事件源 | 仅 `security_events` | 追加 `api_runtime_events` |
| `FetchAPI` | 恒返回空（零行为变化） | 窗口内全量读取 |
| 簇来源 | `source='WAF'` | `WAF` + `API` |
| 判别键 | 仅 `rule_id` | API 簇用 `detector_code` |
| 部署依赖 | 无差异（同一进程内 worker） | 无差异 |

WDSP 判定取 `cfg.Product.APIDynamicProtectionEnabled()`（`app.go` 装配时传入一次；运行期不热切换）。

## 14. 审计与配额

- 审计：suppress / resolve / 手动扫描 / 设置更新全部落 `ai_audit_records`（AI 独立哈希链，见 `docs/AI_SOC_ARCHITECTURE.md` §7），action 分别为 `noise_suppress` / `noise_resolve` / `noise_sweep` / `noise_settings_update`；worker 周期扫描本身不产生审计记录（无操作主体），运行痕迹落 `ai_noise_sweep_runs`；
- 配额：LLM 评分经 `aimodel.Gateway` 走 standard 档路由与熔断；单次扫描评分上限 20 簇 + 每簇 `MaxTokens=256` 构成成本兜底；`llm_verdict_enabled=false`（默认）时整链零 LLM 调用；token 消耗逐次累计入 `ai_noise_sweep_runs.tokens_used`；
- 注意：worker 后台评分不经过 `aicost.CheckQuota` 用户配额（无用户上下文），成本控制依赖开关 + 批次上限。

## 15. 测试清单

后端（Go Test）：

| 文件 | 覆盖 |
|------|------|
| `server/internal/ainoise/fingerprint_test.go` | URI 归一化（数字/UUID/hex/幂等）、指纹确定性与判别键优先级 |
| `server/internal/ainoise/store_test.go` | MemStore 聚类幂等、状态流转约束、候选查询、推荐去重 |
| `server/internal/ainoise/worker_test.go` | SweepOnce 全流程、源失败 PARTIAL/FAILED、enabled 语义、LLM 降级 |
| `server/internal/ainoise/verdict_test.go` | ParseVerdict（围栏/杂文本/白名单/钳制）、LLM 失败降级 UNKNOWN |
| `server/internal/ainoise/recommend_test.go` | DRAFT 推荐生成、同簇去重、证据引用 |
| `server/internal/aitools/noise_tools_test.go` | 2 个 Tool 注册/权限/白名单/查询与详情、DENIED 审计 |
| `server/internal/aihandlers/noise_handler_test.go` | 9 个端点权限、筛选校验、suppress/resolve 流转 409、手动扫描、设置校验 |

前端（Vitest）：

| 文件 | 覆盖 |
|------|------|
| `web/src/pages/ai/noise-reduction/__tests__/NoiseReductionPage.test.tsx` | 页面渲染与交互 |
| `web/src/api/__tests__/ai-noise.test.ts` | `aiNoiseApi` 全部方法（含非法参数拒绝） |
| `web/src/utils/__tests__/menu.test.ts` | 菜单项与路由可见性 |

## 16. 遗留限制（如实说明）

1. **迁移 000021 未在真实 PostgreSQL 实例执行过**：建表与权限种子仅经单元测试（MemStore / SQL 静态核对）验证，首次部署需观察迁移执行结果；
2. **设置以字符串形式存 `system_settings`**（组 `ai_noise`，`UpsertString` 写入、读取方自行解析），无类型化存储；
3. **API 源无处置状态过滤**：`api_runtime_events` 无 `disposition_status` 列，`FetchAPI` 读窗口内全量（与 WAF 源「仅未处置」语义不同）；
4. **事件计数只统计被扫描窗口覆盖的事件**：早于首次扫描窗口的历史事件不补扫；事件计数依赖关联幂等，`security_events` 为分区表无法对 `ai_noise_cluster_events.event_id` 建外键（逻辑关联，事件删除后关联行保留）；
5. **后台评分不走用户配额**：见 §14，成本靠开关与批次上限兜底；
6. **WDSP 开关装配期定型**：运行期切换 `api_dynamic_protection` 需重启进程才改变 API 源行为。

## 17. 关联文档

- AI 总体架构：[AI_SOC_ARCHITECTURE.md](AI_SOC_ARCHITECTURE.md)
- AI Agent 设计：[AI_AGENT_DESIGN.md](AI_AGENT_DESIGN.md)
- 权限设计：[RBAC_DESIGN.md](RBAC_DESIGN.md)
- 安全设计：[SECURITY_DESIGN.md](SECURITY_DESIGN.md)
- 开发状态：[DEVELOPMENT_STATUS.md](DEVELOPMENT_STATUS.md)
