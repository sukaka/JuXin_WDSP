# 阶段8（统一Web与API动态防护）实现核查报告

> 核查日期：2026-07-22
> 核查依据：`docs/tasks/STAGE_8_UNIFIED_WEB_API_DYNAMIC_PROTECTION.md`（与用户提供版本逐字节一致）
> 核查方式：对后端、网关引擎、前端、测试四个领域逐项对照任务书原文，全部结论均有仓库文件证据支撑。

---

## 一、总体结论

**按任务书原文口径：阶段8远未完成，整体完成度约 10–20%。**

需要说明的是，`docs/DEVELOPMENT_STATUS.md:319-330` 并未声称任务书全部完成，而是按自定义的"验收口径"交付了一个子集，并列出了部分"诚实遗留"。因此这是**有意裁剪的减量交付**，而非声称完成后缺漏。但实际缺口比该文档自己披露的更大（详见 §三.2 引擎未挂接网关一节）。

| 领域 | 完成度（对任务书原文） | 结论 |
|------|----------|------|
| 数据库表 | 3/27（且2张为简化结构） | 严重缺失 |
| REST 接口 | 8 条替代路由，任务书命名空间 0/35 | 严重缺失 |
| 权限点 | 5/27（命名体系不同） | 严重缺失 |
| AI 工具（48章） | 0/10 | 未实现 |
| 专项文档（64章） | 15份专项 + 测试报告全缺 | 未实现 |
| Makefile 命令（63章） | 0/22 | 未实现 |
| 网关统一引擎 | 骨架真实但未接入请求路径 | 核心原则未落地 |
| 前端页面（53章） | 2/12（均为简化版） | 严重缺失 |
| 测试（56–62章） | 骨架级 | 严重缺失 |
| 退出条件（65章90条） | 大部分不满足 | 不可标记阶段8通过 |

---

## 二、后端管理面核查

### 2.1 数据库迁移（任务书第五十章，27张表）

迁移文件仅两个：`server/migrations/000016_stage8.up.sql`、`server/migrations/000017_seed_stage8_perms.up.sql`。

实际建表 3 张：

| 任务书要求的表 | 状态 |
|---|---|
| `api_endpoints` | ⚠️ 已建但字段大幅简化：缺 `domain_id`/`raw_path_example`/`normalized_path`/`protocol_type`/`api_confidence`/`asset_status`/`learning_status`/`current_model_version_id`/`classification_locked`；实际为 method/path_template/endpoint_key/confidence/status/is_api 简化结构 |
| `api_model_versions` | ⚠️ 已建但简化：缺 `version_number`/`parent_version_id`/`request_schema_id`/`sample_count`/`created_reason`/`activated_at` 等，仅 id/endpoint_id/status/schema_json/content_hash |
| 其余 24 张（`api_endpoint_aliases`、`api_endpoint_path_segments`、`api_assets`、`api_learning_jobs`、`api_learning_samples`、`api_parameter_models`、`api_parameter_statistics`、`api_parameter_relations`、`api_request_schemas`、`api_response_schemas`、`api_classifications`、`api_classification_dimensions`、`api_custom_taxonomies`、`api_identity_profiles`、`api_object_models`、`api_behavior_profiles`、`api_call_edges`、`api_sensitive_fields`、`api_runtime_findings`、`api_schema_violations`、`api_lifecycle_events`、`api_model_reviews`、`api_model_diffs`、`api_import_specs`、`api_spec_diffs`） | ❌ 全部不存在（对 `server/` 全量正则搜索零命中） |

另多建了一张清单外的 `api_runtime_events`（统一运行时主事件表）。

### 2.2 REST 接口（任务书 51.1–51.6，约35个API）

路由注册于 `server/internal/app/app.go:641-655`。任务书要求的 `/api/v1/api-security/*` 命名空间**完全不存在**，实际为另一套路径：

| 已实现（app.go:648-655） | 对应任务书 |
|---|---|
| `GET /api/v1/api-endpoints`、`GET /api/v1/api-endpoints/{id}` | ≈51.1 list/get |
| `POST /api/v1/api-endpoints/discover` | 任务书外新增（手工喂发现数据） |
| `POST /api/v1/api-endpoints/{id}/confirm` | ≈51.1 confirm |
| `GET/POST /api/v1/api-model-versions`、`POST .../{id}/confirm` | ≈51.2 部分（候选创建+冻结） |
| `GET /api/v1/api-runtime-events` | ≈51.6 的运行时事件列表 |

**未实现（约 27/35）**：learning/start|stop|status、models/{id}/diff、submit-review/reject/activate/archive、endpoints merge/split/ignore/classify、parameters 全部 4 个、classifications、graph、topology、specs/import 全部 3 个、findings、violations、posture、runtime/statistics。

Handler：`server/internal/apiassets/handler.go`、`server/internal/apimodels/handler.go`、`server/internal/apiruntime/handler.go`。另注：`server/openapi/openapi.yaml` 未收录任何新API。

### 2.3 权限（任务书52章，27个权限点）

`server/migrations/000017_seed_stage8_perms.up.sql:3-9` 实际种子仅 5 个：`api_endpoints.read`、`api_endpoints.manage`、`api_models.read`、`api_models.manage`、`api_runtime_events.read`，已分配给 SECURITY_ADMIN / AUDIT_ADMIN / SYSTEM_ADMIN。

任务书要求的 `api_asset.*`、`api_learning.*`、`api_model.*`（单数）、`api_parameter.*`、`api_classification.*`、`api_spec.*`、`api_graph.read`、`api_runtime.read`、`api_policy.*`、`api_audit.read` 全部不存在。

已实现的 8 条路由均真实挂了 `middleware.RequirePermission(...)`（app.go:648-655）。

### 2.4 AI 工具（任务书48章，10个 Tool）

AI Tool 注册中心在 `server/internal/aitools/`（registry.go + 5 个工具文件），已注册 Tool 均为阶段7工具（`security_event.*`、`application.*`、`policy.*`、`rule.*`、`access_log.*`、`statistics.*`、`draft.*` 等）。

任务书要求的 `api_asset.search/get`、`api_model.get/diff`、`api_parameter.get`、`api_graph.query`、`api_runtime.statistics`、`api_risk.search`、`api_learning.status`、`api_classification.explain` **一个都不存在**。`docs/DEVELOPMENT_STATUS.md:330` 已将其列为"诚实遗留"。

### 2.5 文档（任务书64章，18份）

- ❌ 15 份阶段8专项文档全缺：UNIFIED_DYNAMIC_SECURITY_ARCHITECTURE、REQUEST_CONTEXT_DESIGN、API_DISCOVERY_DESIGN、API_PATH_NORMALIZATION、API_PARAMETER_MODEL、API_LEARNING_SECURITY、API_MODEL_VERSIONING、API_CLASSIFICATION_DESIGN、API_SCHEMA_PROTECTION、API_IDENTITY_SECURITY、API_AUTHORIZATION_ANALYSIS、API_SENSITIVE_DATA、API_BEHAVIOR_ANALYSIS、API_SECURITY_GRAPH、API_PRODUCT_SEPARATION
- ❌ STAGE8_TEST_REPORT.md 缺失（STAGE2–STAGE7 报告均在）
- ⚠️ API_DESIGN.md、SECURITY_DESIGN.md 存在但无阶段8内容
- ✅ DEVELOPMENT_STATUS.md 存在且含阶段8小节

### 2.6 Makefile stage8-* 命令（任务书63章，22个）

`grep -in "stage8" Makefile` 零命中。`stage8-build/migrate/seed/up/status/test-*/down` 全部缺失（Makefile 目标止步 stage7-*）。

---

## 三、网关统一引擎核查

`gateway/dynamic_security/` 是独立 Go module，全部非测试代码约 1073 行，管线骨架真实存在且 9 个包单测全绿。

### 3.1 目录结构对照（任务书第六章）

| 模块 | 状态 | 规模（非测试） |
|---|---|---|
| `context/` | 真实 | 231 行 |
| `parser/` | 真实（仅 JSON） | 208 行 |
| `normalizer/` | 真实 | 70 行 |
| `classifier/` | 真实（启发式打分） | 67 行 |
| `detectors/` | 半空壳：仅 1 文件 2 函数 | 80 行 |
| `decision/` | 真实但极简 | 100 行 |
| `events/` | 半空壳：仅结构体构造 | 43 行 |
| `learning/` | 半真实（含 stub） | 184 行 |
| `pipeline/` | 真实（但无生产调用方） | 90 行 |
| `versioning/` | 不存在（并入 learning/version.go） | — |
| `telemetry/` | **完全不存在** | 0 |

### 3.2 最关键缺口：引擎未接入网关（任务书第二章核心原则未落地）

- `jiuzhang_guard` **不 import** dynamic_security，guard 的 `go.mod` 不依赖它，`gateway/Dockerfile` 的 xcaddy 构建不包含它；
- `pipeline.Process` 在全仓库的唯一调用方是 `server/internal/product/waf_regression_test.go`（测试）；
- Coraza/WAF 命中走 `gateway/cmd/eventparser` 和 jiuzhang_guard 自有 `events.Logger`，**不经过 RequestContext**；
- `API_DYNAMIC_PROTECTION_ENABLED` 只注入 server 容器（`deployment/docker-compose.stage5.yml:104`），网关容器没有该变量；
- "关闭时不影响 WAF"**平凡成立**——开着也不影响，因为引擎根本不在请求路径上。

即任务书要求的"一套产品、一条流量处理链、一次协议解析、统一风险决策"在运行时**不生效**。`DEVELOPMENT_STATUS.md` 的遗留清单只提到"真实 Caddy 全链路 e2e 未做"，**未披露引擎压根未挂接网关这一更根本的缺口**。

### 3.3 RequestContext 字段覆盖（任务书第七章约55字段）

`context/context.go:72-130` 定义约 30 个字段，**缺失约 15 个**：

- 请求解析类：`request_headers`、`request_cookies`、`query_parameters`、`path_parameters`、`form_parameters`、`json_document`、`xml_document`、`multipart_parts`、`uploaded_files`（只存在于 `parser.Parsed` 局部结构或完全没有）
- GraphQL：`graphql_operation`、`graphql_variables` 完全缺失
- 响应侧：`response_headers` 缺失；`response_status/size/hash` 字段存在但无任何写入点
- 指纹类：`device_fingerprint`、`object_identifiers` 缺失；`session_fingerprint`、`tenant_fingerprint`、`identity_fingerprint` 字段存在但无写入点

### 3.4 检测器（8 缺 6）

`detectors/` 只有 `detectors/schema.go` 一个文件两个函数：

- `CheckSchemaDeviation`：对比观测字段与 formal schema，产生 undefined_field/type_mismatch/missing_field 三种 match —— **真实逻辑**；
- `CheckIdentitySignals`：仅检测 authorization/x-api-key 头是否存在 —— **占位**。

**不存在**：authentication（认证有效性）、sensitive_data、behavior、resource（BOLA/BFLA）、lifecycle、rate_limit 检测器。`api_discovery` 由 classifier+normalizer 拼出雏形，但无自动上报链路。

### 3.5 决策引擎

`decision/engine.go`（100 行）为真实逻辑：6 个动作常量齐全，优先级 TEMP_BLOCK > RATE_LIMIT > BLOCK（仅 PROTECT 模式）> OBSERVE > ALLOW；"唯一 finalize" 约束成立。但：

- `MASK_RESPONSE` **无任何产生路径**；
- `TEMP_BLOCK`/`RATE_LIMIT` 只有外部 match 带相应 Category 时才触发，目前没有任何检测器产生它们。

### 3.6 统一事件：有结构、有表、有读接口、没有生产者

- `events/event.go` 的 `PrimaryEvent`（主事件 + 多 Details）结构存在但仅 43 行，网关侧无落库、无上报、无 sink；
- 管理面 `server/internal/apiruntime/events.go` 的 `SavePrimary` 写入 `api_runtime_events` 表，但 **`SavePrimary` 全仓库零调用方**——该表在生产路径上永远为空；
- "同一 Request ID 只生成一个主事件"只靠约定保证，无去重/幂等机制。

### 3.7 学习与版本

- 网关侧 `learning/version.go`：内存 Store，CreateCandidate/Confirm（FORMAL + 旧版 SUPERSEDED）/`MutateFormal` 返回 `ErrFormalImmutable` 均为真实逻辑且有测试；但 `Observe()` 是 **stub**（只 `samples++` 丢弃 fields），"达到最小样本生成候选"的触发条件未实现；
- 管理面 `server/internal/apimodels/store.go` 用 DB 实现同一语义（Confirm 带 `FOR UPDATE` 事务），冻结不可变由"只 UPDATE status、无 schema 更新接口"保证；
- **两侧未连通**：没有任何代码把管理面的 formal schema 下发到网关，`pipeline.Config.FormalSchema` 需调用方手工传入；
- API"发现"靠手工 `POST /api-endpoints/discover` 喂数据，网关不会自动上报，"持续发现"无数据源。

### 3.8 大报文限制（任务书 §7.2）

部分真实生效：`MaxBodyParseBytes`（超限截断+采样+置 `BodyTruncated`）、`MaxJSONDepth`、`MaxFieldCount` 均有实现和测试；`MaxXMLDepth`、`MaxFileMetaCount` **没有对应解析代码**（无 XML/form/multipart 解析），是纯配置占位；"响应体采样比例"未定义。

### 3.9 代码规模估计

dynamic_security 非测试 1073 行中：真实逻辑约 800 行，stub/空转约 100 行，其余为类型定义；管理面 stage8 配套（apiassets+apimodels+apiruntime）约 660 行真实 CRUD/迁移代码。**整体处于"管线骨架 + 管理面 CRUD 闭环完成、运行时接入未开始"的状态。**

---

## 四、前端核查

### 4.1 页面对照（任务书53章12个页面）

阶段8 新增仅 2 个页面目录 + 1 个 API client（均由提交 `8462a87` 引入）：

| 任务书页面 | 实现情况 |
|---|---|
| API资产 | ⚠️ 部分（`web/src/pages/api-endpoints/ApiEndpointsPage.tsx`，129行）——只有方法/路径模板/置信度/状态/命中 5 列；53.1 要求的用途、协议、学习状态、当前版本、最近访问、请求量、风险、Shadow/Zombie 标记均未实现 |
| 模型版本 | ⚠️ 部分（`web/src/pages/api-models/ApiModelsPage.tsx`，122行）——仅创建候选/确认冻结；53.2 要求的时间线、样本数、参数变化、对比、拒绝、重新学习均未实现 |
| API学习中心 / 参数模型 / 用途分类 / API安全图谱 / API调用拓扑 / API风险 / Shadow与Zombie API / 敏感数据 / 规范对比 / API策略 | ❌ 全部无页面 |

其余 39 个页面目录均为阶段1–7 产物。另：`web/src/api/apiAssets.ts:60` 定义的 `apiRuntimeEventsApi` 无任何调用方，是死代码。

### 4.2 路由、菜单与开关

- 路由 `web/src/router/index.tsx:246-261`，菜单 `web/src/utils/menu.ts:82-94` 新增"接口防护"分组，守卫与角色过滤机制与旧页面一致；
- **前端无 `PRODUCT_EDITION` / `API_DYNAMIC_PROTECTION_ENABLED` 门控**：`productApi.edition()`（apiAssets.ts:69）无人调用；纯 WAF 版本部署时这两个菜单仍对有权限角色可见。

### 4.3 UI 一致性结论：**基本一致，是"简配"不是风格跑偏**

一致的部分：

- 同一 AdminLayout 壳（深色 Sider + 白 Header + Content margin:16）、单 `<Card title>` 容器，与旧页面相同；
- 零自定义 CSS、全内联 style、antd 组件、中文文案、secondary 说明文字，与旧页面及风格指南一致；
- 操作按钮 `type="link" size="small"`；错误处理用 `QueryErrorAlert`（比部分旧页面的内联 Alert 更符合多数约定）；
- 无 Mock 数据：两页全部通过真实 client 调后端（`apiEndpointsApi`、`apiModelsApi`），grep `mock/fake/dummy` 无命中。

具体落差 5 处（新旧页面观感差异的来源）：

1. **新建表单位置模式不同（差异最大）**：旧页面把创建表单收进 Drawer/Modal、Card extra 放 `type="primary"` 新建按钮（如 `AccessRulesPage.tsx:445-494` + Drawer）；阶段8 页面把创建表单直接平铺在列表上方（`ApiEndpointsPage.tsx:84-114` 用 inline Form，`ApiModelsPage.tsx:44-80` 用常驻 vertical 表单）。
2. **状态 Tag 未走统一封装**：旧页面用 `StatusTag` + 集中 `*_META` 映射（如 `SecurityEventsPage.tsx:104`）；阶段8 页面在文件内手写 meta 映射（`ApiEndpointsPage.tsx:52-59`、`ApiModelsPage.tsx:93-99`），不符合风格指南"必复用 StatusTag"约定。
3. **表格配置减配**：旧列表页标配 `scroll={{ x: 1500+ }}`、`showSizeChanger`、`showTotal`，阶段8 两页均无（`ApiEndpointsPage.tsx:120-125`）。
4. **菜单图标缺失**：`AdminLayout.tsx` 的 `MENU_ICONS` 没有 `/api-endpoints`、`/api-models` 条目，其余 40+ 项全有图标。
5. **行内操作不做权限显隐**：旧页面按 `hasPermission(permissions, 'xxx.manage')` 控制按钮（`AccessRulesPage.tsx:398`）；`ApiEndpointsPage.tsx:67` 的"确认"按钮对 read 用户也渲染。

### 4.4 工作区未提交改动的性质：在统一 UI，不引入新风格

- `web/src/components/QueryErrorAlert.tsx`：新增 `error == null` 提前返回（修复 `error={null}` 时渲染无描述红色 Alert 的 bug）；
- `web/src/pages/analytics/AnalyticsPage.tsx:389`：无权限分支改为构造 403 `ApiError`，落到黄色"暂无权限查看"提示——语义修正；
- `web/src/components/__tests__/QueryErrorAlert.test.tsx`（新增）：补 3 个 Vitest 用例；
- `docs/FRONTEND_UI_STYLE_GUIDE.md`（新增 478 行）：把本仓现有视觉约定沉淀成规范，内容与实际代码核对属实；
- `web/vite.config.ts`：dev 代理支持 `VITE_API_PROXY` 环境变量，默认仍使用标准端口 `18081`，纯开发环境调整；
- `deployment/docker-compose.stage5.yml`：补阶段8 环境变量（`PRODUCT_EDITION`/`API_DYNAMIC_PROTECTION_ENABLED`/`API_MAX_*`），合理改动。

---

## 五、测试核查（任务书 55–63章）

### 5.1 单元测试（56章，25项）

`gateway/dynamic_security/` 下 8 个测试文件、20 个测试函数、442 行，实测**全部通过**（注意：dynamic_security 是独立 module，须进子目录跑 `go test ./...`）：

- ✅ 有测试（9 项，其中 5 项很浅）：API识别、路径归一化、动态段识别、API合并（弱）、参数提取（弱）、类型识别（极弱）、模型冻结、身份提取（弱）、Schema偏离、风险聚合、统一事件、敏感数据脱敏（弱）
- ❌ 完全缺失（16 项）：API拆分、字符串统计、数值统计、数组和对象Schema、文件模型、条件关系、样本过滤、防污染、版本触发、版本差异、重新学习、用途分类、API Tool权限 等

### 5.2 接口测试（57章，18项）

- 阶段8 相关测试仅 `server/internal/apiassets/` 3 个（httptest+内存存储，非真实 DB/权限/审计链路）；
- `server/internal/apimodels`、`server/internal/apiruntime` **零测试文件**；
- `server/tests/` 有 stage3–stage7 集成测试，**无 stage8 文件**；
- 约 **2/18 项**有测试；合并拆分、学习启停、版本对比、模型激活、重新学习、参数修改、用途分类、规范导入、Shadow/Zombie、图谱、风险、权限越权、审计均无（多数 API 本身不存在）。

### 5.3 流量回放（58章）、学习测试（59章）、用途识别测试（60章）、安全测试（61章约35项）、E2E（62章七场景）、性能（55章）

**全部空白。** `test/` 目录最新只到 stage7；`web/e2e/` Playwright spec 到 stage7 为止，grep 无任何 stage8/api-endpoint 匹配。58章要求的"回放后验证 Web/API 共用同一 Request ID"无对应物。

### 5.4 前端测试

Vitest 实测 10 文件 82 用例全部通过，但无一覆盖阶段8页面（两个新页面均无测试；唯一新增的 `QueryErrorAlert.test.tsx` 是未提交文件，与阶段8页面无关）。

### 5.5 实测运行证据

- `grep -in "stage8" Makefile` → 零匹配（exit=1）；
- `cd gateway/dynamic_security && go test ./...` → 8 包 `ok`，20 个测试函数全过（detectors 包无测试文件）；
- `cd server && go test ./...` → 无 FAIL，但 `server/tests` verbose 下 **87 个 SKIP / 仅 6 个 PASS**（无 POSTGRES_PASSWORD/VALKEY_PASSWORD 环境整体跳过，"ok"是跳过而非通过）；
- `cd web && npx vitest run` → 82 passed。

### 5.6 测试报告

`docs/` 下**不存在 STAGE8_TEST_REPORT.md**。`DEVELOPMENT_STATUS.md` 对功能遗留较诚实，但**对测试缺口未披露**（56章 16/25 缺、57章 16/18 缺、58–62章全空、63章命令 0/22、65章第 80–86 条测试类退出条件均不满足），与 65章第 87 条"文档与实际一致"存在口径冲突。

---

## 六、任务书65章退出条件总览

90 条退出条件中，可判定满足的主要是骨架类条目（存在统一 RequestContext 骨架、候选确认冻结逻辑、偏离不扩宽机制、统一主事件结构、API 开关关闭时 WAF 无回归——但最后一项是平凡成立）；**大部分不满足**，包括但不限于：

- 第 1–4 条（同一流量链/一次解析/统一上下文/Coraza 只是检测器之一）：引擎未接入网关，运行时不成立；
- 第 6–8 条（自动识别/置信度可见）：无自动发现数据源，靠手工喂；
- 第 13–20 条（参数模型体系）：请求/响应参数模型、字符串/数值/数组/对象/文件模型、条件关系均未实现；
- 第 23–34 条（样本过滤/防污染/版本触发/版本对比/重新学习）：未实现；
- 第 35–40 条（用途多维/自定义分类/OpenAPI导入对比）：未实现；
- 第 41–43 条（Shadow/Zombie/Deprecated）：未实现；
- 第 44–50 条（请求/响应 Schema 检测）：仅网关侧一个简化偏离检查，且不在请求路径上；
- 第 51–55 条（身份/凭据指纹/维度限流/敏感数据/泄露检测）：未实现；
- 第 56–64 条（图谱/拓扑/BOLA/BFLA/字段越权/Mass Assignment/行为基线/流程偏离）：未实现；
- 第 65–68 条（统一决策/统一事件）：结构存在但运行时无生产者、未挂接；
- 第 69–71 条（统一策略发布/版本不可变/回滚一致）：未实现；
- 第 72–74 条（AI Tool 接入/AI 不自动确认/不自动发布）：AI Tool 未实现（后两条平凡成立）；
- 第 78–86 条（迁移/单测/接口/回放/污染/E2E/性能/安全测试）：大部分未执行；
- 第 87 条（文档与实际一致）：见 §五.6，存在口径冲突。

**结论：按任务书第65章，不得标记阶段8通过。**

---

## 七、建议

### 7.1 若目标是按任务书原文收口（优先级从高到低）

1. **把统一引擎真正挂进 jiuzhang_guard 请求链**：Coraza 命中写入 RequestContext、决策结果作用于响应、`API_DYNAMIC_PROTECTION_ENABLED` 注入网关容器——这是任务书第二章核心原则，当前完全缺失；
2. **打通事件生产者链路**（网关→管理面上报 → `api_runtime_events`）和 **formal schema 下发通道**（管理面→网关）；
3. 补齐数据库表（27 张）、接口命名空间（`/api/v1/api-security/*`）、权限点（27 个）；
4. 补检测器（authentication/sensitive_data/behavior/resource/lifecycle/rate_limit）与 parser（XML/form/multipart/GraphQL）；
5. 补测试体系（56–62章几乎全空）与 15 份专项文档 + STAGE8_TEST_REPORT；
6. 前端按 53 章补齐其余 10 个页面。

### 7.2 若接受"骨架验收口径"（最低限度应做）

1. 把"引擎未挂接网关请求路径"如实写进 `DEVELOPMENT_STATUS.md` 遗留清单（当前未披露）；
2. 前端 5 处 UI 落差整改（工作量约半天）：
   - `AdminLayout.tsx` 的 `MENU_ICONS` 补 `/api-endpoints`、`/api-models` 图标；
   - 阶段8 页面状态列改用统一 `StatusTag`；
   - 新建表单改为 Drawer/Modal + Card extra 主按钮模式；
   - 表格补 `scroll x`/`showSizeChanger`/`showTotal`；
   - 行内按钮加 `api_endpoints.manage` / `api_models.manage` 权限显隐；
3. 提交当前工作区的合理改动（QueryErrorAlert 修复、风格指南、compose 环境变量等）；
4. 决定前端是否接 `/product/edition` 做 WDSP 菜单门控（当前纯 WAF 版本也会看到"接口防护"菜单）。

---

*本报告由对仓库的静态核查与实跑测试生成，全部结论可对照文中证据路径复核。*
