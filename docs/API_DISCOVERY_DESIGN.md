# API 发现设计（阶段8 / WDSP）

## 一、目的与范围

API 发现回答三个问题：哪些流量是 API（识别）、它们构成哪些API（归一与登记）、
这些API处于什么管理与学习状态（生命周期）。本文覆盖：

- 网关侧多信号分类器（`gateway/dynamic_security/classifier/api.go`）；
- 发现数据流：guard 事件 → 采集器 → API资产幂等 upsert；
- 管理面手工确认、合并/拆分、忽略、分类；
- 资产状态（`asset_status`）与学习状态（`learning_status`）两轨生命周期。

路径归一化细则见 `docs/API_PATH_NORMALIZATION.md`；模型版本见
`docs/API_MODEL_VERSIONING.md`。

## 二、识别：分类器信号打分

任务书 §8.1 要求「不得仅依赖 URL 包含 `/api/`」。网关请求相位使用
`classifier.Classify`（`gateway/dynamic_security/classifier/api.go`），基于一次
请求解析产物做多信号加权打分：

| 请求侧信号 | 权重 | 依据 |
|------|------|------|
| `content_type_json` | 0.35 | 请求 Content-Type 为 JSON 或体嗅探为 JSON |
| `graphql_path` | 0.40 | 路径含 `/graphql` |
| `content_type_xml` | 0.25 | Content-Type 为 XML/SOAP |
| `json_fields` | 0.25 | JSON 体提取出字段 |
| `versioned_path` | 0.20 | 路径含 `/v1/`、`/v2/` |
| `api_prefix` | 0.15 | 路径含 `/api/`（只是信号之一，非充分条件） |
| `accept_json` | 0.15 | Accept 头要求 JSON |
| `write_json` | 0.10 | POST/PUT/PATCH 且 JSON 体 |

打分截断到 1.0；**得分 ≥ 0.35 判为 API**，输出 `{IsAPI, Confidence, Signals}`。
请求相位结果保存到 `ctx.APIConfidence`、扩展键 `api.is_api` / `api.signals` 和
事件字段 `api_confidence`，用于网关运行时事件；该请求侧行为保持不变。

Agent v2 资产联动使用同一分类器的 `ClassifyWithResponse` 入口，在完整可见响应上
追加以下证据：

| 响应侧信号 | 权重 | 依据 |
|------|------|------|
| `response_json` | +0.25 | 响应 Content-Type 为 JSON |
| `response_xml` | +0.20 | 响应 Content-Type 为 XML/SOAP |
| `response_html` | -0.35 | 2xx 成功 HTML 响应（GraphQL、SOAP/XML、gRPC 等结构性协议除外） |

响应未采集、单向源、截断或流式直通时不作负向推断，保留请求侧结论；gRPC 由可信
`grpc` 元数据直接确认（置信度 0.95，仍低于人工确认 1.0），不解析 Protobuf 正文。
该入口只影响新观测的资产发现分类，不改变网关请求阻断决策。

非互斥分类（任务书 §2.3）：分类器只回答「是不是 API、把握多大」，不把请求
分流到另一套系统；Web 与 API 共用同一条链路与同一上下文。

## 三、发现数据流

```text
guard.emitAPIEvent（apiprotect.go:123）
  │  触发条件：分类为 API 或存在检测明细（apiprotect.go:90）
  │  Record{request_id, endpoint_key, method, path_template(归一化路径),
  │         is_api, api_confidence, risk_*, final_action, details}
  ▼
api-runtime-events.log（JSONL；endpoint_key≤560、path_template≤512 截断，
  控制字符剥离，apievents.go:36-39、60-72）
  ▼
apiruntime.Collector.CollectOnce（collector.go:198；2s 轮询、断点续传、轮转检测）
  ├─ handleRecord（collector.go:310）：
  │    method 与 path_template 非空即调
  │    apiassets.UpsertDiscovery(method, pathTemplate, confidence, isAPI)
  │    （upsert 失败只记日志，不影响主事件入库，collector.go:314-317）
  └─ notable 记录（有检测明细或动作非 ALLOW，collector.go:57-59）：
       SavePrimary → api_runtime_events（按 request_id 幂等）
```

Agent v2 机器端点是第二条发现来源：`POST /api/v1/agents/{agent_id}/http` 完成
校验、幂等入库后，仅对新记录执行 `linkHTTPAssets`。已绑定记录按 Host、应用绑定、
方法和模板化路径去重后调用 `UpsertDiscovery`；v1 因兼容契约维持 `is_api=true、
confidence=0.8`，v2 改按 `ClassifyWithResponse` 的实际证据输出 `is_api/confidence`。
未绑定记录只落 `UNASSIGNED` 来源行，不做端点 upsert；重复事件不推进资产计数。
普通 Web 流量可登记为 `is_api=false` 的非 API 画像，不靠丢弃事件提高表面准确率。

`UpsertDiscovery`（`apiassets/store.go:323-365`）以 `endpoint_key =
METHOD + 空格 + path_template` 为身份键，配合复合作用域唯一索引
`uq_api_endpoints_scope`（迁移 000137）幂等入库：

- 首次：`INSERT ... asset_status='DISCOVERED', hit_count=1`；
- 再次命中：`ON CONFLICT (application_id, domain_id, application_binding_id,
  host, endpoint_key, protocol_type) DO UPDATE`——`hit_count+1`、
  `last_seen_at=now()`、`api_confidence` 取两者较大值；
- 采集器重放、多网关节点上报同一键均不产生重复API。

API表身份列：`http_method / normalized_path / raw_path_example / endpoint_key /
api_confidence / is_api / hit_count / first_seen_at / last_seen_at`
（迁移 000018，`apiassets/store.go:47-68`）。

### API 资产导出

- `GET /api/v1/api-security/endpoints/{id}/export?format=json`：单个 API 详细档案
  （`export_version=1`），包含基础与业务归属、识别结论、分类维度、来源分类信号、
  最近 20 个模型版本、当前版本参数、运行时响应 Schema、学习任务与最近 100 条
  脱敏样本、最近 100 条生命周期事件、1h/24h/7d 补零流量、最多 100 条 Agent
  来源关系，以及最近 50 条 Finding/弱点和最多 500 条敏感字段摘要。
- `GET /api/v1/api-security/endpoints/export?format=csv`：按列表同一筛选条件导出
  资产清单，单页 100 循环拉取、总量上限 10000，字段做公式注入转义。
- 两个接口均要求 `api_asset.export`，共享导出限流并写操作审计；仅输出既有脱敏
  元数据，不导出请求/响应正文、Token、密钥、样本明文或敏感参数值。模型或扩展
  数据入口未接线时返回 503，不生成看似完整的残缺档案。

## 四、手工确认与资产操作

管理面路由统一挂在 `/api/v1/api-security/endpoints`（`apiassets/handler.go:33-47`），
权限点逐路由强制校验：

| 操作 | 路由 / 权限点 | 语义 |
|------|---------------|------|
| 列表/详情 | `GET .../endpoints`（`api_asset.read`） | asset_status/learning_status/keyword/application_id 过滤；详情附 `api_assets` 业务维度 |
| 导出 | `GET .../endpoints/export`、`GET .../{id}/export`（`api_asset.export`） | 筛选清单 CSV / 单个详细 JSON；共享导出限流并写审计，内容边界见「API 资产导出」 |
| 批量确认 | `POST .../endpoints/confirm`（`api_asset.confirm`） | `asset_status=CONFIRMED` 并记 `confirmed_at`；单次≤100 个，逐项报告失败（handler.go:82-129） |
| 忽略 | `POST .../{id}/ignore`（`api_asset.ignore`） | `asset_status=IGNORED`，写生命周期事件 |
| 合并 | `POST .../{id}/merge`（`api_asset.merge`） | other 并入 primary：命中数累加、历史键归档 `api_endpoint_aliases`、写 MERGED 事件（store.go:312-383） |
| 拆分 | `POST .../{id}/split`（`api_asset.split`） | 指定新归一化路径拆出API（继承方法/置信度/协议），单次≤50 路径，键冲突返回 409（handler.go:283-338、store.go:387-436） |
| 编辑资产 | `PATCH .../{id}`（`api_asset.edit`） | purpose/exposure(INTERNAL/PARTNER/PUBLIC)/owner/tags 全量替换，长度与数量校验（handler.go:157-223） |
| 自动分类 | `POST .../{id}/classify`（`api_asset.edit`） | 路径/方法启发式写 PURPOSE/EXPOSURE/ACCESS 三维（source=AUTO）；已锁定返回 409（store.go:565-598、784-818） |
| 人工分类 | `PUT .../{id}/classification`（`api_classification.manage`） | 逐维 upsert（source=MANUAL）并锁定，自动分类不得覆盖（apisecurity/store.go:153-178） |

全部写操作记录操作审计（模块 `api_assets`/`api_security`，含前后摘要与风险等级，
handler.go:548-569）；状态变化写 `api_lifecycle_events`（原状态/新状态/原因/操作者，
store.go:439-476）。

## 五、生命周期：两轨状态

**资产状态**（`asset_status`，白名单见 `store.go:31-36`）：

```text
DISCOVERED ──人工确认──► CONFIRMED
    │                       │
    ├──忽略──► IGNORED      └──标记──► DEPRECATED（仍被调用时网关侧产生 OBSERVE 明细）
```

- `DISCOVERED`：采集链路自动登记的初始态；
- `CONFIRMED`：人工确认为正式资产；
- `IGNORED`：管理员标记忽略（`POST .../{id}/ignore` 路由）；
- `DEPRECATED`：白名单内的合法值，当前无专用路由（可经仓储/SQL 标记，
  管理面接口在后续补充）；网关生命周期检测器对发布基线中 DEPRECATED
  API的调用产生 `lifecycle.deprecated_api_call`（OBSERVE/MEDIUM，
  `detectors/lifecycle.go:34-46`）。

**学习状态**（`learning_status`，白名单见 `store.go:39-44`）：

```text
NOT_STARTED ──learning/start──► LEARNING ──learning/stop──► PAUSED
                                                    （LEARNED 为完成态预留）
```

学习启停与学习任务（`api_learning_jobs`）联动：`StartLearning` 建 RUNNING 任务并置
`LEARNING`，已有 RUNNING 返回 409；`StopLearning` 置任务 STOPPED 并回 `PAUSED`
（store.go:602-684）。两轨分离：资产是否受管理（asset_status）与模型学到哪一步
（learning_status）互不阻塞（任务书 §12）。

**Shadow 识别**：网关生命周期检测器以发布下发的「已知API基线」
（`api_known_endpoints`，`ListKeyStatus`，store.go:272-287）为准，API 流量命中
表外API即产生 `lifecycle.new_endpoint`（OBSERVE/LOW，信号 `shadow_candidate`，
`detectors/lifecycle.go:19-32`）。

## 六、关键设计决策

1. **发现喂数据与事件入库解耦**。所有被输出的运行时记录都喂 `UpsertDiscovery`
   （含 `is_api=false` 的非 API 记录，保留非 API画像），只有 notable 记录进
   事件表（`collector.go:56-59`）。发现覆盖面不受「是否有风险命中」影响。
2. **幂等键用 endpoint_key 而非 UUID**。网关与采集器不需要知道数据库主键，
   归一化算法即身份；重放、扩容、重启天然幂等（store.go:204-212）。
3. **置信度只升不降（GREATEST）**。同一API多次观测取最大置信度，避免偶发低信号
   请求拉低已积累的识别结论（store.go:210）。
4. **合并留别名、拆分留事件**。合并把历史API键归档进 `api_endpoint_aliases`
   （alias_key 唯一，重复归档幂等），旧键流量可追溯；拆分写 SPLIT 生命周期事件，
   审计链完整（store.go:353-374、426-431）。
5. **自动分类可锁定**。AUTO 来源分类置信度低（0.5-0.9），人工分类（MANUAL，
   置信度 1）后置 `classification_locked`，自动分类返回冲突不得覆盖
   （store.go:579-581；apisecurity/store.go:169-177），落实任务书 §8.3
   「人工锁定后自动识别不得覆盖」。
6. **确认是人工动作**。自动链路只产生 DISCOVERED 与置信度；CONFIRMED 只能经
   管理面接口批量确认，为后续「确认模型」提供可信的资产边界。

## 七、当前实现范围与限制

1. **发现信号集仍是任务书 §8.1 的裁剪子集**：网关请求相位不使用响应；Agent v2
   资产联动已使用响应 Content-Type，但 Token/签名特征（认证检测独立于分类器）、
   调用客户端/User-Agent、状态码（不作为独立正向信号）、跨请求字段结构稳定性、
   重复API模式、Webhook 特征仍未参与。四级识别结果
   （CONFIRMED_API/PROBABLE_API/POSSIBLE_API/NON_API）已实现，并与
   布尔 `IsAPI` + 0..1 置信度同源输出。
2. **Zombie API 未实现**：任务书 §11.2 的「标记下线仍有流量」判定无对应状态与
   检测器；`asset_status` 白名单不含 SHADOW/ZOMBIE（Shadow 仅以检测信号与
   基线缺失表达，见第五节）。
3. **运行时发现表无写入方**：`api_runtime_findings`（SHADOW/ZOMBIE/BOLA 等条目）
   与查询接口已建，但当前无生产写入路径；Shadow/Deprecated 线索以主事件
   `details_json` 中的 lifecycle 明细为准。
4. **协议类型按来源分层**：网关管线可标注 GRAPHQL/SOAP/WEBSOCKET 等结构协议；
   Agent v2 资产联动当前仅按可信 `grpc` 元数据写 `GRPC`，其余仍回落 `REST`，
   不从响应内容猜测结构协议。空值仍回落 REST（迁移 000018 默认值）；首写不覆盖。
   遗留：GraphQL 不按 operationName 拆API（API键仍按路径归一化）。
5. **非 API也会登记**：`is_api=false` 的记录同样 upsert API（见决策 1），
   列表需以 `is_api`/置信度自行区分；当前列表接口未提供 is_api 过滤参数。
6. **应用归属**：`application_id` 列已建，但发现 upsert 不填（事件的
   application_id 未传入 UpsertDiscovery 签名），归属靠后续管理操作。

## 八、与任务书章节对应

| 本文章节 | 任务书 |
|----------|--------|
| 二、分类器 | §八 API流量识别、§2.3 非互斥分类 |
| 三、发现数据流 | §六 总体架构（事件与学习回流）、§54 可观测性 |
| 四、手工确认 | §8.3 人工操作、§51.1 API资产接口、§五十二 权限 |
| 五、两轨状态 | §十一 API资产状态、§十二 API学习状态、§11.4 状态审计 |
| 七、限制 | §11.1/11.2 Shadow/Zombie、§65 退出条件未满足项披露 |

---

Copyright © 聚信得仁
All Rights Reserved.
