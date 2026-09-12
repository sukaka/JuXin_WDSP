# WDSP Agent HTTP 事件 schema v2 与机器端点幂等 — 三方冻结契约

**版本：V1.1（2026-09-08 修订；V1.0 2026-09-08 冻结）**
**上游：docs/tasks/wdsp-p1/P1-03_AGENT_GATEWAY_PROTOCOLS.md §4.1/§4.2；兼容基线：docs/agents/WDSP_AGENT_PHASE1_CONTRACT.md 与 PHASE3 契约 §3/§6**

本文件冻结 HTTP 事件 schema v2 字段表、逐字段上限与 null 语义、能力协商扩展、批次幂等语义与资产来源关系，供 server / wdsp-agent / web 三方共同遵守。本契约是 Phase 1–5 契约的**增量**，未提及部分沿用既有冻结口径（认证、错误信封、分页、脱敏纪律均不变）。

落地范围标记约定：

- **[G1]** 本次落地：server 侧迁移、机器端点接收/校验/幂等入库/来源关系持久化均已实现并有测试。
- **[冻结]** 仅冻结线格式与语义，由 G2/G3 适配器（Nginx mirror / Envoy tap）产生真实数据；G1 server 已能接收与持久化这些字段，但当前唯一适配器（PASSIVE_HTTP1）不产生部分取值。

## 1. 批次包络与版本判别

`POST /api/v1/agents/{agent_id}/http` 复用不变。批次顶层新增可选字段 `schema_version`：

```json
{ "schema_version": 2, "records": [ ... ] }
```

- `schema_version` 缺省或为 `1` → 按 v1 批次处理（Phase 3 契约 §3 原样，行为不变，旧 Agent 零感知）。
- `schema_version: 2` → v2 批次，记录结构按 §2。其他取值 → 400 永久失败（`INVALID_ARGUMENT`）。
- v2 批次仅当该 Agent 已通过能力协商声明支持 v2（§3）时才被接受；未协商 Agent 发送 v2 批次 → 400 永久失败，客户端必须降级为 v1 采集模式重发，**不得**无限重试。
- 批次上限不变：**每批 ≤ 100 条记录、序列化后 ≤ 8 MiB（含 JSON 转义与包络字段）**。超限为永久失败，客户端先缩减可选正文/元数据并标记截断，仍超限则丢弃并计数（不得依赖服务端拒绝实现无限"稍后再试"）。

## 2. v2 记录字段表（`records[]` 项）

v2 记录是 v1 记录（Phase 3 契约 §3：flow_id、request_ts、response_ts、latency_ms、五元组、direction、request、response、k8s）的**超集**。v1 既有字段的类型、必填性与同步 null 语义原样保留，以下仅列 v2 增量与变更。

| 字段 | 类型 | 必填 | 上限/枚举 | null 语义 | 范围 |
|---|---|---|---|---|---|
| `event_id` | string | 是 | 1–128 字符，`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$` | 不允许 null/空串 | [G1] |
| `source_type` | string | 是 | `PASSIVE_HTTP1` / `NGINX_MIRROR` / `ENVOY_TAP` | 不允许 | [G1]（后两个枚举 [冻结]，G2/G3 产生） |
| `source_instance` | string | 是 | ≤255 字符；受控采集实例标识（非 Agent 身份，不可用于认证） | 不允许 null；空串非法 | [G1] |
| `source_epoch` | int | 是 | ≥0，来源进程重启代次（单调递增） | 不允许 | [G1] |
| `source_capabilities_version` | string | 可空 | ≤64 字符；采集源能力版本，与 policy_version、Agent build 分开记录 | null/空串 = 来源无独立能力版本 | [G1] |
| `observed_http_version` | string | 是 | `1.0` / `1.1` / `2` / `3` / `UNKNOWN` | 不允许 null；无法确认时填 `UNKNOWN`，不得从 User-Agent 推断 | [G1]（`2`/`3` [冻结]，G3 产生） |
| `original_http_version` | string | 可空 | 同上枚举 | null = 原协议不可确认（如 tap 位于上游侧、HTTP/2 转 HTTP/1 镜像）；**观测协议与原协议分开记录，不得互相回填** | [冻结]（G3 适配器产生） |
| `tls_visibility` | string | 是 | v2 扩展为 `PLAINTEXT` / `DECRYPTED` / `UNKNOWN`；v1 仍仅 `PLAINTEXT`（fail-closed 不变） | 不允许 null | [G1]（`DECRYPTED` 需可信终止点证据 [冻结]，G2 产生；不能由外部 Header 单独决定） |
| `association_state` | string | 是 | `COMPLETE` / `REQUEST_ONLY` / `PARTIAL` / `UNCORRELATED` | 不允许 | [G1]（COMPLETE 之外取值 [冻结]，G2/G3 产生） |
| `association_reason` | string | 条件 | ≤64 字符，枚举：`""`（state=COMPLETE）/ `SOURCE_REQUEST_ONLY` / `TIMEOUT` / `DISCONNECT` / `TRUNCATED` / `CORRELATION_MISS` | 不允许 null；state=COMPLETE 时必须为 `""`，其余 state 必须非空 | [G1] |
| `capture_stream_id` | string | 可空 | ≤255 字符；来源作用域内连接/流关联标识（HTTP/2 stream、tap stream） | null = 来源无流概念或不可获得；**不替代 Agent 身份或业务 Request ID** | [冻结]（G3 产生） |
| `application_binding_id` | string(UUID) | 可空 | 合法 UUID；管理面批准的来源映射标识 | null = 无绑定（与 `binding_version` 同有同无） | [G1]（绑定注册表服务端复核 [冻结]，G2 随来源绑定管理落地） |
| `binding_version` | int | 可空 | ≥0 | 同上；两字段同有同无，缺一即 400 | [G1] |
| `collection_ts` | float | 是 | 正 Unix 秒（毫秒精度，同 request_ts 口径） | 不允许 | [G1] |
| `request.headers` / `response.headers` | object | 是 | **v2 改为数组形态**：`{"name": ["v1","v2"]}`，保序保留重复值，禁止隐式逗号合并（尤其 Set-Cookie）；名 ≤255 字节、单值 ≤8192 字节、条目 ≤64/方向；名小写规范化由 Agent 完成，冲突（Host vs `:authority`）不得静默覆盖 | 空对象 `{}` = 无头部；不允许 null | [G1]（G2/G3 适配器遵循同规则） |
| `request.trailers` / `response.trailers` | object | 可空 | 同 headers 数组形态与上限 | null = 无 trailer 或来源不可见；空对象 = 确认无 trailer | [冻结]（G3 产生） |
| `request.body` / `response.body` | string | 是 | 同 v1（已脱敏/已截断内容，服务端不二次脱敏） | 空串 = 未采集；语义见 `body_quality` | [G1] |
| `request.body_quality` / `response.body_quality` | object | 是 | 见 §2.1 | 不允许 null（即使未采集也要如实说明） | [G1] |
| `grpc` | object | 可空 | 见 §2.2 | null = 非 gRPC 流量；**HTTP 200 ≠ RPC 成功** | [冻结]（G3 产生；本期仅元数据，不解析 Protobuf 正文） |

v1 字段在 v2 中的口径确认：`request_ts/response_ts/latency_ms` 同步 null 规则不变；`response` 整体可 null（此时 `response_ts/latency_ms` 同步 null，且 `association_state` 不得为 `COMPLETE`）；`flow_id` 保留（Agent 侧流关联标识）；`k8s` 增量不变。

`ingestion_ts` **不在上报报文中**：由服务端在接收时生成（`agent_http_events.ingestion_ts`），与 `collection_ts` 分列度量采集→入库延迟，均不混入业务延迟（业务延迟仍仅 `latency_ms`）。

### 2.1 `body_quality` 子对象

```json
{ "captured_bytes": 128, "original_total_size": 4096, "truncated": true, "skipped_reason": "" }
```

| 字段 | 类型 | 语义 |
|---|---|---|
| `captured_bytes` | int ≥0 | 实际捕获（脱敏前测量、脱敏后数量不得大于此值）字节数；未采集为 0 |
| `original_total_size` | int ≥0 或 null | 原始报文总大小；**未知长度必须填 null，不得填 0**（0 仅表示确认为空报文体） |
| `truncated` | bool | 因预算截断 |
| `skipped_reason` | string | `""` / `content_type` / `encoding`（与 v1 枚举一致；skipepd 时 body 应为空串） |

一致性约束：`captured_bytes > 0` 时 `skipped_reason` 必须为 `""`；`skipped_reason` 非空时 `captured_bytes` 必须为 0；`truncated=true` 且 `original_total_size` 非 null 时要求 `original_total_size` ≥ `captured_bytes`；**`truncated=true` 允许 `original_total_size=null`，表示「截断且原始总大小未知」**（如流式读取中断、Envoy tap 按 `max_buffered_*_bytes` 截断后总大小不可确认——V1.1 修订，见修订记录）。

### 2.2 `grpc` 子对象（[冻结]，G3 产生）

```json
{ "service": "pkg.UserService", "method": "GetUser", "grpc_status": 0, "stream_state": "CLOSED" }
```

| 字段 | 类型 | 语义 |
|---|---|---|
| `service` / `method` | string，各 ≤255 字符 | 由 `:path` 可信解析（`/pkg.Service/Method`）；无法解析则对应字段空串 |
| `grpc_status` | int 0–16 或 null | 来自 trailers 的 `grpc-status`；流未结束/不可见为 null，**不得伪造 0** |
| `stream_state` | string | `OPEN` / `CLOSED` / `CANCELLED` / `UNKNOWN`；取消与未结束如实表示 |

## 3. 能力协商（注册/心跳扩展）

在既有注册与心跳上扩展，旧 Agent 零感知：

- **注册**（`POST /api/v1/agents/enroll`）请求新增可选 `capabilities` 对象：
  ```json
  { "capabilities": { "http_event_schema_versions": [1, 2] } }
  ```
  缺省 = `[1]`。元素须为 `{1,2}` 子集，其他取值 400。
- **心跳**（`POST /api/v1/agents/{agent_id}/heartbeat`）请求可携带同名字段；携带时服务端更新该 Agent 的能力集，未携带时保持既有值。
- **注册与心跳响应**均新增 `capabilities` 对象，内容为服务端接受后的生效集合（声明集 ∩ 服务端支持集，当前 = `{1,2}`）：
  ```json
  { "capabilities": { "http_event_schema_versions": [1, 2] } }
  ```
- 生效集合持久化于 `agents.http_event_schemas`（默认 `{1}`），机器端点以此判定是否接受 v2 批次。旧服务端无此响应字段，旧 Agent 无此请求字段，双向忽略即为降级协商。

## 4. 批次语义（v2）

1. **全量校验后事务写入**：v2 批次先对全部记录逐条校验，全部通过后在**单事务**内写入；任何失败整批回滚，不存在部分提交。
2. **幂等去重**：按 `(agent_id, event_id)` 唯一（部分唯一索引，`event_id IS NOT NULL`）。重试/补传重放同一 `event_id` → 确认但不重复入库、不扩大资产计数（资产联动仅对实际新入库的记录执行）。同批内重复 `event_id` 同样只入库一次。
3. **成功响应** `202`：
   ```json
   { "accepted_count": 3, "duplicate_count": 1 }
   ```
   `accepted_count + duplicate_count == len(records)`；与输入条数不符视为服务端错误。
4. **永久非法记录**：任一记录校验失败 → `400`，响应携带**全部**非法记录的可定位索引与原因：
   ```json
   { "error": { "code": "INVALID_ARGUMENT", "message": "..." },
     "invalid_records": [ { "index": 2, "reason": "records[2]: event_id 非法" } ] }
   ```
   整批不部分提交；客户端隔离非法记录后重建剩余批次重发，不得在整批永久失败上无限重试。
5. **错误分类**：
   - `400`（正文超限、JSON 非法、schema 不支持、记录非法）→ 永久失败，不重试原批；
   - `401` → 按既有续期/退避处理（契约 §8，行为不变）；
   - `403`（Agent 禁用）→ 停止上报待心跳恢复，行为不变；
   - `429` → 尊重 `Retry-After`（机器端点当前无独立限流，保留该语义供后续启用，不得在本版本引入）；
   - 网络错误与 `5xx` → 有界重试（次数与退避由 Agent 侧预算冻结，不依赖服务端提示）。
6. v1 批次语义**完全不变**（`202 {"accepted": n}`，入库失败整体 500，无去重）——旧 Agent 兼容为冻结要求。

## 5. 资产来源关系

HTTP 事件入库成功 ≠ 资产关联成功。来源关系持久化于新表 `agent_http_asset_sources`（迁移 000133）：

| 列 | 语义 |
|---|---|
| `agent_id` | 上报 Agent（级联删除同 agent_http_events） |
| `endpoint_id` | 关联成功的 `api_endpoints.id`；未关联为 NULL |
| `host` / `method` / `path_template` | 资产键（**含 Host**，不同 Host 不合并；path 为模板化结果） |
| `source_type` / `source_instance` / `source_epoch` | 来源三元组 |
| `application_binding_id` / `binding_version` | 上报时声明的绑定（可 NULL） |
| `association_state` | `LINKED`（端点 upsert 成功）/ `UNASSIGNED`（v2 记录未声明绑定，待管理面确认，**不随意归入同名路径资产**）/ `QUOTA_REJECTED`（授权配额拒绝）/ `FAILED`（其他关联失败，`last_error` 记类别原因） |
| `first_seen_at` / `last_seen_at` | 该来源键的首/末次观测 |

语义冻结：

1. 去重键含 Host：`(host, method, path_template)` 逐批去重后再联动，不同 Host/应用不因 method+path 相同而合并；来源关系唯一键为 `(agent_id, host, method, path_template, source_type, source_instance)`，**多来源关联同一资产时各自成行**，不覆盖既有所有权。
2. gRPC 端点协议类型由 v2 记录的 `grpc` 子对象（可信协议元数据）决定为 `GRPC`，**不再统一写死 `REST`**；v1 记录维持 `REST` 现状。
3. v2 未声明绑定的记录：事件照常入库，资产联动**不执行** upsert，来源关系落 `UNASSIGNED` 待确认（§3.1 不随意归入同名路径资产）；v1 记录维持既有联动行为（兼容性冻结）。
4. 配额拒绝（`QUOTA_REJECTED`）、未绑定（`UNASSIGNED`）、关联失败（`FAILED`）均可经管理端查询（`GET /api/v1/traffic/agents/{agent_id}/http-asset-sources`，沿用 `traffic.agents.view` 权限），不只 Warn。
5. 重复事件（duplicate）不触发资产联动与来源关系写入，`last_seen_at` 不推进——重放不得放大任何计数。

## 6. 存储映射（迁移 000133）

`agent_http_events` 新增列（全部向后兼容，存量行取默认值，v1 写入路径不受 v2 校验约束）：

| 列 | v1 行取值 |
|---|---|
| `schema_version SMALLINT NOT NULL DEFAULT 1` | 1 |
| `event_id VARCHAR(128) NULL` | NULL（部分唯一索引不覆盖） |
| `source_type VARCHAR(16) NOT NULL DEFAULT 'PASSIVE_HTTP1'` | PASSIVE_HTTP1 |
| `source_instance VARCHAR(255) NOT NULL DEFAULT ''` | '' |
| `source_epoch BIGINT NOT NULL DEFAULT 0` | 0 |
| `source_capabilities_version VARCHAR(64) NOT NULL DEFAULT ''` | '' |
| `observed_http_version VARCHAR(8) NOT NULL DEFAULT 'UNKNOWN'` | UNKNOWN |
| `original_http_version VARCHAR(8) NULL` | NULL |
| `association_state VARCHAR(16) NULL` | NULL |
| `association_reason VARCHAR(64) NOT NULL DEFAULT ''` | '' |
| `capture_stream_id VARCHAR(255) NULL` | NULL |
| `application_binding_id UUID NULL` / `binding_version BIGINT NULL` | NULL |
| `grpc JSONB NULL` | NULL |
| `request_trailers / response_trailers JSONB NULL` | NULL |
| `req_body_quality / resp_body_quality JSONB NULL` | NULL |
| `collection_ts / ingestion_ts TIMESTAMPTZ NULL` | NULL |
| `tls_visibility` CHECK 扩展 `DECRYPTED` | 既有取值不变 |

`agents` 新增 `http_event_schemas SMALLINT[] NOT NULL DEFAULT '{1}'`。

v2 行的 headers 以数组形态 jsonb 存入既有 `request_headers`/`response_headers` 列（同列双形态：v1 为 string map、v2 为数组 map，按 `schema_version` 列区分解读）；`body_quality` 四要素同时镜像到既有 `req/resp_truncated`、`req/resp_original_size`（`original_total_size` 已知时）、`req/resp_skipped_reason` 列以保持管理端列表/详情兼容，完整对象另存 `req/resp_body_quality` jsonb（`captured_bytes` 与"未知长度"语义仅此保留）。

**管理端展示口径（G4a 已落地，2026-09-08）**：http-events 列表/详情既有字段照常工作（截断/跳过标记来自镜像列）；任务书 §4.3 管理接口与页面对齐已完成——列表/详情返回 v2 标量字段（来源三元组/能力版本/观测与原协议/关联状态与原因/流标识/来源绑定/collection_ts/ingestion_ts），详情还原 v2 headers/trailers 数组形态并带出 grpc/body_quality 子对象（v1 行上述子对象为 null，不伪造）；Agent 详情暴露 `http_event_schemas` 能力集（旧 Agent 页面显示「需升级」）；资产关联状态经 `GET /api/v1/traffic/agents/{agent_id}/http-asset-sources` 独立面板展示。权限沿用 `traffic.agents.view`/`traffic.agents.manage`，未新开入口。

## 7. 安全与脱敏纪律（沿用并重申）

- URI、Header、trailer、正文、grpc metadata 及错误文本均须 Agent 离主机前脱敏（Phase 3 契约 §5），服务端不二次脱敏但保留长度/控制字符边界校验。
- `event_id` 不得含敏感正文（随机或哈希派生）；`source_instance` 为受控配置标识，不接受事件自报身份用于认证或授权。
- 外部 Header（含 `X-Forwarded-*`、自报 `application_id`）不产生跨应用写入权限；`DECRYPTED` 不能由外部 Header 单独决定。

## 附录 A：NGINX_MIRROR 来源剖面（G2 落地，增量不改动正文冻结口径）

本附录描述 `wdsp-agent/internal/mirrorsrc`（Nginx mirror 适配器）落地后，`source_type=NGINX_MIRROR` 记录的具体口径；与正文冲突时以正文冻结条款为准。

- **单向源固定 null 口径**：`response`、`response_ts`、`latency_ms` 恒 null，`capture_direction=REQUEST_ONLY`、`skipped_reason=SOURCE_REQUEST_ONLY`。镜像接收器对 Nginx 子请求恒回 204，该状态码与业务响应无关，不得回填。
- **观测协议**：`observed_http_version` 如实标注子请求实际协议（Nginx mirror 子请求经 `proxy_pass` 通常为 `1.0`/`1.1`；adapter 从 Go `r.ProtoMajor/Minor` 映射）；`original_http_version` 恒 null（adapter 无法观测客户端与 Nginx 之间的原始协议，禁止猜测或从外部头推导）。
- **TLS 可见性**：`tls_visibility=DECRYPTED` 仅由部署拓扑断言（agent 配置 `mirror.tls_terminated_upstream=true`，接入模板锁定同机 unix socket / 回环），不由任何外部 Header 决定；默认 `PLAINTEXT`。
- **来源标识**：`source_instance` 取自受控配置 `mirror.source_instance`（必填）；`source_epoch` 为接收器启动时刻 Unix 秒（同一实例重启即换代次）；`source_capabilities_version` 恒为 `nginx-mirror/1`。`event_id`（flow_id）形态 `agentID-mirror-<instance>-<ms>-<seq>`。
- **可信控制头**：`X-WDSP-Original-Body-Size`（十进制字节数）由 Nginx mirror 内部 location 注入（`set $wdsp_orig_cl $http_content_length`，子请求 `Content-Length` 被 Nginx 清空时传递原始正文大小）。仅当 Go 侧 `req.ContentLength<=0` 时采用；该头连同全部 `x-wdsp-*` 命名空间头一律剥离、不进入记录。伪造防护：接入强制实例令牌（`X-WDSP-Mirror-Instance` 单值等值比对，缺失/错误/多值均 403 且不计入采集），令牌覆盖任何注入头。
- **body_quality 一致性**：chunked 且未读尽（原始总大小不可确认）时 `original_total_size` 保持 null（不填 0），`truncated` 如实保留（V1.1 起允许 truncated=true + null 组合表达「截断但总大小未知」）；已捕获字节数 `captured_bytes` 如实保留。
- **上行与降级纪律**：镜像记录仅经 v2 线格式上行；服务端未协商 v2 时不降级 v1，按 `drop_reason=mirror_v2_not_negotiated` 计数丢弃。
- **已知边界**：事件五元组为 Nginx↔适配器镜像连接的真实对端（unix socket 接入时以 `127.0.0.1:0` 占位），非真实客户端；业务侧取消/慢速/大正文上传不影响采集（E2E S4–S6 已取证，证据 `test/wdsp-agent-e2e/mirror/runs/`）。

## 附录 B：ENVOY_TAP 来源剖面（G3 落地，增量不改动正文冻结口径）

本附录描述 `wdsp-agent/internal/tapsrc`（Envoy tap 管理流适配器）落地后，`source_type=ENVOY_TAP` 记录的具体口径；与正文冲突时以正文冻结条款为准。S0 锁定与全部实测发现见 `deployment/envoy-tap/README.md`，真实取证证据见 `test/wdsp-agent-e2e/envoy-tap/runs/`。

- **单会话约束**：Envoy Admin 同时只允许一条已挂接 tap 流（v1.35.3 实测第二条 `POST /tap` 返回 400 "An attached /tap admin stream already exists."）。适配器因此为单会话设计：全部 tapped listener 的 tap filter 共用同一 `config_id`，一条管理流统一接收；原 §3.3 设想的多 channel（每 listener 一条流）不可行，以本实测约束为准。
- **不可获得字段（如实占位/置空，不造假）**：tap 缓冲输出不含地址、时间戳、连接/流 ID——五元组以 `127.0.0.1:0` 占位；`request_ts=response_ts=collection_ts`（tap 消息接收时间），`latency_ms=0` 不表达业务延迟；`capture_stream_id` 恒 null。
- **协议断言机制**：tap 输出中 HTTP/1 与 HTTP/2 呈现同一伪头形态，观测协议只能来自部署断言（会话级 `tap.observed_http_version`，覆盖全部 tapped listener；混合协议时必须 UNKNOWN，禁止据内容猜测）。tap 位于下游侧，断言有效时 `original_http_version=observed_http_version`，UNKNOWN 时恒 null。`tls_visibility=DECRYPTED` 仅由部署断言 `tap.tls_terminated=true`（可信终止点、同机回环拓扑）决定，混合终止点时必须 false，不由外部 Header 决定。
- **配对口径**：HTTP/2 多路复用的请求/响应配对由 Envoy 按流缓冲完成（一条 HttpBufferedTrace=一个流）；适配器不做跨消息配对，不用五元组/时间接近合并流。响应缺失（取消/重置/断连冲刷）如实 `association_state=REQUEST_ONLY`。
- **gRPC 口径**：仅元数据；`grpc_status` 取自响应 trailers，trailers-only 响应（错误快捷路径）时并入响应 headers 呈现（Envoy 实测形态），两处均如实解析；非法值视为不可见（null）；取消/未完成如实 `stream_state=UNKNOWN`，不伪造 `grpc_status=0`；消息正文恒不采集（`skipped_reason=content_type`），不解析 Protobuf。取消/截止场景 tap 实际到达形态以取证证据（verify-report.md「实际到达形态」节）为准。
- **WebSocket 口径**：只交付握手视图（101/失败状态如实记录）；帧/消息正文不驻留、不解析；握手记录在连接关闭时由 Envoy 冲刷（非实时）。
- **body_quality 截断口径**：正文被 Envoy 按 `max_buffered_*_bytes` 截断时 `truncated=true` 且 `original_total_size=null`（V1.1「截断但原始总大小未知」）；未截断时 `original_total_size` 为实际缓冲长度。
- **来源标识**：`source_instance` 取自受控配置 `tap.source_instance`（必填）；`source_epoch` 为适配器进程启动代次；`source_capabilities_version` 恒为 `envoy-tap/1`。`x-wdsp-*` 控制命名空间头一律剥离不入记录。
- **上行与降级纪律**：tap 记录仅经 v2 线格式上行；服务端未协商 v2 时不降级 v1，按 `drop_reason=tap_v2_not_negotiated` 计数丢弃（与 mirror 分账）。
- **输出与崩溃锁定**：输出格式锁定 `streaming_admin + JSON_BODY_AS_BYTES`；`streaming_admin + PROTO_BINARY_LENGTH_DELIMITED` 在 v1.35.3 实测使 Envoy 进程崩溃（SIGTRAP，absl null check），二进制路径禁用；不使用 file_per_tap 文件输出（脱敏前不落盘，无需 ADR）；Admin 仅回环。

## 修订记录

| 版本 | 日期 | 修订内容 | 批准 |
|---|---|---|---|
| V1.0 | 2026-09-08 | 初始冻结（G0+G1） | 三方冻结 |
| V1.1 | 2026-09-08 | §2.1 一致性约束修订：允许 `truncated=true` 且 `original_total_size=null` 表达「截断但原始总大小未知」（原约束要求 truncated=true 必配非 null original_total_size，使该真实场景不可表达）。同步修订：`server/internal/agents/http_events_v2.go` 一致性校验与测试、`wdsp-agent/internal/mirrorsrc` 不再强行回填 `truncated=false`、附录 A 对应口径。其他条款不变，对存量合法记录无影响（仅放宽此前必被拒的组合） | 主代理批准（P1-03 G3 任务附带契约澄清） |
| V1.1（增补） | 2026-09-08 | 新增附录 B：ENVOY_TAP 来源剖面（G3 落地）。纯增补，不改动正文与附录 A 任何冻结条款；单会话设计以 Envoy v1.35.3 实测约束（Admin 同时只允许一条已挂接 tap 流）为依据，取代原多 channel 设想 | 主代理批准（P1-03 G3 任务范围） |
