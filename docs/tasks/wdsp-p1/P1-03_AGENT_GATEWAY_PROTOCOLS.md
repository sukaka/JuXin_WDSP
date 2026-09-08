# P1-03：Agent 解密后接入及协议覆盖开发任务书

日期：2026-09-06。状态：待开发与验收。入口：[P1 总纲](README.md)；接续：[WORKLOG.md](WORKLOG.md)。

## 1. 目标与完成边界

让 WDSP Agent 从真实 Nginx、Envoy 和 Kubernetes 环境接收解密后的业务观测数据，经统一脱敏、限额、关联、缓存和上报形成可查询的 HTTP/API 资产。为每种来源提供真实协议证据、数据完整性和故障恢复状态。

本任务增强被动观测。镜像与 tap 采集不能直接阻断原业务请求；采集可见性也不等于网关具备该协议的在线防护能力。应用代码级调用栈、SQL 和异常仍依赖 APM 探针，不由 Agent 镜像自动生成。

P1 必须完成以下支持矩阵。范围外的能力须在产品页面、文档与证据中明确标为未支持，不能用“支持 HTTP/2、gRPC、WebSocket”笼统覆盖。

| 来源与业务协议 | P1 必须可见的内容 | 本期边界 |
|---|---|---|
| 现有被动 HTTP/1 采集 | 请求、可配对响应、有限正文与截断状态 | 保持原能力，补统一契约与可靠性；不是密文解密 |
| Nginx TLS 终止后 mirror | 原请求方法、Host、路径、允许的 Header、可选有限正文 | 仅请求；原业务响应和完整业务延迟不可见 |
| Envoy TLS 终止后的 HTTP/1、HTTP/2 tap | 规范化请求与响应、来源协议、流关联、截断及部分数据 | 依据 Envoy 输出采集，不实现原生 HTTP/2 HPACK 帧解析器 |
| Envoy gRPC unary 与 streaming | HTTP/2 流、服务/方法路径、内容类型、可获得的 trailers 与 grpc-status、取消/未完成状态 | P1 只保证元数据；不声明 Protobuf 字段解码或任意双向消息审计 |
| WebSocket 经可用采集源的 HTTP 握手 | Upgrade 请求、可获得的握手响应与来源能力 | 帧、消息正文、压缩扩展和长连接内容不解析 |
| Kubernetes | 真实 Pod、Namespace、Node 关联及更新/失效状态 | 工作负载归属区分权威 owner 信息与推断；不承诺全网络可见 |

原生旁路 HTTP/2/gRPC 解析、WebSocket 帧解析、HTTP/3/QUIC、AF_XDP 吞吐升级保留为后续任务。P1 不以 HTTP/2 转 HTTP/1 后的镜像冒充原生 HTTP/2 报文解析。

## 2. 现有实现与已知边界

先读以下现有文件及 Phase 1–5 契约，再决定新增文件名。不能把目录误写为 `agent/`。

| 现有路径 | 可复用内容与应核对的边界 |
|---|---|
| `wdsp-agent/internal/httpsensor/` | HTTP/1 重组、解析、正文采集与脱敏；新来源应共享策略与脱敏规则 |
| `wdsp-agent/internal/events/http.go` | HTTPRecord、请求/响应与批次；目前 TLSVisibility 注释为恒 PLAINTEXT |
| `wdsp-agent/internal/buffer/buffer.go` | 已有磁盘缓存；不是待新建的内存队列 |
| `wdsp-agent/internal/transport/` | 上报、重试和证书 PoP；应用层 PoP 不等于传输层 mTLS |
| `wdsp-agent/internal/k8smeta/` | 现有 Kubernetes 元数据采集与缓存 |
| `server/internal/agents/routes.go`、`server/internal/agents/machine_http.go`、`server/internal/agents/http_events.go`、`server/internal/agents/http_store.go` | 机器接入、校验、存储、管理查询和资产联动 |
| `server/internal/agents/policy_versions.go`、`server/internal/agents/overrides_admin.go` | 策略版本、回退和临时采集覆盖 |
| `web/src/pages/traffic-agents/` | Agent 列表、详情、策略、HTTP 事件、临时覆盖界面 |
| `deployment/kubernetes/`、`test/wdsp-agent-e2e/` | 当前部署与 E2E 入口；后者存在模拟 Kubernetes 和临时编译 shim 路径 |
| `docs/agents/WDSP_AGENT_PHASE1_CONTRACT.md`、`docs/agents/WDSP_AGENT_PHASE2_CONTRACT.md`、`docs/agents/WDSP_AGENT_PHASE3_CONTRACT.md`、`docs/agents/WDSP_AGENT_PHASE4_CONTRACT.md`、`docs/agents/WDSP_AGENT_PHASE5_CONTRACT.md` | server/agent/web 已冻结的数据、缓存、权限和元数据约定 |
| `docs/agents/WDSP_DISTRIBUTED_AGENT_DESIGN.md`、`docs/agents/WDSP_AGENT_REMAINING_WORK.md` | 总设计与历史剩余工作；历史验收数字不作为本次证据 |

编写时发现的明确契约缺口：

1. 机器 HTTP 批次限制为最多 100 条、序列化后 8 MiB；现有 batcher 对单条超大记录存在独占一批放行路径，与服务端接收上限不一致。应统一前置预算和永久失败处置，不能无限缓存重试。
2. `server/internal/agents/machine_http.go` 的资产发现目前复用 UpsertDiscovery；源码说明未在资产关系中持久化 source/agent_id。新接入不能延续只靠模糊路径反查的来源说明。
3. 当前请求/响应字段不能完整表达 HTTP/2 多路复用、gRPC trailers、来源能力和部分采集。新增字段必须同步 server/agent/web 与契约版本。
4. 当前磁盘缓存具备分段、大小与年龄限制，但执行淘汰时对当前段存在特殊处理。活动段超龄、单段超限的实际影响须复现，不能只根据配置项存在就声称严格限额。
5. `test/wdsp-agent-e2e/run.sh` 中可向临时源码快照加入编译 shim；正式交付验收必须使用目标源码直接构建，不允许用该路径代替真实依赖修复。模拟 Kube API 只能作为组件测试。

## 3. 接入架构与来源可信边界

### 3.1 共用处理链路

```text
HTTP/1 sensor / Nginx mirror adapter / Envoy tap adapter
    → 来源认证与能力识别
    → 有界规范化、流关联和采集级别选择
    → 共用脱敏与正文处理
    → schema 校验、大小预算、稳定 event_id
    → 已脱敏缓存与有界发送队列
    → 现有 Agent 认证上报
    → 幂等入库、资产来源关系、管理查询与质量状态
```

新适配器不得绕过原采集策略、临时覆盖 TTL、脱敏和配额。原始数据不得进入磁盘缓存、证据、调试日志或错误日志；序列化失败也只能记录字段类别与原因。

默认仅本机 Unix Socket 或明确隔离的 loopback 接入，使用 socket 权限、进程身份/受控容器挂载限制写入。开放远程采集监听不属于默认部署；如确有需求，应另做认证与网络边界 ADR，不能以“内网可信”代替鉴权。

Agent 身份来源于既有注册与机器认证，不从事件中的 agent_id 采信。应用映射由管理配置中的来源绑定、网关实例、Host 与明确路由映射确定；外部 Header 或 Agent 自报 application_id 不能取得跨应用写入权限。没有可靠映射的记录进入 UNASSIGNED 待确认状态，不随意归入同名路径资产。

### 3.2 Nginx 解密后镜像

采用 Nginx 自身 TLS 终止后的请求镜像，源配置需覆盖伪造的来源 Header 并携带固定采集实例标识。适配器接收镜像副本，不代理原始业务响应。

Nginx mirror 创建子请求且忽略其响应；启用 mirror_request_body 会预先读取请求正文，并影响非缓冲代理。因此不能把镜像接收器响应当作业务响应，也不能假设开启正文镜像对上传和流式业务没有影响。[Nginx mirror 官方文档](https://nginx.org/en/docs/http/ngx_http_mirror_module.html)

默认仅镜像必要请求元数据；正文按路径显式开启并给出大小和流式限制。真实验收覆盖大文件、慢上传、取消、chunked 和业务延迟。镜像端故障不改变业务授权或返回结果；其资源和排队开销必须测量。

`response=null`、`response_ts=null`、`latency_ms=null`，缺失原因为 SOURCE_REQUEST_ONLY。不因接收器返回 202 填入业务 status=202，不用镜像接收延迟代替源站延迟。原始协议无法可靠获取时填 UNKNOWN，不从 User-Agent 推断。

### 3.3 Envoy tap 与 HTTP/2/gRPC

S0 锁定 Envoy 具体发行版本、镜像 digest、tap protobuf/schema 和输出配置，核对该版本文档。官方将 tap 标为实验性功能；常见输出是受控管理流或文件，不能假定它原生向任意采集 HTTP 端点推送 JSON。[Envoy tap 官方文档](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/tap_filter)

P1 默认使用本机受控管理流加适配读取器，限制输出、分片、连接数和采集时长；不把 Envoy Admin 暴露到公网，也不常态写原始 tap 文件。若锁定版本只能满足其他安全输出方式，先写 ADR、证明脱敏前不落持久盘和访问隔离，再冻结部署模板。无法满足时对应支持格标 BLOCKED，不能退回不受控文件采集。

读取器必须按实际输出编码处理分帧和分片，支持流中断重连、半消息和乱序；不得把一次 read 当成完整 JSON 或 protobuf。按网关实例、重启代次、连接/流标识配对，不能只用 TCP 五元组或时间接近配对 HTTP/2 多路流。

明确 tap 位于下游或上游的哪一侧，分别记录原始业务协议与适配器观测协议。gRPC HTTP status=200 不等于 RPC 成功；读取 trailers 中可获得的 grpc-status，取消或未结束流保持未知/部分状态，不伪造 grpc-status=0。

P1 不解析未提供 schema 的 Protobuf 正文，不将二进制作为 UTF-8 或 JSON 参数学习。默认不采集 gRPC 消息正文，仅输出服务、方法、时间、状态、截断与来源；敏感 metadata 仍需脱敏。WebSocket 只交付握手视图，页面明确消息不可见。

## 4. 数据、接口与兼容契约

### 4.1 HTTP 事件 v2 增量

以下字段为**新增约定**。S0 形成正式 schema 示例、上限和迁移；没有协商前不能直接向严格校验的旧服务端发送新枚举。

| 字段 | 语义 |
|---|---|
| schema_version、event_id | 事件版本与 Agent 范围内稳定 ID；重试不改变 ID，不能含敏感正文 |
| source_type、source_instance、source_epoch | PASSIVE_HTTP1 / NGINX_MIRROR / ENVOY_TAP；受控来源与重启代次 |
| source_capabilities_version | 采集源能力版本；与 policy_version、Agent build 分开记录 |
| observed_http_version、original_http_version | 观测协议与可确认原协议；不确定为 null/UNKNOWN |
| tls_visibility | PLAINTEXT / DECRYPTED / UNKNOWN；DECRYPTED 需可信终止点证据，不能由外部 Header 单独决定 |
| association_state、association_reason | COMPLETE / REQUEST_ONLY / PARTIAL / UNCORRELATED；含超时、单向源、断连、截断等原因 |
| capture_stream_id | 来源作用域内连接/流关联标识；不替代 Agent 身份或业务 Request ID |
| application_binding_id、binding_version | 已批准的来源映射；服务端重新校验，不直接信任任意 application_id |
| headers、trailers | v2 明确重复字段、大小写与顺序规则；必要时用数组保留重复值，不能隐式逗号合并 Set-Cookie 等特殊字段 |
| grpc | 可空的 service、method、grpc_status、stream_state；未结束、不可见与成功分别表示 |
| body_quality | 截断、跳过原因、实际捕获字节、原始总大小是否已知；未知长度不能填 0 |
| collection_ts、ingestion_ts | 来源采集和服务端接收时间；分别度量延迟，不混成业务延迟 |

URI、Header、trailer、正文及错误文本均先脱敏；`:authority`、`:method` 等伪头按冻结规则映射，Host/authority 冲突不能静默覆盖。保留原协议质量状态，不能把不完整输入转换成可信完整请求。

### 4.2 机器端点与幂等

复用现有 `POST /api/v1/agents/{agent_id}/http`，机器接口使用自身 JSON 契约，不能套管理端响应 envelope。现有返回 `202 {"accepted": n}`，入库失败整体报错；新版本语义如下：

1. 在现有注册/心跳能力协商上扩展 event schema 支持范围，实际落点由 S0 核对；未确认 v2 前只使用旧兼容采集模式，不能静默丢弃新字段宣称完整支持。
2. v2 批次在服务端全量校验后事务写入，按 `(agent_id, event_id)` 唯一去重；重复事件确认但不重复入库或扩大资产计数。
3. v2 成功响应分别返回 accepted_count、duplicate_count，和输入条数核对；永久非法记录返回可定位的索引与原因，且本批不部分提交。客户端隔离非法记录后重建剩余批次，不在整批永久失败上无限重试。
4. 正文超限、schema 不支持、记录非法是永久失败；认证过期按现有续期/退避处理；429 尊重 Retry-After；网络/5xx 才进入有界重试。修改旧错误码需兼容测试并写契约差异。
5. 保留最多 100 条、序列化后最多 8 MiB 的上限，包含 JSON 转义和 envelope；单条先缩减可选正文/元数据并标记截断，仍超限则丢弃并计数。不得依赖服务端拒绝实现无限“稍后再试”。

资产发现是独立可重试的派生步骤：HTTP 事件成功入库不等于资产关联成功。新增持久化来源关系与受限补偿队列/状态，保存 endpoint、Agent、来源实例、绑定版本、首次/最后观测及关联状态；不要把原有资产所有权覆盖成最后上报 Agent。

应去重并保留多来源关联；避免仅按 method+path 将不同 Host/应用合并。gRPC 标识由可信协议元数据产生，不继续统一写为 REST。配额拒绝、未绑定应用和关联失败均可查询，不能只 Warn 后在 UI 显示全部成功。

### 4.3 管理接口与页面

复用现有 Agent 详情、策略版本及 `/api/v1/traffic/agents/{agent_id}/http-events` 列表/详情，扩展来源、协议、数据质量、去重、缓存和资产关联状态；沿用已存在的 `traffic.agents.view`（读取）和 `traffic.agents.manage`（管理）权限、CSRF 和数据范围，不另开匿名查询入口。

策略明确：适配器 enabled、允许来源实例、来源绑定、元数据/正文级别、字段脱敏、请求/响应预算、流超时、缓存容量和临时覆盖到期。保存、服务端目标版本、Agent 收到版本、实际加载结果分别显示。旧 Agent 不支持的能力禁止假报启用，应显示需升级。

## 5. 资源、缓存与数据安全

1. 为每个来源设置连接数、在途流数、单流缓冲、总缓冲、Header/正文、解压后大小、压缩比、解析深度、时间和采样上限。默认元数据采集；不支持或超限时降为有说明的部分记录，不能无限拼接流。
2. 统一脱敏须覆盖 Authorization、Cookie、Set-Cookie、代理认证、API Key、URL query、表单、JSON、trailer 和诊断文本。L0–L3 与临时采集覆盖按原契约复用；未知二进制/压缩或不能安全脱敏的内容跳过，不采集后再赌后端能清洗。
3. 已有磁盘缓存参考默认 16 MiB 分段、512 MiB 总量、30 分钟年龄；最终默认值以复核代码为准。必须验证活动段、单条大记录、磁盘满、损坏段、权限和重启，严格执行上限且有淘汰计数。
4. 沿用目录 0700、文件 0600 等最小权限；缓存中只允许已脱敏数据。文件权限不等于加密，不得声称已有磁盘加密。需要静态加密时另行设计密钥生命周期，不能硬编码密钥。
5. 补传与实时流量之间有可配置公平预算，不允许长期离线积压永久饿死实时采集。使用至少一次发送与服务端幂等，不宣称网络恰好一次。
6. 接收、解析与发送队列必须有界。满载时按冻结策略丢弃低优先级采集并报告具体原因；不能阻塞或修改原业务流量。Agent 故障是否影响代理 CPU/延迟用真实负载测量。
7. 统一指标至少包含 received、normalized、masked、queued、accepted、duplicate、dropped_by_reason、spool_bytes/oldest_age、source_disconnect、association_pending。日志缺失和状态未知不能显示为零丢包。

## 6. Kubernetes 与部署验收

在真实 Linux Kubernetes 环境使用锁定镜像与最小 RBAC，覆盖至少两个业务 Pod 的创建、滚动更新、迁移和删除。验证 Pod IP 重用不会关联旧租户/工作负载，缓存有过期与失效状态；元数据 API 失效时业务采集继续，但显示 STALE/UNAVAILABLE。

先检查现有 k8smeta 对 Pod/Endpoint、节点过滤及 owner 的实现。禁止为了拿元数据赋予 cluster-admin，禁止把推断的工作负载显示为已验证。跨 Namespace 与 hostNetwork 场景必须给出映射证据，不能只测试固定假 IP。

交付独立 Nginx、Envoy 和 Kubernetes 接入模板与支持矩阵，每份列出版本、采集位置、权限、数据范围、资源上限、停止采集和回退步骤。所有采集入口默认关闭，启用前显示实际将采集的字段及脱敏示例。

## 7. 实施阶段

| 阶段 | 任务 | 退出条件 |
|---|---|---|
| G0 | 复核现状，锁定代理版本和输出格式、协议矩阵、schema 与资源预算 | server/agent/web 契约可审查；范围外能力明确 |
| G1 | v2 能力协商、统一规范化/脱敏、幂等、来源关系及迁移 | 旧 Agent/Server 兼容、大小上限和机器认证测试通过 |
| G2 | Nginx 请求镜像适配与真实 TLS 流量 | 请求来源、缺响应说明、故障和业务性能证据完整 |
| G3 | Envoy HTTP/2/gRPC/握手适配与关联 | 多流、trailer、半消息、重启与不支持状态可验证 |
| G4 | 严格缓存、背压、真实 Kubernetes 与页面 | 丢弃/补传/健康/来源可解释，真实 Pod 变更通过 |
| G5 | 兼容升级、回退与完整矩阵回归 | 所有强制项通过；构建未注入 shim；限制与原始证据归档 |

## 8. 强制验收清单

| ID | 场景与操作 | 必须验证的结果 |
|---|---|---|
| AGT-001 | 原 HTTP/1 双向、chunked、截断与 TLS 密文输入 | 旧能力不退化；密文不伪装明文消息 |
| AGT-002 | 真实 Nginx HTTPS 终止、GET/POST 元数据镜像 | 原请求字段和可信来源正确，不依赖公网接收器 |
| AGT-003 | 镜像接收器返回各种状态而业务源站返回不同状态 | response/latency 保持不可见，不把镜像响应写为业务结果 |
| AGT-004 | Nginx 大上传、慢上传、流式、取消及镜像故障 | 采集边界明确，业务影响有延迟/资源原始数据 |
| AGT-005 | Envoy 真实 HTTP/2 多路并发、连接重用 | 请求响应按实例/代次/流配对，不串流或用五元组误并 |
| AGT-006 | Envoy tap 分片、半包、乱序、重连与进程重启 | 有界重组；不能解析时部分/丢弃原因明确，无无界缓存 |
| AGT-007 | gRPC unary 成功和非零 grpc-status | HTTP 200 与 RPC 失败分别显示，trailer 来源准确 |
| AGT-008 | gRPC streaming、取消、截止时间与长连接 | 未完成/取消可辨别；无整流无限缓存或 Protobuf 明文猜测 |
| AGT-009 | WebSocket 正常/失败握手及消息发送 | 只声明握手；页面明确消息帧未采集 |
| AGT-010 | 原始 HTTP/2 转 HTTP/1、未知来源与伪造 TLS Header | 原协议/观测协议分开，不伪造 DECRYPTED 或原生解析能力 |
| AGT-011 | Header、query、正文、trailer 带合成敏感标记 | Agent 出口、磁盘、日志、证据均无标记明文 |
| AGT-012 | 重复 Header、authority 冲突、压缩炸弹与二进制正文 | 规范化规则一致；超限/未知安全跳过，内存 CPU 受控 |
| AGT-013 | 100/101 条批次、JSON 转义后 8 MiB 边界和单条超大 | 严格限制；不出现永久超限整批无限补传 |
| AGT-014 | 5xx/断线后整段重放、重复确认与响应丢失 | event_id 不变，服务端幂等，计数和资产不重复放大 |
| AGT-015 | 一条非法记录、旧 schema、401/403/429 与 5xx | 按永久/可恢复错误分类；批次原子性与续期/退避正确 |
| AGT-016 | 缓存活动段超龄、单段超量、满盘、损坏和进程崩溃 | 容量/年龄严格受控，丢弃可见，重启不输出未脱敏数据 |
| AGT-017 | 长时间离线后恢复同时持续实时流量 | 补传与实时均能前进；队列和丢弃指标准确 |
| AGT-018 | 非授权本机进程、恶意远程输入、伪造 Agent/来源身份 | 默认入口隔离有效，机器认证与来源绑定不可绕过 |
| AGT-019 | 同路径不同应用、多 Agent 同一资产、未绑定来源 | 应用隔离和多来源关系正确，不覆盖所有权或错误合并 |
| AGT-020 | 资产配额拒绝、发现失败后补偿与 gRPC 资产分类 | 事件入库/资产关联状态分离，失败可追踪，协议不全写 REST |
| AGT-021 | 真实 Kubernetes Pod 滚动、删除、IP 重用、Namespace | 元数据关联及时失效，无旧归属串联；证据非 fake Kube |
| AGT-022 | Kubernetes API 403/超时与 RBAC 最小权限 | 采集可继续但元数据显式失效，不申请 cluster-admin |
| AGT-023 | 旧 Agent 对新 Server、新 Agent 对旧 Server | 协商/降级明确，未支持能力不被显示为已启用 |
| AGT-024 | 临时采集覆盖到期、策略部分 ACK、保存/发布失败 | 真实生效与目标版本分开；到期停止额外正文采集 |
| AGT-025 | 无权限读取正文、缺 CSRF、恶意文本与列表返回 | 服务端鉴权有效，无 XSS，筛选/分页上下文保留 |
| AGT-026 | 高并发短请求、长流、来源断开与恢复页面 | 来源、缓存、丢弃、数据质量有独立状态，不只绿灯在线 |
| AGT-027 | 目标源码直接构建并运行真实代理/K8s E2E | 无编译 shim 或 Mock 替代；记录版本、digest、节点和执行数 |
| AGT-028 | 正式升级后关闭适配器、回退策略与程序 | 原业务继续；旧记录可读；新 schema 缓存不被旧程序误解析 |

## 9. 交付与开发提示词

最终交付须包含三方契约、迁移/索引、适配器、来源绑定、部署模板、协议矩阵、保留数据与缓存处理方案、真实环境回放证据。回退时先停止新来源并处理 v2 缓存，再降级不支持 v2 的程序；不可静默丢弃积压或把解析失败当空缓存。

```text
实现 docs/tasks/wdsp-p1/P1-03_AGENT_GATEWAY_PROTOCOLS.md。先读 P1 总纲、WORKLOG、AGENTS 和本任务第 2 节列出的五份 Agent Phase 契约；核对 wdsp-agent、server/internal/agents、管理页及现有 E2E。只按 G0 到 G5 逐阶段推进。

复用现有 HTTP/1、脱敏、磁盘缓存、PoP 上报和管理权限。新增 Nginx 请求镜像与 Envoy tap 适配器前，冻结锁定版本、实际输出格式、来源绑定和 schema v2 协商。请求镜像无原业务响应；HTTP/2 多流要真实配对；gRPC 本期为元数据；WebSocket 本期为握手。不得以转码结果冒充原生协议解析，不宣称 Agent 在线阻断。

补齐单条超大批次、幂等重放、永久错误、严格缓存上限和资产来源关系。脱敏必须在出主机及持久化前；默认本地受控入口，不放开 Admin 或采集端口。真实 Linux、Nginx、Envoy、Kubernetes 执行 AGT-001 至 AGT-028，不用 fake Kube、源码 shim、历史数字代替证据。每阶段更新 WORKLOG，交付文件、契约、测试、限制和回退；缺环境保留 BLOCKED。
```
