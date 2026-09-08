# 九章 WAF / WDSP 双模式业务性能监控与代码级 APM 详细设计方案

> 文档状态：方案评审稿  
> 编写日期：2026-08-30  
> 适用产品：九章 WAF、九章 WDSP / API 防护产品线  
> 目标读者：产品、架构、后端、网关、前端、测试、运维与安全团队  
> 变更性质：新增能力设计，不涉及现有版本号调整

## 1. 决策摘要

系统采用一套统一观测平台，同时支持两种互补模式：

1. **无 Agent 业务性能监控（默认常开）**：复用 Caddy/WAF 网关、访问日志、运行时事件和主动探测，在不侵入业务应用的前提下提供请求量、成功率、状态码、端到端耗时、端点性能、上下游可用性、WAF 处置影响和基础调用关系。
2. **有 Agent 代码级 APM（按需启用）**：仅在需要看到应用内部 SQL 耗时、目标函数调用、线程/协程阻塞、GC、连接池、消息队列等待和完整分布式调用链时部署。日常使用低开销基线策略，深度诊断必须通过有时限、可审计、自动回收的诊断会话开启。

两种模式共用应用、环境、API 端点、租户、时间范围、`request_id` 与 W3C `trace_id` 等关联维度。无 Agent 模式不是 APM 的简化页面，而是独立可用的生产监控能力；Agent 模式是针对内部原因定位的增强层。Agent、采集器或 APM 存储故障时，不得阻断或显著拖慢业务请求与 WAF 防护链路。

推荐采用 OpenTelemetry（OTel）作为遥测协议和基础语义，采用本地 Collector + 中央 Collector Gateway 的分层采集架构；PostgreSQL 保存配置、权限、诊断会话和 SLO，ClickHouse 保存高容量 trace/span 与聚合结果，Valkey 保存短期状态和缓存。原始 span 不写入现有 PostgreSQL 指标表。

## 2. 背景与现状

### 2.1 已有能力

当前仓库已具备以下基础，可直接复用：

| 能力 | 当前实现 | 可复用点 |
|---|---|---|
| 网关访问监控 | `server/internal/aggregations/`、`server/internal/metrics/metrics.go` | `http_requests_total`、`http_request_duration_ms`、P50/P95/P99、应用维度分钟/小时/日聚合 |
| 系统健康 | `server/internal/runtimehealth/` | 网关、API、PostgreSQL、Valkey、上游、证书、磁盘等组件健康快照 |
| 系统告警 | `server/internal/systemalerts/` | 告警状态机、去重、冷却、抖动抑制、自动恢复和审计模式 |
| WAF 访问日志 | Caddy JSON access log、`server/internal/accesslogs/` | 请求方法、域名、URI、状态码、响应大小、端到端耗时 |
| API 请求上下文 | `gateway/dynamic_security/context/` | `RequestID`、`TraceID`、`ApplicationID`、`APIEndpointID` 等关联字段模型 |
| API 资产 | `api_endpoints` 及 WDSP 管理接口 | 归一化方法/路径、应用归属、资产状态、学习状态 |
| API 调用拓扑 | `api_call_edges`、图谱/拓扑页面 | 调用关系表和可视化入口 |
| 安全数据最小化 | RequestContext、解析器和事件模型 | 凭据脱敏、请求体只存哈希/结构、受控扩展字段 |

### 2.2 关键缺口

现有能力只能回答“请求从网关看起来慢不慢”，不能稳定回答“为什么慢”：

- access log 尚未稳定携带 `application_id`、`api_endpoint_id`、`request_id`、`trace_id` 和 WAF 事件关联键；
- 运行时事件偏向异常或安全事件，纯 `ALLOW` 流量不足以还原完整业务基线；
- `api_call_edges` 已有读模型但缺少可靠写入链路，不能形成真实服务依赖和完整调用链；
- 没有应用进程内部的 SQL、缓存、RPC、消息、函数、异常、线程、GC、连接池数据；
- 现有 PostgreSQL 聚合表适合低基数指标，不适合保存海量 span 和高维 trace；
- 没有 Agent 注册、证书、策略、兼容性、升级、撤销和诊断会话控制面；
- 系统健康页关注平台组件，不等同于按业务应用、端点和版本分析的 APM 页面。

## 3. 建设目标与非目标

### 3.1 建设目标

- 无需业务应用改造即可看到应用/API 的 RED 指标：Rate、Errors、Duration。
- 从应用、API 端点、状态码、环境、版本、WAF 动作等维度发现性能退化。
- 部署 Agent 后，支持 HTTP/RPC、数据库、缓存、消息队列和跨服务 trace。
- 按需支持 SQL 耗时、目标函数调用、线程/协程阻塞、GC 和消息等待定位。
- WAF 安全事件、API 资产、业务请求与 APM trace 双向跳转。
- 遥测采集具备租户隔离、最小化、脱敏、采样、限流、审计与容量保护。
- 支持虚拟机、裸机、Docker 和 Kubernetes 部署，兼顾离线交付。
- 可分阶段上线，关闭新功能后不改变现有网关和管理面的行为。

### 3.2 非目标

- 第一阶段不建设通用日志平台，不替代现有安全事件和审计日志系统。
- 不默认采集请求/响应正文、认证信息、Cookie、Session、SQL 参数值或消息正文。
- 不默认对所有业务函数做全量方法级追踪；任意函数观测必须定向配置或手工埋点。
- 不承诺仅靠自动插桩即可覆盖所有框架和自研协议。
- 不在首期实现持续 CPU/内存全量剖析；连续 profiling 作为后续独立能力评估。
- 不允许 Agent 控制面执行任意命令、上传任意脚本或修改业务代码。

## 4. 双模式产品定义

### 4.1 能力矩阵

| 能力 | 无 Agent | Agent 基线模式 | Agent 深度诊断 |
|---|---:|---:|---:|
| 请求量、状态码、端到端时延 | ✓ | ✓ | ✓ |
| 应用/API 端点 P50/P95/P99 | ✓ | ✓ | ✓ |
| WAF 动作与性能关联 | ✓ | ✓ | ✓ |
| 上游可用性、网关到源站耗时 | ✓ | ✓ | ✓ |
| 服务依赖拓扑 | 近似/有限 | ✓ | ✓ |
| 完整分布式调用链 | — | ✓，参与服务需传播上下文 | ✓ |
| SQL/缓存/RPC/MQ span | — | ✓，受框架兼容性限制 | ✓ |
| SQL 指纹与慢 SQL 聚合 | — | ✓ | ✓，可提高采样率 |
| 运行时、GC、连接池、线程池 | — | ✓ | ✓ |
| 任意目标函数调用 | — | 仅手工埋点/预配置探针 | ✓，定向且限时 |
| 线程/协程阻塞分析 | — | 基础指标 | ✓，依赖语言诊断能力 |
| 消息队列生产、等待、消费链路 | — | ✓ | ✓ |
| CPU/内存剖析 | — | — | 后续增强，严格限时 |

### 4.2 使用原则

- **默认无 Agent**：新接入应用先获得外部业务性能视图，无需业务团队安装组件。
- **基线 Agent 常驻可选**：需要分布式 trace 和常规应用内部依赖时开启低开销策略。
- **深度诊断临时开启**：只有确认需要 SQL 细节、目标函数、线程阻塞、GC 或高采样完整链路时才开启，默认 15 分钟，最长 2 小时，结束后自动恢复基线策略。
- **能力如实降级**：链路中有服务未部署 Agent 或未传播上下文时，页面显示“部分链路”，不得伪装为完整 trace。

## 5. 总体架构

```text
                         ┌──────────────── 九章管理面 ────────────────┐
                         │ 应用/APIs/SLO/告警/权限/诊断会话/Agent策略 │
                         │ PostgreSQL（配置） + Valkey（短期状态）    │
                         └──────────────────┬─────────────────────────┘
                                            │
业务客户端 ──► Caddy + Coraza + Guard/WAF ──┼──► 业务应用/服务
                 │          │               │          │
                 │          │ W3C Trace      │          ├─ OTel Agent/SDK（可选）
                 │          └───────────────────────────┤  HTTP/RPC/DB/MQ/Runtime
                 │                                      ▼
                 │                            本地 OTel Collector
                 │                            （宿主机/Sidecar/DaemonSet）
                 │                                      │ OTLP/mTLS
                 ▼                                      ▼
       Access Log / WAF Event                 中央 Collector Gateway
                 │                            认证、限流、脱敏、批处理、采样
                 └──────────────┬───────────────────────┘
                                ▼
                      APM Ingest / Query 服务
                         │              │
                         ▼              ▼
                 ClickHouse          聚合/SLO/告警
              Trace/Span/明细聚合       │
                         └──────► APM Web 控制台
```

### 5.1 组件职责

| 组件 | 职责 | 不允许承担的职责 |
|---|---|---|
| WAF/网关关联模块 | 生成或校验 trace 上下文、写访问日志关联字段、记录网关和上游耗时 | 保存请求正文、同步等待 APM 后端 |
| 语言 Agent/SDK | 自动插桩、运行时指标、上下文传播、本地脱敏 | 执行远程任意代码、绕过业务权限 |
| 本地 Collector | 接收 OTLP、补充宿主/容器属性、内存队列、批处理、重试和首层过滤 | 保存长期数据、持有管理数据库凭据 |
| 中央 Collector Gateway | mTLS 认证、租户绑定、限流、二次脱敏、采样、路由和背压 | 信任客户端自报租户、参与业务请求 |
| APM Ingest/Query | 元数据校验、聚合、查询、诊断会话和 WAF 关联 | 接收无限制高基数字段 |
| ClickHouse | 保存 trace/span、事件和高容量聚合 | 保存 Agent 私钥、注册令牌和 RBAC |
| PostgreSQL | 保存配置、RBAC、SLO、会话、Agent 元数据和审计 | 保存海量原始 span |
| Valkey | 在线心跳、短期配额、查询缓存、会话状态 | 作为遥测事实的唯一持久化存储 |

### 5.2 分支与产品线边界

依据 `docs/BRANCHING_AND_PRODUCT_LINES.md`：

- OTel 接收、通用 APM 数据模型、Agent 管理、采样、SLO 和公共页面属于共享基础能力，优先落在 `main`；
- API 端点、敏感数据、用途分类、API 图谱和 WAF 安全事件关联属于 WDSP/API 增强，通过产品能力开关在 `develop` 接线；
- 合并时避免在 `develop` 复制一套 APM 基础实现，防止产品线长期分叉。

## 6. 端到端数据流

### 6.1 无 Agent 流程

1. 请求进入 Caddy，网关校验外部 `traceparent`；无效或不可信时生成新的 trace 上下文。
2. WAF 创建/补齐统一 RequestContext，将 `request_id`、`trace_id`、应用、域名、端点候选、WAF 动作写入受控上下文。
3. 反向代理记录网关总耗时、WAF 处理耗时、上游连接/首字节/总耗时（能获取的阶段分别记录）。
4. Access Log Collector 解析完整 ALLOW/BLOCK 流量，按应用和归一化端点产生分钟聚合。
5. 管理面展示 RED、慢端点、错误端点、源站异常和 WAF 处置影响；若仅能识别域名而无法识别端点，明确显示“未归类端点”。

### 6.2 Agent 基线流程

1. 业务服务收到网关传递的 W3C trace 上下文。
2. Agent 自动创建 SERVER/CLIENT/DB/MESSAGING span，使用语义约定生成低基数属性。
3. Agent 通过 OTLP 将数据异步发往本地 Collector；失败时有界重试，队列满后按策略丢弃，不阻塞应用。
4. Collector 绑定证书身份和租户，不接受 span 自报的 `tenant_id` 作为授权依据。
5. 中央 Collector 完成过滤、采样和路由，写入 ClickHouse；聚合任务生成服务、端点、SQL 和依赖的分钟指标。
6. 查询服务通过 `trace_id` 把网关访问记录、WAF 事件和应用内部 span 拼接为同一请求视图。

### 6.3 深度诊断流程

1. 具备权限的用户选择租户、应用、环境、实例、诊断能力、采样率和持续时间。
2. 系统展示预计额外开销、数据量和敏感风险，二次确认后创建诊断会话并写审计。
3. 策略只下发给匹配的 Agent；Agent 校验签名、有效期和允许能力后应用。
4. 会话期间可提高目标端点采样率，开启 SQL 慢查询细节、目标函数探针或线程阻塞诊断。
5. 到期、人工停止、容量保护或 Agent 失联时自动回到基线；结果保留会话 ID，方便复盘。

## 7. 关联标识与上下文传播

### 7.1 统一字段

| 字段 | 来源 | 用途 |
|---|---|---|
| `tenant_id` | Collector 证书/接入配置 | 强制租户隔离，不信任客户端覆盖 |
| `application_id` | 域名映射或 Agent 注册 | 对齐现有应用模型 |
| `api_endpoint_id` | WAF 归一化识别 | 对齐 API 资产、用途和风险 |
| `service.name` | Agent 资源属性 | APM 服务主标识，必须映射到应用或待认领服务 |
| `deployment.environment.name` | Agent 策略 | 生产、预发布、测试、开发 |
| `service.version` | 构建/部署注入 | 发布前后性能对比 |
| `service.instance.id` | 容器/进程/实例 | 实例级问题定位 |
| `request_id` | 网关生成 | 用户支持、访问日志和安全事件检索 |
| `trace_id` / `span_id` | W3C/OTel | 分布式调用链关联 |
| `waf_event_id` | WAF 事件 | 安全事件与性能链路双向跳转 |
| `diagnostic_session_id` | 管理面 | 标识深度诊断产生的数据 |

### 7.2 W3C Trace Context 信任规则

- 使用标准 `traceparent` / `tracestate` 传播，兼容异构语言；不自创传播头。
- 公网入口把外部 trace 视为不可信输入：格式错误、全零 ID、超长或异常 `tracestate` 一律丢弃并新建上下文。
- 是否延续外部 trace ID 由应用/域名策略决定；高安全场景默认新建内部 trace，并可保存不可逆关联摘要。
- 不盲从外部 sampled 标志，采样由本系统策略决定。
- 向客户端返回 trace ID 必须可配置；默认仅在可信内网或故障工单场景返回，避免形成额外枚举信息。
- 跨信任域传播时清理非必要 `tracestate`，且不得把租户、用户名或凭据放入传播头。

## 8. Agent 与语言支持策略

### 8.1 支持优先级

| 语言/运行时 | 首期建议 | 基线能力 | 深度能力与限制 |
|---|---|---|---|
| Java | P0 | Java Agent 自动插桩、HTTP/RPC/JDBC/MQ、JVM/GC/线程池 | 目标方法扩展、JFR 类诊断后续；禁止默认全方法追踪 |
| .NET | P0/P1 | CLR 自动插桩、ASP.NET、HTTP、数据库、运行时指标 | EventPipe/线程诊断后续，需验证框架和 Runtime 版本 |
| Node.js | P1 | preload 自动插桩、HTTP、常见数据库/MQ、event-loop 指标 | CPU profile 和自定义函数需限时开启或代码埋点 |
| Python | P1 | `opentelemetry-instrument`、常见 Web/DB/HTTP 库 | GIL、线程阻塞和任意函数不能仅靠通用自动插桩完整覆盖 |
| Go | P0（九章自身） | SDK/中间件显式埋点优先，HTTP/DB/RPC | 自动 eBPF 插桩依赖 Linux 内核/权限，作为可选兼容项，不作为首期唯一方案 |
| PHP | P2 | 依据实际客户技术栈评估 | 扩展兼容性和进程模型需专项验证 |

### 8.2 自动插桩边界

OpenTelemetry 自动插桩主要覆盖已支持的框架和库，并不能自动看到任意业务函数。代码级函数调用采用三层策略：

1. 框架/库自动 span：默认基线能力；
2. 业务关键路径手工埋点或注解：长期稳定、语义明确，推荐用于核心交易；
3. 诊断会话定向方法探针：仅允许匹配预定义包/类/方法，限制深度、次数、参数采集和持续时间。

禁止通过“匹配所有方法”实现所谓全量函数追踪，因为它会造成不可控 CPU、内存、数据量和敏感信息风险。

### 8.3 Agent 生命周期状态

```text
NOT_INSTALLED
    │ 注册
    ▼
ENROLLING ──失败──► ENROLL_FAILED
    │ 成功
    ▼
CONNECTED_BASELINE ◄──────────────┐
    │ 开启诊断                     │ 到期/停止/保护熔断
    ▼                              │
DIAGNOSING ────────────────────────┘
    │ 心跳超时          │ 撤销
    ▼                  ▼
OFFLINE             REVOKED
```

Agent 心跳不等于业务服务健康；两者在页面上分别展示，避免将“Agent 离线”误报为“业务宕机”。

## 9. Agent 注册、认证与策略下发

### 9.1 注册流程

1. 管理员创建一次性注册令牌，绑定租户、应用、环境、允许的语言和有效期；令牌只显示一次。
2. Agent 首次启动生成本地密钥，通过 TLS 向注册接口提交令牌和 CSR。
3. 管理面校验令牌后签发短期客户端证书，返回 Collector 地址、基础资源属性和已签名策略。
4. 后续 OTLP 和控制面请求使用 mTLS；证书轮换不依赖长期注册令牌。
5. 撤销 Agent 后，证书加入拒绝列表并停止接受其遥测；相关操作写入 `operation_audits`。

### 9.2 策略内容

- 允许的信号：traces、metrics、runtime、exceptions；
- 基线采样、慢请求阈值、错误保留规则；
- 属性允许清单、长度上限、SQL 处理方式；
- 本地队列、批量大小、内存上限和导出超时；
- 诊断会话范围、能力、有效期和熔断阈值；
- Collector 地址、证书轮换和配置版本。

策略必须签名并带版本号、签发时间和过期时间。Agent 只接受版本递增且签名有效的策略；控制面不可达时继续使用最后一份有效基线策略，过期的深度诊断策略必须本地自动失效。

## 10. 信号模型与采集字段

### 10.1 无 Agent 指标

- 请求量：按应用、归一化端点、方法、状态码类别统计；
- 时延：网关总耗时、WAF 处理耗时、上游连接耗时、首字节和上游总耗时；
- 错误：4xx、5xx、连接失败、超时、重试、熔断；
- 流量：请求/响应字节分布，使用区间桶，不把原始大小作为标签；
- 安全关联：ALLOW/BLOCK/OBSERVE、攻击类型、风险级别；
- 资产质量：未归类端点、影子/僵尸端点、版本变化和新端点性能基线。

### 10.2 Trace/Span 类型

| Span kind/类别 | 关键字段 | 注意事项 |
|---|---|---|
| HTTP SERVER | method、route template、status、duration | 不使用原始 URL 作为聚合键 |
| HTTP/RPC CLIENT | peer service、operation、status | 主机名需归一化，禁止记录 URL 查询值 |
| DB CLIENT | db system、operation、namespace、SQL fingerprint | 默认不保存 bind values；statement 需归一化/脱敏 |
| CACHE | system、operation、hit/miss、duration | 禁止保存 key 原文，可选不可逆摘要 |
| MESSAGING PRODUCER/CONSUMER | system、destination template、message operation、queue wait | 禁止保存消息正文和业务主键 |
| INTERNAL | 受控函数名、阶段名 | 仅手工埋点或诊断白名单 |
| WAF/GATEWAY | WAF 阶段、动作、上游阶段 | 低开销，不逐条记录所有规则执行 span |

### 10.3 运行时指标

- Java：heap/non-heap、GC 次数与暂停、线程状态、类加载、连接池和线程池；
- .NET：GC、堆、异常率、线程池队列、锁竞争等兼容指标；
- Node.js：event loop delay/utilization、heap、GC、活跃句柄；
- Python：进程 CPU/内存、GC、线程/协程相关可用指标；
- Go：goroutine、heap、GC pause、调度器和连接池；
- 容器/主机：CPU、内存、网络、磁盘和重启次数，由 Collector/平台采集，避免每个 Agent 重复采集。

不同语言不能强行统一不存在的指标。页面使用统一类别 + 原生指标明细，并展示数据来源与兼容性。

## 11. SQL、函数、线程、GC 与消息诊断设计

### 11.1 SQL

- 默认保存 SQL 指纹、数据库类型、库/Schema、操作类型、耗时、错误类型和行数区间；
- 指纹化移除字面量、注释和多余空白，`IN (...)` 等列表归一化，避免基数爆炸；
- 默认不保存 SQL 参数、连接串、用户名、完整异常中的凭据；
- 原始 statement 仅在受控诊断会话中、通过脱敏后可选保存，建议首期仍保持关闭；
- 慢 SQL 页面同时显示调用端点、上层服务、执行次数、P95、错误率和示例 trace，避免只按单次耗时排序。

### 11.2 目标函数

- 配置必须精确到应用、版本、包/命名空间和方法模式；
- 禁止默认捕获入参、返回值和局部变量；确有需要时只能选择允许字段并执行类型/长度/敏感规则校验；
- 限制最大嵌套深度、每 trace 最大函数 span 数和单实例每秒新增 span 数；
- 编译器内联、异步边界和动态代理可能导致函数不可见，页面需展示探针实际命中率。

### 11.3 线程/协程阻塞与 GC

- 基线模式使用运行时指标发现异常，不持续抓取完整线程栈；
- 深度诊断可按语言能力采集锁竞争、线程池排队、event-loop delay、goroutine 堆积或有限线程样本；
- 线程栈可能包含类名、路径和业务信息，按敏感数据处理并受更高权限控制；
- GC 分析必须关联堆使用、分配率、暂停时间、请求吞吐和版本，避免仅凭单次 GC 暂停下结论。

### 11.4 消息队列等待

- Producer span 记录发送，Consumer span 记录接收/处理；等待时间以消息系统可用时间戳计算；
- 传播 trace 上下文时遵循消息系统 header/property 能力，不能修改的遗留消息使用 link 关联；
- destination 使用主题/队列模板，不记录动态租户队列名或消息 key 原文；
- 重试、死信、批量消费和重复投递必须建模为事件/属性，避免把等待时间误算为业务处理时间。

## 12. 数据最小化与安全设计

### 12.1 默认禁止采集

- Authorization、Cookie、Set-Cookie、Session、API Key、JWT、签名和客户端证书私钥；
- 请求/响应正文、文件内容、消息正文；
- SQL bind values、数据库连接密码、完整连接串；
- 用户名、手机号、身份证、银行卡、精确位置等敏感字段原文；
- 原始 URL 查询参数、缓存 key、业务订单号等高基数标识；
- 环境变量、进程命令行中的秘密和任意本地文件内容。

### 12.2 两级脱敏

1. **Agent/本地 Collector 首层**：源头删除禁止字段，URL/SQL 归一化，限制属性数量和长度；
2. **中央 Collector 二层**：再次执行 allowlist、正则脱敏、敏感数据分类规则和租户配额，防止错误 Agent 配置泄漏。

已进入存储的数据若发现敏感泄漏，应支持按租户、时间、字段或 trace ID 执行受审计删除。任何导出同样经过字段权限和 CSV 注入防护。

### 12.3 威胁模型

| 威胁 | 影响 | 控制措施 |
|---|---|---|
| 伪造 `traceparent` | 污染链路、跨租户关联 | 入口校验、信任域策略、重新生成、租户不从 header 获取 |
| 伪造租户/应用属性 | 越权写入或读取 | mTLS 身份绑定租户；服务映射由控制面决定 |
| OTLP 洪泛/高基数攻击 | Collector/存储耗尽 | 每证书限流、内存限制、属性 allowlist、基数预算、熔断 |
| Agent 泄漏敏感数据 | 合规与数据安全风险 | 默认拒绝、两级脱敏、测试语料、字段扫描、审计删除 |
| 注册令牌窃取/重放 | 非法 Agent 接入 | 一次性、短有效期、绑定范围、CSR、使用即作废 |
| 策略被篡改 | 开启高开销/越权采集 | 签名策略、版本单调递增、有效期、本地能力白名单 |
| 恶意/失陷 Agent | 遥测投毒 | 证书撤销、速率/体积异常检测、隔离队列、可信版本清单 |
| 查询接口滥用 | 大查询拖垮存储或越权 | RBAC、租户条件强制注入、时间窗/行数上限、查询审计 |
| 深度诊断忘记关闭 | 长期性能和数据风险 | 自动过期、本地截止时间、全局 kill switch、容量保护 |

## 13. 采样、限流与基数控制

### 13.1 推荐默认策略

| 信号 | 默认策略 |
|---|---|
| 聚合指标 | 100% 接收，标签严格受控 |
| 健康/心跳 | 100%，固定周期 |
| 正常 trace | 基线 1%～5%，按租户和服务配置 |
| 错误 trace | 尽量保留 100%，受硬配额保护 |
| 慢 trace | 尾采样保留，阈值可按端点基线动态计算 |
| WAF 高风险/阻断 trace | 优先保留，仍执行脱敏 |
| 新版本/新端点 | 发布窗口临时提高采样 |
| 深度诊断 | 目标服务/端点 10%～100%，严格限时和限量 |

### 13.2 采样位置

- Agent 端 head sampling 可以降低网络和 Agent 开销，但被丢弃的 trace 无法由后续 tail sampling 恢复；
- 需要按错误、慢请求或安全事件决策时，在中央 Collector 做 tail sampling；
- 中央多实例 tail sampling 必须按 trace ID 做一致性路由，确保同一 trace 的 span 到达同一决策实例；
- 超大规模环境可采用“前置概率采样 + 中央尾采样”，但错误/高风险保留规则要通过明确策略保证，不宣称绝对 100%。

### 13.3 基数预算

- 聚合维度只用归一化 route，不使用原始 path；
- SQL 使用 fingerprint，不使用原始 statement 作为标签；
- 异常使用类型 + 归一化堆栈指纹；
- 每 span 限制属性数、事件数、link 数、单值长度和总字节数；
- 每租户、服务和实例设置 spans/s、bytes/s、活跃 trace 和每日存储配额；
- 超限时优先丢弃正常 trace，再丢弃重复异常样本，最后才影响错误/慢请求样本；所有丢弃量必须有自监控指标。

## 14. 容量模型与保留策略

### 14.1 估算公式

```text
spans_per_second = request_rate × sampled_trace_rate × average_spans_per_trace
raw_bytes_per_day = spans_per_second × average_compressed_span_bytes × 86400
physical_bytes = raw_bytes_per_day × replica_factor × retention_days
```

规划示例（不是性能承诺）：1000 请求/秒、5% trace 采样、每 trace 10 个 span、每 span 压缩后 300 字节，则约为 500 span/秒、12.96 GB/天；双副本约 25.92 GB/天。若保存 7 天原始 span，需在此基础上预留索引、合并、临时空间和 30%～50% 安全余量。

### 14.2 推荐保留层级

| 数据 | 默认保留 | 说明 |
|---|---:|---|
| 原始正常 trace | 7 天 | 可按版本/容量调整 |
| 错误、慢请求、高风险 trace | 14～30 天 | 单独 TTL 或标记保留 |
| 1 分钟聚合 | 30 天 | 服务/端点/SQL/依赖 |
| 1 小时聚合 | 180 天 | 趋势和容量规划 |
| 1 天聚合 | 1～2 年 | SLO 与版本趋势 |
| 诊断会话元数据与审计 | 按审计制度 | 不随原始 trace 同时删除 |

保留期必须可按租户策略缩短；延长保留需同时评估磁盘、备份、合规和查询性能。

## 15. 存储设计

### 15.1 PostgreSQL（控制面）

建议新增概念实体，最终名称以迁移评审为准：

- `apm_services`：Agent 服务与现有 application 的映射、认领状态；
- `apm_agents`：实例、语言、版本、状态、证书指纹、最后心跳；
- `apm_agent_policies`：基线策略版本、采样、脱敏和资源限制；
- `apm_diagnostic_sessions`：范围、能力、有效期、状态、发起/停止人；
- `apm_slos` / `apm_alert_rules`：指标目标、窗口和通知配置；
- `apm_storage_policies`：租户配额、TTL 和降级顺序。

所有变更型操作接入现有 `operation_audits`；注册令牌只保存不可逆摘要。

### 15.2 ClickHouse（数据面）

建议数据集：

- 原始 trace/span 与 span event；
- 服务、端点、SQL、依赖的分钟聚合；
- 异常指纹和示例 trace；
- 诊断会话产生的受控扩展数据。

按日期分区，排序键优先包含租户、服务、时间和 trace ID，结合实际查询画像设计跳数索引与物化视图。生产环境由九章维护明确的 Schema、TTL 和迁移，不依赖 Collector 在启动时自动创建或升级表。ClickHouse exporter 和 Collector 版本固定，升级前做兼容性回归。

### 15.3 不选 PostgreSQL 保存原始 span 的原因

原始 span 写入量高、属性多且查询常按时间/服务/trace 聚合，会与现有配置、审计、安全事件和管理事务竞争资源。PostgreSQL 保留强一致控制面，ClickHouse 承担列式高吞吐数据面，可以隔离故障域并独立扩容。

## 16. 接口草案

以下为评审用契约草案，不代表已存在接口；实现时必须同步 OpenAPI、权限、审计和测试。

### 16.1 查询接口

| 方法与路径 | 用途 | 建议权限 |
|---|---|---|
| `GET /api/v1/apm/overview` | 全局 RED、错误、慢请求、服务健康 | `apm.overview.read` |
| `GET /api/v1/apm/services` | 服务清单、模式、Agent 覆盖率 | `apm.services.read` |
| `GET /api/v1/apm/services/{id}` | 服务详情、版本/实例/端点 | `apm.services.read` |
| `GET /api/v1/apm/endpoints` | 端点性能列表 | `apm.services.read` |
| `GET /api/v1/apm/traces` | Trace 检索 | `apm.traces.read` |
| `GET /api/v1/apm/traces/{trace_id}` | 瀑布图、关联 WAF 事件 | `apm.traces.read` |
| `GET /api/v1/apm/sql` | SQL 指纹聚合与示例 trace | `apm.sql.read` |
| `GET /api/v1/apm/dependencies` | 服务/数据库/MQ 依赖 | `apm.services.read` |
| `GET /api/v1/apm/exceptions` | 异常指纹、趋势、示例 | `apm.traces.read` |
| `GET /api/v1/apm/runtime` | GC、线程、堆、连接池等 | `apm.runtime.read` |
| `GET /api/v1/apm/agents` | Agent 状态和兼容性 | `apm.agents.manage` |

所有列表接口必须有租户、时间窗、分页和服务范围；trace 明细接口限制最大 span 数，超限返回截断标识。

### 16.2 管理接口

| 方法与路径 | 用途 | 建议权限/审计 |
|---|---|---|
| `POST /api/v1/apm/agents/enrollment-tokens` | 创建一次性注册令牌 | `apm.agents.manage`，高风险审计 |
| `POST /api/v1/apm/agents/{id}/revoke` | 撤销 Agent | `apm.agents.manage`，高风险审计 |
| `PUT /api/v1/apm/policies/{id}` | 修改基线策略 | `apm.settings.manage`，高风险审计 |
| `POST /api/v1/apm/diagnostic-sessions` | 开启诊断 | `apm.diagnostics.manage`，高风险审计 |
| `POST /api/v1/apm/diagnostic-sessions/{id}/stop` | 提前停止诊断 | `apm.diagnostics.manage`，高风险审计 |
| `PUT /api/v1/apm/slos/{id}` | 配置 SLO | `apm.settings.manage`，中风险审计 |
| `POST /api/v1/apm/export` | 导出查询结果 | `apm.export`，审计、限行、脱敏 |

OTLP 数据面使用独立监听地址（通常为 4317 gRPC、4318 HTTP），不得与管理 API 共用浏览器会话认证。

## 17. 管理控制台信息架构

### 17.1 页面结构

1. **业务性能总览**：请求量、错误率、P95/P99、Apdex/SLO、慢服务、慢端点、版本退化、WAF 影响；
2. **服务目录**：应用映射、环境、版本、实例、观测模式、Agent 覆盖率和数据新鲜度；
3. **服务详情**：RED 趋势、端点、依赖、SQL、异常、实例、运行时与发布对比；
4. **API 性能**：复用 API 资产，展示用途、生命周期、敏感数据、风险与性能；
5. **调用链检索**：按 trace/request、服务、端点、时延、错误、WAF 动作和版本筛选；
6. **Trace 瀑布图**：临界路径、并行分支、DB/MQ/外部调用、缺失段和时钟偏差提示；
7. **数据库与缓存**：SQL 指纹、慢查询、错误、连接池、缓存命中与示例 trace；
8. **消息队列**：生产/等待/消费时长、积压、重试、死信和消费者分布；
9. **运行时**：GC、堆、线程/协程、event loop、连接池与实例对比；
10. **诊断中心**：会话创建、开销提示、实时状态、自动倒计时、结果和审计；
11. **Agent 管理**：安装指引、版本兼容、在线状态、策略、证书与撤销；
12. **SLO 与告警**：目标、燃尽、告警历史、确认、恢复和关联 trace。

### 17.2 关键交互

- 任何图表都显示当前数据来源：“无 Agent”“Agent 基线”“深度诊断”，防止误解覆盖范围；
- 从 WAF 安全事件一键打开同一 `trace_id`，从 trace 返回对应安全事件和 API 资产；
- Trace 瀑布图明确标识缺失服务、未插桩区段、采样造成的不完整和异步 link；
- SQL/异常列表默认展示指纹和聚合，不直接暴露原始内容；
- 开启诊断前展示预计采样量、CPU/延迟预算、有效期和自动停止时间；
- 查询默认时间窗 15 分钟或 1 小时，大时间窗自动切换聚合数据，避免扫描原始 span。

## 18. SLO 与告警

### 18.1 建议指标

- 可用性：成功请求 / 有效请求；业务 4xx 是否计入失败由端点策略定义；
- 时延：P95/P99、慢请求比例、按端点阈值；
- 错误：5xx、异常、依赖错误、数据库超时、消息消费失败；
- 饱和度：线程池队列、连接池使用率、event-loop delay、堆、GC 暂停、消息积压；
- 数据质量：Agent 离线、Collector 丢弃、trace 不完整率、端点未归类率；
- 发布回归：同服务新旧版本的吞吐、错误和时延差异。

### 18.2 告警规则

- 复用现有 `systemalerts` 的去重、冷却、抖动抑制、自动恢复和审计理念；
- APM 告警按租户 + 服务 + 环境 + 规则去重，不按实例创建海量告警；
- 使用持续窗口和最小请求量，避免低流量端点因单次错误告警；
- SLO 建议使用多窗口燃尽率，首期也可先实现静态持续阈值；
- 告警详情附带受控示例 trace，但通知内容不包含 SQL、URL 参数或用户数据。

## 19. 部署拓扑

### 19.1 虚拟机/裸机

- 业务进程加载语言 Agent；本地 Collector 以 systemd 服务运行；
- Agent 仅连接 `127.0.0.1` 或本机 Unix socket，Collector 通过 mTLS 连接中央网关；
- 本地队列目录、内存和 CPU 有明确上限，安装/卸载脚本可回滚。

### 19.2 Docker

- Collector 采用每宿主机或 sidecar 模式，依据隔离要求选择；
- Agent 参数通过只读环境或启动参数注入，不把注册令牌写入镜像层；
- 镜像固定 digest/version，提供 SBOM、签名和离线包。

### 19.3 Kubernetes

- 本地 Collector 使用 DaemonSet，中央 Collector 使用 Deployment；
- 可使用 OpenTelemetry Operator 做受控注入，但必须限定 Namespace、工作负载标签和语言版本；
- tail sampling 前通过 trace-ID aware load balancing 路由；
- Collector 使用 PodDisruptionBudget、反亲和、资源限制和持久/内存队列策略。

### 19.4 高可用与背压

- 中央 Collector 无状态部分水平扩展；tail sampler 的 trace 状态按 trace ID 固定路由；
- ClickHouse 至少双副本/分片策略按部署规模确定，控制面和数据面故障隔离；
- 数据面不可用时 Collector 有界重试，超过容量后按优先级丢弃并计数；
- 不允许无限磁盘队列填满业务主机；默认遥测故障 fail-open，不影响 WAF 转发。

## 20. 故障场景与降级行为

| 场景 | 预期行为 | 可观测结果 |
|---|---|---|
| Agent 初始化失败 | 应用继续启动或按显式严格模式处理；默认不阻断 | Agent 注册失败告警 |
| 本地 Collector 不可达 | Agent 有界缓冲后丢弃，不同步等待 | 导出失败、丢弃计数 |
| 中央 Collector 不可达 | 本地队列限量重试 | Collector 链路告警 |
| ClickHouse 不可用 | 中央队列限量缓存，查询显示数据延迟 | 存储不可用/采集滞后 |
| 管理面不可用 | 继续最后有效基线；诊断按本地截止时间停止 | 控制面失联状态 |
| Agent 证书过期 | 拒绝数据并提示轮换；不回退明文 | 证书告警 |
| 遥测突增 | 限流、采样降级、优先保留错误/慢请求 | 丢弃原因和策略变更 |
| 时钟漂移 | 瀑布图校正/提示，实例产生时钟告警 | trace 显示不确定区段 |
| 未部署 Agent 的下游 | 保留网关/上游 span，标记链路缺口 | “部分链路”状态 |

## 21. 性能预算与验收基线

性能指标需在目标语言、框架和真实流量模型上验证，下列为首期验收目标，不是未经测试的承诺：

### 21.1 Agent 基线模式

- 同构压测下吞吐下降不超过 3%；
- P95 延迟增加不超过 3% 或 2 ms（取较大值）；
- 稳态额外 CPU 不超过 5%，内存上限按语言和实例规格配置；
- Collector/存储不可用时，业务延迟无持续性放大；
- 禁用或卸载 Agent 后业务行为恢复，且不需修改业务数据。

### 21.2 深度诊断模式

- 创建会话时必须显示更高开销预算，默认仅选定实例；
- 会话达到 CPU、内存、队列或 span 速率阈值时自动降采样或停止；
- 诊断结束 1 分钟内恢复基线策略；Agent 离线后也必须依靠本地时间停止；
- 所有诊断数据可定位到会话、发起人和有效期。

### 21.3 平台查询

- 总览和常用聚合查询在目标容量下 P95 ≤ 2 秒；
- 单条 trace（不超过设定 span 上限）P95 ≤ 3 秒；
- 大时间窗强制使用聚合表，禁止无界原始扫描；
- 查询超时、截断、采样和数据延迟必须对用户可见。

## 22. 功能开关与兼容性

建议能力开关（最终名称以实现评审为准）：

- `APM_ENABLED`：启用通用业务性能页面和查询；
- `APM_AGENT_INGEST_ENABLED`：启用 Agent/OTLP 数据面；
- `APM_DEEP_DIAGNOSTICS_ENABLED`：允许创建深度诊断会话；
- WDSP 产品能力开关控制 API 资产、敏感数据、WAF 事件和 trace 的增强关联。

关闭全部新开关时，现有访问日志聚合、系统健康、WAF 防护和 WDSP 页面行为保持不变。数据库迁移采用新增表/列的向后兼容方式，先部署可读旧数据的服务，再启用采集，回滚时先停入口和任务再回滚应用，不删除已经采集的数据。

## 23. 实施阶段与任务拆分

### 阶段 0：ADR、容量验证与技术 POC（1～2 周）

交付：

- 确认 ClickHouse、Collector 发行方式、OTel 版本与许可证；
- 选择首批语言和真实示例应用；
- 验证 W3C 上下文经过 Caddy/WAF/业务服务的传播；
- 以目标吞吐验证 span 大小、采样、ClickHouse 写入和查询；
- 明确租户、应用、服务、环境和 API 端点映射规则。

退出条件：形成 ADR、容量表、兼容矩阵和安全评审结论；没有未决的强依赖版本。

### 阶段 1：无 Agent 业务性能增强（2～3 周）

交付：

- access log 补齐 request/trace/application/endpoint/WAF 关联字段；
- 完整 ALLOW/BLOCK 流量聚合，补充端点级 RED 和上游阶段耗时；
- 业务性能总览、服务/API 性能列表和无 Agent 标识；
- 慢端点、错误率、数据新鲜度告警；
- 对 `api_call_edges` 增加真实、可重算的基础写入链路。

退出条件：不安装 Agent 也能按应用和端点定位慢请求区间，并从 WAF 事件定位对应访问记录。

### 阶段 2：APM 数据面与 Agent 基线（3～5 周）

交付：

- 本地/中央 Collector、mTLS 注册、策略和心跳；
- ClickHouse schema、TTL、聚合、限流、采样和自监控；
- 首批 Java + Go（九章自身）支持；按客户优先级加入 .NET；
- 服务目录、trace 检索和瀑布图；
- HTTP/RPC/DB/MQ 基线 span 与 WAF 双向关联。

退出条件：跨至少 3 个服务的 trace 可还原，未插桩段被准确标记，Agent/Collector 故障不影响业务。

### 阶段 3：数据库、异常、运行时和 SLO（2～3 周）

交付：

- SQL 指纹、慢 SQL、异常指纹、依赖拓扑；
- JVM/Go 等运行时与实例对比；
- SLO、阈值告警、版本回归；
- Node.js/Python 支持视客户技术栈接入。

退出条件：能从慢端点下钻到慢 SQL/外部依赖/运行时异常，并生成可复现证据。

### 阶段 4：深度诊断（3～4 周）

交付：

- 有时限诊断会话、审批/权限、签名策略、自动停止和 kill switch；
- 定向函数探针、线程/协程阻塞、增强 GC 和 MQ 等待；
- 开销保护、结果对比和诊断审计。

退出条件：在目标语言中完成端到端演练，超限会自动降级/停止，敏感字段测试无泄漏。

### 阶段 5：规模化与交付加固（2～3 周）

交付：

- Collector 和 ClickHouse HA、容量告警、备份恢复和灾难演练；
- 离线包、固定镜像、SBOM、签名、升级/回滚和兼容矩阵；
- 10 倍流量突发、网络分区、存储故障和时钟偏差测试；
- 运维手册、排障手册和客户接入指南。

上述为 4 人左右团队约 10～16 个日历周的初步估算，实际取决于首批语言数量、ClickHouse 运维形态和深度诊断范围。

## 24. 测试计划

### 24.1 单元与契约测试

- trace/context 生成、校验、传播和信任边界；
- URL/SQL/异常指纹归一化与敏感字段脱敏；
- 采样、限流、配额、自动过期和状态机；
- 聚合幂等、迟到数据、TTL 与查询条件；
- OpenAPI、权限、租户强制过滤和审计。

### 24.2 集成与端到端测试

- Caddy → Java/.NET/Go/Node/Python → DB → MQ 的混合链路；
- 同步、异步、重试、超时、取消、批量消费和错误传播；
- WAF ALLOW/BLOCK/OBSERVE 与 trace/访问日志双向跳转；
- Agent 新旧版本、服务滚动发布、证书轮换和撤销；
- 无 Agent、部分 Agent、全 Agent 三种覆盖状态。

### 24.3 性能与稳定性测试

- 基线 Agent on/off 的吞吐、P50/P95/P99、CPU、内存和 GC 对比；
- 诊断会话不同采样率和函数探针范围的开销曲线；
- Collector 队列、tail sampler、ClickHouse 写入和查询容量；
- 10 倍突发、长 trace、大 span、高基数和异常风暴；
- 网络丢包、Collector 重启、ClickHouse 只读/不可用和磁盘不足。

### 24.4 安全与隐私测试

- 以 Authorization、Cookie、JWT、手机号、身份证、银行卡、SQL 参数和消息正文组成泄漏语料库；
- 验证 Agent、两层 Collector、存储、API、导出和告警通知全路径无明文；
- 跨租户读写、伪造证书、令牌重放、策略降级、trace header 注入和查询 DoS；
- 依赖漏洞、镜像签名、SBOM、许可证与离线安装包完整性。

## 25. 验收清单

### 25.1 无 Agent

- [ ] 新应用不安装 Agent 即可看到应用和归一化端点的请求量、错误率、P95/P99。
- [ ] 可区分网关/WAF 阶段和上游阶段耗时，无法细分时页面如实标识。
- [ ] ALLOW、BLOCK、OBSERVE 流量口径完整，聚合可重算且不重复。
- [ ] WAF 事件、访问日志、API 资产可通过 request/trace ID 关联。
- [ ] 未识别端点不会污染高基数指标，并有“未归类”治理入口。

### 25.2 Agent 基线

- [ ] 支持至少首批两种语言，兼容矩阵、安装、卸载和回滚文档齐全。
- [ ] 跨服务、数据库和消息队列链路可展示，断点被标为部分链路。
- [ ] SQL 参数、凭据、正文和敏感数据默认不进入 Collector、存储和 UI。
- [ ] Agent/Collector/APM 存储故障不阻断 WAF 和业务请求。
- [ ] 达到第 21 章的目标环境性能预算。

### 25.3 深度诊断

- [ ] 只有授权用户能创建会话，所有动作可审计。
- [ ] 会话绑定范围、能力、采样率和截止时间，不能无限期运行。
- [ ] 目标函数、线程/协程、GC、SQL 和 MQ 能力按语言如实展示。
- [ ] 到期、控制面失联或超出资源预算时自动恢复基线。
- [ ] 页面显示额外开销、数据截断、采样和兼容性限制。

### 25.4 平台

- [ ] 所有查询强制租户隔离、时间窗和分页；导出受权限和审计控制。
- [ ] Collector 丢弃、队列、采样、存储延迟和查询错误均有自监控。
- [ ] TTL、配额、备份、恢复、升级和回滚经过演练。
- [ ] 关闭功能开关后现有系统行为不变。

## 26. 主要风险与建议决策

| 决策项 | 建议默认 | 需要确认的问题 |
|---|---|---|
| 遥测标准 | OpenTelemetry | 固定哪个发行版和版本升级节奏 |
| Trace 存储 | ClickHouse 独立数据面 | 客户是否已有集群、单机/集群交付边界 |
| 首批语言 | Java + Go，.NET 紧随 | 客户应用语言占比和框架版本 |
| Agent 默认策略 | 无 Agent 默认；Agent 低采样可选 | 哪些产品版本/许可证开放 |
| 深度诊断 | 定向、限时、自动停止 | 是否需要审批流、最长时长和数据保留 |
| SQL 内容 | 默认只存 fingerprint | 客户是否允许脱敏 statement，建议首期不开放 |
| 原始 trace TTL | 正常 7 天，异常/慢请求 14～30 天 | 实际吞吐、磁盘预算和合规要求 |
| Profiling | 不纳入首期 | 是否单独立项、支持哪些语言和操作系统 |
| WAF trace 入口 | 校验外部上下文，按信任域决定续接 | 公网场景是否统一重建内部 trace |

## 27. 推荐仓库落点（实施时确认）

为保持现有模块边界，建议而非强制采用：

- `server/internal/apm/`：控制面、查询、聚合、SLO 和 Agent 管理；
- `server/migrations/`：控制面表、权限和兼容性迁移；
- `gateway/modules/jiuzhang_guard/` 与 `gateway/dynamic_security/context/`：trace/请求关联字段；
- `web/src/pages/apm-*`：总览、服务、trace、SQL、运行时、诊断和 Agent 页面；
- `deployment/apm/`：Collector、ClickHouse、证书和离线交付配置；
- `docs/`：架构、数据字典、安装、运维、兼容矩阵和安全说明。

正式实施前先建立 ADR，避免在仓库内直接引入未固定版本的 Collector 配置或第三方 Agent 二进制。

## 28. 官方参考资料

- [OpenTelemetry Zero-code Instrumentation](https://opentelemetry.io/docs/zero-code/)
- [Zero-code instrumentation concepts and limitations](https://opentelemetry.io/docs/concepts/instrumentation/zero-code/)
- [OpenTelemetry Collector deployment patterns](https://opentelemetry.io/docs/collector/deploy/)
- [Agent to Gateway deployment pattern](https://opentelemetry.io/docs/collector/deploy/other/agent-to-gateway/)
- [OpenTelemetry sampling](https://opentelemetry.io/docs/concepts/sampling/)
- [OpenTelemetry semantic conventions](https://opentelemetry.io/docs/specs/semconv/)
- [Database semantic conventions](https://opentelemetry.io/docs/specs/semconv/db/)
- [Runtime semantic conventions](https://opentelemetry.io/docs/specs/semconv/runtime/)
- [OpenTelemetry sensitive data handling](https://opentelemetry.io/docs/security/handling-sensitive-data/)
- [W3C Trace Context](https://www.w3.org/TR/trace-context/)
- [OpenTelemetry Collector ClickHouse exporter](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/exporter/clickhouseexporter/README.md)
- [ClickHouse OpenTelemetry integration](https://github.com/ClickHouse/clickhouse-docs/blob/main/docs/use-cases/observability/build-your-own/integrating-opentelemetry.md)

## 29. 最终建议

先做“无 Agent 关联链路 + OTel/ClickHouse 小规模 POC”，不要一开始就同时承诺所有语言和全量 profiling。第一条可交付闭环应是：

```text
WAF 慢请求
  → 应用/API 端点
  → trace
  → 慢 SQL / 外部依赖 / 消息等待 / 运行时异常
  → 版本或实例根因
  → 告警与诊断会话证据
```

在这条闭环稳定、脱敏和性能预算达标后，再逐语言扩展定向函数和阻塞诊断。这样既满足“平时不装 Agent 也能监控”，也能在真正需要时进入代码级 APM，而不会让深度诊断能力成为业务系统长期的稳定性风险。

---

Copyright © 聚信得仁  
All Rights Reserved.
