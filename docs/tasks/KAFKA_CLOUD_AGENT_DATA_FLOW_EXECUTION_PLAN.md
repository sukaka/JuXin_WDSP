# WDSP Kafka 事件总线、云 API Agent 与数据流向执行方案

> 文档状态：一期主链路已实现；本文保留原执行方案，实际交付边界与验证记录见第 17 节。
> 适用产品线：九章 WDSP。
> 关联设计：`docs/API_DATA_FLOW_AND_CROSS_BORDER_ANALYSIS_DESIGN.md`、`docs/BUSINESS_PERFORMANCE_APM_DESIGN.md`、`docs/agents/WDSP_DISTRIBUTED_AGENT_DESIGN.md`。

## 1. 建设目标

在不能部署透明代理、不能使用交换机 SPAN、不能购买或配置云流量镜像的环境中，仅通过在业务侧安装 Agent，完成：

1. 应用 API 性能监控：入站/出站 HTTP、RPC、SQL、MQ 调用和分布式 Trace。
2. API 安全采集：API 资产、请求/响应 Schema、敏感字段、运行状态和安全分析所需元数据。
3. 中心事件接入：使用 Kafka 承接中心 Receiver 与异步消费者之间的事件流，提供削峰、缓冲、回放和消费者解耦。
4. 数据流分析：自动构建“来源—服务—API—Kafka—数据库—第三方”的调用拓扑，并在有证据时标注流转的数据类型和字段。
5. 可解释性：每条边区分观察、关联、推断和声明，展示证据、时间范围、样本量、数据质量和置信度。

最终验收场景：

```text
Client
  → order-service / POST /orders
  → profile-service / GET /profiles/{id}
  → Kafka / customer-events
  → notification-service
  → 第三方短信服务

图中自动出现：
- 服务与 API 节点；
- 调用次数、错误率、耗时；
- Kafka Topic 和生产/消费关系；
- 有证据的“手机号、身份证号”等数据类型标签；
- 点击边可下钻到脱敏证据和 Trace。
```

## 2. 实施前基线与约束

### 2.1 已有能力

- APM 当前链路为业务 OTel Agent/SDK → 本地 Collector → 中央 Collector → ClickHouse。
- APM 已能根据 CLIENT/PRODUCER Span 推导服务、数据库、MQ 和外部地址依赖。
- 流量 Agent 已有注册、心跳、证书 PoP、策略、限量缓存、批量上报和 v1/v2 HTTP 事件协议。
- `POST /api/v1/agents/{agent_id}/http` 已有鉴权、幂等、资产联动和持久化逻辑。
- API 安全已有资产、运行时事件、敏感字段、Schema、风险和调用边等基础能力。
- 数据流向与跨境分析已有完整设计稿，但尚未形成本方案所述的实时 Agent → Kafka → 数据流图链路。

### 2.2 实施前缺口

- 当前底层没有 Kafka 部署和 Go 生产者/消费者。
- APM 默认不采集请求/响应正文，现有策略也没有 API 安全观测信号。
- 现有流量 Agent 主要是主机/Kubernetes 旁路 Sensor，不是进程内 API Sensor。
- 现有 API 调用边主要依据同一身份的相邻调用推断，不能替代真实服务调用证据。
- 现有 APM 依赖边是客户端 Span 单视角推导，尚未完成 CLIENT/SERVER、PRODUCER/CONSUMER 配对和字段级传播分析。

### 2.3 不可突破的红线

- Agent 不得成为业务串行节点，采集和上报故障不得阻断业务。
- 业务 Agent 不直连 Kafka；Kafka 只允许部署在 WDSP 中心数据面。
- 新增远程 API 观测协议不得传输完整请求/响应正文、Authorization、Cookie、Token、SQL 绑定值或 Kafka 消息原文。
- 原始 Body 只允许在业务节点内受控处理；离开节点前必须完成结构提取、敏感识别、脱敏和丢弃。
- 不把低置信度推断包装成确定事实，不把“未识别到敏感字段”表述为“没有敏感数据”。
- 不修改现有 v1/v2 Agent 线协议语义，不破坏现有网关 JSONL 采集链路。
- 所有第三方组件、客户端库和镜像必须完成许可证审查、版本锁定和 SBOM/依赖登记；禁止 `latest`。

## 3. 总体技术决策

| 决策 | 选择 | 原因与代价 |
|---|---|---|
| Kafka 使用范围 | 一期承接新增云 API 观测事件；既有 v1/v2 与 APM 主链路暂不强切 | 先交付云上 API 能力，避免同时改变尾采样、旧 Agent ACK 和既有数据正确性 |
| Agent 形态 | 统一安装包：语言探针 + 本地 `wdsp-agent` + 本地 OTel Collector | 统一交付不等于塞进一个进程；避免每种语言重复实现证书、缓存和脱敏 |
| 语言优先级 | Java/Spring 首个正式版本，随后 Node.js、Python、.NET；Go 使用 SDK/中间件 | Java 零代码接入成本低；Go 不能照搬 Java 字节码方案 |
| 中心存储 | PostgreSQL 管资产/风险/权限，ClickHouse 管高频观测和图聚合，Valkey 只做缓存/热状态 | 避免把全量 API 观测压到 PostgreSQL；Kafka 不作为永久事实库 |
| 数据流证据 | Trace 优先，Request/Message ID 和字段 HMAC 次之，时间相似度只作低可信推断 | 保证数据流图可解释 |
| 采样 | APM 性能采样与 API 安全采样独立 | 防止 APM 5% 尾采样造成 API 资产和数据流大面积断链 |
| 部署 | 开发单 Broker；生产三节点 KRaft，不引入 ZooKeeper | 降低组件数量并满足生产高可用 |
| Schema 管理 | 使用版本化 JSON 契约，不新增 Schema Registry | 控制一期组件数量和交付复杂度 |

### APM 为什么不一期强切 Kafka

当前 APM 多实例链路依靠 trace ID 路由保证同一 Trace 到达同一尾采样实例。若在现有 Router/Sampler 之间直接插入 Kafka，会引入分区再均衡、尾采样状态迁移、租户身份透传和回放重复计数问题。

一期保持 APM OTLP 主链路不变，数据流分析通过 `trace_id/span_id` 关联 API 观测与 APM Span。后续若需要 APM 也经过 Kafka，必须单独完成 ADR、trace 亲和、再均衡和回放验收后再启用。

## 4. 目标架构

```text
业务云主机 / Kubernetes Pod
┌──────────────────────────────────────────────────────────┐
│ 业务进程                                                  │
│  └─ 九章语言探针 / OTel Instrumentation                  │
│      ├─ HTTP Server/Client、RPC、SQL、MQ Span             │
│      └─ 有界本地 API Capture（Body 仅在节点内可见）        │
│              │                                           │
│              ├─ OTLP → 本地 Collector ────────────────┐   │
│              │                                       │   │
│              └─ Unix Socket → 本地 wdsp-agent          │   │
│                     ├─ 限量/解压/解析                   │   │
│                     ├─ Schema/敏感字段识别              │   │
│                     ├─ HMAC/脱敏/丢弃原文               │   │
│                     └─ 有界磁盘 Spool + PoP 上报        │   │
└─────────────────────────────┬───────────────────────────┘
                              │ HTTPS + 证书 PoP
                              ▼
                 WDSP API Observation Receiver
                     鉴权 / 绑定 / 校验 / 配额
                              │ acks=all，幂等生产
                              ▼
                    Kafka（中心私有网络）
                              │
          ┌───────────────────┼────────────────────┐
          ▼                   ▼                    ▼
  API Projection       Dataflow Builder       DLQ/质量监控
  资产/Schema/风险      服务边/字段传播          重试/审计/告警
          │                   │
          ▼                   ▼
     PostgreSQL           ClickHouse
                              │
                              ▼
                    数据流图 / 路径 / 证据 API

APM Collector → ClickHouse 的 Span 数据经 trace_id/span_id 与上述观测关联。
```

## 5. Kafka 实施方案

### 5.1 部署形态

新增 `deployment/kafka/`：

- `docker-compose.kafka.yml`：开发/测试单 Broker，明确标注不可用于生产高可用。
- `docker-compose.kafka-ha.yml`：三节点 KRaft 示例。
- `k8s/`：生产 StatefulSet、Service、Headless Service、PDB、NetworkPolicy、持久卷和资源限制。
- `README.md`：安装、证书、Topic 初始化、扩容、备份边界和故障处理。

要求：

1. 使用 Apache Kafka KRaft，不部署 ZooKeeper。
2. 生产三副本，Broker 分布在不同故障域；`default.replication.factor=3`、`min.insync.replicas=2`。
3. Broker 仅监听 WDSP 中心私网，禁止暴露公网；管理面与业务云 Agent 不直接访问 Broker。
4. 启用 TLS 和 SASL 或 mTLS，生产者、API 投影消费者、数据流消费者使用不同身份和最小 ACL。
5. 镜像按架构分别锁定 tag 与 digest，登记 `docs/DEPENDENCIES.md`、第三方声明和 SBOM。
6. Kafka 持久卷只用于事件缓冲，不替代 PostgreSQL/ClickHouse 备份。

### 5.2 Topic 规划

一期只创建实际使用的 Topic：

| Topic | 内容 | Message Key | 建议保留 | 消费者 |
|---|---|---|---|---|
| `wdsp.api.observations.v1` | 已脱敏的 API 元数据、Schema、字段类型、Trace 关联 | `agent_id` | 初始 72h，容量验证后冻结 | API 投影、数据流构建、质量统计，各自独立 Consumer Group |
| `wdsp.api.observations.dlq.v1` | 无法消费的脱敏原记录、错误类别、重试次数 | `agent_id + event_id` | 初始 7 天 | DLQ 管理与修复重放 |

既有 `agent_http_events` v1/v2 暂不迁移到 Kafka。后续迁移必须单独创建有严格 ACL 和短保留期的 Topic，因为旧协议可能包含按旧策略脱敏后的 Body，不得与无正文观测 Topic 混用。

分区数不凭经验固定，按下式在压测后确定：

```text
partition_count >= 目标消费者并行度
partition_count >= ceil(峰值事件数/秒 ÷ 实测单分区稳定消费能力)
```

以 `agent_id` 为 Key 保持单 Agent 事件有序；跨 Agent 的同 Trace 通过事件时间和 Trace ID 关联，不依赖全局顺序。

### 5.3 统一事件信封

```json
{
  "schema_version": 1,
  "event_id": "01J...",
  "agent_id": "uuid",
  "application_binding_id": "uuid-or-null",
  "occurred_at": "RFC3339Nano",
  "received_at": "RFC3339Nano-by-receiver",
  "source": {
    "type": "IN_PROCESS",
    "language": "java",
    "framework": "spring-webmvc",
    "agent_version": "locked-version",
    "source_epoch": 1
  },
  "service": {
    "name": "order-service",
    "instance_id": "pod-or-host-instance",
    "version": "1.4.0",
    "environment": "prod",
    "namespace": "shop",
    "cluster": "cloud-a"
  },
  "trace": {
    "trace_id": "32hex-or-empty",
    "span_id": "16hex-or-empty",
    "parent_span_id": "16hex-or-empty"
  },
  "http": {},
  "observations": {},
  "quality": {}
}
```

Receiver 不信任 Agent 自报的 `agent_id`、应用绑定或授权范围，必须以认证身份和数据库绑定关系覆盖/校验。Kafka Header 只放 `schema_version`、`event_id`、`agent_id`、`content_type`，不放敏感字段。

### 5.4 生产确认语义

- 使用幂等生产者、`acks=all`、有界重试和压缩；生产启用 TLS。
- Receiver 只有在 Kafka 确认写入后才返回 `202`。
- `202 accepted_count` 表示“已可靠进入事件总线”，不伪装成“已完成 PostgreSQL/ClickHouse 落库”。
- Kafka 不可用返回可重试 `503`；本地 Agent 保留有界 Spool 并按退避重试。
- 中心过载返回 `429 + Retry-After`；非法记录返回 `400` 并给出记录索引和原因。
- 不在 Kafka 故障时静默绕回直接数据库模式；只有显式配置的迁移模式才允许切换。

### 5.5 消费、幂等与 DLQ

采用 at-least-once 投递，不宣称跨 Kafka、PostgreSQL、ClickHouse 的端到端 exactly-once：

1. 消费者完成存储批次后手工提交 Offset。
2. PostgreSQL 使用 `(agent_id, event_id)` 或等效唯一约束幂等。
3. ClickHouse 原始表以 `event_id` 为排序/去重依据；所有读取与聚合显式处理重复，不能只等待后台 Merge。
4. 数据流投影保存 `(consumer, partition, offset)` 处理水位；重放不会重复累计计数。
5. 临时错误有界退避重试；永久 Schema 错误进入 DLQ，不能静默丢弃。
6. DLQ 查看、重放和删除均需要独立权限并记录审计；重放仍使用原 `event_id` 保证幂等。

### 5.6 Go 客户端与配置

新增 `server/internal/ingest/`，抽象：

```text
Producer.PublishBatch(ctx, topic, records)
Consumer.Run(ctx, handler)
Health(ctx)
Close(ctx)
```

生产实现只选一个 Kafka Go 客户端，经许可证、维护状态、KRaft/SASL/TLS/幂等能力审查后锁定版本；不得在代码中同时引入多个 Kafka 客户端。配置至少包括：

```text
KAFKA_ENABLED=false
KAFKA_BROKERS=
KAFKA_TLS_*
KAFKA_SASL_*
KAFKA_PRODUCE_TIMEOUT=10s
KAFKA_REQUIRED_ACKS=all
KAFKA_API_OBSERVATION_TOPIC=wdsp.api.observations.v1
KAFKA_CONSUMER_GROUP_PREFIX=wdsp
KAFKA_MAX_BATCH_BYTES=
KAFKA_MAX_BATCH_RECORDS=
```

默认关闭；未配置时新 API 观测端点明确返回不可用，现有 WAF/APM 功能不受影响。

## 6. 云 API Agent 改造方案

### 6.1 统一 Agent 包职责

#### 语言探针

- 拦截 HTTP Server、HTTP Client，后续增加 RPC/MQ 框架。
- 提供 method、route、host、status、latency、service、trace/span、错误信息。
- 按策略在进程内读取有界 Body，并通过本地 Unix Socket 发送给 `wdsp-agent`。
- 不持有中心 Kafka 凭据，不直接访问管理数据库。
- 探针初始化或本地发送失败只丢弃遥测并计数，不影响业务请求。

#### 本地 `wdsp-agent`

新增模块建议：

```text
wdsp-agent/internal/inprocess/    本地接收、来源认证、背压
wdsp-agent/internal/apiobserve/   Schema、敏感识别、字段 HMAC、事件构造
wdsp-agent/internal/apievent/     远程批次、幂等 ID、质量指标
```

复用现有注册、PoP、策略版本、Buffer、限速、重连、配置 ACK 和自监控能力。

本地接收优先级：

1. Linux 裸机/Kubernetes sidecar：Unix Domain Socket，目录和 Socket 最小权限。
2. 不支持 UDS 的运行时：仅 `127.0.0.1`，使用每次安装生成的随机本地凭据。
3. 禁止把本地原始 Body 接收端口绑定到 `0.0.0.0` 或容器对外端口。

### 6.2 两种契约必须分开

#### 本地 Capture 契约 `wdsp.local.api-capture.v1`

允许包含原始 Body，但只能在业务节点内部传输，带以下硬限制：

- 每方向 Body 默认上限和全局硬上限；
- 解压后大小、字段数、嵌套深度、数组长度、Header 数限制；
- 每请求处理超时和最大正则/校验次数；
- 队列、连接数和未完成请求数限制；
- 不支持或超限只记录原因，不无限驻留内存。

#### 远程 Observation 契约 `wdsp.api-observation.v1`

新增机器端点：

```text
POST /api/v1/agents/{agent_id}/api-observations
```

复用现有机器身份认证、PoP 和禁用状态检查，新增能力协商：

```json
{
  "capabilities": {
    "api_observation_schema_versions": [1]
  }
}
```

每批记录数、序列化字节数、单字段数、字符串长度均有硬上限；响应包含 `accepted_count`、`duplicate_count` 和质量状态。旧服务端没有该能力时，API 安全通道停用，APM 和现有 Agent 功能继续工作。

### 6.3 远程 HTTP 观测内容

```json
{
  "direction": "SERVER",
  "method": "POST",
  "scheme": "https",
  "host": "orders.example.internal",
  "route": "/orders",
  "path_template": "/orders",
  "status": 201,
  "latency_ms": 18,
  "request_content_type": "application/json",
  "response_content_type": "application/json",
  "peer_service": "",
  "fields": [
    {
      "side": "REQUEST",
      "location": "JSON_BODY",
      "path": "$.customer.mobile",
      "data_type": "PHONE",
      "level": "L3",
      "value_hmac": "hmac-sha256:...",
      "hmac_key_id": "key-2026-01",
      "value_present": true,
      "truncated": false
    }
  ],
  "quality": {
    "route_source": "FRAMEWORK",
    "request_body_state": "ANALYZED",
    "response_body_state": "SKIPPED_CONTENT_TYPE",
    "capture_sampled": true,
    "truncated": false
  }
}
```

约束：

- 不上传原始 Query、完整 URL、Header 值或 Body。
- 框架能提供 Route 时优先使用；否则使用既有归一化规则，并标记 `route_source`。
- `fields` 只包含结构化路径、类型、敏感级别和不可逆指纹；无 HMAC 的字段也可用于 Schema 学习，但不能用于值传播关联。
- `quality` 必须区分未采、截断、不支持、解析失败和确实无字段。

### 6.4 敏感规则与 HMAC 密钥

1. 服务端把现有敏感数据类型、值级规则和脱敏策略编译为语言无关、版本化的 Agent 策略。
2. 正则规则采用有界、可预编译的安全子集；不支持的规则在策略发布时拒绝，不能到 Agent 才静默跳过。
3. 字段传播使用 HMAC-SHA256，不使用当前普通 SHA-256 截断 Hash 代替。
4. HMAC 密钥按租户/授权边界隔离，密文保存在服务端既有秘密设施，经认证通道下发本地 Agent；不得进入 Git、日志、Kafka 或浏览器。
5. 事件携带 `hmac_key_id`；轮换支持短期双密钥窗口，窗口结束后新边使用新 Key，历史证据仍可解释。
6. 手机号、身份证等规范化规则必须按数据类型固定并版本化；不得为了提高匹配率随意改变原文语义。
7. HMAC 仍按伪标识数据保护，页面不向普通权限用户展示完整指纹。

### 6.5 采集模式与采样

```text
METADATA：仅 API/服务/状态/耗时，不读取 Body。
SCHEMA：读取有界 Body，提取字段路径和类型，不做值级传播。
SENSITIVE：增加敏感值校验和 HMAC，供数据传播关联。
DIAGNOSTIC：仅限时、限范围、可审计提高采集级别，仍不允许原文远程外发。
```

- 安全元数据与性能 Trace 独立采样。
- 资产发现优先保证覆盖；正文分析按应用/端点/身份/风险定向提升。
- 本地 Spool 满时按策略降级正文分析，保留高价值安全事件和基础元数据，并如实上报丢弃原因。
- 所有丢弃都计入 `dropped_by_reason`，不能显示虚假的 100% 采集完整率。

### 6.6 语言与框架交付顺序

第一阶段只承诺 Java/Spring：

- Spring WebMVC 入站；
- 一个主流 HTTP Client 出站；
- W3C TraceContext；
- JSON 请求/响应；
- Spring Kafka 或所选 Kafka 客户端的 PRODUCER/CONSUMER Span；
- Kubernetes sidecar 和 Linux 裸机安装。

第二阶段增加 Node.js、Python、.NET；Go 通过 HTTP Middleware/Transport Wrapper 和 SDK 实现。每种语言都必须独立做框架兼容、性能、安全和升级测试，不因 Java 成功就宣称全语言支持。

### 6.7 Kafka 业务流量观测

分两级交付：

1. **服务依赖级**：利用 OTel PRODUCER/CONSUMER Span 获取 `messaging.system=kafka`、Topic、操作、服务、Trace，生成 `service → topic → service`。
2. **消息字段级**：只有显式开启且框架支持时，在业务节点内分析消息 Schema/字段并输出无正文 Observation；默认不读取消息原文，不支持时只展示 Topic 依赖并标记数据类型未知。

## 7. 中心 Receiver 与 API 投影改造

### 7.1 Receiver

在 `server/internal/agents/` 增加 Observation Handler，但不在该包中堆叠 Kafka 细节：

```text
agents/machine_api_observations.go   鉴权、配额、契约校验
agents/api_observation_v1.go         线协议类型与验证
ingest/producer.go                   Kafka 生产抽象
ingest/kafka/                        唯一客户端实现
```

装配点在 `server/internal/app/app.go` 和 `server/cmd/api/main.go`：

- 注册新机器端点；
- 注入应用绑定、端点配额和 Kafka Producer；
- 启动/停止消费者并纳入统一生命周期；
- 把 Kafka、Receiver、Consumer Lag 纳入运行健康和告警。

### 7.2 抽出可复用 API 投影服务

当前 `apiruntime.Collector` 同时承担 JSONL 读取和事件副作用装配。新增消费者不能直接依赖文件 Offset 逻辑，应抽出入站无关的投影接口：

```text
APIEventProjector.ProjectBatch(ctx, []NormalizedAPIEvent)
```

由现有 JSONL Collector 和 Kafka Consumer 共用，负责：

- API 资产 Upsert；
- 请求/响应 Schema 和参数学习；
- 敏感字段台账；
- notable 安全事件与 Finding；
- 流量桶和运行时指标；
- 来源关系和数据质量。

网关事件与 Agent 事件的差异必须在 Normalized Event 中显式表达，不能伪造 `gateway_node`、最终阻断动作或 WAF 检测明细。Agent 纯观测事件默认 `final_action=OBSERVE`，不能写成已阻断。

### 7.3 身份与应用绑定

为统一安装包新增工作负载绑定，而不是强行合并历史两套 Agent 主键：

```text
agent_workload_bindings
- id
- traffic_agent_id
- apm_agent_id（可空）
- application_id
- service_name
- environment
- binding_version
- status
- created_at / updated_at
```

管理面展示一个工作负载及其 APM/API 两个通道健康状态；新安装可一次登记，但底层兼容现有 Agent。应用绑定必须由管理面授权，Agent 不能通过自报 service.name 跨应用写入。

数据库迁移从当前最大编号 `000191` 后分配；实施前必须重新检查并行开发产生的最大编号。

## 8. 数据流分析与存储

### 8.1 ClickHouse 逻辑表

建议在独立 `wdsp` 数据库或明确前缀下建设：

```text
api_observations
- event_id、agent_id、application_id、occurred_at、received_at
- service/name/instance/environment、trace_id/span_id/parent_span_id
- direction/method/host/path_template/status/latency
- route_source、capture_quality、schema_version、source_version

api_field_observations
- event_id、side、location、field_path、data_type、level
- value_hmac、hmac_key_id、truncated、quality

service_call_edges_minutes
- minute、application_id、source_service、target_service/target_type/target_name
- protocol、calls、errors、duration_sum、duration_max
- evidence_type、sample_trace_ids

data_flow_edges_minutes
- minute、application_id、source_node、target_node
- data_type、field_count、observations、evidence_type、confidence_bucket
- first_seen、last_seen、sample_event_ids
```

禁止在这些表保存原始 Body、Header 值、Query 值、Token 或 Kafka 消息原文。具体 TTL 通过容量测试后配置，原始观测短于聚合边保留期。

### 8.2 服务调用边算法

按证据强度排序：

1. **OBSERVED**：CLIENT Span 与 SERVER Span 通过 Trace/Parent 或服务对端属性配对。
2. **OBSERVED_MQ**：PRODUCER/CONSUMER Span 与 Topic 构成生产/消费边；能关联消息上下文时连接上下游。
3. **CORRELATED**：Request ID、Message ID、Correlation ID 或字段 HMAC 跨事件匹配。
4. **INFERRED**：仅时间窗口、Schema 或既有身份相邻调用支持，默认低可信且不直接生成高风险结论。
5. **DECLARED**：人工/CMDB/数据目录登记，与观察边分开保存和展示。

现有 `api_call_edges` 继续兼容，但其中的相邻调用推断不能直接改标为 OBSERVED。

### 8.3 字段传播算法

在已确认的服务/API 边上：

1. 比较上游 RESPONSE 与下游 REQUEST 的 `(normalized_type, value_hmac, hmac_key_id)`。
2. 匹配成功生成 `CORRELATED_FIELD` 证据，并记录字段路径、类型和样本数。
3. Trace 同时直接关联时提升证据等级；只有 Schema 名称相似时保持低可信。
4. 同一值经过加密、哈希、聚合后无法自动等同，除非有 Schema/声明或专门派生规则。
5. 数据类型集合是“已观察到的类型”，不是完整字段清单；采样不足时显示覆盖率未知。

### 8.4 查询接口

新增 `server/internal/apidataflow/`，建议接口：

```text
GET /api/v1/api-security/data-flow/graph
  ?start=&end=&application_id=&method=&data_type=&max_edges=&view=service

GET /api/v1/api-security/data-flow/nodes/{node_id}
  ?start=&end=

GET /api/v1/api-security/data-flow/edges/{edge_id}
  ?start=&end=

GET /api/v1/api-security/data-flow/edges/{edge_id}/evidence
  ?start=&end=&cursor=&limit=

GET /api/v1/api-security/data-flow/quality
  ?start=&end=&application_id=
```

要求：

- 强制时间窗、最大边数、最大证据数和游标限制。
- 所有查询按应用授权范围过滤。
- `data-flow.read` 查看脱敏图，`data-flow.evidence.read` 查看字段级证据；导出单独权限并审计。
- 响应显式包含 `evidence_type`、`confidence`、`coverage`、`truncated`、`data_source` 和降级原因。
- OpenAPI、权限种子、操作审计和接口测试同步交付。

## 9. 前端数据流图

新增 `web/src/pages/api-data-flow/`，使用项目现有 React/Ant Design/ECharts 体系，不先引入第二套图引擎。

第一期功能：

- 时间范围、应用、Method、数据类型、最大边数过滤；
- 服务视图，后续增加网络视图；
- 从左到右分层布局，节点按环境/应用分组；
- 节点显示服务名、访问次数、API 数、平均/最大耗时和健康状态；
- 边显示数据类型、调用量、证据类型；风险颜色与证据线型分离；
- 节点右侧详情展示依赖和被调用；
- 边详情展示字段、证据、首末观察时间、样本 Trace 和覆盖率；
- 逐层展开、缩放、拖拽、导出；
- “无数据”“未接入 Agent”“Kafka/ClickHouse 降级”“采样导致部分链路”分别展示，不能统一画成空图。

前端只消费真实接口，不使用静态演示节点冒充完成。

## 10. 分阶段执行任务

### 阶段 0：ADR、契约与依赖冻结

任务：

- 冻结 Kafka 边界、Topic、ACK、重放和 DLQ 语义。
- 冻结本地 Capture 与远程 Observation 两份契约。
- 冻结 Java/Spring 首版框架矩阵。
- 完成 Kafka 镜像和 Go 客户端许可证、版本、digest、SBOM 审查。
- 编写 `docs/agents/WDSP_CLOUD_API_SENSOR_CONTRACT.md` 和 Kafka ADR。

完成门禁：契约评审通过；不允许在契约未冻结时并行修改多种语言线协议。

### 阶段 1：Kafka 基础数据面

任务：

- 交付单机与三节点 KRaft 部署、TLS、ACL、Topic 初始化和健康检查。
- 实现 `server/internal/ingest/` 生产者、消费者、指标和 DLQ。
- 完成真实 Kafka 的重复、乱序、Broker 故障、消费重放和 ACL 测试。
- 更新部署、依赖、许可证、备份和运维文档。

完成门禁：中心故障不影响业务；消费者重启和消息重放不重复计数；Kafka 不暴露公网。

### 阶段 2：Observation Receiver 与 API 投影

任务：

- 新增 Observation 端点、能力协商、配额和 Kafka 生产。
- 抽出文件/ Kafka 共用的 APIEventProjector。
- 实现 API 投影 Consumer、ClickHouse 原始观测表和质量统计。
- 保持既有 v1/v2 和网关 JSONL 全量回归。

完成门禁：端到端只传脱敏事件；Kafka 不可用时 Agent 可重试；重复上报不扩大资产和计数。

### 阶段 3：Java 云 API Agent MVP

任务：

- 本地 UDS Capture 接收、背压和硬限制。
- Java 探针实现 Spring Server/Client、Trace 关联和有界 Body Capture。
- 本地 Agent 实现 JSON Schema、敏感识别、HMAC、脱敏和远程批量上报。
- 统一安装包、策略、证书、Spool、升级与回滚。
- 在无透明代理、无镜像的测试命名空间验证 HTTPS 和东西向 API。

完成门禁：只安装 Agent 即可发现真实 API；原始 Canary 敏感值不出现在 Kafka、数据库、日志和浏览器；Agent 故障不影响业务。

### 阶段 4：数据流构建与查询

任务：

- 配对 CLIENT/SERVER 和 PRODUCER/CONSUMER Span。
- 生成服务/API/Kafka 边和字段传播证据。
- 实现 ClickHouse 聚合、查询接口、权限和证据下钻。
- 建立观察/关联/推断/声明的明确口径。

完成门禁：标准 A→B→Kafka→C 场景自动成图；重复回放不重复计数；无证据路径不画成确定数据流。

### 阶段 5：数据流图与运营闭环

任务：

- 交付图、节点/边详情、质量视图和过滤。
- 联动 API 资产、敏感字段、Trace 和风险页面。
- 完成前端 Vitest、接口测试和 Playwright 主流程。

完成门禁：页面所有数字来自真实查询；断链、采样和降级均有明确提示。

### 阶段 6：扩展能力

独立排期，不阻塞一期验收：

- Node.js、Python、.NET 和 Go SDK；
- Kafka 消息字段级观测；
- 更多 RPC、数据库和第三方依赖；
- 跨境、第三方共享、声明与实际流向核对；
- 既有 v1/v2 Agent 和 APM Span 是否迁入 Kafka 的独立 ADR 与迁移。

## 11. 测试与验收矩阵

| 编号 | 场景 | 必须验证 |
|---|---|---|
| KFK-01 | Broker 全部不可用 | Receiver 可重试失败，Agent 有界缓存，业务不受影响 |
| KFK-02 | 同一批消息重复投递 | 资产、事件、调用量不重复 |
| KFK-03 | Consumer 崩溃后重放 | Offset/水位正确，图计数正确 |
| KFK-04 | 永久非法消息 | 进入 DLQ，有告警，可审计重放 |
| KFK-05 | 非授权 Producer/Consumer | TLS/ACL 拒绝并有审计 |
| AGT-01 | 云上无代理、无镜像、HTTPS | 进程内仍发现入站/出站 API |
| AGT-02 | 大 Body/压缩炸弹/深 JSON | 硬上限生效，不 OOM，不阻塞业务 |
| AGT-03 | Agent/Collector/Kafka 故障 | 业务成功，遥测降级有指标 |
| AGT-04 | 老服务端/老 Agent | 能力协商降级，既有 v1/v2 不变 |
| SEC-01 | 手机号、身份证、Token Canary | 原值不出现在 Socket 之外的 Kafka/PG/CH/日志/UI |
| SEC-02 | 伪造应用绑定/跨 Agent 上报 | 服务端拒绝，不能跨应用写数据 |
| SEC-03 | 高基数路径和字段 | 归一化、限额和配额生效 |
| FLOW-01 | A 调 B，同 Trace | 生成高可信服务/API 边，可跳 Trace |
| FLOW-02 | B 生产 Kafka，C 消费 | 出现 Topic 及生产/消费关系 |
| FLOW-03 | 上游响应字段进入下游请求 | 边上出现正确数据类型和字段证据 |
| FLOW-04 | 仅相邻时间调用 | 只标推断，不冒充真实传播 |
| FLOW-05 | 采样/未插桩/不支持消息体 | 显示部分链路和未知，不显示“无敏感数据” |
| HA-01 | 单 Broker 故障 | ISR 正常时生产/消费继续，无不必要业务影响 |
| HA-02 | ClickHouse 不可用 | 事件留在 Kafka，Lag 告警，恢复后追平 |
| PERF-01 | 现网峰值及两倍目标负载 | 记录吞吐、Lag、丢弃、CPU、内存、P95，不预先宣称达标 |
| PERF-02 | Java 业务基准对比 | 按现有 APM 性能预算目标实测，未达标不得全量推广 |

安全测试必须扫描实际 Kafka 消息、ClickHouse、PostgreSQL、Agent 日志、服务端日志、API 响应和页面导出，而不是只检查配置项。

## 12. 可观测性与容量管理

### 12.1 Kafka/Receiver 指标

- Produce 成功率、确认时延、重试和失败原因；
- Consumer Lag、最旧消息年龄、处理吞吐和批次耗时；
- DLQ 数量、重放次数、永久错误类型；
- Broker ISR、Under-replicated Partitions、离线分区、磁盘水位；
- Receiver 按 Agent/应用的配额拒绝和限流。

### 12.2 Agent 指标

- 本地 Capture 接收/解析/丢弃；
- Body 截断、不支持类型、解压失败、字段数超限；
- Spool 字节、最老 segment、重试、永久失败；
- HMAC 规则版本、策略版本、证书到期时间；
- 探针 CPU、内存、耗时和业务错误率对照。

### 12.3 数据质量指标

- 有 Trace 的 API 事件比例；
- 可配对 CLIENT/SERVER、PRODUCER/CONSUMER 比例；
- Route 来自框架/归一化/未知的比例；
- 正文已分析/采样/截断/不支持比例；
- 数据流边按 OBSERVED/CORRELATED/INFERRED 的分布。

所有比例必须来自真实计数；无法计算时显示未知。

## 13. 灰度、迁移与回滚

1. **实验室**：Kafka + Collector + ClickHouse + 演示 A→B→Kafka→C，完成契约和故障测试。
2. **Shadow**：新 Agent 只上报，数据流结果不对客户开放，与既有 API 资产和 APM 依赖对比。
3. **单应用灰度**：默认 METADATA，逐步开启 SCHEMA、SENSITIVE；观察性能与误报。
4. **小范围生产**：单 Kafka Consumer 可停可回放，确认 Lag、数据质量和权限。
5. **正式开放 UI**：仅在数据质量达标后展示高可信边；低可信边默认折叠。
6. **扩展**：逐语言、逐框架、逐应用推广。

回滚：

- 关闭 Agent API Capture，仅保留 APM；业务无需回滚。
- 停止新 Observation Receiver，旧 Agent 和 WAF 主链路不受影响。
- 停止数据流 Consumer，保留 Kafka 消息，修复后按 Offset 重放。
- UI 可独立关闭，已确认的资产/风险不删除。
- Kafka 配置和 Topic 变更必须可重复执行；禁止用删除 Topic 作为常规回滚手段。

## 14. 预计变更范围

```text
deployment/kafka/                       新增 Kafka 部署与运维配置
deployment/apm/                         保持一期主链路，补关联说明
server/internal/ingest/                 新增事件总线抽象与实现
server/internal/agents/                 新增 Observation 接收与能力协商
server/internal/apiruntime/             抽出入站无关 API 投影
server/internal/apidataflow/            新增数据流构建、查询与权限
server/internal/apm/                    复用 Span，补配对/查询适配
server/migrations/                      绑定、权限、审计等迁移
server/openapi/openapi.yaml             新接口契约
wdsp-agent/internal/inprocess/          本地进程内采集入口
wdsp-agent/internal/apiobserve/         本地结构化、敏感识别、HMAC
wdsp-agent/internal/transport/          Observation 上报
wdsp-agent/instrumentation/java/        Java/Spring 探针及构建
web/src/pages/api-data-flow/            数据流页面
web/src/api/、router、menu               真实接口和菜单接线
test/                                   Kafka、Agent、数据流集成与 E2E
docs/                                   契约、依赖、部署、安全和运维文档
AGENTS.md                               能力实际交付后更新架构与索引
```

实施时遵循一次一个阶段；每一阶段附带单元测试，接口附接口测试，关键链路附真实 E2E，不能用 Mock 数据代替最终验收。

## 15. 最终完成定义

只有同时满足以下条件，才能声明该能力完成：

- 云上业务仅安装 Agent，无透明代理、无流量镜像即可发现入站和出站 API。
- 中心新 API 观测事件实际经过 Kafka，不是配置中存在 Kafka 但业务仍绕过。
- Kafka 故障、消费者重放和 DLQ 行为经过真实 Broker 验证。
- 请求/响应原文和 Canary 敏感值未离开业务节点，未出现在中心存储和日志。
- A→B→Kafka→C 的真实测试链路自动生成服务/API/Topic 拓扑。
- 有字段传播证据时正确显示数据类型；无证据时明确显示未知或推断。
- 图、资产、风险、Trace 之间可按真实标识下钻。
- 权限、应用隔离、审计、配额、限量、脱敏和保留期均生效。
- 既有网关、v1/v2 Agent、APM 和 API 安全回归全部通过。
- 性能数字来自真实压测；未达到预算时限制灰度，不修改结论或删除测试。

## 16. 默认实施口径

- 首个业务语言为 Java/Spring，首个云部署形态为 Linux + Kubernetes sidecar，同时保留裸机安装能力。
- 一期只读观测，不做 Agent 进程内阻断。
- 一期 Kafka 只承接新 API Observation，不强切现有 APM 和旧 Agent 主链路。
- 不使用 Schema Registry，不引入 ZooKeeper，不允许 Agent 直连 Kafka。
- 数据流图以真实证据优先，宁可展示部分链路，也不补画不存在的边。

## 17. 一期实现与验证记录（2026-11-06）

### 17.1 已交付边界

- Kafka 4.1.2 KRaft 部署、Topic 初始化、TLS/ACL 示例及 franz-go 生产者/消费者；一期只承接新增 API Observation，旧 Agent v1/v2 与 APM OTLP 主链路未迁移。
- `POST /api/v1/agents/{agent_id}/api-observations` 复用机器身份、应用绑定、配额与能力协商；事件经 Kafka 后由资产投影和数据流消费者处理，不绕过总线直接落库。
- Java 17+ 探针支持 Spring 6 MVC Server 与 RestTemplate Client；原始 Body 仅通过本机 Unix Socket 传输，本地 Go Agent 输出结构、敏感类型、HMAC、Trace 和质量，不输出 Body。
- ClickHouse 保存观测、字段与数据流贡献，PostgreSQL 保存资产和控制面；查询去重按 `(agent_id,event_id)` 执行，不依赖后台合并。
- 数据流页面默认提供业务系统间的 HTTP API 关系图，同一对系统合并为一条边并汇总 API 列表、请求/响应敏感字段；支持应用/时间/Method/数据类型/最大关系数筛选、图/表切换、上下游和字段证据下钻。Kafka 等异步贡献仍可用于存储与兼容视图，但不混入该默认主图；空态、部分链路和存储错误分别提示。

### 17.2 可重复验收

- `server/internal/ingest/` 的真实 Kafka 集成测试覆盖生产、消费、重复与故障语义。
- `TestCloudAPIDataFlowEndToEnd` 使用真实 PostgreSQL、Valkey、Kafka、ClickHouse，验证 `orders → profile → Kafka/customer-events → notification`、重复上报去重、API 计数、字段证据和管理 API。
- `wdsp-agent/instrumentation/java/build.sh` 与 `test/cloud-agent-e2e/run.sh` 验证真实 Spring MVC/RestTemplate 进程内采集、Unix Socket、字段识别和无原文远程输出。
- `test/cloud-agent-e2e/run-full-stack.sh` 启动隔离临时数据面，在完整集成场景末尾执行 `web/e2e/api-data-flow.spec.ts`，用 Chromium 验证真实图、应用筛选、节点详情与字段证据；不读取或修改其他项目的开发服务。
- 前端类型检查、生产构建和定向 Vitest；OpenAPI 合并及代码双向对账。实际命令结果以本次验收记录和 CI 为准。

本次实测结果：Java 探针 5 项单元测试通过，真实 Spring 场景输出 4 条观测（含 RestTemplate），无原始手机号或 `body_base64` 越过本机边界；完整集成测试与 Chromium 主流程通过，应用隔离筛选、节点详情、`$.mobile` 的 `CORRELATED_FIELD` 和样本 Trace 均在真实页面验证。

### 17.3 不应误报为已完成

- 当前仅正式支持 Java/Spring MVC 与 RestTemplate；Node.js、Python、.NET、Go SDK、更多 RPC/SQL/MQ 插桩属于阶段 6 后续工作。
- Kafka 消息字段级自动观测未实现；测试中的 MQ 字段证据由合法 Observation 输入构造，不代表 Java 探针已能读取 Kafka 消息正文。
- 开发单 Broker 不是生产高可用证明；三 Broker 故障切换、TLS/ACL 实网拒绝、云上 Kubernetes 部署、容量与 Java 性能预算仍须在目标环境按第 11 节验收，不能用单元测试替代。
- 本文不宣称已完成现网性能压测、全量灰度或既有 APM 的 Kafka 迁移。

### 17.4 参考图增强与验收状态

已补充：可选的直接对端 IP `peer_address`；节点环境、命名空间、集群和主机地址元数据；`view=network` 的应用观测网络端点视图；基于 ECharts 自定义系列的分区、节点卡片、字段标签、曲线边、拖拽、缩放、分组折叠和按层展开；节点详情增加调用关系与基础设施页。折叠或缺少元数据时明确提示，不补造事实。

上述增强已通过 Go 全量测试、后端相关测试和构建、前端严格类型检查、定向 lint/Vitest 与生产构建，OpenAPI 双向对账通过。`web/e2e/api-data-flow.spec.ts` 覆盖真实画布点击/拖拽、网络视图和基础设施元数据。Docker 引擎恢复后，新增场景的完整 Kafka + ClickHouse + PostgreSQL + Chromium 复验已通过；真实节点 `10.20.0.30` 的端点详情返回 200，调用关系、字段证据与环境元数据均完成实际验证。

### 17.5 业务系统 API 流向口径修正（2026-11-07）

- 默认 `view=service` 只保留调用双方均为受监控业务系统、且具有 CLIENT/SERVER Trace 配对证据的 HTTP API 关系（`OBSERVED_TRACE`）；排除来源 IP、Kafka 主题、未监控外部接收方、单边观测和纯字段关联虚边。网络视图用于单独查看观测端点和消息基础设施。
- 同一对系统在同一应用授权范围内聚合为一条关系，返回去重后的 `apis` 列表，避免按 Method/Path 拆成多条视觉重叠边；`max_edges` 对应系统关系数。
- 配对 CLIENT/SERVER 时同时归集请求和响应敏感字段。边箭头仍表示 API 调用方向，界面分别标注请求 `A → B` 与响应 `B → A` 的敏感类型，不把响应误画成一次反向调用。
- 节点详情列出直接上游、直接下游及每条关系的 API 和请求/响应敏感类型，并可继续进入字段路径、HMAC、证据类型和样本 Trace；不返回原始敏感值。
- 验收输入调整为 `orders → profile`、`profile → identity`、`orders → identity`，验证多跳与直连同时存在。单元测试、页面测试及真实数据面/浏览器验收分别记录实际执行结果，未运行真实数据面时不得以历史结果替代本次验收。

本次实测：`go test ./internal/apidataflow` 通过；前端 14 项定向 Vitest、定向 ESLint、严格类型检查与生产构建通过；OpenAPI 752 个操作双向零差。`test/cloud-agent-e2e/run-full-stack.sh` 使用真实 PostgreSQL、Valkey、Kafka、ClickHouse 和 Chromium 执行通过，三条系统关系、API 列表、请求/响应敏感字段、画布点击/拖拽、系统上下游和字段证据均完成验证；临时容器与网络已清理。

### 17.6 数据流向页面视觉精修（2026-11-07）

- 服务主图保持无环境底色，网络视图使用低饱和分区；横纵轴使用一致缩放，节点不再因画布比例被拉高。节点卡片展示真实调用量、API 数量、平均与最大耗时，Kafka 等名称按可用宽度省略，完整名称仍可在下钻中查看。
- 画布按单列最大节点数调整高度，提供节点/关系计数、缩放、还原、按层展开和健康/字段图例；系统索引继续支持真实节点下钻。筛选区补充明确标签并按容器宽度换行，窄屏下画布概览与工具栏不再重叠。
- 节点详情以调用量、API 数量、直接上下游和耗时形成摘要，保留下游、上游及采集信息；关系明细区分请求/响应敏感类型，保留 API、字段路径、HMAC、证据类型和 Trace，不显示原始敏感值。
- 合并且保留并行新增的 `apis`、请求/响应字段兼容处理，恢复 `topology` 状态与真实 `view=service|network` 查询。默认服务关系口径与网络观测口径不混用。

本次在 1440×900 桌面视口使用现有 30 条真实 Agent → Kafka → ClickHouse 演示观测检查服务视图（11 节点、10 条关系）、网络视图和 `orders` 节点详情。前端严格类型检查、16 项定向 Vitest、定向 ESLint 和生产构建全部通过。

`test/cloud-agent-e2e/run-full-stack.sh` 最终复验通过：`TestCloudAPIDataFlowEndToEnd` 29.45 秒，Chromium 场景 8.6 秒，真实画布点击、拖拽、节点上下游和字段证据均通过。Kafka 就绪单次探测上限按本机实测调整为 30 秒并保留失败诊断；Chromium 断言等待调整为 30 秒以覆盖容器冷启动，未放宽任何数据或交互断言。

### 17.7 受监控业务系统主图与全类型演示（2026-11-07）

- 服务主图进一步限定为 `protocol=HTTP`、`source_type=SERVICE`、`target_type=SERVICE`、`evidence_type=OBSERVED_TRACE`。只有客户端和服务端均有 Agent 观测并能按 Trace 配对的业务系统 API 调用才进入主图；客户端 IP、Kafka Topic、未监控外部服务、单边观测与字段相关虚边均不进入主图。
- 演示观测覆盖 `PHONE`、`CN_ID`、`ACCOUNT`、`EMAIL`、`ADDRESS`、`ID`、`BANK_CARD`、`PASSPORT`、`TOKEN`、`PASSWORD` 十类字段，按真实 Agent 接收接口经 Kafka 消费到 ClickHouse，不是前端写死图。字段类型覆盖不代表 Java 探针已能自动识别全部类型，当前探针自动识别范围仍以第 17.3 节边界为准。
- 请求、响应和消息字段分别标识方向；消息字段在详情和证据中保留，纯 HTTP 主图的关系明细不显示空的消息列。字段证据只包含路径、类型、HMAC、证据类型和 Trace，不包含原始密码、证件号、令牌等敏感值。
- 节点平均耗时修正为按累计调用量加权平均，新增多关系与峰值边界单元测试，不再逐边固定除以 2。
- 新版独立演示环境持久化主密钥，使用仅限测试构建的临时信任根与演示授权；不修改正式授权信任根，不读取或覆盖旧环境密钥。旧演示容器及数据卷保留，未删除旧数据。

本次实测：30 条新增演示观测经真实 Agent 接收链路处理，服务视图返回 6 个业务系统、5 条 API 关系和全部 10 类字段，所有节点均为 `SERVICE`，所有边均为配对 HTTP 观测，节点平均耗时不超过峰值。实际浏览器完成 `auth` 节点点击、`account → auth` 上下游及证据下钻，账号、密码、访问令牌的请求字段与用户标识、访问令牌的响应字段均正确显示，HMAC 和 Trace 可见且无原始敏感值。`go test ./internal/apidataflow`、前端 16 项定向 Vitest、类型检查、定向 ESLint、生产构建及 OpenAPI 752 个操作双向对账全部通过。

### 17.8 独立中文系统与多轨分区展示（2026-11-07）

- 演示对象调整为独立中文业务系统，不再把 `orders/profile/identity` 等节点表达为同一业务链的内部服务。5 组配对为：OA办公系统→统一认证系统、人力资源系统→统一认证系统、电商订单系统→支付结算系统、客户关系系统→数据分析系统、风险控制系统→数据分析系统；共 8 个独立系统、5 条 API 关系、30 条观测，仍覆盖全部 10 类演示字段。
- 中文名称直接来自 Observation 的真实 `service.name`，未在前端维护写死的中英文映射。每组 CLIENT/SERVER 共用 Trace 并保留请求/响应字段证据，不包含 IP、Kafka 或未监控外部业务节点。
- 服务视图按真实无向连通分量划分独立交互分区，分区名称使用“独立系统交互 · 序号”，不以环境或命名空间冒充业务域。宽屏按分区实际宽度与高度二维换行，行内顶部对齐、短行居中；窄屏可逐行展示，单连通分量和网络视图保留原布局约定。
- 每种敏感字段类型使用一条低饱和平行轨道，正交路径带适度圆角，小箭头表示 API 调用方向；扩大轨道点击区域，保留节点/轨道下钻、拖拽、双轴同步缩放、折叠和右侧证据。画布概览与分区标题使用同一行基线，避免文字重叠。
- 替换本地演示数据前已保存原始观测的 Native 备份；该备份仅用于本地演示恢复，不作为生产备份能力声明。

本次实测：新版 30 条观测通过真实 Agent → Kafka → ClickHouse 链路生成 8 个独立系统、5 条配对 API 关系及 10 类字段，所有节点/边的平均耗时均不超过峰值。1440×900 实际页面确认中文系统、二维分区、多轨连线、字段图例和顶部间距显示正常。前端 22 项定向 Vitest、严格类型检查、定向 ESLint 和生产构建通过。最终 `test/cloud-agent-e2e/run-full-stack.sh` 复验通过：`TestCloudAPIDataFlowEndToEnd` 49.73 秒，Chromium 场景 17.5 秒，真实画布点击、拖拽、系统上下游和字段证据均通过。页面标题、页签和无障碍定位名称保持既有稳定口径，临时容器与网络由测试脚本清理。

### 17.9 跨批次、多实例配对与重复调用修正（2026-11-07）

- `BuildContributions` 保持为对一个观测快照进行关联的纯函数及既有 Go API。生产 Kafka 数据流消费者不再只配对当前批次：先把脱敏 Observation 和字段 HMAC 持久化到 ClickHouse，再按本批 Trace ID 从共享 `api_observations` / `api_field_observations` 读取去重后的完整快照，重建并幂等保存贡献。不同 Agent、Kafka 批次、分区和管理面实例因此共享同一持久化事实源，不使用进程内配对状态。
- 同 Trace 重复调用同一目标服务时，先保留所有 `CLIENT.span_id = SERVER.parent_span_id` 的精确父子配对，再对剩余记录按目标服务、事件时间进行一对一回退配对；一个 SERVER 不再被多个 CLIENT 复用，未配对 SERVER 也不会因同服务已有客户端而被整体抑制。
- 跨批次后到的对端会生成 `PAIRED_CLIENT` / `PAIRED_SERVER` 内部修正版本。图与证据查询先按 `(agent_id,event_id,edge_id)` 选择最新版本，再排除这些修正记录，因此 service 主图能获得新配对，network/boundary 不会保留已被配对的旧单边边或重复计数。修正记录不改变既有 HTTP API 响应结构。
- 权限校验、应用过滤、证据审计和脱敏边界保持不变；持久化关联只读取既有结构化字段路径、类型和 HMAC，不读取或新增原始正文、Header、Token 等敏感内容。

本次定向验证：`go test ./internal/apidataflow -count=1` 通过；配置隔离的真实 ClickHouse 25.8 后，`go test ./internal/apidataflow -run Integration -v -count=1` 中观测、service/network/boundary、跨批次多 Agent 重复调用、反向到达顺序和重复回放用例均通过。未配置 Kafka 的既有管线集成测试按条件跳过，本次不把它表述为 Kafka 端到端验收。

### 17.10 内外网边界与来源证据展示（2026-11-07）

- Observation HTTP 增加可选 `client_address`、`client_address_source`、`server_address`，继续保留 `peer_address` 作为直接对端。Java SERVER 在同一次请求中采集 `getRemoteAddr()` 和 `getLocalAddr()`，默认只发 `DIRECT_PEER`，不信任 Forwarded/X-Forwarded-For，也不从 Header 推断区域。
- 使用 `apigeo.ClassifyIPScope` 计算地址范围，不依赖 GeoIP 文件、服务名或 Host 猜测。仅当可信来源为 PUBLIC、目标为 INTERNAL 时生成 `PUBLIC_TO_INTERNAL`；缺少客户端地址、目标地址、来源 UNKNOWN 或范围不一致时保持 UNKNOWN。`TRUSTED_PROXY` / `GATEWAY` 仅代表经验证来源链的证据类型，当前 Java 不会自动产生这些来源，未验证代理/NAT 不宣称可还原真实终端。
- 新增 `view=boundary`，仅查询 CLIENT/EXTERNAL → SERVICE 的 HTTP 关系及 `PUBLIC_TO_INTERNAL` / `UNKNOWN`，不放宽现有 service 的 SERVICE→SERVICE + OBSERVED_TRACE 主图。节点增加 `network_zone`，边及证据记录透传 direct peer、真实 client/server 地址、来源类型、边界类型和判定依据。OpenAPI 同步保持可选字段兼容。
- 页面新增“内外网边界”视图，分别标识“公网来源”“内网来源”“外部来源/区域未知”，并用实线/虚线区分确定与未知边界。详情同时显示地址、方向、判定依据、字段路径、HMAC 和 Trace；原始密码、证件号、Token 等不进入证据展示。
- ClickHouse `006_network_boundary.sql` 以 `ADD COLUMN IF NOT EXISTS` 加法升级。图查询及证据查询采用 `latest_*` 中间别名解决 ClickHouse 聚合别名与 WHERE 的冲突，不改变原权限、应用隔离、时间和筛选语义。
- 菜单叶子项与一级/二级分组均补齐语义化图标，未知菜单或分组使用统一默认图标，菜单名称、权限、路由和折叠交互不变。

本次实测：真实 Agent 接收两条边界 Observation，`8.8.8.8 → 统一认证系统` 形成 `PUBLIC_TO_INTERNAL`，`1.1.1.1` 保持 `UNKNOWN / UNTRUSTED_CLIENT_SOURCE`。实际页面显示 3 个节点、2 条关系；证据抽屉正确展示 client/peer/server 地址、`DIRECT_PEER`、目标 `10.20.0.30`、字段 HMAC 和 Trace，无原始敏感值。`go test ./internal/apidataflow ./internal/agents ./internal/apigeo`、Java 6 项测试、前端 30 项定向测试、菜单 13 项测试、OpenAPI 752 个操作双向对账均通过。`test/cloud-agent-e2e/run-full-stack.sh` 中 `TestCloudAPIDataFlowEndToEnd` 91.80 秒、Chromium 边界场景 33.7 秒均通过，临时容器与网络由脚本清理。

### 17.11 网关敏感字段与真实 Agent 数据流读取时关联（2026-11-17）

- 网关 `apievents` 已输出的 `trace_id` 现由服务端 `apiruntime.Record` / `PrimaryEvent` 透传，并经迁移 `000217_api_runtime_event_trace` 持久化到 `api_runtime_events.trace_id`。仅接受 32 位小写 hex 且非全零的 W3C Trace ID；历史事件及缺失/非法 Trace 不回填、不生成替代关联键。
- Graph 与 Evidence 在读取时按 `trace_id + method + 规范化 path + application_id` 关联真实贡献，不使用采样 `sample_trace_ids` 充当完整关联键。仅从单次事件 `details_json` 中提取 `detector=sensitive_data` 且带 `data_type` 的 `evidence.field/location/direction`，生成 `location.field` 路径、大写数据类型和 `match=OBSERVED`；例如 `credential` 保持为 `CREDENTIAL`，不猜成 `PASSWORD`。
- 该 enrichment 只补充已存在的真实 Agent 配对贡献，不回写 ClickHouse 贡献、不造边，也不改变 `calls/errors/latency/evidence_type/confidence`。网关补充字段不携带原值或 HMAC；无匹配贡献的事件不产生新关系，同 Trace 的不同端点不会被一并染色。
- 关联查询按完整键去重并分批、限量读取；候选边、引用和事件行均有界。普通未按数据类型过滤的 Graph 在 runtime 关联读取失败或引用不完整时保留既有真实边，并通过 `truncated=true`、`quality.partial=true` 和质量消息显式降级；带 `data_type` 筛选的查询若无法获得完整关联结果则报错，不返回静默缺失的筛选结果。
- 前端展示 `CREDENTIAL` 对应的 `form.pwd` 请求字段路径及 `OBSERVED`，其中类型按现有中文词表显示为“凭据口令”；该字段不显示 HMAC 或原始密码。

本次执行 `bash test/cloud-agent-e2e/run-full-stack.sh` 完整通过：真实临时 PostgreSQL 执行至迁移 000217，Observation 经真实 Agent 接收接口、Kafka 和 ClickHouse 形成配对贡献，晚到 runtime 事件在第二次 Graph 查询及 Evidence 中关联成功；`data_type=CREDENTIAL&max_edges=1`、同 Trace 不同端点隔离、无匹配事件不造边及调用指标不变均通过。`TestCloudAPIDataFlowEndToEnd` 为 `PASS`（20.24 秒），真实 Chromium 场景 `1 passed`（9.7 秒），临时容器和网络已清理。

边界不变：历史无 `trace_id` 的 runtime 事件无法补入数据流图；必须已经存在与网关事件共享 Trace 的真实 Agent CLIENT/SERVER 配对贡献，单纯存在敏感字段事件不足以形成边。`trace_inject_upstream` 仍默认关闭，本次验收显式构造共享 Trace，不宣称已经通过该默认开关自动接通网关与 Agent 的 Trace 链路。
