# WDSP 云 API Sensor 契约 v1

> 状态：冻结 v1，已实现 Java/Spring MVC、RestTemplate 与本地 Go Agent 配套；新增语言或框架不得改变本契约语义。
> 上游方案：`docs/tasks/KAFKA_CLOUD_AGENT_DATA_FLOW_EXECUTION_PLAN.md`。

## 1. 边界

- 远程端点：`POST /api/v1/agents/{agent_id}/api-observations`。
- 复用流量 Agent 的 Bearer/证书 PoP、启用状态、应用绑定和配额；Agent 不直连 Kafka。
- 批次顶层 `schema_version=1`，每批最多 100 条、序列化后最多 4 MiB。
- 远程事件不得包含完整请求/响应 Body、Query 值、Header 值、Authorization、Cookie、Token、SQL 绑定值、SQL 原文或消息原文。
- `202` 表示事件已可靠写入中心接收层，不表示所有异步投影已经完成。

## 2. 能力协商

注册与心跳的 `capabilities` 增加可选字段：

```json
{"api_observation_schema_versions":[1]}
```

服务端取双方交集。旧端忽略该字段时等价于不支持；不支持时 Agent 禁止上报本契约，既有 HTTP v1/v2 与 APM 不受影响。

## 3. 批次与事件

```json
{
  "schema_version": 1,
  "records": [{
    "event_id": "ev-64-lowercase-hex",
    "occurred_at": "2026-11-04T08:00:00.123456Z",
    "application_binding_id": "uuid-or-null",
    "binding_version": 1,
    "source": {
      "type": "IN_PROCESS",
      "language": "java",
      "framework": "spring-webmvc",
      "agent_version": "1.0.0",
      "source_epoch": 1
    },
    "service": {
      "name": "order-service",
      "instance_id": "order-service-abc",
      "version": "1.0.0",
      "environment": "prod",
      "namespace": "shop",
      "cluster": "cloud-a"
    },
    "trace": {"trace_id":"32hex","span_id":"16hex","parent_span_id":"16hex-or-empty"},
    "http": {
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
      "peer_address": "192.0.2.10",
      "client_address": "192.0.2.10",
      "client_address_source": "DIRECT_PEER",
      "server_address": "10.20.30.40"
    },
    "fields": [{
      "side": "REQUEST",
      "location": "JSON_BODY",
      "path": "$.customer.mobile",
      "data_type": "PHONE",
      "level": "L3",
      "value_hmac": "hmac-sha256:64-lowercase-hex",
      "hmac_key_id": "key-1",
      "value_present": true,
      "truncated": false
    }],
    "quality": {
      "route_source": "FRAMEWORK",
      "request_body_state": "ANALYZED",
      "response_body_state": "NOT_COLLECTED",
      "capture_sampled": true,
      "truncated": false
    }
  }]
}
```

## 4. 字段约束

- `event_id`：1～128 字符，字母数字开头，仅含 `[A-Za-z0-9._:-]`；重试和重启保持稳定，不得由正文派生。
- `occurred_at`：RFC3339，拒绝未来超过 5 分钟的事件；历史事件允许补传。
- `source.type`：v1 仅 `IN_PROCESS`；`language/framework/agent_version` 为长度受限的非敏感标识。
- `service.name/instance_id`：必填；其余服务属性可空，未知不得编造。
- `trace_id`：空或 32 位小写 hex；`span_id/parent_span_id` 为空或 16 位小写 hex；全零 ID 拒绝。
- `direction`：`SERVER`、`CLIENT`、`PRODUCER`、`CONSUMER`。
- `method`：大写 HTTP 方法或空（MQ）；`route/path_template` 不得包含 `?`、`#`、控制字符，最长 512。
- `status`：0 表示未知，否则 100～599；`latency_ms` 为 `0..2^31-1`。
- `peer_address`：可选 IPv4/IPv6 直接对端地址，不含端口；它是进程实际观察到的连接对端，代理/NAT 后不得冒充终端真实用户。旧 Agent 可不提供。
- `client_address`：可选 IPv4/IPv6 观测客户端地址，不含端口，必须与 `peer_address` 分开保存；不得以代理地址冒充已经验证的终端真实客户端。
- `client_address_source`：可选来源证据，非空时仅允许 `DIRECT_PEER`、`TRUSTED_PROXY`、`GATEWAY`、`UNKNOWN`。`DIRECT_PEER` 表示 `client_address` 来自当前连接直接对端；此时若同时提供 `peer_address`，两者必须相等。
- `server_address`：可选 IPv4/IPv6 服务端本地连接地址，不含端口；SERVER 来自 `request.getLocalAddr()`，不得改用 `Host` 或转发 Header。
- 旧记录仅提供 `peer_address` 时，其来源证据按 `DIRECT_PEER` 兼容解释，新字段为空不改变旧记录语义；这不把代理/NAT 的直接对端提升为已验证终端。
- 任何 `Forwarded`、`X-Forwarded-For` 或类似 Header 都不能自动成为可信客户端证据，不得用于生成或改写这些地址，也不得据此推断公网/内网。`TRUSTED_PROXY`、`GATEWAY` 只能来自经过配置和验证的信任链；当前 Java Spring MVC 默认只发送 `DIRECT_PEER`，不会生成前两种证据。
- `fields`：每条事件最多 256 个；`side=REQUEST|RESPONSE|MESSAGE`，`location=JSON_BODY|FORM|XML|QUERY|HEADER|PATH|MESSAGE`。
- `path`：最长 512，仅结构化字段路径，禁止携带字段值。
- `value_hmac`：空或 `hmac-sha256:` 加 64 位小写 hex；有指纹时 `hmac_key_id` 必填。
- `request_body_state/response_body_state`：`ANALYZED`、`NOT_COLLECTED`、`SAMPLED_OUT`、`TRUNCATED`、`UNSUPPORTED_CONTENT_TYPE`、`DECODE_FAILED`、`POLICY_DISABLED`。
- `route_source`：`FRAMEWORK`、`NORMALIZED`、`UNKNOWN`。

## 5. 响应

成功：

```json
{"accepted_count":100,"duplicate_count":0}
```

永久非法：HTTP 400，`invalid_records` 返回全部记录索引与原因，整批不生产。过载：HTTP 429 并携带 `Retry-After`。Kafka/接收层临时失败：HTTP 503，Agent 有界重试。重复事件按 `(agent_id,event_id)` 去重，不重复增加资产或图计数。

## 6. 本地 Capture 边界

本地协议与远程协议分离。本地 Capture 可携带 Body，但仅允许 Unix Socket 或带随机本地凭据的回环连接；不得绑定非回环地址。本地 Agent 必须在远程发送前完成限量、正文丢弃、字段提取、敏感识别与 HMAC。Kafka、PostgreSQL、ClickHouse、管理 API、日志和 UI 均不得出现原始 Body。地址证据采集不额外读取或采集真实请求体。

## 7. 证据语义

- `SERVER/CLIENT` 是进程内直接观察。
- `PRODUCER/CONSUMER` 是消息操作直接观察，不代表消息字段一定可见。
- 公网/内网范围只能由服务端 `server/internal/apigeo.ClassifyIPScope` 根据观测地址判定，不依赖 GeoIP 数据库，不从 Header、服务名或资产名称推断。
- 仅当来源范围为 `PUBLIC`、目标范围为 `INTERNAL` 且来源证据不是 `UNKNOWN` 时，边界才能为 `PUBLIC_TO_INTERNAL`；否则必须为 `UNKNOWN`。证据代码仅允许 `DIRECT_PEER`、`TRUSTED_PROXY`、`GATEWAY`、`MISSING_CLIENT_ADDRESS`、`MISSING_SERVER_ADDRESS`、`UNTRUSTED_CLIENT_SOURCE`。
- `DIRECT_PEER` 只证明直接连接。已知存在未验证代理/NAT、客户端或服务端地址缺失、来源不受信时，必须显示 `UNKNOWN`，不能猜测终端方向；代理地址不得展示成终端真实客户端。
- 字段 HMAC 匹配只产生 `CORRELATED_FIELD`，必须与调用/消息边组合后才能形成字段传播路径。
- 采样、截断、未知 Route、未插桩必须保留在 `quality` 和查询响应中。
