# Envoy tap 接入模板（WDSP Agent tapsrc，P1-03 G3）

适用范围：业务前置 Envoy 终止 TLS（或明文入口），希望把**下游侧** HTTP/1、
HTTP/2（含 gRPC）与 WebSocket 握手经 tap 管理流交付给同机 wdsp-agent 做被动
安全观测的场景。本接入是**旁路观测**，不具备任何在线阻断能力；适配器只出向
连接本机回环 Admin 读取 tap 流，不监听采集端口、不代理业务流量；适配器故障
不影响 Envoy 转发（tap 会话随连接断开被 Envoy 取消）。

## S0 版本与输出形态锁定（先于一切部署）

| 项 | 锁定值 |
|---|---|
| Envoy | `envoyproxy/envoy:v1.35.3@sha256:4d496918618a7ebd6c71ae8285e31ebff092f3a0a5ad642d50decf4a54eb2456`（tag+digest 双锁；多架构交付须按架构分别锁定 digest） |
| tap 输出 | `streaming_admin` 管理流（适配器作为 `POST /tap` 客户端主动读取），格式 `JSON_BODY_AS_BYTES` |
| tap 控制 | `admin_config`（不静态常驻 tap 配置；tap 配置随管理流会话生命周期，Envoy 重启即失效，由适配器重连后重新提交） |
| Admin 暴露 | **仅本机回环**（127.0.0.1:9901，或同容器/同 Pod 回环）；禁止绑定/发布到任何非回环地址 |

S0 实测结论（v1.35.3，证据 `test/wdsp-agent-e2e/envoy-tap/runs/`）：

1. `streaming_admin + PROTO_BINARY_LENGTH_DELIMITED` 会使 Envoy 进程崩溃
   （absl null check，SIGTRAP，实测可复现）——**二进制输出格式禁用**，
   本模板锁定 `JSON_BODY_AS_BYTES`。
2. JSON 管理流为美化 JSON 消息以换行相接的自相似流：适配器按括号深度
   分帧（分片/半消息由缓冲处理），TCP 保序不重排；流中断后有界退避重连
   并重新提交 tap 配置。
3. 因受控管理流可用，**不使用 file_per_tap 文件输出**——无需「脱敏前不落盘」
   ADR；tap 数据不写入任何持久介质（Agent 磁盘缓存只存脱敏后记录）。
4. **Envoy Admin 同时只允许一条已挂接 tap 流**（v1.35.3 实测：第二条
   `POST /tap` 返回 400 "An attached /tap admin stream already exists."）。
   因此适配器为**单会话**设计：所有需要采集的 listener 的 tap filter
   使用**同一个** `config_id`，由一条管理流统一接收；协议/TLS 断言按
   会话维度配置，覆盖全部 tapped listener——同一 Envoy 上混合 h1/h2 或
   混合 TLS/明文的 listener 不能同时挂 tap（断言只能 UNKNOWN/false，
   或拆到不同 Envoy 实例）。

## 采集位置与数据范围

```text
客户端 ──TLS──▶ Envoy listener（TLS 终止，tap filter admin_config）──▶ 源站
                     │
                     └─ tap 管理流（适配器 POST /tap 主动读取，回环）──▶ wdsp-agent tapsrc
```

- 可见：规范化请求+响应（伪头映射、重复 Header 保序数组、trailers）、
  来源协议（部署断言）、截断状态、gRPC 元数据（service/method/
  grpc-status）、WebSocket 握手视图。
- **不可见/口径**（如实标注，不造假）：
  - tap 缓冲输出不含连接/流 ID、地址、时间戳：`capture_stream_id=null`；
    五元组以 `127.0.0.1:0` 占位；`request_ts=response_ts=collection_ts`（tap
    消息接收时间），`latency_ms=0` 不表达业务延迟（契约附录 B）。
  - tap 输出中 HTTP/1 与 HTTP/2 呈现同一伪头形态，**观测协议只能来自
    部署断言**（会话级配置 `observed_http_version`，覆盖全部 tapped
    listener），缺省 UNKNOWN；不从内容猜测。
  - HTTP/2 多路复用的请求/响应配对由 Envoy 按流缓冲完成（一条
    HttpBufferedTrace=一个流）；适配器不做跨消息配对，不用五元组/时间
    接近合并流。
  - gRPC：仅元数据；HTTP 200 ≠ RPC 成功（grpc_status 取自响应 trailers）；
    取消/未完成如实 UNKNOWN，不伪造 grpc-status=0；默认不采集消息正文
    （content_type 跳过），不解析 Protobuf。
  - WebSocket：只交付握手视图；帧/消息正文不驻留、不解析。
  - 正文被 Envoy 按 `max_buffered_*_bytes` 截断时：
    `truncated=true` 且 `original_total_size=null`（契约 V1.1：截断但原始
    总大小未知）。
- 脱敏：与被动 HTTP/1 采集同一 httpsensor 出口，离主机前完成；多值
  Header/Trailer 逐值脱敏保序保留；`x-wdsp-*` 控制命名空间剥离。

## 部署步骤

1. **Envoy 配置**：每个需要采集的 listener 的 HCM 加入 tap filter（示例见
   本目录 `envoy.tap.yaml.example`）：

   ```yaml
   - name: envoy.filters.http.tap
     typed_config:
       "@type": type.googleapis.com/envoy.extensions.filters.http.tap.v3.Tap
       common_config:
         admin_config: { config_id: wdsp_tap }   # 所有 tapped listener 共用同一 config_id（单管理流约束）
   ```

   Admin 保持回环绑定（`admin.address.socket_address: 127.0.0.1:9901`）。

2. **agent.json 启用 tap 段**（默认关闭；显式启用，单会话）：

   ```json
   {
     "tap": {
       "enabled": true,
       "admin_addr": "127.0.0.1:9901",
       "source_instance": "envoy-prod-1",
       "config_id": "wdsp_tap",
       "observed_http_version": "2",
       "tls_terminated": true,
       "body_enabled": false,
       "max_body_bytes": 4096
     }
   }
   ```

   - `config_id` 必须与所有 tapped listener 的 tap filter
     `admin_config.config_id` 一致（同一会话 ID）。
   - `observed_http_version` 是**部署断言**：仅当全部 tapped listener 的
     ALPN/协议配置一致且已知时填写（如 ALPN 锁定 `h2` → "2"）；不确定或
     混合协议必须省略（UNKNOWN），不从内容猜测。
   - `tls_terminated` 是**部署断言**：仅当全部 tapped listener 均为可信
     TLS 终止点（本模板锁定同机回环拓扑）时置 true → `DECRYPTED`；
     混合 TLS/明文 listener 时必须为 false。
   - `max_body_bytes` 同时下发为 tap 输出 `max_buffered_rx/tx_bytes`
     （Envoy 侧超限即截断）；`body_enabled=false` 时正文不驻留、仅记大小与
     截断状态；gRPC 正文恒不采集。

3. **同机/同 Pod 拓扑**：适配器与 Envoy 共享回环（裸机同机，或 K8s
   sidecar 同 Pod）。Admin 端口不发布、不进 Service。

## 运行与停止

- 启动：agent 启动后建立**单条** `POST /tap` 管理流（提交会话级 tap 配置，
  config_id 覆盖全部 tapped listener）；Envoy 未就绪或拒绝时按 1s→30s
  有界退避重连（计数 `disconnects/reconnects/admin_rejects`）。
- 停止采集：agent.json 置 `tap.enabled=false` 或停止 agent；管理流断开后
  Envoy 侧 tap 会话即取消。回退时先停止本适配器并处理 v2 缓存，再降级
  不支持 v2 的程序（P1-03 §9）。
- 上行纪律：tap 记录仅经 HTTP 事件 schema **v2** 线格式上行；服务端未协商
  v2 时丢弃计数（`dropped_by_reason=tap_v2_not_negotiated`），不降级 v1 误标来源。

## 资源上限

| 项 | 默认 | 硬上限 |
|---|---|---|
| tap 会话 | 1 条（单管理流约束） | 1 |
| 单条 TraceWrapper JSON | 1 MB | 8 MB（超限丢弃计数并继续同步） |
| 正文缓冲（Envoy 侧+本地） | 4 KB | 10 MB（config.HardMaxBodySize） |
| Header/Trailer 存储总量 | 16 KB/消息 | 钳断计数 |
| 重连退避 | 1s→30s | 上限封顶 |

## 支持矩阵（本来源）

| 业务协议 | P1 可见 | 边界 |
|---|---|---|
| HTTP/1.1（下游 tap） | 请求+响应、trailers、截断状态 | 协议版本来自部署断言 |
| HTTP/2（下游 tap） | 同上加按流配对 | 不实现原生 HPACK 帧解析；配对由 Envoy 缓冲完成 |
| gRPC unary/streaming | service/method、grpc-status、取消/未完成状态 | 仅元数据；正文不采集；Protobuf 不解析 |
| WebSocket | 握手视图（101/失败状态） | 帧/消息不可见；握手记录在连接关闭时由 Envoy 冲刷 |
