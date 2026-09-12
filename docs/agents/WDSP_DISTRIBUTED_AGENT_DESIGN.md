# 九章 WDSP 无流量镜像环境分布式 Agent 流量采集与转发系统详细设计方案

**文档版本：V1.0**\
**适用产品：九章 WDSP（Web 动态防护 / Web & API Security）**\
**文档用途：AI/Codex 开发实施文档**

------------------------------------------------------------------------

## 1. 项目背景

九章 WDSP 当前需要对 Web、API
等业务流量进行持续检测、资产发现、攻击识别、API
建模、敏感数据识别、异常行为分析和安全运营。

在传统 IDC 环境中，可以通过交换机 SPAN、TAP 等方式直接将镜像流量发送至
WDSP。但在公有云、政务云、私有云、国产云、虚拟化环境及 Kubernetes
环境中，可能存在以下问题：

1.  云平台不提供 VPC Traffic Mirroring。
2.  用户没有云网络层镜像权限。
3.  流量镜像功能需要额外购买。
4.  跨 VPC、跨租户环境无法统一镜像。
5.  Kubernetes 东西向流量难以从传统网络出口完整获取。
6.  HTTPS 流量即使能够抓包，也可能只能获取 TLS 密文。
7.  多云、多机房场景无法将所有业务流量直接接入单台 WDSP。
8.  全量原始流量跨网络回传会产生巨大的带宽和存储压力。

因此需要为九章 WDSP 增加一套独立的：

> **WDSP Distributed Sensor / Edge Agent 分布式流量采集系统**

通过在业务主机、Kubernetes Node、网关/Nginx/Ingress 等位置部署轻量
Agent，在不改变正常业务链路的前提下旁路采集 Web/API
流量，并将流量副本、HTTP 结构化数据或安全事件发送给中心 WDSP。

------------------------------------------------------------------------

# 2. 建设目标

本项目不是重新开发一套 WAF，而是解决 WDSP 的"流量从哪里来"问题。

核心目标：

``` text
没有交换机镜像
        ↓
没有云 Traffic Mirror
        ↓
部署 WDSP Agent
        ↓
采集业务主机 Web/API 流量
        ↓
安全、可靠地发送给 WDSP
        ↓
WDSP 继续使用现有检测能力
```

必须实现：

-   Linux 主机 Agent。
-   主机网络流量采集。
-   入站和出站流量采集。
-   Web/API 业务流量过滤。
-   原始 Packet 镜像。
-   HTTP 元数据提取。
-   HTTP Request/Response 结构化输出。
-   安全事件输出。
-   GRE/VXLAN 等镜像传输能力。
-   Agent 与 WDSP 之间的加密控制通道。
-   本地缓存。
-   断线重连。
-   流量限速。
-   Agent CPU/内存保护。
-   中央统一管理。
-   Agent 在线状态监控。
-   远程策略下发。
-   多 Agent 接入。
-   流量来源标识。
-   与现有 WDSP 检测引擎兼容。

后续阶段支持：

-   Kubernetes DaemonSet Sensor。
-   Nginx/Ingress/Envoy Gateway Sensor。
-   eBPF 深度采集。
-   TLS 解密点流量获取。
-   动态采样。
-   可疑会话升级为 Full Capture。

------------------------------------------------------------------------

# 3. 非目标

第一阶段不要做以下事情：

-   不让 Agent 直接承担 WAF 阻断。
-   不让 Agent 成为业务流量必须经过的串行节点。
-   不让 Agent 调用大模型处理每个网络包。
-   不在 Agent 中重新实现完整 WDSP 检测引擎。
-   不默认采集服务器所有网络协议。
-   不默认将所有原始网络流量跨公网发送。
-   不修改业务服务器正常 TCP/IP 转发路径。
-   Agent 故障不得导致业务中断。

Agent 第一阶段的核心定位：

> **旁路 Sensor + Traffic Broker + Edge Collector**

------------------------------------------------------------------------

# 4. 总体架构

## 4.1 标准架构

``` text
                       ┌─────────────────────────────┐
                       │         九章 WDSP            │
                       │                             │
                       │ Traffic Receiver            │
                       │ Session Reassembly          │
                       │ HTTP Parser                 │
                       │ WAF Detector                │
                       │ API Security                │
                       │ Data Security               │
                       │ AI Security                 │
                       │ Event Center                │
                       │ Agent Manager               │
                       └──────────────▲──────────────┘
                                      │
                         Sensor Transport Protocol
                                      │
                 ┌────────────────────┼────────────────────┐
                 │                    │                    │
                 │                    │                    │
        ┌────────┴────────┐  ┌────────┴────────┐  ┌────────┴────────┐
        │ Host Agent A    │  │ Host Agent B    │  │ K8s Sensor     │
        │                 │  │                 │  │                │
        │ eBPF/TC         │  │ AF_PACKET       │  │ eBPF/TC       │
        │ Packet Filter   │  │ Packet Filter   │  │ Pod Discovery │
        │ HTTP Metadata   │  │ Mirror Engine   │  │ Flow Export   │
        └────────▲────────┘  └────────▲────────┘  └────────▲───────┘
                 │                    │                    │
              eth0/ens*            eth0/ens*           Node NIC
                 │                    │                    │
              Web/API             Web/API             Pod Traffic
```

------------------------------------------------------------------------

# 5. 部署模式

WDSP 必须同时支持五种流量接入方式。

## 5.1 模式 A：交换机镜像

``` text
Switch SPAN
    ↓
WDSP
```

保留现有方式。

## 5.2 模式 B：云平台 Traffic Mirror

``` text
Cloud Traffic Mirror
        ↓
      WDSP
```

云平台支持时优先使用原生能力。

## 5.3 模式 C：Host Agent

``` text
Cloud VM
┌──────────────────────┐
│ Application          │
│                      │
│ eth0                  │
│  │                   │
│  ├─ 正常业务          │
│  │                   │
│  └─ Agent 捕获副本    │
└──────────┬───────────┘
           │
           ▼
          WDSP
```

这是本项目重点。

## 5.4 模式 D：Kubernetes Sensor

``` text
K8s Cluster

Node A                    Node B
├ Pod                     ├ Pod
├ Pod                     ├ Pod
└ Sensor DaemonSet        └ Sensor DaemonSet
      │                         │
      └──────────┬──────────────┘
                 ↓
                WDSP
```

## 5.5 模式 E：Gateway Sensor

``` text
Internet
   ↓
SLB
   ↓
Nginx / Envoy / Ingress
   ├────────────→ Backend
   │
   └── Mirror/Event ────→ WDSP
```

------------------------------------------------------------------------

# 6. Agent 核心架构

建议 Agent 使用 Go 开发。

对于高性能 Packet Capture 部分，可根据阶段选择：

-   第一阶段：AF_PACKET/libpcap。
-   第二阶段：eBPF + TC。
-   高性能阶段：AF_XDP。
-   极高性能场景：DPDK（可选，不作为第一阶段依赖）。

Agent 内部模块：

``` text
┌────────────────────────────────────┐
│            WDSP Edge Agent         │
├────────────────────────────────────┤
│ Agent Manager                      │
│ Configuration Manager              │
│ Interface Discovery                │
│ Packet Capture Engine              │
│ BPF Filter                         │
│ Flow Tracker                       │
│ TCP Session Tracker                │
│ HTTP Metadata Extractor            │
│ Traffic Replicator                 │
│ Transport Engine                   │
│ Local Buffer                       │
│ Rate Limiter                       │
│ Health Monitor                     │
│ Metrics Exporter                   │
│ Control Channel                    │
│ Security Module                    │
└────────────────────────────────────┘
```

------------------------------------------------------------------------

# 7. Agent 工作流程

``` text
启动 Agent
   ↓
读取本地配置
   ↓
连接 WDSP
   ↓
Agent 注册
   ↓
获取采集策略
   ↓
发现网卡
   ↓
挂载采集程序
   ↓
捕获 Packet
   ↓
BPF 初步过滤
   ↓
Flow 分类
   ↓
判断是否 Web/API 流量
   ↓
选择输出模式
   ↓
RAW / HTTP / EVENT
   ↓
本地队列
   ↓
限速/批处理/压缩
   ↓
发送 WDSP
   ↓
WDSP ACK
   ↓
更新统计
```

------------------------------------------------------------------------

# 8. 流量采集范围

默认不要抓所有流量。

默认关注：

``` text
TCP:
80
443
8000
8001
8080
8081
8443
8888
9000
9443
```

管理员可以增加自定义端口。

例如：

``` yaml
capture:
  interfaces:
    - eth0
  direction: both

  tcp_ports:
    - 80
    - 443
    - 8080
    - 8443

  custom_ports:
    - 7001
    - 7002
```

必须支持：

-   INGRESS
-   EGRESS
-   BOTH

------------------------------------------------------------------------

# 9. 三种数据输出模式

这是整个系统最重要的设计之一。

## 9.1 RAW_PACKET

发送原始网络包副本。

``` text
Ethernet
 ↓
IP
 ↓
TCP
 ↓
Payload
```

用途：

-   完整 TCP 重组。
-   WDSP 原有流量引擎。
-   深度协议分析。
-   网络取证。

优点：

-   WDSP 获得最原始数据。
-   最大程度兼容现有检测能力。

缺点：

-   带宽消耗最大。
-   HTTPS 仍然可能是密文。

------------------------------------------------------------------------

## 9.2 HTTP_STREAM

Agent 解析 HTTP 后发送结构化请求/响应。

示例：

``` json
{
  "agent_id": "agent-001",
  "host_id": "host-1001",
  "timestamp": 1788256800,
  "client": {
    "ip": "10.1.1.10",
    "port": 51234
  },
  "server": {
    "ip": "10.1.2.20",
    "port": 8080
  },
  "request": {
    "method": "POST",
    "scheme": "http",
    "host": "api.example.com",
    "uri": "/api/login",
    "headers": {},
    "body": ""
  },
  "response": {
    "status": 200,
    "headers": {},
    "body": ""
  }
}
```

用途：

-   API 资产发现。
-   API Schema 学习。
-   参数画像。
-   敏感数据识别。
-   AI 分析。
-   攻击检测。

------------------------------------------------------------------------

## 9.3 EVENT_ONLY

只发送元数据和安全事件。

``` json
{
  "agent_id": "agent-001",
  "src_ip": "10.1.1.10",
  "dst_ip": "10.1.2.20",
  "method": "POST",
  "host": "api.example.com",
  "uri": "/api/login",
  "status": 200,
  "request_bytes": 1240,
  "response_bytes": 3821
}
```

用于低带宽环境。

------------------------------------------------------------------------

# 10. 推荐的自适应采集策略

不要让所有流量永远采用 RAW_PACKET。

建议实现：

``` text
普通流量
    ↓
METADATA

重要 API
    ↓
HTTP_STREAM

异常流量
    ↓
FULL HTTP

高风险会话
    ↓
RAW PACKET / SESSION CAPTURE
```

定义四个 Capture Level：

  Level   模式          内容
  ------- ------------- -------------------------------
  L0      Metadata      五元组、URL、状态码、流量大小
  L1      HTTP Header   Header + Metadata
  L2      Full HTTP     Request/Response Body
  L3      Raw Session   原始 Packet / TCP Session

WDSP 可以动态向 Agent 下发：

``` text
将 10.10.20.30:8443 的 /api/payment
从 L0 提升至 L2
持续 30 分钟
```

------------------------------------------------------------------------

# 11. HTTPS 处理

这是必须单独设计的部分。

仅在 eth0 抓取 443：

``` text
Client
  ↓
TLS Ciphertext
  ↓
Agent
```

Agent 通常只能看到 TLS 密文。

因此必须支持多种 HTTPS 获取模式。

## 11.1 TLS 终止后采集

例如：

``` text
Client
   ↓ HTTPS
Nginx
   ↓ HTTP
Backend
```

Agent 优先采集：

``` text
Nginx → Backend
```

此时已经是 HTTP 明文。

这是推荐方式。

## 11.2 Gateway Mirror

对于 Nginx/Envoy/Ingress：

``` text
TLS
 ↓
Gateway
 ↓ 解密
HTTP
 ├→ Backend
 └→ Sensor
```

## 11.3 WDSP TLS Termination

如果 WDSP 本身作为反向代理，可以由 WDSP 解密。

Agent 不承担证书管理。

## 11.4 TLS 可见性标识

每个流必须标识：

``` text
tls_visibility:

ENCRYPTED
DECRYPTED
PLAINTEXT
UNKNOWN
```

WDSP UI 必须明确展示：

> 当前资产 HTTPS 流量为加密流量，无法进行完整 Payload 分析。

禁止系统在只看到 TLS 密文时声称已经完成完整 API Payload 检测。

------------------------------------------------------------------------

# 12. Agent → WDSP 传输协议

必须区分：

## 数据通道

负责：

-   Packet
-   HTTP Stream
-   Event

## 控制通道

负责：

-   注册
-   心跳
-   配置
-   策略
-   升级
-   状态
-   告警

架构：

``` text
Agent
 ├── Control Channel ─── TLS/gRPC ───→ WDSP
 │
 └── Data Channel
       ├── RAW → GRE/VXLAN/自定义封装
       └── HTTP/Event → gRPC Stream
```

------------------------------------------------------------------------

# 13. RAW 流量远程传输

同一二层环境可以直接 Packet Replication。

跨网络推荐：

-   GRE
-   ERSPAN
-   VXLAN

建议第一阶段优先：

``` text
VXLAN
```

或：

``` text
GRE
```

数据格式：

``` text
Original Packet
      ↓
Tunnel Encapsulation
      ↓
IP Network
      ↓
WDSP
      ↓
Decapsulation
      ↓
Original Packet
      ↓
WDSP Traffic Engine
```

必须保留原始：

-   src_ip
-   dst_ip
-   src_port
-   dst_port
-   protocol
-   TCP flags
-   payload
-   timestamp

------------------------------------------------------------------------

# 14. Agent 身份体系

每个 Agent 必须有唯一：

``` text
agent_id
```

建议 UUID。

例如：

``` text
a3c98f51-61ab-43cb-9c73-xxxxx
```

Agent 注册信息：

``` json
{
  "agent_id": "...",
  "hostname": "web-prod-01",
  "os": "Rocky Linux 9",
  "kernel": "5.14",
  "architecture": "x86_64",
  "agent_version": "1.0.0",
  "interfaces": [
    {
      "name": "eth0",
      "ip": "10.0.1.10"
    }
  ]
}
```

------------------------------------------------------------------------

# 15. Agent 注册机制

首次安装：

``` text
管理员
 ↓
WDSP
 ↓
生成 Enrollment Token
 ↓
安装 Agent
 ↓
Agent 携带 Token 注册
 ↓
WDSP 验证
 ↓
签发 Agent Credential
 ↓
建立长期身份
```

Token：

-   一次性。
-   有过期时间。
-   可以撤销。

------------------------------------------------------------------------

# 16. Agent 安全通信

必须使用：

``` text
TLS 1.2+
```

推荐：

``` text
mTLS
```

Agent：

-   Client Certificate。

WDSP：

-   Server Certificate。

避免简单：

``` text
API KEY
```

长期裸奔。

------------------------------------------------------------------------

# 17. 本地缓存

WDSP 不可达时：

``` text
Agent
 ↓
Local Buffer
```

建议：

``` text
/var/lib/wdsp-agent/buffer/
```

必须支持：

-   最大容量。
-   最大保存时间。
-   FIFO。
-   自动清理。
-   恢复后续传。

例如：

``` yaml
buffer:
  enabled: true
  max_size: 2GB
  max_age: 30m
```

RAW Packet 默认不建议长时间缓存。

Event 可以缓存较长时间。

------------------------------------------------------------------------

# 18. 背压机制

如果：

``` text
业务流量 = 2Gbps
Agent → WDSP = 500Mbps
```

Agent 绝不能无限缓存。

需要：

``` text
Incoming
   ↓
Queue
   ↓
High Watermark?
   ├ NO → Send
   └ YES
       ↓
    Degrade
```

降级顺序：

``` text
L3 RAW
 ↓
L2 Full HTTP
 ↓
L1 Header
 ↓
L0 Metadata
 ↓
Sampling
```

业务永远优先。

------------------------------------------------------------------------

# 19. Agent 自我保护

Agent 必须配置资源上限。

例如：

``` yaml
limits:
  cpu_percent: 20
  memory_mb: 512
  outbound_mbps: 200
```

如果超过：

``` text
CPU > 20%
```

执行：

``` text
降低采集级别
↓
降低采样率
↓
停止 RAW
↓
保留 Metadata
```

禁止 Agent 因为安全检测拖死业务服务器。

------------------------------------------------------------------------

# 20. Fail-Open 原则

Agent 必须是旁路。

任何情况下：

``` text
Agent Crash
Agent OOM
Agent Disconnect
WDSP Offline
Network Failure
```

都不得影响：

``` text
Application Traffic
```

必须实现：

``` text
Agent Failure
     ↓
Capture Stops

业务：
继续正常运行
```

这是生产环境的硬性要求。

------------------------------------------------------------------------

# 21. 去重机制

多网卡、多 Agent、K8s 环境可能重复看到相同流量。

建议生成：

``` text
flow_fingerprint
```

基于：

``` text
src_ip
dst_ip
src_port
dst_port
protocol
timestamp_window
tcp_seq
payload_hash
```

WDSP Receiver 做短时间窗口去重。

------------------------------------------------------------------------

# 22. Flow ID

每个 TCP Flow 分配：

``` text
flow_id
```

例如：

``` text
agent_id + 5tuple + timestamp
```

Request 和 Response 必须能够关联。

------------------------------------------------------------------------

# 23. 时间同步

所有 Agent 必须检测：

``` text
system clock
```

推荐 NTP/chrony。

Agent 每次心跳上报：

``` text
agent_time
server_time
clock_offset
```

超过阈值：

``` text
> 5 seconds
```

WDSP 告警。

否则攻击时间线和会话关联可能错误。

------------------------------------------------------------------------

# 24. WDSP Agent Manager

新增一级或二级菜单：

``` text
系统管理
  └── Agent 管理
```

页面包含：

-   Agent 总数。
-   在线数量。
-   离线数量。
-   异常数量。
-   Agent 版本。
-   主机名。
-   IP。
-   OS。
-   Kernel。
-   CPU。
-   内存。
-   当前采集 Mbps。
-   当前发送 Mbps。
-   Packet/s。
-   Drop/s。
-   当前模式。
-   TLS 可见性。
-   最后心跳。

------------------------------------------------------------------------

# 25. Agent 详情页

Tab：

``` text
基本信息
网卡
采集策略
实时流量
资源监控
传输状态
本地缓存
日志
版本
```

实时指标：

``` text
Captured PPS
Captured Mbps
Forwarded PPS
Forwarded Mbps
Dropped PPS
Queue Length
CPU
Memory
Disk Buffer
```

------------------------------------------------------------------------

# 26. 采集策略中心

新增：

``` text
Agent 策略
```

策略字段：

``` text
名称
适用 Agent
网卡
方向
协议
端口
IP范围
域名
采集等级
Body大小限制
采样率
带宽限制
```

------------------------------------------------------------------------

# 27. 策略示例

``` yaml
name: production-web

selector:
  tags:
    environment: production

capture:
  interfaces:
    - eth0

  direction: both

  protocols:
    - tcp

  ports:
    - 80
    - 443
    - 8080
    - 8443

capture_level: L1

limits:
  max_body_size: 1048576
  outbound_mbps: 100

sampling:
  enabled: false
```

------------------------------------------------------------------------

# 28. 标签系统

Agent 支持 Tag：

``` text
environment=production
business=erp
region=beijing
cloud=aliyun
owner=team-a
```

策略可以按照 Tag 下发。

------------------------------------------------------------------------

# 29. 多租户

如果 WDSP 支持租户：

``` text
tenant_id
```

必须贯穿：

``` text
Agent
Flow
HTTP Event
Security Event
API Asset
```

禁止跨租户数据混淆。

------------------------------------------------------------------------

# 30. Agent 与 API Security 联动

Agent 流量进入 WDSP 后：

``` text
Agent
 ↓
Traffic Receiver
 ↓
HTTP Parser
 ↓
API Discovery
 ↓
API Asset
 ↓
Schema Learning
 ↓
Parameter Baseline
 ↓
API Risk
```

必须记录：

``` text
source_type = AGENT
agent_id
host_id
interface
```

------------------------------------------------------------------------

# 31. Agent 与 WAF 检测联动

旁路 Agent 模式只能：

``` text
OBSERVE
```

不能直接：

``` text
BLOCK
```

因为流量已经是副本。

事件必须标识：

``` text
enforcement_capability:

OBSERVE_ONLY
INLINE_BLOCK
```

Agent Mirror：

``` text
OBSERVE_ONLY
```

WDSP Inline：

``` text
INLINE_BLOCK
```

避免 UI 出现"已拦截"，实际上只是旁路发现。

------------------------------------------------------------------------

# 32. Agent 与 AI 联动

不要：

``` text
每个 Packet → LLM
```

正确：

``` text
Packet
 ↓
Parser
 ↓
Detector
 ↓
Event
 ↓
Risk Aggregation
 ↓
高价值上下文
 ↓
AI Agent
```

AI 用于：

-   告警研判。
-   攻击链分析。
-   API 异常解释。
-   攻击溯源。
-   风险总结。
-   规则建议。

------------------------------------------------------------------------

# 33. 数据脱敏

Agent 可以选择：

``` text
Authorization
Cookie
Set-Cookie
Password
Token
身份证
手机号
银行卡
```

在离开主机之前进行脱敏。

策略：

``` text
NONE
MASK
HASH
DROP
```

例如：

``` text
Authorization: Bearer ********
```

------------------------------------------------------------------------

# 34. Request/Response Body 限制

禁止默认无限抓 Body。

建议：

``` text
Default: 256 KB
Maximum: 10 MB
```

超过：

``` text
body_truncated = true
```

记录原始大小：

``` text
original_body_size
```

------------------------------------------------------------------------

# 35. 文件上传处理

multipart/form-data：

默认：

``` text
只提取：
filename
content-type
size
form fields
```

不默认把大型文件完整上传至 WDSP。

可以针对高风险事件开启完整采集。

------------------------------------------------------------------------

# 36. WebSocket

第一阶段：

-   识别 Upgrade。
-   建立 Flow。
-   记录连接信息。
-   统计 message/bytes。

第二阶段：

-   WebSocket Frame Parser。
-   Payload 检测。

------------------------------------------------------------------------

# 37. HTTP/2

必须进入第二阶段核心计划。

第一阶段允许：

``` text
HTTP/1.1
```

第二阶段：

``` text
HTTP/2 Stream
```

需要正确处理 multiplexing，不能简单按照 TCP Connection = HTTP Session。

------------------------------------------------------------------------

# 38. gRPC

后续：

``` text
HTTP/2
 ↓
gRPC
 ↓
protobuf metadata
```

第一阶段可以识别：

``` text
Content-Type: application/grpc
```

------------------------------------------------------------------------

# 39. Kubernetes Sensor

部署：

``` text
DaemonSet
```

每个 Node 一个 Sensor。

需要识别：

``` text
node
namespace
pod
service
container
workload
```

流量事件增加：

``` json
{
  "k8s": {
    "cluster": "prod",
    "namespace": "payment",
    "pod": "payment-api-xxxx",
    "service": "payment-api"
  }
}
```

------------------------------------------------------------------------

# 40. Agent 安装

Linux：

``` bash
wdsp-agent install \
  --server https://wdsp.example.com \
  --token <ENROLLMENT_TOKEN>
```

安装后：

``` text
/etc/wdsp-agent/
/var/lib/wdsp-agent/
/var/log/wdsp-agent/
```

systemd：

``` text
wdsp-agent.service
```

------------------------------------------------------------------------

# 41. Agent 生命周期

状态：

``` text
INSTALLING
ONLINE
DEGRADED
OFFLINE
DISABLED
UPGRADING
ERROR
```

------------------------------------------------------------------------

# 42. Agent 升级

WDSP：

``` text
Agent Manager
 ↓
选择 Agent
 ↓
Upgrade
```

流程：

``` text
下载
 ↓
校验 SHA256
 ↓
验证签名
 ↓
备份旧版本
 ↓
升级
 ↓
Health Check
 ↓
失败自动回滚
```

------------------------------------------------------------------------

# 43. Agent 日志

日志等级：

``` text
DEBUG
INFO
WARN
ERROR
```

默认：

``` text
INFO
```

禁止默认记录完整：

-   Cookie。
-   Authorization。
-   Request Body。
-   Password。

------------------------------------------------------------------------

# 44. WDSP Receiver

新增服务：

``` text
wdsp-sensor-receiver
```

负责：

-   Agent Connection。
-   Authentication。
-   Data Ingestion。
-   Decompression。
-   Tunnel Decapsulation。
-   Agent Metadata。
-   Deduplication。
-   Queue。
-   Traffic Engine Dispatch。

架构：

``` text
Agents
 ↓
Receiver
 ↓
Message Bus
 ↓
Traffic Engine
 ↓
Detector Pipeline
```

------------------------------------------------------------------------

# 45. Receiver 高可用

生产环境：

``` text
Agent
 ↓
Load Balancer
 ↓
Receiver 1
Receiver 2
Receiver 3
 ↓
Message Bus
 ↓
WDSP
```

Agent 配置多个 endpoint：

``` yaml
servers:
  - wdsp-01
  - wdsp-02
```

------------------------------------------------------------------------

# 46. 消息队列

HTTP/Event 数据建议进入：

``` text
Kafka / NATS / Redpanda
```

如果现有 WDSP 已有消息总线，优先复用。

不要为了 Agent 单独引入复杂基础设施，除非现有吞吐量确实需要。

------------------------------------------------------------------------

# 47. 数据库设计

## agents

``` sql
id
agent_id
tenant_id
hostname
ip
os
kernel
arch
version
status
last_seen
created_at
updated_at
```

## agent_interfaces

``` sql
id
agent_id
name
mac
ipv4
ipv6
mtu
speed
capture_enabled
```

## agent_policies

``` sql
id
name
tenant_id
config_json
version
status
created_at
updated_at
```

## agent_policy_bindings

``` sql
id
policy_id
agent_id
applied_version
status
applied_at
```

## agent_metrics

建议进入时序数据库。

字段：

``` text
agent_id
timestamp
cpu
memory
capture_pps
capture_bps
forward_pps
forward_bps
drop_pps
queue_depth
buffer_bytes
```

------------------------------------------------------------------------

# 48. API 设计

## Agent 注册

``` text
POST /api/v1/agents/enroll
```

## Agent 心跳

``` text
POST /api/v1/agents/{id}/heartbeat
```

## 获取配置

``` text
GET /api/v1/agents/{id}/config
```

## 配置 ACK

``` text
POST /api/v1/agents/{id}/config/ack
```

## Metrics

``` text
POST /api/v1/agents/{id}/metrics
```

实际高频数据建议使用 gRPC Stream，而不是 REST。

------------------------------------------------------------------------

# 49. gRPC 服务建议

``` proto
service SensorService {
    rpc Connect(stream AgentMessage)
        returns (stream ServerMessage);
}
```

AgentMessage：

``` text
Register
Heartbeat
Metrics
FlowEvent
HttpEvent
AgentLog
ConfigAck
```

ServerMessage：

``` text
Config
CapturePolicy
CaptureLevelChange
Upgrade
Disable
Diagnostics
```

------------------------------------------------------------------------

# 50. 性能指标

第一阶段目标：

Agent 空闲：

``` text
CPU < 1%
Memory < 100MB
```

正常 Web 流量：

``` text
CPU < 10%
Memory < 300MB
```

建议第一阶段设计目标：

``` text
500 Mbps / Agent
```

后续：

``` text
1 Gbps+
```

必须真实压测后才能对外公布性能数字。

------------------------------------------------------------------------

# 51. 丢包监控

Agent 必须统计：

``` text
packets_received
packets_processed
packets_forwarded
packets_dropped
kernel_drops
queue_drops
transport_drops
```

WDSP UI：

``` text
采集完整率
```

例如：

``` text
99.97%
```

但只能根据实际计数计算，不能伪造。

------------------------------------------------------------------------

# 52. 网络带宽保护

默认：

``` text
Agent Outbound <= 100 Mbps
```

用户可修改。

达到阈值：

``` text
RAW
 ↓
HTTP
 ↓
Metadata
```

------------------------------------------------------------------------

# 53. 大规模部署

1000 Agent 场景：

``` text
                 WDSP Control Plane
                        │
              ┌─────────┴─────────┐
              │                   │
       Receiver Cluster      Agent Manager
              │
           Message Bus
              │
       Detection Cluster
```

Agent Manager 与 Data Receiver 必须解耦。

------------------------------------------------------------------------

# 54. 健康评分

每个 Agent：

``` text
Health Score 0-100
```

指标：

-   在线状态。
-   CPU。
-   内存。
-   丢包。
-   队列。
-   Buffer。
-   WDSP RTT。
-   配置同步。
-   版本。
-   时间偏差。

------------------------------------------------------------------------

# 55. 告警

必须提供：

``` text
Agent Offline
Agent High CPU
Agent High Memory
Packet Drop
Queue Overflow
Buffer Full
Clock Drift
Certificate Expiring
Version Outdated
Capture Stopped
Interface Down
WDSP Unreachable
```

------------------------------------------------------------------------

# 56. 审计日志

所有操作进入 WDSP 审计：

``` text
创建 Agent Token
删除 Agent
禁用 Agent
修改策略
下发策略
修改采集等级
Agent 升级
Agent 回滚
修改带宽限制
启用 Full Capture
```

------------------------------------------------------------------------

# 57. 隐私与数据控制

支持：

``` text
URL Query Mask
Header Mask
Body Mask
Sensitive Field Mask
```

管理员可配置：

``` text
password
passwd
token
access_token
refresh_token
authorization
cookie
```

------------------------------------------------------------------------

# 58. 开发目录建议

``` text
wdsp-agent/
├── cmd/
│   └── agent/
├── internal/
│   ├── capture/
│   ├── ebpf/
│   ├── filter/
│   ├── flow/
│   ├── http/
│   ├── transport/
│   ├── buffer/
│   ├── config/
│   ├── health/
│   ├── metrics/
│   ├── security/
│   └── upgrade/
├── pkg/
│   └── protocol/
├── api/
│   └── proto/
├── packaging/
│   ├── rpm/
│   └── deb/
└── tests/
```

WDSP：

``` text
services/
├── sensor-receiver/
├── agent-manager/
├── traffic-normalizer/
└── agent-policy/
```

------------------------------------------------------------------------

# 59. 开发阶段

## Phase 1：MVP

目标：

> 一台 Linux VM 安装 Agent 后，能够把指定端口的镜像流量送到 WDSP。

实现：

-   Agent 注册。
-   网卡发现。
-   AF_PACKET/libpcap。
-   TCP 端口过滤。
-   入/出方向。
-   RAW Packet。
-   Agent 心跳。
-   基础 Metrics。
-   Agent 管理页面。
-   在线/离线。
-   简单配置下发。

验收：

``` text
curl → Web Server
```

WDSP 能看到该请求对应的流量。

------------------------------------------------------------------------

## Phase 2：生产基础能力

实现：

-   eBPF/TC。
-   本地 Queue。
-   限速。
-   Buffer。
-   Fail-Open。
-   mTLS。
-   策略版本。
-   策略回滚。
-   Drop Metrics。
-   Agent Health。
-   自动重连。

------------------------------------------------------------------------

## Phase 3：HTTP Sensor

实现：

-   HTTP/1.1 Parser。
-   Request/Response 关联。
-   HTTP Metadata。
-   Full HTTP。
-   Body Limit。
-   Header Mask。
-   Sensitive Mask。
-   API Security 接入。

------------------------------------------------------------------------

## Phase 4：智能采集

实现：

``` text
L0
L1
L2
L3
```

支持 WDSP 动态调整采集等级。

------------------------------------------------------------------------

## Phase 5：Kubernetes

实现：

-   DaemonSet。
-   Node Sensor。
-   Pod Metadata。
-   Namespace。
-   Service。
-   Workload。
-   K8s UI。

------------------------------------------------------------------------

## Phase 6：Gateway Sensor

实现：

-   Nginx。
-   Envoy。
-   Ingress。
-   TLS 终止后 HTTP 获取。

------------------------------------------------------------------------

## Phase 7：高性能

实现：

-   AF_XDP。
-   Zero Copy。
-   Multi Queue。
-   CPU Affinity。
-   Batch Processing。

目标：

``` text
1Gbps+
```

最终性能以压测结果为准。

------------------------------------------------------------------------

# 60. MVP 验收场景

环境：

``` text
VM-A
10.0.0.10
Nginx

VM-B
10.0.0.20
WDSP
```

VM-A：

``` text
安装 Agent
```

访问：

``` text
POST /api/login
```

要求 WDSP 能看到：

``` text
Agent
Host
Source IP
Destination IP
Source Port
Destination Port
Method
Host
URI
Timestamp
Bytes
```

如果采集位置为 TLS 解密后的 HTTP，还需要看到：

``` text
Headers
Body
Response
```

------------------------------------------------------------------------

# 61. 故障验收

必须测试：

## Agent Kill

``` text
kill -9 wdsp-agent
```

结果：

``` text
业务正常。
```

## WDSP Shutdown

结果：

``` text
业务正常。
Agent 进入断线状态。
```

## 网络中断

结果：

``` text
业务正常。
Agent 根据策略缓存或降级。
```

## Agent CPU 达到阈值

结果：

``` text
自动降低 Capture Level。
```

## Queue Full

结果：

``` text
丢弃安全副本，不影响业务。
```

这是上线前必须通过的红线测试。

------------------------------------------------------------------------

# 62. 性能测试

必须测试：

``` text
100 Mbps
300 Mbps
500 Mbps
1 Gbps
```

记录：

``` text
CPU
Memory
Packet Loss
Agent BPS
WDSP BPS
Latency
Queue
Drop
```

旁路模式不使用"业务请求增加多少延迟"作为主要指标，因为 Agent
不应处于业务转发路径。

------------------------------------------------------------------------

# 63. 产品 UI

新增：

``` text
数据接入
```

下面：

``` text
流量接入
├── 流量源
├── Agent 管理
├── Agent 策略
├── K8s Sensor
├── 网关 Sensor
├── 接入状态
└── 流量质量
```

------------------------------------------------------------------------

# 64. 流量源页面

显示：

``` text
名称
类型
来源
Agent
IP
流量
PPS
协议
TLS状态
数据质量
状态
```

类型：

``` text
SPAN
CLOUD_MIRROR
HOST_AGENT
K8S_SENSOR
GATEWAY_SENSOR
```

------------------------------------------------------------------------

# 65. 数据质量

新增：

``` text
Traffic Visibility Score
```

例如：

``` text
网络层可见：100%
TCP可重组：99.8%
HTTP可解析：92%
HTTPS明文可见：68%
Request Body可见：65%
Response Body可见：60%
```

这对于 API Security 非常重要。

系统必须告诉用户：

> WDSP 到底看到了多少数据。

------------------------------------------------------------------------

# 66. 与现有 WDSP 的最终关系

Agent 不替代 WDSP。

``` text
Agent
=
眼睛 / Sensor

WDSP
=
大脑 + Detection + Security Operations
```

最终：

``` text
                 九章 WDSP
                    │
       ┌────────────┼────────────┐
       │            │            │
     WAF         API Sec       AI Sec
       │            │            │
       └────────────┼────────────┘
                    │
              Traffic Platform
                    ▲
                    │
       ┌────────────┼─────────────┐
       │            │             │
      SPAN      Host Agent    K8s Sensor
       │            │             │
    IDC流量       VM流量         Pod流量
```

------------------------------------------------------------------------

# 67. 第一阶段开发任务拆分

## TASK-001 Agent Skeleton

创建 Go Agent 工程。

完成：

-   config
-   logging
-   service
-   shutdown
-   version

## TASK-002 Enrollment

完成 Agent 注册。

## TASK-003 Interface Discovery

自动发现 Linux 网卡。

## TASK-004 Packet Capture

AF_PACKET/libpcap 抓包。

## TASK-005 BPF Filter

支持端口/IP过滤。

## TASK-006 Flow Metadata

提取五元组。

## TASK-007 Transport

Agent → WDSP。

## TASK-008 Heartbeat

Agent 在线状态。

## TASK-009 Metrics

PPS/BPS/Drop/CPU/Memory。

## TASK-010 Agent Manager

WDSP UI。

## TASK-011 Policy

策略创建和下发。

## TASK-012 Fail-Open Test

验证 Agent 故障不影响业务。

------------------------------------------------------------------------

# 68. AI 开发执行原则

给大模型/Codex 开发时必须遵守：

1.  不一次性实现全部 Phase。
2.  每 Phase 独立验收。
3.  第一阶段优先跑通真实 Packet。
4.  不先做漂亮 UI 再补数据面。
5.  所有 UI 数据必须最终来自真实 Agent Metrics。
6.  测试数据只允许用于开发演示。
7.  生产模式禁止自动生成虚假 Agent/流量。
8.  Agent 故障绝不能影响业务。
9.  所有 Buffer 必须有硬上限。
10. 所有 Queue 必须有硬上限。
11. 所有 Body Capture 必须有大小上限。
12. 所有流量回传必须有带宽限制。
13. 所有策略必须版本化。
14. 策略必须支持回滚。
15. Agent 必须能够被中心禁用。
16. Agent 升级必须验证签名。
17. 不允许把大模型放入 Packet 热路径。
18. AI 分析只能消费经过筛选的安全上下文。

------------------------------------------------------------------------

# 69. 推荐最终技术路线

第一版：

``` text
Go
+
AF_PACKET/libpcap
+
BPF Filter
+
gRPC
+
mTLS
+
现有 WDSP Traffic Engine
```

第二版：

``` text
Go
+
eBPF/TC
+
gRPC
+
GRE/VXLAN
+
HTTP Sensor
```

第三版：

``` text
eBPF
+
AF_XDP
+
Distributed Sensor
+
Adaptive Capture
+
K8s Sensor
```

不要第一版直接上：

``` text
DPDK
+
完整 HTTP/2
+
gRPC Parser
+
K8s
+
AI
+
全流量存储
```

否则开发复杂度会失控。

------------------------------------------------------------------------

# 70. 最终产品能力

完成后，九章 WDSP 应能够实现：

``` text
有交换机镜像
→ SPAN 接入

有云镜像
→ Cloud Mirror 接入

没有任何镜像能力
→ Host Agent 接入

Kubernetes
→ K8s Sensor 接入

Nginx/Ingress
→ Gateway Sensor 接入
```

最终形成：

> **九章 WDSP 多源分布式流量可视化与安全检测架构**

核心价值不是"Agent 抓包"本身，而是让 WDSP
不再依赖某一种云厂商、交换机或网络镜像能力。

只要业务运行在可部署 Sensor 的主机、节点或网关环境中，WDSP
就可以获得对应 Web/API 流量可见性。

------------------------------------------------------------------------

# 71. 开发优先级总结

## P0

-   Host Agent。
-   Linux。
-   Packet Capture。
-   BPF Filter。
-   Agent 注册。
-   mTLS。
-   Agent → WDSP 数据通道。
-   Flow Metadata。
-   RAW Packet。
-   Agent Manager。
-   Metrics。
-   Fail-Open。
-   Rate Limit。
-   Drop Monitoring。

## P1

-   eBPF/TC。
-   HTTP Parser。
-   Request/Response。
-   L0-L3 Capture Level。
-   Buffer。
-   Backpressure。
-   数据脱敏。
-   TLS Visibility。
-   Agent 自动升级。
-   策略版本/回滚。

## P2

-   Kubernetes Sensor。
-   Gateway Sensor。
-   HTTP/2。
-   WebSocket。
-   gRPC。
-   AF_XDP。
-   Adaptive Capture。
-   多 Receiver 集群。

------------------------------------------------------------------------

# 72. 最重要的架构红线

开发过程中不得违反以下原则：

``` text
第一：
Agent 永远旁路。
Agent 挂掉不能影响业务。

第二：
Agent 负责采集，不负责代替 WDSP。

第三：
不要把 LLM 放到实时 Packet 热路径。

第四：
优先采集 Web/API 有效流量，
而不是无脑上传整台服务器全部流量。

第五：
HTTPS 必须明确区分密文可见与明文可见。

第六：
流量、Queue、Buffer、Body 全部必须有限制。

第七：
Agent → WDSP 必须能够识别真实流量来源，
不能因为隧道封装丢失原始五元组。

第八：
旁路检测结果只能标记检测/观察，
不能错误显示为“已拦截”。

第九：
先完成 Host Agent + WDSP Receiver，
再扩展 K8s、Gateway、AI。

第十：
生产稳定性优先于功能数量。
```

------------------------------------------------------------------------

# 73. 第一阶段完成定义（Definition of Done）

只有满足以下全部条件，Phase 1 才算完成：

-   Linux Agent 可以安装、启动、停止、卸载。
-   Agent 可以自动注册到 WDSP。
-   WDSP 可以显示 Agent 在线状态。
-   Agent 可以发现指定网卡。
-   可以配置监听端口。
-   可以获取双向 Packet。
-   可以提取五元组。
-   可以把采集数据发送至 WDSP。
-   WDSP 能识别 Agent 来源。
-   WDSP 能看到真实访问流量。
-   Agent 有 PPS/BPS/Drop 指标。
-   Agent 与 WDSP 断开后自动重连。
-   Agent 停止后业务完全正常。
-   WDSP 停止后业务完全正常。
-   Agent 达到资源阈值后自动降级。
-   不存在无限 Queue。
-   不存在无限 Buffer。
-   不存在无限 Body Capture。
-   控制通道具备身份认证。
-   所有关键操作存在审计日志。

完成上述内容以后，再进入 HTTP Sensor、eBPF、Kubernetes 等后续阶段。
