# 九章 WDSP 分布式流量采集 Agent — Phase 1（MVP）实施契约

**版本：V1.0（Phase 1 冻结契约）**
**上游设计：docs/agents/WDSP_DISTRIBUTED_AGENT_DESIGN.md（§59 Phase 1、§67 TASK-001~012、§73 DoD）**

本文件是 Phase 1 开发期间 server（管理后端）、wdsp-agent（边缘 Agent）、web（前端）三方必须共同遵守的冻结契约。任何字段/路径变更必须三方同步。

## 1. 范围（Phase 1 只做这些）

- Linux Host Agent：AF_PACKET 旁路抓包（纯 Go，CGO_ENABLED=0，复用 gateway/mirrorcap 的 pcapgo 模式）、指定 TCP 端口过滤、入/出/双向、五元组提取、HTTP/1.x 请求行+Host 嗅探（仅明文，不做 Body 采集）、TLS ClientHello 识别（仅标记可见性，不解密）。
- 三种输出中的两种：`FLOW`（流元数据+HTTP 元数据事件，JSON 批量上报）与 `RAW`（原始包二进制帧批量上报，服务端 Phase 1 只做校验、计数、丢弃，不入库）。
- 控制通道：注册（一次性 Enrollment Token）、心跳（含 metrics）、配置拉取与 ACK、禁用/启用。认证为 `Authorization: Bearer <credential>`；mTLS 属 Phase 2，Phase 1 部署必须置于 HTTPS 之后。
- 本地缓存：断线时事件落盘（有硬上限、FIFO、最大保存时间），恢复后优先补传。
- 自我保护：出站带宽令牌桶限速、内存队列硬上限、CPU/内存阈值自动降级（停止抓包、保留心跳）、Fail-Open（Agent 任何故障不影响业务——旁路只读天然满足，代码中不得有任何回注报文能力）。
- 管理面：Enrollment Token 签发、Agent 列表/详情/禁用/删除、策略 CRUD 与绑定下发、流量事件查看、在线状态派生。

## 2. 标识与编码约定

- `agent_id`：服务端签发的 UUID 字符串（Agent 本地持久化，重启不变）。
- Enrollment Token：明文形如 `wdt_<64 hex>`（32 字节随机），服务端只存 SHA-256 hex 摘要，一次性使用，有过期时间，可撤销。
- Agent Credential：明文形如 `wda_<64 hex>`，注册响应中下發一次，服务端只存 SHA-256 hex 摘要。Agent 后续所有机器端点请求携带 `Authorization: Bearer <credential>`。
- 时间：JSON 中 Unix 秒（number）或 RFC3339 字符串，以各端点定义为准；HTTP 响应头时间以 RFC3339 为准。
- 所有列表端点分页参数：`page`（1 起）、`page_size`（默认 20，最大 100），响应 `{ "items": [...], "total": <int64> }`。
- 错误响应统一：`{ "error": { "code": "<MACHINE_CODE>", "message": "<human readable>" } }`，HTTP 状态码语义化（400/401/403/404/409/500）。

> **勘误（2026-09，实现口径）**：上两条与 §3 的线格式描述仅适用于**机器端点**（Agent → WDSP，§3），机器端点保持本契约原文裸 JSON + `{"error":{...}}` 不变（wdsp-agent 按此解析）。**管理端点**（§4）实现上采用仓库统一响应信封 `response.Body{ "code", "message", "data", "request_id" }`（`server/internal/response`）：成功时 `code=SUCCESS`，本契约所载响应结构（对象或 `{ "items", "total" }`）承载于信封 `data` 字段；错误时 `code` 取仓库统一错误码（`INVALID_ARGUMENT`/`RESOURCE_NOT_FOUND`/`RESOURCE_CONFLICT`/`INTERNAL_ERROR`），HTTP 状态码语义不变；`204 No Content` 响应不变（无信封）。

## 3. 机器端点（Agent → WDSP，不走会话/RBAC，走 credential 认证）

基路径全部在管理后端同一 HTTP 服务上。

### 3.1 注册

`POST /api/v1/agents/enroll`（无需 credential）

请求：
```json
{
  "enrollment_token": "wdt_...",
  "hostname": "web-prod-01",
  "ip": "10.0.1.10",
  "os": "Rocky Linux 9",
  "kernel": "5.14.0",
  "arch": "x86_64",
  "version": "1.0.0",
  "interfaces": [
    { "name": "eth0", "mac": "aa:bb:cc:dd:ee:ff", "ipv4": "10.0.1.10", "ipv6": "", "mtu": 1500, "speed_mbps": 1000 }
  ]
}
```
响应 `201`：
```json
{ "agent_id": "a3c98f51-...", "credential": "wda_...", "heartbeat_interval_seconds": 15, "config_version": 0 }
```
错误：400 参数非法；401 token 无效/过期/已用/已撤销。

### 3.2 心跳（携带 metrics 快照）

`POST /api/v1/agents/{agent_id}/heartbeat`

```json
{
  "timestamp": 1788256800,
  "status": "ONLINE",
  "metrics": {
    "cpu_percent": 3.2, "memory_mb": 128.5,
    "capture_pps": 1200, "capture_bps": 12345678,
    "forward_pps": 1100, "forward_bps": 10000000,
    "drop_pps": 5, "queue_depth": 12, "buffer_bytes": 0,
    "packets_received": 900000, "packets_processed": 890000,
    "packets_forwarded": 880000, "packets_dropped": 10000,
    "kernel_drops": 3, "current_mbps": 12.3
  }
}
```
`status` 枚举：`ONLINE | DEGRADED | ERROR`。
响应 `200`：
```json
{ "server_time": 1788256801, "config_version": 12, "desired_state": "ENABLED", "heartbeat_interval_seconds": 15 }
```
`desired_state`：`ENABLED | DISABLED`。Agent 收到 `DISABLED` 必须停止抓包（保留心跳）。`config_version` 大于本地已应用版本时，Agent 拉取配置。
另有 `POST /api/v1/agents/{agent_id}/metrics`，body 仅为上面 `metrics` 对象，服务端处理逻辑相同（返回 204）。

### 3.3 配置拉取与 ACK

`GET /api/v1/agents/{agent_id}/config` → `200`：
```json
{
  "version": 12,
  "policy": {
    "name": "production-web",
    "capture": {
      "interfaces": ["eth0"],
      "direction": "both",
      "protocols": ["tcp"],
      "ports": [80, 443, 8080, 8443]
    },
    "capture_level": "L0",
    "output": { "mode": "FLOW" },
    "limits": { "max_body_size": 262144, "outbound_mbps": 100, "cpu_percent": 20, "memory_mb": 512 },
    "sampling": { "enabled": false, "rate": 1.0 },
    "buffer": { "enabled": true, "max_size_mb": 512, "max_age_minutes": 30 }
  }
}
```
- `direction`：`ingress | egress | both`。
- `capture_level`：`L0 | L1 | L2 | L3`（Phase 1 Agent 仅实现 L0/L1 等价行为：元数据+请求头嗅探；收到 L2/L3 按 L1 处理并记录日志，不得报错拒绝）。
- `output.mode`：`FLOW | RAW | FLOW_RAW`。
- 无绑定策略时 `policy` 为 `null`，`version` 为当前 agents.config_version；Agent 使用内置默认（见 §6）并照常 ACK。

`POST /api/v1/agents/{agent_id}/config/ack`：
```json
{ "version": 12, "status": "APPLIED", "error": "" }
```
`status`：`APPLIED | FAILED`。

### 3.4 流量事件上报

`POST /api/v1/agents/{agent_id}/flows`
```json
{
  "events": [
    {
      "event_type": "request",
      "flow_id": "<agent_id>-<srcip>-<srcport>-<dstip>-<dstport>-<startts>",
      "timestamp": 1788256800,
      "src_ip": "10.1.1.10", "src_port": 51234,
      "dst_ip": "10.1.2.20", "dst_port": 8080,
      "protocol": "tcp",
      "direction": "ingress",
      "bytes_in": 0, "bytes_out": 0, "packets_in": 0, "packets_out": 0,
      "tls_visibility": "PLAINTEXT",
      "http_method": "POST", "http_host": "api.example.com", "http_uri": "/api/login", "http_status": 0
    }
  ]
}
```
- `event_type`：`request`（HTTP 请求行/Host 解析成功即上报）| `flow_end`（流关闭或空闲超时，携带累计字节/包计数）。
- `tls_visibility`：`PLAINTEXT | ENCRYPTED | UNKNOWN`（识别到 TLS ClientHello/密文 → ENCRYPTED；HTTP 明文解析成功 → PLAINTEXT；其余 UNKNOWN）。
- 每批 events 上限 500 条；超限 Agent 必须分批。
- 响应 `202`：`{ "accepted": <int> }`。入库失败整体 500，Agent 转入本地缓存。

### 3.5 RAW 包上报

`POST /api/v1/agents/{agent_id}/packets`，`Content-Type: application/x-wdsp-packet-batch`，二进制 body：

```
偏移  长度  含义
0     4     magic "WDP1"
4     8     batch_timestamp_unix (big-endian uint64)
12    2     frame_count (big-endian uint16)
14    ..    frames...
每个 frame:
  8  ts_sec (BE uint64)
  4  ts_usec (BE uint32)
  4  orig_len (BE uint32)
  4  cap_len (BE uint32)
  .. packet bytes (cap_len 字节，含 Ethernet 头)
```
- 单批 body 上限 8 MB；frame cap_len 上限 65535。
- 响应 `202`：`{ "accepted_frames": <int> }`。Phase 1 服务端校验 magic/长度后计数（累计到 agents.last_metrics 的 raw_frames_received/raw_bytes_received）并丢弃，不入库。

## 4. 管理端点（会话 + RBAC，走标准 authChain）

权限点：`traffic.agents.view`（GET）、`traffic.agents.manage`（写操作）。审计：token 签发/撤销、Agent 禁用/启用/删除、策略创建/修改/删除/绑定，均记 HIGH 级审计（module=`traffic-agents`）。

> **勘误（2026-09，实现口径）**：本节各端点所示响应 JSON 为信封 `data` 载荷结构——实际线格式为仓库统一信封 `response.Body{code,message,data,request_id}`（见 §2 末附注）；HTTP 状态码与 204 语义不变。

- `POST /api/v1/traffic/agents/enrollment-tokens` `{ "label": "prod-web", "ttl_minutes": 60 }` → `201 { "id": "...", "token": "wdt_...", "expires_at": "RFC3339" }`（token 仅此一次返回明文）。`ttl_minutes` 范围 5–10080。
- `GET /api/v1/traffic/agents/enrollment-tokens` → 列表（不含明文 token，含 used/revoked/expired 状态）。
- `POST /api/v1/traffic/agents/enrollment-tokens/{id}/revoke` → 204。
- `GET /api/v1/traffic/agents/summary` → `{ "total": n, "online": n, "offline": n, "degraded": n, "disabled": n }`。
- `GET /api/v1/traffic/agents?status=&q=&page=&page_size=` → 分页列表。item：`{ agent_id, hostname, ip, os, kernel, arch, version, status, disabled, last_seen, last_metrics, config_version, applied_config_version, created_at }`。
- `GET /api/v1/traffic/agents/{agent_id}` → 详情（上表字段 + `interfaces` 数组 + `policy_binding` 对象或 null）。
- `POST /api/v1/traffic/agents/{agent_id}/disable` → 204；`POST /api/v1/traffic/agents/{agent_id}/enable` → 204。
- `DELETE /api/v1/traffic/agents/{agent_id}` → 204（吊销 credential、删除绑定与网卡、保留审计）。
- `GET /api/v1/traffic/agents/{agent_id}/events?page=&page_size=` → 分页流量事件（按 ts 倒序）。
- 策略：
  - `GET /api/v1/traffic/policies` / `POST /api/v1/traffic/policies` `{ "name": "...", "config": <policy json，见 3.3> }`
  - `GET /api/v1/traffic/policies/{id}` / `PUT`（修改后 version+1）/ `DELETE`
  - `POST /api/v1/traffic/agents/{agent_id}/policy` `{ "policy_id": "..." }` 绑定（每 Agent 同时仅一条生效绑定，重复绑定即换绑）
  - `DELETE /api/v1/traffic/agents/{agent_id}/policy` 解绑

## 5. 状态派生规则（服务端查询时计算，不落库）

- `disabled = true` → `DISABLED`
- `last_seen` 距今 > 60 秒（或从未心跳且创建超过 60 秒）→ `OFFLINE`
- 否则取最近一次心跳上报的 `status`（`ONLINE | DEGRADED | ERROR`）

## 6. Agent 本地行为约定

- 本地状态目录 `/var/lib/wdsp-agent/`（`agent.json` 存 agent_id+credential+server 地址；`buffer/` 存磁盘缓存），配置目录 `/etc/wdsp-agent/`，日志走 stderr/systemd journal，级别默认 INFO。
- 无策略时的内置默认采集集：端口 `80,443,8000,8001,8080,8081,8443,8888,9000,9443`，direction=both，output=FLOW，outbound_mbps=100。
- 命令：`wdsp-agent enroll --server <url> --token <wdt_...>`；`wdsp-agent run [--config /etc/wdsp-agent/agent.json]`；`wdsp-agent version`。
- 心跳间隔默认 15s（以服务端注册/心跳响应为准）；metrics 随心跳上报。
- 断线重连：指数退避（1s 起，上限 60s）；断线期间事件写入磁盘缓存；恢复后先补传缓存再发新数据。
- 自我保护：每 10s 采样进程 CPU%（/proc/self/stat 差值/核数）与 RSS；连续 3 次超阈值 → 停止抓包进入 DEGRADED（心跳继续），回落后连续 3 次低于阈值 80% 自动恢复。
- 限速：全部外发字节（flows/packets/metrics/heartbeat 不计入心跳本身的小流量，仅计数据通道 flows+packets）经过令牌桶，速率 = policy.limits.outbound_mbps（默认 100）；桶满时 RAW 帧直接丢弃计数，FLOW 事件尝试入磁盘缓存，缓存满则丢弃计数。
- 内存队列硬上限：10000 事件或 64MB（先到为准）；磁盘缓存默认上限 512MB、单段 16MB、最长时间 30 分钟，超限 FIFO 删除最旧段。
- Body 采集：Phase 1 不采集任何请求/响应 Body（max_body_size 仅作前向兼容字段保留）。
- 红线：Agent 不得向任何网卡回写报文；不得因抓包 panic 影响宿主（所有抓包 goroutine recover 后降级重试）。

## 7. 数据库（迁移 000108/000109）

> 注：契约初稿写作 000106/000107，因编号被并行任务占用，实际落位 `000108_traffic_agents` / `000109_traffic_agent_perms`，表结构与权限种子不变。

表：`agent_enrollment_tokens`、`agents`、`agent_interfaces`、`agent_policies`、`agent_policy_bindings`、`agent_flow_events`（字段按 §4/§3 契约展开，agents.credential_hash 存 SHA-256 hex；agent_flow_events 建 (agent_id, ts DESC) 索引）。权限种子：`traffic.agents.view`、`traffic.agents.manage` 授予 SYSTEM_ADMIN、SECURITY_ADMIN（view 另授 AUDIT_ADMIN）。

## 8. 版本与依赖锁定

- server：`go 1.25.6`，不新增直接依赖（Phase 1 用 REST，不引入 gRPC）。
- wdsp-agent：独立 Go module `github.com/jiuzhang-waf/wdsp-agent`，`go 1.25.6`，唯一直接依赖 `github.com/google/gopacket v1.1.19`（与 gateway 锁定一致）；CGO_ENABLED=0 可构建；目标平台 linux/amd64、linux/arm64。
- web：不新增依赖，复用 Ant Design 5 + TanStack Query 现有模式。
