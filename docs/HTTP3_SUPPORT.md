# HTTP/3 支持现状与启用方式（P2-06 诚实子集）

> 范围：本文档如实记录九章 WAF/WDSP（Caddy 2.11.4 + coraza-caddy 2.5.0 + jiuzhang_guard）
> 当前的 HTTP/3（QUIC）能力边界、可选启用方式与旁路验证证据。
> 验证日期：2026-08-20；验证环境：macOS + Docker Desktop，stage5 在用环境未受影响。

## 1. 结论摘要

- **网关二进制具备 HTTP/3 能力**：Caddy 2.11 起对 TLS 监听器**默认开启** HTTP/3
  （QUIC/UDP，与 HTTPS 监听同端口），发布的 JSON 配置中无需新增任何字段。
- **唯一缺口在编排端口发布**：docker compose 的 `ports` 缺省仅映射 TCP，
  QUIC 走 UDP——HTTPS 端口必须同时发布 UDP 映射，HTTP/3 客户端才能拨通。
  可选启用方式已以注释块形式写入 `deployment/docker-compose.wdsp.yml`（实验性，默认关闭）。
- **统一引擎对协议版本无感知（已实测）**：Caddy 终止 QUIC 后将请求以标准
  `http.Request` 交给 jiuzhang_guard / Coraza / reverse_proxy 管线，
  HTTP/3 请求与 HTTP/1.1、HTTP/2 走完全相同的检测与转发路径（见 §4 证据）。
- **协议版本可见性已生效**：HTTP/3 请求的协议版本在三个日志面正确记录
  `HTTP/3.0`（见 §4 证据与 §5 逐面字段口径）。

## 2. 启用方式（可选，实验性）

### 2.1 运行时发布配置（JSON 经 Admin API 发布）

`server/internal/gatewayconfig/generator.go` 生成的 HTTPS server **不带 `protocols` 字段，
Caddy 2.11 默认即启用 h1/h2/h3**（§4 臂 B 实测：删除 `protocols` 后 HTTP/3 依旧服务）。
因此发布通道**零改动**。若未来需要显式收敛协议集合，可在 server JSON 增加：

```json
"protocols": ["h1", "h2", "h3"]
```

（等价的 Caddyfile 写法为 `servers { protocols h1 h2 h3 }`；仅对 TLS 监听器生效。）

### 2.2 编排端口发布（必须，当前唯一缺口）

以 HTTPS 端口 443 为例（端口值须与应用接入配置的 HTTPS 端口一致）：

```yaml
# deployment/docker-compose.wdsp.yml 中已给出同款注释块（默认注释、按需启用）
gateway:
  ports:
    - "443:443"       # h1/h2 回退（TCP）
    - "443:443/udp"   # HTTP/3（QUIC）
```

注意：仅发布 UDP 而不发布 TCP 会导致不支持 h3 的客户端无回退路径；
`Alt-Svc` 通告（Caddy 自动输出 `alt-svc: h3=":443"; ma=2592000`）依赖 TCP 侧先可达。

### 2.3 启动期 Caddyfile（gateway/configs/Caddyfile，仅 POC 形态）

stage5 启动配置为 `:8080` 纯 HTTP（`auto_https off`），**无 TLS 即无 HTTP/3**
（QUIC 强制 TLS 1.3）。生产/演示形态下 HTTPS 站点由发布通道下发（含证书），
不依赖该启动文件；如需在启动文件内直接起 TLS 站点，可显式写
`tls <cert> <key>` 并同样按 §2.2 发布 UDP 端口。

## 3. 旁路验证实验（可复现）

实验资产（与 stage5 完全隔离：独立 compose 项目 `http3lab`、独立端口 18443、独立卷）：

- `deployment/http3-lab/docker-compose.http3-lab.yml` — 网关（stage5 同镜像 digest，
  Caddy v2.11.4）+ 测试源站；`18443:8443` 同时发布 TCP/UDP。
- `deployment/http3-lab/caddy-lab.json` — 与发布产物同构的 JSON 配置：
  `headers(RequestID) → jiuzhang_guard（含 access_log 与 API 动态防护 OBSERVE）→
  waf（DetectionOnly + CRS）→ headers → reverse_proxy` 完整链。
- `deployment/http3-lab/gen-cert.sh` — 自签证书生成（产物 `.runtime/` 已 gitignore，仅实验用）。

复现步骤（仓库根目录）：

```bash
bash deployment/http3-lab/gen-cert.sh
docker compose -f deployment/http3-lab/docker-compose.http3-lab.yml up -d
# 客户端：macOS 自带 curl 不支持 h3；本实验使用临时 Go 客户端
# （quic-go v0.59.0，网关既有依赖版本，客户端代码不进入仓库）。
docker compose -f deployment/http3-lab/docker-compose.http3-lab.yml down -v   # 清理
```

## 4. 验证证据（真实命令与输出摘要）

环境：`jiuzhang-gateway@sha256:145e27c9…0283b`（Caddy v2.11.4，与 stage5 在用镜像一致）。

**臂 A：显式 `protocols: ["h1","h2","h3"]`**

```
# TCP 侧回退与 Alt-Svc 通告（macOS curl，协商 h2）
$ curl -sk -D - https://localhost:18443/
HTTP/2 200
alt-svc: h3=":8443"; ma=2592000

# HTTP/3 请求（Go quic-go 客户端，直连 QUIC）
GET https://localhost:18443/                -> proto=HTTP/3.0 status=200
GET https://localhost:18443/api/orders/123  -> proto=HTTP/3.0 status=404   # 源站真实响应（无此路径）
GET https://localhost:18443/health          -> proto=HTTP/3.0 status=200
```

协议版本记录三面核对：

```
# Caddy 访问日志（/var/log/caddy/access.log）
request.proto = HTTP/3.0        # HTTP 层协议
request.tls.proto = h3          # QUIC 层 ALPN

# guard 全量访问日志（/var/log/caddy/access-full.jsonl）
"http_version":"HTTP/3.0"       # 3 条 h3 请求逐条对应；h2 请求记录 HTTP/2.0

# API 运行时事件（/var/log/caddy/api-runtime-events.log，OBSERVE）
{"endpoint_key":"GET /api/orders/{id}","proto":"HTTP/3.0","client_ip":"172.30.0.1",
 "final_action":"OBSERVE","details":[{"detector":"resource_access", ...}]}
```

要点：h3 请求经完整 guard 管线——路径模板归一化（`/api/orders/{id}`）、
检测器触发（`resource_access` OBSERVE）、真实客户端 IP 识别均正常工作，
响应为源站真实返回（200/404 与路径存在性一致），证明统一引擎对 HTTP/3 协议无关。

**臂 B：删除 `protocols` 字段（默认行为）**

```
GET https://localhost:18443/health -> proto=HTTP/3.0 status=200   # 默认即开启，零配置改动
```

（臂 B 验证后已将 `caddy-lab.json` 恢复为显式 protocols 版本，`diff` 一致。）

## 5. 能力边界（如实声明）

**已验证（本次实测）**：

- HTTP/3 请求经 Caddy 终止 QUIC → 统一 guard 管线 → 源站，响应正常；
- 协议版本可见性：`HTTP/3.0` 正确记录于 Caddy 访问日志、guard 全量访问日志
  （`http_version`）、API 运行时事件（`proto`）；
- h1/h2 回退与 `Alt-Svc` 通告正常；发布通道 JSON 零改动即可用（默认开启）。

**已知口径差异（如实）**：

- WAF 访问控制/CC 安全事件（guard-events.log → `access_control_events` 表）
  **无协议版本字段**——proto 可见性覆盖 API 运行时事件与全量访问日志，
  未覆盖访问控制/CC 事件（如需，为独立增量工作）。

**未实现（"深度解析"剩余边界，不在本次子集内）**：

- QUIC 层深度解析未做：0-RTT 会话恢复风险面、连接迁移（Connection Migration）、
  QUIC 报文级指纹/ flood 防护、stream 级背压等均不在统一引擎处理面内——
  引擎所见仅为 QUIC 终止后的 `http.Request`；
- QUIC 层 DDoS/放大攻击防护（如 Retry 包策略、初始报文放大限制）依赖
  Caddy/quic-go 内置默认值，未做策略化治理；
- HTTP/3 专属字段（QPACK 动态表、PRIORITY 帧等）无解析与检测；
- 生产级 h3 性能实测（QPS/时延矩阵）未做。

## 6. 遗留

- 生产编排（`docker-compose.yml` 及 stage5 在用编排）暂未默认发布 UDP——
  是否开启由部署方按 §2.2 显式选择（实验性，默认关闭）；
- 访问控制/CC 事件如需协议版本字段，需扩展 `events.Event` 结构与
  `access_control_events` 表（跨分片契约，独立评估）；
- "深度解析"全量能力（§5 未实现项）按 P2-06 原始任务书另行立项。
