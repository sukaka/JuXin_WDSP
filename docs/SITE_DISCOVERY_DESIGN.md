# 站点资产自动发现设计（流量学习域名/IP/端口）

## 一、背景与目标

部分客户并不清楚自己网络里实际开放了哪些 Web 站点。本功能从流经网关的流量中被动学习站点资产（域名 + 源站 IP + 端口 + 协议），在管理端形成资产清单，管理员人工确认后可到「网站应用」手动接入防护。

- 覆盖部署模式：镜像旁路（MIRROR）、路由牵引（ROUTED）、透明串接（TRANSPARENT）。
- HTTPS 站点通过解析 TLS ClientHello SNI 获取域名（无需解密流量）。
- 全端口自适应：协议嗅探，不限于固定端口集。
- 处置闭环：展示 → 人工确认/忽略 → 手动接入。不做一键转应用、不做自动接入。
- 反向代理（REVERSE_PROXY）模式不新增观测点：该模式下站点必须已配置才能过流，无发现价值。

## 二、总体架构

```
镜像口/业务口/桥口 ──AF_PACKET(只读副本)──> mirrorcap
   ├─ 目的端口 ∈ 检测端口集 → 现有 HTTP 还原 + Coraza 检测管线（不变），顺带记发现
   └─ 其他全部端口 → 首包协议嗅探：
         HTTP 方法前缀 → 解析 Host → 记发现 → 丢弃流
         TLS 0x16 0x03  → 解析 ClientHello SNI → 记发现 → 丢弃流
         其他           → 立即丢弃流
   └─ DiscoveryAggregator：(domain,ip,port,protocol) 窗口聚合，30s flush
        → site-discovery.jsonl（共享日志卷）

server: sitediscovery.Collector tail JSONL（断点续传）→ upsert site_asset_discoveries
管理端: GET /api/v1/site-discoveries + confirm/ignore/restore → 前端「站点发现」页
```

关键决策：

- **观测点统一收敛到 mirrorcap**。透明串接桥上被 REDIRECT 牵引的流量、路由牵引节点业务口的过境流量，都可被 AF_PACKET 以只读副本方式旁路捕获；tproxyd 保持「牵引+五元组上报+字节透传」职责不变，零侵入。
- **上报通道复用「JSONL + 共享卷 + 采集器」**，遵守架构约束（不新增网关→管理面 HTTP 推送）。
- **发现与检测独立启停**：无 MIRROR 应用（检测关闭）时，发现抓包仍可运行；同一接口被两者使用时共用抓包句柄。

## 三、网关侧设计（gateway/mirrorcap）

### 3.1 TLS SNI 解析（sni.go）

纯标准库手写 TLS record + ClientHello 解析：校验 record header（0x16, 0x03xx）→ handshake type=1 → 跳过 random/session_id/cipher_suites/compression → 定位 extension type=0（server_name）→ 取第一个 host_name。读取上限 16KB；非 TLS/无 SNI/截断/畸形均明确返回空，不 panic。不引入任何第三方依赖。

### 3.2 发现聚合与嗅探（discovery.go）

- `DiscoveryAggregator`：key={Domain,IP,Port,Protocol}，聚合 first/last/hits 与窗口内去重客户端集合（上限 1000，防内存膨胀）；每 flush_interval（默认 30s）把窗口结果追加写 JSONL 并重置窗口。
- 嗅探护栏：每条流只做一次首包判定，嗅探读取总量 ≤16KB；判完即 `DiscardBytesToEOF`，非 Web 流成本为常数级；流并发上限沿用现有 maxConn 护栏。
- 检测端口上的 HTTP 流量由 Detector 顺带 `Observe(hostOnly(req.Host), meta, "HTTP")`，不重复解析。

### 3.3 发现记录 JSON 契约（site-discovery.jsonl 每行）

```json
{
  "type": "site_discovery",
  "node": "gw-1",
  "domain": "example.com",
  "ip": "10.0.0.5",
  "port": 443,
  "protocol": "HTTPS",
  "source_mode": "MIRROR",
  "hits": 123,
  "client_count": 17,
  "window_start": "2026-08-21T04:00:00Z",
  "window_end": "2026-08-21T04:00:30Z"
}
```

- `domain` 空串 = 未识别（如无 SNI 的 TLS 握手）。
- `protocol` ∈ HTTP/HTTPS；`source_mode` ∈ MIRROR/ROUTED/TRANSPARENT，由发布方按接口角色下发。
- `hits`/`client_count` 为窗口内近似指标（采集器重放会重复累计，接受为近似值）。

### 3.4 sidecar 配置（mirrorcap.json 新增 discovery 块）

```json
{
  "discovery": {
    "enabled": true,
    "interfaces": [
      {"name": "eth2", "mode": "MIRROR"},
      {"name": "eth0", "mode": "ROUTED"}
    ],
    "flush_interval_sec": 30,
    "log": "/var/log/caddy/site-discovery.jsonl"
  }
}
```

沿用边车文件既有纪律：文件优先、env 兜底、last-good 保留、15s 轮询热启停。

发布链路（server/internal/gatewayconfig/sidecars.go）生成规则：

- 节点有 MIRROR 应用 → 取 role=MIRROR 接口，mode=MIRROR；
- 节点有 ROUTED/TRANSPARENT 应用 → 追加 role=TRAFFIC 接口，mode 取 TRANSPARENT（有透明应用时）否则 ROUTED；
- 无任何被动/串接应用 → enabled=false。

## 四、服务端设计（server/internal/sitediscovery）

### 4.1 表结构（迁移 000077_site_discovery）

`site_asset_discoveries`：

| 列 | 类型 | 说明 |
|---|---|---|
| id | uuid pk | |
| domain | text not null default '' | 空=未识别（保证唯一键可用） |
| ip | text not null | 源站 IP |
| port | integer not null | 源站端口 |
| protocol | text not null | HTTP/HTTPS |
| source_mode | text | 发现来源部署模式 |
| gateway_node | text | 发现节点 |
| seen_count | bigint | 累计命中次数（近似） |
| client_count | integer | 最近窗口去重客户端数（覆盖式） |
| first_seen / last_seen | timestamptz | |
| status | text default 'NEW' | NEW/CONFIRMED/IGNORED（CHECK 约束） |
| confirmed_by / confirmed_at | | 人工确认审计 |
| created_at / updated_at | timestamptz | |

`UNIQUE (domain, ip, port)`。同迁移种子权限点 `site_discovery.read` / `site_discovery.manage`（角色授权对齐 applications 权限点）。

### 4.2 Upsert 语义

`ON CONFLICT (domain, ip, port) DO UPDATE`：`seen_count` 累加、`client_count`/`last_seen`/`gateway_node` 覆盖、`first_seen` 保留首插值；**不覆盖** `status`/`confirmed_by`/`confirmed_at` 等人工处置字段。

### 4.3 采集器

断点纪律与 `apiruntime/collector.go` 一致：offset+inode+前缀指纹、轮转检测、原子保存、批量事务、错误行写错误文件、失败断点不前移。`type != site_discovery` 的行跳过。

### 4.4 管理 API

| 方法 | 路径 | 权限 | 说明 |
|---|---|---|---|
| GET | /api/v1/site-discoveries | site_discovery.read | 分页 + status/protocol/source_mode/keyword 过滤，按 last_seen 倒序 |
| POST | /api/v1/site-discoveries/{id}/confirm | site_discovery.manage | NEW→CONFIRMED |
| POST | /api/v1/site-discoveries/{id}/ignore | site_discovery.manage | NEW/CONFIRMED→IGNORED |
| POST | /api/v1/site-discoveries/{id}/restore | site_discovery.manage | →NEW（清空确认审计） |

确认/忽略/恢复走既有操作审计机制。OpenAPI 契约见 `server/openapi/fragments/11-site-discovery.yaml`。

## 五、前端（web/src/pages/site-discovery）

菜单「应用防护」组「网站应用」之后新增「站点发现」（roles=SECURITY_ADMIN）。表格列：域名（未识别置灰）、IP、端口、协议、来源模式（镜像旁路/路由牵引/透明串接）、网关节点、命中次数、客户端数、首次/最近发现、状态、操作。筛选：状态（默认 NEW）/协议/来源模式/关键字。行操作按状态机给出 确认/忽略/恢复；确认成功提示可前往「网站应用」手动接入，并提供跳转链接。

## 六、边界与风险

- **HTTPS 无 SNI**（老旧客户端）：退化为 IP+端口、域名「未识别」，属预期。
- **镜像只能看到明文**：HTTPS 仅取 SNI，不解析 URL/内容；检测能力边界不变。
- **全端口抓包性能**：首包分类+立即丢弃，非 Web 流常数级开销；流上限沿用现有护栏。
- **旁路铁律不变**：发现只读观测，决策封顶 OBSERVE，绝不阻断。
- **近似计数**：`seen_count`/`client_count` 为运营参考指标，不作精确计量。
- 反向代理模式无发现（见「一、目标」）；透明/路由模式下已接入应用的流量也会被记录，属预期（清单可按状态过滤）。
