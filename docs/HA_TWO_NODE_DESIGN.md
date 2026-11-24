# 双节点高可用与数据同步方案（HA Two-Node Design）

> 目标：两台网关节点组成高可用对，配置/证书/边车/防火墙/版本全量一致、计数与行为状态共享、任一节点故障不中断防护。
> 基础：当前代码库已具备并经全面修复的关键能力（见 `docs/DEVELOPMENT_STATUS.md` 与 `docs/HA_ACTIVE_STANDBY_DESIGN.md`）：
> - **安全节点协同通道（`hasyncd` + `server/internal/nodesync`）**：零第三方 Go 依赖，非 root（`uid/gid 1000:1000`），HMAC-SHA256 + ±60s 时间窗 + 120s 有界 Nonce 防重放 + 可选 TLS（CA/SHA-256 指纹 pin）；统一承接跨机 Caddy `/load`、边车配置（`ha-vip.json`/`network.json`/`tproxyd.json`/`mirrorcap.json`）、宿主机防火墙端口放行、15s 周期遥测汇聚与双机滚动升级包分发。
> - **发布扇出与证书同步（迁移 `000074` + `000236`）**：同一构建产物推送至全部登记次要节点（优先经 `hasyncd /v1/caddy/load` 转发至目标本机 Unix Socket，向后兼容直连 `admin_addr`）；HTTPS 站点采用 Caddy 原生 `apps.tls.certificates.load_pem` 内存加载（数据库与磁盘快照经 `RedactConfigSecrets` 强制脱敏为 `"***"`，回滚/重试由 `reinjectConfigSecrets` 按 `tags[0]` 证书 ID 从加密表重注入，失败闭环中止）；跨节点一致性校验采用剥离顶层 `admin` 段的 `CanonicalBusinessConfigHash`；直连 HTTP(S) `admin_addr` 扇出前通过 `GET /config/admin` 保留目标节点自身监听配置，绝不覆写为本机 Unix Socket；自动跳过本机主节点避免重复重载；支持 `POST /api/v1/config-versions/{id}/retry-sync` 按版本全量或定向单节点重试。
> - **网关节点身份与纯 WAF 解锁**：`jiuzhang_guard.Provision()` 优先读取 `GATEWAY_NODE_NAME` 环境变量（与 `netcollector`/`software_bypass` 一致，彻底移除 `nodepatch` 依赖）；节点管理与同步接口（`GET/POST/PATCH/DELETE /api/v1/api-security/nodes`、`POST /api/v1/api-security/nodes/{id}/test`、`GET /api/v1/api-security/nodes/consistency`）在纯 WAF 与 WDSP 全产品形态均可用。
> - **双机滚动升级（迁移 `000237`）**：支持 `LOCAL`（单机）与 `HA_ROLLING`（先备后主滚动升级），双机预检含脑裂阻断、备机失败立即止损不触碰主节点、支持失败备机单节点重试。
> - **共享状态存储**：`behavior_store=valkey`（滑窗/游标/并发，Lua 原子、Fail-open）+ CC 计数 `counter_backend=valkey` + 2 键平滑轮换 TLS 会话票据密钥（`gateway_runtime:tls_session_ticket_key` 支持 1~2 个逗号分隔 64 位 hex 密钥）。
> - **采集幂等**：事件按 `request_id` 去重、批次事务原子提交、断点续传。

---

## 1. 推荐拓扑

### 1.1 转发面：两网关 Active-Active（前置 LB 场景）

```text
                ┌──────── 负载均衡 ────────┐
                │  云LB / 硬件LB / DNS轮询   │  ← 客户端入口（VIP/域名）
                └──────┬───────────┬───────┘
                       ▼           ▼
               网关节点A (gw-a)    网关节点B (gw-b)  （同版本镜像、GATEWAY_NODE_NAME 区分身份）
               │  Caddy+Guard      │  Caddy+Guard
               │  havipd/netmgrd   │  havipd/netmgrd
               │  (本地侧车卷)      │  hasyncd (HMAC+TLS, uid 1000)
               └──→ 共享 Valkey ←──┘                 （行为/限速/会话共享：A60+B60>100 成立）
                       │
               管理面（api）+ PostgreSQL 主库         （配置/证书/资产/模型/审计/ha_events 唯一权威）
                       │
                       └── HMAC-SHA256 + 防重放 + TLS ──► 节点B hasyncd（配置/边车/防火墙/升级包/遥测）
```

> 无前置 LB 的透明串接主备拓扑（Keepalived VIP + Link-Pair 端口联动）详见 `docs/HA_ACTIVE_STANDBY_DESIGN.md`。

- **负载均衡选择**（按部署环境三选一）：
  1. 云/硬件 LB（最稳）：健康检查 `/health`（Caddy 已提供），故障自动摘除；
  2. Keepalived VRRP VIP（无外部 LB 时）：双机运行 `havipd`（封装 Keepalived），VIP 漂移 + `track_interface` 联动 + 脑裂检测（`HA_SPLIT_BRAIN` CRITICAL 告警）；
  3. DNS 轮询（最简）：故障摘除慢（TTL 级），仅建议灰度/实验环境。
- **会话亲和**：不需要。所有共享判定状态（CC/行为/封禁/管理会话）在 Valkey，身份指纹盐（`identity_salt`）与 TLS 会话票据密钥（1~2 键平滑轮换 `tls_session_ticket_key`）经发布通道全节点一致下发。

### 1.2 数据面：单写多读

- **PostgreSQL 主库唯一**：两节点的管理面服务连同一主库；高可用增强可选流复制 + 故障切换（Patroni/repmgr）或云托管主备（见 §3）。
- **Valkey 单实例共享**（v1 最简）或主从/哨兵（v2 增强）：计数类状态允许重建（丢失仅影响窗口期判定，Fail-open 已覆盖故障语义）。
- **网关→管理面单向日志采集**保持不变（架构红线）：每节点各自 `api-runtime-events.log` + 断点，采集器按 `request_id` 幂等去重；节点重启/断流重放安全。

### 1.3 管理面形态

两节点部署下管理面（api）**单实例即可**（不承载实时转发，故障期间防护不受影响：网关在最后一次成功发布的配置上继续运行，采集积压由断点幂等追平）。若要求管理面也 HA：双 api 实例共享同一 PG + Valkey，无状态天然可双跑（采集器按 `request_id`/幂等键去重；发布/滚动升级建议人为单点执行纪律，见 §4）。

---

## 2. 数据同步矩阵（每类数据的机制与一致性级别）

| 数据类 | 同步机制 | 一致性 | 现状 |
|---|---|---|---|
| 站点/防护/策略配置（含 API 模型、约束、脱敏、授权基线、合规规则、签名/扫描密钥） | 一次构建 → 优先经 `hasyncd /v1/caddy/load`（未配 `sync_agent_addr` 时回退直连 `admin_addr` 且保留目标 `admin` 段）+ `CanonicalBusinessConfigHash` 比对 + 逐节点回填 + 定向重试 | 强（业务配置逐字节语义一致） | **已交付** |
| HTTPS 证书与私钥 | `apps.tls.certificates.load_pem`（自动拼接 `ChainPEM`），内存直载免落盘；快照/预览经 `RedactConfigSecrets` 掩码 `"***"`，回滚/重试由 `reinjectConfigSecrets` 按 `tags[0]` 解密重注入 | 强（发布驱动，跨机无需共享证书盘） | **已交付** |
| TLS 会话票据密钥（STEK） | `gateway_runtime:tls_session_ticket_key` 支持 1~2 个逗号分隔 64 位 hex 密钥，注入 `apps.tls.session_tickets.key_source.keys_hex`（首键加密、次键平滑解密）；脱敏/重注入全闭环 | 强（平滑无感轮换） | **已交付** |
| 回滚与单节点重试 | 整站版本快照经 `reinjectConfigSecrets` 还原密钥后全节点扇出回滚；`POST /api/v1/config-versions/{id}/retry-sync` 支持全量或单节点定向重试 | 强 | **已交付** |
| 边车配置（`ha-vip.json`、`network.json`、`tproxyd.json`、`mirrorcap.json`） | 本机共享卷原子写 + 经 `hasyncd PUT/DELETE /v1/sidecars/{name}` 白名单原子推送（`ha-vip.json` 权限 `0640`，其余 `0644`，目录 `0770`） | 强（变更即时下发，失败写 `ha_events` `SYNC_FAILED`） | **已交付** |
| 宿主机防火墙放行端口 | 发布完成后经 `hasyncd POST /v1/firewall/ensure`（1~65535、≤64 端口）使用备机本机 `.hostctl-secret` 按 v2 HMAC 规范签名落盘交备机 `hostctl-exec.sh` 执行 | 强（端口精准放行） | **已交付** |
| 节点遥测、版本、网口与 HA/网络状态 | `NodeTelemetrySweeper`（15s 周期）轮询 `hasyncd GET /v1/status`，更新 `api_gateway_nodes`（`last_seen_at`/`last_policy_version`/`reported_version`/`ha_vip_status`/`network_status`），汇聚远端网口至 `gateway_node_interfaces`，状态迁移幂等落库 `ha_events` | 最终一致（≤15s） | **已交付** |
| 双机系统版本更新 | `HA_ROLLING` 先备后主滚动升级（迁移 `000237` `upgrade_node_executions`）：流式推送离线包至备机 `hasyncd`（SHA-256 + HMAC）→ 备机宿主机 `upgrade-executor.sh` 固定信任根独立验签执行 → 校验备机版本与健康后升主节点 | 强（备机失败立即中止不触主） | **已交付** |
| CC 限速/临时封禁计数 | `counter_backend=valkey` 共享计数器 | 强（共享原子计数） | **已交付** |
| 行为滑窗/对象游标/凭据并发与跨 IP 检测 | `behavior_store=valkey` 经发布下发启用（**默认 memory，双机部署必须显式置 valkey**） | 强 | **已交付** |
| 运行时事件/审计 | 各节点各自日志卷 → 采集器汇聚入库（`request_id` 幂等 + 批次事务原子） | 最终一致（秒级） | **已交付** |
| 身份指纹 | 同一 `identity_salt` 经发布下发（Redact 脱敏） | 强 | **已交付** |
| GeoIP 数据文件 | 各节点本地数据文件，随离线包/升级包同版本交付 | 部署一致 | **已交付** |
| 模型/策略版本账本 | PG 唯一账本（`api_runtime_policies` 等），网关侧不存状态 | 强 | **已交付** |

---

## 3. PostgreSQL 与 Valkey 的高可用选项

- **v1（推荐起步）**：PG 主从流复制（异步）+ 备份恢复（既有 `backups/restore` 体系）；故障时手工/脚本切换。Valkey 单实例或主从哨兵（计数状态允许重建，Fail-open 兜底）。
- **v2（可选增强）**：PG 同步复制或托管主备（云 RDS 类）；Valkey Sentinel 自动切换（网关 counter/behavior 客户端支持连接重试 + Fail-open 覆盖短暂中断）。

---

## 4. 脑裂与故障处理

- **转发面数据分歧**：Active-Active 下两网关配置同源、计数共享，不存在策略/计数脑裂；
- **VRRP VIP 双主脑裂（Active-Standby 场景）**：`hastatus.Sweeper` 结合 `ha_groups` 与全量成员汇聚状态检测同一组内 ≥2 个新鲜节点同时报告 `MASTER` 或持有 VIP，立即触发 **`HA_SPLIT_BRAIN`（CRITICAL，归属「基础设施」通知类别）** 并向 `ha_events` 写入 `SPLIT_BRAIN` 事件；前端展示醒目红条，且**脑裂未恢复期间滚动升级预检自动拒绝启动**；恢复单主后自动 `AutoRecover`；
- **管理面分裂**（双 api 形态时）：周期任务双跑幂等已由设计覆盖；发布与滚动升级动作建议人为单点执行纪律（自动 leader 选举列为后续增强）；
- **节点失联**：心跳/遥测 STALE（>5min）/SILENT（>1h）+ 一致性告警；LB 健康检查摘除；恢复后可一键 `retry-sync` 或重发自动对齐，日志断点续采追平；
- **数据漂移检测**：`GET /api/v1/api-security/nodes/consistency` 明确回答全节点版本一致性；不一致自动告警并支持全量/单节点定向重试同步。

---

## 5. 部署清单（两节点最小落地）

1. **两台网关主机**：同版本镜像（digest 锁定）或同版本裸机二进制，设置各自唯一 `GATEWAY_NODE_NAME`（如 `gw-a`/`gw-b`），配置 `api_node_heartbeat_seconds=60`；
2. **启用 `hasyncd` 协同代理**（推荐生产必选）：
   - 在备节点准备 `0600` 权限的 `HASYNC_SECRET_FILE`（≥32 字节 hex，如 `openssl rand -hex 32`）与管理网口 TLS 证书；
   - Docker 形态通过 `--profile ha-sync` 启用 `hasyncd`（非 root `1000:1000`、`cap_drop: [ALL]`、`read_only: true`）；裸机形态在密钥文件落盘后启用 `jiuzhang-hasyncd.service`（受 `ConditionPathExists` 保护，单机不启动）；
3. **节点登记与连通测试**：在控制台「API 防护 → 节点校验」（纯 WAF 与 WDSP 形态均可用）新增或编辑节点，填写 `node_name`、`sync_agent_addr`（推荐 `https://<内网管理IP>:18443`）、`sync_secret`（加密落库永不回显）并开启 `sync_enabled` → 点击「连通测试」（`POST /api/v1/api-security/nodes/{id}/test`）确认 `caddy_reachable`、`hostctl_ready`、`upgrade_ready` 就绪；
4. **基础设施与共享状态**：共享 Valkey（系统设置 `gateway_runtime` 显式置 `behavior_store=valkey`，并配置 `identity_salt` 与 64 位 hex `tls_session_ticket_key`）、共享 PG 主库、各自本地日志卷；
5. **LB/VIP**：按 §1.1 选择外部 LB 或启用 `havipd` VRRP VIP；健康检查 `/health`；
6. **告警联动**：通知渠道订阅「基础设施」类别（覆盖 `HA_SPLIT_BRAIN`、`HA_VIP_FAULT`、`LINK_PAIR_DOWN`、`LINK_PAIR_SUPPRESSED`、`NETWORK_APPLY_FAILED`、`API_GATEWAY_NODES` 与 `UPGRADE_FAILED`）。

---

## 6. 验证方案（自动化 + 目标 Linux 实机门槛）

> **双机 HA Lab（已更新消除 `nodepatch`）**：编排 `deployment/ha-lab/docker-compose.ha-lab.yml` 为 `gw-a`/`gw-b` 直接注入 `GATEWAY_NODE_NAME` 环境变量，并将 `ha-admin-b` 挂载至 `/var/run/caddy/node-b`（完全落于 `/var/run/caddy/` 白名单内，无任何安全边界放宽）；验证脚本 `test/ha/ha-lab-verify.sh` 覆盖配置一致、共享计数、故障摘除、发布中故障与管理面中断全场景。

1. **配置与 HTTPS 证书一致性**：发布含 HTTPS 站点配置 → 两节点均 `SUCCESS`、`CanonicalBusinessConfigHash` 一致、`GET /api-security/nodes/consistency` `consistent=true`、curl 两节点 HTTPS 均 200 且跨节点 TLS 会话恢复 `Reused`；
2. **STEK 2 键平滑轮换**：写入 `newKey,oldKey` 并发布 → 旧票据仍可恢复、新连接签发新票据 → 轮换窗口后收敛为单 `newKey`；
3. **共享计数**：A/B 各打 60 次同身份写请求（阈值 100）→ 共 120>100 触发统一限速（`behavior_store=valkey`）；
4. **故障摘除与定向重试**：发布瞬间断开备机 → 主成功、备记 `FAILED` + 告警 → 备机恢复后调用 `POST /api/v1/config-versions/{id}/retry-sync` 定向对齐；
5. **双机滚动升级**：选择 `HA_ROLLING` 上传离线升级包 → 先备后主执行并记录 `upgrade_node_executions`；模拟备机失败验证立即止损且主节点零影响，修复后单节点补升；
6. **目标 Linux 实机交付门槛**：依据 `docs/tasks/UPGRADE_INCIDENT_2026-11-17.md`，本机单测、mock、镜像构建与 harness 验证**不可替代**目标 Linux 宿主机的真实安装、跨机升级、回滚与外部客户端实测，正式发版前必须在真实 Linux 双机环境完成端到端验收。

---

## 7. 风险与边界（如实声明）

### 7.1 跨节点协同通道安全边界

- **首选通道（`hasyncd`）**：所有端点强制校验 **HMAC-SHA256 + ±60s 时间窗 + 120s 有界 Nonce 防重放**，**不存在任何未认证 HTTP/TCP 端点**（`--healthcheck` 仅读取本机健康戳文件）；进程以非 root `1000:1000` 运行，不挂载 `docker.sock`，不申请 `NET_ADMIN`；升级包独立由备机宿主机 `upgrade-executor.sh` 按固定信任根 Ed25519 复验签名。
- **管理面出站防线**：`sync_agent_addr` 与 `admin_addr` 均强制校验仅允许内网地址（拒绝公网、云元数据 `169.254.169.254`、链路本地、userinfo/路径/查询/片段），拨号时执行 DNS 重解析复检防重绑定并禁用 HTTP 重定向。
- **兼容通道（直连 `admin_addr`）**：仅作无 `hasyncd` 时的向后兼容路径；Caddy Admin API 无内建鉴权，生产环境**强烈建议统一收敛至 `hasyncd` + HTTPS/TLS**，不暴露无鉴权 TCP Caddy Admin 端口；如确需直连 HTTP(S) `admin_addr`，须采用内部 PKI `https://`、仅绑带外管理网卡并配置防火墙源地址白名单。

### 7.2 其他如实边界

- **无 TCP 连接镜像/状态同步**：切换瞬间在途长连接会断开一次由客户端重连（详见 `docs/HA_ACTIVE_STANDBY_DESIGN.md` §7.3）；
- **共享 Valkey 单点与 Fail-open**：Valkey 故障时行为/CC 判定按 Fail-open 降级，不中断业务转发；
- **异步 PG 复制窗口**：主从切换瞬间可能丢失最近秒级管理面写入（资产/审计），已发布安全策略不受影响；
- **双 api 实例**：发布与滚动升级任务暂需人为单点执行纪律（自动 leader 选举列为后续增强）；
- **实机验证声明**：任何未在目标 Linux 宿主机实测的安装、升级、回滚及外部访问项，在交付记录中必须如实标记 `NOT_RUN`。
