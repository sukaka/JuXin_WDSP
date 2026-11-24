# 主备高可用（VIP 漂移 + 网桥端口联动 + 会话保持）设计

> 状态：**生产级双机 HA 全面落地（含 `havipd` + `hasyncd` 跨机协同、双节点状态/脑裂汇聚、`ha_events` 持久化与双机滚动升级）**
> 关联文档：
> - `docs/HA_TWO_NODE_DESIGN.md`（双节点 Active-Active、跨机配置/证书/边车/防火墙同步与双机滚动升级方案）
> - `docs/NETWORK_MODES_DESIGN.md`（多网口管理与透明串接/路由牵引/镜像模式）
> - `docs/BARE_METAL_GATEWAY_DESIGN.md`（裸机网关部署）
> - `docs/HA_OPERATIONS_GUIDE.md`（部署清单、运维手册与故障处置矩阵）
> 关联代码：`gateway/netmgrd`（宿主机网络与 Link-Pair 执行末端）、`gateway/havipd`（VIP/Keepalived 执行末端）、`gateway/hasyncd`（零第三方依赖 HMAC 跨节点协同代理）、`gateway/modules/jiuzhang_guard/stek`（多键静态 STEK）、`server/internal/nodesync`（安全协同客户端与 15s 遥测汇聚）、`server/internal/apinodes`（节点管理/连通测试/一致性）、`server/internal/hagroups`（主备组/远端同步/脑裂判定/事件持久化）、`server/internal/hastatus`（多节点告警与 `HA_SPLIT_BRAIN`）、`server/internal/gatewayconfig`（`load_pem` 证书同步与发布扇出）、`server/internal/upgrades`（先备后主滚动升级）

---

## 1. 背景与目标

现有 Active-Active HA 方案（`HA_TWO_NODE_DESIGN.md`）的转发面前提是**前置负载均衡**（云 LB / 硬件 LB / DNS）。目标客户环境中存在另一类典型部署：

- **无前置 LB**，上游为防火墙或交换机，靠**链路通断**决定流量走 A 链路还是 B 链路；
- WAF/WDSP 以**透明网桥串接**在链路中，两台设备做主备（Active-Standby）；
- 管理入口走 **VIP**，VIP 平时在主节点，主故障时漂移到备节点；
- 网桥任一成员口链路故障时，必须**把配对口也 down 掉**——否则上游看到本链路仍然"通"，不会切换，流量黑洞。

本文定义该形态的产品化设计，全部能力**页面可配置**（纯 WAF 与 WDSP 全产品形态均可用）。目标：

1. **主备 VIP**：页面指定虚拟 IP（IPv4 CIDR）、主备角色（优先级）、抢占策略、`track_interfaces`（监控网桥成员口）；经 `hasyncd` 自动同步双节点 `ha-vip.json`，VIP 漂移/脑裂状态汇聚进视图、持久化至 `ha_events` 并触发告警。
2. **端口联动（Link-Pair）**：网桥成员口掉 carrier → 配对口联动 set down；故障恢复 → 配对口回 up；防抖防震荡；支持管理面直接编辑并下发远端备节点 `network.json`。
3. **会话保持**：链路/VIP 切换后，终端用户**不需要重新登录**，管理控制台会话不中断，反代终结 TLS 场景支持 2 键平滑轮换会话票据密钥恢复；各层会话语义见 §7 如实声明。
4. **配置与版本双机一致**：单点配置经发布通道（`load_pem` 证书 + 边车 + 防火墙端口）同步双节点，版本升级经 `HA_ROLLING` 先备后主滚动执行，漂移由一致性视图与定向重试兜底。

## 2. 术语

| 术语 | 含义 |
|---|---|
| 主备组（HA Group） | 两台网关节点组成的 Active-Standby 对，共享一个或多个 IPv4 VIP；单个节点同一时间仅允许归属一个主备组 |
| VIP | 虚拟 IP（IPv4 CIDR），经 VRRP（Keepalived）在主备节点间漂移 |
| Link-Pair（端口联动对） | 网桥的两个成员口互为配对：一方链路故障，另一方被 `netmgrd` administratively down；故障恢复后回 up |
| `track_interfaces` | Keepalived `track_interface` 监控的关联接口列表（如透明网桥成员口），链路故障触发主动降级让位 |
| carrier | 网卡链路层载波状态（`/sys/class/net/<if>/carrier` 或 `ip link` 的 `LOWER_UP` 标志） |
| 联动标记 | `netmgrd` 记录"该口是被本组件联动 down 的"事实，恢复判定的唯一依据（防误动运维手工操作） |
| `hasyncd` | 运行在备节点上的非 root 轻量协同代理（HMAC-SHA256 + ±60s + Nonce 防重放 + 可选 TLS），承接配置/边车/防火墙/升级包同步与遥测上报 |

## 3. 需求范围

### 3.1 功能需求（FR）

| 编号 | 需求 |
|---|---|
| FR-1 | 页面创建/编辑/删除主备组：成员节点（恰 2 台已登记网关节点，跨组互斥）、IPv4 CIDR VIP 列表、VRID、整秒 `advert_int_ms`（1000~10000）、`track_interfaces`、各节点优先级、抢占开关、安全字符集 VRRP 认证串 |
| FR-2 | 页面为本节点及已接入 `hasyncd` 的远端备节点配置网桥与 Link-Pair（`hold_down`/`hold_up`/`max_flaps_per_hour`） |
| FR-3 | `netmgrd` 监控成员口 carrier，按状态机执行联动 down/up，状态经本机卷与 `hasyncd /v1/status` 汇聚至管理面 |
| FR-4 | `havipd` 按下发配置生成 Keepalived 配置（节点区分 `router_id`、`-r` VRRP pidfile、重启孤儿清理、`--healthcheck`），启停 Keepalived 并回写 `ha-vip-status.json` |
| FR-5 | 管理面汇聚全组成员运行状态（`node_statuses`）、实时检测双主脑裂（`split_brain` + `HA_SPLIT_BRAIN` CRITICAL 告警）、持久化 `ha_events` 时间线并支持远程人工回切 |
| FR-6 | TLS 会话票据密钥材料（`gateway_runtime:tls_session_ticket_key`，1~2 键平滑轮换）与 HTTPS 证书（`load_pem`）经发布通道加密/脱敏一致下发 |
| FR-7 | 支持 `HA_ROLLING` 先备后主双机滚动升级（脑裂阻断、备机失败立即止损不触碰主节点、单节点重试） |
| FR-8 | 全部配置与升级动作走 CSRF + 权限校验（`ha.read`/`ha.manage`、`upgrades.*`）+ 高危操作审计 |

### 3.2 非功能需求（NFR）

- VIP 漂移时间：主节点整机断电场景 ≤ 5s（Keepalived 默认 `advert_int` 1s × 3 + 收敛余量）；
- 端口联动反应时间：carrier 丢失 → 配对口 down ≤ 3s（轮询 500ms + `hold_down` 默认 1s + 执行余量）；
- 防抖：链路抖动（1s 内反复 up/down）不得引起配对口震荡；连续联动频率超限进入抑制并告警；
- 切换期间已建立 TCP 连接**会断开**（如实声明，见 §7.3），客户端自动重连，HTTP 短连接成功率 ≥ 99%（重试一次语义）。

### 3.3 明确不做（边界）

- **TCP 连接镜像/状态同步**（conntrack 同步、会话表同步）：不做。行业同级串联产品同样不做；代价是切换时在途长连接断一次（§7.3）。
- 跨地域多活、三层以上集群、网关间状态 gossip：不做（与 `HA_TWO_NODE_DESIGN.md` 一致）。
- QUIC/HTTP3 连接迁移：不做。
- 备节点**业务流量预热**：不做（备节点平时不承载业务流量，仅心跳/遥测/配置同步）。

## 4. 总体架构

```text
            上游防火墙/交换机（按链路通断选路：默认链路1，断→链路2）
              │ 链路1                     │ 链路2
        ┌─────┴─────┐              ┌─────┴─────┐
        │ eth2  eth3│              │ eth2  eth3│   ← Link-Pair + track_interface
        │ [  br0   ]│              │ [  br0   ]│
        │ 网关A (主) │              │ 网关B (备) │   ← GATEWAY_NODE_NAME=gw-a / gw-b
        │ tproxyd / │              │ tproxyd / │
        │  caddy    │              │  caddy    │   ← load_pem 证书 + 2 键 STEK
        │ netmgrd   │              │ netmgrd   │
        │ havipd    │◄── VRRP ────►│ havipd    │   ← VIP：默认在 A，故障漂移到 B
        │           │              │ hasyncd   │◄── HMAC+防重放+TLS（配置/边车/防火墙/升级/遥测）
        └─────┬─────┘              └─────┬─────┘
              └──────► 共享 Valkey ◄─────┘         （CC/行为/判定态/管理会话；Fail-open）
                        │
              管理面 api + PostgreSQL 主库           （配置/证书/ha_events/upgrade_node_executions 权威）
```

- **转发面**：A 承载全部业务流量；B 链路因 A 的 Link-Pair 全口 up 且上游选路规则而不承载流量；B 进程全量运行（通过 `hasyncd` 保持配置、证书、边车与防火墙端口与 A 一致）。
- **管理入口 VIP**：运维/浏览器访问 VIP → 落在 MASTER 所在节点；VIP 漂移后管理会话不中断（共享 Valkey）。
- **配置与更新面**：管理面一次构建后，通过本地卷 + `hasyncd` 同步全节点 Caddy 配置（含 `load_pem` 证书）、边车文件（`ha-vip.json`/`network.json`/`tproxyd.json`/`mirrorcap.json`）、宿主机防火墙端口与离线升级包；`NodeTelemetrySweeper` 每 15s 反向汇聚各节点活性、版本、网口与 VIP/网桥状态。

## 5. 关键设计决策

| 编号 | 决策 | 理由 / 备选 |
|---|---|---|
| D-1 | VIP 用 **Keepalived 封装**（生成配置 + 启停 + 状态采集），不自研 VRRP | VRRP 协议细节（GARP、抢占、脑裂、单播协商）自研风险高；Keepalived 成熟可靠 |
| D-2 | Link-Pair 在 **`netmgrd` 扩展**实现，不新增宿主机网络守护进程 | 复用既有 `network.json`/`network-status.json` 契约与安全红线（exec 参数数组、5s 超时、幂等） |
| D-3 | Keepalived 封装为**独立 sidecar `gateway/havipd/`** | 长驻守护进程生命周期与 `netmgrd` 语义不同；独立进程故障域隔离；`ha-vip.json` 采用 `0640` 权限供同组 `1000` 读取且 `other` 不可读 |
| D-4 | 节点身份由 **`GATEWAY_NODE_NAME` 环境变量**决定，彻底取消 `nodepatch` | 保持"同一构建产物全节点一致"的扇出铁律；`havipd` 与 `jiuzhang_guard` 均按本机节点名自选条目或打标 |
| D-5 | 新增零第三方依赖 **`gateway/hasyncd`** 承接跨节点协同 | Caddy Admin API 无鉴权且无法同步边车、防火墙与升级包；`hasyncd` 以非 root `1000:1000` 运行，强制 HMAC-SHA256 + 防重放 + 可选 TLS |
| D-6 | HTTPS 证书采用 Caddy 原生 **`load_pem`**，STEK 采用 **1~2 键平滑轮换** | 避免跨节点共享证书磁盘；`RedactConfigSecrets` 与 `reinjectConfigSecrets` 确保数据库/磁盘快照永不留明文私钥 |
| D-7 | 联动恢复保守 + 抢占默认 `nopreempt` + 单节点仅属一组 | 只恢复带联动标记的口；主恢复不自动抢 VIP 避免二次闪断；`uq_ha_group_members_node_id` 彻底根除多组覆盖单文件 |
| D-8 | 双机升级采用 **`HA_ROLLING` 先备后主保守滚动策略** | 备机失败立即止损不触碰主节点；脑裂态拒绝启动升级；备机独立按固定信任根验签 |

## 6. 端口联动（Link-Pair）详细设计

### 6.1 配置契约（`network.json` 扩展与跨节点编辑）

`netmgrd` 输入契约（`bridges[]` 元素可选 `link_pair` 字段；缺省不启用）：

```json
{
  "bridges": [
    {
      "name": "br0",
      "ports": ["eth2", "eth3"],
      "link_pair": {
        "enabled": true,
        "hold_down_ms": 1000,
        "hold_up_ms": 5000,
        "max_flaps_per_hour": 20
      }
    }
  ],
  "ip_forward": true,
  "routes": [],
  "updated_at": "..."
}
```

- `link_pair` 仅允许出现在**恰好 2 个成员口**的桥上；
- `hold_down_ms`：carrier 持续丢失阈值（默认 `1000`，区间 `[200, 10000]`）；
- `hold_up_ms`：carrier 恢复阈值（默认 `5000`，区间 `[1000, 60000]`）；
- `max_flaps_per_hour`：每小时联动上限，超限进 `SUPPRESSED` 并告警（默认 `20`，区间 `[1, 200]`）；
- **远端备节点支持**：`GET /api/v1/gateway/network-config?node_name=` 返回 `remote_editable` 标记；当目标节点为已登记 `sync_agent_addr` 且 `sync_enabled=true` 的备节点时，`remote_editable=true`，管理面使用该节点经遥测汇聚的网口清单校验后落库并通过 `hasyncd PUT /v1/sidecars/network.json` 原子下发，同时返回其汇聚的 `network_status`。

### 6.2 状态回写（`network-status.json`）

```json
{
  "applied_at": "...",
  "ok": true,
  "bridges": [{"name": "br0", "state": "ok", "message": "..."}],
  "link_pairs": [
    {
      "bridge": "br0",
      "state": "BOTH_UP|DEGRADED|PROPAGATED_DOWN|SUPPRESSED",
      "down_port": "eth2",
      "propagated_port": "eth3",
      "propagated_by_linkpair": true,
      "flap_count_hour": 3,
      "last_event_at": "...",
      "message": "eth2 carrier lost 1.2s -> eth3 set down"
    }
  ]
}
```

### 6.3 监控与执行状态机

```text
BOTH_UP ──任一口 carrier 丢失持续 hold_down──► PROPAGATED_DOWN
                                                  │  （配对口 set down + 打联动标记 + 回写 + 告警）
PROPAGATED_DOWN ──故障口 carrier 恢复持续 hold_up──► BOTH_UP
                                                  │  （配对口 set up + 清联动标记 + 回写）
任意态 ── flap 超限 ──► SUPPRESSED（冻结动作 + 告警；原样重新保存配置即复位）
```

- 动作仅 `ip link set dev <if> down|up`（exec 参数数组，不经 shell，5s 超时），幂等；
- **联动标记**：只恢复 `propagated_by_linkpair=true` 的口，绝不触碰运维手工 down 的口；
- **抑制复位**：重新保存配置（`updated_at` 变化）即复位抑制态；
- **与进程级 fail-open 关系**：网口 carrier 丢失 → Link-Pair down 对口让上游切走；数据面进程崩溃 → fail-open 直通等待 watchdog 自愈，二者不冲突。

## 7. 会话保持（会话同步）设计

### 7.1 会话分层模型与切换语义

| 层 | 状态持有方 | 切换影响 | 同步机制 | 结论 |
|---|---|---|---|---|
| 应用会话（业务登录态） | 客户端 cookie/token + 源站 | **无影响** | 无需同步 | **用户不需要重新登录** |
| WAF 判定态（CC/临时封禁/行为滑窗/身份指纹） | 共享 Valkey | 无影响 | `counter_backend=valkey` + `behavior_store=valkey` + `identity_salt` 全节点一致 | **已交付**（双机必显式置 `valkey`） |
| 模型/策略/学习产物 | PostgreSQL 主库 | 无影响 | 单权威源 | **已交付** |
| TLS 会话（反代终结 TLS） | WAF 实例内存（STEK） | 密钥一致 → 直接 `Reused`；未配密钥 → 回退一次完整握手（不掉登录态） | `tls.stek.jiuzhang` + `gateway_runtime:tls_session_ticket_key`（1~2 键平滑轮换） | **已交付** |
| TLS 会话（桥接透传模式） | 端到端 | 无影响 | 天然保持 | **天然保持** |
| TCP 连接（在途长连接） | 端到端内核态 | **切换即断一次** | 不做连接镜像（§3.3） | 如实声明（§7.3） |
| 管理控制台会话 | 共享 Valkey | 无影响 | VIP 漂移后原 cookie 连续有效 | **管理员不需要重新登录** |

### 7.2 TLS 会话票据密钥 2 键平滑轮换

- 系统设置 `gateway_runtime:tls_session_ticket_key` 接受 **1~2 个逗号分隔的 64 位 hex 密钥**（32 字节/键，严格校验长度、合法 hex 与无重复，拒绝 >2 键）。
- 生成器输出至 `apps.tls.session_tickets.key_source.keys_hex`（`tls.stek.jiuzhang` 自研静态 provider）：首键用于加密新签发票据，次键用于解密旧票据，轮换期间双机均能平滑恢复旧会话，零握手抖动。
- `RedactConfigSecrets` 与 `reinjectConfigSecrets` 完整覆盖多键脱敏与回滚重注入，绝不明文落库或落盘。

### 7.3 TCP 在途连接：如实声明

切换瞬间在途 TCP 连接**必然中断**（RST 或超时）；HTTP/1.1 短连接由客户端/浏览器自动重试，用户无感；WebSocket、SSE、长轮询、大文件上传等长连接会断一次并依赖客户端重连。不做 conntrack 连接镜像，本边界与主流硬件 WAF 一致并向客户如实声明。

## 8. VIP 与主备管理设计

### 8.1 `havipd`（`gateway/havipd/`）与打包交付

- **契约与权限**：读取 `/var/run/caddy/sidecars/ha-vip.json`（权限 **`0640`**，目录 `0770`，同组 `1000` 可读、`other` 无访问权限）；生成的 Keepalived 配置 `<workdir>/<group>.conf` 权限保持 `0600`；状态文件 `ha-vip-status.json` 权限 `0644`（不含任何敏感串）。
- **契约示例**：

```json
{
  "group": "ha-main",
  "state": "ENABLED",
  "members": [
    {"node": "gw-a", "priority": 120},
    {"node": "gw-b", "priority": 100}
  ],
  "vrrp": {
    "vrid": 51,
    "vips": ["192.168.31.100/24"],
    "iface": "eth0",
    "preempt": false,
    "advert_int_ms": 1000,
    "auth_pass": "v1psecr8",
    "unicast_peers": ["192.168.31.61", "192.168.31.62"],
    "track_interfaces": ["eth2", "eth3"]
  },
  "updated_at": "2026-11-24T16:00:00Z"
}
```

- **前后端与执行端一致校验**：
  - `auth_pass`：严格匹配 `^[A-Za-z0-9._:@+-]{1,8}$`（杜绝空格、控制字符及 `{}` `#` `!` `"` `\` 配置注入）；
  - `advert_int_ms`：默认 `1000`，仅允许 `[1000, 10000]` 且为 `1000` 整数倍（精确匹配 Keepalived VRRPv2 秒级通告）；
  - `vips`：仅允许合法 **IPv4 CIDR**（`ip.To4() != nil`）；
  - `track_interfaces`：最多 16 个合法接口名、去重保序且不得等于 `iface`，渲染为 Keepalived `track_interface { ... }` 块；
  - `router_id`：生成为 `JZ_HA_<sanitize(group)>_<sanitize(node)>`，确保主备节点具备不同 `router_id`。
- **只读容器与重启孤儿清理**：
  - 启动 Keepalived 时显式传入 `--pid <workdir>/<group>.pid -r <workdir>/<group>.vrrp.pid`，兼容 `read_only: true` 容器（避免写只读 `/run/vrrp.pid`）；
  - `ha-vip.json` 不存在时（即使 `havipd` 刚重启 `s.cfg == nil`），`stopAnyManagedKeepalivedLocked` 扫描 `WorkDir/*.pid`（先主 pidfile 后 `.vrrp.pid`），逐一经 `/proc/<pid>/comm == "keepalived"` 校验后执行 `SIGTERM`→`SIGKILL` 同步停止并清理过期/损坏 pidfile，彻底杜绝重启后 VIP 残留；
  - 提供 `--healthcheck` 探针（无需 `--node`，校验状态文件存在、mtime ≤30s 且 JSON/state 合法），供 Docker `HEALTHCHECK` 与升级执行器复用；
  - 已完整纳入 Docker 镜像（`gateway/images/havipd/Dockerfile`，digest 锁定）、Stage5 Compose（默认启用、无配置时静默 `STOPPED`、`cap_drop: [ALL]` + `cap_add: [NET_ADMIN, NET_RAW, NET_BROADCAST]` + `group_add: ["1000"]` + `read_only: true`）、离线包（15 镜像）、裸机包（`jiuzhang-havipd.service`）及增量/全量升级包。

### 8.2 脑裂检测与多节点汇聚

- 默认 `nopreempt`（D-7），`track_interfaces` 绑定网桥成员口；
- `GET /api/v1/ha/groups` 与 `GET /api/v1/ha/groups/{id}` 返回全组成员汇聚状态 `node_statuses` 与布尔字段 `split_brain`（同组 ≥2 个新鲜成员报告 `MASTER` 或持有 VIP 时为 `true`）；
- `hastatus.Sweeper` 结合 `ha_groups` 与全量成员汇聚状态（本机卷 + `api_gateway_nodes.ha_vip_status`/`network_status`）：
  - 检测到双主/双持 VIP → 触发 **`HA_SPLIT_BRAIN`（CRITICAL）** 并落库 `ha_events`（`SPLIT_BRAIN`），恢复单主自动 `AutoRecover`；
  - 任一成员 `FAULT`/状态过期/Keepalived 停止 → 触发 `HA_VIP_FAULT`（消息标明故障节点名）；
  - 任一成员网桥 `PROPAGATED_DOWN`/`SUPPRESSED`/`ok=false` → 触发对应告警并标明节点名。

### 8.3 数据模型（迁移 `000080` + `000107` + `000236` + `000237`）

- **`ha_groups`**：主备组配置表，迁移 `000236` 新增 `track_interfaces JSONB NOT NULL DEFAULT '[]'`；创建/更新在显式 `pgx` 事务内原子覆盖主表与成员表，空切片恒序列化为 `[]`（绝不写 JSONB `null`）。
- **`ha_group_members`**：成员表（恰 2 行），迁移 `000236` 新增唯一索引 `uq_ha_group_members_node_id (node_id)` 保证单节点同时仅属一个主备组（冲突映射 HTTP 409）。
- **`ha_events`**（迁移 `000236`）：持久化漂移、联动、脑裂、回切与同步失败历史（`id`、`group_id`、`group_name`、`node_name`、`event_type`、`detail JSONB`、`occurred_at`，索引 `(group_id, occurred_at DESC)`、`(node_name, occurred_at DESC)`、`(occurred_at DESC)`）。
- **`api_gateway_nodes`**（迁移 `000236` 扩展）：新增 `sync_agent_addr`、`sync_secret_ciphertext`（加密存储、API 仅返回 `has_sync_secret`）、`reported_version`、`ha_vip_status`/`ha_vip_status_at`、`network_status`/`network_status_at`。
- **`upgrade_jobs` & `upgrade_node_executions`**（迁移 `000237`）：`upgrade_jobs` 新增 `cluster_mode`（`LOCAL`/`HA_ROLLING`），`upgrade_node_executions` 跟踪逐节点角色（`STANDBY`/`PRIMARY`）、顺序、状态（`PENDING`/`TRANSFERRING`/`APPLYING`/`VERIFYING`/`SUCCESS`/`FAILED`/`SKIPPED`）、版本与错误详情。

### 8.4 核心 REST 接口（详见 `server/openapi/wdsp-api.yaml`）

| 方法与路径 | 权限 | 说明 |
|---|---|---|
| `GET /api/v1/ha/groups` | `ha.read` | 主备组列表 + 本机 `status` + 全量成员 `node_statuses` + `split_brain` |
| `POST /api/v1/ha/groups` | `ha.manage` | 创建主备组，按本机归属写本地 `ha-vip.json` 并经 `hasyncd` 推送远端成员，返回 `sync_results` |
| `GET /api/v1/ha/groups/{id}` | `ha.read` | 详情 + `status` + `node_statuses` + `split_brain` |
| `PATCH /api/v1/ha/groups/{id}` | `ha.manage` | 更新主备组（乐观锁 + 节点互斥），同步推送新成员并收回被移出成员的 `ha-vip.json`，返回 `sync_results` |
| `DELETE /api/v1/ha/groups/{id}` | `ha.manage` | 仅在本机属该组（或无其他组占用本机）时删本机 `ha-vip.json` 防误删，并通知远端成员收回，返回 `sync_results` |
| `POST /api/v1/ha/groups/{id}/failback` | `ha.manage` | 人工回切：优先依据全量新鲜成员状态判定 VIP 实际持有方（独立管理面亦可用），同步双节点并写入 `ha_events`（`FAILBACK`） |
| `GET /api/v1/ha/events` | `ha.read` | 持久化 HA 事件时间线分页查询（支持 `group_id`/`node_name`/`event_type` 筛选） |
| `GET/POST/PATCH/DELETE /api/v1/api-security/nodes` | `ha.read`/`api_runtime.read` 与 `ha.manage`/`api_policy.publish` | 全产品形态（含纯 WAF）节点预登记、协同代理配置、连通测试（`POST .../nodes/{id}/test`）与离网删除（被主备组引用时 409 拒绝） |
| `POST /api/v1/config-versions/{id}/retry-sync` | `gateway_configs.publish` | 对指定已发布版本重跑全量或单节点配置同步 |
| `GET /api/v1/upgrades/nodes` & `POST /api/v1/upgrades/{id}/retry-node` | `upgrades.read` / `upgrades.execute` | 集群节点版本状态视图与失败备节点单节点重试升级 |

## 9. 故障场景矩阵

| 场景 | 预期行为 | 恢复 |
|---|---|---|
| 主节点单个桥口掉 carrier | Link-Pair down 对口（≤3s）+ Keepalived `track_interface` 降优先级 → 上游切备链路、VIP 漂移；在途长连接断一次 | 插回线 → `hold_up` 后对口回 up；`nopreempt` 不抢 VIP；人工 failback 回切 |
| 主节点整机断电 | Keepalived 收不到通告 → VIP ≤5s 漂移到备；备机遥测上报 `MASTER` 并记 `ha_events` | 开机 → `BACKUP` 待命；配置经一致性视图核对，必要时 `retry-sync` |
| 备节点掉电 | 无业务影响；心跳/遥测 STALE/SILENT 告警 | 开机 → `hasyncd` 遥测恢复，重发或 `retry-sync` 对齐 |
| 主节点 WAF 进程崩溃 | fail-open 直通（链路不断，上游不切）；进程拉起即恢复检测 | 既有 watchdog |
| 网口抖动（反复 up/down） | `hold_down`/`hold_up` 防抖；超 `max_flaps` → `SUPPRESSED` 冻结 + 告警 | 查物理链路后原样重新保存网络配置复位 |
| 管理面 api 宕机 | 网关按最近发布配置运行；VIP/联动宿主机自治不受影响 | api 恢复后遥测与采集追平 |
| VRRP 脑裂（双 MASTER） | 触发 `HA_SPLIT_BRAIN`（CRITICAL）+ `ha_events` `SPLIT_BRAIN` + 页面红条；滚动升级预检自动阻断 | 恢复 VRRP 通告链路，确认收敛后解除脑裂告警 |
| 滚动升级中备节点失败 | 标记备节点 `FAILED`、主节点 `SKIPPED`、任务 `FAILED`（`STANDBY_UPGRADE_FAILED`），**绝不触碰主节点** | 排查修复备节点后调用单节点重试继续补升 |
| Valkey 宕机 | CC/行为 Fail-open 降级；业务转发不中断 | Valkey 恢复后计数重建 |

## 10. 安全红线（不可放宽）

- `netmgrd`/`havipd`/`hasyncd` 全部零新增第三方 Go 依赖（仅标准库），外部命令一律 exec 参数数组执行（不经 shell）、单动作 5s 超时；
- `hasyncd` 非 root `1000:1000`、`cap_drop: [ALL]`、`read_only: true`、无 `docker.sock`、无未认证 HTTP 端点；HMAC-SHA256 + ±60s + 120s Nonce 防重放；`HASYNC_SECRET_FILE` 缺失或不足 32 字节 hex 启动失败闭环；
- 联动只动带本组件标记的口，绝不 down 管理口或已配 IP 的口；VIP 接口禁止为网桥成员口；
- VRRP 认证串、TLS 证书私钥、`tls_session_ticket_key`、`sync_secret`：一律加密落库、接口永不回显明文、快照/预览强制 Redact 脱敏、禁入日志；
- 备机离线升级包固定信任根 Ed25519 验签仍由备机宿主机 `upgrade-executor.sh` 独立执行，管理面不可绕过；
- fail-closed 原则：契约文件解析失败保留 last-good 并显式报错；Keepalived 缺失不 crash-loop；权限/CSRF/审计不可绕过。

## 11. 风险与边界（如实声明）

- Keepalived 为系统包依赖（Docker 镜像内已内置并锁定基础镜像 digest；裸机部署须预装 Keepalived）；容器化运行需 `NET_ADMIN`/`NET_RAW`/`NET_BROADCAST`，生产推荐裸机或受控容器部署；
- 在途 TCP 长连接切换即断（§7.3），不做 conntrack 连接镜像；
- 共享 Valkey 为判定态单点（故障时 Fail-open 降级，不中断转发）；
- 端口联动依赖物理网卡/光模块 carrier 语义正确，交付前须在目标物理链路复测；
- 目标 Linux 宿主机真实安装、双机升级、回滚与外部客户端访问仍为正式发版前必做实机门槛（单测/harness 不可替代，遵循 `docs/tasks/UPGRADE_INCIDENT_2026-11-17.md`）。
