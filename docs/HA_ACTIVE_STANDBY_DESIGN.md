# 主备高可用（VIP 漂移 + 网桥端口联动 + 会话保持）设计

> 状态：**M1/M2 已落地并实测通过，M3 落地中**（2026-08-28；各里程碑实测记录见 §13 与文末实施注记）
> 关联文档：
> - `docs/HA_TWO_NODE_DESIGN.md`（双节点 Active-Active 方案，本文为其并列形态而非替代）
> - `docs/NETWORK_MODES_DESIGN.md`（多网口管理与透明串接/路由牵引/镜像模式）
> - `docs/BARE_METAL_GATEWAY_DESIGN.md`（裸机网关部署）
> 关联代码：`gateway/netmgrd`（宿主机网络执行末端，含端口联动）、`gateway/havipd`（VIP 执行末端）、`gateway/modules/jiuzhang_guard/stek`（静态 STEK）、`server/internal/apinodes`（节点登记/扇出/一致性）、`server/internal/hagroups`（主备组管理）、`server/internal/gatewayconfig`（发布构建）

---

## 1. 背景与目标

现有 HA 方案（`HA_TWO_NODE_DESIGN.md`）的转发面前提是**前置负载均衡**（云 LB / 硬件 LB / DNS），流量双活分摊。目标客户环境中存在另一类典型部署：

- **无前置 LB**，上游为防火墙或交换机，靠**链路通断**决定流量走 A 链路还是 B 链路；
- WAF/WDSP 以**透明网桥串接**在链路中，两台设备做主备（Active-Standby）；
- 管理入口走 **VIP**，VIP 平时在主节点，主故障时漂移到备节点；
- 网桥任一成员口链路故障时，必须**把配对口也 down 掉**——否则上游看到本链路仍然"通"，不会切换，流量黑洞。

本文定义该形态的产品化设计，全部能力**页面可配置**。目标：

1. **主备 VIP**：页面指定虚拟 IP、主备角色（优先级）、抢占策略；VIP 漂移状态进节点视图与告警。
2. **端口联动（Link-Pair）**：网桥成员口掉 carrier → 配对口联动 set down；故障恢复 → 配对口回 up；防抖防震荡。
3. **会话保持**：链路/VIP 切换后，终端用户**不需要重新登录**，管理控制台会话不中断；各层会话语义见 §7 如实声明。
4. **配置单点**：沿用发布扇出铁律——只在管理面配置，同一构建产物全节点一致下发，主备配置漂移由一致性视图兜底。

## 2. 术语

| 术语 | 含义 |
|---|---|
| 主备组（HA Group） | 两台网关节点组成的 Active-Standby 对，共享一个或多个 VIP |
| VIP | 虚拟 IP，经 VRRP（keepalived）在主备节点间漂移 |
| Link-Pair（端口联动对） | 网桥的两个成员口互为配对：一方链路故障，另一方被本组件 administratively down；故障恢复后回 up |
| carrier | 网卡链路层载波状态（`/sys/class/net/<if>/carrier` 或 `ip link` 的 LOWER_UP 标志） |
| 联动标记 | netmgrd 记录"该口是被本组件联动 down 的"事实，恢复判定的唯一依据（防误动运维手工操作） |
| 切换 | 上游设备感知链路中断/VRRP 通告后，流量改走备链路的过程（上游行为，非本系统动作） |

## 3. 需求范围

### 3.1 功能需求（FR）

| 编号 | 需求 |
|---|---|
| FR-1 | 页面创建/编辑/删除主备组：成员节点（2 台，须为已登记网关节点）、VIP 列表、VRID、各节点优先级、抢占开关 |
| FR-2 | 页面为网桥开启 Link-Pair：hold_down / hold_up 防抖参数可配（带默认值与合法区间） |
| FR-3 | netmgrd 监控成员口 carrier，按状态机执行联动 down/up，状态与最近事件回写并上报管理面 |
| FR-4 | keepalived 封装组件（havipd）按下发配置生成配置、启停 keepalived、采集 MASTER/BACKUP/FAULT 状态与漂移事件 |
| FR-5 | 管理面汇聚主备状态页：当前 MASTER 节点、VIP 在位状态、联动状态、漂移/联动历史、一致性告警 |
| FR-6 | TLS 会话票据密钥材料（反向代理终结 TLS 场景）经发布通道加密下发，全节点一致、可轮换 |
| FR-7 | 全部配置动作走操作审计（高危）；权限点 `ha.read` / `ha.manage`，归安全管理员角色 |

### 3.2 非功能需求（NFR）

- VIP 漂移时间：主节点整机断电场景 ≤ 5s（keepalived 默认 advert 1s × 3 + 收敛余量）；
- 端口联动反应时间：carrier 丢失 → 配对口 down ≤ 3s（轮询 500ms + hold_down 默认 1s + 执行余量）；
- 防抖：链路抖动（1s 内反复 up/down）不得引起配对口震荡；连续联动频率超限进入抑制并告警；
- 切换期间已建立 TCP 连接**会断开**（如实声明，见 §7.3），客户端自动重连，HTTP 短连接成功率 ≥ 99%（重试一次语义）。

### 3.3 明确不做（边界）

- **TCP 连接镜像/状态同步**（conntrack 同步、会话表同步）：不做。行业同级串联产品同样不做；代价是切换时在途长连接断一次（§7.3）。
- 跨地域多活、三层以上集群、网关间状态 gossip：不做（与 HA_TWO_NODE 一致）。
- QUIC/HTTP3 连接迁移：不做。
- 备节点**业务流量预热**：不做（备节点平时不承载业务流量，仅心跳/采集）。

## 4. 总体架构

```text
            上游防火墙/交换机（按链路通断选路：默认链路1，断→链路2）
              │ 链路1                     │ 链路2
        ┌─────┴─────┐              ┌─────┴─────┐
        │ eth2  eth3│              │ eth2  eth3│   ← Link-Pair：一口断→对口联动down
        │ [  br0   ]│              │ [  br0   ]│
        │  网关A 主  │              │  网关B 备  │
        │ tproxyd/  │              │ tproxyd/  │
        │  caddy    │              │  caddy    │
        │ netmgrd   │              │ netmgrd   │   ← 网桥/联动执行末端（既有扩展）
        │ havipd    │◄── VRRP ────►│ havipd    │   ← VIP：默认在A，A故障漂移到B
        └─────┬─────┘              └─────┬─────┘
              └──────► 共享 Valkey ◄─────┘        （CC/行为/判定态/管理会话：既有）
                        │
              管理面 api + PostgreSQL 主库          （配置唯一权威：既有）
```

- **转发面**：A 承载全部业务流量；B 链路因 A 的 Link-Pair 全口 up 且上游选路规则而不承载流量（B 自身口均 up，等待上游切换）；B 进程全量运行（检测配置一致），仅无流量。
- **管理入口 VIP**：运维/浏览器访问 VIP → 落在 MASTER 所在节点的管理面；VIP 漂移后管理会话不中断（§7.4）。
- **配置面**：不变——管理面构建一次，发布扇出全节点 `/load` + 哈希比对（既有），本设计新增的配置项全部纳入同一发布通道。

## 5. 关键设计决策

| 编号 | 决策 | 理由 / 备选 |
|---|---|---|
| D-1 | VIP 用 **keepalived 封装**（生成配置 + 启停 + 状态采集），不自研 VRRP | VRRP 的正确性细节（garp、抢占、脑裂、组播/单播协商）自研风险高；keepalived 成熟且被同形态产品广泛采用。备选（自研轻量 VRRP）记录为不采纳及原因 |
| D-2 | Link-Pair 在 **netmgrd 扩展**实现，不新增宿主机组件 | netmgrd 已是"宿主机网络执行末端"，同一契约通道（network.json / network-status.json）、同一安全红线（`ip` 命令数组执行、5s 超时、幂等）；联动本质是网桥成员口管理的延伸 |
| D-3 | keepalived 封装为**新 sidecar `gateway/havipd/`**（独立进程，与 netmgrd 同级） | keepalived 是长驻守护进程的生命周期管理，与 netmgrd 的"幂等执行 + 轮询重试"语义不同；独立进程故障域隔离，互不影响 |
| D-4 | 主备差异化配置（优先级等）**不走 nodepatch**，由发布构建产出统一的 `members[]` 数组，havipd 按本机 `gateway_node` 名自选条目 | 保持"同一构建产物全节点一致"的扇出铁律；nodepatch 保持单一职责（节点身份/心跳） |
| D-5 | TLS 会话票据密钥经**发布通道下发**（随证书同级加密），不做节点间运行时同步 | 发布通道已有密钥分发能力（脱敏密钥/身份盐同通道）；运行时 gossip 超出边界 |
| D-6 | 联动恢复采用**保守策略**：只恢复带本组件联动标记的口；组件重启后标记以 status 文件为准 | 防误动运维手工 down 的口；重启场景对齐规则见 §6.5 |
| D-7 | 抢占默认 `nopreempt`（不自动回切） | 主节点恢复后不抢 VIP，避免二次闪断；回切为人工动作（页面按钮）。可配置 |

## 6. 端口联动（Link-Pair）详细设计

### 6.1 配置契约（network.json 扩展）

netmgrd 既有输入契约向后兼容扩展（`bridges[]` 元素新增可选 `link_pair` 字段；缺省 = 不启用，行为与现状完全一致）：

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

- `link_pair` 仅允许出现在**恰好 2 个成员口**的桥上（联动语义就是成对）；配置校验拒绝其他成员数；
- `hold_down_ms`：carrier 持续丢失达到该时长才认定故障（默认 1000，合法区间 [200, 10000]）；
- `hold_up_ms`：carrier 恢复达到该时长才回 up（默认 5000，区间 [1000, 60000]）；
- `max_flaps_per_hour`：单口每小时联动次数上限，超限进入**抑制态**（保持当前状态不再动作）并上报告警（默认 20，区间 [1, 200]；0 = 不限制，不推荐）。

### 6.2 状态回写（network-status.json 扩展）

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

管理面采集链路复用既有节点状态通道（与 network-status.json 同机制），无需新增上报协议。

### 6.3 监控与执行状态机

每座启用 Link-Pair 的桥一个独立状态机（netmgrd 监控循环，500ms 轮询成员口 carrier）：

```text
BOTH_UP ──任一口 carrier 丢失持续 hold_down──► PROPAGATED_DOWN
                                                  │  （配对口 set down + 打联动标记 + 回写 + 告警）
PROPAGATED_DOWN ──故障口 carrier 恢复持续 hold_up──► BOTH_UP
                                                  │  （配对口 set up + 清联动标记 + 回写）
任意态 ── flap 超限 ──► SUPPRESSED（冻结动作 + 告警；页面可人工复位）
```

执行语义（沿用 netmgrd 安全红线）：

- 动作仅 `ip link set dev <if> down|up`（exec 参数数组，不经 shell，5s 超时），幂等（先读现状，已是目标态则跳过）；
- **联动标记**：执行联动 down 时记录 `propagated_by_linkpair=true`（内存 + status 文件双写）；只有带标记的口才允许被本组件回 up——运维手工 down 的口本组件绝不动；
- **故障中再故障**：PROPAGATED_DOWN 期间另一口也掉 carrier（双口全断）→ 保持状态、如实回写；任一口先恢复且过 hold_up → 回 BOTH_UP 流程（配对口 up），另一口继续按独立口监控；
- 监控循环崩溃不影响已执行状态；netmgrd 进程重启后按 §6.5 对齐。

### 6.4 与进程级 fail-open 的关系（关键区分，必须如实呈现）

| 故障 | 行为 | 上游视角 | 依据 |
|---|---|---|---|
| 网口 carrier 丢失（拔线/对端 down/网卡故障） | **Link-Pair 联动 down 配对口**，链路呈现中断 | 检测到链路断 → 切换到备链路（备链路上检测能力完整） | 本设计 §6 |
| WAF 数据面进程死亡（tproxyd/caddy 崩溃） | **fail-open 直通**：看门狗清规则，桥接转发保持 | 链路仍通，流量未被检测地通过（短暂，进程拉起即恢复） | 既有（NETWORK_MODES_DESIGN §4.3，已实测） |

两种语义不冲突：口坏 → 让上游切走（因为本路径已残缺）；进程坏 → 保持链路（因为很快自愈，切换代价更大）。两者可叠加：进程 fail-open 期间若网口也坏，Link-Pair 照常联动。

### 6.5 netmgrd 重启对齐规则（保守）

重启后读取 status 文件恢复联动标记：

- 一口 up 一口 down 且 down 口有联动标记 → 继续按状态机走（等故障口恢复后回 up）；
- 一口 up 一口 down 且**无**联动标记（运维手工操作或标记丢失）→ **不动**，回写 `message` 并上报告警（等待人工处置；提供页面"对齐为双 up"按钮，属运维确认动作）；
- 双口 down 且有标记 → 保持监控；任一口 carrier 恢复 → 先 up 该口，另一口按 hold_up 判定后回 up。

## 7. 会话保持（会话同步）设计

用户核心关切：链路/VIP 切换后"会话都没了、用户要重新登录"。先分层拆解"会话"，再逐层给出机制与结论。

### 7.1 会话分层模型与切换语义

| 层 | 状态持有方 | 切换影响 | 同步机制 | 结论 |
|---|---|---|---|---|
| 应用会话（业务登录态） | 客户端 cookie/token + 源站会话存储 | **无影响**——WAF 不持有业务登录态，cookie 随请求走，源站不感知路径变化 | 无需同步 | **用户不需要重新登录** |
| WAF 判定态（CC 计数/临时封禁/行为滑窗/身份指纹） | 共享 Valkey | 无影响——备节点接管后判定语义连续 | 既有：`counter_backend=valkey` + `gateway_runtime.behavior_store=valkey`（HA_TWO_NODE 已交付；部署红线：必须显式置 valkey） | 已交付 |
| 模型/策略/学习产物 | PostgreSQL 单库 | 无影响 | 既有（单权威源） | 已交付 |
| TLS 会话（反代模式 WAF 终结 TLS） | WAF 实例内存（票据密钥） | 票据密钥不一致 → 会话恢复失败 → **回退完整握手**（多 1-RTT 与计算开销，**不掉登录态**） | 本设计 §7.2：票据密钥材料经发布通道下发，全节点一致 | 需新增 |
| TLS 会话（桥接透传模式） | 端到端（客户端↔源站） | 无影响——WAF 不终结 TLS | 无需同步 | 天然保持 |
| TCP 连接（在途长连接） | 端到端内核态 | **切换即断**（路径变了，五元组无法在新路径延续） | 不做连接镜像（§3.3） | 如实声明，见 §7.3 |
| 管理控制台会话 | 共享 Valkey（既有会话存储） | 无影响——VIP 漂移后浏览器带原 cookie 访问同一 VIP，会话仍在 | 既有 | 管理员不需要重新登录 |

### 7.2 TLS 会话票据密钥下发（FR-6）

- **问题**：Caddy/certmagic 默认会话票据密钥为实例内存生成、周期轮换，双节点不一致；主备切换后客户端 TLS session resumption 必然失败，回退完整握手。
- **方案**：发布构建时将**票据密钥材料**（32 字节随机串，按版本可轮换）作为一级配置项纳入发布产物，经既有密钥分发通道（与脱敏密钥/身份盐同通道，加密落库、Redact 脱敏）下发至全部节点；网关 TLS 装配以该材料初始化会话票据。
- **轮换**：随发布版本轮换（每次发布生成新材料）；同一版本内全节点一致。旧票据在轮换后失效 = 一次全握手，可接受。
- **验证任务（lab 必做）**：`openssl s_client -sess_out/-sess_in` 实测跨节点票据恢复成功率；若 Caddy 侧不支持外部票据密钥注入，降级方案为关闭会话票据了解耦为"切换后一次全握手"，并如实记录该降级（影响仅为性能，无登录态损失）。
- **注意**：票据密钥属高敏材料，复用既有加密落库与审计纪律；禁止写入日志。

### 7.3 TCP 在途连接：如实声明

- 切换瞬间在途 TCP 连接**必然中断**（RST 或超时，取决于上游切路实现）；HTTP/1.1 短连接由客户端/浏览器自动重试，用户无感；WebSocket、SSE、长轮询、大文件上传等**长连接会断一次**，依赖客户端重连逻辑。
- 这是所有不做到连接镜像的串联/主备产品的共同边界（含主流硬件 WAF），本文如实声明，不夸大。
- 缓解：上游设备支持"链路切换仅对新连接生效、旧连接自然老化"时，闪断面更小——属上游能力，本系统不依赖。

### 7.4 结论（对用户的直接回答）

- **终端用户不需要重新登录**：业务登录态在 cookie/源站，路径切换不触碰；
- **管理员不需要重新登录**：控制台会话在共享 Valkey，VIP 漂移无感；
- **防护判定连续**：CC/封禁/行为状态共享，备节点接管语义一致；
- **唯一新增工作**：TLS 会话票据密钥一致下发（反代终结场景的性能优化项，非登录态项）；
- **如实边界**：在途长连接断一次重连（§7.3）。

## 8. VIP 与主备管理设计

### 8.1 havipd（gateway/havipd/）

宿主机 sidecar（与 netmgrd 同级、同部署形态），职责：

1. 读契约文件 `ha-vip.json`（发布链路写入，默认 `/var/run/caddy/sidecars/ha-vip.json`）；
2. 生成 keepalived 配置（VRRP instance per VIP），启停/reload keepalived（exec 参数数组、不经 shell、5s 超时；零新增 Go 依赖）；
3. 周期采集 keepalived 状态（MASTER/BACKUP/FAULT，经 notify 脚本或 vrrp track 状态文件），回写 `ha-vip-status.json`；
4. 漂移事件（BACKUP→MASTER / MASTER→BACKUP/FAULT）记录并上报（复用节点状态通道 → 管理面告警 + 历史）。

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
    "auth_pass_ref": "ha-group-ha-main"
  },
  "updated_at": "..."
}
```

- havipd 按本机 `gateway_node` 名在 `members[]` 中定位本机优先级（D-4）；
- `auth_pass_ref` 引用发布通道下发的 VRRP 认证串（与票据密钥同纪律：加密落库、脱敏、禁日志）；
- keepalived 未安装/版本不兼容 → status 显式报错 + 告警，不 crash-loop（同 netmgrd 纪律）；
- 支持单播 VRRP（云上禁组播环境）：`unicast_peers` 由 members 的节点地址生成（节点地址取节点登记信息）。

### 8.2 脑裂抑制

- 默认 `nopreempt`（D-7）：备升主后，原主恢复不抢 VIP，消除回切闪断与反复漂移；
- VRRP 通告链路与管理/采集链路建议不同网段（部署清单注明）；
- keepalived `track_interface` 绑定承载网桥成员口：本机桥口全 down 时主动降优先级让位（双机都坏时维持现状 + 告警，不制造第三次抖动）；
- 双 MASTER 出现（脑裂）→ 两侧均上报告警（havipd 检测到对端 garp 与自身 MASTER 冲突），页面红条提示人工处置。

### 8.3 数据模型（迁移草案，编号待分配）

```sql
-- 主备组
CREATE TABLE ha_groups (
  id uuid PRIMARY KEY,
  name text NOT NULL UNIQUE,
  state text NOT NULL DEFAULT 'ENABLED',      -- ENABLED/DISABLED
  vrid int NOT NULL,
  iface text NOT NULL,                         -- VIP 承载网卡（管理/业务口，校验不得为桥成员口）
  vips jsonb NOT NULL,                         -- ["192.168.31.100/24"]
  preempt boolean NOT NULL DEFAULT false,
  advert_int_ms int NOT NULL DEFAULT 1000,
  unicast boolean NOT NULL DEFAULT false,
  auth_ciphertext text,                        -- VRRP 认证串（加密落库）
  created_by uuid, created_at timestamptz, updated_at timestamptz, version int
);
-- 组成员（恰 2 行；priority 决定主备倾向）
CREATE TABLE ha_group_members (
  group_id uuid REFERENCES ha_groups(id) ON DELETE CASCADE,
  node_id uuid REFERENCES api_gateway_nodes(id),
  priority int NOT NULL,
  PRIMARY KEY (group_id, node_id)
);
-- 漂移/联动历史（页面时间线 + 审计旁证）
CREATE TABLE ha_events (
  id bigserial PRIMARY KEY,
  group_id uuid, node_name text,
  event_type text NOT NULL,     -- VIP_MASTER/VIP_BACKUP/VIP_FAULT/LINKPAIR_DOWN/LINKPAIR_UP/LINKPAIR_SUPPRESSED/SPLIT_BRAIN
  detail jsonb,
  occurred_at timestamptz NOT NULL DEFAULT now()
);
```

Link-Pair 配置不进新表：挂在既有网桥配置（站点/节点网络配置）上，随 network.json 下发（§6.1），保持单一契约。

### 8.4 API 设计（草案，OpenAPI 片段后补）

| 方法与路径 | 权限 | 说明 |
|---|---|---|
| `GET /api/v1/ha/groups` | `ha.read` | 主备组列表（含成员/状态摘要） |
| `POST /api/v1/ha/groups` | `ha.manage` | 创建（参数校验：VRID 1-255、VIP CIDR、成员恰 2 且为已登记节点、优先级 1-254 且不重复） |
| `GET /api/v1/ha/groups/{id}` | `ha.read` | 详情 + 实时状态（MASTER 节点/VIP 在位/联动态） |
| `PATCH /api/v1/ha/groups/{id}` | `ha.manage` | 改优先级/抢占/VIP/启停；生效走整站发布 |
| `DELETE /api/v1/ha/groups/{id}` | `ha.manage` | 删除（先 DISABLED 发布收敛，再删；二次确认） |
| `POST /api/v1/ha/groups/{id}/failback` | `ha.manage` | 人工回切（nopreempt 下把 VIP 切回指定节点；临时提优先级 + 发布） |
| `POST /api/v1/ha/groups/{id}/link-pairs/{bridge}/reset-suppression` | `ha.manage` | 解除联动抑制态 |
| `GET /api/v1/ha/events` | `ha.read` | 漂移/联动历史（分页过滤） |

全部写操作：CSRF + 参数校验 + 操作审计（高危）+ 经整站发布生效（复用幂等键纪律）。

### 8.5 页面设计

- 新一级菜单「系统管理 → HA 主备」（或并入「节点校验」页签，由前端按信息架构定）：
  - 组卡片：VIP、当前 MASTER（实时）、两节点优先级/心跳/版本一致性、联动状态徽标；
  - 配置表单：VIP/VRID/优先级/抢占/单播开关；网桥 Link-Pair 开关与防抖参数（挂在网桥配置表单内）；
  - 时间线：漂移与联动事件（来自 `ha_events`）；
  - 危险动作二次确认：删除组、人工回切、解除抑制。

## 9. 发布/下发流程

1. 页面改 HA 配置 → 落库（§8.3）→ 触发/等待整站发布（既有幂等键纪律）；
2. 发布构建：在既有产物基础上生成 `network.json`（含 link_pair，§6.1）与 `ha-vip.json`（§8.1），敏感材料（VRRP 认证串/TLS 票据密钥）经密钥通道注入；
3. 扇出全节点 `/load` + sidecar 契约文件落共享卷；netmgrd/havipd 各自幂等执行并回写状态；
4. 一致性视图扩展：`/nodes/consistency` 纳入 ha-vip/network 契约版本哈希；执行失败/状态异常 → 既有告警通道。

## 10. 故障场景矩阵

| 场景 | 预期行为 | 恢复 |
|---|---|---|
| 主节点单个桥口掉 carrier | Link-Pair down 对口（≤3s）→ 上游切备链路；业务连续（备节点同配置接管）；在途长连接断一次 | 插回线 → hold_up 后对口回 up；nopreempt 不抢 VIP；人工 failback 回切 |
| 主节点整机断电 | keepalived 收不到通告 → VIP ≤5s 漂移到备；上游因链路断电早已切走 | 开机 → BACKUP 待命；配置经一致性视图核对，必要时重发 |
| 备节点掉电 | 无业务影响；心跳 STALE/SILENT 告警 | 开机 → 心跳恢复，断点续采追平 |
| 主节点 WAF 进程崩溃 | fail-open 直通（链路不断，上游不切）；进程拉起即恢复检测 | 既有 watchdog |
| 网口抖动（反复 up/down） | hold_down/hold_up 防抖；超 max_flaps → SUPPRESSED 冻结 + 告警 | 页面复位或人工处置 |
| 管理面 api 宕机 | 网关按最近发布配置继续运行；VIP/联动为宿主机自治，不受影响 | api 恢复后状态追平 |
| VRRP 脑裂（双 MASTER） | 双侧告警；业务因上游只选一条链路而不至于双写分歧 | 人工按页面提示处置 |
| Valkey 宕机 | CC/行为 Fail-open 降级（既有语义）；转发不中断 | Valkey 恢复后计数重建 |

## 11. 安全红线（不可放宽）

- netmgrd/havipd 全部动作 exec 参数数组执行（不经 shell）、单动作 5s 超时、零新增第三方依赖（keepalived 为系统包，非 Go 依赖）；
- 联动只动**带本组件标记**的口；任何时刻不得 down 管理口/已配 IP 的口（沿用收入桥红线同款校验：口上存在 inet 地址即拒绝联动）；
- VIP 接口校验：不得为任何网桥成员口；VRID/网段冲突校验；
- VRRP 认证串、TLS 票据密钥：加密落库、Redact 脱敏、禁日志、随发布轮换；
- 全部页面写操作：CSRF + 权限点 + 参数校验 + 操作审计（高危）；配置生效必经发布通道，禁止旁路直写节点；
- fail-closed 原则：契约文件解析失败保留 last-good 并显式报错；keepalived 缺失不 crash-loop。

## 12. 验证方案（全部可自动化；新建 `deployment/ha-standby-lab/`）

lab 形态：双网关节点（容器）+ keepalived（容器内 cap NET_ADMIN）+ veth 对模拟桥口（`ip link set down` 模拟 carrier 丢失）+ 客户端容器持续打流。

| 编号 | 场景 | 断言 |
|---|---|---|
| V1 | 页面创建主备组并发布 | 两节点 ha-vip.json 一致；havipd 状态 A=MASTER B=BACKUP；VIP 仅在 A 可 ping |
| V2 | `ip link set eth2 down`（主节点桥口） | ≤3s 内 eth3 被联动 down；network-status.json 状态 PROPAGATED_DOWN；ha_events 有 LINKPAIR_DOWN；上游模拟器切链路后 HTTP 200 恢复 |
| V3 | 会话保持 | 切换前建立的应用 cookie 会话切换后原样可用（无需重新登录）；管理控制台会话保持；CC 计数在备节点连续（切换前 60 + 切换后 50 > 阈值 100 触发限速） |
| V4 | TLS 票据 | `openssl s_client` 在 A 取票据 → B 上恢复成功（或如实记录降级为全握手） |
| V5 | 主节点断电（`docker stop`） | VIP ≤5s 漂移到 B；管理面 VIP 访问连续；ha_events 有 VIP_MASTER(B) |
| V6 | 抖动 | 口 1s 内 10 次 up/down → 配对口不震荡；超限进 SUPPRESSED + 告警 |
| V7 | 恢复与回切 | 故障口恢复 → hold_up 后双 up；nopreempt 下 VIP 不动；人工 failback 后 VIP 回 A |
| V8 | 一致性 | 手工改 B 节点 keepalived 配置 → 一致性告警 + 重发恢复 |
| V9 | 重启对齐 | 联动态中重启 netmgrd → 标记恢复，不误动无标记口 |
| V10 | 长连接边界 | WebSocket 在切换时断一次并自动重连（如实记录为预期行为） |

## 13. 分阶段实施

| 阶段 | 内容 | 验收 |
|---|---|---|
| M1 | Link-Pair：netmgrd 扩展（监控/状态机/回写/防抖/抑制）+ network.json 契约 + 页面开关 + 审计 | V2/V6/V9 通过；单测覆盖状态机全迁移 |
| M2 | havipd + keepalived 封装 + ha_groups 数据模型 + API + 页面 + 漂移历史 | V1/V5/V7/V8 通过 |
| M3 | TLS 票据密钥下发 + 会话保持整体验证 | V3/V4/V10 通过；降级与否如实记录 |
| M4 | 文档（部署清单/运维手册/交付检查项）+ 告警接入通知渠道 | ha-standby-lab 全场景自动化通过 |

## 14. 风险与边界（如实声明）

- keepalived 引入系统包依赖（版本兼容矩阵需维护；容器内运行需 NET_ADMIN，裸机/虚拟机为推荐形态）；
- 在途 TCP 连接切换即断（§7.3），对长连接重业务（实时推送/大文件传输）影响需对客户如实说明；
- 共享 Valkey 仍是判定态单点（Fail-open 兜底，同 HA_TWO_NODE 边界）；
- 端口联动依赖 carrier 语义正确：个别网卡驱动/光模块 carrier 误报需在物理环境复测（与 NETWORK_MODES_DESIGN 已记录的"与现网 STP/环路共处留待物理环境复测"同级）；
- 上游设备的链路切换策略（是否仅新连接切换、切换阈值）非本系统可控，部署清单需明确联调项；
- 双管理面 api 形态下的发布单点纪律沿用 HA_TWO_NODE §4 已知边界。

## 15. 实施注记（2026-08-28，对设计决策的实测修正）

- **M1（Link-Pair）已落地**：netmgrd 扩展（监控/状态机/防抖/抑制/联动标记/重启对齐）+ 服务端 netconfig 校验下发 + 网络配置页开关与状态表。实测：netmgr-lab 59/59（真实 veth carrier 断/通、抑制与复位）。决策修正：抑制复位除「期望指纹变化」外补充「重新保存配置（updated_at 版本戳变化）即复位」语义，使页面原样保存即可复位（§6 的复位通道按此执行，`reset-suppression` 专用按钮不再单列）。
- **M2（主备 VIP）已落地**：`gateway/havipd`（keepalived 封装/状态采集/漂移事件）+ `ha_groups`/`ha_group_members`（迁移 000080）+ `ha.*` 权限点 + REST 接口（含人工回切）+「系统运维 → HA 主备」页。实测：havip-lab 31/31（真实 keepalived 全生命周期）。lab 抓出并已修复 4 个实现缺陷：VIP 掩码误归一化、僵尸进程误判存活、PID 复用误信号（加 /proc comm 校验）、停机竞态（停止改同步语义）。
- **M3 轮换语义修正**（对 §7.2）：票据密钥材料**不按发布版本轮换**（每次发布会话全部失效代价过大），改为 `gateway_runtime:tls_session_ticket_key` 设置项持久化（与 identity_salt 同通道同纪律：加密落库/快照 Redact/非法值中止发布），轮换=运维更换设置值（可带新旧两键平滑过渡，tls.stek.jiuzhang 支持 keys_hex 多键，首键加密、余键解密兼容）。未配置该键时保持 Go 进程内随机键缺省（跨节点回退全握手，§7.2 降级语义不变）。
- **STEK 实现**：自研 `tls.stek.jiuzhang` 静态 provider（`gateway/modules/jiuzhang_guard/stek`），`apps.tls.session_tickets.key_source` 注入；Caddy 侧无内置静态 STEK provider（`standard`=进程内随机、`distributed`=需共享存储插件，均不适用双节点主备），调研结论与选型见 §7.2 与实施记录。
- **M2 边界（如实）**：双节点状态汇聚与 `ha_events` 表待采集通道落地（当前 ha-vip-status.json 边车透传仅本节点卷）；keepalived 容器运行需 NET_ADMIN，裸机/虚拟机为推荐形态。
