# 主备高可用部署与运维手册（HA Active-Standby & Two-Node Sync）

> 适用：九章 WDSP / WAF 双机高可用全栈能力——
> 跨机配置/证书（`load_pem`）/边车/防火墙同步（`hasyncd`）、网桥端口联动（Link-Pair）、主备 VIP（`havipd`/Keepalived + `track_interface`）、2 键平滑轮换 TLS 会话票据、多节点状态与脑裂告警（`HA_SPLIT_BRAIN`）、持久化事件时间线（`ha_events`）与先备后主双机滚动升级（`HA_ROLLING`）。
> 读者：交付工程师与现场运维。设计原理与架构边界见 `docs/HA_ACTIVE_STANDBY_DESIGN.md` 与 `docs/HA_TWO_NODE_DESIGN.md`。

---

## 1. 部署清单（双机生产最小落地）

### 1.1 前置条件

| 项 | 要求 |
|---|---|
| 网关节点 | 两台同版本镜像（digest 锁定）或同版本裸机主机，各自配置唯一 `GATEWAY_NODE_NAME`（如 `gw-a` / `gw-b`） |
| 网卡 | 透明串接每节点至少 2 个业务口（成对进桥，**不得预配 IP**）+ 1 个管理口（承载管理访问、VRRP 与 `hasyncd` 协同流量） |
| 上游设备 | 透明串接场景由防火墙/交换机按链路通断选路；Active-Active 场景由前置 LB 健康检查 `/health` |
| 基础设施 | 共享 PostgreSQL 主库、共享 Valkey（计数/行为/管理会话；**必须**显式置 `behavior_store=valkey`） |
| `havipd` 与 Keepalived | Docker 形态已随离线包内置 `jiuzhang-havipd` 镜像（默认启用，无 `ha-vip.json` 时静默待命，`cap_add: [NET_ADMIN, NET_RAW, NET_BROADCAST]`、`read_only: true`、`group_add: ["1000"]`）；裸机形态需宿主机安装 `keepalived` 与 `iproute2` 并运行 `jiuzhang-havipd.service` |
| `hasyncd` 协同代理 | Docker 形态通过 `--profile ha-sync` 在备节点启用（非 root `1000:1000`、`cap_drop: [ALL]`、`read_only: true`）；裸机形态在创建密钥文件后启用 `jiuzhang-hasyncd.service`（`ConditionPathExists` 保护，单机默认不启） |

### 1.2 部署步骤

1. **初始化 `hasyncd` 共享密钥与 TLS（备节点）**：
   - 生成 32 字节随机 hex 密钥并设权限 `0600`（属主 `1000:1000`）：
     ```bash
     openssl rand -hex 32 > /opt/jiuzhang/data/runtime/hasync.secret
     chmod 600 /opt/jiuzhang/data/runtime/hasync.secret
     ```
   - 生产环境建议为 `hasyncd` 配置内网管理口 TLS 证书（`--tls-cert` / `--tls-key`），并将监听地址绑定到管理网卡内网 IP（如 `10.10.0.2:18443`），防火墙仅放行主节点管理 IP 访问该端口。
   - 确认备节点 `hasyncd` 健康探针通过：`hasyncd --healthcheck` 退出码为 `0`（仅读本地健康戳，无未认证 HTTP 端点）。
2. **启动两台网关节点**：
   - 主节点 `GATEWAY_NODE_NAME=gw-a`，备节点 `GATEWAY_NODE_NAME=gw-b`（环境变量直接覆盖，不再需要 `nodepatch`）。
   - 确认 `havipd --healthcheck` 在双节点均返回退出码 `0`（校验 `ha-vip-status.json` 30s 内新鲜且 JSON 合法）。
3. **节点登记与连通测试（纯 WAF 与 WDSP 均可用）**：
   - 进入「API 防护 → 节点校验」，点击「新增节点」（或编辑已发现节点）登记备节点 `gw-b`：
     - `sync_agent_addr`：`https://<备节点管理IP>:18443`（内网隔离带外网段可用 `http://`，会有安全日志提醒）
     - `sync_secret`：填入步骤 1 生成的 64 位 hex 密钥（加密落库，保存后仅显示「已配置」永不回显）
     - 开启 `sync_enabled`
   - 点击行内「连通测试」确认 `ok=true`、`caddy_reachable=true`、`hostctl_ready=true`、`upgrade_ready=true` 且返回远端版本号。
4. **共享状态与 TLS 会话票据**：
   - 系统设置 `gateway_runtime` 组配置：
     - `behavior_store = valkey`（主备切换 CC/行为判定连续的前提）
     - `identity_salt`（身份指纹盐，随发布双机一致下发）
     - `tls_session_ticket_key`（64 位 hex，`openssl rand -hex 32` 生成；平滑轮换时可填 `新密钥,旧密钥` 两键）
   - 触发一次整站发布，确认主备节点均 `SUCCESS`（含 HTTPS 站点的 `load_pem` 证书、边车与备机防火墙端口均自动同步）且「节点校验」一致性为 `consistent=true`。
5. **网桥与端口联动（支持直接配置备节点）**：
   - 进入「系统运维 → 网络配置」，先配置主节点 `gw-a` 网桥（成员口恰 2 个）并开启「端口联动」（默认 `hold_down=1000ms`、`hold_up=5000ms`、`max_flaps=20/h`）保存；
   - 切换节点下拉框至已启用同步的备节点 `gw-b`（`remote_editable=true` 自动解锁编辑，自动加载备机遥测网口清单），配置同等网桥与联动规则并保存下发至备机 `hasyncd`。
6. **主备组（VIP 漂移 + `track_interfaces`）**：
   - 进入「系统运维 → HA 主备」新建主备组：
     - VIP：IPv4 CIDR（如 `192.168.31.100/24`）
     - VRID：`1~255`（同二层域唯一）
     - `advert_int_ms`：`1000~10000` 且为 `1000` 整数倍（整秒）
     - 承载网卡 `iface`：非网桥成员口（如管理/业务口 `eth0`）
     - `track_interfaces`：勾选关联的网桥成员口（如 `eth2`、`eth3`，不得与 `iface` 相同）
     - 成员节点：恰 2 个（单节点同一时间仅可加入一个主备组），高优先级为主，默认关闭抢占（`nopreempt`）
     - 可选 VRRP 认证串：1~8 位安全字符（`A-Za-z0-9._:@+-`）
   - 保存后查看返回的逐节点 `sync_results`，确认主备双机均已收到 `ha-vip.json`（权限 `0640`）。
7. **验证**：按 §4 交付检查项逐项验证。

### 1.3 上线前红线核对

- [ ] `ha-vip.json` 权限 `0640`、目录 `0770`、`keepalived.conf` 权限 `0600`、`hasync.secret` 权限 `0600`；
- [ ] VIP 承载网卡不是任何网桥成员口；桥成员口均无 IP 地址；
- [ ] `behavior_store=valkey` 已生效；`tls_session_ticket_key` 已配置并验证跨机 `Reused`；
- [ ] 两节点配置一致性视图 `consistent=true`，且 HTTPS 站点在备机直测返回 200；
- [ ] 通知渠道已订阅「基础设施」类别且覆盖 `CRITICAL`/`HIGH`/`MEDIUM`（`HA_SPLIT_BRAIN` 等告警才可触达，见 §5）。

---

## 2. 运维手册（日常操作）

### 2.1 状态查看

| 看什么 | 在哪看 |
|---|---|
| 双节点 VIP 运行态、是否脑裂（红条）、持久化事件时间线 | 「系统运维 → HA 主备」页（多节点对比卡 + `ha_events` 时间线） |
| 本机及远端备节点网桥/端口联动态 | 「系统运维 → 网络配置」页（切换节点查看） |
| 双节点心跳、协同代理地址、系统版本与配置一致性 | 「API 防护 → 节点校验」页 |
| 集群节点版本一致性与滚动升级执行进度 | 「系统管理 → 系统升级」页（集群版本卡 + 任务详情逐节点表） |
| HA 相关系统告警 | 「系统管理 → 系统告警」（类型见 §5） |

### 2.2 常见操作

- **人工回切（切换演练/计划内维护）**：「HA 主备」组行「回切」→ 选择目标节点并确认。服务端综合全量新鲜成员状态判定实际 VIP 持有方（即使管理面独立部署亦可识别），调整优先级同步双机并写入 `ha_events`（`FAILBACK`）。切换瞬间在途长连接断一次，用户**不需要重新登录**。
- **配置同步失败重试**：在「节点校验」页点击对应节点「重试同步」（调用 `POST /api/v1/config-versions/{id}/retry-sync`），无需重发整站即可定向补齐备节点。
- **TLS 票据密钥 2 键平滑轮换**：
  1. 将 `gateway_runtime:tls_session_ticket_key` 修改为 `新64位hex,旧64位hex` 并发布（此时新会话用新键加密，旧会话仍可用旧键平滑恢复，零握手抖动）；
  2. 等待一个会话票据生命周期后，将设置收敛为单 `新64位hex` 并发布。
- **VRRP 认证串更新/清除**：在「HA 主备」编辑弹窗输入新认证串，或勾选「清除已有 VRRP 认证串」显式清除，保存即同步双节点。
- **端口联动抑制复位**：先排查物理链路/光模块，再在「网络配置」页切到对应节点**原样保存一次**即复位。
- **停用/删除主备组**：编辑为 `DISABLED` 释放 VIP 且保留配置；删除组仅在所属节点收回 `ha-vip.json`（不误删无关组）并通知远端备机同步收回。

### 2.3 双机滚动升级操作（`HA_ROLLING`）

1. 在「系统管理 → 系统升级」顶部查看「集群节点版本状态」卡片，确认所有备节点协同代理就绪、版本兼容且**无未决脑裂告警**（存在 `HA_SPLIT_BRAIN` 时预检将自动拒绝启动滚动升级）。
2. 上传并校验离线升级包，执行升级时选择模式：**HA 集群滚动升级（先备后主，推荐）**（单机或仅维护本机时可选 `LOCAL` 仅升级本节点）。
3. 滚动执行阶段（任务详情实时展示 `upgrade_node_executions`）：
   - **PRECHECK & BACKUP**：先完成双机预检，并在主库执行一次全量加密备份；
   - **备节点阶段（`STANDBY`）**：逐台流式传输升级包至备机 `hasyncd`（HMAC + SHA-256 校验）→ 备机宿主机 `upgrade-executor.sh` 独立复验固定信任根 Ed25519 签名并升级 → 等待备机 `/v1/health` 恢复且 `version == version_to`；
   - **失败止损**：若任一备节点失败，任务立即转 `FAILED`（`STANDBY_UPGRADE_FAILED`）、其余待升节点（含主节点）标记 `SKIPPED`、发告警，**主节点零变更、业务不受影响**；待故障备机修复后，在任务详情点击该节点的「重试节点升级」单独补升；
   - **主节点阶段（`PRIMARY`）**：全部备节点升级验证通过后，再升级主节点（主节点重启期间由 Keepalived VIP / LB 自动将流量承接到已升级完毕的备节点）。

### 2.4 故障处置矩阵

| 现象 | 含义 | 处置 |
|---|---|---|
| 告警「主备双主脑裂」（`HA_SPLIT_BRAIN` CRITICAL）+ 页面红条 | 同组 ≥2 个新鲜节点同时报告 `MASTER` 或持有同一 VIP（多为 VRRP 通告链路分区） | 优先恢复 VRRP 互联/交换机策略；检查双节点网络与 `havipd` 日志；收敛单主后告警自动恢复，必要时执行人工回切 |
| 告警「主备VIP异常」（`HA_VIP_FAULT`） | 指定节点 Keepalived 停止/FAULT 或 `havipd` 状态过期 | 按告警中节点名登录排查 `havipd` 与 Keepalived 日志，恢复后自动转 `MASTER`/`BACKUP` |
| 告警「端口联动触发」（`LINK_PAIR_DOWN`） | 指定节点网桥一口掉 carrier，配对口已联动 down | 排查物理链路/光模块/对端口；恢复后自动回 up |
| 告警「端口联动抑制」（`LINK_PAIR_SUPPRESSED`） | 物理链路抖动超每小时上限已冻结联动 | 修复物理链路后在该节点「网络配置」页原样保存复位 |
| 告警「网络配置执行失败」（`NETWORK_APPLY_FAILED`） | 指定节点网桥/路由执行失败（如桥口带 IP 或口不存在） | 按告警 message 修正配置或清除桥口 IP，保存后自动重试 |
| 同步结果 `FAILED` / `ha_events` 出现 `SYNC_FAILED` | 备节点 `hasyncd` 不可达、密钥不匹配或时钟偏差超过 ±60s | 检查 NTP 时钟同步、管理网防火墙与 `hasync.secret`，用「连通测试」验证后点击「重试同步」 |
| 滚动升级失败 `STANDBY_UPGRADE_FAILED` | 备机传输/验签/执行/健康探针失败（主节点未被触碰） | 查看 `upgrade_node_executions` 错误码与备机执行器日志，修复后点击「重试节点升级」 |

### 2.5 切换对会话的影响（如实口径）

- 应用登录态（cookie/token）：**不受影响**，用户不需要重新登录；
- 管理控制台会话：**不受影响**（共享 Valkey）；
- CC/封禁/行为判定：**连续**（共享 Valkey）；
- TLS 会话恢复：配置 `tls_session_ticket_key` 后跨节点直接 `Reused`（支持 2 键平滑轮换）；未配置时回退一次完整握手（性能影响，不掉登录态）；
- 在途长连接（WebSocket/SSE/大文件上传）：**断一次**由客户端重连（不做 TCP conntrack 镜像）。

---

## 3. 交付检查项（双机高可用）

| # | 检查项 | 方法 | 通过标准 |
|---|---|---|---|
| HA-1 | 节点登记与协同通道 | 「节点校验」页登记 `hasyncd` 并点击「连通测试」 | 两节点 ACTIVE，`caddy_reachable`/`hostctl_ready`/`upgrade_ready` 均 true |
| HA-2 | 配置与 HTTPS 证书同步 | 发布含 HTTPS 站点配置 | 两节点均 `SUCCESS`、`consistent=true`，双节点 curl HTTPS 均 200 |
| HA-3 | 共享判定态 | A 打 60 次 + B 打 60 次同身份写请求（阈值 100） | 触发一次统一限速（`behavior_store=valkey` 生效） |
| HA-4 | 双机端口联动 | 拔主节点桥口一根线 | ≤3s 配对口联动 down，`PROPAGATED_DOWN` + 告警；备机亦可从页面配置联动 |
| HA-5 | 联动抑制与复位 | 人工快速反复断通同一口 | 超限进 `SUPPRESSED` + 告警；原样保存复位 |
| HA-6 | VIP 漂移与 `track_interfaces` | 停主节点或断主桥口 | ≤5s VIP 漂移到备，「HA 主备」多节点状态卡与 `ha_events` 有记录 |
| HA-7 | 会话保持与 2 键 STEK 轮换 | `openssl s_client -sess_out A → -sess_in B` | `Reused`；2 键轮换窗口旧票据不断 |
| HA-8 | 脑裂告警与恢复 | 模拟双节点 VRRP 分区 | 页面红条 + `HA_SPLIT_BRAIN`（CRITICAL）告警 + `ha_events` 落库；恢复后自动消除 |
| HA-9 | 滚动升级与备机止损 | `HA_ROLLING` 先备后主升级；另测备机失败场景 | 正常场景双机版本一致；备机失败立即中止且主节点无变更，修复后单节点重试通过 |
| HA-10 | 恢复收敛与重启清理 | 删主备组 / 重启 `havipd` | 双节点 VIP 彻底释放，无残留 Keepalived 孤儿进程 |

---

## 4. 告警接入（通知渠道）

系统告警 → 通知渠道订阅「**基础设施**」类别：

| 类型 | 等级 | 触发 | 自动恢复 |
|---|---|---|---|
| `HA_SPLIT_BRAIN` 主备双主脑裂 | **CRITICAL** | 同组 ≥2 个新鲜成员同时报告 `MASTER` 或持有 VIP | 恢复单主即自动恢复 |
| `HA_VIP_FAULT` 主备VIP异常 | HIGH | 任一成员 Keepalived FAULT/未运行、配置已下发但未上报或状态过期（>30s） | 成员恢复正常即恢复 |
| `NETWORK_APPLY_FAILED` 网络配置执行失败 | HIGH | 任一成员 `network-status` `ok=false` 或解析失败 | 执行成功即恢复 |
| `LINK_PAIR_DOWN` 端口联动触发 | MEDIUM | 任一成员桥口链路故障已联动 down | 恢复 `BOTH_UP` 即恢复 |
| `LINK_PAIR_SUPPRESSED` 端口联动抑制 | HIGH | 任一成员联动频率超限冻结 | 复位后恢复 |

---

## 5. 已知边界（交付必读）

- **目标 Linux 实机验收不可省略**：依据 `docs/tasks/UPGRADE_INCIDENT_2026-11-17.md`，本机单测、镜像构建、签名校验和 harness 测试不能替代目标 Linux 宿主机的真实安装、双机升级、回滚与外部客户端访问；未在实机执行的项必须如实标记 `NOT_RUN`；
- **无 TCP 连接镜像**：在途长连接切换即断一次（§2.5），长连接重业务须提前向客户说明；
- **共享 Valkey 单点**：Valkey 故障时按 Fail-open 降级，不中断转发；
- **物理链路 carrier 语义**：个别网卡驱动/光模块 carrier 误报与上游设备切换策略须在现场物理链路联调复测；
- **时钟同步**：`hasyncd` 强制 ±60s 防重放时间窗，双机节点务必启用 NTP/Chrony 保持时钟同步。
