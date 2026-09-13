# 网络诊断工具与网络设置（NTP/DNS）设计

## 一、功能定位与范围

1. **网络诊断工具**（前台「系统运维 → 网络工具」）：在管理界面直接发起网关节点侧
   的连通性诊断——ping、TCP 端口探测（tcp_probe）、traceroute、DNS 查询（dns_query）
   与按需抓包（capture，pcap 下载），用于部署排障与源站连通性核实，替代运维人员
   SSH 登录网关节点手工执行命令。
2. **NTP/DNS 网络设置**（前台「系统设置 → 网络」分组）：在管理界面配置网关节点的
   DNS 解析器与时间同步服务器，经既有 netmgrd 配置下发通道在宿主机落地。

两部分共用同一条「server → 共享卷文件契约 → netmgrd 执行 → 结果回写 → server 落库/
透传」的边车通道，与 mirrorcap/tproxyd/network.json 同一共享卷、同一原子写纪律。
本文档定义总体架构、文件契约、安全模型、落地顺序与已知限制。

## 二、总体架构

### 2.1 网络诊断工具链路

```
管理前端「系统运维 → 网络工具」
  │  POST /api/v1/network-tools/jobs（权限 network_tools.execute）
  ▼
server/internal/netdiag/（handler/store/worker/types）
  │  ① 参数校验（目标仅 IP/合法主机名、数值边界、过滤模板）
  │  ② 落库 netdiag_jobs（PENDING）+ 审计
  │  ③ 原子写请求文件 <GATEWAY_SIDECAR_DIR>/diag/request-<jobUUID>.json（0600）
  ▼
gateway/netmgrd/ diag 消费端（diag.go，1s tick 串行处理）
  │  ④ 复读校验目标与参数（两端校验，不信任 server 单侧）
  │  ⑤ 执行动作（Go 原生或系统二进制参数数组，不经 shell）
  │  ⑥ 原子写结果文件 result-<jobUUID>.json；抓包另产 capture-<jobUUID>.pcap
  ▼
server Worker（2s tick 消费结果）
  │  ⑦ 结果落库（SUCCESS/FAILED/STOPPED/TIMEOUT 终态）
  │  ⑧ pcap 搬入 NETDIAG_DATA_DIR 并 sha256 入库
  ▼
前端轮询 GET /jobs/{id} 展示；GET /jobs/{id}/download 下载 pcap
  （权限 network_tools.download，下载时校验 sha256 与库一致）
```

- **串行执行**：netmgrd 以 1s tick 单 worker 串行认领 diag 请求，同一时刻只执行一个
  诊断动作，避免并发抓包/路由跟踪耗尽网关资源。
- **停止**：POST `/jobs/{id}/stop` 由 server 写入停止标记 `stop-<jobUUID>`，netmgrd
  下个 tick 检测到后终止当前执行，结果记 STOPPED。
- **超时兜底**：每个请求携带 `timeout_sec`，netmgrd 超时强杀并记 TIMEOUT；server
  Worker 另有过期巡检，结果文件丢失的任务不会永远悬挂。

### 2.2 NTP/DNS 设置链路

```
系统设置页保存 NTP/DNS（system_settings：network.ntp_servers / network.dns_servers）
  │
  ▼  保存网络配置 PUT /api/v1/gateway/network-config
server 从 system_settings 合并进 network.json 新可选字段
  dns_servers / ntp_servers（omitempty，空不出现，向后兼容）
  ▼
netmgrd apply 落地：
  DNS：resolvectl → 原子重写 resolv.conf → UNSUPPORTED
  NTP：systemd-timesyncd drop-in → chronyd drop-in → UNSUPPORTED
  ▼
回执 network-status.json 新增 dns_status / ntp_status
  （APPLIED / UNSUPPORTED / FAILED + message）
  ▼
server 只读原样透传前端
```

复用既有 `node_network_configs` 持久化与 network.json 下发通道（见
[NETWORK_MODES_DESIGN.md](NETWORK_MODES_DESIGN.md) 第七节），新增字段向后兼容：
旧 netmgrd 收到未知字段忽略，旧 server 不产字段即维持原行为。

## 三、网络诊断工具设计

### 3.1 API 与权限

| 接口 | 权限 | 说明 |
|------|------|------|
| `POST /api/v1/network-tools/jobs` | `network_tools.execute` | 创建诊断任务（五种动作），校验 → 落库 → 写请求文件 → 审计 |
| `GET /api/v1/network-tools/jobs` | `network_tools.execute` | 任务列表（分页/筛选） |
| `GET /api/v1/network-tools/jobs/{id}` | `network_tools.execute` | 任务详情（含执行输出，截断后入库） |
| `POST /api/v1/network-tools/jobs/{id}/stop` | `network_tools.execute` | 写入停止标记，执行端下个 tick 终止 |
| `GET /api/v1/network-tools/jobs/{id}/download` | `network_tools.download` | 下载 pcap（仅 capture 成功任务；sha256 与库一致才放行） |

权限种子（迁移 000161）：两个权限点仅授 SYSTEM_ADMIN。写操作全量审计——
execute / download / stop 分别记录 operation_audits，风险级别按动作区分。

任务表 `netdiag_jobs`（迁移 000160）：

| 列 | 说明 |
|----|------|
| `id` | UUID 主键（即契约文件名中的 jobUUID） |
| `node` | 目标网关节点名 |
| `action` | ping / tcp_probe / traceroute / dns_query / capture |
| `target` | 诊断目标（IP 或合法主机名） |
| `params` | JSONB，动作参数快照 |
| `status` | PENDING / RUNNING / SUCCESS / FAILED / STOPPED / TIMEOUT |
| `exit_code` / `stdout` / `stderr` | 执行结果（stdout/stderr 截断 64KB 入库） |
| `duration_ms` / `finished_at` | 执行耗时与完成时间 |
| `capture_file` / `capture_size` / `capture_sha256` | 抓包产物元信息（server 搬入 NETDIAG_DATA_DIR 后回填） |
| `capture_packets` | JSONB 可空（迁移 000163），Worker 解析 pcap 产出的数据包列表（见 §3.6）；NULL = 非抓包任务或产物未解析/解析失败 |
| `created_by` / `created_at` | 发起人与发起时间 |

### 3.2 diag 文件契约

共享卷目录 `<GATEWAY_SIDECAR_DIR>/diag/`；所有文件均由写方先写临时文件再 rename
（原子写），请求文件权限 0600。

`request-<jobUUID>.json`（server 写，netmgrd 读）：

| 字段 | 类型 | 说明 |
|------|------|------|
| `version` | int | 契约版本 |
| `job_id` | string | 任务 UUID，与文件名一致 |
| `node` | string | 目标节点名；netmgrd 只认领与自身 NODE_NAME 一致的请求 |
| `action` | string | ping / tcp_probe / traceroute / dns_query / capture |
| `target` | string | IP 或合法主机名（两端各校验一次） |
| `params.count` | int | ping 包数 / dns_query 复用 |
| `params.port` | int | tcp_probe 目标端口 |
| `params.max_hops` | int | traceroute 最大跳数 |
| `params.duration_sec` | int | capture 抓包时长（5–300s） |
| `params.iface` | string | capture 网口 |
| `params.filter_proto` / `filter_port` / `filter_host` | string/int/string | capture 过滤三元素（见 §3.4） |
| `timeout_sec` | int | 执行超时硬上限 |

`result-<jobUUID>.json`（netmgrd 写，server Worker 读）：

| 字段 | 说明 |
|------|------|
| `job_id` | 任务 UUID |
| `status` | SUCCESS / FAILED / STOPPED / TIMEOUT |
| `exit_code` | 进程退出码（Go 原生动作按语义映射） |
| `stdout` / `stderr` | 输出（截断 64KB） |
| `duration_ms` | 执行耗时 |
| `capture_file` / `capture_size` | 抓包产物文件名与大小（仅 capture） |
| `finished_at` | 完成时间 |

其他文件：`stop-<jobUUID>`（停止标记，server 写）；`capture-<jobUUID>.pcap`
（抓包产物，netmgrd 写，server Worker 搬入 NETDIAG_DATA_DIR 并 sha256 入库，
下载接口校验一致后才放行——防止产物被卷内其他写入者替换）。

### 3.3 五种动作语义与参数边界

| 动作 | 执行方式 | 参数与边界 | 超时硬上限 |
|------|----------|------------|------------|
| `ping` | 系统 `ping` 二进制（参数数组） | `count` 有界；目标仅 IP/合法主机名 | 30s |
| `tcp_probe` | Go 原生 net.DialTimeout | `port` 1–65535；返回 connected / connection refused 等语义化结果 | 内置短超时 |
| `traceroute` | 系统 `traceroute` 二进制（参数数组） | `max_hops` 有界 | 60s |
| `dns_query` | Go 原生解析器 | 目标仅合法主机名/待反解 IP | 内置短超时 |
| `capture` | 系统 `tcpdump`（参数数组） | `duration_sec` 5–300s；`iface` 合法网口名；过滤仅三元素固定模板；产物 ≤100MB | duration_sec 上限 300s |

### 3.4 安全模型

诊断工具本质是把宿主机网络命令开放给 Web 用户，安全约束在接口层与执行端双侧
强制执行（两端校验，任何单侧被绕过都不构成注入面）：

| 约束 | 实现 |
|------|------|
| 目标白名单校验 | server 与 netmgrd 各自校验 target 仅为合法 IP 或合法主机名（字符集/长度白名单），拒绝任何含 shell 元字符的输入 |
| 不经 shell | tcp_probe/dns_query 为 Go 原生实现；ping/traceroute/capture 以**参数数组**（exec argv）调用系统二进制，不存在命令拼接 |
| 无自由 BPF | capture 过滤仅开放 proto / host / port 三元素固定模板（服务端拼装为受限表达式），不开放任意 BPF 语法 |
| 限额 | ping ≤30s、traceroute ≤60s、capture 5–300s；pcap ≤100MB；stdout/stderr 截断 64KB |
| 串行执行 | netmgrd 单 worker 1s tick 串行认领，天然互斥 |
| 权限与审计 | execute/download 双权限点仅 SYSTEM_ADMIN；execute/download/stop 全量 operation_audits |
| 产物完整性 | pcap sha256 入库，下载时与磁盘文件重新校验一致才放行 |

### 3.5 部署

**Docker（stage5 网关栈）**：`deployment/docker-compose.stage5.yml` 新增 netmgrd
服务——`network_mode: service:gateway`（与网关同网络命名空间，诊断结果即网关视角）、
`cap_add: NET_RAW,NET_ADMIN`、挂载同一 `/var/run/caddy` 卷、`NODE_NAME` 与
`GATEWAY_NODE_NAME` 一致。镜像 `gateway/images/netmgrd/Dockerfile`（build context
为 `gateway/`）：alpine 基座 digest 锁定，安装 iproute2/iputils/tcpdump/traceroute。

根 `docker-compose.yml` 只有 postgres/valkey 基座、不含网关栈，故未接入 netmgrd
服务（如实说明：本地开发基座无法使用网络工具，需 stage5 或裸机部署）。

**裸机**：netmgrd 已作为宿主机驻留组件存在，仅需额外安装系统包
iputils / tcpdump / traceroute。

### 3.6 页面内数据包解析展示

抓包任务成功后，server Worker 在搬移 pcap 产物并 sha256 入库之后，用内置纯 Go
pcap 解析器（`server/internal/netdiag/pcap.go`，零第三方依赖）就地解析产物，把
数据包列表 JSON 存入 `netdiag_jobs.capture_packets`（JSONB，迁移 000163），详情
接口 `GET /api/v1/network-tools/jobs/{id}` 的 job 对象带 `capture_packets` 字段，
页面可直接在任务详情内查看数据包列表，无需下载 pcap。

**解析层次**：经典 pcap 全局头（24 字节；magic 0xa1b2c3d4/0xd4c3b2a1 两种端序及
微秒/纳秒变体，仅支持 Ethernet linktype=1）→ 逐包 16 字节记录头
（ts_sec/ts_usec/incl_len/orig_len）→ Ethernet II（802.1Q/QinQ VLAN tag 逐层跳过）
→ IPv4/IPv6（IPv6 跳过 hop-by-hop/routing/destination/fragment 扩展头）→
TCP/UDP/ICMP/ICMPv6。

**字段表**（`capture_packets` 数组元素，OpenAPI `NetdiagCapturePacket`）：

| 字段 | 类型 | 说明 |
|------|------|------|
| `no` | int | 包序号（按解析成功顺序从 1 编号） |
| `ts` | string | 捕获时间（RFC3339，微秒精度） |
| `src` / `dst` | string | 源/目的地址（IP；非 IP 包为 MAC） |
| `sport` / `dport` | int/null | 仅 TCP/UDP，其余为 null |
| `proto` | string | TCP/UDP/ICMP/ICMPv6；其他 IP 协议 `IP-<num>`；非 IP `ETH-0x<ethertype hex>` |
| `flags` | string | 仅 TCP，按 FIN,SYN,RST,PSH,ACK,URG,ECE,CWR 顺序逗号连接 |
| `length` | int | 线原始长度（记录头 orig_len） |
| `preview` | string | 传输层 payload 可打印 ASCII（非可打印字节替换为 `.`），截断 80 字符；无 payload 空串 |

**上限与健壮性**：最多解析前 **200** 个包，文件含更多包时正常返回前 200 个并在
Worker 日志标记 truncated（页面可按 `len == 200` 提示可能截断）；截断包/畸形包
跳过不报错，文件尾部记录截断保留已解析部分；全局头非法（长度不足/magic 未知/
非 Ethernet linktype）判定为解析失败。

**失败回退语义**：解析失败（非法 pcap、读文件失败、入库失败）**不阻断任务成功**——
仅记 `slog.Warn`，`capture_packets` 保持 NULL，详情接口该字段为 `null`，页面回退
为仅显示 pcap 下载按钮。列表接口不查询该列（避免大 payload），列表项恒为 `null`。

## 四、NTP/DNS 网络设置设计

### 4.1 设置项与校验

| 设置键 | 默认 | 校验 |
|--------|------|------|
| `network.ntp_servers` | `pool.ntp.org` | 逗号分隔、≤4 个，逐项 IP/合法主机名 |
| `network.dns_servers` | 空（=继承宿主机） | 逗号分隔、≤4 个，逐项 IP/合法主机名 |

迁移 000162 种子 + `settings.go` 白名单/校验：非法值（如注入字符、超限个数）
在设置接口层即 400 拒绝（已实测）。

### 4.2 下发与落地

- **合并下发**：保存网络配置（`PUT /api/v1/gateway/network-config`）时，server 从
  system_settings 读取当前 NTP/DNS 值合并进 network.json 的新可选字段
  `dns_servers`/`ntp_servers`（omitempty——空值不出现在文件中，旧契约消费者
  零影响，向后兼容）。
- **netmgrd 落地顺序**（按宿主机环境自动选择，逐级探测）：
  - DNS：① `resolvectl`（systemd-resolved 环境）→ ② 原子重写 `/etc/resolv.conf`
    （排除 systemd stub 与容器托管挂载点，避免写坏容器内挂载）→ ③ UNSUPPORTED；
  - NTP：① systemd-timesyncd drop-in → ② chronyd drop-in → ③ UNSUPPORTED。
- **结果回报**：network-status.json 新增 `dns_status`/`ntp_status`，取值
  `APPLIED` / `UNSUPPORTED` / `FAILED` + message。FAILED 计入整体失败（ok=false）
  触发既有周期重试；UNSUPPORTED 不计入失败（环境本身不具备落地通道，重试无意义）。
  server 只读原样透传前端。
- **容器环境行为**：netmgrd 运行于容器网络命名空间时无 systemd/宿主 resolv.conf
  可写，正确回报 UNSUPPORTED（已实测）——该设置项面向裸机部署，容器栈如实降级。

## 五、测试与验证

- **单元/集成测试**：gateway netmgrd diag 22 例 + dns_ntp 17 例；server netdiag
  handler/worker/store 集成测试（真实 PG）；settings/netconfig 校验与合并测试；
  前端 NetworkToolsPage 10 例 + 系统设置 3 例（全量 945 例绿）。
- **stage5 实测**：ping/traceroute SUCCESS 真实输出；tcp_probe 8081 SUCCESS、
  80 端口正确报 connection refused；dns_query 解析正常；10s 抓包 50 包 pcap
  下载 sha256 与库一致；60s 抓包手动停止记 STOPPED；DNS/NTP 全链路 UNSUPPORTED
  回报正确；非法 DNS 值 400 拒绝；operation_audits 记录 execute/download/stop
  风险级别正确。
- **OpenAPI**：`server/openapi/fragments/20-network-tools.yaml`，
  `make openapi-reconcile` 661 路由双向零差集。

## 六、已知限制（如实披露）

1. **单节点认领**：diag 请求按 NODE_NAME 匹配，仅本节点 netmgrd 认领；多节点部署
   下任务只在指定节点执行，无跨节点编排。
2. **capture 串行**：单 worker 串行执行，抓包期间其他诊断任务排队；长时间抓包
   （上限 300s）会阻塞后续任务。
3. **容器 UNSUPPORTED**：NTP/DNS 设置在容器部署下如实回报 UNSUPPORTED，仅裸机
   部署可实际落地。
4. **根 compose 未接入**：根 `docker-compose.yml` 仅 postgres/valkey 基座、不含
   网关栈，故未加入 netmgrd 服务；网络工具需 stage5 栈或裸机部署使用。
5. **诊断视角**：所有诊断动作在网关节点网络命名空间内执行，结果代表网关视角的
   连通性，不等同于管理端（server）或客户端视角。

Copyright © 聚信得仁
All Rights Reserved.
