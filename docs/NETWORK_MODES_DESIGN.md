# 多网口管理与多模式部署设计（WDSP）

## 一、需求与范围

1. **网口管理**：硬件服务器多网口（如 4 电口 + 4 光口）场景下，系统能够枚举物理网口、
   在管理界面排序并保存（如约定前 4 口为电口、后 4 口为光口），排序结果持久化，
   供部署配置与运维展示使用。
2. **多部署模式**：在现有反向代理模式之外，支持**透明串接**、**路由牵引**、**镜像（旁路）**
   三种部署模式。

本文档定义方案与分期。网口管理为第一阶段直接实施；三种新模式按技术风险排序逐阶段
技术验证后落地（见第五节）。

## 二、网口管理设计

### 2.1 关键事实（已核实）

- 接口命名与枚举属于宿主机 OS 层（内核/udev），应用与 Docker 不感知；`eth0..N`
  传统命名按探测顺序分配，**不保证与物理口位置对应**（电口/光口可能交错），
  稳定对应关系必须依赖 PCI 拓扑（`ethtool -i` 的 bus-info）或 MAC 地址。
- 系统当前容器化部署，网口采集需要宿主机权限：网关容器挂载 `/sys/class/net`（只读）
  即可枚举，`ethtool` 能力需 `NET_ADMIN` 或在安装期由宿主脚本采集。

### 2.2 数据模型（server 侧，新迁移）

`gateway_node_interfaces`：节点物理网口清单与排序。

| 列 | 说明 |
|----|------|
| `id` | UUID 主键 |
| `node_name` | 网关节点名（对应 GATEWAY_NODE_NAME） |
| `ifname` | 当前接口名（eth0 / enp3s0f0） |
| `mac` | MAC 地址（稳定标识之一） |
| `ip_addresses` | 当前绑定的全局单播 IPv4/IPv6 地址列表（`TEXT[]`，CIDR 形式，IPv4 优先；过滤回环/链路本地地址） |
| `pci_path` | PCI 拓扑路径（如 0000:03:00.0，换内核不变的物理位置标识） |
| `driver` | 驱动（igb/ixgbe/i40e/e1000…） |
| `media_type` | 介质类型：`TP`（电口）/ `FIBRE`（光口）/ `UNKNOWN`（ethtool port 字段 + 驱动推断） |
| `link_speed` | 链路速率（如 1000/10000 Mb/s，DOWN 为 0） |
| `sort_order` | 用户排序序号（界面拖拽保存） |
| `role` | 用途标记（管理/业务/镜像口等，可选） |
| `first_seen_at` / `last_seen_at` | 采集时间 |

约束：`UNIQUE (node_name, ifname)`；同一 `pci_path` 同节点唯一（防雷同名上报）。

### 2.3 采集与上报

- 网关侧周期性（启动 + 每 60s）读取 `/sys/class/net/*`（ifname/MAC/operstate/speed），
  结合 `net.Interfaces()` 采集当前网络命名空间内各网口的全局单播 IPv4/IPv6（CIDR 形式，
  生产 `network_mode: host` 与裸机部署下即宿主机实际 IP）及 ethtool（驱动/bus-info/port 类型）
  组装清单，写 `node-interfaces.jsonl` 快照由服务端采集入库。
- 管理端 UPSERT 清单（保留用户已设定的 `sort_order`/`role`，新发现的口排末尾）。
- 纯 Docker/容器内采集降级：无 ethtool 权限时 `media_type=UNKNOWN`，界面提示
  「需在宿主机运行 ops 脚本补全介质识别」。

### 2.4 排序与保存

- 管理界面「系统运维 → 网口管理」页：按节点分组展示网口表格（名称/IP 地址/介质/速率/MAC/
  PCI 路径/角色/状态），拖拽或上下移动排序，保存写 `sort_order`。
- 排序语义：**仅作展示与配置引用顺序**（部署配置中的接口选择器按此序展示），
  不改写 OS 接口名。
- 可选增强「命名固化」：按排序结果生成 udev/.link 规则（按 MAC/PCI 路径绑定
  `copper0-3`/`fiber0-3` 之类的稳定名），由宿主机 ops 脚本执行——消除 ethX 漂移。
- 权限：读 `system_health.read`（或新权限点 `node_interfaces.read`），排序/角色编辑
  `system_health.write` 级；写操作全量审计。

## 三、部署模式总体架构

```
部署模式（每应用/节点级配置，随配置发布下发）
├─ reverse_proxy  反向代理（现有，默认）
├─ routed         路由牵引（三层转发 + 检测）
├─ transparent    透明串接（二层桥 + 牵引检测）
└─ mirror         镜像旁路（被动检测，不阻断）
```

共同约束：所有模式复用同一套检测管线（Coraza/CRS + jiuzhang_guard）与配置发布通道；
差异只在**流量到达方式**与**阻断能力**。镜像模式只检测不阻断；透明/路由模式可阻断。

**站点资产发现**（2026-08 新增）：mirror/routed/transparent 三模式统一由 mirrorcap 以
AF_PACKET 只读副本旁路抓包，全端口协议嗅探（HTTP Host + TLS ClientHello SNI）学习
站点域名/IP/端口，详见 [SITE_DISCOVERY_DESIGN.md](SITE_DISCOVERY_DESIGN.md)；
reverse_proxy 模式不做发现（该模式站点本已配置才能过流）。

## 四、三种新模式技术方案

### 4.1 路由牵引模式（routed）

- 流量路径：客户端/交换机将目标网段路由指向 WAF 节点，WAF 作为下一跳接收后转发源站。
- 实现要点：内核 `ip_forward=1`；网关监听地址绑定节点业务口地址；回源时保持真实
  客户端 IP（TPROXY 或按既有可信代理链解析 XFF）；回程路由规划避免三角传输。
- 与反代差异最小（仍终结 TCP），**作为新模式的第一优先实施**。
- 待验证项：TPROXY 保持源地址的 listener 支持（见 4.3 验证清单共用）。

#### 4.1.1 PoC 验证结论（阶段B 技术验证，已实测）

实验编排 `deployment/docker-compose.routed-lab.yml`（独立 project `routedlab`），
验证脚本 `test/waf/scripts/routed-lab-tests.sh`（PASS/FAIL 计数，可重复执行）。
拓扑：`client 172.30.10.10 → 目的路由 via 172.30.10.2(WAF) → WAF 172.30.20.2:8080
终结 TCP/检测 → origin 172.30.20.10:8081`（client_net/server_net 双网桥）。

实测结果（9/9 PASS）：

- **检测与阻断正常**：正常请求经路由送达 WAF 返回源站 200；带 SQLi 特征
  （`' OR '1'='1`）的请求返回 403（Coraza On 命中 CRS 阻断）。Host 头匹配在路由
  模式下天然成立（客户端按域名访问，Host 头不变）。
- **IP 溯源正确（不经任何代理头）**：WAF 访问日志 `request.remote_ip` 与 Coraza
  审计日志 `transaction.client_ip` 均为真实客户端 `172.30.10.10`——路由模式下
  TCP 连接天然携带真实源地址（WAF 是下一跳），不依赖 XFF 等代理头，无伪造风险。
- **回源语义与反代一致**：路由模式仍终结 TCP，源站看到的对端是 WAF 的业务口地址
  （172.30.20.2），与现有反向代理一致，**不伪造源 IP**。
- **纯三层转发路径成立**：WAF 仅 `ip_forward=1` 转发（不终结 TCP）时，配合对称
  回程（origin 加 `172.30.10.0/24 via 172.30.20.2`），客户端可直达源站且源站看到
  真实客户端 IP——证明三层连通性与源地址在路由转发下端到端保持。

限制与边界：

- 当前 Caddy 构建**无 TPROXY listener**（`list-modules` 实测仅
  proxy_protocol/http_redirect/tls），因此本模式不保持源地址到源站；
  **TPROXY 全透明源地址保持列为后续可选增强**（需扩展构建或自定义 listener 插件）。
- 实验环境 Docker Desktop（macOS）：容器间路由在 Linux VM 内部生效；实测其 VM
  默认放行跨网桥转发，非对称回程下客户端可绕过 WAF 直连源站（基线用例已记录并
  给出告警）。该行为为实验环境特性，不代表生产网络。

生产部署要求：

1. **对称路由**：源站回程流量必须经 WAF（策略路由/源地址会话保持，或源站默认
   网关指向 WAF），避免三角传输导致状态检测失效或阻断页无法送达；
2. 或在 **WAF 上对回源连接 MASQUERADE**（源站看到 WAF 地址，回程自然对称，
   与反代语义等价）；
3. **源站侧 ACL/安全组仅放行来自 WAF 节点的流量**，消除绕过 WAF 的直连通道；
4. TPROXY 源地址保持作为后续增强项另行验证（与 4.3 透明串接共用验证清单）。

### 4.2 镜像模式（mirror）

- 流量路径：交换机 SPAN/镜像口复制流量到 WAF 镜像口，节点只读分析。
- 实现要点：新增旁路采集器（AF_PACKET/gopacket）抓取并重组 HTTP 会话 → 送入
  检测管线的观察路径（不产生任何阻断动作）→ 事件照常入库。
- 性能隔离：抓包丢包不熔断、采样与速率上限可配；单节点 CPU 占用上限约束。
- 该模式独立于现有 Caddy 数据面，属于新增组件，工作量集中在会话重组与背压。

#### 4.2.1 PoC 验证结论（阶段C，2026-08-18 实测 18/18 PASS）

**实现组件**（全部新增，不改动既有数据面）：

- `gateway/mirrorcap/`（gateway 根 go.mod）：旁路采集器包——抓包（pcapgo
  `EthernetHandle`，AF_PACKET 纯 syscall raw socket，无 libpcap、无 cgo，
  CGO_ENABLED=0 静态编译）、TCP 四元组流重组（tcpassembly/tcpreader，
  仅重组目的端口 ∈ MIRROR_PORTS 的 client→server 方向流）、循环 `http.ReadRequest`
  还原连续/pipeline 请求（Body 截断至 MIRROR_BODY_MAX，剩余排空保持流对齐）、
  空闲流周期冲刷（半开连接清理）、流上限护栏（默认 4096）；
- `gateway/cmd/mirrorcap/main.go`：环境变量装配 + SIGTERM/SIGINT 优雅退出
  （实测 docker stop 退出码 0，最终统计落盘）；
- 检测路径：Coraza v3.7.0（与网关同一锁定版本）以 **SecRuleEngine DetectionOnly**
  内嵌运行（规则链与 Caddyfile 逐条一致，仅引擎模式不同），命中规则转为
  `detector=waf` 明细（脱敏：不含命中载荷值），作为 externalMatches 送入
  `dynamic_security` 统一管线（`parser.ParseRequest` + `pipeline.Process`，
  Mode=OBSERVE）；事件按 `jiuzhang_guard/apievents` 同一 JSONL 契约输出，
  服务端既有采集器可原样入库（本 PoC 自包含，断言直读卷内文件）；
- **旁路铁律**：事件 `final_action` 一律封顶 OBSERVE；镜像来源以 Details 首位
  INFO 级 `mirror.capture` 明细标注（决策引擎跳过 INFO 不定案、采集端透传存储，
  与现有消费方零冲突），`pipeline_decision` 记入其 evidence。

**实验拓扑**（`deployment/docker-compose.mirror-lab.yml`，独立 project mirrorlab）：
client(172.30.30.20) ──server_net──> origin(172.30.30.10:8081)；mirror 容器以
`network_mode: container:mirrorlab-origin` 共享 origin 网络命名空间——Docker 无真实
SPAN，这是无交换机环境下模拟镜像口的标准做法（被动副本、只读分析，流量路径等价）。
mirror 容器 `cap_add: NET_RAW,NET_ADMIN`，规则卷只读挂载 `gateway/rules`。

**实测结果**（`test/waf/scripts/mirror-lab-tests.sh`，18/18 PASS）：

- 正常请求：产生捕获记录，`endpoint_key=GET /echo`、method/raw_path 正确，
  `details[0]` 为 `mirror.capture` 标注；
- SQLi 特征请求（`id=1' OR '1'='1`）：事件 `risk_level=CRITICAL`（risk_score=225）、
  `final_action=OBSERVE`，waf 命中含 CRS `942100`（libinjection SQLi）、CUSTOM_PACK
  变体规则与九章二次评估 `9000104`；Coraza 审计日志可按请求标记交叉定位同一事务；
  攻击请求照常 200 到达源站（旁路无阻断环节）；
- 源地址：`client_ip=172.30.30.20`（真实客户端，取自四元组而非任何代理头），
  `source_fingerprint` 统一 HMAC 指纹非空；
- 零侵入：镜像抓包进行中同一 URL 两次响应逐字节一致，origin 看到的对端仍是真实
  客户端 IP；
- 可观测：每 60s（实验 5s）一行统计日志（packets/dropped/streams/requests/events），
  实验全程 `dropped=0`、`event_errors=0`；
- POST JSON 带体请求实测还原正确（`POST /api/json`，参数观测字段齐全）。

**限制与边界**（PoC 范围，如实声明）：

- 仅 HTTP/1.x **请求侧**明文流量；不重组/不分析响应方向（`response_status` 契约 0=未采集）；
- **HTTPS 镜像无法解密**：旁路无密钥也无终止能力，加密流量只能看到 TLS 握手元数据，
  本模式适用明文区段（内网/S LB 卸载后）的镜像检测；
- 抓包丢包不熔断、不回传背压：SPAN 采样/内核丢包导致流缺失字节时，该流以显式错误
  终止解析（`LossErrors`），不无限等待；
- gopacket v1.1.19 的 `afpacket` 包源文件含 `import "C"`，CGO_ENABLED=0 下不可用，
  故抓包层用同版本 `pcapgo.EthernetHandle`（同为 AF_PACKET 纯 syscall）；代价是逐包
  recvmsg、无 TPACKET_V3 环形缓冲，高带宽下丢包率高于 afpacket——生产化可换纯 syscall
  TPACKET_V3 自实现（保持零 cgo）；
- 事件关联契约不记录 query 明文（数据最小化），测试按「请求串行+事件顺序追加」基线
  定位用例事件；
- 实验环境 Docker Desktop（macOS）：共享网络命名空间模拟镜像口，结论代表流量路径与
  检测链路正确性；真实 SPAN 的混杂模式抓包、万兆速率下的丢包率与 CPU 上限约束
  留待物理环境复测。

### 4.3 透明串接模式（transparent）

- 流量路径：两口（如 eth2/eth3）建桥 br0 二层串接，经 netfilter 牵引（TPROXY/
  REDIRECT）到本机检测监听，检测后放行转发。
- 实现要点：桥接与 iptables/nftables 规则由安装脚本生成（含 `bridge-nf-call` 开关）；
  Caddy 需 TPROXY 透明代理 listener 支持（**技术验证项 T1**）；故障 fail-open 策略
  （进程/服务 down 时桥接直通，复用软件 bypass 思路；硬件级断电 bypass 依赖网卡
  本身能力，仅文档说明）。
- 风险最高：串接在数据通路上，任何实现缺陷直接影响业务连通性，必须 PoC 验证 +
  集成测试（含故障注入：kill 网关进程验证直通）。

#### 4.3.1 PoC 验证结论（阶段D，2026-08-18 实测 22/22 PASS；2026-08-21 扩 HTTPS SNI 分流后 29/29 PASS）

**实现组件**（全部新增，不改动既有数据面）：

- `gateway/tproxyd/`（gateway 根 go.mod，零新增依赖、仅标准库）：透明牵引进程
  包——监听 REDIRECT 牵引端口；对每个被牵引连接以 getsockopt(SO_ORIGINAL_DST)
  （纯 syscall，CGO_ENABLED=0 静态编译）读取 conntrack 记录的原始目的地址；向
  下游 Caddy 前置一行 PROXY protocol v1（真实源 IP/端口 + 原始目的）；随后双向
  io.Copy（*net.TCPConn splice 零拷贝）透传，半关闭语义双向传播；并发上限护栏
  （TPROXY_MAX_CONNS，超上限新连接立即关闭并计数，背压不失控）；周期统计日志
  （默认 60s）；SIGTERM 优雅退出（宽限等待在途连接、超时强制断开，最终统计落盘）。
  PROXY 头构造与 sockaddr_in 解码为纯函数；
- `gateway/cmd/tproxyd/main.go`：环境变量装配 + 信号处理（结构对齐 mirrorcap）；
- 单测 `gateway/tproxyd/*_test.go`（13 用例全绿；`go build ./... && go test ./...`
  全模块绿）：PROXY 头格式（含 IPv4-mapped 接受/纯 IPv6 拒绝/端口边界）、
  sockaddr_in 网络字节序解码、配置解析、注入桩端到端中继（PROXY 头逐字断言 +
  双向字节透传）、并发上限拒绝、原始目的解析失败关连接、优雅退出强制断开；
- `deployment/docker/tproxy-lab/`：实验镜像（alpine RepoDigest 锁定，与 mirrorcap
  同一基座；iptables/iproute2/curl 构建期取自 alpine 3.20 仓库；caddy/testorigin
  由 extract-binaries.sh 从 digest 锁定的本机镜像 docker cp 提取——BuildKit 无法
  把自建镜像 name@digest FROM 解析到本地存储，会回源 registry 失败；tproxyd 宿主机
  交叉编译）、实验 Caddyfile（规则链与 stage5 静态配置逐条一致，差异仅
  listener_wrappers 与 upstream 地址）、entrypoint.sh（拓扑 → 内核参数 → 源站 →
  Caddy → 牵引规则 → tproxyd → 看门狗）；
- `deployment/docker-compose.tproxy-lab.yml`（独立 project tproxylab）：单
  privileged 容器、`network_mode: none`（业务面仅容器内自建桥接拓扑）、
  规则/配置/阻断页只读挂载、日志卷落宿主机；
- `test/waf/scripts/transparent-lab-tests.sh`：PASS/FAIL 计数，可重复执行
  （复跑方式见脚本头注释）。

**实验拓扑**（单容器内 netns 模拟二层串接——Docker 网桥间无法真二层桥接，这是
无交换机环境下的标准模拟法）：
client ns(192.168.50.10/24) ──veth── br0 ──veth── origin ns(192.168.50.20:8081)；
bridge-nf-call-iptables=1 使桥接流量过 iptables，nat/PREROUTING 将桥上 tcp/8081
REDIRECT 到 tproxyd(0.0.0.0:15000)；tproxyd 以 PROXY v1 把真实五元组上报给
loopback 上的 Caddy（:8080 站点 bind 127.0.0.1；proxy_protocol wrapper
allow 127.0.0.1/32 仅信牵引进程）；Caddy coraza On 检测后反代源站。客户端与源站
同网段，零代理配置按普通直连访问。

**实测结果**（22/22 PASS）：

- 正常请求经「桥 → REDIRECT → tproxyd → PROXY v1 → Caddy → 源站」返回 200，
  响应体正确（service/upstream_mark），源站回显的 X-Request-Id 与响应安全头
  证明流量确实经过 WAF 管线（客户端零代理配置）；
- SQLi 特征请求（`' OR '1'='1`）返回 403 + 九章阻断页：inline 阻断在透明串接
  拓扑下生效；
- IP 溯源：Caddy access.log `request.remote_ip` 与 Coraza 审计
  `transaction.client_ip` 均为真实客户端 192.168.50.10——真实源地址经 PROXY
  协议（连接级元数据，非 HTTP 头，客户端无法伪造）进入 Caddy；
- 源站视角（回源语义实测）：TCP 对端为 WAF 桥地址 192.168.50.1（REDIRECT 方案
  回源连接由 Caddy 发起，与反代语义一致，不伪造源 IP）；源站同时收到
  `X-Forwarded-For: 192.168.50.10`（真实客户端经反代理头传达）；
- fail-open：kill -TERM 与 kill -9 杀掉 tproxyd 后，看门狗在探测周期内 flush
  牵引链，桥接恢复二层直通——同一请求直连源站 200（源站看到真实客户端
  192.168.50.10、无 X-Request-Id，流量不再检测）；docker restart 后拓扑重建、
  检测恢复（SQLi 再被 403、正常请求再经 WAF）；
- 统计日志：accepted/bytes 计数随流量增长，实验全程 rejected=0、
  origdst/dial/header/accept 错误=0。

**HTTPS SNI 分流实测**（2026-08-21 追加，同拓扑扩 tcp/443 牵引，29/29 PASS）：

- tproxyd 新增 ProtectHosts 防护域名清单（env `TPROXY_PROTECT_HOSTS` / 下发文件
  `protect_hosts`）：TLS 连接嗅探 ClientHello SNI（仅 Peek 不消费字节）——清单内
  域名前置 PROXY v1 送 Caddy TLS 监听器（TargetTLS）终结检测；清单外域名按
  SO_ORIGINAL_DST 原始目的直接 TCP 透传回源站（TLS 端到端，不注入任何字节）；
  明文 HTTP 维持原路径；解析失败倒向 TLS 检测路径（防畸形 ClientHello 绕过）；
  嗅探读超时（默认 3s）关连接并计数；域名精确匹配（小写归一、容忍末尾点）；
- 实测（防护清单=[www.test.com]，源站同 IP 双虚拟主机）：`https://www.test.com`
  经 WAF 终结检测返回 200 + X-Request-Id + 安全响应头，其 SQLi 403；同 IP 的
  `https://www.test1.com` 端到端透传——客户端校验到的是**源站自签名证书**
  （CN=www.test1.com，WAF 不持有该域名任何证书角色），响应无 WAF 注入头；
  统计行 `sni(protected=5 passthrough=1 ...)` 分流计数正确；
- Caddyfile 适配注意（实测踩坑）：全局 servers 块的 listener_wrappers 必须显式
  把 `tls` 占位符放在 `proxy_protocol` **之后**——Caddy 默认将全部 wrapper 排在
  TLS 握手之后（caddyhttp/app.go 的 tlsPlaceholderWrapper 逻辑），不显式指定
  会导致 PROXY 行被当作 TLS 记录解析、握手直接失败（curl 报 unexpected eof）；
- 实验环境源站 TLS 由 `openssl s_server -www` 模拟（未改动 stage1 testorigin），
  自签名证书由 entrypoint 运行时签发（镜像新增 openssl，构建期取自 alpine 3.20
  仓库，与 iptables/curl 同一约定）。

**关键实测事实**（内核与构建约束，决定方案选型）：

- Docker Desktop（macOS）VM 内核：xt_REDIRECT（nat）可用；br_netfilter
  bridge-nf-call-iptables 可置 1；`iptables -t mangle -j TPROXY` 规则亦可安装
  （内核 TPROXY 目标可用）——但当前 Caddy 构建**无 TPROXY listener**
  （list-modules 实测仅 http_redirect/proxy_protocol/tls），故数据面采用
  REDIRECT + 自研 tproxyd（SO_ORIGINAL_DST）+ PROXY protocol 的**透明代理**
  方案（WAF 终结 TCP/HTTP，五元组对网络层透明）；TPROXY 双向全透明（源地址
  保持到源站）留作增强（需自定义 listener 插件，或 tproxyd 升级 IP_TRANSPARENT
  监听 + fwmark 策略路由）；
- 本构建的 Caddyfile 适配器：listener_wrappers 仅支持全局 `servers` 块（站点块
  内报 unrecognized directive，实测）；listener 绑定地址由 `bind` 指令控制
  （站点地址的主机部分是 Host 匹配器而非绑定地址）。

**限制与边界**（PoC 范围，如实声明）：

- REDIRECT 方案源站看到 WAF 地址（与现有反代一致）；TPROXY 源地址保持到源站
  为后续增强项；
- HTTPS：透明串接下 TLS 密文由 tproxyd 嗅探 ClientHello SNI 分流（ProtectHosts
  清单）——清单内域名送 Caddy TLS 监听器终结检测（部署防护站点证书）；清单外
  域名按原始目的端到端 TCP 透传（WAF 无需其证书，不注入 PROXY 头）；解析失败
  （截断/畸形/无 SNI/ECH）倒向 TLS 检测路径防绕过；ECH 加密 ClientHello 时 SNI
  不可见，按解析失败处理（列为边界）；域名精确匹配不支持通配符；
- fail-open 覆盖进程级故障（看门狗清规则直通）；硬件级断电 bypass 依赖网卡本身
  能力，仅文档说明；
- 仅 IPv4（PROXY v1 TCP4）；IPv6 透明串接留待生产化；
- 看门狗清规则后转入 fail-open 稳态（PID1 驻留维持桥接直通，不重启震荡），检测
  恢复依赖编排/运维重启容器；
- 实验环境 Docker Desktop（macOS）：netns 模拟二层串接，结论代表流量路径、牵引
  机制、检测链路与 fail-open 行为正确性；物理两口桥接的线速性能、真实硬件
  bypass、与现网 STP/环路共处留待物理环境复测。

## 五、分期实施

| 阶段 | 内容 | 验收 |
|------|------|------|
| A | 网口管理：采集上报 + 排序持久化 + 管理页 + 审计 | 多网口主机枚举正确、排序保存生效、光电识别准确 |
| B | 路由牵引模式：技术验证（源地址保持/回程）→ 配置化 → 集成测试 | 路由拓扑下检测与阻断正确、IP 溯源正确（PoC 已实测 9/9 PASS，见 §4.1.1：SQLi 经路由阻断 403、日志 client_ip=真实客户端、回源 200；TPROXY 源地址保持列为后续增强） |
| C | 镜像模式：旁路采集器 PoC → 会话重组 → 事件入库 | SPAN 流量产生正确事件、零阻断副作用（PoC 已实测 18/18 PASS，见 §4.2.1：正常/SQLi 请求事件正确、SQLi risk=CRITICAL 且 final_action=OBSERVE、client_ip=真实客户端、源站响应零影响、抓包统计齐全；HTTPS 不可解密与 TPACKET_V3 环缓冲列为已知边界） |
| D | 透明串接模式：TPROXY PoC → 桥接安装脚本 → 故障直通测试 | 串联检测阻断正确；kill 进程流量直通（PoC 已实测 22/22 PASS，见 §4.3.1：正常请求 200、SQLi 403+阻断页、日志 client_ip=真实客户端（PROXY 协议上报）、源站视角回源语义与反代一致且 XFF 携带真实客户端、kill -TERM/-9 均 fail-open 直通且重启恢复检测；TPROXY 源地址保持与 HTTPS 终结列为已知边界） |

模式切换与既有「软件 bypass」联动：任何阻断模式下可一键 bypass 透传排障。

## 六、与现有设计的关系

- 请求处理顺序（AGENTS.md）在反代/路由模式保持一致；透明模式在牵引点之后等价；
  镜像模式无阻断环节，顺序中「记录访问日志和安全事件」保持。
- 网口排序不改变 AGENTS.md 既有约定，新增接口管理页遵循既有权限/审计纪律。

## 七、页面配置网桥与路由牵引（server 侧通道）

将路由牵引（§4.1）与透明串接（§4.3）所需的三层/二层网络前置配置产品化到管理页：
用户在页面创建网桥（如 br0 串接 eth2/eth3）、配置 ip_forward 与牵引路由，由网关
节点 netmgrd 组件在宿主机执行落地。

### 7.1 通道与契约

- **下发**：server 把期望配置**原子写**共享卷 `/var/run/caddy/sidecars/network.json`
  （同目录临时文件 + rename；api 容器该目录可写，网关节点 netmgrd 读取执行）。
  与 mirrorcap/tproxyd 边车同一共享卷、同一原子写纪律。
- **回执**：netmgrd 执行后回写同目录 `network-status.json`；server 只读原样透传给
  前端（文件不存在/解析失败 → status=null，不视为接口错误，解析失败记 Warn）。
- **持久化**：期望配置按节点存 `node_network_configs` 表（迁移 000065，
  `node_name` 主键、`config JSONB`、`updated_at`），供页面回显与重发。

`network.json`（bridges/routes 可为空数组，updated_at 由 server 生成）：

```json
{"bridges":[{"name":"br0","ports":["eth2","eth3"]}],"ip_forward":true,"routes":[{"dst":"10.9.0.0/24","via":"192.168.50.1"}],"updated_at":"..."}
```

`network-status.json`（netmgrd 回写，server 只读）：

```json
{"applied_at":"...","ok":true,"bridges":[{"name":"br0","state":"ok|error","message":"..."}],"ip_forward":"ok|error|skipped","routes":[{"dst":"...","via":"...","state":"ok|error","message":"..."}],"message":"..."}
```

### 7.2 接口与权限

| 接口 | 权限 | 说明 |
|------|------|------|
| `GET /api/v1/gateway/network-config?node_name=` | `system_health.read` | 返回 `{desired, status}`；node_name 缺省默认节点；非默认节点 status 恒为 null（状态属本网关共享卷） |
| `PUT /api/v1/gateway/network-config` | `system_settings.update` | body 为配置段（node_name 可选，缺省默认节点）；校验 → 存库 → 原子写 network.json → 审计 |

写操作审计：`module=system`、`action=update_gateway_network_config`、风险 **MEDIUM**
（网络变更）；边车写入失败记录 FAILURE 审计并返回 500（不静默吞掉）。

### 7.3 校验与安全约束（网络配置属高危操作，接口层强制执行）

| 规则 | 约束 |
|------|------|
| 桥名 | 必须匹配 `br\d{1,2}`（br0-br99）且节点内唯一 |
| 成员口数量 | 每桥 ≥2 且 ≤32；桥总数 ≤32；路由总数 ≤128 |
| 成员口存在性 | 全部存在于该节点网口清单（gateway_node_interfaces）且 `present=true` |
| **管理口禁入桥** | `role=MANAGEMENT` 的接口禁止加入桥——防止桥接误配置锁死管理通道 |
| 跨桥唯一 | 同一接口不得出现在两个桥（同一桥内也不得重复） |
| 路由合法性 | `dst` 必须为合法 CIDR 且节点内不重复；`via` 必须为合法 IP |
| 仅默认节点可写 | sidecar 卷属于本网关节点，写非默认节点即错配执行端，一律 400 |
| updated_at | 由服务端生成，客户端传入按未知字段拒绝（请求体 DisallowUnknownFields） |

Copyright © 聚信得仁
All Rights Reserved.
