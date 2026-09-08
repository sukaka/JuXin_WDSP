# 裸机网关性能调优指南（通用 x86/ARM 平台 + 10G 光模块）

> 本文档配套脚本 `ops/install/tune-gateway-baremetal.sh`（安装器 `--tune N` 选项内部调用它）。
> 万兆吞吐实测留待物理环境复测（沿用 docs/NETWORK_MODES_DESIGN.md 既定惯例），
> 本文给出目标档定义、逐项调优依据与验收方法；本次交付未在物理万兆环境实测。

## 一、适用范围与平台矩阵

适用于 **WAF 与 WDSP 产品线的裸机网关主机（systemd 形态）**，即按
`docs/BARE_METAL_GATEWAY_DESIGN.md` 部署的网关节点；容器形态的网关不经过本调优
（容器内不可改宿主机内核/网卡参数）。

平台矩阵与 `docs/DEPENDENCIES.md` 的双架构交付说明衔接：

| CPU 平台 | 架构归一 | OS |
|----------|----------|----|
| Intel Xeon、AMD EPYC | amd64 | CentOS / RHEL / Rocky / AlmaLinux / Ubuntu / Debian / Anolis / openCloudOS 等主流发行版 |
| 海光 C86、兆芯 KX/KH（含 KH-40000） | amd64（x86-64 兼容，不单独出包） | 麒麟 V10 / 统信 UOS / openEuler |
| 鲲鹏、飞腾 | arm64 | 麒麟 V10 / 统信 UOS / openEuler |

内核建议 **≥4.19**：`tcp_congestion_control=bbr` 需要 ≥4.9，麒麟 V10、
openEuler 20.03+ 内核均满足；脚本应用前会读取
`/proc/sys/net/ipv4/tcp_available_congestion_control`，不含 bbr 时跳过该项并告警，
不影响其余调优项。

## 二、性能目标档

三档 HTTP 吞吐目标（经网关、CRS 规则开启的过检流量），安装时用 `--target N` /
`--tune N` 选择，缺省 6：

| 档位 | HTTP 吞吐目标 | 硬件前提 |
|------|--------------|----------|
| 6 | ≥6 Gbps | ≥16 核（同 NUMA）、内存 ≥32G、10G 网卡 ≥4 队列 |
| 8 | ≥8 Gbps | ≥24 核（同 NUMA）、内存 ≥64G、10G 网卡 ≥8 队列 |
| 10 | ≥9.5 Gbps（近线速） | ≥32 核（同 NUMA）、内存 ≥64G、10G 网卡 ≥16 队列（MSI-X） |

注意：**Coraza/CRS 规则复杂度会显著影响实测值**。上表以典型策略（CRS 默认规则集、
PL1）为基线；CRS 全开（PL3/PL4）或大量自定义正则时 CPU 消耗成倍上升，实测值以
物理环境复测为准（见「验收方法」）。

## 三、逐项调优说明

### 3.1 CPU governor 与 NUMA 亲和

- **为什么**：`powersave`/`schedutil` governor 在突发流量下升频有毫秒级延迟，
  直接反映为尾时延抖动；国产平台（鲲鹏/海光）跨 NUMA 访存代价高，网卡中断与
  网关进程落在不同 NUMA 节点会显著拉低吞吐。
- **怎么设**：全部核 `scaling_governor=performance`（幂等，无 cpufreq 的虚拟机
  自动跳过）；网卡 MSI-X 中断绑定到该网卡所在 NUMA 节点的本地 CPU
  （读 `device/numa_node` + `device/local_cpulist`，读不到降级为本机全部 CPU 并告警）。

### 3.2 网卡链路确认与 ring buffer

- **为什么**：10G 光模块协商成千兆（模块/光纤不匹配、对端自协商异常）是最常见的
  「调优无效」根因；ring buffer 过小在突发下直接驱动层丢包（`ethtool -S` 可见
  rx_missed/errors 增长）。
- **怎么设**：脚本按 `/sys/class/net/<if>/speed == 10000` 自动发现接口（发现不到
  需 `--iface` 显式指定并先排查链路）；`ethtool -G <if> rx N tx N`，
  N = min(档位预设, 网卡上限)，预设 6/8 档 4096、10 档 8192，上限从 `ethtool -g`
  的 Pre-set maximums 读取。

### 3.3 TSO/GSO/GRO 与 LRO

- **为什么**：TSO/GSO/GRO 把分段/聚合卸载给网卡或软聚合，降低 CPU 拷贝与协议栈
  开销，万兆下是必开项。**LRO 在网桥/透明代理模式下必须关**：LRO 在驱动层把多个
  TCP 段聚合成超大帧，桥接/转发路径会把聚合帧原样转发，导致对端收到内容被改写的
  报文、桥接转发异常（透明/路由/网桥模式见 docs/NETWORK_MODES_DESIGN.md）；纯反代
  终结 TCP 的场景虽不受此影响，但同一脚本要覆盖三种部署形态，统一关闭。
- **怎么设**：`ethtool -K <if> tso on gso on gro on lro off`。

### 3.4 队列数与中断合并

- **为什么**：多队列网卡只有队列数 ≥ 处理核数才能吃满多核；中断合并（adaptive）
  在低负载时省 CPU、高负载时自动放大聚合窗口。
- **怎么设**：`ethtool -L <if> combined N`，N = min(NUMA 本地核数, 网卡最大
  combined 队列数，`ethtool -l` 读取；读不到则跳过并告警）；
  `ethtool -C <if> adaptive-rx on adaptive-tx on`（不支持的驱动告警跳过）。

### 3.5 MSI-X IRQ 绑核与 irqbalance 处置

- **为什么**：中断默认均衡散布在全机 CPU 上，跨 NUMA 的中断处理带来远端访存；
  irqbalance 周期性重均衡会冲掉手工绑核。
- **怎么设**：从 `/sys/class/net/<if>/device/msi_irqs/`（其次 /proc/interrupts）
  枚举 IRQ 号，把 `/proc/irq/<n>/smp_affinity_list` 按 NUMA 本地 CPU 列表轮转
  写入。irqbalance 在运行时脚本**不擅自停系统服务**，仅打印建议：运维二选一——
  `systemctl disable --now irqbalance`，或在 `/etc/sysconfig/irqbalance`
  配置网卡 IRQ ban；已知悉仍要保留时用 `--keep-irqbalance` 抑制建议。

### 3.6 sysctl 参数（/etc/sysctl.d/99-jiuzhang-gateway-tuning.conf）

| 参数 | 含义 | 6 档 | 8 档 | 10 档 |
|------|------|------|------|-------|
| net.core.somaxconn | listen 队列深度（accept  backlog） | 32768 | 65535 | 65535 |
| net.core.netdev_max_backlog | 网卡收报协议栈排队深度 | 65536 | 131072 | 262144 |
| net.core.rmem_max / wmem_max | socket 缓冲区上限 | 67108864（64M） | 134217728（128M） | 268435456（256M） |
| net.ipv4.tcp_rmem | TCP 读缓冲 min/default/max | 4096 87380 67108864 | 4096 87380 134217728 | 4096 87380 268435456 |
| net.ipv4.tcp_wmem | TCP 写缓冲 min/default/max | 4096 65536 67108864 | 4096 65536 134217728 | 4096 65536 268435456 |
| net.ipv4.tcp_max_syn_backlog | 半连接队列 | 65536 | 131072 | 262144 |
| net.ipv4.tcp_tw_reuse | TIME_WAIT 复用（出站侧） | 1 | 1 | 1 |
| net.ipv4.ip_local_port_range | 出站源端口范围（反代回源需要） | 10240 65535 | 10240 65535 | 10240 65535 |
| fs.file-max / fs.nr_open | 系统/进程级 fd 上限 | 2097152 | 4194304 | 8388608 |
| net.netfilter.nf_conntrack_max | 连接跟踪表容量 | 1048576 | 2097152 | 4194304 |
| net.ipv4.tcp_congestion_control | 拥塞控制算法（内核支持时） | bbr | bbr | bbr |

平台差异注意点：

- **nf_conntrack_max**：纯反代形态默认不加载 conntrack 模块，此时该键由内核忽略，
  写入无害；若主机另有防火墙/NAT 规则加载了 conntrack，万兆流量下默认表容量
  （常为 262144）会打满丢包，故按档预置。
- **bbr**：对 10G 光链路 + 跨地域回源的长肥管道收益明显；内核不支持时脚本跳过
  并告警，不强制（麒麟 V10 SP3、openEuler 20.03+ 及 RHEL/CentOS 8+、Ubuntu 20.04+
  等主流发行版内核均已内置）。
- **Intel Xeon**：ixgbe/i40e/ice 驱动对多队列与 adaptive 中断合并支持良好，
  按档位默认值执行即可；超线程开启时 NUMA 本地核数按逻辑核计，绑核结果天然覆盖。
- **AMD EPYC**：BIOS 的 NPS（NUMA per socket）设置直接影响绑核效果——NPS1 时
  整槽为单 NUMA 节点，绑核可简化；NPS2/NPS4 时务必确认网卡实际所在节点
  （脚本按 sysfs 的 numa_node 自动处理，但需在验收时复核）。
- **兆芯 KH-40000**：无 AVX2，单核吞吐偏低（见 docs/DEPLOYMENT.md 多架构小节），
  同档建议核数上浮 50%；海光 C86 的 TLS 指令路径与 Intel 不同，HTTPS 占比高时
  以实测为准。

### 3.7 Caddy/反代侧说明

现有默认配置（Caddy 2.11 + 自动 GOMAXPROCS、HTTP/2）可支撑 6G 档，无需改代码
生成器。10G 档建议仅在发布侧把 upstream keepalive 连接池调大（Caddyfile
`reverse_proxy` 的 `keepalive` 相关项），**本次仅作文档建议，不改配置生成器**；
待物理环境复测确认瓶颈后再评估是否纳入生成器默认值。

## 四、验收方法（留待物理环境复测，本次未实测）

按两步走，先排除链路/光模块问题，再验证网关过检吞吐：

**第一步：iperf3 裸 TCP 双向打流**（不经过网关，直连源站或对打）：

```bash
# 服务端
iperf3 -s
# 客户端（≥8 并发流，双向）
iperf3 -c <server-ip> -P 8 -t 30
iperf3 -c <server-ip> -P 8 -t 30 -R
```

判定：双向均 **≥9.4 Gbps**。不达标先查光模块/光纤/自协商（`ethtool <if>` 看
Speed=10000Mb/s、`ethtool -S <if>` 看误码），链路问题解决前不调网关。

**第二步：wrk2 过网关压测**（≥2 台压测机，后端为静态页源站，网关启用目标档
对应的典型 CRS 策略）：

```bash
# 每台压测机（-R 固定请求速率，逐步加压至目标档）
wrk2 -t16 -c512 -d120s -R 20000 --latency https://<gateway-ip>/<static-page>
```

判定标准（建议值）：

- HTTP 吞吐达目标档 **±5%**（6 档 ≥5.7 Gbps 过检流量，10 档 ≥9.0 Gbps）；
- 全程 **无 5xx**、无连接错误；
- **p99 时延 ≤ 50ms**（静态页、局域网内回源；HTTPS 或 CRS 全开时可放宽至 100ms，
  以复测记录为准）。

## 五、运维说明

### 5.1 回滚

```bash
# 1) 摘除 sysctl 调优并还原内核默认值（重启或逐项 sysctl 恢复）
rm -f /etc/sysctl.d/99-jiuzhang-gateway-tuning.conf
sysctl --system
# 2) 停用开机重放
systemctl disable --now jiuzhang-gateway-tune-nic.service
rm -f /etc/systemd/system/jiuzhang-gateway-tune-nic.service /opt/jiuzhang-gateway/tune-nic.sh
systemctl daemon-reload
# 3) 网卡 ring/offload/队列与 IRQ 亲和性如需立即还原，重启网卡或整机即可
#    （ethtool -G/-K/-L 均为运行态设置，重启后恢复驱动默认）
# 4) 移除落档
sed -i '/^JIUZHANG_GW_TUNE_TARGET=/d' /etc/jiuzhang-gateway/install.env
```

### 5.2 与升级的关系

- 调优产物全部带管理标记 `jiuzhang-managed: perf-tuning`，网关升级流程不触碰；
- 重复执行调优脚本（换档位）幂等：sysctl 文件、unit、辅助脚本按标记覆盖重写，
  install.env 中 `JIUZHANG_GW_TUNE_TARGET` 原地更新；
- 档位核对用 `tune-gateway-baremetal.sh --target N --check`（只读，不一致逐项
  输出并 exit 1），可纳入巡检。
