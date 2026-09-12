# wdsp-agent — 九章 WDSP 分布式流量采集边缘 Agent（Phase 1-5）

旁路流量采集 Agent：在 Linux 主机上通过 AF_PACKET 或 eBPF/TC 只读抓包，提取五元组流元数据，
经 TCP 双向重组还原 HTTP/1.1 请求/响应（状态码、时延、Header/Body，脱敏后）并经 HTTPS
上报 WDSP 管理后端（TLS 仅标记可见性，不解密）。

- 冻结契约：`docs/agents/WDSP_AGENT_PHASE1_CONTRACT.md`（§3 机器端点、§6 本地行为）、
  `docs/agents/WDSP_AGENT_PHASE2_CONTRACT.md`（§7-§12 机器身份证书与 PoP 认证）、
  `docs/agents/WDSP_AGENT_PHASE3_CONTRACT.md`（HTTP Sensor：采集等级/脱敏/Body 限制）、
  `docs/agents/WDSP_AGENT_PHASE4_CONTRACT.md`（智能采集：定向提升/背压降级/策略采样）
- 上游设计：`docs/agents/WDSP_DISTRIBUTED_AGENT_DESIGN.md`（TASK-001~009/012）

## 红线

- **纯旁路只读**：代码中不存在任何向网卡写报文的能力（AF_PACKET 仅收包路径；
  eBPF 程序恒 `TC_ACT_OK`，不丢包/改包，TCX 摘钩后无残留）。
- **Fail-Open**：所有抓包/解析/外发 goroutine 均 recover 保护；任何内部错误只降级
  （停抓、转缓存、丢弃计数）不退出进程；Agent 崩溃/断线不影响业务流量（旁路天然保证）。
- **硬上限**：内存队列 10000 flow 事件 / 2048 HTTP 记录 / 10000 RAW 帧或 64MB；
  磁盘缓存默认 512MB / 单段 16MB / 单事件 30 分钟；单方向 Body 采集默认 256KB
  （硬上限 10MB，超限截断不驻留）；重组连接表 4096。
  出站数据通道令牌桶限速（默认 100Mbps）。不允许任何无限队列/缓存。

## 构建

直接依赖：`github.com/google/gopacket v1.1.19`（与 gateway 锁定一致）、
`github.com/cilium/ebpf v0.22.0`（Phase 2 eBPF 后端，MIT 许可证）、
`golang.org/x/sys v0.45.0`（AF_PACKET 自研句柄 unix 调用，D-06 起转为直接依赖，
与 gateway 一致），其余全部标准库。
`go.mod` 锁定 `go 1.25.6`；间接依赖 `golang.org/x/net v0.48.0`
（gopacket/cilium-ebpf 传递依赖，由 MVS 决定）。
CGO_ENABLED=0 纯静态构建（eBPF 字节码以 go:embed 内嵌，运行时不需要 clang）。

```bash
cd wdsp-agent

# 开发构建（本机）
go build ./...

# 发布构建 linux/amd64（纯静态、裁剪符号）
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build \
  -trimpath -ldflags="-s -w -X main.version=1.0.0" -o wdsp-agent ./cmd/agent

# linux/arm64
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build \
  -trimpath -ldflags="-s -w -X main.version=1.0.0" -o wdsp-agent-arm64 ./cmd/agent

# 校验
go vet ./...
go test ./... -count=1
```

非 Linux 平台可编译运行，但抓包为桩模式（仅控制通道：注册/心跳/配置），用于开发调试。

## 机器身份证书与 PoP 认证（Phase 2-B，契约 §7-§12）

应用层证书持有证明（Proof-of-Possession），安全目标等价 mTLS 且与部署拓扑无关：
私钥不出 Agent、请求级签名防重放、证书可撤销可轮换。Bearer credential 仍是回退通道。

### 证书生命周期

1. **签发**：`enroll` 自动生成/复用 ECDSA P-256 密钥对（已存在且可用则复用），
   生成 CSR（**CN 留空**，由服务端填 agent_id）随注册请求 `csr_pem` 上送；
   服务端签发证书（TTL 90 天）后保存三件套并进入 PoP 模式。
2. **认证**：持有有效证书时，**全部机器端点**（heartbeat/metrics/config/ack/flows/
   packets/rotate-cert）自动携带 PoP 三头（与 Bearer 同时发送，三头一体，签名失败
   则不发出请求）：
   - `X-WDSP-Agent-Cert`：客户端证书 DER 的 base64（标准编码）；
   - `X-WDSP-Agent-Timestamp`：Unix 秒；
   - `X-WDSP-Agent-Signature`：base64(ECDSA/SHA256 签名)，签名串逐字节为
     `POP\n<METHOD>\n<PATH>\n<TS>\n<hex(SHA256(body))>`（空 body 也算哈希；
     PATH 仅请求路径，不含 host/query）。
3. **轮换**：证书存活期过半（TTL/2，90 天证书即 45 天）后，控制循环每个心跳周期
   检查并自动 `POST /api/v1/agents/{id}/rotate-cert`（新密钥对+CSR，用**当前证书**
   PoP）；成功后原子替换 agent.key/agent.crt/ca.crt 并更新 agent.json 的
   `cert_expires_at`；失败按 1s→60s 指数退避重试，旧证书到期前持续可用。
4. **过期**：证书过期后 PoP 自动停用并回退 Bearer（rotate-cert 仅接受 PoP 认证，
   过期证书无法自举轮换），日志 WARN 提示需管理员重新注册。

### 文件清单（状态目录，默认 `/var/lib/wdsp-agent/`）

| 文件 | 权限 | 内容 |
|------|------|------|
| `agent.key` | 0600 | ECDSA P-256 私钥（SEC1 PEM），永不离机 |
| `agent.crt` | 0644 | 客户端证书 PEM（CN=agent_id，TTL 90 天） |
| `ca.crt` | 0644 | traffic-agent CA 证书 PEM（供未来 https 切换校验服务端，当前不强制） |

`agent.json` 增量字段 `cert_expires_at`（RFC3339，omitempty；空=Bearer 模式）。
`enroll`/`run` 均支持 `--state-dir` 覆盖状态目录（默认 `/var/lib/wdsp-agent`）。

### 兼容性

- **老服务端**（不识别 `csr_pem`）：enroll 响应证书三字段为 null，Agent 按 Bearer
  模式正常运行并日志说明，行为与 Phase 1 完全一致。
- **老 Agent**（Phase 1 注册、无证书的 agent.json）：照常以 Bearer 模式运行；
  **不自动补证书**（rotate-cert 仅接受 PoP，老 Agent 无 token 也无法重新 enroll），
  需管理员在 UI 触发重新注册方可升级 PoP 模式（契约 §12 如实声明的限制）。
- **防降级**：服务端对"PoP 头存在但无效"一律 401 不降级；Agent 侧持有有效证书时
  绝不省略任何 PoP 头，证书过期时宁可完全不发（回退 Bearer）也不发残缺签名。

## 抓包后端（Phase 2）

两种后端，统一抽象为 `capture.Backend`（Start/Close/SetPorts/KernelStats），
消费管线（解码过滤→flow→事件）完全一致：

| 后端 | 机制 | 内核要求 | 权限 |
|------|------|----------|------|
| `afpacket` | AF_PACKET raw socket + 用户态端口/方向过滤 | 任意 Linux | `CAP_NET_RAW`（混杂需 `CAP_NET_ADMIN`） |
| `ebpf` | TC 层 TCX link 逐网卡挂 ingress+egress，内核态 TCP/端口初筛，ring buffer 上送 | ≥ 6.6（TCX）、内核 BTF（CO-RE） | `CAP_BPF` + `CAP_NET_ADMIN`（或 root） |

### 后端选择与回退（Fail-Open）

配置 `capture.backend`：`afpacket | ebpf | auto`（默认 `auto`）。两处来源，
本地 agent.json `capture_backend` 显式值优先，其次服务端策略
`policy.capture.backend`（Phase 2 追加字段）：

- `afpacket`：直接使用 AF_PACKET；
- `ebpf` / `auto`：先尝试 eBPF，**任何**加载/挂载失败（无 BTF、权限不足、
  内核 <6.6、TCX 不可用）自动回退 AF_PACKET，`slog.Warn` 记录原因，
  并随心跳 metrics 上报 `capture_backend=afpacket` 与
  `backend_fallback_reason`（omitempty 追加字段，服务端可忽略）。
  进程绝不因 eBPF 失败退出或影响业务流量。

### AF_PACKET 接收完整性与截断快速失败（D-06）

pcapgo.EthernetHandle 的接收缓冲等于接口 MTU，TSO/GSO/GRO 聚合超帧
（实测 5116B+）会被 recvmsg 静默截断，且其 fd 私有、无法调大 SO_RCVBUF。
为此 AF_PACKET 后端改用自研句柄（`capture/eth_linux.go`，纯 syscall、
CGO_ENABLED=0，语义与 pcapgo 一致）：

- 单帧接收缓冲 64KB（覆盖最大 GRO 超帧），`SO_RCVBUF` 目标 4MB
  （优先 `SO_RCVBUFFORCE`，无 CAP_NET_ADMIN 时回落普通 SO_RCVBUF，
  回读生效值记日志）；PACKET_AUXDATA + SO_TIMESTAMPNS（回落 SO_TIMESTAMP）。
- **截断检测**：PACKET_AUXDATA 携带线上真实长度，`OrigLen > 实际捕获字节数`
  即判定截断（eBPF 后端 snaplen 钳制同语义），`capture.Stats.Truncated` 与
  心跳 `truncated_frames` 计数。
- **快速失败**：含截断包的连接重组流永久缺段（旁路无重传），httpsensor
  立即终止该连接并补发 `response=null` 记录（含正在读取 Body 的 inflight
  请求与配对队列残余，精确一次），不再干等 ~90s 空闲冲刷；flow 事件不受影响。

eBPF 后端安全语义：C 程序恒返回 `TC_ACT_OK`，任何路径不丢包/改包；
TCX link 为 fd 生命周期，进程退出（含异常崩溃）内核自动摘钩，无残留。

### eBPF 程序要点（internal/ebpfcapture/）

- **挂点**：TC ingress + egress 两个 hook，单实例覆盖多网卡（逐 ifindex 挂载；
  单网卡/单方向失败降级继续，全部失败才判定后端不可用回退）。
- **内核初筛**：非 TCP（含 IPv6 扩展头、双层 VLAN）不上送；端口集合为
  BPF hash map（key=u16 主机序端口），用户态两阶段热更新（先加后删，无全丢窗口）；
  方向（ingress/egress/both 语义）仍由用户态共享 filter 判定，与 AF_PACKET
  路径单一语义源；TC 挂点方向（RX/TX）随事件带给用户态。
- **事件**：ring buffer（默认 4MB，2 的幂可调），定长头 24B
  （ts ktime ns / ifindex / orig_len / cap_len / dir）+ 变长帧字节。
- **snaplen**：默认 2048（覆盖完整 MTU1500 帧 1514B），agent.json
  `capture_snaplen` 可调，钳制 [128, 4096]。HTTP 嗅探的 16KB 窗口是
  flow/httpparse 流重组后的累计量，单包无需 16KB；ringbuf 吞吐 ≈ 事件数×
  事件字节数，snaplen 越大高 pps 下越容易满（丢事件），故上限收敛 4096。
- **背压与丢包**：ringbuf 满时内核丢事件，C 程序累加 `capture_stats[1]`
  （dropped）计数 map；用户态周期读取并入心跳 `kernel_drops`。
- **时间戳**：ktime（CLOCK_MONOTONIC）经 /proc/uptime 基准换算墙钟
  （基准不可读时退化为收到时间）。

### eBPF 程序再生成

生成产物（`tccapture_bpfel.go/.o`、`tccapture_bpfeb.go/.o`）已提交，
日常 `go build` 无需 clang。修改 `tc_capture.c` 后在锁定版本容器内再生成：

```bash
cd wdsp-agent
internal/ebpfcapture/generate.sh   # golang:1.25.6-bookworm + clang/llvm/bpftool/libbpf-dev
# 容器内 bpftool 现取 vmlinux.h（CO-RE，不入库）；bpf2go 与 go.mod 同版本 v0.22.0
# 生成环境无法直达 deb.debian.org 时：APT_MIRROR=mirrors.aliyun.com internal/ebpfcapture/generate.sh
```

冒烟（需 privileged Linux 环境，不进常规测试套件）：

```bash
docker run --rm -i --privileged -v "$PWD":/src -w /src golang:1.25.6-bookworm \
  go test -tags ebpfsmoke ./internal/ebpfcapture/ -run TestSmokeTCXRingbuf -v -count=1
```

### 偏离声明

任务书表述 "TC clsact 挂载"。因直接依赖限定 `github.com/cilium/ebpf`
（不引入 netlink 库），而 clsact qdisc 挂载必须构造 netlink tfilter 消息，
实现采用官方替代方案 **TCX**（bpf_link，同为 TC 层 ingress/egress 挂点，
内核 ≥6.6），并额外获得 fd 生命周期自动摘钩的 Fail-Open 收益；
不满足 TCX 的内核由 auto/ebpf 模式自动回退 AF_PACKET。

## HTTP Sensor（Phase 3，契约 §2-§5/§8）

`internal/httpsensor`：TCP 双向流重组 + HTTP/1.1 完整解析 + 请求/响应关联，
参照 gateway/mirrorcap 的 tcpassembly 工厂模式（本 module 独立实现，不 import gateway）。

### 重组与关联

- gopacket tcpassembly 双方向工厂；每条连接 c2s/s2c 两个半流各一条
  `tcpreader.ReaderStream` + 消费 goroutine，`LossErrors=true`（镜像丢包显式失败，
  不无限等待缺失字节）；重组器乱序页缓冲硬上限（约 15MB）。
- HTTP/1.1 keep-alive 多对请求按**到达顺序**配对（不支持 pipelining 乱序——契约 §8）；
  一对请求/响应只上报一次；响应未捕获/连接关闭/超时 → `response=null`、
  `response_ts`/`latency_ms` 为 null。
- **回退红线**：解析失败/非 HTTP 的流静默回退为既有 flow 事件行为（不产生 HTTP 记录、
  不报错、不 panic）；flow 层独立运行不受影响。
- **死锁纪律**：响应侧等待配对设有上限（pairGrace 100ms）——tcpreader 是无缓冲通道，
  消费停滞会阻塞重组器；超时按协议违例回退。
- **截断快速失败（D-06）**：抓包层标记 `Truncated` 的包到达时，连接立即回退并
  补发 `response=null`（finalize 接管 inflight/reqCh，与正常配对路径精确一次），
  不计入 90s 空闲冲刷等待。
- 资源护栏：连接表 4096（超出拒绝并排空）、单连接待配对请求 128 条、
  Header 存储 16KB/消息、单行 32KB、头部块 256KB（超出=协议违例回退）。
- 时间戳语义：`request_ts`/`response_ts` 取消息解析时刻（毫秒精度），
  `latency_ms` 为其差值（旁路近似，非首字节到达时刻）。

### 采集等级（契约 §2，替换 Phase 1 过渡口径）

| 等级 | 语义 |
|------|------|
| `L0` | 仅 flow 元数据事件（request 事件含请求行三元组）——Phase 1 行为 |
| `L1` | L0 + 请求/响应 Header（脱敏后），无 Body |
| `L2` | L1 + Body（受上限与内容类型约束） |
| `L3` | L2 + RAW 包通道（`output.mode` 未含 RAW 时自动附加 RAW 通道） |

- `capture_level` 经既有 config 热更管道即时生效；空/非法值按 L0（保守）。
- 生效等级 ≥ L1 的流停发旧 `event_type=request` 事件（HTTP 记录替代），
  `flow_end` 保留；Phase 4 起按流生效等级判定（基础等级 → overrides 提升 →
  背压帽压制，见「智能采集」）。
- 仅 `tls_visibility=PLAINTEXT` 的流产出 HTTP 记录；密文流仍只走 flow 事件通道。

### Body 限制（契约 §4 硬红线）

- 单方向上限 `limits.max_body_size`（默认 262144=256KB，硬上限 10485760=10MB，
  策略超硬上限按 10MB 截；Agent 侧 `config.Limits.EffectiveMaxBodySize` 钳制）。
- **Body 永不超上限驻留内存**：超限截断（`body_truncated=true`）+ `original_body_size`
  记原始长度（Content-Length 或实际重组长度）；截断后剩余字节边读边丢，
  保持 keep-alive 流字节对齐，继续跟踪至响应结束。
- 内容类型白名单才采 Body：`application/json`、`application/x-www-form-urlencoded`、
  `text/*`、`application/xml`、`application/javascript`、`application/graphql`；
  其余不采（`body_skipped_reason=content_type`，大小照记）。
- `multipart/form-data`：不采本体，尽力提取字段/文件元数据摘要
  （`{"multipart":{"fields":{...},"files":[{"filename","content_type","size"}]}}`，
  字段值过 params 脱敏）；解析失败 `body_skipped_reason=content_type`。
- 压缩响应：gzip/deflate 尝试解压后按白名单处理（解压输出同样钳在上限内）；
  br 及其他编码直接 `body_skipped_reason=encoding`；解压失败同 `encoding`。
- Header 存储总量钳 16KB/消息。

### 脱敏（契约 §5，离主机前强制执行）

策略 `masking` 段（可整体缺省=契约默认值，服务端不补齐缺省段）：

```json
"masking": {
  "headers": { "mode": "MASK", "names": ["authorization","cookie","set-cookie","x-api-key","proxy-authorization"] },
  "params":  { "mode": "MASK", "names": ["password","passwd","pwd","token","access_token","refresh_token","secret","api_key","apikey"] }
}
```

- `mode`：`NONE`（不脱敏）| `MASK`（`********`）| `HASH`（`sha256:<hex 前16位>`）|
  `DROP`（Header 整行删除/参数删除）；mode 非法回落 MASK（Agent 侧防御）。
- 匹配大小写不敏感；params 覆盖 query string、form 字段、JSON Body 一级字段
  （**嵌套 JSON 不递归**——Phase 3 限制，契约 §5）。
- **无旁路**：所有 HTTP 记录唯一构造出口为 `httpsensor.conn.emit` →
  `buildRequest/buildResponse`，脱敏内联完成；transport/agent 发送路径
  不接触未脱敏数据，服务端收到的即为脱敏后数据。

### HTTP 记录上报（契约 §3/§10）

- 机器端点 `POST /api/v1/agents/{id}/http`（认证同 Phase 1/2：Bearer 或 PoP）。
- 每批 ≤100 条且序列化后 ≤8MB（`events.HTTPBatcher` 自动分批；单条超 8MB 的极端
  记录独占一批放行，由服务端取舍）；响应 202 `{"accepted": n}`，500 整体转缓存补传。
- HTTP 记录接入既有内存队列/磁盘缓存/限速/补传管道；缓存记录带单字节类型标签
  （`F`=flow 事件、`H`=HTTP 记录，无标签旧缓存按 flow 事件兼容解析）；
  限速/队列压力优先级：**flow 事件 > HTTP 记录 > RAW**。
- 旧服务端无此端点（404）→ 降级为 L0 行为并 WARN，不再重试该端点
  （不进入缓存补传死循环，404 批次直接丢弃计数不缓存）。
- 记录格式见契约 §3 示例（`flow_id`/`request_ts`/`response_ts`/`latency_ms`/
  五元组/`direction`/`tls_visibility`/`request`/`response`）。

### eBPF 后端与 L1+ 采集的适配注意

eBPF 后端单事件截取受 `capture_snaplen` 限制（默认 2048，硬上限 4096），
**大于 snaplen 的帧 payload 不完整**，重组会命中显式丢包错误使该连接回退为
flow 事件行为。需要完整 HTTP 采集（L1+）的部署建议使用 AF_PACKET 后端
（`capture_backend=afpacket`，全帧捕获）。

## 智能采集（Phase 4，契约 §2/§3/§4）

生效等级单点决策链（`agent.effectiveRank` + flow 包 FlowState）：

```
基础等级（策略 capture_level，/http 404 降级为 L0）
  → 定向规则 max 提升（overrides，只升不降）
  → 背压降级帽 min 压制（帽变化不修改策略、不产生 config ACK 失败）
  → 采样过滤（建流时判定，同流一致；采样外 flow 仅发 flow_end 计数）
```

### 定向采集规则（overrides，契约 §2.2/§2.4）

- config 响应新增顶层字段 `overrides`（未过期规则全量；旧服务端无此字段按空数组），
  随策略热更整表替换，**不重启抓包**；规则快照随 agent.json 持久化。
- 匹配条件（多字段 AND）：`dst_ip`（IP/CIDR，v4/v6）、`dst_port`、`host`
  （精确、大小写不敏感）、`uri_prefix`（≤512 字节，以 `/` 开头）。
- 两阶段求值：`dst_ip/dst_port` 在 flow 首包；`host/uri_prefix` 在请求行嗅探
  成功时即时提升该流后续采集（L0 流从当前请求起按新等级采集，已过的不补——
  httpsensor 为该方向补合成 SYN 建立重组序列基准）。
- 生效等级 = `max(基础等级, 命中规则最高等级)`（规则只升不降）；
  过期（now > expires_at）规则即时忽略并惰性清理（流表扫描同周期 Prune）。
- 红线：规则数钳 100（超出 Warn 截断）；任何规则解析失败跳过该规则不阻断采集。

### 背压自动降级链（契约 §3.1）

- 水位（流表扫描同周期采样）：内存队列深度（flow+http 事件合计占硬上限 10000
  的比例）与限速桶饱和（连续 5s 无法足额发送，令牌桶拒绝连续时长）取最大值。
- 阶梯（逐级）：`L3 → L2 → L1 → L0 → SAMPLE`；高水位 70% 触发，每水位档只降
  一级且每 10s 最多降一级（90% 危急水位不额外加速）；水位 <50% 持续 30s 逐级
  回升，每 30s 最多升一级。
- 帽语义：生效等级 = `min(策略/规则等级, 降级帽)`；SAMPLE 档 = L0 帽 + 强制
  rate=0.1 确定性采样（临时覆盖策略采样，退避结束还原策略值）。
- 状态上报：帽 < L3 时心跳 `status=DEGRADED`，metrics 增加 `backpressure_cap`
  （当前帽等级）与 `backpressure_events`（累计降级次数，只增不清零），均
  omitempty；恢复 L3 后 status 回 ONLINE。
- 与自我保护（CPU/内存停抓）的关系：自我保护触发直接到保底档（停抓仅心跳，
  既有行为不变）；背压链是资源正常但出口拥塞时的平滑降级。
- 降级帽压回 L0 时在飞的 HTTP 连接立即终止（补发 `response=null`，已采集数据
  不丢），释放重组资源。

### 策略采样（policy.sampling 落地，契约 §4）

- `sampling: {"enabled": true, "rate": 0.1}`：flow 级确定性采样
  （SHA-256(flow_id) 前 8 字节大端映射 [0,1) < rate 则采集，同流一致）；
  rate=1 等价关闭；rate≤0 或 >1 按关闭处理（管理端 400，Agent 侧防御）。
- 采样外 flow 仅保留 flow_end 计数事件（统计不丢量），不产生 HTTP 记录/RAW。

## Kubernetes 元数据（Phase 5）

- `k8s.enabled` 支持 `auto`（默认）、`on`、`off`；`auto` 仅在检测到 Pod 内
  ServiceAccount 凭据和 Kubernetes API 环境变量时启用。
- DaemonSet 通过 `NODE_NAME` 指定本节点；Agent 每 30 秒分页同步 Running Pod 与
  Endpoints，构建只读 IP 快照。同步失败保留最近一次成功快照，不中断抓包。
- flow 与 HTTP 记录在发出前按 IP 附加可选 `k8s` 块；两端均命中时取目标端，
  包含 cluster/namespace/pod/workload/service/side。未命中时不发送空对象。
- `K8S_CLUSTER_NAME` 指定稳定集群名。Kubernetes API 客户端仅使用 Go 标准库，
  不引入 client-go。

## 使用

权限按后端而定：AF_PACKET 需要 `CAP_NET_RAW`（混杂需 `CAP_NET_ADMIN`）；
eBPF 需要 `CAP_BPF` + `CAP_NET_ADMIN`（或 root）。auto 模式下 eBPF 权限/内核
不满足时自动回退 AF_PACKET（见「抓包后端」）。

```bash
# 1. 注册（一次性 Enrollment Token，由 WDSP 管理端签发，形如 wdt_<64 hex>）
#    enroll 自动生成机器身份密钥并上送 CSR（Phase 2-B），服务端签发证书后进入 PoP 模式
sudo ./wdsp-agent enroll --server https://wdsp.example.com --token wdt_<64hex>
# 自签证书实验环境可显式跳过证书校验（生产禁止）：
#   --insecure-skip-verify
# 状态目录（agent.key/agent.crt/ca.crt/buffer）可用 --state-dir 覆盖：
#   --state-dir /var/lib/wdsp-agent

# 2. 运行
sudo ./wdsp-agent run                 # 默认读 /etc/wdsp-agent/agent.json
sudo ./wdsp-agent run --config /path/agent.json --state-dir /var/lib/wdsp-agent --debug

# 3. 版本
./wdsp-agent version
```

注册成功后写 `/etc/wdsp-agent/agent.json`（0600），包含 `server`/`agent_id`/`credential`
（PoP 模式另有 `cert_expires_at`）；机器身份三件套写状态目录（见「机器身份证书」）。
Phase 1 不交付 install/systemd，二进制直接运行或自行编写 unit 文件。

## 配置示例（agent.json）

```json
{
  "server": "https://wdsp.example.com",
  "agent_id": "a3c98f51-61ab-43cb-9c73-xxxxxxxxxxxx",
  "credential": "wda_<64hex>",
  "heartbeat_interval_seconds": 15,
  "applied_config_version": 12,
  "limits": { "max_body_size": 0, "outbound_mbps": 100, "cpu_percent": 20, "memory_mb": 512 },
  "buffer": { "enabled": true, "max_size_mb": 512, "max_age_minutes": 30 },
  "capture_backend": "auto",
  "capture_snaplen": 2048,
  "cert_expires_at": "2026-12-01T00:00:00Z"
}
```

`cert_expires_at` 为 Phase 2-B 增量（omitempty），仅 PoP 模式存在；旧 agent.json
无该字段照常工作（Bearer 模式）。

无绑定策略时使用内置默认采集集：端口 `80,443,8000,8001,8080,8081,8443,8888,9000,9443`，
direction=both，output=FLOW，outbound_mbps=100。服务端下发策略（契约 §3.3）后：
接口集合或后端（`policy.capture.backend`）变化 → 重建抓包后端；端口/方向变化 →
原子热更新（AF_PACKET 句柄不重启 / eBPF 端口 map 两阶段增量同步）；
limits/buffer → 热更新限速桶与缓存上限；`desired_state=DISABLED` → 停抓保心跳。

## 本地行为（契约 §6）

- 心跳默认 15s（以服务端注册/心跳响应为准），随心跳上报 metrics
  （pps/bps/drop/queue_depth/buffer_bytes/kernel_drops/CPU/RSS，
  Phase 2 追加 capture_backend/backend_fallback_reason，
  D-06 追加 truncated_frames 抓包截断帧计数，
  Phase 4 背压降级时追加 backpressure_cap/backpressure_events）。
- 断线指数退避重连（1s→60s）；断线期间 FLOW 事件写磁盘缓存，恢复后**先补传缓存再发新数据**；
  RAW 帧不缓存（桶满/失败直接丢弃计数）。
- 自我保护：每 10s 采样进程 CPU%（/proc/self/stat 差值/核数）与 RSS；连续 3 次超阈值
  （默认 cpu 20%、mem 512MB）→ 停抓进入 DEGRADED（心跳继续）；回落至阈值 80% 以下
  连续 3 次自动恢复。
- 目录：配置 `/etc/wdsp-agent/`，状态 `/var/lib/wdsp-agent/`（`buffer/` 磁盘缓存，
  `agent.key`/`agent.crt`/`ca.crt` 机器身份三件套，Phase 2-B），
  日志 stderr（systemd journal 接管），默认 INFO。

## 目录结构

```
cmd/agent/            CLI（enroll / run / version）
internal/
  config/             agent.json 加载/保存（0600）、内置默认策略
  cert/               机器身份：P-256 密钥/CSR/证书 PEM 工具 + 轮换管理器（Phase 2-B）
  netif/              网卡发现（排除 lo，name/mac/ipv4/ipv6/mtu/speed）
  capture/            抓包后端抽象（Backend/选择回退）+ AF_PACKET 后端（linux，eth_linux.go 自研 64KB 帧缓冲句柄）+ 非 linux 桩；平台无关解码过滤
  ebpfcapture/        eBPF/TC 后端：tc_capture.c + bpf2go 生成产物（已提交）+ TCX 挂载/ringbuf 用户态
  filter/             端口集合 + ingress/egress/both 方向过滤（原子热更）
  flow/               五元组流跟踪（方向归一化、FIN/RST 关闭识别、空闲 90s 驱逐、表上限 65536；生效等级/采样按流驱动）
  httpparse/          HTTP/1.x 请求行+Host 嗅探（≤16KB）、TLS ClientHello 标记
  httpsensor/         HTTP Sensor（Phase 3）：TCP 双向重组 + HTTP/1.1 完整解析 + 请求/响应关联 + Body 红线 + 脱敏唯一出口；Phase 4 按流生效等级 AssembleLevel（中段建链补合成 SYN）
  override/           定向采集规则集（Phase 4）：IP/CIDR/端口/host/uri_prefix AND 匹配、两阶段求值、过期惰性清理、100 条钳制
  backpressure/       背压降级帽状态机（Phase 4：L3→L2→L1→L0→SAMPLE 防抖/迟滞阶梯）+ SHA-256(flow_id) 确定性采样
  events/             契约事件结构、WDP1 RAW 批量帧编解码、HTTP 记录结构与分批器（Phase 3）
  buffer/             段式磁盘缓存（16MB 段、FIFO、30 分钟、at-least-once 补传；flow/HTTP 记录带类型标签）
  ratelimit/          出站数据通道令牌桶（默认 100Mbps）
  transport/          HTTPS 客户端（契约 §3 全部机器端点 + §9 rotate-cert）+ PoP 签名注入（§8）+ 指数退避
  control/            心跳循环、配置拉取与 ACK、启用/禁用、证书轮换检查触发
  selfmon/            CPU/RSS 采样与 DEGRADED 状态机
  agent/              编排层（数据通道、补传、自我保护、抓包管理）
```

## Phase 1 边界

- Phase 1 不采集任何请求/响应 Body；**Phase 3 起** `max_body_size` 生效为
  单方向 Body 采集硬上限（默认 256KB，钳制 ≤10MB），`capture_level` L0-L3
  按契约 §2 冻结语义执行（见「HTTP Sensor」）。
- `http_status` 恒 0；TLS 流量只标记 `ENCRYPTED`，绝不声称完成 Payload 检测。
- RAW 上报服务端 Phase 1 只做校验计数丢弃，不入库。
