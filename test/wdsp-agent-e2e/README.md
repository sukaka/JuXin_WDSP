# WDSP 分布式流量采集 Agent — Phase 1-5 端到端集成验收

对应设计 `docs/agents/WDSP_DISTRIBUTED_AGENT_DESIGN.md` §60（MVP 验收场景）/ §61（故障验收）/ §73（DoD），
冻结契约 `docs/agents/WDSP_AGENT_PHASE1_CONTRACT.md`、`docs/agents/WDSP_AGENT_PHASE2_CONTRACT.md`
（Phase 2-B：机器身份证书与 PoP 认证，§7-§12）、`docs/agents/WDSP_AGENT_PHASE3_CONTRACT.md`
（Phase 3：HTTP Sensor，§2-§6）与 `docs/agents/WDSP_AGENT_PHASE4_CONTRACT.md`
（Phase 4：智能采集——定向规则/采样/背压，§2）与 `docs/agents/WDSP_AGENT_PHASE5_CONTRACT.md`
（Phase 5：Kubernetes 元数据）。在 Docker Desktop on macOS 上一键跑通
"管理后端 ↔ 边缘 Agent"全链路真实集成（非 stub、非 mock）。

## 用法

```bash
./test/wdsp-agent-e2e/run.sh
# 全部断言通过 → 输出 "WDSP AGENT E2E: PASS"（exit 0），否则列出失败项并非零退出
# 调试保留现场：KEEP_WORK=1 ./test/wdsp-agent-e2e/run.sh
# 端口冲突时覆盖：E2E_API_PORT / E2E_PG_PORT / E2E_VALKEY_PORT（默认 28080/25432/26379）
```

前置依赖（主机）：Docker Desktop（运行中）、Go 1.25+、`jq`、`curl`、`openssl`、`rsync`。
不修改 `server/`、`wdsp-agent/`、`web/` 任何代码；不执行任何 git 写操作；
编译产物、数据库、授权密钥全部在 `/tmp/wdsp-agent-e2e.XXXX` 与 Docker 容器层内，跑完自动清理。

## 拓扑

```
主机   api 二进制（快照源码 go build ./cmd/api）          127.0.0.1:28080
容器   postgres:16.4-alpine@<digest>                      127.0.0.1:25432
容器   valkey/valkey:8.1.8-alpine@<digest>                127.0.0.1:26379
网络   wdsp-e2e-net（docker bridge）
容器   wdsp-e2e-agent  = Agent 宿主：business_server.py(8000) + wdsp-agent（AF_PACKET 抓 eth0，
                        fake_kube_server.py(8443)，cap_add NET_RAW/NET_ADMIN，
                        经 host.docker.internal 访问主机管理后端）
容器   wdsp-e2e-client = 流量发起方：curl http://wdsp-e2e-agent:8000/...
                        （报文经 docker 网桥真实穿越 agent 容器 eth0）
```

镜像版本全部按 `docs/DEPENDENCIES.md` 以 multi-arch index digest 锁定（禁止 latest）。
wdsp-agent 按 Docker 架构交叉编译（`CGO_ENABLED=0 GOOS=linux GOARCH=<amd64|arm64>`，
本机 Docker 为 linux/arm64 故产出 arm64 二进制；契约 §8 双平台均支持）。

## 各断言与设计条款对应

| 步骤 | 断言 | 依据 |
|------|------|------|
| 3 | 迁移 000001→000115 全部应用（含 000115_traffic_agent_k8s_metadata） | PHASE1 契约 §7；PHASE2 契约 §1/§10；PHASE3 契约 §6；PHASE4 契约 §2.3；PHASE5 §4 |
| 6 | 管理员登录 → 首次强制改密 → 重新登录；导入临时授权解锁管理面；签发 wdt_ 一次性 token | 契约 §4 |
| 8 | `wdsp-agent enroll` 成功（自动上送 csr_pem），`GET /api/v1/traffic/agents` 可见且派生 status=ONLINE | 契约 §3.1/§5；PHASE2 §7 |
| 8b | Agent 日志「启用 PoP 认证」；状态目录三件套 agent.key(0600)/agent.crt/ca.crt 齐备；管理端详情 cert_fingerprint/cert_not_after 非 null | PHASE2 §7/§11/§12 |
| 8c | 显式创建并绑定 capture_level=L0 策略 → ACK 闭环（Phase 3 起 agent 内置默认策略为 L1，L1+ 停发旧 event_type=request 事件、由 HTTP 记录替代；步骤 9 的旧通道回归需显式 L0 恢复，L0 仅 flow 事件） | PHASE3 §2（等级冻结语义） |
| 9 | request 事件：五元组（client IP→agent IP:8000/tcp）、http_method=POST、http_host、http_uri=/api/login、tls_visibility=PLAINTEXT | 设计 §60；契约 §3.4 |
| 9 | flow_end 事件与同 flow_id 关联、bytes_in+bytes_out>0，且在连接关闭后 ≤30s 内可查（curl `Connection: close` 短连接触发双方 FIN；实测 2~3s） | 契约 §3.4「流关闭即报」；FIN/RST 关闭路径（D-01 已修复） |
| 10 | 创建策略并绑定 → `applied_config_version` 追上 `config_version`（下发+应用+ACK 闭环） | 契约 §3.3/§4 |
| 11 | PUT 策略 output.mode=FLOW_RAW → 再发流量 → `last_metrics.raw_frames_received>0` | 契约 §3.5（服务端校验/计数/丢弃） |
| 11b | PoP 直接证据（poptool 手工构造三头）：a. 无 PoP 头+正确 Bearer → 200（回退通道）；b. PoP 三头齐全但签名篡改+正确 Bearer → 401（防降级，绝不回退）；c. 手工合法 PoP（无 Bearer）→ 200（PoP 路径独立可用） | PHASE2 §8 |
| 11c | 证书轮换：仅 Bearer 调 rotate-cert → 401；旧证书 PoP → 200 签发新证书；管理端 cert_fingerprint 切到新指纹；新证书 PoP 心跳 200（即时生效）；旧证书 PoP 心跳仍 200（24h 宽限） | PHASE2 §9 |
| 11d | HTTP Sensor L2（策略 capture_level=L2 + capture.backend=afpacket + limits.max_body_size=1024，ACK 闭环）：a. POST /api/login（Authorization: Bearer abc123secret + JSON password）→ status=200、latency_ms 非空、PLAINTEXT、request.headers.authorization=`********`、body 无 `p@ssw0rd` 原文（含 `********`）；b. GET /big（5050B，TSO/GSO 全开下为超 MTU 帧）→ response 非 null、status=200、body_truncated=true、original_body_size>1024、body≤1024（D-06 修复后完整重组，非 response=null 补发）；c. POST /upload（application/octet-stream）→ request.body_skipped_reason=content_type、original_body_size 正确、body 无原文；d. GET /gz（Content-Encoding: gzip）→ body 为解压后合法 JSON 且 skipped 为空；e. `last_metrics.truncated_frames` 为 0 或缺省（零捕获截断帧）；http 记录与 flow 事件 flow_id 互查命中 | PHASE3 §2-§5；D-06 复验 |
| 11d-k8s | 假 Kubernetes API 校验 Bearer、分页与 Pod fieldSelector；HTTP 详情完整带出 cluster/namespace/pod/workload/service/side | PHASE5 §2-§4 |
| 11e | PUT capture_level=L1 → ACK 闭环 → 新流量（水位线 id 之后）记录 request/response headers 非空且 body 均为空串 | PHASE3 §2 |
| 11f | API 资产联动：`GET /api/v1/api-security/endpoints?keyword=/api/login` 出现 http_method=POST、normalized_path 含 /api/login、hit_count≥1 的资产 | PHASE3 §6（host 归因偏离见下） |
| 11g | 定向采集规则（基线策略 PUT capture_level=L0 → ACK）：a. POST override `{match:{uri_prefix:"/api/payment"},capture_level:"L2",ttl_minutes:30}` → 201，创建同事务 config_version+1 → ACK；b. GET overrides 列表含该规则且 active=true；c. 命中流量 GET /api/payment → http 记录入库且 response.body 完整（含 `ord_e2e`，基线 L0 流自请求行嗅探起即时提升 L2）；d. 未命中流量 POST /api/login → http-events 端点无新记录（提升不泄漏；L0 恢复的旧 request 事件走 events 端点，不参与本断言）；e. DELETE override → 204 → ACK → 再请求 /api/payment 无新 http 记录（回落 L0） | PHASE4 §2.3/§2.4 |
| 11h | 确定性采样（PUT sampling.enabled=true rate=0.01 + capture_level=L2 → ACK）：20 × GET /index.html 独立短连接后，水位线后新 http 记录 ≤2（rate=0.01 期望≈0.2 条；SHA-256(flow_id) 前 8 字节/2^64 < rate 判定，采样外 flow 仅 flow_end 计数事件、无 http 记录）；随后 PUT enabled=false rate=1.0 → ACK 恢复全量 | PHASE4 §2.2 |
| 11i | 背压降级与恢复（PUT limits.outbound_mbps=0.05 + L2 → ACK）：后台 100 × GET /big（5050B）持续大流量使出站桶持续拒绝（DenialStreak≥5s → 水位 1.0 → 采集帽自 L3 逐级下降），90s 内管理端详情 status=DEGRADED 且 `last_metrics.backpressure_cap` 非空（实测约 10~20s，帽=L2）；随后 PUT outbound_mbps=100 → ACK，180s 内 backpressure_cap 消失且 status 回 ONLINE（水位 <50% 持续 30s 升一级的迟滞回升；降级级数少时实测约 30~60s） | PHASE4 §2.5 |
| 12 | POST disable → Agent 日志「服务端禁用 Agent，停止抓包（心跳继续）」且管理面 status=DISABLED；disable 后重放当前（新）证书 PoP → 401（吊销即时生效） | 契约 §3.2 desired_state；PHASE2 §11 |
| 13 | 停管理后端 → 业务 curl 正常；Agent 日志「心跳失败，退避重连」（指数退避 1s→60s） | 设计 §61 WDSP Shutdown；契约 §6 |
| 14 | `kill -9 wdsp-agent` → 业务 curl（GET+POST）仍正常 | 设计 §61 Agent Kill（Fail-Open 红线） |

> 注：11c 的带外轮换由 poptool 持旧证书完成，运行中的 agent 进程仍持旧证书——其后续心跳
> 恰构成「旧指纹 24h 宽限期可用」的活证据；agent 自身自动轮换（存活期过半，45 天）在 e2e
> 时长内不可达，不做等待。

## 环境引导的实现说明（不改既有代码）

- **授权门控**：无有效授权时管理 API 全部 423（license.Gate）。`genlicense.go` 用随机一次性
  Ed25519 密钥对签发 wdsp/永久/配额不限的临时 `.lic`（与 `server/tests/license_helper_test.go`
  同口径）；管理后端使用显式 `wdsp_testkeys` 测试构建，`LICENSE_VENDOR_PUBLIC_KEY` 仅注入该
  被测进程，正式构建不会读取它，私钥不落盘。
- **管理后端 PRODUCT_EDITION=wdsp**：`/api/v1/api-security` 命名空间按产品形态门控
  （`server/internal/product/edition.go` APIDynamicProtectionEnabled：waf 形态不注册→404，
  app.go 装配处）。本验收即 WDSP 产品线，后端以 wdsp 形态启动，11f 资产联动断言走真实
  管理面路由；机器端 /http 上报与 UpsertDiscovery 联动本身不做形态门控。
- **图形验证码**：默认 `captcha_enabled=true`，脚本无法 OCR。迁移后直接 UPDATE 验收库的
  `system_settings` 关闭（settings 服务无缓存，即时生效）——属验收库配置，非代码改动。
- **api_asset.read 补授**：迁移 000100 权限重划后 `api_asset.read` 划归 SECURITY_ADMIN，
  初始管理员（SYSTEM_ADMIN）查 `/api-security/endpoints` 默认 403；迁移后在验收库向
  SYSTEM_ADMIN 补授该只读权限点（登录在授权之后，即时生效）——同属验收库配置，非代码改动。
- **源码快照编译**：server 的 `go.mod` 含 `replace ../gateway/dynamic_security`，且 Phase 1
  代码（`server/internal/agents/`、`wdsp-agent/` 等）在工作树中尚未提交，因此 run.sh 将
  `server/`、`gateway/dynamic_security/`、`wdsp-agent/` rsync 到 `/tmp` 快照后编译。
- **poptool**：`poptool/`（仅标准库的独立 Go module）是 PoP 验收调试工具，主机侧编译运行：
  `headers` 按契约 §8 用容器内拷出的 agent.key/agent.crt 手工构造 PoP 三头（`-tamper signature`
  翻转签名一字节构造防降级负例）、`csr` 生成新密钥+CN 留空 CSR（轮换用）、`fingerprint`
  计算证书 SHA-256 指纹（与服务端 `CertFingerprint` 同口径）。PoP 断言不依赖 agent 自证，
  全部由 poptool + curl 带外完成。
- **business_server.py**：Phase 3 起业务 HTTP 服务由 `python3 -m http.server` 升级为该脚本
  （HTTP/1.1 + 显式 Content-Length），提供验收端点：`/` 与 `/index.html`（沿用 'business ok'
  首页断言）、`POST /api/login`（脱敏）、`GET /big`（5050B 触发截断）、`POST /upload`
  （octet-stream 跳过）、`GET /gz`（gzip 解压）、`GET /api/payment`（Phase 4 定向提升，
  返回 `{"payment":true,"order":"ord_e2e"}`）。POST 端点读尽请求体避免连接复位影响
  flow_end 语义。
- **L2 验收固定 AF_PACKET**：策略显式 `capture.backend=afpacket`——eBPF/TC 后端 snaplen
  会截大帧，无法保证 >1KB 响应的完整重组（截断断言会失真）；契约/设计允许按后端能力选择，
  eBPF 路径由 capture 层单测覆盖。
- **TSO/GSO 全开运行（D-06 修复验收姿态）**：不对 agent 容器 eth0 做任何卸载关闭、
  business_server 不压 MSS——/big 的 5050B 单写在 docker veth 默认 TSO/GSO 下于抓包点
  聚合成超 MTU 帧，构成修复后超帧抓取能力（64KB 帧缓冲，见 D-06）的真实验收流量；
  11d 同步断言 `last_metrics.truncated_frames` 为 0 或缺省。

## 已知限制与契约偏差

- **D-01（已修复，断言已收紧）**：契约 §3.4 要求 flow_end 在「流关闭**或**空闲超时」发出。
  早期版本 `wdsp-agent/internal/flow/flow.go` 未识别 TCP FIN/RST（只有空闲超时 90s/驱逐/退出
  冲刷三条路径）；现已在 Agent 侧修复：任一侧 RST 立即发 flow_end、双方 FIN 到齐立即发、
  单方 FIN 半关闭按最后活动静默 3s 宽限、每流至多一条 flow_end、流表扫描周期 2s，
  最坏延迟约 5s。验收断言同步收紧为：curl `Connection: close` 短连接触发双方 FIN 后
  **≤30s 内**轮询到 flow_end 且 bytes>0（两次实测 2~3s 可查）。
- **D-02（已消解，shim 留作兜底）**：`server/internal/aiorchestrator` 此前存在与本验收无关的
  进行中修改（调用未实现的 `ResolveContextualMessage`），导致工作树 `go build ./cmd/api`
  失败；run.sh 会在 `/tmp` 快照内按 `orchestrator_test.go` 语义注入最小 shim 兜底（仅快照、
  不入库，且仅在编译错误特征匹配时触发）。该 WIP 现已由工作树作者补齐实现
  （`intent.go:94`），当前运行直接编译通过、shim 未触发。
- **D-03（环境约定）**：容器内 curl 访问"本容器自身 IP"在 Linux 上经 local 路由表走 `lo`，
  eth0 上无报文，无法构成 AF_PACKET 抓包证据（设计 §60 本身也是 VM-B 访问 VM-A 的双机拓扑）。
  因此采用双容器（client→agent）经 docker 网桥产生真实 eth0 流量。
- **D-04**：Agent 宿主镜像基座 `alpine:3.24@<digest>` 锁定；`apk add python3 curl iproute2`
  的包版本随 alpine:3.24 仓库快照浮动（与项目既有 Dockerfile 同一口径）。
- **D-05**：macOS Docker Desktop 的容器网络运行在 Linux VM 内，AF_PACKET 行为与裸机 Linux
  一致；`host.docker.internal` 由 Docker Desktop 提供（脚本同时注入 `host-gateway` 兼容 Linux）。
- **D-06（已修复，e2e 已撤规避并复验）**：`wdsp-agent` AF_PACKET 抓包原经
  `pcapgo.NewEthernetHandle`，接收缓冲 = 接口 MTU；docker veth 默认开启的 TSO/GSO 会把单次
  大写（/big 5050B）在抓包点聚合成超 MTU 帧（实测 5116B），被 recvmsg 静默截断且无检测 →
  tcpassembly 永久缺段（旁路无重传）→ 多段响应的 HTTP 记录拖到约 90s 空闲冲刷才以
  response=null 补发（Phase 3 首跑 /big 记录「丢失」即此因）。修复要点：AF_PACKET 句柄改
  裸 syscall 实现（64KB 帧缓冲、SO_RCVBUFFORCE 4MB、PACKET_AUXDATA + MSG_TRUNC 双通道取
  线上真实长度），DecodePacket 检测 OrigLen>CapLen 标记 `Packet.Truncated`，httpsensor 对
  截断连接立即 finalize 补发 response=null（不再干等空闲冲刷），截断帧计数
  `truncated_frames` 随心跳上报（omitempty）。复验：e2e 撤除「ethtool 关卸载 + TCP_MAXSEG」
  规避后，TSO/GSO 全开下 /big 断言（response 非 null、status=200、body_truncated=true、
  original_body_size=5050）与 `last_metrics.truncated_frames=0` 连续两遍通过；agent Linux
  冒烟 100KB 响应零截断。
- 未覆盖：磁盘缓存补传（断线期间的 buffered events 恢复重放）、token 撤销/过期负例
  （Phase 1 契约内但不在 §60/§61 验收场景主线）；PoP 头不全（仅部分头）
  → 401、过期证书/跨 Agent CN 重放、宽限期到期撤销（24h 不可等待）——后三类已由
  `server/internal/agents/pop_test.go` / `machine_handler_test.go` 单测覆盖；
  Phase 3 的 multipart 摘要、HASH/DROP 脱敏模式、嵌套 JSON 不递归限制、L3 RAW 联动、
  http 记录 7 天 sweeper 清理——由 `wdsp-agent/internal/httpsensor/` 与
  `server/internal/agents/http_*_test.go` 单测覆盖；Phase 4 的 override TTL 自然过期
  （分钟级下限 1min + agent 周期 Prune，e2e 时长内不等待）、过期规则 30 天 sweeper、
  match 多字段组合（src_ip/dst_port 等）、背压多级阶梯逐档断言（e2e 只验首档降级与恢复方向）
  ——由 `wdsp-agent/internal/agent/`、`wdsp-agent/internal/backpressure/` 与
  `server/internal/agents/overrides_test.go` 单测覆盖。
- **背压恢复时序（观察记录）**：11i 恢复段依赖「水位 <50% 持续 30s 升一级」的迟滞机制，
  耗时随降级级数变化（检测点通常在首档 cap=L2，恢复约 30~60s；若降级更深则 30s×级数），
  断言上限取 180s。降级段（DEGRADED + backpressure_cap 出现）为确定性路径
  （DenialStreak≥5s → 首档降级），实测 10~20s，作为硬断言。
- **API 资产 host 归因（已报备偏离）**：契约 §6 要求资产标记 source=AGENT + agent_id，但
  `api_endpoints` 模型无 source/agent_id 字段（apiassets 包只读参考不得修改），联动复用既有
  UpsertDiscovery 入口（`server/internal/agents/machine_http.go` 头部偏离声明）；故 11f 按
  （method, 模板化 uri）断言资产存在，host 证据由 11d http 记录自身的 host 字段承担。
