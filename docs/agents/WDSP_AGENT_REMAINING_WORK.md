# 九章 WDSP 分布式 Agent 流量采集系统 — 剩余工作交接文档

**版本：V1.0（2026-09-02）**
**用途：交接至其他开发环境继续实施。上游设计：docs/agents/WDSP_DISTRIBUTED_AGENT_DESIGN.md**

## 0. 一句话现状

设计文档 §59 的 Phase 1-5 已完成开发；Phase 5（Kubernetes Sensor）新增链路断言已通过，完整端到端套件共 77 项并已连续两遍 PASS；Phase 6/7 未开始。

## 1. 已完成内容索引（全部在工作树，未提交 git）

| 阶段 | 内容 | 位置 |
|------|------|------|
| Phase 1 MVP | 注册/AF_PACKET 抓包/端口过滤/五元组/传输/心跳/metrics/管理页/策略下发/Fail-Open | `wdsp-agent/`、`server/internal/agents/`、`web/src/pages/traffic-agents/` |
| Phase 2 生产基础 | eBPF/TCX 后端、Buffer/限速/重连、策略版本+回滚、健康评分、证书 PoP 认证（mTLS 等价）、统一信封 | 同上 + `server/migrations/000108-000111` |
| Phase 3 HTTP Sensor | TCP 双向重组、请求/响应关联、L0-L3、Body 硬上限、脱敏（离主机前）、API 资产联动、7 天保留清理 | 同上 + `server/migrations/000112-000113` |
| Phase 4 智能采集 | 定向采集提升规则（TTL）、确定性采样、背压自动降级链 | 同上 + `server/migrations/000114` |
| Phase 5 Kubernetes Sensor | in-cluster 元数据同步、flow/HTTP 富化、服务端持久化与管理端展示、DaemonSet/RBAC、假 kube-apiserver 验收 | 同上 + `wdsp-agent/internal/k8smeta/`、`deployment/kubernetes/`、`server/migrations/000115` |

**契约文档（开发必须逐字遵守，已冻结）：**
- `docs/agents/WDSP_AGENT_PHASE1_CONTRACT.md`（机器端点/管理端点/资源红线）
- `docs/agents/WDSP_AGENT_PHASE2_CONTRACT.md`（策略版本/健康评分/证书 PoP §7-12）
- `docs/agents/WDSP_AGENT_PHASE3_CONTRACT.md`（HTTP Sensor/脱敏/Body 红线）
- `docs/agents/WDSP_AGENT_PHASE4_CONTRACT.md`（定向规则/背压链/采样）
- `docs/agents/WDSP_AGENT_PHASE5_CONTRACT.md`（**已冻结并实现**，见 §3）

**验收设施：`test/wdsp-agent-e2e/`**（run.sh 一键编排：PG/Valkey 容器 + 假 kube-apiserver + 真实管理后端 + privileged Agent 容器真实 AF_PACKET 抓包 + poptool PoP 工具，共 77 项断言）。**任何后续阶段的验收都必须扩展该脚本并保持既有断言全绿（连续两遍 PASS 才算完成）。**

**数据库迁移已用到 `000115_traffic_agent_k8s_metadata`**；后续阶段先确认 migrations 目录最大编号再取用。

## 2. 重要纪律（延续执行）

1. 机器端点（`/api/v1/agents/*`）线格式为裸 JSON + `{"error":{...}}`，**不可改**（wdsp-agent transport 依赖）；管理端点为仓库统一信封 `response.Body`。
2. 脱敏必须在 Agent 侧、数据离主机前完成（唯一出口 `wdsp-agent/internal/httpsensor/emit.go`）。
3. Agent 纯旁路：代码中不得出现任何向网卡回写报文的能力；任何内部错误只降级不退出。
4. 所有 Queue/Buffer/Body/带宽必须有硬上限（设计 §68）。
5. 每阶段 = 契约先行（冻结）→ 三线并行（agent/server/web）→ e2e 扩展 → 连续两遍 PASS。
6. 版本锁定：不引入未经登记的依赖；wdsp-agent 当前直接依赖仅 gopacket v1.1.19、cilium/ebpf v0.22.0、golang.org/x/sys。
7. 镜像禁止 latest；自研镜像不虚构已发布 digest。

## 3. Phase 5（Kubernetes Sensor）— 已完成

**契约：`docs/agents/WDSP_AGENT_PHASE5_CONTRACT.md`。** 已实现：

- **Agent 侧**（`wdsp-agent/internal/k8smeta`，新建）：
  - stdlib-only kube-apiserver 客户端（**不引入 client-go**）：in-cluster 检测（KUBERNETES_SERVICE_HOST/PORT + serviceaccount token/ca.crt）；
  - 30s 全量同步 pods（fieldSelector=spec.nodeName，Running）与 endpoints（分页 500 续传）→ IP→{namespace,pod,workload}、IP→service 映射；atomic 快照，查询 O(1)；失败保留旧表 Warn（fail-open）；
  - workload 启发式：ReplicaSet 名去掉 Deployment 哈希后缀（注明局限）；
  - flow 事件与 HTTP 记录 emit 时附加 `k8s` 块（dst/server 侧优先，`side` 标注 src|dst；未命中/非 K8s 缺省 omitempty）；
  - config：`k8s.enabled`（auto/on/off）、`K8S_CLUSTER_NAME` env。
- **Server 侧**：迁移 `000115_traffic_agent_k8s_metadata`（两表各加 `k8s jsonb NULL`）；/flows 与 /http 接受 k8s 块（非法忽略不拒收，确认解码无 DisallowUnknownFields）；管理端透出。
- **部署清单**（`deployment/kubernetes/`，新建）：DaemonSet + RBAC（pods/endpoints list/watch 最小只读）+ ConfigMap + README；Agent 镜像 Dockerfile（`deployment/docker/wdsp-agent/`，多阶段构建 + 锁定 digest alpine 运行时，digest 实测并注明日期）。
- **前端**：事件列表/HTTP 详情展示 namespace/pod + Tooltip 全量；无 k8s 不占位。
- **e2e**：run.sh 生成临时 TLS CA/证书并启动假 kube-apiserver，校验 ServiceAccount Bearer、分页和 Pod fieldSelector，最终断言管理端 HTTP 详情中的完整 `k8s` 块。
- **版本**：wdsp-agent `2.3.0`，Docker 构建通过 ldflags 注入同一版本。

## 4. Phase 6（Gateway Sensor）— 未开始，先写契约再实施

设计依据：§5.5 模式 E、§11.1-11.2（TLS 终止后采集/网关镜像）、§59 Phase 6。建议范围：

- **Nginx 镜像接入**（首选，成本最低）：`ngx_http_mirror_module` 把解密后请求镜像到 Agent 新增的本地 HTTP 接收端点（`internal/gwrecv`：监听 127.0.0.1:9899 之类，接收镜像请求 → 转为 HTTP 记录，`tls_visibility=DECRYPTED`，source 标记 gateway/nginx）；响应侧经 nginx 自定义 access log（JSON 格式含 status/耗时）或 mirror 无响应——契约需明确响应关联策略（建议：镜像请求 + 响应头经 `header_filter` 注入或接受响应不可关联时 response=null，如实标注）。
- **Envoy/Ingress**：Envoy tap 或 contrib 的 mirror 配置样例 + 同一接收端点；Ingress-nginx 复用 Nginx 方案。
- **事件标识**：`tls_visibility=DECRYPTED`（§11.4 枚举已有该值）；flow 五元组用镜像请求携带的真实 Client IP（X-Forwarded-For 解析 + 可信代理约定，与网关侧 jiuzhang_guard 真实 IP 口径对齐）。
- **部署样例**：`deployment/gateway-sensor/`（nginx mirror 配置片段、docker-compose 示例、README）。
- **e2e**：agent 容器内起 nginx（锁定版本）做 TLS 终止 + mirror 到 agent 接收端点 → 断言 HTTPS 请求以 DECRYPTED + 明文 Body 入库。
- 风险点：mirror 只镜像请求不含响应 Body——产品口径必须在契约中明确（建议 Phase 6 接受"请求明文 + 响应元数据"，响应 Body 属后续）。

## 5. Phase 7（高性能）— 未开始，需真实压测环境

设计依据：§6（AF_XDP/Zero Copy/Multi Queue/CPU Affinity/Batch）、§50（500Mbps→1Gbps+）、§62（压测矩阵 100/300/500M/1G）。要点：

- AF_XDP 后端（第三采集后端，复用 capture.Backend 接口与 auto 回退链）；建议评估 cilium/ebpf 生态或自研 syscall（保持依赖克制）。
- 多队列 RSS + CPU affinity、批量外发（HTTP 批与 WDP1 帧批已有基础）。
- **性能数字必须先压测后公布**（设计 §50 红线）：需 Linux 裸机/大规格 VM + pktgen/DPDK-trafficgen 环境，macOS/Docker Desktop 无法给出有效数字——若新环境无此条件，Phase 7 只交付代码与压测方案（`test/performance/` 脚本），数字留空待测。
- eBPF snaplen 与 HTTP Sensor 的关系已在 Phase 3 标注（L1+ 建议 AF_PACKET/AF_XDP 全帧后端），Phase 7 应一并解决大帧重组。

## 6. 设计文档中尚未排期的尾部能力（P2，设计 §71）

- 消息总线接入（§46，Kafka/NATS/Redpanda——现有吞吐暂不需要）
- 多 Receiver 集群 + LB（§45/§53，1000 Agent 场景）
- HTTP/2 / gRPC / WebSocket 帧解析（§36-38）
- 按 Tag 的策略扇出（§28）、多租户贯穿（§29）
- Traffic Visibility Score（§65 数据质量页）、§64 流量源页面（SPAN/CLOUD_MIRROR 等其他源登记）
- Agent 自动升级通道（§42，签名验证+回滚）
- AI 联动（§32，消费筛选后安全上下文——不得进 Packet 热路径）

## 7. 接手检查清单

1. `cd server && go build ./... && go test ./internal/agents/ -count=1` 全绿
2. `cd wdsp-agent && go test ./... -count=1` 全绿 + `GOOS=linux GOARCH=amd64/arm64 CGO_ENABLED=0 go build ./cmd/agent` 通过
3. `cd web && npm run typecheck && npx vitest run src/pages/traffic-agents src/api` 全绿
4. `cd test/wdsp-agent-e2e && ./run.sh` → 77/77 PASS（需 Docker；2026-09-02 已连续两遍通过）
5. 确认 `server/migrations/` 最大编号（Phase 5 已占用 000115）
6. 通读 5 份契约 + 本文档再动手；新阶段先写契约（放 docs/agents/，命名 WDSP_AGENT_PHASE{N}_CONTRACT.md）

## 8. 已知未修复问题与限制（如实移交）

- **aiorchestrator WIP**：工作期间曾被并行任务修复；若新环境 `go build ./cmd/api` 失败且错误指向 `ResolveContextualMessage`，是无关 WIP，e2e 快照 shim 机制（run.sh 内）可兜底。
- **老 Agent（Phase 1 Bearer-only）不自动补证书**：需管理员重新注册（Phase 2 契约 §12 已声明）。
- **apiassets 无 source/agent_id 字段**：API 资产联动的 AGENT 来源归因只能经 `agent_http_events.agent_id` 关联查询（Phase 3 已声明）；要真标记需 apiassets 侧加列。
- **eBPF 后端 snaplen ≤4096**：大帧 payload 不完整时 HTTP 重组回退 flow 行为（Phase 3 README）；L1+ 完整采集用 AF_PACKET。
- **HTTP/1.1 pipelining 乱序不支持**（按到达顺序配对，Phase 3 已注明）。
- **背压降级/恢复时序**为观察项（30s 迟滞×级数）；2026-09-02 首轮 Phase 5 全量回归曾因环境时序未在 90s 内观察到既有 `DEGRADED + backpressure_cap`，随后完整套件连续两遍 77/77 PASS，确认属于偶发环境抖动。
- 工作树大量未提交修改含无关 WIP（其他并行工作），**提交时注意区分归属**；`wdsp-agent/`、`server/internal/agents/`、`test/wdsp-agent-e2e/`、`web/src/pages/traffic-agents/`、`deployment/kubernetes/`（待建）为本项目产出。
