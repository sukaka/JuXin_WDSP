# WDSP Agent P1 支持矩阵与验收证据总表（G5 回归基线）

**日期：2026-09-08。上游：docs/tasks/wdsp-p1/P1-03_AGENT_GATEWAY_PROTOCOLS.md §1/§8；契约：WDSP_AGENT_HTTP_EVENT_V2_CONTRACT.md（V1.1）。**

本表逐格核对任务书 §1 支持矩阵与 §8 强制验收清单（AGT-001～028）的当前证据状态。
状态词表（与 WORKLOG 冻结一致）：PASS / BLOCKED_ENV / NOT_SUPPORTED（范围外能力如实标注）/
PARTIAL（组件层通过但真实环境证据缺口已注明）。每格引用具体证据路径 / run_id / 测试函数。

## 1. 来源与协议支持矩阵（任务书 §1 逐格）

| 来源与业务协议 | P1 承诺可见内容 | 状态 | 证据 |
|---|---|---|---|
| 现有被动 HTTP/1 采集 | 请求、可配对响应、有限正文与截断状态 | PASS | G1 可靠性增强（批次预算/严格缓存/背压公平）；`wdsp-agent` 22 包全绿（2026-09-08 复跑）；批次边界 `internal/agent/agent_p1_test.go`、`internal/events/http_test.go`；升级路径 `internal/agent/upgrade_rollback_g5_test.go:TestG5UpgradePathV1ToV2WithSpool` |
| Nginx TLS 终止后 mirror | 原请求方法/Host/路径/允许 Header/可选有限正文；仅请求 | PASS | 真实 Nginx 1.28.0-alpine（tag+digest 双锁）E2E：run `20260908T101135-51b803`（G2 首轮 PASS=11/断言 37）、G5 复跑 `20260908T151957-2396b3`（PASS=11）；证据 `test/wdsp-agent-e2e/mirror/runs/<run_id>/evidence/verify-report.md`；接入模板 `deployment/nginx-mirror/` |
| Envoy TLS 终止后 HTTP/1、HTTP/2 tap | 规范化请求与响应、来源协议、流关联、截断及部分数据 | PASS | 真实 Envoy v1.35.3（tag+digest 双锁）E2E：run `20260908T131748-c5bdf8`（G3 首轮 PASS=11/断言 34）、G5 复跑 run_id 见 §3 回归记录；证据 `test/wdsp-agent-e2e/envoy-tap/runs/<run_id>/evidence/verify-report.md`；模板 `deployment/envoy-tap/`。**单会话约束**（Admin 同时仅允许一条 tap 流）见契约附录 B |
| Envoy gRPC unary 与 streaming | 服务/方法路径、content-type、trailers 与 grpc-status、取消/未完成状态；仅元数据 | PASS（元数据级） | envoy-tap E2E S2–S6（grpc_status=0/3/14、取消不伪造成功）；取消/截止实际到达形态如实记录于 verify-report「实际到达形态」节。**不声明 Protobuf 字段解码** |
| WebSocket 经可用采集源的 HTTP 握手 | Upgrade 请求与握手响应 | PASS（仅握手视图） | envoy-tap E2E S7（101 握手）/S8（403 失败如实）；帧/消息正文不解析，页面明确不可见 |
| Kubernetes | 真实 Pod/Namespace/Node 关联及更新/失效状态 | **BLOCKED_ENV** | 本机无可用集群（kubectl 无 context、Docker Desktop K8s 未启用、kind/minikube/k3d 均未装、docker.io 不可达）。组件级等价断言已由 `wdsp-agent/internal/k8smeta` 11 个测试覆盖（状态机/条目 TTL/IP 重用差分失效/owner 权威与推断/RBAC 仅 list）；真实集群证据待具备环境后补做 |

**范围外（NOT_SUPPORTED，如实标注，不得以转码/镜像冒充）**：原生旁路 HTTP/2 HPACK 帧解析、WebSocket 帧/消息正文解析、HTTP/3/QUIC、AF_XDP 吞吐升级、gRPC Protobuf 正文解码、Agent 在线阻断。采集可见性 ≠ 网关在线防护能力。

## 2. 强制验收清单（AGT-001～028）状态

| ID | 状态 | 证据（测试函数 / run_id / 路径） |
|---|---|---|
| AGT-001 旧能力不退化、密文不伪装明文 | PASS | `wdsp-agent` 全量 22 包绿（G5 复跑）；`internal/httpsensor`、`internal/events` 测试；v1 线格式完全保留（TestHTTPLegacyServerFallbackV1、TestG5OldAgentV1OnNewServer） |
| AGT-002 真实 Nginx HTTPS 终止镜像 | PASS | mirror E2E S1/S2，runs `20260908T101135-51b803`、`20260908T151957-2396b3`（伪造 XFF 被覆盖、五元组不采信外部头） |
| AGT-003 镜像接收器状态不回填业务 | PASS | mirror E2E S3（源站 500 时记录 response 恒 null） |
| AGT-004 大/慢上传、取消、镜像故障 | PASS | mirror E2E S4–S7（8MB 截断 original_total_size=CL、适配器被杀业务 200、自拉起恢复） |
| AGT-005 Envoy HTTP/2 多路并发配对 | PASS | envoy-tap E2E S1（六流多路复用按流配对不串流，X-Rid 回显） |
| AGT-006 tap 分片/半包/乱序/重连/重启 | PASS | envoy-tap E2E S9（进程重启断连/重连计数、采集恢复）；`internal/tapsrc` 分帧器单测（括号深度状态机、单帧超限丢弃后状态机继续同步） |
| AGT-007 gRPC 非零 grpc-status | PASS | envoy-tap E2E S2/S3（HTTP 200 与 RPC 状态分列；trailers-only 并入响应头形态如实解析） |
| AGT-008 streaming/取消/截止 | PASS | envoy-tap E2E S4–S6（取消=grpc_status null+UNKNOWN 不伪造 0；截止=14 UNAVAILABLE；实际到达形态见 verify-report） |
| AGT-009 WebSocket 握手 | PASS | envoy-tap E2E S7/S8；页面明示帧未采集（web PolicyPanel/HttpEventsPanel，G4a） |
| AGT-010 转码/伪造头不冒充 | PASS | mirror S1（伪造头覆盖）；tap 协议断言仅来自部署配置（契约附录 B）；observed/original 分列 |
| AGT-011 脱敏零泄漏 | PASS | mirror/tap E2E 全局明文扫描（四类合成敏感标记零泄漏，见各 verify-report）；`internal/httpsensor` 脱敏单测 |
| AGT-012 重复头/authority 冲突/超限 | PASS | `internal/tapsrc`（伪头映射、authority 优先、重复头保序）、`internal/mirrorsrc`、server `http_events_v2.go` 校验测试 |
| AGT-013 批次 100 条/8MiB/单条超大 | PASS | `internal/events/http_test.go`（含转义边界）、`internal/agent/agent_p1_test.go`（超大三级缩减/丢弃计数、400 无死循环） |
| AGT-014 重放幂等 | PASS | TestHTTPV2RetryEventIDStable（缓存补传 event_id 不变）、server `machine_http_v2_test.go:TestHTTPEventsV2Batch`（重放全 duplicate）、psql 级 ON CONFLICT 实证（G5：二次插入 0 行受影响） |
| AGT-015 错误分类（400/401/403/429/5xx） | PASS | agent_p1_test（400 索引隔离/429 Retry-After/5xx 转缓存）、`internal/transport/http_v2_test.go`、server machine_http_v2_test（未协商 400/schema_version=3 400） |
| AGT-016 严格缓存上限 | PASS | `internal/buffer/buffer_p1_test.go`（活动段超龄/单段超量/满盘/损坏段/重启；淘汰按 size_evicted/age_evicted/corrupt 计数） |
| AGT-017 离线恢复补传公平 | PASS | `internal/agent/agent_p1_test.go:TestReplayFairnessBudget`（独立份额桶默认 30%，不饿死实时） |
| AGT-018 入口隔离与身份防伪 | PASS | mirror E2E S8（无/错/多令牌一律 403、forbidden 计数）；socket 0660（S9）；server `machine_handler_test.go:TestMachineAuthMatrix` |
| AGT-019 应用隔离与多来源 | PASS | server `machine_http_v2_test.go:TestHTTPEventsV2AssetSources`（去重键含 Host、UNASSIGNED 不 upsert、多来源各自成行） |
| AGT-020 资产关联状态分离 | PASS | 同上（LINKED/UNASSIGNED/QUOTA_REJECTED/FAILED 四态落行可查询，gRPC 不写死 REST）；管理端 `http_admin_v2_test.go:TestListHTTPAssetSources` |
| AGT-021 真实 K8s Pod 变更 | **BLOCKED_ENV** | 无真实集群（见 §1 Kubernetes 格）；组件级：`internal/k8smeta` 差分失效/TTL 测试 |
| AGT-022 K8s API 失效与 RBAC 最小 | **BLOCKED_ENV** | 同上；组件级：403→STALE→恢复、UNAVAILABLE 状态、心跳 metrics 接线测试；RBAC 收敛为仅 list（`deployment/kubernetes/wdsp-agent-rbac.yaml`） |
| AGT-023 新旧 Agent×Server 兼容 | PASS（G5） | agent 侧：TestHTTPLegacyServerFallbackV1（旧 server 无回执→纯 v1）、TestG5UpgradePathV1ToV2WithSpool（升级开通 v2）、TestG5CapabilityRevokedDowngrade（收回降 v1、适配器记录不假报不降级）；server 侧：TestG5OldAgentV1OnNewServer（v1 形状不变）、TestEnrollCapabilities/TestHeartbeatCapabilities（缺省 {1}、非法 400）、未协商 v2→400；管理端能力集展示 TestGetAgentHTTPEventSchemas（不假报启用） |
| AGT-024 覆盖到期/部分 ACK | PASS（G5 补验证） | server：TestMachineConfigOverrides（过期剔除下发）、TestOverrideSweeperCleanup、TestG5PartialACKStateSeparation（目标/生效版本分列 + config_not_synced）、TestG5ConfigAckFailedKeepsPartialState（FAILED 不回填）；agent：TestG5OverrideExpiryStopsElevation（持久化快照重启沿用、到期即时停止提升、Prune 清理）、TestExpiredRulesIgnoredAndPruned |
| AGT-025 权限/CSRF/XSS/列表上下文 | PASS | server 权限沿用 traffic.agents.view/manage（overrides/policy 测试 403 分支）；web G4a Vitest 108 文件/824 用例（含 XSS 纯文本断言与筛选分页上下文保留） |
| AGT-026 来源/缓存/丢弃独立状态 | PASS（组件层） | `internal/agent` metricsSnapshot 统一指标（received/accepted/duplicate/dropped_by_reason/spool/k8smeta_state）；AgentDetailDrawer 三段版本分离 + 资产来源 Tab（G4a） |
| AGT-027 目标源码直接构建 E2E | PASS（Nginx/Envoy） | mirror/envoy-tap E2E 均由仓库源码构建适配器镜像（Dockerfile 多阶段，无 shim）；run_id 见 §3。**真实 K8s E2E BLOCKED_ENV** |
| AGT-028 升级/回退 | PASS（G5；限制见 §4） | agent：TestG5UpgradePathV1ToV2WithSpool / TestG5CapabilityRevokedDowngrade / TestG5AdapterStopPassiveContinues / TestG5LegacyProgramDoesNotMisparseV2Cache；server：迁移 000133 真实 PG（postgres:16.4-alpine digest 锁）up→插 v1 存量行→down（旧记录可读、v2 列移除）→up（行完整、默认 schema_version=1、幂等索引重建）；任务书 §9 回退顺序（先停新来源并处理 v2 缓存再降级程序）已在本文件 §4 固化为操作纪律 |

## 3. G5 回归记录（2026-09-08）

- `cd wdsp-agent && go test ./... -count=1` → 22 包全 ok（含新增 5 个 G5 测试）；`go vet ./...` 干净。
- `cd server && go test ./internal/agents -count=1` → ok（含新增 3 个 G5 测试）；`go vet ./internal/agents` 干净。
- mirror E2E 复跑：run `20260908T151957-2396b3`，PASS=11、断言全过，证据 `test/wdsp-agent-e2e/mirror/runs/20260908T151957-2396b3/`。
- envoy-tap E2E 复跑：run `20260908T152129-c4a655`，PASS=11、记录断言全过（含 S12 V1.1 截断口径、S9 重启恢复、S10 适配器故障业务无损），证据 `test/wdsp-agent-e2e/envoy-tap/runs/20260908T152129-c4a655/`。
- 迁移回退演练：真实 PG 容器（postgres:16.4-alpine@sha256:5660c2cb…e64c）migrate up→down→up + psql 级幂等验证；容器已清理。

## 4. 已知限制（如实声明）

1. **旧程序二进制不可得**：wdsp-agent 在本仓库 git 历史中的首次提交即含 v2 代码（release 1.1.0），旧 tag 不含 agent，无法构建真实 v1 旧二进制做双程序互操作。AGT-028「旧程序不误解析新缓存」以重构的 v1 时代解析开关（F/H/缺省三分支）做实测仿真：'M' 标签记录首字节使缺省分支 JSON 解析必然失败跳过，物理上不可能误解析为合法记录；但**旧程序对纯 'M' 段的段级处置（跳过即删段）会以丢弃收场**——故任务书 §9 回退顺序为强制操作纪律：先停新来源、排空/处理 v2 缓存（新程序补传或显式计数清除），再降级程序版本。
2. **macOS 单容器回环拓扑**：mirror/envoy-tap E2E 均为 Docker Desktop 单容器回环，非多机拓扑；Envoy Admin 回环绑定属设计行为。
3. **tap 不可获得字段**：五元组 127.0.0.1:0 占位、时间戳=接收时间、latency=0、capture_stream_id=null（契约附录 B，如实不造假）。
4. **真实 K8s 两格（AGT-021/022）保持 BLOCKED_ENV**，不得由 fake Kube harness 顶替。
5. 429 语义已冻结但机器端点当前无独立限流器（契约 §4.5，本版本不引入）。
