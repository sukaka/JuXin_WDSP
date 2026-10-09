# NG-BASE-02 契约冻结：覆盖 / 阻断资格 / 执行结果 / 节点能力 / 快照水位（ADR-0007）

> 任务来源：docs/WDSP_API_WAF_NEXTGEN_RD_PLAN.md §15.2 NG-BASE-02；前置事实见 NG-BASE-01-baseline.md。
> 状态：v0.1 冻结稿（2026-10-03）。本文件是设计契约，不是已实现代码；字段名/枚举值在首个实现阶段（S1）落码前允许评审微调，微调必须回写本文件并升 `contract_version`。
> 兼容性原则：新字段在旧读取端可忽略；但**写侧（发布）必须经能力协商**，旧节点缺少必需能力时发布失败，不允许「忽略未知字段后继续 PROTECT」。

## 1. 决策记录（ADR）

| # | 决策 | 理由与约束 |
|---|------|-----------|
| ADR-1 | 五个逻辑对象以**版本化 JSON 契约**承载，经现有发布链/事件链扩展传输；不新建平行策略系统 | 复用不可变快照 + 内容摘要 + 节点确认既有机制（RD_PLAN §4.1） |
| ADR-2 | `CoverageObservation` 独立于攻击 Finding，**永不贡献攻击分数**；独立于 `api_runtime_events.details_json` 存放（新通道/新表，S1 定物理形态） | 防止「覆盖不完整」「依赖不可用」信号被决策引擎误升为 BLOCK（RD_PLAN §3.2 既有陷阱） |
| ADR-3 | 阻断资格（EnforcementEvidence）采用**显式资格 + 版本化增量接入**：仅新模块按本契约取资格；旧检测器保留既有路径并以黄金样本回归 | 不得一次重写全部旧检测器（RD_PLAN §4.4） |
| ADR-4 | 决策优先级维持现状 `BLOCK > TEMP_BLOCK > RATE_LIMIT > MASK_RESPONSE > OBSERVE > ALLOW` | NG-BASE-01 D1 已复核 |
| ADR-5 | 双轨规则生命周期状态机**不存在**，本契约不引用；「发布生命周期」仅用 RD_PLAN §4.3 的 `DRAFT → VALIDATED → SHADOW → CANARY → ACTIVE` 信息性标注，挂在现有发布记录上扩展，不新增策略实体 | NG-BASE-01 D2 |
| ADR-6 | 故障语义按 RD_PLAN §4.5 矩阵：服务端故障不映射 401，依赖故障不伪装 403；`UNKNOWN / DEPENDENCY_UNAVAILABLE / NOT_SUPPORTED / LIMIT_EXCEEDED` 为一等公民状态 | 可用性语义与安全性语义分离 |
| ADR-7 | 时间敏感语义全部携带 `issued_at / valid_until / lease_seconds`；跨节点时钟偏差超限时禁止启用时效型严格保护（上限值 S1 冻结，候选 30s） | RD_PLAN §14.3 |
| ADR-8 | reason code 采用命名空间枚举并固定：`COV_* / AUTHZ_* / FLOW_* / CAP_* / EXEC_* / MCP_* / ID_*`；明确为产品内部码，不冒充行业标准 | RD_PLAN §13.3 |

## 2. 字段字典

### 2.1 CapabilityManifest（节点能力清单）

节点在接入/心跳时自报；管理面把它与「本次发布所需能力」做**集合包含**校验（不比版本字符串）。

| 字段 | 类型 | 约束 |
|---|---|---|
| `contract_version` | string | 本契约文档版本（如 `ngc/0.1`），不一致即拒绝协商 |
| `node_id` | string | 注册节点 ID（现有节点注册体系） |
| `product_version` | string | 信息性；不作为能力判定依据 |
| `build_digest` | string(sha256) | 网关二进制摘要 |
| `protocols` | object | `{"http": {"levels":["1.1","2"]}, "graphql": {"level":"off\|parse\|cost_v1"}, "grpc": {"level":"frame\|unary_g1\|stream_g2"}, "mcp": {"level":"observe\|acl_v1"}}`；未知键忽略 |
| `detectors` | array<{name, version}> | 检测器命名空间 + 契约版本（如 `{"name":"authzdecide","version":"az/1"}`） |
| `actions` | array<string> | 支持动作：`block,temp_block,rate_limit,mask_response,observe,allow,grpc_error,mcp_error` |
| `limits` | object | `{"max_grpc_frame_bytes":…,"max_graphql_ast_nodes":…,"max_decompress_ratio":…,…}` 实际生效值 |
| `generated_at` | RFC3339 | 节点本地时钟；仅展示用 |

规则：发布负载中携带 `required_capabilities`（同构子集）；节点缺任一必需项 → 该节点发布失败并展示缺口（`CAP_MISSING:<key>`）；不得静默降级。

### 2.2 CoverageObservation（覆盖观测）

| 字段 | 类型 | 约束 |
|---|---|---|
| `request_id` | string(64) | 现有请求关联号 |
| `application_id` | uuid | — |
| `endpoint_key` | string | 现有端点键（模板化，不含原始参数） |
| `detector` | string | 命名空间检测器（如 `graphql.cost_v1`） |
| `phase` | enum | `request\|response` |
| `scope_declared` | object | 声明的检查范围：`{bytes,messages,fields,direction}`；仅检查首帧时 messages=1 且 direction 如实 |
| `status` | enum | `FULL\|PARTIAL\|SKIPPED\|ERROR\|NOT_APPLICABLE` |
| `reason_code` | string? | SKIPPED/ERROR/NOT_APPLICABLE 必填：`COV_DISABLED / COV_RULE_UNSELECTED / COV_CAPABILITY_MISSING / COV_DEPENDENCY_UNAVAILABLE / COV_INPUT_TRUNCATED / COV_PARSE_ERROR / COV_NA_FROZEN_RULE / COV_UPSTREAM_REJECTED / COV_PIPELINE_DISABLED` |
| `bytes_examined` | int | 实际检查字节数（截断时 < scope_declared.bytes） |
| `truncated` | bool | — |
| `policy_version` | string | 生效策略摘要 |
| `node_id` | string | — |
| `occurred_at` | RFC3339 | — |

聚合维度：应用 × 端点模板 × 协议 × 方向 × 检测器 × 策略版本 × 节点 × 分钟窗，组合设上限（超限归 `other` 桶并计丢弃）。指标口径按 RD_PLAN §5.2（`E=FULL+PARTIAL+SKIPPED+ERROR`；`E=0` 显示「无适用流量」）。

### 2.3 EnforcementEvidence（阻断资格）

| 字段 | 类型 | 约束 |
|---|---|---|
| `subject_trust` | enum | `JWT_VERIFIED\|MACHINE_SIGNED\|NONE`；请求体/普通头声明一律 NONE |
| `tenant_id / principal_id / role` | string | 来自已验证身份链；HMAC 域隔离 |
| `evidence_source` | enum | `MANUAL_CONFIRMED\|AUTHORITY_SYNC\|HISTORY_INFERRED`；最后一类**永远不具备阻断资格** |
| `snapshot_version` | string | 关系/策略快照摘要 |
| `snapshot_watermark` | object | 见 2.5；用于撤销边界举证 |
| `rule_id / rule_version` | int / string | 命中规则与其版本 |
| `determination` | enum | `DETERMINISTIC\|PROBABILISTIC`；只有 DETERMINISTIC 可具备资格 |
| `eligibility` | enum | `ELIGIBLE\|NOT_ELIGIBLE` |
| `ineligible_reason` | string? | `AUTHZ_SUBJECT_UNTRUSTED / AUTHZ_SNAPSHOT_STALE / AUTHZ_RELATION_CONFLICT / AUTHZ_SCOPE_MISMATCH / AUTHZ_EVIDENCE_INFERRED / AUTHZ_MODEL_NOT_APPLICABLE` |
| `unknown_policy_ref` | string? | UNKNOWN 时按端点已批准策略引用（默认继续既有防护，不伪称越权） |

### 2.4 ExecutionOutcome（执行结果）

| 字段 | 类型 | 约束 |
|---|---|---|
| `candidate_action` | enum | 决策候选（检测器提交） |
| `final_action` | enum | 统一决策输出（决策优先级见 ADR-4） |
| `executed_action` | enum | 实际执行（协议不支持/已转发时可降级，必须如实记录） |
| `protocol_status` | object | `{"http_status":403}` 或 `{"grpc_status":"PERMISSION_DENIED"}` 或 `{"jsonrpc_error":{code,message}}` |
| `forwarded_to_origin` | bool | 请求是否已到达源站（阻断断言的第一证据） |
| `bytes_forwarded` | int | 已转发字节（流式/部分转发时 >0 即不可撤回） |
| `failure_reason` | string? | `EXEC_PROTOCOL_UNSUPPORTED / EXEC_ALREADY_STREAMED / EXEC_ADAPTER_ERROR` |
| `evidence_refs` | array<string> | 关联 Finding/覆盖/授权记录 ID |

不变量：**计划阻断 ≠ 已阻断**；`executed_action=allow 且 forwarded_to_origin=true` 的条目永远不得展示为「已拦截」。

### 2.5 SnapshotWatermark（快照水位）

| 字段 | 类型 | 约束 |
|---|---|---|
| `relation_version` | string | 关系内容摘要（现有 ModelVersion 扩展） |
| `revocation_watermark` | uint64 | 单调递增撤销水位；普通策略回滚不得使其下降 |
| `issued_at / valid_until` | RFC3339 | 签发/失效时间 |
| `lease_seconds` | int | 节点租约（规划目标 ≤60，验收目标 ACK P99 ≤5s，见 RD_PLAN §8.3） |
| `node_applied` | map<node_id,{applied_at, ack_at, relation_version, revocation_watermark}> | 节点应用与 ACK 事实；未 ACK 节点及最大陈旧窗口必须可见 |

规则：`PreviousValid` 回退只允许落到「仍有效且 revocation_watermark 不下降」的快照；恢复授权必须走重新授权流程并产生新审计。

## 3. 兼容样本（v0.1，供 S1 落码时对照）

### 3.1 CoverageObservation：gRPC 仅完成首帧检查

```json
{
  "request_id": "9bfdcc4b-ed2d-4fda-b421-e9420cf5ae44",
  "application_id": "31f65aed-0cd6-423e-a5aa-119c1273686f",
  "endpoint_key": "grpc://shop.example.com/shop.OrderService/Get",
  "detector": "grpc.frame_g1",
  "phase": "request",
  "scope_declared": {"bytes": 1048576, "messages": 1, "fields": ["*"], "direction": "request"},
  "status": "PARTIAL",
  "reason_code": "COV_INPUT_TRUNCATED",
  "bytes_examined": 262144,
  "truncated": true,
  "policy_version": "pol-9f2c1ab7",
  "node_id": "gateway-baremetal-01",
  "occurred_at": "2026-10-03T08:00:01Z"
}
```

### 3.2 EnforcementEvidence：历史推断来源不具备阻断资格

```json
{
  "subject_trust": "JWT_VERIFIED",
  "tenant_id": "t-7f3a", "principal_id": "u-9c21", "role": "member",
  "evidence_source": "HISTORY_INFERRED",
  "snapshot_version": "authz-51cd0e22",
  "snapshot_watermark": {"relation_version": "authz-51cd0e22", "revocation_watermark": 118, "issued_at": "2026-10-03T07:59:00Z", "valid_until": "2026-10-04T07:59:00Z", "lease_seconds": 60, "node_applied": {"gateway-baremetal-01": {"applied_at": "2026-10-03T07:59:04Z", "ack_at": "2026-10-03T07:59:05Z", "relation_version": "authz-51cd0e22", "revocation_watermark": 118}}},
  "rule_id": 1001001, "rule_version": "az/1",
  "determination": "DETERMINISTIC",
  "eligibility": "NOT_ELIGIBLE",
  "ineligible_reason": "AUTHZ_EVIDENCE_INFERRED",
  "unknown_policy_ref": "endpoint-default:continue-observe"
}
```

### 3.3 ExecutionOutcome：计划阻断但响应已部分转发

```json
{
  "candidate_action": "block",
  "final_action": "block",
  "executed_action": "observe",
  "protocol_status": {"http_status": 200, "note": "stream_already_started"},
  "forwarded_to_origin": true,
  "bytes_forwarded": 131072,
  "failure_reason": "EXEC_ALREADY_STREAMED",
  "evidence_refs": ["fnd-88a1", "cov-51f2"]
}
```

## 4. 兼容与演进策略

1. `contract_version` 以 `ngc/<major>.<minor>` 演进；major 不兼容变更必须经发布门禁拒绝旧节点。
2. 读取端忽略未知字段；写侧（策略发布/关系导入）严格校验白名单字段。
3. 数据库演进采用 expand → migrate → contract；兼容窗口结束前不删旧字段。
4. 落码时物理表名/迁移编号按现有 schema 顺延（当前最大 000167），不预占。
5. 本契约与 RD_PLAN §4.4 的映射：CapabilityManifest→2.1、CoverageObservation→2.2、EnforcementEvidence→2.3、ExecutionOutcome→2.4、SnapshotWatermark→2.5；任何与 RD_PLAN 的偏离以本文件为准并回写 RD_PLAN（标注修订日期）。

## 5. S1 衔接清单（进入 S1 前必须闭环）

- [ ] 本契约评审签核（研发负责人 + 安全负责人）。
- [ ] reason code 枚举全文冻结（本文件 §2 各表 + RD_PLAN §13.3 合并去重）。
- [ ] `CoverageObservation` 物理存储方案（新表 vs 复用统计存储）按容量评估确定（RD_PLAN §13.1）。
- [ ] `required_capabilities` 在现有发布负载中的嵌入点确认（gatewayconfig 快照结构评审）。
- [ ] 时钟偏差上限值冻结（候选 30s）。
