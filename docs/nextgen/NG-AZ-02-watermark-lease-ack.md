# NG-AZ-02 撤销水位 / 租约 / 节点 ACK 冻结设计（S3 阶段 1 设计稿，2026-10-04）

> 依据：`docs/WDSP_API_WAF_NEXTGEN_RD_PLAN.md` §8.3（决策与撤销传播 1–6 条）/§8.4/§14.3（时钟漂移）/§16.3（NG-T-A01~A08）+ `docs/nextgen/NG-AZ-01-authority-ingest.md`（移交项：PreviousValid 水位约束、冲突对象决策侧排除、节点 ACK 与租约）。
> 目标：把「撤销事实」以单调水位随既有发布链传播到网关节点，节点以租约约束陈旧窗口，并经既有心跳通道回报 ACK——撤销可验证、陈旧有上界、断连/旧节点/时钟偏差全部如实可见。**本文件只做冻结设计，不含实现**；实现拆分建议见文末。
> 前置事实（NG-BASE-01 D9 / inventory 复核 2026-10-04）：
> - 签名快照现状：`GuardAuthzSnapshot{models,relations,role_baselines,object_hmac_key_hex,policy_version,stale,snapshot_expires_at}`（server/internal/gatewayconfig/guard.go:186），24h 有效期（guardconfig/authz_decision.go:154）；PreviousValid 由 `provider.loadLatestSuccessfulAuthzSnapshot`（authz_lifecycle.go:36）取「最近一次 SUCCESS 版本」授权快照克隆——**目前没有任何水位概念**。
> - 网关消费现状：`detectors.EvaluateAuthorization`（authzdecide.go:143）——当前快照 stale/过期且无可用 PreviousValid 时落 `AUTHZ-POLICY-002` UNKNOWN（fail-closed），决策枚举为 `ALLOW / OBSERVE_VIOLATION / UNKNOWN`；VERIFIED_VIOLATION 尚未存在（§8.3 兼容映射在本设计 §2.D10 定稿）。
> - 心跳通道现状（唯一 ACK 通道，架构约束：网关→管理面单向日志采集，不可新增反向 HTTP 推送）：`apiheartbeat.go` 周期 30~300s 写合成记录（heartbeat=true，含 policy_version/uptime/guard_start_time）→ `apiruntime.Collector` 识别后透传 `HeartbeatRecorder` → `apinodes.Store.RecordHeartbeat` upsert `api_gateway_nodes`（first/last_seen_at、last_policy_version、status）。
> - NG-AZ-01 已建：`api_authority_watermarks`（per-source last_sequence/revocation_watermark/gap_from）、`api_authority_conflicts`（OPEN/RESOLVED）、`api_authority_applied_events`、authority Service 的撤销水位写入路径（只增）。

## 1. 冻结契约

### 1.1 向量撤销水位（vector revocation watermark）

管理面撤销水位是**向量**，不是单一标量（各权威来源的 sequence 编号空间互相独立，混用即伪造单调性）：

```json
{
  "manual_seq": 41,
  "sources": {"<source-uuid-1>": 17, "<source-uuid-2>": 9}
}
```

- `manual_seq`：管理面既有撤销通道（手工撤销/重新授权前的废止、批量过期扫清的撤销语义）产生的单调序号（新表持久化，见 §2.D1）。
- `sources`：各权威来源 `api_authority_watermarks.revocation_watermark` 的逐来源快照。
- 比较语义：向量 A ≥ 向量 B ⇔ A.manual_seq ≥ B.manual_seq **且** A.sources 对 B.sources 的每个键都有不小于的值（缺失键视为 0）。任何分量更小即「A 低于 B」。

### 1.2 快照扩展（向后兼容，全部 omitempty 可选字段）

`GuardAuthzSnapshot` 顶层（当前与 PreviousValid 各一份）增加：

| 字段 | 类型 | 语义 |
|---|---|---|
| `schema` | string | 恒 `"authz-snap/2"`（缺省/其他值按 §2.D4 处置） |
| `revocation_watermark` | object（§1.1） | 本快照编译时刻的管理面向量水位 |
| `lease_seconds` | int | 租约秒数（per-app 维度取最小者编译入快照；§2.D5） |
| `conflicted_objects` | array | 决策侧排除集（§2.D7，有界）：`[{application_id, object_type, tenant_domain, object_ref}]` |
| `produced_at` | RFC3339 | 快照编译时刻（ACK 陈旧窗口与漂移对账的基准） |

### 1.3 心跳 ACK 扩展（apievents.Record 增加，同样可选）

`authz_policy_version`（授权快照 policy_version，区别于全局 api_policy_version）、`authz_watermark`（节点当前应用快照的向量水位）、`authz_snapshot_expires_at`、`authz_lease_seconds`、`authz_applied_at`（节点应用该快照的时刻）。空载/未启用授权快照的节点不携带这些字段（旧采集端零变化）。

### 1.4 查询 API（只读，权限沿用 `api_authorization.read`）

- `GET /api/v1/api-security/authz/node-acks`：全节点 ACK 视图——每节点 `{node_name, status, authz_policy_version, authz_watermark, authz_applied_at, last_ack_at, staleness_seconds, lease_seconds, ack_state}`；`ack_state ∈ {FRESH, STALE_WITHIN_LEASE, STALE_EXPIRED, NEVER_ACKED, CLOCK_SKEW}`；响应顶层附 `max_staleness_seconds`（最大陈旧窗口）与 `management_watermark`（当前管理面向量水位）。**§8.3-5「必须显示未 ACK 节点及最大陈旧窗口」的直接载体**。
- `GET /api/v1/api-security/authz/authorities/{id}/status` 既有端点不变（NG-AZ-01 已交付）。

## 2. 冻结决策点（D1~D10）

### D1 水位定义与持久化：向量水位 + 单例 manual_seq 计数行

- **结论**：管理面向量水位 = `{manual_seq, sources}`（§1.1）。`manual_seq` 由新表 `api_authz_manual_revocation_seq`（单行 id=1，seq bigint）承载：**每一次**既有撤销通道的关系废止（`RevokeObjectRelation`、过期扫清 `ExpireObjectRelations`、重新授权链路中的旧行废止）在**同一事务内** seq+1——撤销事实与水位推进原子提交（RD_PLAN §14.3 outbox 纪律）。权威侧 `sources` 直接读 `api_authority_watermarks`（NG-AZ-01 已保证只增）。
- **单调不下降的持久化保证**：①水位写入只允许 `GREATEST(现值, 新值)`（DB 层 CHECK + 应用层只增，与 NG-AZ-01 同纪律）；②普通策略回滚（整站配置回滚/GuardOverride 重放）**不得**重建或下调该表——回滚路径只读不写（NG-T-A05/D04 锚点）；③水位不进版本快照内容哈希（水位变化不是「配置内容」变化，而是事实推进——否则会与「回滚即哈希复原」语义冲突；水位以独立字段随快照携带，不参与 configuration_hash）。
- **理由**：手工与权威两条撤销入口编号空间不同（D1 向量化的根因）；事务内推进保证「撤销落库但水位丢失」的窗口不存在。

### D2 快照 schema 扩展方式：随快照下发（含冲突集），不建新通道

- **结论**：`schema`/`revocation_watermark`/`lease_seconds`/`conflicted_objects`/`produced_at` 全部作为 `GuardAuthzSnapshot` 顶层字段随既有发布链下发（PreviousValid 同样携带各自的水位）。**不**新建边车文件/Valkey 通道——快照已是签名、原子、有版本戳的唯一授权事实载体，第二通道必然引入「两个事实源竞态」。
- **冲突集随快照下发的取舍**：网关无 DB，决策侧排除必须以数据随行。体积上限 10000 条对象键（粗估 ≤1.5MB JSON——远小于 relations 上限 200000 对应的既有快照体量）；**超限即发布失败（fail-hard）**，绝不截断——截断等于对超限部分静默放行冲突对象（与「不静默降级」纪律一致）。冲突集来源：`api_authority_conflicts WHERE status='OPEN'`，编译时读取（读取失败中止发布，与 authz snapshot 编译同一 fail-hard 口径）。
- **理由**：单通道单事实源；冲突集是「不可信对象」语义，必须与水印水位同一份快照到达，否则存在「水位到了、冲突集没到」的穿透窗口。

### D3 PreviousValid 发布侧约束：分量比较 + 无合格候选即空

- **结论**：`loadLatestSuccessfulAuthzSnapshot` 后增加水位资格过滤——候选旧快照的 `revocation_watermark'` 必须 **≥ 发布时刻管理面水位**（§1.1 分量比较，含 manual_seq 与逐来源），且自身未过期（沿用现有 SnapshotExpiresAt 判定）。**无合格候选时 PreviousValid 为空**（不降级选旧——选了就是把已撤销许可重新下发，NG-T-A05 直接反例）。
- **发布侧单调性校验失败行为**：候选快照水位字段缺失（000172 前旧版本快照）→ 视为水位 0 参与比较——只有当管理面水位也为 0（从未有任何撤销）才合格；管理面水位非零时一律不合格。该校验失败**不中止发布**：PreviousValid 为空是合法的 fail-closed 形态（网关落 UNKNOWN），不构成发布错误；但校验过程本身的 DB/解码错误仍中止发布（基础设施 fail-hard 与 authz 编译同口径）。
- **理由**：§8.3-3「PreviousValid 仅能回退到仍有效且不越过撤销水位的快照」的构造侧实现；「无候选即空」是唯一能同时满足「撤销后回滚不恢复旧许可」与「发布不被人为卡死」的形态。

### D4 网关侧消费：节点水位记忆 + schema 闸门 + 旧节点能力门拒绝

- **结论（四层）**：
  1. **节点水位记忆**：网关在 Guard 实例持有 per-app 已应用水位（随实例整体替换）；应用新快照前比较——新快照水位 **低于** 已应用水位（分量比较）即拒绝应用并记 `AUTHZ_WATERMARK_REGRESSION` 告警事件（fail-closed，保留已应用快照；§8.3-2「不得回退到水位以前的授权快照」）。
  2. **PreviousValid 回退二次校验**：选择 PreviousValid 回退时同样要求其水位 ≥ 节点已应用水位；不满足即不落回退、落 `AUTHZ-POLICY-002` UNKNOWN（现状语义的自然延伸——无合格事实源即 UNKNOWN）。
  3. **schema 闸门**：`schema` 字段缺失或 ≠ `"authz-snap/2"` 时按「v1 快照」处理——行为与当前版本逐字节一致（零兼容回归）；新二进制对 v2 字段全量校验。
  4. **旧节点处置（NG-T-C08）**：携带 v2 快照（watermark/lease/conflicted_objects 任一非空）的发布在 `required_capabilities` 中增加 `detectors.authzdecide` 版本需求 **az/2**（S1 capability 发布门既有机制）——旧节点（自报 az/1）被发布门 fail-closed 拒绝并展示 `CAP_MISSING:detectors.authzdecide`，**不得**让旧节点在「看不见水位」的情况下静默应用新快照。capability 自报表 detectors 增列 `{Name:"authzdecide",Version:"az/2"}`（旧节点报 az/1 不变）。
- **理由**：§8.3-2/3 的节点侧执行；schema 闸门保旧二进制兼容，能力门禁旧部署形态——两层各自解决「旧代码」与「旧节点」两类对象，不互相替代。

### D5 租约语义：per-app 租约秒数 + per-endpoint 过期策略，缺省严格

- **结论**：
  - **字段与挂点**：`lease_seconds` 配置挂在 **per-app**（api_authz 策略段新增可选键；未配置 = 不启用租约约束，与 v1 行为一致）。快照内 `lease_seconds` 取该应用配置值（快照 per-app 编译，逐应用各取）。
  - **缺省值与上限**：缺省候选 60 秒、硬上限 300 秒（>上限按上限夹紧并 Warn）。**§8.3「关系租约最长 60 秒」是规划目标而非能力承诺**——文档与 UI 必须注明；下限 15 秒（防止操作员把租约压到心跳间隔的一半以下造成系统性误报）。
  - **过期判定**：节点本地时钟 `now > authz_applied_at + lease_seconds`（applied_at 由 ACK 上报，消费判定在网关本地以快照应用时刻为准——不依赖管理面时钟）。
  - **过期后两种策略（per-endpoint，挂 api_object_models 级可选标志 `on_lease_expired`）**：
    - `strict`（**缺省**）：授权决策 UNKNOWN（不做授权性放行）+ `DEPENDENCY_UNAVAILABLE` 事件标记——安全保守项即缺省项；源站最终授权校验不受影响（§8.3-6 原语义）。
    - `degraded`：继续按最后快照评估但全部产出强制 OBSERVE 级 + UNKNOWN 标记（可用性优先，明示降级）。
  - **理由**：§8.3-5 承认断连节点在租约内持旧状态——租约是对「最大陈旧窗口」的显式承诺；缺省选严格项符合「授权性放行必须有新鲜事实源」的安全底线，可用性诉求由操作员对具体端点显式选 degraded。

### D6 节点 ACK：心跳扩展字段 + 新表 000173 落库 + 只读查询 API

- **结论**：
  - **心跳扩展**（§1.3）：节点每次心跳携带当前应用授权快照的 `authz_policy_version`、向量水位、快照过期时刻、租约秒数与应用时刻。多 Guard 实例（多应用）的节点按应用逐条上报还是合并？——**合并为节点级一条**：取各应用 `min(lease_seconds)`、水位取各应用分量最小向量（最保守陈旧口径），应用明细留待后续（v1 节点级视图够用，避免心跳记录膨胀）。
  - **存储形态取舍**：新表 `api_node_authz_acks`（迁移 **000173**；`(node_name) PK`：`last_ack_at, authz_policy_version, authz_watermark jsonb, authz_snapshot_expires_at, authz_applied_at, authz_lease_seconds, clock_skew_seconds, updated_at`）。**不选 Valkey/内存**——ACK 是审计与陈旧窗口承诺的事实源，必须重启持久、可 SQL 查询、可与 api_gateway_nodes 联查（同库同事务外一致性要求低，逐拍 upsert 即可）。RecordHeartbeat 扩展为同事务 upsert 两表（api_gateway_nodes + api_node_authz_acks；仅当心跳携带 authz 字段时写后者）。
  - **采集端**：`apiruntime.Heartbeat` 结构加字段透传（旧网关无字段时零值跳过写 ACK 表——纯 v1 节点 `ack_state=NEVER_ACKED` 如实显示）。
  - **未 ACK 与最大陈旧窗口计算**（§1.4 API）：`staleness_seconds = now - authz_applied_at`（未应用过授权快照的节点不参与）；`max_staleness_seconds = max(全节点 staleness)`；`ack_state` 派生规则：NEVER_ACKED（无 ACK 行）/ CLOCK_SKEW（|skew|>上限，见 D8）/ STALE_EXPIRED（staleness > lease）/ STALE_WITHIN_LEASE（staleness ≤ lease 但水位落后管理面）/ FRESH（水位 ≥ 管理面向量水位且 staleness ≤ lease）。
  - **权限与审计**：只读沿用 `api_authorization.read`（000048 已种，SECURITY_ADMIN+AUDIT_ADMIN 持有）；无写端点、无新权限点（与 000169/000170 先例一致）。
- **理由**：§8.3-5「必须显示未 ACK 节点及最大陈旧窗口」的存储与计算落地；心跳是架构允许的唯一通道（apiheartbeat.go 头注释既定），新表是审计级持久化的最小增量。

### D7 冲突对象决策侧排除：VERIFIED_VIOLATION 判定跳过 OPEN 冲突对象

- **结论**：`conflicted_objects` 随快照下发（D2）；BOLA 评估命中冲突集内的 `(application_id, object_type, tenant_domain, object_ref)` 时：
  - 该对象的 OWNER 类判定 **UNKNOWN + `AUTHZ-CONFLICT-001`**（事实不可信如实标记），**不得**产出 VERIFIED_VIOLATION（NG-T-A03/A04），也**不得**产出授权性 ALLOW（冲突不排除干净之前，该对象没有任何可信判定）。
  - 冲突集消费是集合查找 O(1)（快照编译期建索引），键含 tenant_domain（空串 = COALESCE(tenant_id,'') 口径，与 NG-AZ-01 冲突表一致）。
  - 体积上限与超限行为见 D2（10000 条、超限发布失败 fail-hard）。
- **理由**：NG-AZ-01 §3「冲突中的对象不参与 VERIFIED_VIOLATION 判定」的决策侧落地；UNKNOWN（而非 ALLOW）避免冲突被利用为放行通道。

### D8 时钟漂移：心跳对账 + 60s 上限 + 严格授权放行禁止

- **结论**：
  - **检测**：`RecordHeartbeat` 时计算 `skew_seconds = server_now - hb.OccurredAt`（可为负），绝对值超上限即漂移（心跳时间戳即节点时钟的直接读数，无需新增探针）。
  - **上限取值**：**60 秒**（与租约缺省同量级——漂移达到租约尺度时任何时效判定都不可信；RD_PLAN §14.3 只要求「批准上限」，60s 为本设计批准候选，可配置 `authz.clock_skew_max_seconds` 系统设置覆盖，夹紧 10~300s）。
  - **处置**：漂移节点 `api_node_authz_acks.clock_skew_seconds` 记录实际值、`ack_state=CLOCK_SKEW`；该节点上 `strict` 端点**禁止严格授权放行**（UNKNOWN + `AUTHZ-CLOCK-001` 展示原因）——§14.3「跨节点时钟漂移超过批准上限时禁止启用依赖时效的严格保护，并展示原因；不能靠延长所有 Token/快照有效期掩盖问题」。degraded 端点仅如实标记不拦截。
- **理由**：漂移与租约是同一类时效信任问题；禁止放行而非放宽有效期，正是 RD_PLAN 的明确禁令。

### D9 测试计划与时延方法学：NG-T-A05/A06/A07 逐条映射 + 候选验收口径

- **结论（映射到具体测试）**：
  | 用例 | 测试（实现批交付物） |
  |---|---|
  | NG-T-A05（撤销后回退 PreviousValid） | ①构造「publish R1（含关系 X）→ 撤销 X（manual_seq+1 或权威 REVOKE 推进水位）→ 整站回滚到 R1 配置」：R1 快照水位低于管理面水位 → PreviousValid 资格过滤为空（D3）→ 网关 UNKNOWN 且 X 不恢复；②水位表在回滚前后值不变（回滚不回退撤销事实）；③手工撤销与权威 REVOKE 两臂各一遍 |
  | NG-T-A06（重新授权、重复/乱序事件） | NG-AZ-01 已覆盖重复/乱序/缺口（authority 集成套件）；本批增量：重新授权走既有 reauthorize 流程产生新审计且 manual_seq 推进、旧许可不因重放恢复 |
  | NG-T-A07（节点分区与时钟偏差） | ①分区模拟（iptables 断连或停采）：租约内节点持旧快照可评估、ACK 列表 STALE_WITHIN_LEASE；越出租约 → strict 端点 UNKNOWN、degraded 端点 OBSERVE 标记，STALE_EXPIRED 如实显示；②时钟偏差（节点容器 `faketime` 或心跳 OccurredAt 注入 ±120s）：CLOCK_SKEW 展示 + strict 端点禁止放行；③恢复分区 → 下一拍心跳 ACK 收敛 FRESH |
  | NG-T-C08（旧节点收新快照） | capability 门 E2E：az/1 自报节点发布 v2 快照 → `CAPABILITY_MISSING` 拒绝并展示缺口；az/2 节点正常应用（S1 门既有测试形态） |
  - **撤销→ACK 时延方法学（候选验收目标 P99 ≤ 5s，非承诺）**：环境=stage5 单节点、本地 Docker 网络、心跳间隔 30s→实测按 5s 心跳间隔收紧（`api_node_heartbeat_seconds=5` 属允许范围 30~300 之外吗？——不是：30 是下限。因此方法学写「心跳 30s + 发布即时触发」下测量端到端（撤销事务提交 → 发布完成 → 节点应用 → 下一拍心跳 ACK 入库），预期上界≈30s 心跳周期；**P99≤5s 的候选目标仅在「发布即应用、心跳周期 ≤5s 的部署形态」下可达**——当前心跳下限 30s 决定了 5s 目标在本部署形态下不可承诺，需在报告中如实写明这一推导）；样本 ≥500 次撤销或 ≥30min 持续窗，报 p50/p95/p99 与噪声；网络分区下不做任何时延承诺（§8.3 原文语义）。
- **理由**：三条用例分别对应「回滚不恢复」「幂等无静默覆盖」「陈旧有界可见」的验收锚点；时延目标必须带部署形态推导，不能把规划目标写成能力。

### D10 兼容与缺省：增量全可选、VERIFIED_VIOLATION 不更名、回滚不回退事实

- **结论**：
  - **NG-T-C01 兼容**：全部新字段 omitempty——无 v2 字段的配置/节点/快照行为与 v1 逐字节一致；租约未配置 = 不启用租约约束；ACK 表无行 = NEVER_ACKED 如实显示而非报错。
  - **决策枚举**：VERIFIED_VIOLATION 的引入按 §8.3「与现有 OBSERVE_VIOLATION 的兼容映射」另行契约评审，**本批不引入、不更名**——D7 的排除判定落在 UNKNOWN 词表内表达（AUTHZ-CONFLICT-001/AUTHZ-CLOCK-001），不新增决策枚举值。
  - **权限/审计**：ACK 查询只读沿用 `api_authorization.read`；租约/策略配置写入沿用 api_policy.edit（000048 体系内）；manual_seq 推进随撤销事务天然入既有操作审计（不新增审计动作类型）。
  - **回滚策略**：回滚不回退水位表/幂等账本/冲突记录（D1-②）；恢复授权必须经既有重新授权流程并产生新审计（§8.3-4 原语义，本批零改动）。
  - **OpenAPI 增量预估**：+2 操作（`GET /api-security/authz/node-acks` + node detail 增强字段不计操作）→ 对账基线 684 → 预期 686（实现批以 check-api-reconcile 实测为准）。
- **理由**：缺省零变化是新能力的进入纪律（NG-T-C01）；枚举稳定避免迁移既有消费者。

## 3. 本批不做（范围外，如实标注）

- 业务在线推送通道（与离线导入同链同模型的在线 delta；NG-AZ-01 §6 后续项）。
- 权威来源删除端点（NG-AZ-01 移交；本批清理仍走 DB）。
- 前端页面（授权页 ACK/水位/冲突展示——§8.4 界面项，后续前端批次；本批仅 API 契约）。
- VERIFIED_VIOLATION 决策枚举引入与 OBSERVE_VIOLATION 迁移（D10，另行契约评审）。
- 多应用节点的逐应用 ACK 明细（D6 合并口径）、SHADOW/CANARY 灰度（S1 任务书 §4 后续批）。
- 权威事件与 manual_seq 的统一全局序号（向量水位即最终形态，不做编号空间归一）。

## 4. 实现拆分建议（文件级边界不重叠）

**A. 决策链实现（server 快照侧 + 网关消费侧）**
- server：`server/internal/gatewayconfig/guard.go`（GuardAuthzSnapshot 顶层字段）、`server/internal/guardconfig/authz_decision.go`（水位/冲突集/lease 编译入快照 + manual_seq 读取）、`server/internal/guardconfig/authz_lifecycle.go`（D3 PreviousValid 资格过滤）、`server/internal/apiauthz/`（撤销路径事务内 manual_seq 推进）、`server/internal/apiauthzauthority/`（sources 水位读出复用）、capability 自报 az/2（gateway capability_report.go）与 required_capabilities 计算（server capability_gate.go）。
- gateway：`gateway/dynamic_security/detectors/authzdecide.go`（水位记忆比较、冲突集消费、lease 判定、CLOCK/CONFLICT reason code）、`gateway/modules/jiuzhang_guard/module.go`（per-app 水位记忆与 api_authz 段新键解析）。
- 迁移：`000173`（api_authz_manual_revocation_seq + api_node_authz_acks 可由 A/B 任一实现方落同一文件，但**不得拆成两个迁移号**）。

**B. ACK 通道实现（心跳 + 采集 + 查询 API）**
- gateway：`gateway/modules/jiuzhang_guard/apiheartbeat.go` + `apievents`（Record 扩展字段）。
- server：`server/internal/apiruntime/collector.go`（Heartbeat 透传）、`server/internal/apinodes/store.go`（RecordHeartbeat 两表 upsert + skew 计算）、新包或 apiauthzauthority 扩展 `GET /api-security/authz/node-acks`（staleness/ack_state 派生）、OpenAPI 片段登记与对账。
- 边界约定：A 不动心跳/采集/查询；B 不动快照结构/决策消费/水位写入。共享面仅为两处类型（`GuardAuthzSnapshot` 字段、心跳 Record 字段），由 A 先冻结、B 只消费。

## 5. 移交项（后续批次）

- NG-AZ-03：VERIFIED_VIOLATION 决策枚举与 OBSERVE_VIOLATION 兼容迁移（D10 契约评审结论落地）。
- 前端：授权页「来源/有效期/冲突/最后同步/节点 ACK/能否实断」展示（§8.4）。
- 性能：快照携带冲突集与水位的体积基准（200000 relations 上限形态下的发布耗时与网关加载耗时抽测）。
- 多节点 stage5 ha-lab 双节点分区演练（A07 的编排化，test/ha 既有设施复用）。

## 实现状态（2026-10-05，NG-AZ-02 A/B 轨 + 集成验收批已交付）

### 实现位置映射（D1~D10）

| 决策点 | 实现位置 |
|---|---|
| D1 向量水位 | 迁移 000173 `api_authz_manual_revocation_seq`（手工通道，撤销事务内 +1：apiauthz/relations.go Revoke/Expire）；权威侧 `api_authority_watermarks`（apiauthzauthority/apply.go，REVOKE 与 snapshot 切换推进）；水位读取/比较 `gatewayconfig.RevocationWatermarkAtLeast`（guard.go） |
| D2 快照扩展 | `GuardAuthzSnapshot`/handler JSON 顶层 v2 字段（schema/revocation_watermark/lease_seconds/conflicted_objects/produced_at，omitempty）；冲突集编译 `authz_decision.go ListOpenAuthzConflicts`（OPEN 行、上限 10000 超限 fail-hard） |
| D3 PreviousValid 资格 | `guardconfig/authz_lifecycle.go authzPreviousValidEligible`（分量比较 ≥ 当前管理面水位 + 未过期；无合格候选置空；缺水位旧快照按 0；DB/解码错误 fail-hard） |
| D4 网关消费 | `jiuzhang_guard/authz_watermark.go`（进程级注册表 + checkAuthzWatermarkRegression：v2 快照水位低于已应用即 Provision 拒绝→/load 400，v1 兼容不校验）；`authzdecide.go` D4-2 PreviousValid 回退二次水位校验；schema 闸门（v1 全惰性）；能力门 az/2（server capability_gate.go + gateway capability_report.go 自报 az/2） |
| D5 租约 | per-app `applications.authz_lease_seconds`（000173 + applications 管理写入夹紧 15~300）→ 编译 `ListAuthzLeaseSeconds` → handler `api_authz_lease_seconds` → Guard 解析夹紧；`authzdecide.go authzLeaseExpired`（AppliedAt 取注册表应用时刻）：strict（缺省）UNKNOWN+AUTHZ-LEASE-001+DependencyUnavailable、degraded 评估继续+AUTHZ-LEASE-002 标记 |
| D6 节点 ACK | 心跳 Record 五字段（apievents；apiheartbeat provider 读注册表合并态：min(lease)/分量最小水位/最旧 appliedAt）；server 迁移 000173 `api_node_authz_acks`（跨代理冻结列）+ apinodes/apiruntime 采集（B 轨）+ `GET /api/v1/api-security/authz/node-acks`（api_authorization.read） |
| D7 冲突排除 | 快照 `conflicted_objects` → detectors `BuildConflictedObjectIndex`（app+type+ref 键，tenant 不入键保守归并）→ BOLA 命中 OPEN 冲突对象 → UNKNOWN+AUTHZ-CONFLICT-001（不出 VERIFIED/ALLOW） |
| D8 时钟漂移 | 节点侧 `authzClockSkewExceeded`（**负向差值专用**，见偏差 #2）；上限 `api_authz_clock_skew_max_seconds`（gateway_runtime 组下发，缺省 60、夹紧 10~300）；strict 端点 UNKNOWN+AUTHZ-CLOCK-001、degraded 仅标记；server 侧心跳 skew 列（B 轨 api_node_authz_acks.clock_skew_seconds） |
| D9 测试方法学 | 见下「时延实测」 |
| D10 兼容 | 全字段 omitempty（v1 逐字节兼容实测）；回滚不回退水位/账本/冲突（D4-1 实测）；OpenAPI 686 零差集 |

### 偏差登记（A 轨 5 + B 轨 6 + 集成新发现 6）

A 轨（已交付时登记）：BFLA 无端点标志按 strict 缺省；`gateway_runtime.authz_clock_skew_max_seconds` 本批补接线完成；租约值取当前配置优先于历史快照随行；reauthorize 不推进 manual_seq（恢复通道非废止）；冲突查找键不含 tenant（保守归并）。
B 轨（另一代理交付时登记，照录）：ACK 合并口径为节点级最保守（min lease/最小水位/最旧 applied）；NEVER_ACKED 如实显示；skew 以心跳 OccurredAt 对账；ack_state 派生不持久化；心跳键沿用既有 __heartbeat__ 占位；000173 两表合一迁移文件。
集成批新发现：
1. **D8 节点侧漂移公式修正（重大）**：原设计字面 `|now − produced_at| > 阈值` 会把快照**自然老化**误判为漂移（24h 有效期快照产生 60s 后全部授权决策退化 AUTHZ-CLOCK-001，stage5 实测复现）。修正为**仅负向差值**（produced_at 超前 now 超阈值 = 节点时钟落后管理面才判漂移）；正向老化归 D5 租约/陈旧与服务端心跳 skew 处理。单测同步修正（aging 不触发/未来触发/上下限/v1 惰性）。
2. **BFLA 时效检查补空基线门控**：租约/漂移时 BFLA UNKNOWN 检查仅在存在角色基线时产出（无 BFLA 端点不产空载检查）。
3. **task 书「strict 端点源站未到达」与 authz OBSERVE 语义不符**：authzdecide 决策恒为 OBSERVE 级信号（现状设计），strict 过期时请求仍放行到源站（源站最终授权校验不受影响，设计 D5 原文）；实测断言按「UNKNOWN+AUTHZ-LEASE-001+dependency_unavailable=true 记录」成立。
4. **objref HMAC 为全量 32 字节**（非截断 16）：E2E 工具初期按截断计算导致关系 ref 不匹配（RELATION-001），修正为全量输出后基线成立（EFFECTIVE_OWNER ALLOW / OTHER_OWNER OBSERVE_VIOLATION）。
5. **compileObjectSegment 对象类型派生**：object_type 取路径静态前段（`/v1/authz-it/{id}` → `authz-it`），非自由命名——关系/事件 object_type 必须按派生值写。
6. **LOCK_BUSY 语义**：本栈发布锁为排队非拒绝——「锁冲突」任务随后仍会成功，同代水位下 PreviousValid 可能因前驱快照同水位而合格（PreviousValid 在场不等于 D3 失效）；D3 否决证据以「前驱快照水位低于当前管理面水位」的形态成立（单测锁定 + 回滚拒载实测互证）。

### E2E 证据摘要（stage5，2026-10-05）

- **NG-T-A05 臂1（手工）**：revoke → `manual_seq=2`；发布快照 `revocation_watermark:{manual_seq:2}`；X 仍 REVOKED；请求 → AUTHZ-RELATION-001（不恢复）。
- **NG-T-A05 臂2（权威）**：GRANT（seq1）→REVOKE（seq2）→ `api_authority_watermarks.revocation_watermark=2`；快照 `{"manual_seq":2,"sources":{"<src>":2}}`；请求 → AUTHZ-RELATION-001。
- **D4-1 回退拒绝**：回滚水位 1 版本（已应用 2,2）→ 任务 `FAILED | ROLLBACK_PUBLISH_FAILED | caddy load failed (status 400): api_authz: revocation watermark regression (incoming manual_seq=1 < applied=2), config load rejected`；当前生效配置与水位的库值均不变。
- **NG-T-C08 能力门**：篡改清单 az/1 → `FAILED | CAPABILITY_MISSING | … CAP_MISSING:detectors.authzdecide(required=az/2,actual=az/1)`；janitor 60s 自愈 az/2 → 发布恢复 SUCCESS。
- **NG-T-A07**：租约内（120s）正常评估；越租约 strict → `AUTHZ-LEASE-001` + `dependency_unavailable=true`；degraded → 评估继续（RELATION-001 如实）+ `AUTHZ-LEASE-002` 标记；`node-acks` 显示 `STALE_EXPIRED staleness=39 lease=15`；恢复后 ACK 收敛。
- **D7**：冲突 OPEN（principals alice+bob）→ 快照 `conflicted_objects` 下发 → `AUTHZ-CONFLICT-001`；REVOKE 后 `RESOLVED` → ALLOW 恢复。
- **node-acks API**：sec_admin 200（ack_state/版本/staleness 齐全）；jiuzhang_admin 403 PERMISSION_DENIED。
- **时延实测（撤销→ACK，30s 心跳形态，REVOKE 臂 4 样本）**：4s/6s/7s/7s（p50=6.5s、max=7s）——本形态由「发布完成→Provision 装配→首拍即时心跳」主导（runner 启动即首跳），秒级；30s 周期仅约束无发布变更的活性刷新。**「撤销→ACK P99≤5s」为候选目标非承诺**：需心跳周期 ≤5s 的部署形态（当前合法区间 30~300s 之外）；GRANT 臂不可经撤销水位测量（水位只含撤销语义，如实边界）。网络分区下不做任何时延承诺。

### 管理面新增（集成批 plumbing）

- `PATCH /api/v1/api-security/object-models/{id}`（publishable/required_relation(首批仅 OWNER)/owner_exclusive/on_lease_expired，api_authorization.manage + 审计；OpenAPI 686 零差集）。
- `applications.authz_lease_seconds` 管理写入（PUT 应用，0=清除/15~300=设置/非法 400）与列表/详情出参。
- gateway_runtime 组两键下发：`api_node_heartbeat_seconds`（0|30~300）、`authz_clock_skew_max_seconds`（10~300 缺省 60）。
