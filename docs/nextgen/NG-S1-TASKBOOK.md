# NG-S1 任务书：覆盖账本、验证闭环与 HTTP 链一致性（S1，用例级）

> 来源：docs/WDSP_API_WAF_NEXTGEN_RD_PLAN.md §15.1 S1（NG-COV-01～04、NG-HTTP-01～02）。
> 输入契约：docs/nextgen/NG-BASE-02-contracts.md（ADR-0007）；语料：NG-BASE-04 §3；基线与差异：NG-BASE-01。
> 入口条件（开工前必须闭环）：K5/K6 签核；§0 前置准备全部完成。
> 纪律：一次只启动一个任务（01→02→03→04→HTTP-01→HTTP-02 顺序）；新能力默认 OFF；不移动 AGENTS.md 请求处理顺序；不复制任何外部产品实现。

## 0. 前置准备（S1 任务进入前的工程动作）

> **被动层骨架已落地（2026-10-03，全部无侵入/零行为变化/独立测试全绿）**：
> ① `gateway/dynamic_security/coverage/`（契约类型+五态+reason 注册表+有界非阻断发射器，24 例）；
> ② `gateway/dynamic_security/capability/`（CapabilityManifest+层级化集合包含校验器 CAP_MISSING，8 例）；
> ③ `server/internal/coverage/`（五态聚合/E 口径/维度上限 other 归拢/确定性采样，6 例）；
> ④ `server/internal/validations/`（决策层重放：真实 decision 引擎、零依赖结构、三重摘要绑定+STALE，8 例）；
> ⑤ `test/httpchain/`（记录型源站+链路清单+5 组语料+驱动，T0 自检 5/5）。
> 类型贯通：server 两包直接复用 gateway 契约类型（replace），两端校验口径一致。
> 剩余全部为接线期工作（检测器补点、事件摄入、PG+迁移、查询接口+权限、前端、发布门、T1 拓扑），
> 侵入面建议在 1.2.1 推送后按本任务书顺序开工。

- [ ] P1 Playwright E2E 补跑登记（基线 §3 未跑项）。
- [ ] P2 性能基线一次（test/performance/p0 preflight → baseline run，仅登记当前态，不做对比）。
- [ ] P3 物理存储评审：`CoverageObservation` 落库方案定案——候选 A：新表 `coverage_observations`（请求级明细，有界保留）+ 聚合表 `coverage_minute_agg`；候选 B：复用现有统计存储。**默认按候选 A 估**（容量：明细仅采样 1/N，聚合全量；保留：分钟聚合 7 天，小时聚合 90 天——RD_PLAN §14.3，最终值随评审记录）。
- [ ] P4 `contract_version` 常量与 reason code 注册表落 `gateway/dynamic_security/coverage/`（新包骨架）。

## 1. NG-COV-01 请求阶段与检测器覆盖记录

**目标**：API 管线内每个检测器按 NG-BASE-02 §2.2 产出 CoverageObservation（五态）；请求入口/出口最小计数接线，能区分「上游已拒绝 / API 管线未启用 / 统计缺失」。

**改动面**：

| 位置 | 动作 |
|---|---|
| `gateway/dynamic_security/coverage/`（新） | Observation 类型、五态枚举、reason code 注册表、发射器（批量/有界队列/丢弃计数，失败不阻断请求） |
| `gateway/dynamic_security/detectors/*.go` | 各检测器在既有短路点补发 SKIPPED/PARTIAL（关闭、规则未选、能力缺失、依赖不可用、输入截断、解析错误）；**只补观测，不改判定语义** |
| `gateway/dynamic_security/decision/engine.go` | 统一决策处补 FINAL 范围声明（scope_declared）；输出给 Observation 关联 ExecutionOutcome 的挂点（为 02 铺路） |
| `gateway/modules/jiuzhang_guard/module.go` 请求入口/出口 | 最小计数：进入 API 管线总数 / 被上游（白名单/封禁/CC/Bot/JWT）拒绝数 / 到达 API 管线数——只计数，不改变处理顺序 |
| `gateway/dynamic_security/apiprotect.go` 放行出口 | 「未启用 API 管线」计数与原因（模式 OFF/未配置） |

**硬约束**：Observation 永不贡献攻击分（ADR-2）；发射失败/队列满只记丢弃计数；热路径零网络 IO（仅内存队列 → 异步落 Valkey/文件契约，同现有事件通道形态）。

**验收（全部真实执行）**：

| 用例 | 断言 |
|---|---|
| 五态单测（gateway 包） | FULL/PARTIAL/SKIPPED/ERROR/NOT_APPLICABLE 各态字段与 reason code 合法；NOT_APPLICABLE 必须带冻结分类规则 ID |
| 前置阻断不漏计 | 被黑名单/CC/Bot 拒绝的请求在入口计数中按「上游已拒绝」归类，不产生检测器 SKIPPED 假账 |
| 截断记账 | 超 `MaxGRPCFrameBytes`/体上限的输入记 PARTIAL + `COV_INPUT_TRUNCATED`，bytes_examined 如实 |
| 性能抽测 | 观测开启下 P99 增量 <1ms（对照同源码基线，stage5 200 请求 p50/p95） |
| NG-T-C01/C03 | 新配置缺省 OFF；覆盖信号与高分攻击线索并存时不产生 BLOCK |

## 2. NG-COV-02 聚合、丢弃/缺节点处理、查询与页面

**目标**：分钟/小时有界聚合（P3 定案表）、丢弃与缺节点如实展示、`GET /api/v1/api-security/protection/coverage` 查询接口与前端「覆盖与验证」视图（复用运行时事件页布局，不新建同名策略入口）。

**改动面**：`server/internal/coverage/`（聚合器+存储+查询）、迁移（顺延 000168+，不预占）、`server/internal/app/app.go` 路由注册（候选权限 `api_protection.read`，注册权限种子+前端隐藏/禁用+越权测试）、`web/src/pages/api-runtime-events/` 相邻位置新增视图、openapi 片段登记。

**验收**：指标口径 `E=FULL+PARTIAL+SKIPPED+ERROR`（E=0 显示「无适用流量」，禁止显示 100%）；`FULL/E` 与 `(FULL+PARTIAL)/E` 分别展示不混用；五态/零分母/缺节点/队列丢弃四态数据 UI/API/导出一致（NG-T-C06）；聚合维度超限归 other 桶并计丢弃；授权覆盖附加口径（可信主体/关系/快照/UNKNOWN 分布）按 §5.2 展示。

## 3. NG-COV-03 无副作用模拟及报告绑定

**目标**：冻结策略+脱敏证据在隔离解析/决策实例内重放（不反代、不调工具、不改真实状态），产出差异报告并与策略摘要绑定；`POST/GET /api/v1/api-security/protection/validations`。

**改动面**：`server/internal/validations/`（模拟器：只读装配解析器+决策引擎的纯函数调用；禁止一切 gateway client/Valkey 写/源站连接——以接口注入隔离，测试断言零外部调用）、报告存储（策略摘要+语料摘要+输入摘要，任何变更使旧报告标 STALE）、权限（`api_protection.validate`）。

**验收**：NG-T-C07（模拟含工具/状态操作时零外部调用断言）；NG-T-C08（报告后策略变更→旧报告失效展示）；缺原始输入时标「不能复现」，不补造输入（RD_PLAN §5.3）；模拟结果含旧/新策略差异、拟新增阻断、证据不足、协议不可复现、例外命中、资源成本。

## 4. NG-COV-04 发布前验证 / 节点能力 / 灰度回退门禁

**目标**：CapabilityManifest 接入发布链（required_capabilities 集合包含校验，缺失节点发布失败）；发布记录扩展 `DRAFT → VALIDATED → SHADOW → CANARY → ACTIVE` 信息性生命周期；按应用/端点/可信主体稳定分桶的灰度与回退。

**改动面**：`server/internal/gatewayconfig/`（快照嵌入 required_capabilities；发布任务评估节点能力）、`gateway/modules/jiuzhang_guard/`（节点自报能力清单，契约 §2.1 生成）、`server/internal/publish*`（生命周期字段与状态迁移、回退演练钩子）。

**验收**：旧节点/缺能力节点发布失败并展示缺口（CAP_MISSING，NG-T-C08）；能力缺失不得 ACK 成功；灰度对整个流程实例稳定分组（非逐请求随机）；回退停止灰度且不回滚撤销水位/重放记录/业务执行事实（NG-T-A05 联动）。

**本批边界（2026-10-03，能力发布门第一批）**：

- 已建：网关自报（`jiuzhang_guard/capability_report.go`——进程级单例 janitor 60s 原子刷新
  sidecar `capability.json`，默认开启、`CAPABILITY_REPORT_DISABLED=1` 排障关闭，清单内容
  逐键有据写死为进程常量：http=1.1/graphql=parse/grpc=frame|unary_g1（按描述符注册表翻转）/
  mcp=observe，不报未实现能力；h2 层级评估留后续）→ server 发布门
  （`gatewayconfig/capability_gate.go`——`RequiredCapabilities` 负载特性段推导 + 主节点
  manifest 加载 + staleness（3×tick=180s）判定，挂 executePublish 回归门禁之后、/load 之前；
  缺能力 `CAPABILITY_MISSING`（message 含 CAP_MISSING:<key> 全缺口）/清单缺失或过期
  `CAPABILITY_MANIFEST_UNAVAILABLE`，fail-closed 不发送 /load）。
- required 计算当前仅覆盖 grpc 现存特性段（APIGRPCDescriptors→unary_g1+grpc.unary；
  APIGRPCAllowCompression→frame+grpc.frame；APIGRPCMaxFrameBytes→limits）；api MCP 段、
  GraphQL cost_v1、actions 需求、coverage 观测（可降级）本期不列入；空需求免门禁——
  存量发布零行为变化（兼容约束）。
- 后续项：SHADOW/CANARY 灰度生命周期（DRAFT→…→ACTIVE 状态迁移与稳定分桶、回退演练钩子）；
  远端次要节点 manifest 通道（v1 边界：有需求且登记次要节点时按清单缺失 fail-closed 拒绝，
  message 列出节点清单）；required_capabilities 嵌入版本快照存证（当前按需现算不落库）。

## 5. NG-HTTP-01 多跳解析测试台与链路清单

**目标**：建立「记录型源站 + 链路清单」，逐跳证明客户实际接入链中网关与源站对请求边界解释一致；不是新写 HTTP 解析器。

**改动面**：`test/httpchain/`（新：记录型源站——登记规范化方法/路径/头结构/请求计数/体摘要，不落凭据；链路清单 YAML；驱动脚本）。拓扑：直连 WDSP、前置可信代理（stage5 已有 docker-bridge 模式）、HTTP/2→HTTP/1.1 转换、路径重写、连接复用后继请求。危险样本仅放 `test/httpchain/corpus/`（隔离语料，不进生产包）。

**验收**：NG-BASE-04 §3.1 HC-N01/A01/A02/A03/U01 全过；每个声明支持的链路有正常/异常用例及连接复用验证；无测试拓扑的组合在交付说明标注「未验证」；覆盖项含重复/冲突长度头、传输编码歧义、非法换行、Host/authority、绝对形式、HTTP/2 伪头、请求体边界、升级协议边界。

## 6. NG-HTTP-02 最小修复 / 配置限制（依 HTTP-01 复现结果）

**目标**：仅当 HTTP-01 发现可利用解释差异时实施最小修复或配置约束；无缺陷则保留证据关闭。

**出口判据**：修复前失败与修复后通过的配对用例入库；优先评估上游修复与受支持配置（依赖升级须重新锁版本+镜像摘要+回归）；不做未经证明的多次 URL 解码或请求重写。

## 7. S1 总出口门禁

- [ ] NG-T-C01/C02/C03/C04/C05/C06/C07/C08/C09/C10 对应断言全过（映射 §1-§5 验收）。
- [ ] server/gateway 全量 go test 无新增 FAIL；`stage5-gateway-tests.sh` 40/40 不回退；`custom-pack-blocking-tests.sh` 13/13 不回退；go-ftw 既有通过项不回退（失败簇按基线 §3.1 结论单独跟踪，不算回退）。
- [ ] 性能：观测开启 P99 增量 <1ms、吞吐降 <3%（RD_PLAN §14.2 候选口径，出测量报告含噪声）。
- [ ] OpenAPI 对账零差集；权限种子/前端/越权测试闭环；CHANGELOG 与各任务证据归档 docs/nextgen/s1/。
- [ ] 每个「计划阻断」断言附源站计数证据（ExecutionOutcome.forwarded_to_origin=false）。

## 8. 风险登记（进入即知）

| 风险 | 缓解 |
|---|---|
| 观测接线触碰热路径性能 | 只内存计数+异步通道；性能抽测门禁（§1） |
| 检测器逐一手补观测遗漏 | 在 engine/管线出口做兜底 SKIPPED 记账（未显式申报的检测器按原因归类） |
| 聚合维度爆炸 | 维度组合上限 + other 桶 + 丢弃计数（§2） |
| 灰度分桶不稳定导致流程实例串组 | 分桶键=应用+端点+可信主体（缺主体时明确接入分组，不用易变指纹） |
