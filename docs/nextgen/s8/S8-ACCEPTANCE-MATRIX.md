# S8 验收对账表（NG-REL-01 交付物一：RD 计划 §15.2/§16 逐行对账）

> 日期：2026-10-09 ｜ 依据：`docs/WDSP_API_WAF_NEXTGEN_RD_PLAN.md` §15.2（任务清单）/§16（测试与验收矩阵）
> 口径：S8 批次 A 只做验收交付，不做新功能。本表逐行对账，证据指针指向各阶段出口记录/设计文档/证据目录原文；未执行项一律标 NOT_RUN，不折算为通过。
> 状态词表：**PASS**（断言有实证证据）｜**PARTIAL**（部分断言有实证，缺口逐项注明）｜**NOT_APPLICABLE**（范围明示未激活，不折算不隐藏）｜**NOT_RUN**（未执行）。

## 1. §15.2 任务清单对账（34 项）

| 任务 | 状态 | 完成证据逐字对照 | 证据指针 |
|---|---|---|---|
| NG-BASE-01 冻结源码、未提交改动摘要、构建/依赖与测试基线 | **PASS** | 「基线清单、现状差异、无敏感值」——基线文档在册（含 go-ftw 10014xx 簇差异定责）；源码冻结现状见 §4 注记 | `docs/nextgen/NG-BASE-01-baseline.md`；`docs/nextgen/s1/S1-EXIT-REPORT.md` |
| NG-BASE-02 冻结覆盖/阻断资格/协议执行/能力协商契约 | **PASS** | 「ADR、字段字典、兼容样本」——契约文档在册 | `docs/nextgen/NG-BASE-02-contracts.md` |
| NG-BASE-03 业务威胁模型、权限与失败策略评审 | **PASS** | 「资产/边界/滥用场景/责任人签核」——威胁模型文档在册 | `docs/nextgen/NG-BASE-03-threat-model.md` |
| NG-BASE-04 建立隔离目标及正常/异常/未知语料 | **PASS** | 「run-plan、目标清单、语料摘要」——httpchain 测试台+topology.yaml+HC 语料五组在册 | `docs/nextgen/NG-BASE-04-isolation-corpus.md`；`test/httpchain/` |
| NG-COV-01 请求阶段与检测器覆盖记录 | **PASS** | 「五态单测、前置阻断不漏计」——五态/零分母/缺节点/队列丢弃单测+stage5 双视图实测 | `s1/S1-EXIT-REPORT.md` §1 NG-T-C06 行 |
| NG-COV-02 聚合、丢弃/缺节点处理、查询与页面 | **PASS** | 「API 权限测试、统计对账、E2E」——两角色权限实测+聚合对账+stage5 E2E 在册；前端「覆盖与验证」视图按 S1 §5.5 明示移交后续批（API/数据面已闭环，不阻塞出口） | `s1/S1-EXIT-REPORT.md` §1/§5.5 |
| NG-COV-03 无副作用模拟及报告绑定 | **PASS** | 「零外部执行断言、摘要变更失效测试」——Simulator 空结构体类型锁定+报告 STALE 实测（DB 行不回写） | `s1/S1-EXIT-REPORT.md` §1 NG-T-C07/C08 行 |
| NG-COV-04 发布前验证/节点能力/灰度回退门禁 | **PARTIAL** | 「旧节点拒绝、稳定分桶、回退演练」——旧节点拒绝（能力门 fail-closed CAPABILITY_MISSING 不发送 /load）S1/S3/S6/S7 四阶段反复实证；**SHADOW/CANARY 灰度生命周期与远端次要节点 manifest 通道按任务书边界移交后续批（S1 §5.4），回退演练随 NG-REL-02（NOT_RUN）** | `s1/S1-EXIT-REPORT.md` §1 NG-T-C08 行+§5.4；`s3/S3-AZ03-EXIT-NOTE.md` NG-T-C08 节；`s6`/`s7` 出口记录能力门三态节 |
| NG-HTTP-01 多跳解析测试台与链路清单 | **PASS** | 「源站证据、连接复用和转协议测试」——守恒等式 total=9=6+3、CL/TE 夹带源站计数=0 无串扰、blocked-not-upstream 在册 | `s1/S1-EXIT-REPORT.md` §4；`test/httpchain/topology.yaml` |
| NG-HTTP-02 依据复现结果做最小修复/配置限制 | **PASS** | 「修复前失败与修复后通过配对；无缺陷则保留证据」——三条链路无可利用解释差异，按出口判据**保留证据关闭**；h2→h1.1 链路 stage5 未建拓扑标 untested（移交，见 §3） | `s1/S1-EXIT-REPORT.md` §5.7 |
| NG-GQL-01 库评估、AST 与操作选择 | **PASS** | 「许可证、边界测试、fuzz、黄金样本」——gqlparser v2.5.60 MIT 锁定+五道硬边界 13 单测+fuzz 889k execs 零崩+license-audit 通过 | `docs/nextgen/NG-GQL-01-library-eval.md`；`s2/S2-EXIT-NOTE.md` |
| NG-GQL-02 成本/预算/可信文档编译 | **PASS** | 「溢出、变量、缓存隔离、限额测试」——D1~D11 冻结（饱和不绕回/版本化缓存键/三预算分离）+11 黄金样本全过（§4 锚定 NG-T-G02/G03/G04） | `docs/nextgen/NG-GQL-02-cost-model.md`；`s2/S2-EXIT-NOTE.md` |
| NG-GQL-03 配置/证据/执行接线 | **PARTIAL** | 「OBSERVE/PROTECT E2E、性能分档」——OBSERVE/PROTECT E2E 六步全过（403 JSON 规范体/源站零到达/trusted digest/时间窗）；**性能分档无专项证据，并入性能门槛专项（NOT_RUN，见 §3）** | `s2/S2-EXIT-NOTE.md` stage5 E2E 节；`docs/nextgen/NG-GQL-03-wiring.md` |
| NG-AZ-01 权威来源、批次、乱序/重放 | **PASS** | 「导入事务、权限、冲突与缺口测试」——Ed25519 验签批次导入+五步校验链+水位单调，stage5 E2E 七步全过 | `docs/nextgen/NG-AZ-01-authority-ingest.md` 实现状态节；`s3/S3-EXIT-SUMMARY.md` |
| NG-AZ-02 撤销水位、租约、节点 ACK | **PASS** | 「分区/回滚/恢复测试与时延报告」——D1~D10 全 PASS（回滚水位拒载 ROLLBACK_PUBLISH_FAILED、能力门 az/2、租约双策略、ACK staleness）；时延报告如实（REVOKE→ACK 4/6/7/7s，P99≤5s 标候选非承诺） | `s3/S3-AZ02-EXIT-NOTE.md` |
| NG-AZ-03 BOLA/BFLA 显式阻断资格 | **PASS** | 「UNKNOWN 不误断、可信违规不达源站」——12 负向样本无一实断（9 条 stage5 实证+3 条既有测试承接注明原因）；PROTECT 403 精确体 ×3 源站 0/3 | `s3/S3-AZ03-EXIT-NOTE.md` 完成证据一/二 |
| NG-AZ-04 管理向导、影响评估、全链验收 | **PASS** | 「页面 E2E、审计、业务确认单」——页面 E2E 5/5、审计 HIGH 在册、确认单全生命周期实证 | `s3/S3-AZ04-EXIT-NOTE.md`；`s3/S3-EXIT-SUMMARY.md` |
| NG-FLOW-01 强流程定义与旧观察状态隔离 | **PASS** | 「迁移/版本兼容、定义校验」——000176/000177 版本化+`sflow:v1:` 物理隔离+旧观察态零导入 | `s4/S4-EXIT-SUMMARY.md` FLOW-01 行 |
| NG-FLOW-02 原子预留/提交/释放/fencing | **PASS** | 「多节点竞态、超时迟到响应测试」——双网关 overlay 6 轮并发恰一 200 一 403（共享 Valkey 原子域互证） | `s4/S4-FLOW02-EXIT-NOTE.md` |
| NG-FLOW-03 成功确认与未知恢复 | **PASS** | 「业务超时成功、202、重试/补偿测试」——504→INDETERMINATE 不自动回滚+resolve 收口+迟到 fencing 拒绝+两裁决闭环 | `s4/S4-FLOW03-EXIT-NOTE.md` |
| NG-FLOW-04 管理恢复与运行观测 | **PASS** | 「权限/审计/E2E、持久化恢复报告」——Playwright 五场景两轮全绿+Valkey=热状态/PG=事实源边界实证（停 Valkey 恒 UNKNOWN 不切本地） | `s4/S4-FLOW04-EXIT-NOTE.md`；`s4/S4-EXIT-SUMMARY.md` §S4 完成证据 |
| NG-GRPC-01 帧读取、描述符、有界解压 | **PASS** | 「分片/压缩/内存上限/fuzz」——帧读取器流式重组+四重预算+错误三分类；R01 200KiB 分片双应用源站到达实证；R02 20MiB gzip ResourceExhausted | `s5/S5-EXIT-SUMMARY.md` R01/R02 行 |
| NG-GRPC-02 字段深检与协议化执行 | **PASS** | 「真实 Go/其他客户端对测、trailers」——真实 Go gRPC SDK 对测四分支违规全过，trailers-only 纯 gRPC 错误与 HTML 403 形态差分实证 | `s5/S5-EXIT-SUMMARY.md` R04 行 |
| NG-GRPC-03 管理配置与覆盖统计 | **PASS** | 「unary 完整范围、streaming 明确降级」——描述符管理面+能力门 grpc/2；streaming `skip_reason=streaming_degraded` 如实声明不冒充完整覆盖 | `s5/S5-EXIT-SUMMARY.md` R05 行 |
| NG-MCP-01 协议/目录资产/版本冻结 | **PASS** | 「兼容矩阵、变更不自动信任测试」——D1~D14 冻结；M02 tool_hash 变重置 PENDING_REVIEW 旧审批不继承实证 | `s6/S6-EXIT-SUMMARY.md` M02 行 |
| NG-MCP-02 工具 ACL 与参数校验 | **PASS** | 「无权请求不达工具、Schema 边界」——M01 未授权 403 -32011 计数器=0；M03 预算违规逐条定案+300KiB 尾部违规命中（全量解析实证） | `s6/S6-EXIT-SUMMARY.md` M01/M03 行 |
| NG-MCP-03 结果检查与流式边界 | **PASS** | 「泄漏阻断、不可撤回字节披露」——M04 非流式 -32014 leak=false；SSE 首条实收+次条不外发+disclosed_bytes=148 逐字节一致+final_action=BLOCK | `s6/S6-EXIT-SUMMARY.md` M04 行 |
| NG-MCP-04 页面、审计、客户端兼容 | **PASS** | 「权限/E2E；审批后续项不冒充完成」——权限 api_spec.read/manage 复用零新增+越权测试；官方 Go SDK v1.8.0 对测；目录/绑定管理页已交付（`web/src/pages/api-mcp/`，Vitest 139 文件全绿；**工作区未提交，提交属编排者职责，见 §4**）；M07 审批按冻结措辞 NOT_APPLICABLE 不折算 | `s6/S6-EXIT-SUMMARY.md` M07 行+§已知限制 |
| NG-ID-01 路线选择、客户端接入契约 | **PASS** | 「发行方/客户端配合确认」——D1 冻结 HTTP Message Signatures（RFC 9421/8941 子集）路线+接入契约；Go stdlib 三算法参照客户端对测闭环（**外部身份提供方试点未做，DPoP 试点等列移交，见 §3**） | `docs/nextgen/NG-ID-g1-machine-identity.md`；`s7/S7-EXIT-SUMMARY.md` |
| NG-ID-02 本地验证、重放、密钥轮换撤销 | **PASS** | 「跨节点重放及撤销后回滚测试」——I03 双节点重放原子拒绝+Valkey 中断 503/OBSERVE 披露；I04 撤销不复活+轮换窗口+水位回滚拒载 fail-closed | `s7/S7-EXIT-SUMMARY.md` I03/I04 行 |
| NG-ID-03 权限与 Bot 协同、发布 | **PASS** | 「签名身份不能绕过 WAF/API 的集成测试」——I05 VERIFIED 机器 SQLi 照拦/CC 照判/Bot 挑战照走+exempt 三重显式成立；C04 白名单不绕过实证 | `s7/S7-EXIT-SUMMARY.md` I05/C04 行 |
| NG-REL-01 跨模块/回归/容量与恢复 | **PASS** | 「冻结报告，强制项全部 PASS」——本对账表+冻结回归报告 `S8-REL01-REGRESSION-REPORT.md`；强制项（§16 已交付范围 50 断言+回归套件）全绿，红灯三项根因处置后复跑全过 | 本文件；`s8/S8-REL01-REGRESSION-REPORT.md` |
| NG-REL-02 完整包与前台升级兼容 | **NOT_RUN** | 「纯离线测试机安装、升级、失败恢复」——批次 D 范围，本批未执行不折算 | —（批次 D 任务书） |
| NG-REL-03 运维/限制/版本与交付清单 | **NOT_RUN** | 「用户批准发布后按版本规则交付」——批次 D 范围，需用户批准发布，本批未执行不折算 | —（批次 D 任务书） |

**§15.2 计数：PASS 30 ｜ PARTIAL 2（NG-COV-04、NG-GQL-03）｜ NOT_RUN 2（NG-REL-02/03）**——PARTIAL/NOT_RUN 缺口逐项见 §3，无一冒充。

## 2. §16 验收矩阵汇总（61 用例）

### 2.1 共用安全与覆盖（NG-T-C01~C10）

| 编号 | 状态 | 证据 |
|---|---|---|
| C01 新配置缺省、升级旧配置 | PASS | S1 §1（缺省关闭零行为+黄金对照）；S4/S5/S6/S7 各批 NG-T-C01 节反复实证（无绑定应用零行为+回归不回退） |
| C02 OBSERVE 命中高风险样本 | PASS | S1 §1（OBSERVE 放行不阻断 200+would_block 模拟语义标注）；S2 OBSERVE 拟动作；S5/S6/S7 OBSERVE 对照组 |
| C03 覆盖错误与高分攻击线索并存 | PASS | S1 §1（Observation 独立通道 ADR-2 结构上无入分路径+黄金对照决策输入不变） |
| C04 白名单/L7 allow 命中 | PASS | S1 §1（stage5 40/40 含白名单语义）；S6 C04（白名单命中不绕过 JWT PROTECT/mcpguard）；S7 C04（白名单不绕过机器身份，serveNext 统一出口实证） |
| C05 精确例外命中 | PASS | S1 §1（例外命中保留证据并打标不升级阻断，validations 8 例）；S5 WAF 例外范围限定承载 gRPC 误检 |
| C06 五态/零分母/缺节点/队列丢弃 | PASS | S1 §1（聚合器/agg/stages 双视图+丢弃计数，stage5 实测） |
| C07 模拟执行含工具或状态操作 | PASS | S1 §1（Simulator 空结构体+零外部依赖类型锁定测试） |
| C08 报告后策略被改、老节点接收新策略 | PASS | S1 §1（报告 STALE+能力门三态 fail-closed）；S3-AZ03 E2E-5 三态；S6/S7 能力门三态 stage5 实证 |
| C09 越权管理/跨应用读取 | PASS | S1 §1（两角色 403/200 实测）；S4 F08（越权整页拒绝）；S7 C09（未认证 401+AUDIT_ADMIN 写 403+权限种子口径实证） |
| C10 上传超大、压缩异常、路径穿越 | PASS | S1 §1（批次>100→400/字段超限 400/evidence 原文拒绝/httpchain 4KB 大头无 5xx）；S5 R02 压缩膨胀有界 |

### 2.2 协议测试（NG-T-H01~H03、G01~G06、R01~R06）

| 编号 | 状态 | 证据 |
|---|---|---|
| H01 长度/编码/头边界歧义 | PASS | NG-BASE-04 语料 HC-N01/HC-A01/HC-U01；S1 §4（CL/TE 夹带源站计数=0+同连接无串扰） |
| H02 HTTP/2 转换、路径重写、可信代理 | **PARTIAL** | HC-A02 绝对形式/路径重写/可信代理链路已测（S1 §5.7 三条链路无可利用解释差异）；**h2→h1.1 链路 stage5 网关 h2 支持面未建拓扑，topology.yaml 标 untested（移交 §3）** |
| H03 Host/authority 与外部 URL | PASS | HC-A03（Host 与 authority 不一致/伪造转发头）：以网关锁定 authority 裁决为准，不接受不可信来源覆盖（S1 §5.7 保留证据关闭） |
| G01 多 operation 与 operationName | PASS | S2 E2E（多 operation 未命名 PROTECT GQL_ADMISSION_REJECTED/OBSERVE 放行记录）；NG-GQL-03 §SelectOperation 只算被选定 operation |
| G02 fragment 循环/膨胀、深度/alias | PASS | NG-GQL-01 五道硬边界（64KiB/深度 20/alias 100/节点 10000/fragment 循环）13 单测+fuzz 889k 零崩 |
| G03 变量/默认值/指令/列表 | PASS | NG-GQL-02 D1~D11（response-key 合并/列表上界/变量不求值保守口径）+§4 黄金样本锚定 |
| G04 HTTP batch 与成本整数溢出 | PASS | NG-GQL-02 D6（饱和运算 2^62-1 上界，溢出即超预算不绕回）+§4 黄金样本锚定 |
| G05 APQ 未审核、Schema 更新 | PASS | NG-GQL-02 D10（APQ 不自动等于可信文档，仅审核登记摘要进白名单）+版本化缓存键（Schema/模型变更旧缓存失效）；S2 E2E trusted digest 白名单内放行/变体 403 |
| G06 超限 PROTECT 与 OBSERVE | PASS | S2 E2E（PROTECT 403 JSON 规范体源站零到达/OBSERVE 放行记录）；NG-GQL-03 §3 失败四分流 |
| R01 gRPC 分片帧/长度错误/空消息 | PASS | S5 R01（200KiB=13 帧分片重组源站到达+覆盖读数一致；错误三分类） |
| R02 压缩膨胀/未知算法 | PASS | S5 R02（20MiB gzip→ResourceExhausted 预算触顶/decode_error UNKNOWN 双路径分明） |
| R03 repeated/map/oneof/缺描述符 | PASS | S5 R03（缺描述符直达源站 skip_reason=no_descriptor，UNKNOWN 恒不阻断） |
| R04 一元违规请求 | PASS | S5 R04（四分支 trailers-only 纯 gRPC 错误，测试服务未执行，固定短语防探测） |
| R05 流首条正常后续违规 | PASS | S5 R05（streaming_degraded 如实声明部分覆盖，不报告「整个调用通过」）；G2/G3 未实现按断言明示 |
| R06 cancel/deadline/慢消费 | PASS | S5 R06（50 次中途 cancel RSS 598.5→422.6MiB 无驻留反降+零 panic+取消路径如实披露） |

### 2.3 授权与流程（NG-T-A01~A08、F01~F08）

| 编号 | 状态 | 证据 |
|---|---|---|
| A01 有效本人 OWNER/其他 OWNER | PASS | S3-AZ03 完成证据二（owner 200 ALLOW 到达/other PROTECT 403 源站 0/3；OBSERVE 基准 OBSERVE_VIOLATION 不实断） |
| A02 未验证主体、历史推断所有者 | PASS | S3-AZ03 负向样本 1/2（无 JWT/伪造 JWT 恒 UNKNOWN 放行，不误断） |
| A03 同名对象跨租户/共享对象 | PASS | S3-AZ03 负向样本 9（租户不一致→OBSERVE_VIOLATION+TENANT-001 不实断；阻断资格评审列移交 §3） |
| A04 关系过期、冲突、签名错误 | PASS | S3-AZ03 负向样本 3/4/5（无有效关系/已撤销/OPEN 冲突恒 UNKNOWN）；NG-AZ-01 五步校验链（验签/乱序/重放） |
| A05 撤销后回退 PreviousValid | PASS | S3-AZ02 D3/D4-1（PreviousValid 资格过滤+水位回退拒载 ROLLBACK_PUBLISH_FAILED） |
| A06 重新授权、重复/乱序来源事件 | PASS | NG-AZ-01（导入事务+幂等+缺口可见，stage5 E2E 七步全过）；S3-AZ02 D7（冲突排除 REVOKE 后 RESOLVED→ALLOW 恢复） |
| A07 节点分区与时钟偏差 | **PARTIAL** | 租约约束 stage5 实证（S3-AZ02 D5 strict/degraded 双策略+D6 ACK staleness+D8 漂移修正语义）；**ha-lab 双节点分区演练矩阵移交（S3-AZ02 遗留 3/S3-AZ03 遗留 5，NOT_RUN）** |
| A08 BFLA 可信角色与伪造角色头 | PASS | S3-AZ03 BFLA 三态 E2E（继承/显式/全 OBSERVE）；伪造 JWT→UNKNOWN（角色仅取自 JWT VERIFIED 可信主体） |
| F01 正常流程及合法并行 | PASS | S4 F01（两步 COMMIT→INSTANCE_CONFIRMED；parallel_group 并行不误拒） |
| F02 双节点同时执行同一步 | PASS | S4 F02（双网关 6 轮并发恰一 200 一 403，共享 Valkey 原子域） |
| F03 幂等重试与同键异参 | PASS | S4 F03（同键同摘要幂等/异摘要 403 IDEMPOTENT-CONFLICT-001，裁决采 403 闭环） |
| F04 超时但源站已成功 | PASS | S4 F04（504→INDETERMINATE 不自动回滚+resolve CONFIRM_SUCCEEDED 收口+HIGH 审计） |
| F05 迟到响应与旧 fencing token | PASS | S4 F05（接管 f=2→3，旧 token COMMIT REJECTED FENCE-001 不覆盖新状态） |
| F06 取消后新实例、定义升级 | PASS | S4 F06（裁决①育龄窗：RETIRED 有非终态实例仍下发，旧实例按旧版本走完/新实例用新版本） |
| F07 Valkey 故障/网关重启 | PASS | S4 F07（停 Valkey 恒 UNKNOWN 放行不切本地+恢复后 fence 单调延续+PG 可对账） |
| F08 人工恢复越权/重复恢复 | PASS | S4 F08（jiuzhang_admin 403/expected_version 409/终态重复 409/HIGH 审计，单测+E2E+Playwright 三证） |

### 2.4 MCP 与机器身份（NG-T-M01~M07、I01~I05）

| 编号 | 状态 | 证据 |
|---|---|---|
| M01 未授权工具、Token 受众错误 | PASS | S6 M01（未授权 403 -32011 计数器=0；受众错误/缺 Token 401+Bearer challenge 非 JSON-RPC 体三重区分；OBSERVE 放行有记录） |
| M02 同名工具更新 Schema/摘要 | PASS | S6 M02（tool_hash 变重置 PENDING_REVIEW 不继承旧审批；语义相等幂等保留 APPROVED） |
| M03 嵌套参数、重复键、超长文本 | PASS | S6 M03（预算 413 -32013/深层重复键 403 -32012/300KiB 尾部违规全量解析命中/边界不误拒） |
| M04 工具结果敏感数据/流式输出 | PASS | S6 M04（-32014 转发前阻断 leak=false；SSE disclosed_bytes=148 如实披露+final_action=BLOCK） |
| M05 扩展方法、stdio、本地工具出网 | PASS | S6 M05（词表外放行不判攻击+llm.mcp_unknown_method OBSERVE；stdio/出网未覆盖明示不冒充） |
| M06 提示词伪造管理员/关闭策略 | PASS | S6 M06（伪造管理员文本不改变身份权限：bob 仍 -32011 echo=0 未到达；alice 正常到达） |
| M07 审批参数变化/重放/跨租户复用 | **NOT_APPLICABLE** | S6 M07（完整审批闭环属后续子阶段，RD_PLAN §11.3 明文；首期高风险默认拒绝+事件关联；按冻结措辞不折算 PASS 不隐藏必做项） |
| I01 有效证明/签名、方法或 URI 变化 | PASS | S7 I01（三算法 200+源站到达+MID_VERIFIED；改 method/path/query/body 401 四形态；RFC 9421 附录 B 黄金样本逐字节） |
| I02 Token 与密钥绑定不符 | PASS | S7 I02（principal_binding 不符 401 MID-PRINCIPAL-MISMATCH 不升级；keyid 未登记/alg 不符/词表外均 401；JWT 缺席机器身份独立成立） |
| I03 两节点重放、重放存储不可用 | PASS | S7 I03（A 收后 B 同 nonce 401 MID-REPLAY-DETECTED 原子拒绝；停 Valkey 双节点 503+OBSERVE 放行披露；恢复后正常） |
| I04 密钥撤销、轮换、普通策略回滚 | PASS | S7 I04（撤销 401 MID-KEY-REVOKED；轮换重叠窗新旧键均过；回滚水位拒载 ROLLBACK_PUBLISH_FAILED 已撤销键不复活） |
| I05 合法机器发起 WAF/API 攻击 | PASS | S7 I05（VERIFIED+SQLi 照拦 403/CC 429/Bot 挑战照走；exempt∩绑定命中∩VERIFIED 三重显式豁免在册） |

### 2.5 发布与运行（NG-T-D01~D08）——批次 D（NG-REL-02/03）范围，本批一律 NOT_RUN

| 编号 | 状态 | 注记 |
|---|---|---|
| D01 完整离线新装 | NOT_RUN | 批次 D（纯离线测试机）；本批未执行 |
| D02 前台应用升级 | NOT_RUN | 批次 D（校验签名/版本/能力/空间/迁移） |
| D03 迁移失败、节点升级中断 | NOT_RUN | 批次 D |
| D04 回滚与旧网关 | NOT_RUN | 批次 D。部分间接证据在册（S3-AZ02 水位回退拒载、S7 I04 回滚 fail-closed、能力门旧节点拒绝），不折算为 D04 通过 |
| D05 同机 WDSP 与其他应用 | NOT_RUN | 批次 D |
| D06 长时/高并发/恶意资源输入 | NOT_RUN | 24h 稳定性与高并发专项未跑（见回归报告 §8）；资源预算有界性由各模块单测/预算测试部分承载，不折算 |
| D07 日志、导出、安装包秘密扫描 | NOT_RUN | 批次 D（安装包）；日志脱敏为既有机制，S 系列专项扫描未执行 |
| D08 真实环境未提供 | NOT_RUN | 本条即纪律本身：兆芯/openEuler 等真实环境未提供，一律标 NOT_RUN 不折算 |

**§16 计数：PASS 50 ｜ PARTIAL 2（H02、A07）｜ NOT_APPLICABLE 1（M07）｜ NOT_RUN 8（D01~D08）**

## 3. 明确后续项（各阶段移交项汇总，不冒充完成）

| # | 移交项 | 来源 | 去向 |
|---|---|---|---|
| 1 | 性能门槛正式双报告（固定硬件普通 amd64 + 兆芯/openEuler）与 24h 稳定性 | S1 §3（本环境噪声大于门槛不冒充）、S6/S7 §已知限制 | 性能专项/批次 D |
| 2 | NG-REL-02 完整包与前台升级兼容（纯离线测试机安装/升级/失败恢复，含 openEuler 测试） | RD 计划 §15.2 | 批次 D |
| 3 | NG-REL-03 运维/限制/版本与交付清单（需用户批准发布） | RD 计划 §15.2 | 批次 D |
| 4 | M07 完整审批闭环（审批参数变化/重放/跨租户复用） | S6 M07/§已知限制（RD_PLAN §11.3 子阶段） | 审批子阶段 |
| 5 | gRPC G2/G3（streaming 逐消息检查与背压）；>1MiB 无压缩大体 h2c 转发挂起排查 | S5 关闭声明/§偏差 6 | 后续批次 |
| 6 | MCP stdio/本地工具出网受控出口（SSRF 专项）、词表外方法 DENY 旋钮、GET SSE 反向请求面、会话状态机、调用预算 stage5 证据、发布校验警示管理面展示 | S6 §已知限制 | 后续批次 |
| 7 | DPoP 路线试点、控制面批准公钥同步通道、撤销 ACK 拓扑可视化、机器身份↔apiauthz 融合评审、弱指纹调研、mTLS 客户端证书链验证、RETIRED 窗口事件标注 | S7 §已知限制/§偏差 3 | 后续批次 |
| 8 | AZ：CLOCK_SKEW 负向漂移 stage5 实证（需时钟注入设施）、TENANT-001 阻断资格评审、角色基线行级 enforcement 写通道、报表归并 UI 化、双人复核、权威在线推送通道/来源删除端点、快照体积基准 | S3-AZ02/AZ03 §遗留 | 后续批次 |
| 9 | FLOW：多 ACTIVE 绑定同端点 commit 语义、实例键加 definition_id 分量、步骤级超时与传输层超时映射、指标增量聚合、业务签名回执/源站自动回查、定义可视化编辑器 | S4 §移交项 | 后续批次 |
| 10 | COV：SHADOW/CANARY 灰度生命周期+远端次要节点 manifest 通道、前端「覆盖与验证」视图、能力清单 h2 层级评估 | S1 §5.4/5.5/5.6 | 后续批次 |
| 11 | HTTP：h2→h1.1 链路拓扑（topology.yaml untested）、path-rewrite 链扩编、go-ftw 10014xx 簇用例整改后复跑 | S1 §5.2/5.3 | 后续批次 |
| 12 | ha-lab 双节点分区演练矩阵（AZ-02/03 与 FLOW 合并编排，含 A07 分区断言） | S3/S4 移交 | 后续批次 |
| 13 | 本批新登记：stage8-unified-decision-tests.sh 缺 Bot 墓碑前置（S3-AZ03 联调新发现 3 已载明的部署契约，套件脚本未遵守）；protocol-tests.py 为阶段1 POC 适配物（自述「仅对本地 POC 网关执行」），是否纳入 stage5 常规回归待裁决；stage5 网关头部尺寸上限评审（Caddy 平台缺省 1MB vs POC 64KB 断言差异） | 本批回归报告 §5/§6 | 编排者裁决 |
| 14 | 源码冻结现状：S1~S7 全部交付物当前为工作区未提交改动（384 修改+305 未跟踪，含 web 两页面目录），提交与推送属编排者职责（AGENTS.md 协作纪律），本批不做 git 写操作 | 本批回归报告 §2 | 编排者 |

## 4. 口径与声明

1. 本表只登记已执行证据；PARTIAL/NOT_RUN 逐项注明缺口与去向，无一折算为 PASS。
2. 各阶段出口记录（s1~s7）为本表一手证据来源；本批亲跑回归证据见 `S8-REL01-REGRESSION-REPORT.md`（含首轮三项红灯的根因、处置与复跑全绿记录）。
3. 状态判定按 §15.2「完成证据」列逐字对照；任务「具体工作」列中超出完成证据列的范围（如 NG-COV-02 页面、NG-MCP-04 页面）单独注明交付/移交状态，不混入断言判定。
4. 工作区未提交状态（git 384 M + 305 ??，分支 main @ e341853）如实登记；版本冻结的提交动作按 AGENTS.md 属编排者（Codex）职责。
