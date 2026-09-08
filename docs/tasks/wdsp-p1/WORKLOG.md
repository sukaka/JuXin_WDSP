# WDSP P1 开发接续与记忆文件

更新时间：2026-09-06（S0 实施核实完成，进入 S1）。

## 当前用户目标

2026-09-06 起：按本目录 README 与四份任务书进行功能开发，按 S0→S6 顺序实施，一次一个阶段；**与并行进行的 P0 实施任务（docs/tasks/wdsp-p0）不得冲突，冲突处自行裁决优先级**（裁决结果见 S0 记录「并行任务协调」节）。

历史：此前一轮仅交付 Markdown 任务包（六份文档已完成并校验，保留在下文）。

## 编写基线

- 仓库：`/Users/zhanglei/Documents/JiuZhang_WAF`。
- 核对 HEAD：`3c73774`；当前工作区存在大量未提交改动，观察包括未提交文件，不能仅归因于 HEAD。
- 范围依据：`docs/evidence/wdsp-competitor-gap-analysis-2026-09-06.md` 第 7 节四项 P1。
- 已完成的 P0 任务包位于 `docs/tasks/wdsp-p0/`；其任务书完成与 P0 功能完成是不同状态。
- 本轮仅新增 `docs/tasks/wdsp-p1/` 文档，保护其他现有修改。

## 已核实的关键事实

1. APM 已有真实查询、数据面配置、SQL/异常页面和安全事件 Request ID 跳转；当前部分 CH 查询把未配置与失败统一降为空页 + agentless，需补可判别状态。
2. Bot 已有身份行为、轻量指纹、风险策略与 CC；未找到完整业务浏览器挑战闭环。TLS 版本/密码套件不是 JA3/JA4，管理登录验证码不是业务挑战。
3. Agent 位于 `wdsp-agent/`。已有 HTTP/1 解析、脱敏、磁盘缓存、证书 PoP 传输、管理页及 Kubernetes 元数据代码；当前 HTTPRecord 注释和协议契约不能直接表达所有解密后、多路复用场景。
4. Nginx mirror 只镜像请求；镜像子请求的响应不能当作原业务响应。Envoy tap 的输入输出形态须按锁定版本验证，不是假定通用 HTTP 推送。
5. 旧 Agent E2E 使用模拟 Kubernetes，脚本存在在临时源码快照加入编译 shim 的路径；这些不能作为本次正式构建的真实 Kubernetes 验收证据。
6. 已有 go-ftw、API 回放、BAS 覆盖映射和 CI。BAS 报告的分类映射不是逐条真实 Payload 回放，不能直接作为检出率分母。

## 文档进度

| 文件 | 状态 | 说明 |
|---|---|---|
| README.md | 完成 | 总纲、依赖、阶段、共享约束与总提示词 |
| P1-01_SECURITY_APM_DEMO.md | 完成 | 真实演示、数据健康、关联和 18 项验收 |
| P1-02_BOT_CHALLENGE.md | 完成 | 应用策略、挑战、网关边界和 24 项验收 |
| P1-03_AGENT_GATEWAY_PROTOCOLS.md | 完成 | 接入矩阵、三方契约、可靠性和 28 项验收 |
| P1-04_RULE_MODEL_REGRESSION.md | 完成 | 固定语料、候选对比、可信证据、发布门禁、回退和 26 项验收 |
| 文档校验 | PASS | 6 份 Markdown、23 个本地链接、96 个验收 ID、代码块和表格结构均通过 |

六份 Markdown 已写完，包含 96 项强制验收要求。最终复核补全 Agent 与风险引擎文件路径，核对 `traffic.agents.view` / `traffic.agents.manage`，澄清关闭访问日志对应用探针数据的影响，以及发布记录与已签名回归报告的不可变边界。以下功能开发状态保持未实施。

## 文档校验记录

2026-09-06 使用 `python3` 标准库内联脚本，检查本目录全部 Markdown 的本地链接、代码块闭合、表格列数、行尾空白、验收 ID 连续性/唯一性、模块提示词与实施状态；最终退出码为 0。

- 文档 6 份，本地链接 23 个，无失效链接或结构错误。
- 四份任务书分别包含 18 / 24 / 28 / 26 项验收，共 96 项。
- 核对 74 个行内仓库路径：73 个存在；`test/security-apm-demo/` 为明确标注的新增目录，不是已有实现。
- 复核时 P0 共用运行器路径已经出现；路径存在不代表其能力或测试完成，实施阶段仍须核对真实状态。
- S0–S6 七个功能实施阶段均为 NOT_RUN。本轮未运行应用单元、接口、E2E 或性能测试，未改动产品代码、应用版本、提交或推送。

文档交付已完成。下一位开发模型从 README 的 S0 开始核实当前代码与依赖，再按阶段实施；不要把本次文档 PASS 计入功能验收。

## 功能开发进度

下列状态用于实施模型接续，不因文档写完而改为 PASS。

| 阶段 | 状态 | 证据 |
|---|---|---|
| S0 实施现状核实与契约冻结 | PASS | 2026-09-06 完成四项现状核实与共享契约冻结，详见「S0 记录」；代码行为未改动 |
| S1 回放基础与改动前基线 | PASS（工具层） | 2026-09-06 完成 P1-04 R1：语料契约+判定/对比+run.sh 增量+174 单测全绿；真实网关回放 BLOCKED_ENV（无隔离栈，不假 PASS）。详见「S1 记录」 |
| S2 安全与 APM | PASS（APMD-017 除外） | 2026-09-07 A1/A2/A3、2026-09-08 A4（真实产品栈联调四场景 PASS）完成，见四条 S2 记录；APMD-017 用户耗时验证 BLOCKED（无未参与者人员条件，任务脚本已固化待执行） |
| S3 Bot 挑战 | PASS（4 项 PARTIAL 如实披露） | 2026-09-07 B0+B1+B2、2026-09-08 B3 预备+B3 请求链接入（真实 Caddy/Valkey 集成测试 PASS）+B4（管理页+基准 27/27）+B5（升级/关闭/回退演练 23/23）完成，见 S3 各记录；验收矩阵 BOT-001~024 PASS 20/PARTIAL 4/FAIL 0（docs/WDSP_BOT_CHALLENGE_ACCEPTANCE_MATRIX.md） |
| S4 Agent 协议与 K8s | PASS（AGT-021/022 BLOCKED_ENV） | 2026-09-08 G0-G5 全部完成（含 G5 兼容升级回退+完整矩阵回归复跑），见 S4 各记录与 docs/agents/WDSP_AGENT_P1_SUPPORT_MATRIX.md；真实 K8s 证据 BLOCKED_ENV（本机无集群，组件级断言已覆盖） |
| S5 持续门禁与回退 | PASS | 2026-09-08 R3（CI 分层+证据登记+发布门禁，迁移 000134/135，stage 5/5）、R2（全量回放 24 例语料，基线 48/48、候选对比精准捕获唯一预期内丢失检测、性能关联）、2026-09-09 R4b（ENFORCE 端到端+误报/故障回退全相位 PASS 无 BLOCKED）与 R4a（回归管理界面+页面 E2E 11/11）完成，见 S5 各记录与 docs/evidence/regressions/ 两份终验报告 |
| S6 最终交付 | PASS | 2026-09-09 汇总交付证据与客户说明 docs/tasks/wdsp-p1/DELIVERY_SUMMARY.md；最终全量验证扫尾全绿（gateway 根+子模块、server build+vet+internal 全包、wdsp-agent、web 113 文件/858 用例、p1reg 201 单测） |

## S0 记录（2026-09-06，实施现状核实与契约冻结）

阶段/任务书：总纲 S0，兼 P1-04 R0；任务书版本 2026-09-06。

时间、分支、commit、工作树摘要：2026-09-06；分支 `develop`；HEAD `3c73774`；工作树约 1540 个已修改/未跟踪文件（非本任务引入）。**重要：P0-03 JWT 信任链的实现代码已存在于工作树但未提交、未登 P0 WORKLOG**（`server/internal/jwttrust/`、`gateway/dynamic_security/jwtverify/`、`gateway/modules/jiuzhang_guard/jwt_trust.go`、迁移 000125/000126/000127、`web/src/pages/applications/detail/JwtTrustTab.tsx` 等全部未跟踪）——P0 任务正在本工作区活跃开发，其 WORKLOG（S3 NOT_RUN）滞后于实际。本阶段为只读核实，仅修改本 WORKLOG。

### 并行任务协调（用户裁决授权的优先级约定）

| 共享点 | 归属与优先级裁决 |
|---|---|
| 数据库迁移编号 | P0 已占至 000127（000047 为历史跳号）。**P1 自 000128 起**；每个 P1 阶段动笔前必须重核 `server/migrations/` 最大编号，与 P0 新增的迁移错号。 |
| final_decision schema 本体 | **归 P0-04（S4，当前 NOT_RUN）**。P1-02 不得先建本体；仅在 P0-04 schema 落地后做有版本的 CHALLENGE 增量扩展（类型/存储/聚合/查询/旧客户端回退）。若进入 S3 时 P0-04 仍未落地，P1-02 只做不依赖 final_decision 的 B0–B1，CHALLENGE 相关验收（BOT-022）保持 BLOCKED，不用 API final_action 或 HTTP 状态码冒充。 |
| P0-02 runner（`test/performance/p0/run.sh`、`p0bench/`） | 归 P0。**P1-04 只做严格增量**：白名单（run.sh:650）加 `regression`/`compare`、`cmd_regression`/`cmd_compare` 函数、`p0bench/cli.py` 加子命令；不改既有六子命令语义与 plan 校验口径。`p0bench.corpus` 与 P0 语料 v1 schema 硬绑定，P1 语料校验器另建于 `test/regression/p1/`，不改 `p0bench.corpus`。 |
| 受控证据存储适配器 | P0-01 已实现的是 git 文件+离线校验器，**服务端受控存储不存在**。由 **P1-04（R3，S5 阶段）负责新建双方共用的受控本地存储适配器**，此处声明以避免 P0 S6 重复开发；P0 侧如先到 S6 需要它，应读本文件并在 P0 WORKLOG 记录引用关系。 |
| `docs/capabilities/capabilities.json` | 归 P0-01 维护。P1 各阶段产出真实证据后只按既有 schema 追加 evidence_refs/状态（S6 汇总时），不改工具与 schema。 |
| 网关 `module.go` / `guard.go` 等共享文件 | P0 S3/S4 正在改（JWT 挂接、处置上下文）。P1 在 S3/S4 之前不触碰这些文件；进入 S3/S4 前先重读 P0 WORKLOG 与 git diff 确认其已落定。冲突总原则：**P0 已冻结契约优先，P1 只做有版本增量；共享文件先落地者优先，后来者重核双方 WORKLOG**。 |
| 旧共享环境脚本 | `test/waf/scripts/stage8-replay-tests.sh` 及 stage5 栈继续归历史用途；P1 回归禁止以默认值引用共享库/固定容器名（`jiuzhang-stage5-*`），必须用 P0 隔离参数。 |

### 四项任务书现状核实结论（逐项核实，仅列关键事实与差异）

**P1-04（回归）**：
- go-ftw 语料存在（`test/waf/ftw/crs-tests/` 202 个用例，断言走 Coraza 审计日志 `expect_ids`）；版本锁 v2.4.0 仅在 `docs/DEPENDENCIES.md:14` 与 SBOM，**无可执行版本校验，CI 不跑 ftw**；`ftw.yaml` 写死 stage1（127.0.0.1:18080 + bind mount 审计日志）。
- `stage8-replay-tests.sh:27-30` 确认寄生共享 stage5（固定容器名、共享库、无状态重置），与任务书限制 3 一致。
- `tools/bas-regression/` 存在，但静态映射引用的 4 个 .conf（webshell.conf 等）在当前 CUSTOM_PACK 已不存在，`DEFAULT_XLSX` 是开发者本机绝对路径——作为覆盖分母来源前须先修复。
- 模型回退（`runtime_policy.go:324-373` RollbackToKnownGood + 重触发发布、失败落 FAILED）与任务书限制 4 一致，可复用。
- 规则摘要：仅 `waf_rules` 逐规则 content_hash；**规则包级不可变摘要不存在**，需新建。
- 发布：`publisher.go:521-564` 次要节点 ACK 为事后回填 `last_sync_*`、不阻断发布；快照不可变（版本链+configuration_hash）属实。"等全部节点 ACK 再回放"是新增要求。
- CI（`.github/workflows/ci.yml`）：无 schedule；**嵌套 Go 模块 jiuzhang_guard（59 测试文件）/dynamic_security（80）/wdsp-agent（39）在 CI 零覆盖**，任务书限制 5 证实。
- P0-02 runner 已实现且结构清晰（run.sh:647-669 白名单分发；p0bench 提供 plan/corpus/isolation/replay/metrics/reconcile/report 可复用件）；P0 语料 21 条，deferred 两条（A-JWT-01 待 P0 S3、A-EXC-01 待 P0 S4）。
- 证据服务端存储不存在；`test/regression/` 不存在。

**P1-01（安全+APM 演示）**：
- "CH 未配置/失败降级为空数据+agentless"属实（`chstore.go:9-10` 纪律注、`258-275`、`296-357`；`chstore_aggregates.go:282` 等）；availability/query_state/reason_codes/correlation 字段**全部不存在**。
- `trace-search` 支持 request_id/时间窗（上限 24h、分页 100），**不支持 application_id**；应用级 RBAC 不存在（仅全局权限点），A0 须如实声明复用全局模型。
- 前端：事件跳转**仅**携带 request_id（`EventDetailDrawer.tsx:275-284`）；Traces 页 URL 预填仅 trace_id/request_id，五态（加载/等待/缺失/无权限/存储故障）不区分；SQL/异常页无 trace 级定位参数。`ApmTraceDrawer` 的 404 分支为死代码（后端无命中返回 200 空数组）。
- 传播链：内部 request_id 由 Caddy headers handler 覆盖式写入（外部同名头不污染）；`trace_inject_upstream` **默认 false**，演示需显式开启；`CHHealth.LatestIngestAt`（`chstore_health.go:59`）可复用为入库水位来源。
- `test/security-apm-demo/` 不存在；`docker-compose.apm.yml` central profile 镜像 tag+digest 双锁可复用。

**P1-02（Bot 挑战）**：
- 业务挑战闭环、`/_wdsp/` 保留端点、bot-policy API、`bot_policy.*` 权限、CHALLENGE 动作**全部不存在**（riskengine 动作枚举 `config.go:28` 显式排除 CHALLENGE/TEMP_BLOCK 新类别）。
- 网关链路核实：CC 在 `module.go:1318-1320`、serveNext 在 `1322-1323`，Bot 插点与任务书 §3.2 一致；**但保护地址（1242）、白名单（1271）、L7 allow（1345）三处直达 serveNext，不经 CC 之后**——"白名单/L7 allow 不隐式跳过 Bot"需在 B0 显式设计挂接并经集成测试验证。
- 应用级策略最佳先例 = jwttrust（按应用草稿行+版本历史表+expected_version 409+preflight+fail-hard 发布+前端 Tab），Bot 仿此；CC 的 AppRules 扇出形态不适合单策略版本化。
- Valkey 纪律：共享引擎、键前缀 `jiuzhang:guard:*`、单 Lua 往返+300ms 超时、现有消费方全部 fail-open 回退内存；**Bot PROTECT 状态不可用须 503 fail-closed，是对既有纪律的显式例外**，B0 冻结。
- final_decision 本体未实施（P0-04 NOT_RUN），见上方协调表。

**P1-03（Agent 协议）**：任务书 5 个疑点**全部属实**——
- 单条超大记录独占批（`events/http.go:80-96` 首条无条件入批）→ 服务端 400 → 转磁盘缓存 → 无限重放死循环（`agent.go:757-766`）。
- 资产发现不持久化 source/agent_id（`machine_http.go:13-16` 包注释自述偏离）；`linkHTTPAssets` 硬编码 ProtocolType REST、按 method+path 去重不含 host。
- v2 字段（schema_version/event_id/source_type 等）全部不存在；注册/心跳无能力协商字段（唯一先例：404→L0 降级）。
- 磁盘缓存活动段不参与年龄/大小淘汰（`buffer.go:172,179` 的 `len(segments)>1` 条件），总量可超上限约一个活动段（~37MB）；无丢弃计数器。
- E2E 编译 shim（`test/wdsp-agent-e2e/run.sh:123-151`）与 fake kube（284-307 + `fake_kube_server.py`）确认存在，正式验收禁用。
- 另：`agent_http_events` 无 event_id/唯一约束，重放产生重复行；k8smeta 失败保留旧快照但无 STALE/UNAVAILABLE 状态与条目 TTL；RBAC 为 ClusterRole（watch 权限冗余）；daemonset 镜像 `jiuzhang/wdsp-agent:2.3.0` 未锁 digest。

### 冻结的共享契约（S1 直接执行依据）

1. **状态词表**：PASS / FAIL / SKIP / BLOCKED / NOT_RUN / NOT_APPLICABLE，与 `p0bench/report_core.py` 词表完全一致；环境阻塞机器口径 status=BLOCKED、reason=ENVIRONMENT_UNAVAILABLE。
2. **P1 语料 manifest schema v1**（新建于 `test/regression/p1/`，不复用 p0bench.corpus 校验器）：顶层 `schema_version(=1)/corpus_id/created_at/description/cases`；用例字段按任务书 §4.1 十项（case_id/case_version/content_sha256/family/tags/criticality/truth(BENIGN|ATTACK|UNKNOWN)/truth_reason/source/license/authorization/scope/prerequisites/steps/seed/reset_plan/expectations_by_profile/evidence_requirements/dataset_partition(TRAIN|VALIDATION|HOLDOUT)）；拒绝未知 schema 主版本、重复 ID、路径越界；UNKNOWN 与 deferred 不进分母的口径沿用 P0。
3. **run.sh 挂点**：`main()` 白名单加 `regression|compare`；新增 `cmd_regression`/`cmd_compare`；Python 侧 `p0bench/cli.py` subparsers 加同名子命令；退出码非零覆盖 FAIL/BLOCKED/NOT_RUN/非法 SKIP/数量不足/证据校验失败；`compare` 只读已完成证据目录。改动保持纯增量，不改既有子命令。
4. **证据根**：`docs/evidence/regressions/<run-id>/`，run_id 沿用 `YYYYMMDDTHHMMSS-xxxxxx`；plan.json 0444 冻结、manifest.json、status.json、逐例结果、report.md 只读生成的纪律沿用 P0-02 benchmarks 目录规则。
5. **受控本地存储适配器（原则冻结，R3 前细化）**：对象 ID 由服务端生成；写入仅经受控登记接口；流式 sha256；manifest ≤4 MiB、导入请求 ≤1 MiB、用例结果分块；保留期与限额在 R3 设计记录中给数值；只读读取接口不泄露越权对象。
6. **快照指纹（原则冻结）**：候选指纹 = 配置快照 configuration_hash + 规则包摘要（新建）+ 模型/运行时产物 content_hash + 执行构建 digest 的确定拼接；规范化字段白名单与版本化在 R3 冻结，禁止为命中旧证据任意删字段。
7. **节点 ACK 口径（S5 前细化）**：现状扇出事后回填；回归执行前等待目标节点 ACK 的来源（last_sync_* 或新通道）、超时与部分生效词表在 S5 与发布门禁一并冻结。
8. **CI 分层（原则冻结）**：嵌套 Go 模块枚举（gateway/modules/jiuzhang_guard、gateway/dynamic_security、wdsp-agent、server 等 8 个 go.mod）纳入 PR 层；定期完整回归用 schedule 工作流；go-ftw 版本断言加入 preflight（可执行校验位置）。
9. **go-ftw 运行环境**：正式回归中 ftw 必须在 P0 隔离栈运行，不复用写死 stage1 的 `ftw.yaml`；S1 生成隔离变体配置。

### 验收 ID 基线

共 96 条：APMD-001～018、BOT-001～024、AGT-001～028、REG-001～026。当前全部 NOT_RUN。

### 计划改动文件（S1，允许随实施微调并在后续记录说明）

- 新增：`test/regression/p1/`（corpus/manifest.json、cases/、profiles/、adapters/、tests/、README.md）、`docs/evidence/regressions/README.md`。
- 增量修改（P0 资产，严格增量）：`test/performance/p0/run.sh`（白名单+usage+两个 cmd 函数）、`test/performance/p0/p0bench/cli.py`（子命令）及必要的 p0bench 新增模块文件。
- 不触碰：`p0bench/corpus.py`、`p0bench/plan.py` 既有校验口径、P0 语料、任何 server/gateway/web 业务代码。

实际执行命令与环境标识：只读核实（4 个并行探查代理 + git status/log），未运行应用测试，未修改产品代码。

未完成事项、依赖和限制：P0 S3 实现未提交且未登其 WORKLOG，P1 后续阶段以"工作树实际内容 + 双方 WORKLOG"双重核对为准；S2/S4 的真实环境（隔离硬件、Linux K8s、Envoy）若不可用按 BLOCKED_ENV 标记。

下一步：S1 — P1-04 R1，首批正常/攻击语料、回放适配器、隔离与状态重置、改动前基线（冒烟级，不宣称全量验收）。

## S1 记录（2026-09-06，P1-04 R1：语料契约、回放适配器、前测基线工具）

阶段/任务书：S1 = P1-04 R1；任务书版本 2026-09-06。主代理复核后登记。

时间、分支、commit、工作树摘要：2026-09-06；`develop` @ `3c73774`；工作树沿用 S0 基线（P0 S3 代码仍未提交）。本阶段新增 `test/regression/p1/`、`docs/evidence/regressions/` 两个目录，对 `test/performance/p0/run.sh`（P0 未提交资产）做严格增量；未 git add/commit。

本阶段目标与改动文件：
- 新增 `test/regression/p1/`：`p1reg/` 工具包（纯标准库 2058 行：corpus schema v1 校验器、runplan、replayplan、judge、compare、report、cli 八个子命令）、`adapters/http_replay.py`（environment=None 恒返 BLOCKED/ENVIRONMENT_UNAVAILABLE；敏感头/正文只留 sha256 指纹；重置计划拒绝 FLUSHALL/FLUSHDB）、`profiles/observe.json`+`protect.json`、`corpus/`（manifest v1 + 18 条 WAF 用例：7 BENIGN 全 MANDATORY、11 ATTACK；TRAIN 仅正常样本，攻击样本全部 VALIDATION/HOLDOUT；manifest sha256 `53cfe68c…e6152e`）、`tests/` 174 个 unittest、README.md。
- 新增 `docs/evidence/regressions/README.md` + 首个真实运行证据 `20260906T235413-1797f7/`（plan.json/replay-plan.json 0444 冻结、status.json：corpus-validation PASS、regression-plan PASS、replay-plan PASS（36 计划样本）、regression-execution BLOCKED/ENVIRONMENT_UNAVAILABLE）。
- run.sh 严格增量（现 1054 行；增量段 891-1054：`regression|compare` 白名单、usage、`cmd_regression`/`cmd_compare` 等五函数）；既有六子命令与 p0bench 全部文件未动（复验：cmd_preflight/smoke/correctness/matrix/soak/recovery 原位保留）。

与任务书/S0 的差异及理由：S0 曾计划给 `p0bench/cli.py` 加子命令；实际 P1 工具自带 CLI（`python3 -m p1reg.cli`），功能入口等价且对 P0 资产零改动，冲突面更小。语料暂不覆盖 API/JWT/例外/Bot/Agent/APM 类（对应 P0/P1 阶段未落地，已在 manifest description 与 README 如实标注待补充，未放占位假样本）。

实际执行命令与结果（主代理独立复验）：
- `python3 -m unittest discover -s test/regression/p1/tests` → Ran 174 tests OK。
- `bash -n test/performance/p0/run.sh` → 通过；`p1reg.cli validate-corpus` → `CORPUS_OK cases=18`，exit=0。
- 篡改检测（编码代理执行）：改 1 字节用例 → content_sha256 失配，exit=2。
- `run.sh regression --plan test/regression/p1/run-plan.example.json` → 计划/语料 PASS，执行层如实 BLOCKED，exit=3，证据落盘。
- `run.sh compare`（夹具：candidate 新增 1 条失败）→ 逐例差异报告 verdict=FAIL，exit=1。

验收 ID → 状态（工具层，非真实网关验收）：REG-001（schema/数量/缺失拒绝）、REG-002（哈希篡改检测）、REG-003（计数/N-A 口径单测）、REG-008（分区隔离与禁止自动更新 expected 的校验器逻辑）→ PASS（工具层单测）；REG-004/005/006/007/009/010/011/012/014/024/025/026 等需真实环境或后续阶段 → NOT_RUN/BLOCKED；CI/门禁/签名类（REG-013/015-023）属 R3 阶段 → NOT_RUN。

数据库迁移/配置兼容/回退方式：本阶段无。

协调事项（转 P0 任务）：发现 macOS /bin/bash 3.2 + UTF-8 locale 缺陷——`$VAR` 后紧跟全角字符时变量名越界（set -u 下中断且 EXIT trap 可能洗码）。P1 增量段已用 `${VAR}` 界定；**P0 所写 run.sh 既有行存在同类隐患**（约 run.sh:329、549、566、703、761），建议 P0 任务统一改 `${VAR}`（无语义变化）。P1 未代改 P0 区域。

未完成事项、依赖和限制：执行层未接隔离栈（S1 预期，真实回放与事件对账属 R2/S5）；攻击样本期望基于 CUSTOM_PACK/CRS 声明范围编写、未经真实网关验证，首跑暴露的误报/漏报即回归目标，修正预期须升 case_version；`.gitignore` 未覆盖 `__pycache__/`（建议后续补一行，本阶段未改根文件）。

下一步：S2 — P1-01 安全与 APM 真实演示（A0 核实已在 S0 完成，直接进入 A1 演示环境搭建与 A2 后端 availability 增量）。

## S2 记录（2026-09-07，P1-01 A1：安全与 APM 标准演示——独立演示夹具）

阶段/任务书：S2 = P1-01 A1；任务书 docs/tasks/wdsp-p1/P1-01_SECURITY_APM_DEMO.md。主代理复核后登记。

时间、工作树摘要：2026-09-07；`develop` 分支；新增 `test/security-apm-demo/` 目录（未 git add/commit），另对 `docs/APM_ONBOARDING_GUIDE.md` 加一段指针（§7.1，单一事实来源归演示 README）。未触碰 server/gateway/web、deployment/ 与 docs/tasks/wdsp-p0/。

本阶段目标与改动文件（全部位于 test/security-apm-demo/）：
- `docker-compose.security-apm-demo.yml`：独立编排（服务 A→B→postgres 测试库 + 演示 collector + 演示 ClickHouse；无 name/container_name，run 级标签参数化；端口显式分配绑 127.0.0.1；CH schema 以只读挂载引用 ../../deployment/apm/clickhouse 的 001/002/003，引用而非复制）。
- `run.sh`（bash 3.2 兼容）：preflight / startup [--sampling] / traffic / verify / cleanup 五子命令；run_id 唯一、双标签归属校验、密码 /dev/urandom 现场生成（0600，cleanup 删除）、启动失败回滚仅清本 project；从不调用管理面 API。
- `services/`（独立 Go 模块）：service-a（otelhttp 入口→B）/ service-b（otelhttp + 手工 DB Span，const SQL 写 db.statement，与产品 SQL 指纹口径 hex(MD5(db.statement)) 精确对齐）/ demootel / democommon（场景白名单 slow-sql|exception，含单测）；Dockerfile 多阶段（golang:1.25-alpine / alpine:3.24 digest 锁，同 server/Dockerfile 基线）。
- `collector/demo-keep-all.yaml` / `demo-sampled.yaml`：演示采样双配置（对照产品 central-gateway.yaml；sampled 形态正常基线 0%，错误/慢≥2s/WAF 高风险全留）；`db-init/001_demo_schema.sql`（demo_items + demo_sleep_bounded clamp≤3s + 合成错误函数）；README.md（中文操作手册，十节）。

实际执行命令与结果（真实运行，两轮完整取证）：
- keep-all 轮 run_id=`20260907T012233-d53486`：startup（含写入通路 canary 自检）→ traffic（8 类造流全 200/500 如期，trace_id 齐全）→ verify：A1-01~05 全 PASS（A1-02 含四层 Span 父子链 + SpanId 唯一性核对），A1-06/A1-07 SKIP（keep-all / 无 GATEWAY_BASE_URL），尾声 A1-export-health PASS（send_failed_spans=0），exit=3。证据：runs/20260907T012233-d53486/{traffic.jsonl, spans-*.jsonl, verify-report.md, status.json, collector-metrics-final.txt}。
- sampled 轮 run_id=`20260907T012620-1b9f6d`：startup --sampling sampled → traffic → verify：A1-01/03/04 PASS，A1-02/A1-05 SKIP（采样设计丢弃，verify 自动识别形态），A1-06 PASS（决策计数 received=9 / sampled=3 / not_sampled=6 自洽 = 8 造流+1 canary；正常 trace CH 查无），A1-07 SKIP，A1-export-health PASS，exit=3。证据：runs/20260907T012620-1b9f6d/ 同上 + collector-metrics-snapshot.txt。
- 两轮 cleanup 后 `docker ps/volume ls --filter label=apmdemo.run_id` 均归零，证据目录保留。
- 静态验证：`docker compose ... config --quiet` OK；services 下 `go build/vet/test` 全过（democommon 单测 PASS）；`bash -n run.sh` OK；`run.sh preflight` 通过（含镜像 tag+digest 锁定复核、deployment/apm 引用资产存在性）。

实测发现并修复的四个真实缺陷（均有日志/数据证据）：
1. **bash 3.2 + set -u 空数组展开**：demo_req 的 `"${hdrs[@]}"` 在无场景头请求上抛 unbound variable（被 `||` 兜底吞成 status=null）。改 `${hdrs[@]+"${hdrs[@]}"}` 惯用法。
2. **ClickHouse 25.8 物化视图 INVOKER 权限链（本阶段最大发现）**：demo 原授权「仅 INSERT ON apm.otel_traces」（沿用 deployment/apm/clickhouse/README.md:68 口径）在实测中表现为——基表插入成功、MV 推送报 `code 497 ... while pushing to view apm.otel_traces_trace_id_ts_mv`、exporter 重试 6 次后 "Dropping data"，**基表残留 7 倍重复行**（MergeTree 不去重）；002_aggregates.sql 聚合链为两级级联（otel_traces→分钟表→小时/天表），每层都要求写入者对源表有 SELECT。修复：demo apm_writer 改为 `INSERT ON apm.otel_traces` + `SELECT ON apm.*`；并在 startup 增加写入通路 canary（slow-sql 请求，两采样形态均被 slow-keep-all 保留，有界等待入库且 send_failed=0，失败即回滚），verify 增加尾声护栏 A1-export-health，A1-02 增加 SpanId 唯一性核对。**协调事项（转生产工作包）**：deployment/apm/clickhouse/README.md:68 的「仅 INSERT」授权建议在同版本 CH + 该 schema 下会遇到同类报错，生产 collector 写入账号的实际授权面需复核；本夹具不改动 deployment/。
3. **exporter 计数器与入库行为脱节**：v0.154.0 下 clickhouse exporter 重试失败按 span 计 send_failed，重试成功不计 sent（实测 sent_spans=0 而数据已在 CH）。A1-06 证据链改为 tail_sampling 决策计数器（`new_trace_id_received` / `global_count_traces_sampled{decision=...}`，v0.154.0 实测输出，Development 稳定性）+ CH 地面真值；exporter 计数仅作诊断。
4. **pipefail + grep 空匹配自伤**：指标求和管道 `grep ... | awk ...` 在指标不存在（零失败的正常情形）时 grep exit 1，经 pipefail+set -e 静默杀死脚本（canary/尾声护栏曾因此绕过 startup_die 残留栈）。6 处补 `|| true`；另 canary trace_id 提取同法加固。

与任务书的差异及理由：
- compose 增加静态校验占位默认值（`STATIC-CHECK-PLACEHOLDER-NOT-A-SECRET` / `STATIC-CHECK-ONLY`），使裸 `docker compose config` 可解析；真实运行 run.sh 总是覆盖，占位值已在 compose 头注释与 README 声明。
- DB Span 不用 otelsql（goproxy.cn 对其 v0.69.0 报 unknown revision、官源直连超时），改 OTel SDK 手工埋点（const SQL 写 db.statement，Client kind）——与产品指纹口径一致，语义等价。
- 端口由 run.sh startup 显式分配（Docker Desktop 4.43.1 实测空宿主端口不分配随机端口，P0 的「留空随机」写法在本机不成立）；demo 网络 `internal: false`（实测 internal 网络下已发布端口用户态转发不通，与 deployment/docker-compose.apm.yml 同口径）。
- Go 依赖显式锁回主线基线：otel v1.44.0 / otelhttp v0.69.0 / pgx v5.7.2（对齐 server/go.mod）。

验收 ID → 状态：A1-01~05 → PASS（keep-all 轮实测）；A1-06 → PASS（sampled 轮实测，NOT_SAMPLED_CONFIRMED 三件套齐备）；A1-07 → SKIP（GATEWAY_NOT_CONFIGURED：本机无已接入演示应用的既有部署，接入是操作员手动步骤，脚本不代劳、不伪造网关证据）；场景 2/3/6（网关 OBSERVE/PROTECT/并存区分）→ SKIP 待接入后复跑；场景 7（仅网关观测）→ 按设计不自动化（A1 骨架不断言因果）。

协议/权限/性能/兼容限制：新增 Go 依赖均为宽松许可证（otel v1.44.0 全家 Apache-2.0、otelhttp v0.69.0 Apache-2.0、pgx v5.7.2 MIT）；镜像 postgres:16.4-alpine（PostgreSQL License）/ clickhouse 25.8-alpine（Apache-2.0）/ otelcol-contrib 0.154.0（Apache-2.0）/ golang:1.25-alpine、alpine:3.24（同 server/Dockerfile 基线）全部 tag+digest 双锁。演示 Collector 明文 OTLP（compose 内网，4317/4318 不发布宿主；生产中央网关 mTLS 口径不变）。网关→上游 traceparent 注入现状（trace_inject_upstream 恒 false）已在 README §8-2 如实声明，A1-07 按 request_id 对账口径核对。

未完成事项、依赖和下一步：网关联调（场景 2/3/6）需一套既有部署人工接入后复跑 `GATEWAY_BASE_URL=… traffic && verify`；tail_sampling 决策计数器为 Development 稳定性指标，collector 升级时需复核指标名；A2（管理面 availability/UNAVAILABLE 展示接线）与 A3（页面纪律）为后续子阶段。

## S2 记录（2026-09-07，P1-01 A2：APM 后端 availability / correlation / 应用约束）

阶段/任务书：S2 = P1-01 A2；任务书同上节 §4.2/§4.3。主代理复验后登记。

时间、工作树摘要：2026-09-07；`develop` @ `3c73774`（工作树基线同 S0/S1）。改动限于 `server/internal/apm/`（工作树既有未跟踪目录）与 `server/openapi/fragments/12-apm.yaml`；未 git add/commit；未新增迁移与依赖。

本阶段目标与改动文件：
- 新增 `availability.go`（589 行：availability/correlation 判定逻辑、30s TTL 水位缓存按查询器身份失效且失败不缓存、异常文本掩码与 rune 截断）与 `availability_test.go`（967 行，17 个新测试函数）。
- 增量修改：`types.go`（Availability/Correlation/CorrelationCandidate/ExceptionTraceItem 与全部冻结词表常量）、`store.go`（Overview/ServiceDetail availability；TraceView 带 correlation；PG 证据查询 resolveRequestID/securityEventEvidence）、`chstore.go`（SearchTraces 应用约束下推 + request_id 解析，全部出口携带 availability+correlation）、`chstore_aggregates.go`（sql/exceptions trace 级定位，match_mode=trace_exact/window_aggregate，degraded 携带 availability）、`handler.go`（application_id/trace_id 非法 → 400 不静默忽略；services/endpoints/overview 携带 availability）；既有测试按新签名适配；CH 集成测试新增 `TestCHStoreTraceLevelLocation`（无 APM_CH_TEST_DSN 如实 SKIP）。
- `server/openapi/fragments/12-apm.yaml` 同步：3 个新查询参数、4 个新 schema、8 处既有 data schema 扩展。

接口最终形状（A3 前端对接依据）：availability={query_state(READY/EMPTY/PARTIAL/UNAVAILABLE), reason_codes[9 冻结枚举], observed_sources[GATEWAY,OTEL], last_collected_at, last_ingested_at, estimated_lag_ms, partial}；correlation={state(MATCHED/AMBIGUOUS/PENDING/NOT_FOUND/NOT_EXPECTED/UNKNOWN), match_basis, candidate_count, reason, candidates[]}（trace-search 仅 request_id 检索时携带，omitempty；traces/{id} 恒携带）；/sql 与 /exceptions 新增 trace_id 参数与 match_mode/match_note，exceptions 另有 trace_exceptions[]（掩码+截断标记）。envelope、data_source/message 旧字段、开关 503、无权限 403 语义不变。

实际执行命令与结果（主代理复验）：`cd server && go test ./internal/apm -count=1` → ok（无 FAIL）；`go vet ./internal/apm` → 干净；`go build ./...`（server）→ 通过；gofmt 干净。实施中修复一处真实缺陷：掩码正则原实现遇 `Authorization: Bearer <token>` 只掩到 Bearer 一词、令牌本体泄漏，已修并加泄漏回归断言。

与任务书差异及理由：application_id 指向不存在应用返回 400（覆盖 endpoints 空页先例，OpenAPI 已写明）；NO_INSTRUMENTATION_CONFIRMED/NOT_SAMPLED_CONFIRMED 保留词表但本阶段不产出（无探针注册/采样决策证据源，仅凭查不到 Span 只报 NO_MATCH/UNKNOWN）；endpoints 的 availability 为保持六接口口径一致的自扩项。

验收 ID → 状态：本阶段支撑 APMD-008/009/011/012/013/015 的后端判定能力（工具层单测覆盖）；这些 ID 的接口+E2E 验收待 A3/A4 真实环境，保持 NOT_RUN。

协调事项：① `server/openapi/wdsp-api.yaml`、`openapi.yaml` 为 tracked 且带他人未提交改动，本阶段**未重新生成**；需编排方在合适时点跑 `python3 server/openapi/merge.py` + `make openapi-reconcile`（只加参数/字段不加路由）。② NOT_EXPECTED 证据边界当前 = access_logs.waf_action=BLOCK 或 security_events.action='BLOCK'；P0-04 final_decision 落地后的合流替换点已在 availability.go 头注释标明（判定函数单点替换）。

已知限制：estimated_lag_ms 为表级水位估计非请求级；request_id 全局唯一使 AMBIGUOUS 理论难触发（防御逻辑保留并有测试）；掩码尽力而为（cookie 多键值对仅掩首值）；message/stack rune 截断 2048/8192 带标记。

下一步：A3 — 前端事件/Trace/SQL/异常跳转与五态缺数据 UX（按本节最终接口形状对接），随后 A4 网关联调、演示脚本固化与用户任务耗时验证（APMD-017 人员条件不具备时标 BLOCKED）。

## S2 记录（2026-09-07，P1-01 A3：前端跳转上下文与五态缺数据 UX）

阶段/任务书：S2 = P1-01 A3；任务书 §5 文案要求与 §4.3 契约。主代理复验后登记。

时间、工作树摘要：2026-09-07；`develop` @ `3c73774` 工作树基线。改动全部在 `web/`；未 git add/commit。说明：A3 实施主体由编码代理在首次会话完成（文件时间戳 01:48–01:51），该会话中断未及终验；接续会话逐条对照任务书 §5/§4.3 与 A2 接口形状完成核实与一处防御加固（`ApmAvailabilityAlert.tsx:65-67` 为 observed_sources 补空值兜底），再实跑全部门禁。

本阶段目标与改动文件（web/ 内）：
- 新增/扩展工具与组件：`web/src/utils/apm.ts` A3 段（五态词表中文映射、入库等待判定与 30s 预算/5s 间隔退避、站内白名单返回路径 `sanitizeApmReturnPath` 拒绝 `//`/scheme/控制字符、事件跳转 href 构造 request_id+application_id+±5 分钟窗、URL 时间窗解析、纯文本截断）；`ApmAvailabilityAlert.tsx`（availability 统一展示 + 入库水位组件，含「目前仅有网关观测数据」与接入指引）；`ApmCorrelationNotice.tsx`（关联强度与 AMBIGUOUS 候选表，不自动任选）。
- 页面：`ApmTracesPage.tsx`（URL 预填扩展 start_time/end_time/service/application_id，非法值忽略并提示；五态区分——加载/等待入库有界重试且卸载清理定时器/无匹配/403 不泄露存在性/UNAVAILABLE 显示「调用链存储暂不可用」+重试不渲染零值表）；`ApmTraceDrawer.tsx`（详情携带时间窗+application_id、关联强度与 partial 展示、权限裁剪下钻、NOT_EXPECTED 文案）；`ApmSqlPage.tsx`/`ApmExceptionsPage.tsx`（trace_id 深链、window_aggregate 标注「同时间窗候选，未精确定位」、堆栈纯文本+长度上限）；`EventDetailDrawer.tsx` 在他人未提交改动（JWT 验证信息）之上叠加跳转，未覆盖。
- 类型与 API client：`web/src/types/index.ts:2246-2467`、`web/src/api/apm.ts`（application_id/trace_id/详情时间窗参数）、路由权限门 `web/src/router/index.tsx:907-955`。
- 旧后端缺字段 → 全部显示「状态信息不足」（traces 页 :210,331、SQL 页 :280、异常页 :289、抽屉 :143-145），不编造原因。

测试与验证（主代理复跑确认）：`npm run typecheck`、`npm run lint` 通过；`npm test` → **105 文件 / 781 用例全绿**（其中 A3 新增约 62 个：五态矩阵、URL 非法值、from 开放重定向拒绝、correlation 各态、权限裁剪、HTML 不执行断言、30s fake-timers 有界等待与卸载清理）；`npm run build` 通过。Playwright E2E 需真实栈，留待 A4。

与任务书/A2 契约差异：无。已知限制：SecurityEventsPage 筛选为组件内 state（无 URL 参数化），仅列/分页偏好经 storageKey 保留（任务书「已有能力则保持」口径）；estimated_lag_ms 展示标注为表级水位估计；AMBIGUOUS 候选在 traces 页内就地切换抽屉不改写 URL。

验收 ID → 状态：支撑 APMD-002/006/011/012/014/016 的前端能力（组件测试层覆盖）；这些 ID 的 E2E 与真实环境验收待 A4，保持 NOT_RUN。

下一步：S2 收尾 = A4（网关联调场景 2/3/6/7 复跑、演示脚本固化、APMD-017 用户任务耗时验证——人员条件不具备则标 BLOCKED）。之后进入 S3（P1-02 Bot 挑战 B0；开始前须重核 P0-04 final_decision 落地状态与 P0 WORKLOG）。

## S3 记录（2026-09-07，P1-02 B0 契约冻结 + B1 策略/编译/发布链路）

阶段/任务书：S3 第一段 = P1-02 B0+B1；任务书 docs/tasks/wdsp-p1/P1-02_BOT_CHALLENGE.md §3.2/§4/§7。主代理复验后登记。

时间、分支、工作树摘要：2026-09-07；`develop` @ `3c73774` 工作树基线。**并行任务动态：P0-04 已落地迁移 000130_exception_scope_contract / 000131_api_runtime_events_final_decision / 000132_security_events_final_decision（final_decision 本体出现，P1-02 §6 的 CHALLENGE 增量扩展前提开始具备）**。本任务占用迁移 000128/000129（先于 P0 的 000130-132，无碰撞）；**下一 P1 迁移自 000133 起，用前重核**。未 git add/commit。

B0 冻结决策（已编码落地）：
- 信号三组：请求行为（复用 identitybehavior 窗口计数）、访问序列（已知 URI 比例/方法枚举）、客户端声明（UA 分类+TLS 版本/套件，标注可伪造弱信号）；挑战需 ≥2 独立组且 ≥1 行为组，同源计数不重复计权；七指标白名单已冻结。
- 参数：nonce_ttl 90s(30..300)、clearance_ttl 900s(60..3600)、difficulty 14bit(10..18)、max_attempts 3(1..5)、挑战类型 JS；selectors 仅 GET + 路径精确/规范化前缀，禁止正则与全站通配。
- 保留命名空间 `/_wdsp/bot/v1/`（verify 在其下）；route_reservation 版本化（enabled/tombstone/released）；Valkey 前缀 `jiuzhang:guard:bot`（本阶段仅冻结常量）。
- 网关配置解析选 **fail-closed**（jwt_trust 口径：严格解码+全量校验拒绝加载），不用 riskengine 消毒口径——理由：PROTECT 语义被静默降级等于应挑战变放行（bot_policy.go 头注释）。

本阶段改动文件：
- 新增：迁移 000128/000129（bot_policies 草稿行+bot_policy_versions 历史+权限种子，对齐 000125/126 模式）；`server/internal/botpolicy/`（policy/store/validate/handler + 两类测试）；`server/internal/guardconfig/bot_policy.go` + 测试（fail-hard 加载）；`gateway/modules/jiuzhang_guard/bot_policy.go` + 测试（解析/校验/装配，OFF 不装配，非 OFF 仅持有 `g.botPolicy`，**ServeHTTP 未接**）；`server/openapi/fragments/17-bot-policy.yaml`；`server/tests/stage_bot_policy_test.go`（7 个集成测试）。
- 增量：guardconfig/provider.go（loadBotPolicy 接入 BuildGuardConfig、replayRuntimeSecrets 含 BotPolicy PROTECT 依赖检查回滚门禁）；app.go（装配+三条路由）；module.go（Guard 加 BotPolicy 配置字段、Provision/Validate 挂接——请求链未动）。

接口：`GET/PUT /api/v1/applications/{id}/bot-policy` + `POST .../preflight`（冲突预检：L7 拒绝/allow 覆盖、保护地址全量段 WARN、api_endpoints 已登记路径冲突、shared_state、节点能力）；PUT 完整替换 expected_version 409/400/404/403；保存后经现有 PublishFunc 发布（对齐 riskpolicy 口径，状态分离返回不冒充节点生效）；审计升 PROTECT=HIGH。

实际执行命令与结果（主代理复验）：`cd server && go test ./internal/botpolicy ./internal/guardconfig -count=1` → 两包 ok（19 测试）；`go build ./...` 通过；`cd gateway/modules/jiuzhang_guard && go test ./... -count=1` → 全部子包 ok。编码代理另跑一次性容器集成测试 `go test ./tests -run TestBotPolicy` → 7/7 PASS（迁移生命周期/权限/跨应用隔离/preflight 冲突/ListForGuard/down-up），容器已清理。实施中修复真实缺陷：ListReservedNamespacePaths 引用了 000018 已改名的 api_endpoints 列（实跑暴露，已改正）。

与任务书差异：路由参数 `{id}` 与全仓 mux 惯例一致；preflight 超出字面范围增加 shared_state/节点能力检查（同 jwttrust 发布门禁口径）；OFF 也做全量校验（配置面与管理面同口径）。

验收 ID → 状态：支撑 BOT-001（三模式配置面）、BOT-003（选择器规则与冲突拒绝）、BOT-020（权限/CSRF/409/审计）的链路与测试层；完整验收需 B2-B5 真实挑战与网关接入，保持 NOT_RUN。

未完成事项与下一步：B2 —— 挑战状态/nonce 原子消费/clearance 签名（Valkey `jiuzhang:guard:bot` 命名空间、fail-closed 503 例外）与 verify 本地端点；B3 —— ServeHTTP 插点（CC 后 serveNext 前，含保护地址/白名单/L7 allow 三分支显式挂接）+ final_decision CHALLENGE 增量（P0-04 本体已开始出现，动手前重核其 schema 落点与 P0 WORKLOG）。

## S3 记录（2026-09-07，P1-02 B2：挑战安全核心）

阶段/任务书：S3 第二段 = P1-02 B2；任务书 §5/§6。主代理复验后登记。

时间、工作树摘要：2026-09-07；`develop` 工作树基线。**注意：并行 P0 任务同期在改 module.go/apiprotect.go/disposition.go/jwt_trust.go（S4 最终处置），本阶段严格避让，botchallenge 仅 import counters/events/ratelimit 三个稳定包；P0 在 events.go 的 FinalDecision 字段原样保留（本阶段仅纯增量 BotDetail）**。未 git add/commit；无新第三方依赖。

本阶段改动文件（全部新增/纯增量）：
- 新包 `gateway/modules/jiuzhang_guard/botchallenge/`（14 文件约 4000 行含测试）：botchallenge.go（冻结常量/错误哨兵/Config.Validate fail-closed/EventSink）、keyring.go（独立 HMAC 密钥环 current+previous 轮换窗口，key_id 词形+密钥≥32B+仅内存允许列表）、token.go（session/clearance 双 purpose 域分隔令牌 `v1.<b64>.<hex HMAC>`）、pow.go（SHA-256 长度前缀编码 `wdsp-bot-pow-v1‖lp(cid)‖lp(nonce)‖lp(app)‖lp(host)‖lp(solution)`）、store.go（Valkey 状态层 4 个单往返 Lua：issue/read/consume/fail；consume 为比较并消费单往返，双节点并发恰好一次成功）、service.go（Offer/LogObservedOffer/ValidateClearance）、verify.go（ServeNamespace/ServeVerify 全管线：POST-only 405、未知子路径本地 404、8KiB、严格同源 Origin+Fetch Metadata、三维限速、绑定校验、失败绝不设 clearance、204+clearance Cookie、永不反代）、render.go（CSP nonce 严格策略+frame-ancestors 'none'+no-store+全转义+无 eval；内嵌纯 JS FIPS 180-4 SHA-256 含自检向量、2048 迭代分片让出主线程、≤2s 预算、sessionStorage 一次性标记最多自动刷新一次、noscript+aria-live）。
- `events/events.go` 纯增量：6 个 BOT_* 事件类型 + `Event.Bot *BotDetail`（PolicyVersion/PolicyEpoch/Mode/Reason/FlowID/KeyID/Attempts/ResponseNote）+ sanitize 扩展；测试断言 nonce/solution/Cookie/密钥材料/会话摘要不泄漏。

冻结常量：限速签发 6/会话·60/IP·600/应用每分钟、验证 12/120/1200、MaxInFlightPerApp=10000、正文 8KiB、opTimeout 300ms。

实际执行命令与结果（主代理复验）：`cd gateway/modules/jiuzhang_guard && go test -race ./botchallenge/ ./events/ -count=1` → 两包 ok；`go vet` 干净；`grep botchallenge module.go` → 0（请求链未动）。编码代理另跑全模块 `-race` → 17 包全 ok（botchallenge 39 测试函数：16 并发恰好一次 204、重放 409、过期/伪造/未知 key_id/跨 Host/跨应用/代次撤销、篡改难度 400、限速 429、容量 503、故障 fail-closed 503、脱敏断言、CSP/转义）。

与任务书/B0 的差异（裁量记录）：① policy_epoch 暂取策略 Version（B1 schema 无独立字段，换版即撤销，语义等价）；② PoW 输入不含会话（HttpOnly Cookie JS 不可取，会话绑定由状态层 sd 摘要原子比对完成）；③ offer 限速 429 归 ISSUE_RATE_LIMITED 事件（避免枚举膨胀）；④ 每标签页最多一次自动刷新（sessionStorage 标记，防循环）；⑤ Content-Type 仅显式非 json 才 415；⑥ SetReadDeadline 对 HTTP/2 尽力而为（能力探测降级）。

已知限制：页面内 JS 端到端正确性待 B4 真实浏览器验证（页面自检向量兜底）；fakevalkey 与真实 Valkey Lua 语义靠双实现人工对齐，真实 Valkey 集成验证留 B3/B4；server 侧遗留：guardconfig 密钥下发通道（bot_policy.go:66 TODO(B2)）与 accesscontrolevents 的 applyBotEvent 落库。

下一步：B3 —— ServeHTTP 插点接入（CC 后 serveNext 前 + 保护地址/白名单/L7 allow 三分支显式挂接，集成测试覆盖真实 Caddy/Coraza 顺序）、final_decision CHALLENGE 版本化增量（先重核 P0-04 schema 现状）、server 密钥下发通道与 Bot 事件落库。**B3 与 P0 S4 共享 module.go/events 文件，动手前必须重核 P0 WORKLOG 与 git diff。**

## S2 记录（2026-09-08，P1-01 A4：真实产品栈联调与演示脚本固化）

阶段/任务书：S2 = P1-01 A4；任务书 §3.2/§7/§8。主代理抽查复验后登记。

时间、工作树摘要：2026-09-08；`develop` 工作树基线。改动全部在 `test/security-apm-demo/`（该目录整体 untracked）；未 git add/commit；未触碰任何产品代码、docs/tasks/wdsp-p0/、test/regression、test/performance/p0。执行期间 Docker Desktop 曾随机器休眠停止，由主代理重启后继续。

本阶段目标与改动文件：
- 新增 `docker-compose.product-stack.yml`：mgmt-postgres / mgmt-valkey（stage5 同锁定镜像）+ gateway（构建 ../../gateway）+ api（构建 server/Dockerfile，`WDSP_LICENSE_TEST_KEYS=1` 测试口径）+ adminpatch（profile=tool 一次性容器）；api 的 APM_CLICKHOUSE_DSN 按 run 注入演示 ClickHouse（apm_writer 最小授权）。
- 新增 `services/cmd/adminpatch/main.go`（stdlib）：经 Caddy Admin Unix Socket 递归置 jiuzhang_guard `trace_inject_upstream=true` → /load → 回读校验（实测 `{"patched_handlers":1,"verified":true}`）；每次发布自动重打。
- service-a 加 `GET /demo/stats` 源站计数端点；demootel/democommon 支持 OTEL_SDK_DISABLED（场景 7）；run.sh 扩展 --with-product 与分波次 traffic/verify；README.md 更新（§5 复现序列、§8 产品事实声明、§11 固化 APMD-017 任务脚本：5 步动线+4 题正确回答标准+执行纪律）。

真实运行（run_id=`20260908T075619-65f2f8`，同一 run 依次四场景，接入全程走真实管理 API：登录→强制改密→临时授权导入→开访问日志→建 OBSERVE 应用（上游 service-a:8080）→发布至 SUCCESS→adminpatch→网关自检）：
- 场景 2（命中但观察）A4-01 PASS：3 条 OBSERVE 攻击的安全事件 ↔ trace-search correlation=MATCHED ↔ trace 详情含 demo-service-a/b 且 observed_sources=GATEWAY+OTEL。
- 场景 3（网关阻断）A4-02 PASS：3 条攻击全 403；源站计数 delta=2 仅含透传请求；CH 零应用 Span；correlation=NOT_EXPECTED（BLOCK 证据链）。
- 场景 6（同时但无关）A4-03 PASS：攻击与慢 SQL 的 request_id/trace_id 互不交叉；SQL 指纹经 `/apm/sql?trace_id=` trace 级定位对账；只证可区分不断言因果。
- 场景 7（仅网关观测）A4-04 PASS：关遥测后业务照常 200；access_logs 可用；PENDING 余量期（产品既定 5min）后落终态；trace 详情仅 GATEWAY 源零 Span；SQL 页空列表不伪造。
- 同次 verify 回归 A1-01~05、A1-07、A1-export-health 全 PASS；A1-06 按 keep-all 形态 SKIP（sampled 形态已在 A1 轮验收）。证据：runs/20260908T075619-65f2f8/（verify-report.md、status.json 12 行、evidence-a4/*.json 原始 API 响应、spans-*.jsonl CH 地面真值、protect-stats.json 等）。cleanup 实测归零（容器/网络/卷/凭据全删）。

调通中修复的夹具缺陷（7 个，详见编码代理报告）：路由方法误用、乐观锁 version 遗漏、响应字段名 otel_spans、瀑布断言改为 SQL 指纹口径（产品数据最小化剔除原始 db.statement 系既定行为）、request_id 跨波次撞名（加波次分量）、A4-04 等待封顶 6.5min（对齐产品 correlationPendingMargin=5min）、status.json heredoc 写法 bug。**遗留证据瑕疵：A1 两轮（20260907T012233-d53486、20260907T012620-1b9f6d）的 status.json results 为空（该 bug 所致）；verify-report.md 完整（各 8 条 PASS/SKIP），按「不覆盖旧证据」纪律保留原样，追溯以 verify-report.md 为准。**

产品侧事实（非缺陷，README §8 已声明）：`trace_inject_upstream` 网关侧已实现但管理面发布取值接线未落地（guard.go 恒 false），A4 用运行态补丁——**管理面接线属后续工作包（建议列入 S6 或独立任务，与 P0 协调）**；trace-search 的 application_id 约束依赖 apm_services（Agent 认领才建行），演示无 Agent，断言按此口径。

验收 ID → 状态：APMD-002/003/006/007 → PASS（本 run 证据）；APMD-017 → BLOCKED（人员条件不具备，任务脚本已固化于 README §11 待执行）；其余 APMD 项已由 A1-A3 在工具/组件层覆盖，完整 E2E 验收状态以各 ID 对应证据为准。

下一步：S3-B3 —— Bot 接入 ServeHTTP 请求链（先重核 P0 S4 在 module.go/disposition.go 的进展与 P0 WORKLOG），CHALLENGE 写入 final_decision 的版本化增量（P0-04 迁移 000131/000132 已落地，可对接到 Bot 事件）、server 侧密钥下发通道与 Bot 事件落库。

## 阶段顺序调整记录（2026-09-08，主代理裁决）

P0 任务于 2026-09-07 起进入 S4 实施（最终处置/例外），活跃编辑 `disposition.go`、`dynamic_security/decision/`、`securityevents/`、`module.go`。按 S0 裁决（P0 已冻结契约优先、共享文件先落地者优先），**P1-02 B3 的请求链接入与 CHALLENGE final_decision 增量推迟到 P0 S4 落定后**；期间先行推进零冲突工作：B3 预备（server 侧）与 S4（P1-03）G0/G1。理由与范围记录于此，验收门槛不变。

## S3 记录（2026-09-08，P1-02 B3 预备：server 密钥下发通道 + Bot 事件落库）

改动文件：新增 `server/internal/guardconfig/bot_keys.go`（system_settings gateway_runtime 组 `bot_signing_keys` 密文 JSON 通道：解密校验 key_ref 词形/hex≥32B/≤8 条，错误信息不含密钥材料）+ 测试；`server/internal/accesscontrolevents/` 新增 Bot 事件解析（`applyBotEvent` 落 details.bot，rawBotDetail 只声明允许字段——nonce/solution/Cookie/签名材料解码期即丢弃，类型系统保证脱敏；未知类型/字段容忍）+ 测试。增量：guard.go（GuardConfig.BotSigningKeys，经 guardBotPolicyWithKeys 并入应用 bot_policy 段）、publisher.go（WDSP 关闭形态剥除密钥）、guardconfig/bot_policy.go（TODO(B2) 做实：PROTECT 的 key_ref 必须在已注入密钥集合否则 fail-hard 拒绝发布）、provider.go（脱敏 `***`、回滚重放门禁同口径）、app.go 接线、网关 bot_policy.go（signing_keys omitempty 严格解码兼容、assembleBotKeyring→NewKeyring、PROTECT 缺密钥 fail-closed 拒载、密钥环挂 botPolicyJSON.keyring 非导出字段——**module.go 零改动**）。

复验（主代理）：`cd server && go test ./internal/guardconfig ./internal/accesscontrolevents -count=1` ok；`gateway/modules/jiuzhang_guard` 根包+botchallenge+events ok。已知限制：preflight 未加密钥就绪检查（B3 统一处理）；密钥管理面写入入口（UX/轮换手册）留 B4/B5；密钥池全局下发（不按应用隔离）。

## S4 记录（2026-09-08，P1-03 G0+G1 server 侧：v2 契约冻结 + 幂等 + 资产来源关系）

契约冻结：新增 `docs/agents/WDSP_AGENT_HTTP_EVENT_V2_CONTRACT.md`（批次包络与版本判别、逐字段表含 headers/trailers 数组保序/grpc/body_quality、能力协商、批次语义与错误分类、资产来源关系、存储映射、安全纪律；每字段标注 [G1] 落地或 [冻结] 待 G2/G3）。

实现：迁移 **000133**（动笔前重核无碰撞；agent_http_events 加 v2 列 + `(agent_id,event_id) WHERE event_id IS NOT NULL` 部分唯一索引——兼容存量 NULL 行；新建资产来源关系表）；`http_events_v2.go`（类型/枚举/全量校验/能力协商）、`http_store_v2.go`（单事务 ON CONFLICT 幂等，返回新入库下标+重复数）、`asset_sources_admin.go`（GET http-asset-sources，沿用 traffic.agents.view）；machine_http.go 批次版本判别分发（v1 原样保留；未协商 v2 发 v2 → 400 永久失败不静默丢弃）；linkHTTPAssets 重写（去重键含 Host、gRPC 不写死 REST、未绑定→UNASSIGNED 不 upsert、来源关系四态 LINKED/UNASSIGNED/QUOTA_REJECTED/FAILED 可查询）；注册/心跳接入 `capabilities.http_event_schema_versions`（旧 Agent 零感知）。

验证（编码代理实跑+主代理复验）：`go test ./internal/agents -count=1` 约 760 测试 ok（主代理复验同绿）；真实 PG 临时容器 migrate up/down/up 与存量行兼容实证；psql 级幂等验证；临时容器已删。已知限制：v2 headers 管理端详情可视化待 §4.3 阶段；绑定注册表服务端复核标 [冻结]（G2 落地）；429 仅冻结语义未加限流器；旧 Agent 二进制冒烟留 G2+。

## S4 记录（2026-09-08，P1-03 G1 agent 侧：批次预算统一 + 严格缓存 + 背压公平 + 统一指标）

实现（全部 wdsp-agent/）：events/http.go 废除首条无条件入批（超大记录三级缩减→仍超限丢弃计数 dropped_oversize；MaxHTTPRecordBytes=8MiB 减包装开销）；buffer.go 严格限额（活动段不再豁免年龄/大小淘汰，总量硬上限含当前段；单条>maxBytes 拒绝；淘汰按原因计数 size_evicted/age_evicted/corrupt；Stats/OldestAge）；transport.go（APIError.RetryAfter 解析钳制、IsPermanent 400/413/422、429 分类；PostHTTP 返回 accepted+duplicate）；agent.go（400→二分隔离非法记录不转缓存不重放（请求数≤2N-1 无死循环）、429→Retry-After 退避、5xx/网络→转缓存不变；补传独立 replayLoop+带宽份额公平预算默认 30% 不饿死实时；丢弃原因词表九类接进各丢弃点）；httpsensor 脱敏字段计数（masked 指标）；新增 events/http_v2.go（v2 记录构造：StableEventID=SHA-256(agent_id‖flow_id‖request_ts) 重试稳定、SourceRef/关联状态/BodyQuality/GRPCInfo——仅构造未接发送路径，发送接线待 server 契约联调）。

复验（主代理）：`cd wdsp-agent && go test ./internal/... -count=1` 19 包全 ok；编码代理另跑 `-race`（buffer/events/agent）ok。覆盖：100 条/8MiB 含转义边界、超大缩减/丢弃、400 无死循环、429 窗口、活动段超龄、满盘/损坏段/重启、补传公平、指标快照。已知限制：association_pending 用重组连接表近似；公平预算为带宽份额维度；ReplaySharePercent 与 server 契约对齐待联调。

## S4 记录（2026-09-08，P1-03 G1 双侧联调：agent v2 发送路径接通 server v2）

agent 侧（wdsp-agent/）：注册/心跳声明 `capabilities.http_event_schema_versions=[1,2]` 并按服务端回执生效集切换 v2/v1 线格式；v2 批次按契约构造发送；202 accepted/duplicate 分账并校验计数恒等式；400 invalid_records 按索引隔离（不再二分）；未协商/旧服务端完全走 v1；缓存保持 v1 格式、发送时重构造 v2（event_id 内容派生，重放不变，集成测试实证）。**联调中发现 agent 侧原 http_v2.go 草稿与冻结契约多处不符并已对齐**：observed_http_version 枚举改 "1.1" 词表、association_reason 用 TIMEOUT、body_quality 内嵌 request/response 且字段名 original_total_size、headers 改数组形态、schema_version 仅在批次包络、绑定两字段同有同无、budget_exceeded 转写 truncated=true。server 侧逐字段复核与契约一致、零改动。
验证：wdsp-agent 20 包 ok（含 5 个真实往返集成测试：协商→分账、索引隔离、旧 server 降级、未协商 400 降级、500→缓存→补传 event_id 不变）；server agents 包 ok；主代理复验 wdsp-agent 全量 ok + vet 干净。
**契约固有张力（待 G2/G3 前澄清）**：契约 §2.1 要求 truncated=true 必配非 null original_total_size，"截断但原始总大小未知"不可表达；mirrorsrc chunked 未读尽场景会被服务端 400 隔离——需在 G3 前定适配口径。

## S4 记录（2026-09-08，P1-03 G2：Nginx mirror 适配器 + 真实 Nginx 取证）

新增：`wdsp-agent/internal/mirrorsrc/`（unix socket/回环监听、实例令牌认证、x-wdsp-* 控制头剥离、有界正文、v2 单向源封装；16 单测）；`httpsensor/export.go`（脱敏同一出口复用）；`agent/mirror.go`（装配默认关闭、仅 v2 上行不降级、429/5xx 转缓存、invalid_records 索引隔离、'M' 标签缓冲补传）；`cmd/mirrorharness/`（E2E 取证工具）；`test/wdsp-agent-e2e/mirror/`（run.sh + nginx:1.28.0-alpine tag+digest 双锁 + S1–S10 场景）；`deployment/nginx-mirror/`（生产接入模板+README）；契约文档附录 A（NGINX_MIRROR 来源剖面，纯增量）。
真实 E2E（run `20260908T101135-51b803`，PASS=11/断言 37 全过）：伪造令牌 403×3、伪造 XFF 被覆盖、五元组不采信外部头、脱敏零泄漏（全局明文扫描）、8MB 截断 original_total_size=CL、chunked 未知大小如实 null、源站 500 不影响镜像且 response 恒 null、慢上传/取消/适配器被杀业务均 200、socket 0660、源站计数对账。
契约增量（主代理已确认）：`X-WDSP-Original-Body-Size` 可信控制头（Nginx mirror 清空子请求 CL，由 internal location 注入 `$http_content_length`，适配器剥离不入记录，伪造防护靠实例令牌覆盖注入）。模板警示：internal location 需显式 client_max_body_size（实测暴露）。
已知限制：五元组为镜像连接对端非真实客户端；DECRYPTED 为部署拓扑断言非密码学证明；macOS E2E 单容器 loopback 拓扑。

## S4 记录（2026-09-08，P1-03 G4a：管理端 v2 字段 + traffic-agents 页面扩展）

server 管理端（agents 包）：HTTP 事件列表/详情输出全部 000133 v2 列（来源三元组/协议/关联状态/body_quality/grpc/trailers/采集与入库时间）；`headerValuesFromJSON` 修复 v2 数组形态详情 headers 返回空对象的限制（v1 string map / v2 数组双形态，非法回落 `{}`）；Agent 详情暴露 `http_event_schemas` 能力集（空集兜底 {1}）；权限沿用 traffic.agents.view/manage 未新开入口。
web（traffic-agents）：HttpEventsPanel 重写（来源/协议/关联独立状态列，v1 行显示 `-` 不伪造；v2 详情分区含 event_id 幂等 Tag、gRPC 元数据分区（grpc_status null 显示未知不伪造 0）、trailers 表、body_quality、超 30s「疑似缓存补传」启发式 Tag、旧 Agent「需升级」Alert）；AgentDetailDrawer 配置版本三段分离 + 资产来源 Tab（HttpAssetSourcesPanel 四态过滤）；PolicyPanel 采集等级与适配器/来源绑定如实展示。
契约文档 §6 状态行更新（冻结语义未动）。
复验（编码代理实跑）：server agents 包 ok（新增 6 用例）；web typecheck/lint 通过、Vitest 108 文件/824 用例全绿（新增 8 用例含 XSS 纯文本断言与筛选分页上下文保留）。
已知限制：duplicate 为批次级语义不落逐事件标记；「疑似缓存补传」为前端启发式非 Agent 显式上报；策略的适配器/来源绑定字段服务端 schema 待 G2/G3 来源绑定管理落地。

## S4 记录（2026-09-08，P1-03 G4b：k8smeta 状态契约强化 + K8s 验证环境检查）

实现（wdsp-agent/，server 与 gateway 零改动）：
- `internal/k8smeta/k8smeta.go`：快照健康状态机 OK/STALE/UNAVAILABLE（刷新失败保留旧快照，Health 输出距上次成功时长 StaleFor；持续失败 ≥5min 或从未成功 → UNAVAILABLE）；条目 TTL（默认 10min 未被成功快照再确认即不参与解析，防 Pod 删除/IP 重用串联旧归属；快照差分天然失效——全量原子替换保留）；owner 权威/推断区分——Deployment 经 ReplicaSet→Deployment 列表权威解析（仅查本节点 Pod 所在 namespace），RS 缺失或查询失败降级截尾推断并显式标记 entry.inferred、经 Health.InferredOwners 计数；StatefulSet/DaemonSet/Job 直接 owner 与独立 Pod/独立 RS 为权威；hostNetwork Pod 跳过 IP 映射（podIP 即节点 IP）；endpoints 由全集群分页改为按本节点 Pod 所在 namespace 分别查询；实现只用 list 动词。
- 心跳接入：`internal/transport/transport.go` Metrics 新增 k8smeta_state/entries/inferred_owners/stale_seconds/sync_failures（server 端 metrics 为 jsonb 透传落库——RecordHeartbeat `$4::jsonb || rawKeepExpr`，新增键不破坏冻结契约；机器端点 DisallowUnknownFields 仅作用于包络，故未动事件线格式 k8s 字段）；`internal/agent/agent.go` metricsSnapshot 接线，k8s.enabled=on 但无凭据时显式 UNAVAILABLE；不改 status 的 ONLINE/DEGRADED/ERROR 判定（元数据失效不影响采集）。
- 部署：`deployment/kubernetes/wdsp-agent-rbac.yaml` 去除 watch、新增 apps/replicasets list（权威归属解析所需），注释说明收敛理由；`wdsp-agent-daemonset.yaml` 与 README 补 digest 锁定步骤；`test/wdsp-agent-e2e/fake_kube_server.py` 适配 namespace 限定 endpoints + replicasets 路径（该 harness 仅组件测试参考，不作正式证据）。

验证（实跑）：`cd wdsp-agent && go test ./... -count=1` 20 包全 ok；`go test -race ./internal/k8smeta/ ./internal/agent/ -count=1` ok；`go vet ./...` 干净。新增/更新测试 11 个：状态机（UNAVAILABLE→OK→STALE→UNAVAILABLE→OK）、条目 TTL 过期、差分失效（IP 重用/Pod 删除）、owner 权威/推断四分位、独立 RS 权威、RS 403 降级推断+计数、hostNetwork 跳过、endpoints 按 namespace 与跨 ns 隔离、Run 循环 403→STALE→恢复（10ms 刷新注入）、API 超时如实报错、心跳 metrics 接线×2。

AGT-021/AGT-022 → **BLOCKED_ENV**：本机 kubectl v1.32.2 存在但 `kubectl config get-contexts` 为空、KUBECONFIG 未设、~/.kube 不存在；Docker Desktop 运行中但 Kubernetes 未启用；kind/minikube/k3d/k3s/colima 均未安装（任务纪律禁止自行 brew install 大型依赖）；docker.io 不可达（TLS handshake timeout），即使装 kind 也无法拉取 kindest/node。缺口：真实集群的滚动更新/删除/IP 重用/跨 namespace/hostNetwork 映射证据与 RBAC 最小权限实证仍缺，需在具备真实集群的环境补做（组件级等价断言已由上述单测覆盖，但非正式证据）。

已知限制：①daemonset 镜像 `jiuzhang/wdsp-agent:2.3.0` 为自主构建且未发布到可访问仓库，无法取得真实 registry digest——按 Phase 5 契约不虚构，清单保留 tag 并以注释+README 强制发布时改 `<tag>@sha256:<digest>`；②owner 权威/推断区分无法进事件线格式（server 机器端点 DisallowUnknownFields + 不改 server 纪律），可见性走心跳 metrics 的 k8smeta_inferred_owners；③endpoints 失败仍整体置 STALE（保守，防止静默丢失 Service 关联），RS 失败仅降级推断。

## S4 记录（2026-09-08，P1-03 G3：Envoy tap 适配器 + 真实 Envoy 取证）

新增：`wdsp-agent/internal/tapsrc/`（tap.go 单会话管理流客户端——Envoy Admin 回环校验、`POST /tap` 提交会话级 tap 配置、1s→30s 有界退避重连并重提交；scan.go 括号深度+字符串/转义状态机 JSON 分帧器（跨块累积、单帧超限丢弃但状态机继续同步）；trace.go TraceWrapper→v2 规范化——伪头映射、authority 优先于冲突 host、重复头/Trailer 逐值脱敏保序、五元组 127.0.0.1:0 占位、时间戳=tap 消息接收时间（latency 恒 0）、capture_stream_id=nil、gRPC 经 content-type 前缀判定+grpc-status 取响应 trailers/trailers-only 响应头+取消/未完成 UNKNOWN 不伪造 0、WS 只握手视图帧不驻留、gRPC/WS 正文强制 content_type 跳过、x-wdsp-* 剥离；16+ 单测）；`httpsensor/export.go` 增量 MaskedResponseMessage/MaskedHeaderValues；`agent/tap.go` 装配（默认关闭）+ `agent/mirror.go` 泛化为通用 v2 发送路径（tap/mirror 共用，`dropped_by_reason` 按来源分账 `tap_v2_not_negotiated`/`mirror_v2_not_negotiated`）；`config.go` tap 段（单会话字段）；`cmd/tapharness/`（取证工具，计数快照跨守护重启累计）；`test/wdsp-agent-e2e/envoy-tap/`（run.sh 双相位 + envoy-h2.yaml/envoy-h1.yaml + 独立 Go module 取证 harness：web/grpc/ws/h2 客户端服务端，grpc 用 raw codec 免 protoc）；`deployment/envoy-tap/`（README + envoy.tap.yaml.example）；契约附录 B（ENVOY_TAP 来源剖面，纯增补）。

S0 锁定实测三大发现（docker 真实验证，先于实现）：①`streaming_admin + PROTO_BINARY_LENGTH_DELIMITED` 使 Envoy v1.35.3 **进程崩溃**（SIGTRAP，absl null check）→ 锁定 `JSON_BODY_AS_BYTES`，二进制路径禁用；②JSON 管理流为美化 JSON 消息换行相接的自相似流，须按括号深度分帧；③**Admin 同时只允许一条已挂接 tap 流**（第二条 `POST /tap` 400 "An attached /tap admin stream already exists."）→ 适配器被迫单会话设计（原 §3.3 多 channel 设想废弃），多 listener 共用同一 config_id，协议/TLS 断言按会话维度覆盖全部 tapped listener，混合场景必须 UNKNOWN/false。管理流可用 → 不写 tap 文件 → 无需「脱敏前不落盘」ADR。

契约 V1.1 修订（主代理批准的附带澄清）：§2.1 一致性约束允许 `truncated=true + original_total_size=null`（截断但原始总大小未知）；server `http_events_v2.go` 校验与测试、mirrorsrc normalize、附录 A 口径同步；文末修订记录表登记 V1.1 与附录 B 增补两行。

真实 E2E（run `20260908T131748-c5bdf8`，PASS=11/0 FAIL，记录断言 34 项全过，证据 `test/wdsp-agent-e2e/envoy-tap/runs/20260908T131748-c5bdf8/`）：相位 A（8443 TLS/h2 挂 tap）S1 六流多路复用按流配对不串流（X-Rid 回显）、observed=2/DECRYPTED、query token 脱敏、五元组占位、latency=0；S2 gRPC unary grpc_status=0/CLOSED、HTTP 200 与 RPC 状态分列、正文 content_type 跳过、trailers 可见；S3 非零状态 grpc_status=3（**实测发现：trailers-only 响应的 grpc-status/set-cookie 并入响应 headers 呈现**，已如实解析并断言）；S4 streaming CLOSED/0；S5/S6 取消/截止不伪造成功（实测形态：取消=COMPLETE+grpc_status null+UNKNOWN，截止=grpc_status 14 UNAVAILABLE+CLOSED，如实记录于 verify-report「实际到达形态」节）；S12 正文 8KB 超 4KB 缓冲截断 truncated=true+original_total_size=null（V1.1 口径实证）；S9 Envoy 进程重启后断连/重连计数生效、采集恢复；S10 适配器被杀业务 3/3 200（采集故障不影响转发）、守护拉起恢复。相位 B（换 envoy-h1.yaml，8080 明文挂 tap）S7 WS 握手 101/COMPLETE、帧不驻留、observed=1.1/PLAINTEXT；S8 握手失败 403 如实。全局四类合成敏感标记明文零泄漏。适配器计数：received=17/emitted=17/disconnects=4/reconnects=2/parse_errors=0/oversize_drops=0。环境：envoyproxy/envoy:v1.35.3 tag+digest 双锁（本机 arm64），容器零端口发布，run_id 双校验隔离清理。BLOCKED 项：无。

已知限制：①单管理流约束（上述 S0-③）；②tap 缓冲输出不含地址/时间戳/流 ID——五元组占位、时间戳=接收时间 latency=0、capture_stream_id=null（如实，不造假）；③WS 握手记录在连接关闭时才由 Envoy 冲刷（非实时）；④gRPC 取消/截止的 tap 到达形态以取证证据为准（取消无 grpc-status，截止为 Envoy 生成的 14）；⑤macOS 单容器回环拓扑，Admin 回环绑定致容器外不可达属正常行为；⑥契约 §2.1 修订仅放宽此前必被拒的组合，对存量合法记录无影响。

## S4 记录（2026-09-08，P1-03 G5：兼容升级回退 + 完整矩阵回归）

新增：`docs/agents/WDSP_AGENT_P1_SUPPORT_MATRIX.md`（任务书 §1 支持矩阵与 §8 AGT-001～028 逐格证据总表，PASS/BLOCKED_ENV/NOT_SUPPORTED/PARTIAL 词表）；agent 侧 G5 测试 `internal/agent/upgrade_rollback_g5_test.go`（v1→v2 升级带缓存补传、能力收回降 v1 且适配器记录不假报、适配器停止被动采集继续、旧程序不误解析 v2 缓存）；server 侧 `internal/agents/compat_g5_test.go`（旧 v1 Agent 上新 server 形状不变、缺省能力集 {1}、非法 400）、`http_admin_v2_test.go`（资产来源管理端四态）；`internal/k8smeta/k8smeta_state_test.go`、`agent/k8smeta_metrics_test.go`；`test/wdsp-ip/upgrade-executor-gates.sh`（升级执行器危险归档/错误架构拒绝）、`attacker-package-gate.sh`（AT-12 攻击者包不替换固定信任根）；ops/upgrade、ops/offline-package 安全解压加固。
迁移演练：000133 真实 PG（postgres:16.4-alpine digest 锁）up→插 v1 存量行→down（旧记录可读、v2 列移除）→up（行完整、默认 schema_version=1、幂等索引重建）实证；回退顺序（先停新来源并处理 v2 缓存再降级程序）在矩阵文档 §4 固化为操作纪律。
复验（主代理实跑）：`cd wdsp-agent && go test ./... -count=1` 22 包全 ok；`cd server && go test ./internal/agents -count=1` ok；mirror E2E 复跑 run `20260908T151957-2396b3` PASS=11/FAIL=0（status.json 已读）；envoy-tap E2E 复跑 run `20260908T152129-c4a655` PASS=11/FAIL=0（status.json 已读）。
BLOCKED 不变：AGT-021/022 真实 K8s 集群证据 BLOCKED_ENV（本机无集群，组件级断言已覆盖，不得伪造）；范围外能力 NOT_SUPPORTED 已在矩阵文档如实标注。
**S4（P1-03 全部 G 任务）至此完成，G5 关闭。**

## S3 记录（2026-09-08，P1-02 B3：请求链接入 + CHALLENGE final_decision 增量 + preflight 密钥检查）

实现（gateway）：`bot_step.go` 新增——`serveNextViaBot` 统一入口（命名空间 `/_wdsp/bot/v1/` 最前置本地处理→选择器→clearance 先行→合格性→多信号判定→OBSERVE 记录/PROTECT 挑战），module.go 四个放行出口（保护地址/白名单/L7 allow 经 executeL7/常规 CC 后）全部改经 serveNextViaBot；Guard 加 botSvc；bot_policy.go `assembleBotPolicy` 重写（OFF 保留段供墓碑）+`assembleBotService`（PROTECT 缺 valkey/keyring fail-closed 拒载，与发布门禁同口径；OBSERVE 降级 Warn）；`identitybehavior/peek.go` 只读快照 PeekSnapshot（Store 接口本体不加方法，可选接口；MemoryStore/ValkeyStore 单 Lua 只读往返，远端故障回退内存）；`identitybehavior/identity.go` 导出 ClassifyUA；disposition.go +DisActionChallenge/"BOT" executor（CC 后 API 前）；dynamic_security/context +ActionChallenge（仅枚举增量）；botchallenge CallContext 加 RecordTerminal/FinalDecision 回调，Offer/429/503 三结局挂 noteTerminal、emit 挂 FinalDecision（Settled 门禁）。
**真实 Valkey 才暴露的存量 bug 修复**：`botchallenge/store.go` Read 的 HGETALL 字段解析加 `luaFieldString` 两型兼容——counters.Eval 把数字型 bulk string 返回 int64，导致 v/ep/df/exp/att 断言空串、verify 恒 503；fakevalkey 单测从未暴露，真实 Valkey 对拍定位修复（hint 同修法）。
实现（server）：securityevents/store.go:61 与 apiruntime/events.go:96 两处 NOT IN 补 'CHALLENGE'；apisecurity/runtime.go postureProtectedActions 刻意不含 CHALLENGE（注释注明）；botpolicy/handler.go Preflight 新增 signing_key 检查（PROTECT 未就绪 FAIL+publishable=false、OBSERVE WARN、OFF SKIP）；app.go 接线 NewBotSigningKeysLoader；tests/stage_bot_policy_test.go 加 TestBotPolicyPreflightSigningKey 四态。
实现（web）：EventDetailDrawer CHALLENGE/BOT 映射 + types 联合类型 +2 值 + 未知值原样回退用例。
文档：AGENTS.md 请求顺序段与真实实现顺序段、docs/ARCHITECTURE.md 请求顺序图均加 Bot 步骤（主代理已核对与实现一致）。
验证（编码代理实跑 + 主代理复跑）：`gateway/modules/jiuzhang_guard go test -race ./... -count=1` 17 包全 ok（主代理复跑 `go test ./... -count=1` 全绿）；真实 Caddy 集成测试（caddy v2.11.4 + coraza-caddy v2.5.0 对齐 Dockerfile 锁定 + 真实 CRS + docker Valkey 锁定镜像）：中间件顺序、BOT-014（clearance 后 SQLi 仍被 CRS 阻断）、BOT-015（热更新白名单仍挑战）、BOT-016（verify 405/未知子路径 404 本地处理）、策略代次撤销旧通行——PASS；server 五包（botpolicy/guardconfig/securityevents/apiruntime/accesscontrolevents）ok（主代理复跑绿）；stage 测试一次性 PG/Valkey 容器 8/8 PASS；web typecheck + vitest 绿。
已知限制：method_ratio 无每方法计数源恒 UNAVAILABLE；identity_behavior 未启用时行为组不可用→PROTECT 不挑战（preflight/文档注明配套要求）；规则窗口映射档 ≤90s→1m/≤450s→5m/≤1800s→30m/否则 24h；counters.Eval 数字串→int64 共享语义未改，其他 Lua HGETALL 数字字段消费者存在同类潜在风险，待后续排查。

## S3 记录（2026-09-08，P1-02 B4：管理页面 + 挑战页核对 + 浏览器/自动化基准 27/27 PASS）

web 管理页（agent-108 交付，主代理复跑 typecheck/lint/vitest 全绿）：`web/src/api/botPolicy.ts`（GET/PUT/preflight 客户端+B0 冻结限制常量+null 归一化）、`web/src/utils/botPolicy.ts`（中文映射/7 信号指标规格/后端字段错误→表单路径）、`pages/applications/detail/BotPolicyTab.tsx`（管理页主体：未配置/草稿待发布/已发布含批次号/部分节点未生效逐节点 SUCCESS/FAILED/HASH_MISMATCH/依赖故障预检逐项 FAIL-WARN-SKIP+publishable 门禁理由+冲突列表；恢复入口：重新预检/前往发布/409 刷新重载/字段级错误回显；expected_version 乐观锁；reason 必填审计；key_ref 仅引用名；PROTECT 发布门禁警告；「草稿≠生效」明示）、`BotChallengePreview.tsx`（挑战页四态静态预览，只读用户可见）、ApplicationDetailPage 挂 Tab（bot_policy.read 门控，仿 jwt_trust 先例）、ApplicationsPage 筛选/分页迁 URL 查询串（BOT-023 返回列表保留上下文）。测试：BotPolicyTab 11 用例+ApplicationsPage 2 用例（含 XSS 纯文本、未知值 FUTURE_MODE/STATE 原样回退、上下文保留、只读隐藏编辑、403）；全量 vitest **109 文件/839 用例全绿**（主代理复跑确认）。
BOT-006 静态核对（挑战页 render.go）：noscript 可读、12 错误码中文映射+兜底、重试自动 focus、role=status+aria-live、2048 迭代分片让出主线程、≤2s 预算转手动、sessionStorage 一次性标记最多自动刷新一次、429/503 全转义、CSP nonce+no-store+frame-ancestors 'none'、无 eval。Cookie 不可用无独立文案（SESSION_INVALID 重载兜底，如实记录）；慢设备/读屏实测 NOT_RUN（无环境）。
**基准过程中主代理修复的栈级/存量缺陷（均有证据链）**：①server/internal/certificates/store.go GetApplicationCertificate 的 certColumns 未限定别名与 application_certificates JOIN 歧义（id/created_by/created_at/updated_at 四同名列，SQLSTATE 42702）——任何「HTTPS 域名+绑定证书」应用发布必失败的存量 bug，加 certColumnsC 修复；②docker stage5 栈从未接通证书下发通道（裸机设计为宿主机共享目录，docker 栈未接线）——deployment/docker-compose.stage5.yml 新增 stage5-gateway-certs 命名卷（api 挂 /app/runtime/certificates、网关挂 /etc/caddy/certs:ro），server/Dockerfile 与 gateway/Dockerfile 预建对应目录使卷初始化继承 uid 1000 权属（两镜像运行用户同 1000:1000，0600 数值权属一致可读）；③test/waf/scripts/stage5-setup.sh s5_publish 加 LOCK_BUSY 退避重试（策略保存触发自动发布与显式发布竞争）；④run.sh 多处 bash 3.2 `$VAR` 后紧跟全角字符 unbound variable 修复。
浏览器/自动化基准（test/e2e/bot-challenge/，stage5 真实栈+真实 Chromium）：最终轮 run `20260908T184056-940230` **27/27 PASS、verdict=PASS**（主代理读 status.json 确认）。三组分别如实报告：http-script 组（BOT-005 HEAD/POST/JSON 不返回 HTML 挑战直达源站、合格导航第三次被挑战 403+CSP nonce+no-store、伪造 verify 403 不签发、verify GET 405、未知子路径 404 本地）；browser 组（BOT-004：nav_attempts_before_challenge=3、PoW 求解 5ms、verify 204、clearance 落 Cookie、终态 200 到源站）；automation-js 组（如实记录 webdriver=true，与 browser 组同身份累积达阈 nav=1）。**关键口径修正（夹具非产品 bug）**：identitybehavior 在请求收束时记账、PeekSnapshot 只读不含本次请求，uri_concentration≥0.5 数学上第 3 次导航才首次达阈——夹具改为 nav-1/2 断言放行（基线门控）+nav-3 断言挑战，实跑精确命中；B3 集成测试「循环打到挑战」同理。Playwright 解析修为目录级 node_modules 相对软链（运行时生成物，.gitignore 已排除）；spec 反竞态重写（挑战以 403+响应体标记为权威、verify 204 用导航前注册的 response 捕获、clearance Cookie 轮询、webdriver 首航前采集），未降低断言强度。
NOT_RUN/BLOCKED：BOT-004 的 Firefox/Safari/移动维度（基准仅 Chromium 通道）；慢设备/读屏实测。

## S3 记录（2026-09-08，P1-02 B5：升级/关闭/回退演练 + 验收矩阵 + 交付归档）

BOT-024 演练（`test/e2e/bot-challenge/rollback-drill.sh`，真实 stage5 栈一次跑通）：run `20260908T185148-7b707a` **23/23 PASS、verdict=PASS**（主代理读 status.json 确认）。相位 A 升级留证（compose build/up、images.txt）；相位 B PROTECT v1 基线（200/200/403→现场解 PoW→verify 204→clearance 200）；相位 C OFF+RESERVED_TOMBSTONE（4 次导航全 200 挑战停止、verify POST 404/未知路径 404、SQLi 仍 403 非挑战页、历史 BOT_CHALLENGE_OFFERED 事件 API 可读）；相位 D 回退 v3（挑战恢复、旧 epoch=1 双 Cookie 403 不复活、新挑战完整通行）；各相位 publish 留证齐全；演练后栈 down -v 无遗留（主代理 docker ps 确认）。
验收矩阵：`docs/WDSP_BOT_CHALLENGE_ACCEPTANCE_MATRIX.md`——BOT-001~024 逐项映射证据（测试函数名 grep 核实），**PASS 20 / PARTIAL 4 / FAIL 0**。PARTIAL 缺口如实：BOT-004 Firefox/Safari/移动浏览器 NOT_RUN（仅 Chromium）；BOT-006 慢设备/读屏/键盘实测 NOT_RUN；BOT-013 移动网络实测 BLOCKED_ENV；BOT-018 洪峰压测 NOT_RUN。
文档：新增 `docs/BOT_CHALLENGE_OPERATIONS.md`（默认 OFF/三模式语义/8 条已知限制/命名空间表/策略 JSON 示例/密钥登记步骤/部署配套 Valkey+identity_behavior/事件排障）；AGENTS.md 文档索引加两行（与他人 BOLA 两行共存）；test/e2e/bot-challenge/README.md 更新实测状态与 BOT-024 小节。
**P1-02（B0-B5）至此全部完成。**

## S5 记录（2026-09-08，P1-04 R2：全量语料真实回放 + 前后对比 + 性能关联）

语料扩展（§4.2 纪律）：18→24 例（新增 Bot 挑战类：PROTECT 合格导航挑战/clearance 通行/INELIGIBLE 放行/verify 墓碑等 6 例；老例修正预期升 case_version v2；manifest 重算 sha256 `feaadc81…`；TRAIN 仅正常样本纪律保持；无占位假样本）。单测 174→201（主代理复跑 `python3 -m unittest discover -s test/regression/p1/tests` Ran 201 OK）。
执行层接真实环境：新增 `reconcile.py`/`executor.py`/`stage5/` 适配器（stack-up/down + run-plan.stage5.example.json），对 stage5 真实栈（含证书通道修复后的 HTTPS 发布链）逐例回放并事件对账（access_control_events/security_events/final_decision）。
逐例结果与对比：基线构建 48/48 全绿；候选构建（真实规则变更：禁用一条 phase-2 自定义规则 7100001）47/48——compare 报告（`docs/evidence/regressions/compare-20260908T222932-46b792/`）精准捕获唯一预期内变化：丢失检测 1 条（WAF-ATK-WEBSHELL-001 OBSERVE，custom_pack/webshell_uploads 检出归属丢失）、新增误报 0、动作/源站变化 0、6 例 TRUTH_UNKNOWN_EXCLUDED，总判定如实 FAIL（rc=1）；演练后规则已恢复 ENABLED（version 3→4）+重发布+探针实证命中恢复，栈已 down -v 无残留。
性能关联：基线/候选各 74 请求 perf.jsonl（p50 11.31/11.25ms、p95 16.46/18.12ms、p99 25.63/30.19ms；状态码分布与 origin_reached=52 两轮完全一致；结论：影响在噪声范围内，不作统计显著性主张）。
篡改验证（§141）：文件删除被捕获；**内容篡改本地工具层静默接受——如实披露**（内容完整性属签名服务范围，R3 已交付 Ed25519 核验）。
产品发现 7 条（全部真实栈实证、未改产品代码，终验报告 §产品发现）：escapeSecLangArg 转义 bug、CRS 949110 相位抢占、Coraza 无 XML 体处理器、apigeo nil panic、事件关联键口径、族映射、OBSERVE offer 语义——**待后续排期修复**。
终验报告：`docs/evidence/regressions/P1-04-R2-FINAL-REPORT.md`（run_id 清单/环境/判定口径/语料变化/逐例计数/性能表/篡改验证/限制与未覆盖项）。限制：JWT/Agent/APM 类语料仍缺口（如实标注）。

## S5 记录（2026-09-08，P1-04 R3 前半：CI 分层 + 可信证据登记 + 发布门禁）

实现（server，新包 `internal/regression/` 约 2400 行）：types.go 限额冻结（请求 1MiB、manifest 4MiB、分块 4MiB×64、REPORT 16MiB、PERF 256MiB、LOG 64MiB、单 run 512MiB、证据有效期默认 7 天可调 1~30）；canonical.go 确定字节编码（流式拒绝重复 JSON 键+再编码逐字节比对，嵌套深度 200）；signature.go Ed25519 验签+受信公钥登记（system_settings，拒绝未知算法/未知或已撤销 key_id，登记损坏=依赖不可用）；manifest.go schema v1+计数对账；storage.go 受控本地存储适配器（P0-01 服务端存储确认不存在由本任务提供：服务端生成对象 ID、流式 sha256、类别限额、0444 原子登记、0700 根目录、路径越界防御）；store.go pgx 仓储（单事务导入不残留半份、幂等/409、策略乐观锁）；gate.go 门禁评估（OFF 不检查/OBSERVE 只记录/ENFORCE 缺失过期撤销级别不足强制项不完整验证失败证据被清理均 BLOCK、依赖不可用 ErrGateUnavailable 明确失败、恢复通道仅豁免超有效期）；import.go+handler.go 六 API+受控对象上传端点。
迁移：000134（6 表 objects/runs/cases/run_objects/policy/gate_decisions，policy 单行默认 OFF）、000135（权限种子 security_regression.read/.import/.policy）——编号用前重核无抢号；真实 PG 演练 up→down→重 up DRILL_OK。
发布门禁挂接：gatewayconfig/publisher_gate.go（跨包接口+失败码映射），publisher.go 仅 2 处小增量（regressionGate 字段+executePublish 在 saveVersion 后、loadGatewayConfig 前插检查点，失败码 REGRESSION_GATE_REJECTED/UNAVAILABLE，版本标 FAILED）；无 skip_gate 参数（请求带该字段 400）；模型激活/回退经 PublishSync 同一入口单点强制；恢复通道（GuardOverride 历史快照重放）按 §7.3 豁免有效期不豁免撤销/缺失/不完整。
API：GET regressions（过滤分页）/GET {id}（摘要+门禁理由）/GET {id}/cases（分页无原始正文）/POST imports（仅受控对象 ID，201/幂等 200/异内容 409/核验失败 400 不落库）/GET·PUT regression-policy（expected_version 409）/POST regression-objects（受控写入登记通道，godoc 声明补充理由）。OpenAPI 片段 18-security-regression.yaml 已加，merge 重生成留编排方。
工具：tools/regsign/（独立 go.mod 仅标准库）genkey/canonicalize/sign/verify 四子命令，私钥 0600 校验不入库不入仓；端到端 genkey→canonicalize→sign→verify OK，重复键 sign 拒绝。
CI 分层：.github/workflows/ci.yml 头部加分层纪律注释+两个新 job（corpus-schema-check：语料校验+语料工具单测+regsign 构建+regression 包单测；nested-go-modules：9 个 go.mod 矩阵），无 paths 过滤、核心安全集不可跳过；regression-nightly.yml 定期完整回归（cron `17 2 * * *`+dispatch；11 模块全量矩阵+语料/证据链+run.sh regression 强制项 BLOCKED 恒红；注释声明信任边界：无 pull_request_target、无私钥、固定提交）。
验证（编码代理实跑 + 主代理复跑）：`go test ./internal/regression/ ./internal/gatewayconfig/ -count=1` ok（约 60 测试：伪造签名/未知算法/未知与撤销 key_id/重复键/非规范形/过期/恢复通道/并发 409/幂等重导入/哈希篡改/计数不一致/门禁三模式矩阵/依赖不可用；主代理复跑绿）；stage 集成一次性 PG/Valkey 容器 5/5 PASS（Migrations/Permissions/PolicyValidationAndConflict/ImportFlow/UploadLimits）；server build+vet 干净、9 嵌套 module build/vet 过；`run.sh regression` 本机 exit=3 如实 BLOCKED_ENV（证据 docs/evidence/regressions/20260908T174347-f23b04/），与 nightly「缺环境不变绿」一致。
BLOCKED/留待：真实隔离环境全量回放属 R2；ENFORCE 拒绝真实发布的端到端验证属 R2/R4；OpenAPI merge 重生成留编排方；公钥登记无新 UI（web 不在本任务范围）。

## S5 记录（2026-09-09，P1-04 R4b：真实升级/误报/故障回退演练）

全部相位真实 stage5 栈实证通过、无 BLOCKED，栈已拆除。证据：`docs/evidence/regressions/r4b-20260909T0015/`（55 文件+索引）与终验报告 `docs/evidence/regressions/P1-04-R4B-DRILL-REPORT.md`；可复跑脚本 `test/regression/p1/stage5/r4b-drill.sh`（bash -n 过）+ `test/regression/p1/tools/pack_evidence.py` 证据打包器。
相位①ENFORCE 端到端：证据匹配发布 SUCCESS；缺失×2/过期×1 全部 REGRESSION_GATE_REJECTED（版本 FAILED、is_current 不变，无半发布）；证据存储 chmod 000 → REGRESSION_GATE_UNAVAILABLE 明确失败不静默放行；31 行 gate_decisions 指纹逐行等于实发版本 configuration_hash（排队后快照绑定实证）。
相位②误报回退（§7.3）：误伤 L7 规则上线（/search 403）→ 8 FAIL 证据签名导入 → ENFORCE 拒发（声明 FAIL+mandatory_failed=6）→ GuardOverride 快照重放恢复（/search 200）→ 复跑 48/48 → 失败候选未自动重发；豁免矩阵 4/4（仅超有效期 ALLOW，撤销/缺失/不完整均 BLOCK）。
相位③故障回退：网关停止期发布在门禁 ALLOW 后仍 PUBLISH_FAILED（GATEWAY_DOWN/CRITICAL 告警，恢复重发 SUCCESS——「门禁 ALLOW ≠ 发布成功」实证）；次要节点不可达→主 SUCCESS+节点 FAILED+CONFIG_PUBLISH_FAILED/HIGH 告警。
相位④模型门禁：模型 A/B 激活→候选指纹变→无证据 REJECTED 且策略滞留 VALIDATED 不报 ACTIVE、网关指纹不变；绑定证据后 SUCCESS→ACTIVE（A 自动 ROLLED_BACK）；撤销密钥后 rollback → 502 不伪装成功。
产品发现 6 条（真实栈实证，未改产品代码，转修复排期）：学习态指纹漂移×3（证据绑定须待学习态稳定，判据=连发两次拒绝指纹一致）；WAF-BEN-EDGE-001/CUSTOM_PACK 1001012 非确定命中 flake（10 轮 2 轮，transaction.args 为空）；GuardOverride 恢复不清 DB 规则本体；config-versions 回滚不经回归门禁（与 access-control 回滚口径不一致）；**回滚草稿孤儿化**（门禁拒绝路径不回写 runtime 策略，rollback 502 文案与实际 DRAFT 滞留不符，下一次无关发布会静默带生效——优先级最高）；EDGE 事件 client_ip 恒为网关出口；公钥登记无 settings API（直写 DB）。

## S5 记录（2026-09-09，P1-04 R4a：安全回归管理界面 + 页面 E2E 11/11 PASS）

web（agent-108 交付，主代理复跑 vitest/typecheck/lint 绿）：`api/securityRegression.ts`+`utils/securityRegression.ts`（枚举 meta/null 归一化/指纹提取/差异分类/门禁理由建议）；`pages/security-regressions/` 三页（列表：筛选分页挂 URL、计划/实际/缺失、新鲜度超期标红、可用性预判带原因 Tooltip 且注明非终判；详情：run 摘要+核验理由+gate_assessment 逐项理由与恢复动作；用例差异：status 服务端过滤+family/diff 当前页客户端筛选如实标注+diff_summary 纯文本受限展开无 dangerouslySetInnerHTML）；regression-policy 卡（三态 Alert+.policy 权限门控+reason 必填审计+expected_version 409 处理）；配置发布页挂 RegressionGateNotice/RegressionGateFailureDetail（REJECTED/UNAVAILABLE 显示确切缺失项+`cfgfpv1:<hex>` 指纹深链，无 read 权限不渲染）。路由 3 条（security_regression.read）+菜单项。Vitest **112 文件/858 用例全绿**（含 XSS 纯文本、未知枚举回退、上下文保留、权限门控、409）。
E2E（test/e2e/security-regression/，stage5 真实栈+vite dev+Playwright）：最终轮 run `20260909T003233-d76e86` **11/11 PASS、verdict=PASS**（主代理读 status.json 确认）——真实 regsign 签名两份证据经 regression-objects+imports API 登记（服务端真实验签 PASSED），链路一「列表→详情→用例差异→发布门禁状态」、链路二「ENFORCE→真实发布被 REGRESSION_GATE_REJECTED→缺失项+指纹深链→空态」。
调试中发现的两个真实问题（已修）：①web bug：`gate_assessment.reasons` Go nil slice 序列化 null 致详情页白屏——api client 归一化 null→[]+2 例守护测试；②E2E 夹具：StrictMode 双挂致登录 captcha 双发取错 id（dev-only，spec 改为跟踪最新 captcha 响应静默窗收敛）、vite dev 默认绑 ::1 需 --host 127.0.0.1、内联 python 引号笔误、bash 3.2 全角界定（后两处主代理修）。
**P1-04 R0-R4 至此全部完成。**

## S6 记录（2026-09-09，汇总交付证据与客户说明）

交付：`docs/tasks/wdsp-p1/DELIVERY_SUMMARY.md`——四项任务强制验收总表（APMD-001~018：17 PASS+APMD-017 BLOCKED 人员；BOT-001~024：PASS 20/PARTIAL 4/FAIL 0；AGT-001~028：26 PASS+AGT-021/022 BLOCKED_ENV；REG-001~026：工具层/后端/门禁/回退全实证）、关键 run_id 索引、已知限制与未覆盖项如实披露、过程修复的 5 个真实缺陷、13 条产品发现转修复排期（R2 七条+R4b 六条，最高优先级=回滚草稿孤儿化）、客户部署与升级说明（全部新能力默认关闭、启用配套、升级回退路径与运维文档索引）。
最终全量验证扫尾（主代理实跑，exit 0）：`gateway` 根模块 build+test 全绿（仅 tproxyd 良性日志）、`gateway/modules/jiuzhang_guard` 全包绿、`server` build+vet+`./internal/...` 全包绿、`wdsp-agent` 22 包绿、`python3 -m unittest discover -s test/regression/p1/tests` Ran 201 OK、web typecheck+lint+vitest **113 文件/858 用例全绿**。
WORKLOG 阶段状态表已同步：S0-S6 全部 PASS（如实保留 APMD-017 BLOCKED、AGT-021/022 BLOCKED_ENV、BOT 四项 PARTIAL 披露）。
**P1 全部六个阶段至此完成。**

## 每阶段更新模板

```text
阶段 / 任务书：
执行时间、操作者、构建与工作区基线：
本阶段真实差距及依赖：
实现文件与迁移/API/schema 变化：
测试 ID、实际命令、执行数量和 PASS/FAIL/SKIP/BLOCKED：
环境、有效配置、节点 ACK、原始证据路径与哈希：
协议/权限/性能/兼容限制：
升级与回退实测：
剩余工作及下一步：
```

上下文压缩或更换模型前先更新本文件。只将已经执行且有证据的工作标为完成；未跑的测试保留 NOT_RUN。
