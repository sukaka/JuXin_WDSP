# WDSP P0 实施接续记录

更新日期：2026-09-08。

## 当前任务

用户要求（2026-09-06 起）：按照本目录 README 与四份任务书进行开发，按 S0→S6 顺序实施，一次一个阶段。此前一轮仅交付任务书文档（历史记录保留在下文）。

来源：[竞品差距分析](../../evidence/wdsp-competitor-gap-analysis-2026-09-06.md)。入口：[开发总纲](README.md)。

## 编写基线与重要发现

- 检查时 HEAD：`3c73774`；工作区有大量已修改和未跟踪文件。本文档依据当前工作区，不代表该提交的干净源码状态。
- 已有交付检查、身份观测、API 决策、WAF 例外、性能脚本与 APM 页面；任务书要求复用并补齐。
- 业务 JWT 目前有结构识别和未验证声明关联，不能当作业务 Token 已验签。管理登录认证不属于本项替换范围。
- 例外编译存在需复现的条件未组合、动作范围过宽、发布时间过滤到期、首 1000 条及事件草稿关联不完整的线索，详见 P0-04。
- 历史性能报告不是本轮最终验收证据；旧脚本涉及共享环境，新的基准必须隔离。
- 开发总纲与任务书中的新路径、字段、接口和门槛是待实现契约，不能当作现有能力。

## 阶段状态

| 阶段 | 状态 | 证据/说明 |
|---|---|---|
| 开发文档 | 已完成 | 本目录 6 份 Markdown；文档校验记录见下节，不代表功能完成 |
| S0 代码实施前复核 | PASS | 2026-09-06 完成现状核实，结论与差距见下节「S0 记录」；代码行为未改动 |
| S1 能力证据基础 | PASS | 工具+清单+38 单测全绿，详见「S1 记录」；能力验证状态全部 NOT_RUN，不代表功能已验收 |
| S2 基准工具与前测 | PARTIAL | 工具层 PASS（79 单测+真实 preflight），正式测量 BLOCKED_ENV（无专用隔离硬件）；详见「S2 记录」 |
| S3 JWT | PASS | 2026-09-07 完成：JWT-01～17 PASS、JWT-18 BLOCKED（ENVIRONMENT_UNAVAILABLE）；证据 `docs/evidence/releases/dev-s3-jwt-20260907/`；详见「S3 记录」 |
| S4 最终处置和例外 | PASS | 2026-09-08 收尾：EXC-01～15、DEC-01～06 全 PASS（第八轮真实网关冒烟 34/34；DEC-01/02/05 经素材 is_api 修复与 E3 期望契约修正后通过）；证据 `docs/evidence/releases/dev-s4-dec-exc-20260907/`；详见「S4 记录」 |
| S5 最终基准与长稳恢复 | PARTIAL | 2026-09-08 收尾：BENCH-01/02/05/06/07 PASS（工具层 123 单测 + 真实预检）；BENCH-03/04/08/09/10 BLOCKED、BENCH-11/12 BLOCKED（均 ENVIRONMENT_UNAVAILABLE，需专用隔离硬件）；证据 `docs/evidence/releases/dev-s5-bench-20260908/`；详见「S5 记录」 |
| S6 发布证据冻结 | PARTIAL | 2026-09-08 收尾：63 条强制验收项全部可定位（PASS 49 / BLOCKED 13 / NOT_APPLICABLE 1）；EVD-01～09 PASS、EVD-10 NOT_APPLICABLE、EVD-11/12 BLOCKED（无干净构建输入与锁定镜像）；`--release` 门槛实测拒绝（rc=1）；证据 `docs/evidence/releases/dev-s6-freeze-20260908/`；详见「S6 记录」 |

## 本轮文档校验记录

- 交付文件：开发总纲、4 份 P0 任务书、此接续记录；未修改业务代码，未执行应用测试、基准或发布。
- Python 文档检查：6 份 Markdown 的代码围栏闭合、无行尾空格；19 个本地文档链接有效；1 个 JSON 示例语法有效。JSON 示例为草稿，语法有效不代表满足发布证据要求。
- 验收编号检查：共 63 条且无重复，分别为 EVD 12 条、BENCH 12 条、JWT 18 条、DEC 6 条、EXC 15 条。
- 代码路径检查：39 个现有路径存在；`server/internal/jwttrust/` 和 `gateway/dynamic_security/jwtverify/` 为已明确标注的拟新增目录。
- Markdown 表格检查：252 行的列数一致。
- 跨任务检查：构建与有效配置标识、可信身份、最终处置、例外版本和验收状态保持一致；环境阻塞映射为 `BLOCKED` 状态及原因，不记作通过。
- 上述结果仅证明文档结构和引用经过检查；S0—S6 的实施与功能验收均仍为 `NOT_RUN`。

## S0 记录（2026-09-06，实施模型复核）

阶段/任务书版本：S0，任务书版本 2026-09-06。

时间、分支、commit、工作树摘要：2026-09-06；分支 `develop`；HEAD `3c73774`；工作树约 1500 个已修改/未跟踪文件（非本任务引入，含部署、文档、测试资产等）。本阶段未修改任何代码，故基线与任务书编写时一致。Go 1.25.6、Python 3.12.0。

本阶段目标与改动文件：核实四份任务书声称的现有实现与代码线索；冻结共享契约口径；更新本 WORKLOG（仅此一个文件被修改）。

### 已确认存在的实现（复用点）

- **P0-01**：交付检查模块完整存在（`server/internal/delivery/`，22 项检查、PASS/WARNING/FAIL/NOT_APPLICABLE 枚举、PG 双表持久化、run/get/export 三接口、`delivery_checks.run` 权限与审计齐全）；页面 `web/src/pages/delivery-check/DeliveryCheckPage.tsx` 完整；`docs/DELIVERY_ACCEPTANCE_GUIDE.md` 存在。APM 服务在 `server/internal/app/app.go` 真实接线（PG+ClickHouse 双源查询、恒注册路由+热生效总开关）。
- **P0-03**：`checkJWTStructure` 确认为仅结构识别、不验签、恒 OBSERVE（`gateway/dynamic_security/detectors/authentication.go:142-238`）；identitybehavior 的 JWTSubject 取自未验签 claims 仅作关联；`identity_key` 为 HMAC-SHA256 截断指纹。go-jose/v4 v4.1.4 已是 gateway 间接依赖（Apache-2.0），server 侧无 JOSE 依赖。迁移下一可用编号 000125。权限命名风格 `<module>.<action>`。
- **P0-04**：例外 CRUD/enable/disable/create-exception 路由与 `exceptions.read/manage` 权限齐全；SecLang 编译进 before-CRS 段；API 决策引擎纯函数、`Input.Exceptions` 确认为预留未生效；事件侧 API 有 `final_action`、WAF 安全事件无 final_decision 字段。
- **P0-02**：现有性能脚本 11 个全部基于 ab/curl；测试源站 `deployment/stage1/testorigin/main.go` 可复用。

### 已确认的真实差距

- **P0-01**：`docs/capabilities/`、`tools/capability_evidence.py`、`docs/evidence/releases/` 均不存在；仓库无任何 Python 测试体系（需在 S1 决定：unittest 标准库方案，避免引入新依赖链）。
- **P0-02**：`test/performance/p0/`、`deployment/docker-compose.p0-benchmark.yml`、`docs/evidence/benchmarks/` 均不存在；现有脚本寄生共享 stage5 栈（固定容器名 `jiuzhang-stage5-*`、直查共享 postgres、重建共享 api 容器、PUT 改共享策略），不可作为隔离基准入口，仅可复用 harness 惯例。
- **P0-03**：无任何验签/信任链代码；3 个管理 API、策略存储迁移、JWKS 获取缓存、guard 挂接、前端页面全部待建。
- **P0-04**：任务书 §2.2 线索**全部属实**，其中两条比任务书描述更严重：
  - provider 实际只发布前 **20** 条 ENABLED 例外（`List` 的 pageSize 上限 100 且超限时回落 20，`exceptions.go:328-330` 截断 provider.go:13 的 1000），且规则 ID 按 `created_at DESC` 次序从 8000001 递增分配，随新建/删除漂移；
  - `ADJUST_SCORE` 与 `LOG_ONLY` 完全等价（均生成 `ctl:ruleEngine=DetectionOnly`，未调分）；
  - 从事件创建的草稿 ApplicationID=nil、RuleIDs=nil，属 fail-closed 无效草稿（不下发、无 ctl 动作）；
  - 生效/到期仅在发布时过滤，网关侧无运行时时间判断；GenerateSecLang 对 URIExact/URIPrefix/URIRegex/Domain 只择一，Methods/SourceIPs/ContentTypes/有效期等不参与编译。

### 验收 ID 基线

共 63 条：EVD-01～12、BENCH-01～12、JWT-01～18、DEC-01～06、EXC-01～15。当前全部 NOT_RUN。

### 计划改动文件（按阶段，允许随实施微调并在后续记录中说明）

- S1：`docs/capabilities/capabilities.json`、`capabilities.schema.json`、`tools/capability_evidence.py`、`tools/tests/test_capability_evidence.py`、`docs/DELIVERY_ACCEPTANCE_GUIDE.md`（补区别说明）、生成的 `docs/capabilities/CAPABILITIES.md`。
- S2：`test/performance/p0/`（run.sh/collect.py/report.py/run-plan.example.json/corpus/tests）、`deployment/docker-compose.p0-benchmark.yml`、`docs/evidence/benchmarks/<run-id>/`。
- S3：`server/internal/jwttrust/`、`gateway/dynamic_security/jwtverify/`、迁移 000125+、`server/openapi/fragments/16-jwt-trust.yaml`、guard 挂接、web JWT 策略页。
- S4：`server/internal/exceptions/*`（编译/provider/fromevent/handler）、`gateway/dynamic_security/decision`、`gateway/modules/jiuzhang_guard` 处置上下文、事件入库与页面。

与任务书的差异及理由：无。

数据库迁移/配置兼容/回退方式：本阶段无。

实际执行命令与环境标识：只读核实（git status/log、go/python 版本、代码检索），未运行应用测试。

未完成事项、依赖和限制：工作树大量他人未提交改动，后续阶段只 `git add` 本任务文件，不得统一 add；S2/S5 依赖隔离测试环境（当前机器仅有共享 stage5 栈，若专用环境不可用须标 BLOCKED）。

下一步：S1 — 实现 P0-01 能力证据工具、schema 与初始清单（全部 verification_status 从 NOT_RUN 起算）。

## S1 记录（2026-09-06，P0-01 能力证据基础）

阶段/任务书版本：S1，P0-01 任务书 2026-09-06。

时间、分支、commit、工作树摘要：2026-09-06；`develop` @ `3c73774`；工作树沿用 S0 基线，本阶段新增 7 个路径（未 git add/commit）。

本阶段目标与改动文件：
- 新建 `docs/capabilities/capabilities.schema.json`（draft-07 schema）、`docs/capabilities/capabilities.json`（15 项能力初始清单，全部 evidence_refs 空、verification_status NOT_RUN）、`docs/capabilities/CAPABILITIES.md`（render 生成）。
- 新建 `tools/capability_evidence.py`（纯标准库 CLI：check/render/--release；退出码 0 结构有效 / 1 发布门槛未满足 / 2 结构完整性错误）、`tools/tests/test_capability_evidence.py`（38 个 unittest）。
- 新建 `docs/evidence/releases/draft-local/manifest.json`（任务书草稿最小示例，作工具自检夹具）与 `docs/evidence/releases/README.md`（离线证据目录说明）。
- 增补 `docs/DELIVERY_ACCEPTANCE_GUIDE.md` 第 8 节（运行环境检查 vs 版本能力证据的区别）。

与任务书的差异及理由：无；Python 测试采用 unittest 标准库（仓库无 pytest 先例，不引入新依赖链）。

实际执行命令与结果：
- `python3 -m unittest discover -s tools/tests -p 'test_capability_evidence.py'` → 38 tests OK。
- `check` 对草稿 manifest → 退出 0，15 项能力全部 NOT_RUN，输出"结构有效，未完成验收"。
- `check --release` 对草稿 manifest → 退出 1，列出构建门槛缺失与 NOT_RUN 明细。
- 伪造 `release_status=RELEASE_VERIFIED` → 退出 2，状态伪造检测生效。
- `render` 两次输出 `cmp` 逐字节一致。

验收 ID → 状态：EVD-01～09 由 38 个单测对应覆盖 → PASS（工具层）；EVD-10 本阶段无 HTTP/UI 变更 → NOT_APPLICABLE（无接口/页面改动）；EVD-11/EVD-12 → NOT_RUN（须 S6 真实环境证据）。

未完成事项、依赖和限制：清单 verification_status 被强制与计算值一致（状态伪造检测），S2–S5 产出真实证据后须同步更新；快照重算辅助函数未暴露为 CLI 子命令（留给 S6 取证流程）；EVD-11/12 待真实环境。

下一步：S2 — P0-02 隔离基准工具与语料；若专用环境不可用，工具完成后标 BLOCKED，不宣称 S2 测量通过。

## S2 记录（2026-09-06，P0-02 基准工具与语料；测量 BLOCKED_ENV）

阶段/任务书版本：S2，P0-02 任务书 2026-09-06。

时间、分支、commit、工作树摘要：2026-09-06；`develop` @ `3c73774`；沿用 S0 基线，本阶段仅新增文件（未 git add/commit）。

本阶段目标与改动文件（全部新增）：
- `deployment/docker-compose.p0-benchmark.yml`（无固定容器名，project/端口/标签全部按 run_id 隔离，镜像沿用仓库锁定 tag+digest）。
- `test/performance/p0/`：`run.sh`（preflight/smoke/correctness/matrix/soak/recovery 六子命令；双标签归属校验；禁全局 prune；密码 0600 环境文件即删）、`run-plan.schema.json`、`run-plan.example.json`、`corpus/manifest.json`（20 条自研合成语料，12 正常+8 攻击，JWT/例外逃逸两条标 deferred 待 S3/S4）、`collect.py`、`report.py`、`p0bench/` 共享库、`tests/`（79 unittest）、`README.md`。
- `docs/evidence/benchmarks/README.md` 与首个 preflight 证据目录 `20260906T190941-8f07d9/`。

与任务书的差异及理由：新增 `p0bench/` 共享包与 `run-plan.schema.json`（校验逻辑需可测实现）；未执行 smoke（需 compose up 新栈，未获授权，纪律限制），以真实 preflight 作为工具可运行证据。

实际执行命令与结果：
- `python3 -m unittest discover -s test/performance/p0/tests` → 79 tests OK（主代理复验一致）。
- `bash test/performance/p0/run.sh preflight --plan test/performance/p0/run-plan.example.json` → PASS，证据落盘；确认输出无凭据泄漏。
- `docker compose -p … -f deployment/docker-compose.p0-benchmark.yml config --quiet` → 通过（只读验证，未 up 栈）。
- `bash -n run.sh` 语法通过；report.py 对构造样例目录渲染正确。

验收 ID → 状态：BENCH-01/02/05/06/07 → PASS（工具层单测）；BENCH-03/04/08/09/10 → BLOCKED（工具就绪，缺真实隔离环境，reason=ENVIRONMENT_UNAVAILABLE）；BENCH-11/12 → BLOCKED（正式矩阵/72h 长稳/异机复跑需专用硬件）。**S2 测量部分不宣称通过；S5 未通过前四项 P0 总状态不得为完成。**

未完成事项、依赖和限制：ab 闭环并发与 open_fixed_rate 组合被工具拒绝（如需固定到达率需 wrk/k6）；macOS docker stats 为 VM 口径；recovery 仅覆盖网关重启；correctness 的检测证据对账需首次真实运行核对 request_id 格式。

下一步：S3 — P0-03 JWT 信任链完整链路开发（不依赖基准测量结果）。

## S3 记录（2026-09-06～07，P0-03 JWT 信任链）

阶段/任务书版本：S3，P0-03 任务书 2026-09-06。

时间、分支、commit、工作树摘要：2026-09-06 16:45 UTC 至 2026-09-07 04:55 UTC；`develop` @ `3c73774`；工作树沿用 S0 基线（约 1500 个他人未提交文件）。本阶段全部改动未 git add/commit。

本阶段目标与改动文件：
- 网关验签核心（新增）：`gateway/dynamic_security/jwtverify/`（验签、严格声明校验、JWKS 受限获取与有界缓存、KeysetVersion 指纹）。
- 网关挂接（新增）：`gateway/modules/jiuzhang_guard/jwt_trust.go`(+test)；`apiprotect.go` serveNext 统一放行出口 JWT 强制处置（白名单/L7 allow 不绕过）；身份观测 panic 不影响 JWT 强制（fail-open 隔离有 -race 回归测试）。
- server 策略面（新增）：`server/internal/jwttrust/`（CRUD/预检/乐观锁/审计/静态 JWKS 私参拒收/ListForGuard 下发契约）；迁移 000125（策略+不可变版本+内网 IdP 允许清单种子）、000126（jwt_trust.read/manage 权限）、000127（api_runtime_events.jwt_verification 列），均有 down。
- 配置供应链（新增/修改）：`server/internal/guardconfig/jwt_trust.go`(+test)（fail-hard 加载、PROTECT 管线门禁、节点未知语义拒绝）、`provider.go` 接线。
- OpenAPI：`server/openapi/fragments/16-jwt-trust.yaml` 新增，`openapi.yaml`/`wdsp-api.yaml` 重生成（--check 通过，schemas=739）。
- 接口测试（新增）：`server/tests/stage_jwt_trust_test.go`（策略 CRUD/预检/RBAC/409 乐观锁/跨应用隔离/ListForGuard，真 DB）。
- 事件投影（修改）：`server/internal/apisecurity/runtime.go` ListRuntimeEvents 投影 jwt_verification（omitempty）；web 事件详情抽屉加「JWT 验证信息」区块（EventDetailDrawer.tsx / SecurityEventsPage.tsx / types/index.ts，policy_version 兼容 number|string）。
- 前端（新增）：`web/src/api/jwtTrust.ts`、`web/src/utils/jwtTrust.ts`、`web/src/pages/applications/detail/JwtTrustTab.tsx`(+组件测试)、`web/e2e/jwt-trust.spec.ts`。
- 真实网关集成（新增）：`test/e2e/jwt-trust-smoke.sh`，26/26 断言通过（合法 Token 200、伪造 401+challenge、缺 Token 401、OBSERVE 放行、VERIFIED+SQLi→Coraza 403、事件落库含 jwt_verification、发布门禁/预检真实通过）。
- 基准工具接线：`test/performance/p0` jwt_pair 语料 + jwttool.py（123 单测绿；正式测量仍 BLOCKED_ENV）。
- 共享缺陷修复（他人 WIP 引入、阻塞全仓审计写入）：`server/internal/audits/audits.go` recordWithDelivery 去掉 `ON CONFLICT (delivery_id)`（operation_audits 存在 000001 的 no_update/no_delete RULE，PG 报 0A000），改为普通 INSERT + 捕获 23505/idx_operation_audits_delivery_id 返回 (false,nil)。
- 跨模块口径修复（同 kid 换 key 版本不变的真缺陷）：`server/internal/jwttrust/jwks.go` KeysetVersion 重写为与网关 `jwtverify.keysetVersion` 逐字节一致；共享钉版向量两侧同为 `0ea50ea947969fcfee1bd6221cb36cf9`（server TestKeysetVersionGatewayParity / 网关 TestKeysetVersionServerParity 互相钉住）。
- 证据与清单：`docs/evidence/releases/dev-s3-jwt-20260907/`（manifest.json + 20 份 artifacts，工件均附 sha256）；`docs/capabilities/capabilities.json` jwt-verification → IMPLEMENTED/CONNECTED、verification_status 按计算值 BLOCKED、evidence_refs 接入 JWT-01～18；CAPABILITIES.md 重生成；`tools/tests/test_capability_evidence.py` 仓库清单冒烟改为对最新真实证据包校验（状态分布以清单声明为准，不再硬编码全 NOT_RUN）。

与任务书的差异及理由：
- policy_version 类型分叉（管理面 int / 事件链 string）为既定事实，前端类型已兼容 number|string；本阶段不强行统一，记录在此。
- JWT-15 用例6（事件详情 JWT 区块）按设计条件跳过：`security_events` 唯一来源为 Coraza 审计日志（恒不携带 jwt_verification，见 securityevents/normalize.go），JWT 处置事件落 access_control_events/api_runtime_events（迁移 000127）；spec 扫描最近事件后 skip 并以 annotation 记录原因，不伪造事件；区块渲染由组件测试覆盖。
- E2E 期间发现 `web/e2e/global-setup.ts` 把登录限流提额到 100000，被后端校验上限 10000 拒绝（settings.go:347，`login:rate_limit_per_minute {1,10000}`），连跑时末位用例撞默认 10 次/分钟限流（captcha_id not returned）。修复限定在本规格 `test.beforeEach` 清空 `jiuzhang:ratelimit:*`；共享 global-setup 属 stage5 既有资产，未改动，问题记录在此供其所有者决策。
- E2E 驱动脚本（/tmp，未入库）的 trap 拆栈在托管 shell 下两次均未生效，均已手动 `docker compose ... down -v` 强拆并确认无残留。

数据库迁移/配置兼容/回退方式：三个迁移均带 down 且在接口测试中真实执行上下迁移；旧节点不接受未知强制语义（guardconfig 门禁单测覆盖）；策略为每应用独立草稿+发布，草稿不等于生效。

实际执行命令与环境标识：开发机 macOS 25.2.0 arm64；Go 1.25.6、Python 3.12.0、Node 24.13.0、Docker 28.3.0；一次性隔离容器 p0s3-pg（127.0.0.1:55432，postgres:16-alpine）/ p0s3-valkey（127.0.0.1:56379，valkey:8.1.8-alpine），口令仅经环境变量传入；stage5+wdsp compose 隔离栈（15440/16379/18080/18081）；Playwright chromium_headless_shell-1155 + 自有 vite 5199（5173 被其他项目占用，未动）。各验收 ID 的具体命令见 manifest 记录 command 字段（不含凭据）。

验收 ID → 状态 → 证据：
- JWT-01～17 → PASS → `docs/evidence/releases/dev-s3-jwt-20260907/manifest.json` 各记录（artifacts 相对路径 + sha256，工具校验通过）。
- JWT-18 → BLOCKED（reason=ENVIRONMENT_UNAVAILABLE）→ 同 manifest；jwt_pair 语料/接线完成、123 单测绿，正式测量留待 S5。
- 例外说明：JWT-14 的「部分节点失败/回退」未在真实多节点环境演练（单节点栈 + 单测/接口层覆盖）；JWT-15 用例6 条件跳过（见上）。
- 汇总校验：`python3 tools/capability_evidence.py check` 退出 0，jwt-verification 计算值 BLOCKED，发布状态 DEVELOPMENT。

其他实跑记录：全量 `server/tests` 260 PASS / 7 FAIL——7 个均为他人 WIP 或环境原因（APM 需 ClickHouse、license 绑定、SMS DNS、通知 405/400、Stage7 无 AI 模型、未跟踪包 RBAC），与本任务无关；web 全量 typecheck/lint/build/vitest 722 绿（vitest 跑于 00:10，之后 EventDetailDrawer.tsx 被并发改动致其 APM 链接用例失败，非本任务范围，未修）。

未完成事项、依赖和限制：
- JWT-18 依赖 S5 专用基准环境，未通过前四项 P0 总状态不得为完成。
- 单节点证据；HA 双节点下 JWT 策略一致性未演练。
- CI 未接入 python 套件与 jwt-trust-smoke（仓库 CI 入口变更不在本任务授权范围）。
- policy_version 类型分叉待后续统一（见上）。

下一步：S4 — P0-04 最终处置解释与有限范围例外。前置勘察已完成：§2.2 七条线索全部属实，多条比任务书描述更严重（provider 实际只下发前 20 条 ENABLED 例外；LOG_ONLY/ADJUST_SCORE 均为整请求 DetectionOnly；事件草稿 RuleIDs 空导致 ctl 零动作且 ApplicationID nil 被 fail-closed 永不下发），详见下节「S4 前置勘察」。

## S4 前置勘察（2026-09-07，只读复核）

对 P0-04 §2.2 逐条核实（精确行号以当时工作区为准，实施前须再核）：

| 线索 | 结论 | 关键证据 |
|---|---|---|
| URI 四字段择一 | 属实 | exceptions.go GenerateSecLang 单 switch；全空退化 `@rx .*` |
| Methods/SourceIPs/ContentTypes 未用；Cookie/Header 未进目标 | 属实 | GenerateSecLang/buildCtlActions 零引用；仅 ParamNames 进 ctl 目标排除 |
| LOG_ONLY/ADJUST_SCORE → DetectionOnly | 属实 | buildCtlActions 生成 `ctl:ruleEngine=DetectionOnly`，整请求失效 |
| provider 一页且次序分配 ID | 属实且更重 | List pageSize 超 100 被重置为 20（exceptions.go:328-330），实际只下发前 20 条；ID 8000001+ 按 created_at DESC 漂移 |
| 时间仅发布时过滤 | 属实 | provider.go:19-28；SecLang 无时间条件；ExpireTemporary 改状态不重发布 |
| 事件草稿 ApplicationID/RuleIDs 未传入 | 属实且更重 | app.go:1786-1800、fromevent.go:39-50；RuleIDs 空→ctl 零动作；ApplicationID nil→fail-closed 永不下发；URIExact 含 query |
| 风险确认可被单字段绕过 | 属实 | IsBroad/hasSpecificCondition 任一字段非空即「精确」；Enable 路径不再校验 |

补充发现（超出 §2.2）：Create 直接 Status=ENABLED 无 DRAFT 门禁（handler.go:94）；PUT 更新链路丢失 PolicyID（exceptionRequest 无该字段但 UPDATE 写回 policy_id=$5，更新即清空）；enable/disable 不触发发布，UI 无发布状态展示。

## S4 记录（2026-09-07～08，P0-04 最终处置解释与有限范围例外）

阶段/任务书版本：S4，P0-04 任务书 + 本目录 `S4_DESIGN_BASELINE.md`（实施前冻结的处置 DTO 与范围/动作矩阵基线）。

时间、分支、commit、工作树摘要：2026-09-07 至 2026-09-08；`develop` @ `3c73774`；工作树沿用 S0 基线（约 1500 个他人未提交文件，期间并发 agent 持续改动 server/agents 包）。本阶段全部改动未 git add/commit。

本阶段目标与改动文件：
- 最终处置（DEC）：网关 `gateway/modules/jiuzhang_guard/disposition.go`（终止分支 RecordTerminal/Finalize、连接劫持 outcomeHijacked、下游错误 RecordError）；`gateway/dynamic_security/decision|context|pipeline`（观察与实际动作分离：excepted 不定案、OBSERVE 降级、MASK_RESPONSE 优先级）；`gateway/internal/eventparser` 上送；server `securityevents` final_decision 列存取 + GetByID 详情投影（data.event.final_decision，store.go ~279 行）、`apiruntime` 条件补全（已确认拦截优先、幂等合并）；前端 `security-events/EventDetailDrawer.tsx` 最终处置区块。
- 例外（EXC）：`server/internal/exceptions` 重写（多条件交集编译、ValidateInput/ValidateForEnable 严格校验、LOG_ONLY/ADJUST_SCORE 启用门禁、预览 409 乐观锁、ListForPublish 全量 2000 容量字典序确定性、事件草稿绑定真实事件+缺证据 NEEDS_REVIEW）；`server/internal/guardconfig` api_exceptions 接线（app.go SetAPIExceptionsLister + guard.go 注入）；网关 `apiexceptions.go` 求值挂点 + `corazasemantics`（两规则标记法全维翻折、TIME_EPOCH 半开区间运行时求值、2000 条容量实测、`payload_coverage_test.go` 载荷覆盖集不动点：942100/942190/942270/942360+contrib 1001209 全摘除才放行）；迁移 000130/000131/000132（含 security_events 分区级联、历史 LOG_ONLY 标 NEEDS_REVIEW，up/down/幂等 23/23）；前端 `pages/exceptions`（草稿/预览/启用/派生状态如实翻转）。
- 测试资产：`test/e2e/exception-p0-smoke.sh`（真实网关冒烟，头部含 is_api 分类注意事项与 dump 诊断增强）、`test/e2e/exception-p0-e2e-driver.sh`（E2E 驱动：CI Ed25519 临时授权、固定临时口令、vite 5199、pkill 兜底清理）、`web/e2e/exception-p0.spec.ts` 5 用例。
- 证据与清单：`docs/evidence/releases/dev-s4-dec-exc-20260907/`（manifest.json 21 条记录全 PASS + 16 份 artifacts 附 sha256，第六轮 29/34 日志保留为历史证据 `exception-p0-smoke.log`）；`capabilities.json` 两项同步（waf-exceptions → IMPLEMENTED/CONNECTED/PASS + evidence_refs EXC-01～15 + limitations 重写为当前真实限制；request-final-disposition → IMPLEMENTED/CONNECTED/PASS + evidence_refs DEC-01～06）；新增 `docs/evidence/merged-check-s3-s4.manifest.json` 合并校验视图；CAPABILITIES.md 自合并视图重生成；`tools/tests/test_capability_evidence.py` 仓库清单冒烟从「最新单一 manifest」改为「全部真实证据包的临时合并视图」（38 单测保持全绿）。

与任务书的差异及理由：
- 校验器单 manifest 语义与跨阶段累计清单的矛盾：`cross_validate` 要求全部能力的 evidence_refs 在单一 manifest 闭合，而 jwt 证据在 S3 包、DEC/EXC 在 S4 包。处置：构造合并视图（两包 tests 合并、工件路径相对 docs/evidence/ 重写、sha256 原样沿用）作为累计清单权威校验输入，check rc=0；S4 包单跑的预期断链报错与说明一并存入 `artifacts/capability-check.log`。
- 冒烟脚本期望串误写：`||` 拼接布尔经 psql 渲染为 true/false，脚本原写 t/t（E1/E25），已修；非产品缺陷。
- DEC-01/02/05 曾暂停后已解决：第六轮根因=冒烟素材 `/api/json` 经统一管线分类 is_api=false（confidence 0.15），非 API 流量不落 api_runtime_events final_decision。第八轮修复：素材带 JSON CT/Accept/body（分类器得分 1.0），并发现 E3 旧期望串 `ALLOW|…` 与设计契约相反——`apicoraza.go` attributeWAFIntercept 既定语义为统一管线未判阻断而下游 Coraza 真实中断时 final_action 按实记 BLOCK（事实记录而非引擎决策），引擎自身动作留 final_decision.steps（API OBSERVED，即任务书 DEC-01「API 结果不变」）。期望修正为 `BLOCK|WAF|BLOCK|403|OBSERVED` 并补 steps 断言后 34/34 全过。

数据库迁移/配置兼容/回退方式：000130/000131/000132 均带 down，`artifacts/exc15-migration-trial.sh` 真实执行 up/down/幂等重跑 23/23；旧节点无 api_exceptions 字段时 guardconfig fail-hard 语义不变。

实际执行命令与环境标识：同 S3 开发机；一次性容器 p0s3-pg/p0s3-valkey 复用；stage5+wdsp compose 隔离栈（test-license 覆盖构建）；E2E 用 vite 5199（5173 属其他项目未动）。各验收 ID 具体命令见 manifest command 字段。

验收 ID → 状态 → 证据：
- EXC-01～15 → PASS → `docs/evidence/releases/dev-s4-dec-exc-20260907/manifest.json`（含第八轮冒烟 34/34、corazasemantics 载荷覆盖集不动点、迁移演练 23/23、接口测试 16/16、E2E 5/5、web 四件套全绿 vitest 815 用例；EXC-10/13 的 API 侧定时断言在第八轮素材修复后亦通过）。
- DEC-01～06 → 全 PASS → 同 manifest（DEC-03/04/06 第六轮已过；DEC-01/02/05 第八轮翻 PASS：跨侧 request_id 关联计数=1、源站归因 COMPLETED|NONE|ORIGIN|200、API 决策不改写+final_decision 归 WAF/BLOCK；各记录 note 保留第六轮根因历史）。
- 汇总校验：最终合并视图 check rc=0：waf-exceptions 与 request-final-disposition 均计算为 PASS；发布状态 DEVELOPMENT。

其他实跑记录：gateway 侧注意 dynamic_security 与 modules/jiuzhang_guard 为嵌套 go module，须各自目录内跑 go test（从 gateway/ 根跑报 "main module does not contain package"）。

未完成事项、依赖和限制：
- 单节点栈证据；多节点发布扇出部分失败处置未实测（EXC-12 注记）。
- 真实 SSE/gRPC 长连接端到端未专项实测（DEC-06 限制如实保留）。
- Coraza 合流归因与 coraza-caddy v2.5.0 未导出哨兵耦合，升级 CORAZA_CADDY_VERSION 必须复核（apicoraza.go 局限声明）。

下一步：S5 — P0-02 最终基准与长稳恢复（工具层已完成：test/performance/p0 123 单测绿、preflight PASS 证据 `docs/evidence/benchmarks/20260908T083935-e58633`；正式测量项按任务书如实 BLOCKED）。

## S5 记录（2026-09-08，P0-02 最终基准与长稳恢复收尾）

阶段/任务书版本：S5，P0-02 任务书（S2 已完成工具层与前测，本阶段做最终验收收口）。

时间、分支、commit、工作树摘要：2026-09-08；`develop` @ `3c73774`；工作树沿用 S0 基线。本阶段无新增业务代码改动（工具层 S2 已交付），仅复测、落证据、同步清单。

本阶段目标与改动文件：
- 工具层复测：`python3 -m unittest discover -s test/performance/p0/tests` 123/123 OK（日志 `artifacts/p0bench-unittests.log`；输出中 "openssl 签名失败" 一行为负向用例的预期 stderr，套件整体 OK）。
- 预检证据归档：run `20260908T083935-e58633` 的 report/status 拷入证据包（preflight PASS 非强制项；七模式矩阵/安全正确性/事件对账/长稳章节全部如实 NOT_RUN，未伪造测量）。
- 证据与清单：`docs/evidence/releases/dev-s5-bench-20260908/manifest.json`（BENCH-01～12 共 12 条）；新增 `docs/evidence/merged-check-s3-s4-s5.manifest.json` 合并视图（51 条记录）；`capabilities.json` 12 项能力按计算值同步（见下）；CAPABILITIES.md 自合并视图重生成。
- 清单冒烟测试演进：`tools/tests/test_capability_evidence.py` 仓库清单校验从「最新单一 manifest」改为「全部真实证据包的临时合并视图」（S4 已改，S5 落地后自动覆盖三包；38 单测保持全绿）。

与任务书的差异及理由：
- 正式测量项全部 BLOCKED（ENVIRONMENT_UNAVAILABLE）：共享开发机纪律禁止正式性能测量；72 小时长稳与异机复跑无硬件条件。任务书硬约束「S5 不过则四项 P0 总状态不得为完成」如实保留——当前四项 P0 总状态均为未完成。
- 记录级 `capabilities` 适用性补全：S3/S4 manifest 中 JWT-14/JWT-17、DEC-01/03/04/05、EXC-03/08/10/12 的 capabilities 列表按 catalog 场景引用反向补全（校验器语义：记录存在但未声明适用于某能力时按 NOT_RUN 计）；仅元数据补全，不动任何工件与哈希。
- 能力状态连锁变化（计算值，非手填）：BENCH 证据落地后 real-client-ip/access-control-cc/identity-behavior-observation/apm-entry-performance 随 DEC/EXC/JWT 已有证据计算为 PASS；waf-crs-detection/api-assets-models/api-request-response-detection/api-unified-decision/event-chain/config-release-ha/apm-trace-sql-exception/agent-collection-forwarding 计算为 BLOCKED（各自阻塞项见 CAPABILITIES.md 分场景明细）。

数据库迁移/配置兼容/回退方式：本阶段无迁移与配置变更。

实际执行命令与环境标识：同 S4 开发机；未启动任何压测/攻击流量（预检为示例计划登记，purpose=BEFORE）。

验收 ID → 状态 → 证据：
- BENCH-01/02/05/06/07 → PASS → `docs/evidence/releases/dev-s5-bench-20260908/manifest.json`（隔离归属/目标允许表/指标分离/分位数/报告完整性，工具层单测 + 预检实跑）。
- BENCH-03/04/08/09/10 → BLOCKED（reason=ENVIRONMENT_UNAVAILABLE）→ 同 manifest（BENCH-08 可单测部分已绿，端到端对账待真实栈）。
- BENCH-11/12 → BLOCKED（reason=ENVIRONMENT_UNAVAILABLE）→ 同 manifest（72h 长稳不得以短测顶替；无第二套同规格硬件）。
- 汇总校验：合并视图 check rc=0；分布 PASS=5 / BLOCKED=10 / NOT_RUN=0；发布状态 DEVELOPMENT。`artifacts/capability-check.log` 记录合并视图与本包单跑（预期断链）两次输出。

未完成事项、依赖和限制：
- BENCH-03/04/08/09/10/11/12 依赖专用隔离硬件与连续时间窗，是本线出 RELEASE_VERIFIED 的硬阻塞之一。
- JWT-18（jwt_pair 正式测量）同属 S5 范畴，随 BENCH-11 一并待硬件。
- 本阶段证据不含真实负载；预检报告各章节如实 NOT_RUN。

下一步：S6 — 发布证据冻结：当前无干净构建输入与锁定镜像（source.dirty=true、images 为空），RELEASE_VERIFIED 不可达成，S6 只能交付「冻结现状 + 差距清单」，不得伪造发布验收。

## S6 记录（2026-09-08，P0-01 发布证据冻结）

阶段/任务书版本：S6，P0-01 任务书 §7 验收 + 总纲 S6 行（最终构建与证据一致；所有强制验收项可定位；限制与未完成项如实保留）。

时间、分支、commit、工作树摘要：2026-09-08；`develop` @ `3c73774`（与各 manifest source.commit 一致）；工作树 1614 个未提交文件，dirty=true 如实标注。本阶段无业务代码改动。

本阶段目标与改动文件：
- 冻结核查：`docs/evidence/releases/dev-s6-freeze-20260908/artifacts/freeze-coverage-check.log`——63 条强制验收项（EVD 12 + BENCH 12 + JWT 18 + DEC 6 + EXC 15）全部可定位、无缺失无多余；状态分布 PASS 52 / BLOCKED 10 / NOT_APPLICABLE 1（DEC-01/02/05 于冻结后翻 PASS，本日志已刷新）；`--release` 实测拒绝（rc=1，原因：无干净构建输入/快照/文件清单/锁定镜像/配置指纹 + 6 项能力 BLOCKED）。
- S6 manifest：EVD-01～09 → PASS（工具 38 单测全绿，`artifacts/capability-tool-tests.log`）；EVD-10 → NOT_APPLICABLE（本轮 P0-01 无 HTTP/UI 交付面变更）；EVD-11/12 → BLOCKED（ENVIRONMENT_UNAVAILABLE）。
- 最终合并视图：`docs/evidence/merged-check-final-20260908.manifest.json`（四包 63 条，工件哈希经校验器实机比对）；最终 check rc=0（`artifacts/capability-check.log`）；CAPABILITIES.md 自最终视图重生成。
- 中间合并视图 `merged-check-s3-s4.manifest.json` / `merged-check-s3-s4-s5.manifest.json` 保留不删——分别被 S4/S5 证据包的 capability-check.log 引用，不覆盖旧证据。

与任务书的差异及理由：
- RELEASE_VERIFIED 未达成且不得伪造：任务书 §7 EVD-11/12 要求真实环境证据，当前无干净构建输入（dirty 工作树含大量他人 WIP）与第二套硬件，故冻结现状并保留全部阻塞项。
- 能力清单最终分布：PASS 9（waf-crs-detection、real-client-ip、access-control-cc、api-request-response-detection、identity-behavior-observation、api-unified-decision、request-final-disposition、waf-exceptions、apm-entry-performance）、BLOCKED 6（api-assets-models、jwt-verification、event-chain、config-release-ha、apm-trace-sql-exception、agent-collection-forwarding）、NOT_RUN 0；发布状态 DEVELOPMENT。

数据库迁移/配置兼容/回退方式：本阶段无迁移与配置变更。

实际执行命令与环境标识：同 S4/S5 开发机；全部命令为只读校验与报告生成（工具不执行网络请求、不运行 manifest command 字段）。

验收 ID → 状态 → 证据：
- EVD-01～09 → PASS → `docs/evidence/releases/dev-s6-freeze-20260908/manifest.json` + capability-tool-tests.log。
- EVD-10 → NOT_APPLICABLE → 同 manifest（reason 已记）。
- EVD-11/12 → BLOCKED（ENVIRONMENT_UNAVAILABLE）→ 同 manifest + freeze-coverage-check.log。

未完成事项、依赖和限制（出 RELEASE_VERIFIED 的完整差距清单）：
1. 干净构建输入：收敛/隔离他人 WIP 后取干净 commit，生成 snapshot_sha256 + file_manifest。
2. 锁定镜像：按架构锁 digest 填入 images，并记录 config_fingerprint。
3. JWT-18 与 BENCH-03/04/08/09/10/11/12：专用隔离硬件 + 72 小时长稳窗口（连带消解 jwt-verification、api-assets-models、event-chain、config-release-ha、apm-trace-sql-exception、agent-collection-forwarding 六项 BLOCKED 能力）。
4. EVD-11/12：干净环境重建 + 异机复跑。
5. 上述全部消解前，四项 P0 总状态保持未完成，发布状态保持 DEVELOPMENT。

下一步：无后续阶段；等待硬件/构建条件具备后按差距清单补证。

## 开发阶段记录模板

每完成一个阶段追加一条，保留失败与重测历史；不要覆盖旧证据。

```text
阶段/任务书版本：
时间、分支、commit、工作树摘要：
本阶段目标与改动文件：
与任务书的差异及理由：
数据库迁移/配置兼容/回退方式：
实际执行命令与环境标识（不得包含凭据）：
验收 ID → PASS/FAIL/SKIP/BLOCKED/NOT_RUN → 证据路径/哈希：
未完成事项、依赖和限制：
下一步：
```

## 下次接续

S0～S6 全部收尾（S5/S6 为 PARTIAL，阻塞项均为环境与构建条件，非代码缺口；S4 已全 PASS）。当前冻结事实：63 条强制验收项全部可定位（PASS 52 / BLOCKED 10 / NOT_APPLICABLE 1）；能力清单 PASS 9 / BLOCKED 6；发布状态 DEVELOPMENT，`--release` 门槛实测拒绝。出 RELEASE_VERIFIED 的差距清单见「S6 记录」末节（干净构建输入、锁定镜像、测量硬件/72h 长稳、EVD-11/12 重建复跑）。开始前重新读取当前代码，不能把本文件的代码观察视为永久事实。禁止将文档验收状态与功能验收状态混为一谈。
