# 阶段4–8 任务书未完成项审计清单

> 生成时间：2026-09-10
> 范围：docs/tasks/ 下 6 份任务书——STAGE_5_ACCESS_CONTROL_CC、STAGE_6_SECURITY_OPERATIONS_DELIVERY、STAGE_7_AI_SECURITY_OPERATIONS、STAGE_8_UNIFIED_WEB_API_DYNAMIC_PROTECTION、STAGE_8_WDSP_KICKOFF、STAGE_4_7_REMEDIATION_PLAN
> 方法：逐份提取要求项，与 gateway/、server/、web/src/、migrations、Makefile、test/ 当前代码交叉核对；文档自述"已完成"项也抽查了代码真伪。所有状态以代码事实为准。

## 总览

| 文档 | 主体完成度 | 未完成 | 部分完成 | 主要缺口 |
|------|-----------|--------|----------|----------|
| 阶段4–7 修复方案（M-01~26） | **26/26 已实现** | — | — | 全部清零（M-13/M-26 于 2026-09-10/11 修复） |
| 阶段5 访问控制/CC | 主体完成 | 0 项 | 1 项 | §12.5 URI 正则超时（RE2 设计偏离）（§七/§8.1/§十一/§6.5/§8.5/§二十一/§十七/§5.1/§十五 已完成） |
| 阶段6 安全运营交付 | 主体完成 | 1 项 | 3 项 | 72h 稳定性测试、保护地址拦截统计待网关事件（§7.3 来源维度已完成） |
| 阶段7 AI 安全运营 | 主体完成 | 0 项 | 3 项 | 完整 RAG（用户暂缓）、What-If 回放引擎（8/8 场景已完成）、E2E 待集成验收 |
| 阶段8 统一任务书 | 骨架与外壳已全量 | 0 项 | 11 项 | §36 剩余维度、§55 阈值待定义、§7.2 下发面、§22/23 剩余 2 类（归 AUTHZ 线）、测试矩阵待集成验收（§33/§7/§9/§8.2/§44/§35 等 6 项已完成） |
| 阶段8 开工说明 | 8/8 勾选项属实 | 1 项 | 3 项 | 与阶段8 任务书缺口同项；另见 DEVELOPMENT_STATUS 诚实遗留 |

---

## 一、阶段4–7 修复方案（STAGE_4_7_REMEDIATION_PLAN.md）

文档头部自述"主项已实施；M-22–M-24 仍待"，其中 M-22/23/24 实际已完成（见第五节文档过期项）。真正未完成：

| 条目 | 要求 | 状态 | 证据 |
|------|------|------|------|
| ~~M-13~~ | blockCache.Refresh 启动失败需 Error 日志 + 节流事件；fail-closed 时首刷失败拒绝服务 | **已完成 2026-09-11** | `module.go` initialBlockRefresh：日志 + 节流事件（复用 RATE_LIMIT_ENGINE_ERROR/ENGINE_ERROR 口径，请求与启动路径共用节流键）+ fail-closed 首刷失败拒绝加载（半成品回收，fail-open 行为不变）；2 个单测全绿 |
| ~~M-26（S11）~~ | 可信代理链全 trusted 时的回落处理 | **已完成 2026-09-10** | `clientip/clientip.go` Result 新增 ChainAllTrusted，全链可信回落连接源 IP；module.go 复用 TRUSTED_PROXY_INVALID 事件（action=CONNECTION_FALLBACK）；14/14 单测通过 |
| ~~M-26（S12）~~ | CSRF Origin 端口归一化（nit） | **已完成 2026-09-10** | `middleware/auth.go` sameOrigin 默认端口归一（https→443/http→80，非默认端口精确匹配），畸形 Origin 拒绝；新增 15 个用例全绿 |

注：M-26 两项均已修复。M-26 原文标注 nit/P2。

## 二、阶段5 访问控制与 CC（STAGE_5_ACCESS_CONTROL_CC.md）

| 条目 | 要求 | 状态 | 证据 |
|------|------|------|------|
| ~~§十一 事件→黑名单~~ | 从安全事件加入黑名单：自动填充 8 字段 + 管理员确认 5 项 | **已完成 2026-09-10** | `accessrules/prefill.go` 预填接口（8 字段+建议时长分档≤72h+共享出口/保护地址/已有规则确认项，无数据不编造）+ Create 支持 source_type=SECURITY_EVENT（白名单校验+事件存在性校验）+ 前端双入口与确认 Modal；实库集成测试 18 个用例通过 |
| ~~§十七 发布后验证~~ | 发布后执行真实IP/黑白名单/CC 测试 → 标记生效 | **已完成 2026-09-11** | `gatewayconfig/publisher_smoke.go`：发布后经 `/_wdsp/bot/v1/publish-smoke` 404 墓碑路径三探针（REAL_IP/BLACKLIST/CC 行为验证），FAIL 走既有回滚路径，探针不可达降级 SKIPPED 如实记录；版本 validation_result 落 SMOKE_PASS/FAIL/SKIPPED；前端版本列表加"流量验证"列；实库集成通过。~~遗留：CC 精确计数探针~~ 已于 2026-09-11 第十波补齐：网关 `/_wdsp/debug/v1/cc-counter` 回显端点（仅回环/RFC1918/ULA、不回显键材料、自身不计数、结构不可反代；ratelimit.Peek 只读访问器）+ publisher_smoke 第四探针 CC_EXACT（合成来源打满阈值+回显验证递增+第 N+1 次断言 429，不可达/未采信如实 SKIP）+ 开关 system_settings `gateway_runtime.debug_cc_counter`（迁移 000157 缺省 true，可关） |
| ~~§6.5 日志字段~~ | `client_ip_source`/`trusted_proxy_used`/`forwarded_chain_summary` | **已完成 2026-09-10** | events.Event 与 accessLogRecord 三字段（omitempty+截断）+ 迁移 000144 加列 + server 解析/落库/读回同步，单测全绿。~~遗留：JWT_*/BOT_*~~ JWT/BOT 事件点三字段已于 2026-09-11 补齐（jwtEventBase + botchallenge CallContext 透传，各带单测） |
| ~~§5.1 自定义 429 页面~~ | 429/阻断响应可配置、随发布下发 | **已完成 2026-09-11** | 迁移 000151 block_response 组 4 设置键 + 网关 `blockresponse.go`（x/net/html 白名单净化防 XSS）+ module.go writeTooMany 配置化（默认逐字节不变有单测锁定）+ 随发布热下发 + 系统设置页"阻断响应页面"页签；实库 TestStage5BlockResponseSettings 通过 |
| ~~§七 保护地址自动维护~~ | 系统自动登记 | **已完成 2026-09-11** | `protectedaddresses/scheduler.go`：启动即刷 + 周期调度（PROTECTED_ADDRESS_REFRESH_INTERVAL，默认 1h，失败记日志不退出），挂接 cmd/api/main.go；手动端点保留；4 个单测全绿 |
| ~~§8.5 规则关联事件~~ | 查看规则关联事件 | **已完成 2026-09-10** | GET /api/v1/access-rules/{id}/events 已注册（app.go:1137，权限 access_rules.read）；ListFilter 新增 AccessRuleID；前端规则页加"关联事件"抽屉；OpenAPI 04 已更新 |
| ~~§十五 共享 NAT 检查~~ | 自动封禁前检查共享出口风险 | **已完成 2026-09-11** | `temporaryblocks/natguard.go`：自动封禁落点（UpsertFromEvent）前查近 24h 同 IP 不同身份数（identity_ip_history，与 prefill 共享出口同口径），达阈降档为缩短封禁时长（DB+Valkey 同步夹紧、LEAST 幂等不抵消）；配置 cc_auto_block 组三键（迁移 000153，默认开/阈值2/15分钟，非法回落默认）；审计事件 CC_TEMP_BLOCK_DOWNGRADED 全程留痕；查询失败按原样封禁+slog.Error 不静默；7 单测+3 实库集成通过。边界：采集器轮询 ~2s，网关先行全时长封禁数秒后被降档 |
| §12.5 URI 正则超时 | 长度限制 + 安全校验 + 执行超时 | 部分完成（设计偏离） | 长度/校验有；无执行超时，以 RE2 线性时间替代（代码自述防 ReDoS） |
| ~~§二十一 CC 分步配置~~ | 前端分步向导 | **已完成 2026-09-10** | RateLimitPage 改为四步 Steps 向导（RateLimitWizardDrawer + wizard.ts 纯逻辑：基本范围→阈值窗口→处置动作→确认摘要），分步校验+末步摘要+干跑保留+编辑回填；13 个 vitest 用例全绿 |
| ~~§8.1 DRAFT 状态~~ | 规则状态含 DRAFT | **已完成 2026-09-11** | ValidateStatusTransition 状态机（EXPIRED→ACTIVE、DRAFT→DISABLED 均 400）；导入落 DRAFT、发布快照仅 ACTIVE、显式启用生效；前端标签/筛选/启用；单测+实库集成全绿 |

## 三、阶段6 安全运营与交付（STAGE_6_SECURITY_OPERATIONS_DELIVERY.md）

| 条目 | 要求 | 状态 | 证据 |
|------|------|------|------|
| ~~§11.5 维护窗口~~ | 告警按维护窗口抑制 | **已完成 2026-09-10** | 迁移 000142 system_alert_maintenance_windows 表 + evaluator Raise 前抑制（suppressed_count/last_suppressed_at 可观测，异常不放行）+ CRUD 路由/审计/OpenAPI + 告警页维护窗口 Drawer；6 个单测全绿（DB 层待有库环境验证） |
| ~~§10.2 文件句柄监控~~ | fd 采集 | **已完成 2026-09-10** | `runtimehealth/fd*.go` 三指标（Linux /proc，阈值 80% 可配）+ FD_USAGE_HIGH 规则 + evaluator DEGRADED→raise/UP→recover 挂接已补（第二波）；单测全绿 |
| ~~§7.1 方法/Content-Type 分布~~ | 请求统计含两维分布 | **已完成 2026-09-10** | 网关 access_logs 本已带 request_method/content_type；`analytics/store.go` 新增 MethodDistribution/ContentTypeDistribution 挂到 request-trend；前端分析页两分布图；OpenAPI fragment 05 已同步 |
| §7.3 可信代理来源统计 | 按可信代理来源 IP 维度统计；保护地址拦截统计 | 主体完成 2026-09-10（保护地址拦截统计待网关事件） | `analytics/store.go` 新增 ClientIPSourceDistribution/TrustedProxyDistribution（access_logs 000144 两列实时聚合），挂 request-trend；前端两分布卡片；OpenAPI 已同步。保护地址命中需 module.go 发事件（有在途改动，待后续波次） |
| ~~§11.4 告警导出~~ | 告警导出功能 | **已完成 2026-09-10** | GET /api/v1/system-alerts/export 已注册（app.go:1235，读权限+导出限流）；系统告警页加导出按钮；OpenAPI 已更新；集成测试 TestStage6SystemAlertsExport 已写（待有库环境运行） |
| §十六 高危漏洞扫描检查项 | 交付检查含漏洞扫描 | 未完成 | `delivery/checks.go:83-104` 共 22 项，无漏洞扫描类 |
| ~~§十七 DEPENDENCY_LICENSES.md~~ | 依赖许可证清单文件 | **已完成 2026-09-10** | `docs/DEPENDENCY_LICENSES.md` 已建（Go 直接依赖+前端 dependencies/devDependencies 全量+10 个第三方镜像+数据资产）；scripts/license-audit.sh 第 5 步强制 licenses/ 双向同步，`make license-audit` 通过；无 GPL/AGPL 依赖 |
| ~~§二十六 THIRD_PARTY_NOTICES.md~~ | 文档清单要求 docs/ 路径 | **已完成 2026-09-10（口径对齐）** | 决策：文件保留仓库根（README/离线包打包/compose 挂载等十余处引用），任务书 §二十六清单已修正为根路径 |
| §22.1 72 小时稳定性 | 72h 连续稳定性测试 | 未完成（已如实记录） | 测试报告遗留#2：仅短浸泡；`stage6-soak.sh` 默认 HOURS=1 |
| §8.3 rule_hit_summaries | 汇总表写数 | 部分完成（已如实记录） | 表已建但不写数，由 waf_rule_hits_total 指标承载（设计偏离） |
| §13 恢复后审计可用 | 恢复后审计可回写 | 部分完成（已如实记录） | 审计归档按设计不恢复写回，仅存于备份文件 |

## 四、阶段7 AI 安全运营（STAGE_7_AI_SECURITY_OPERATIONS.md）

| 条目 | 要求 | 状态 | 证据 |
|------|------|------|------|
| §23 知识库与 RAG | 完整 RAG：知识索引、embedding 检索、文档分级、引用 ID | 部分完成（大幅简化） | 无 ai_knowledge* 表、无 embedding 检索；KnowledgeAgent 实为规则元数据 ILIKE 检索（`aiagents/misc_agents.go:296-299`）；状态文档如实记为遗留 |
| §19 What-If 模拟 | 8 种模拟场景 + 历史事件离线回放 | **8/8 场景已完成 2026-09-11**（回放引擎遗留） | 服务端五新场景（aihandlers 真实聚合估算+口径写入回答+OpenAPI 08 枚举）+ **前端 8 场景入口**（whatIf.ts 纯函数校验+例外列表拉取，15 例 vitest）。遗留：全矩阵回放引擎（设计级）；add_exception 的 application_id/uri 收敛参数未暴露（可选补） |
| ~~§15.2/15.3 URI/应用画像~~ | 一等结构化画像 | **已完成 2026-09-10** | AnalyzeAttackProfile 优先级 ip>uri>application_id 结构化分支（queryURIProfile/queryAppProfile 真实 SQL 聚合，零数据如实"数据不足"）；前端画像对象选择器 |
| ~~§12.1 事件分析输入范围~~ | 时间范围/应用/IP/URI/规则/Request ID | **已完成 2026-09-10** | AnalyzeEvent 扩展 7 个可选结构化入参（逐一校验），维度组合走真实聚合组装上下文（analyze_context.go） |
| ~~§11.4 输出中断自动续写~~ | finish_reason=length 自动续写 | **已完成 2026-09-10** | orchestrator 透传真实 finish_reason + 自动续写循环（默认上限 2 次可配、续写前配额校验、SSE 步骤事件）、done payload 带 auto_continues、AssistantPage 截断提示；7 个单测全绿 |
| ~~§37 自动化命令~~ | ai-model-test / ai-tool-test / ai-agent-test / ai-prompt-test / stage7-test-rag | **已完成 2026-09-10** | Makefile:386-418 五个目标已加并入 .PHONY；stage7-test-rag 按"RAG 未实现、实跑 KnowledgeAgent 现有检索链路测试"口径实现（§23 RAG 本体仍未完成，不因此关闭） |
| ~~§10.5 rate_limit_statistics.get~~ | 访问控制统计 Tool | **已完成 2026-09-10** | `aitools/access_tools.go:39` 注册（RiskReadOnly、rate_limits.read、参数化聚合 access_control_events 五类 CC 事件+趋势+应用分布）；单测全绿；Tool 总数 61 |
| §36 E2E 场景二~八 | 误报草稿/画像草稿/攻击链/根因/压缩/注入/降级 E2E | 代码完成 2026-09-10，待集成环境验收 | `stage7-ai-soc.spec.ts` 补齐场景二~八共 7 个 test（真实 UI 行为断言，无空转绿）；本机无后端环境未实跑，需真实栈复跑 |
| ~~§30 接口路径一致~~ | 文档所列确切路径 | **已完成 2026-09-11** | 5 条 GET /{id} 详情路由补齐（models/agents/tools/audits/evaluations，404/400/权限语义统一）；OpenAPI fragments 08/09 已更新 |
| §34.1 评估集 | 至少 12 类内置评估集 | 种子已完成并实库验证 2026-09-11 | 迁移 000143：12 类×3 用例；实库加载验证通过（12 集 36 用例、幂等往返无损）；首轮评估运行（活模型）待有模型环境 |
| ~~§24.4 对抗测试环节~~ | Prompt 发布流程含对抗测试步骤 | **已完成 2026-09-11** | `aiprompts/adversarial.go` 内置 9 条对抗样本（注入/越权/泄露）+ 发布双门（回归 PASSED + ADVERSARIAL_PASSED，PublishGateError 结构化）；迁移 000146；端点 + 前端三态展示/明细弹窗/发布门错误友好展示；stage7 集成测试已适配双门并实库通过 |
| ~~§26.4 AI 数据保留期限~~ | 分表配置保留期限与清理 | **已完成 2026-09-10** | `guardjanitor/ai_retention*.go`：system_settings 五项保留配置（90/90/90/180/365 天，非法回落默认）+ 分批限量 sweep（main.go:137-141 调度，小时级）+ 引用保护（被审计引用的会话/任务/草稿不删、ACCEPTED/PENDING_REVIEW 草稿保留）+ 审计表因哈希链约束只归档不删并逐轮校验链完整性；迁移 000141；11/11 单测通过（DB 层集成验证待有库环境） |

## 五、阶段8 统一任务书（STAGE_8_UNIFIED_WEB_API_DYNAMIC_PROTECTION.md）

骨架已全量（27/27 表、51.x 接口命名空间、27/27 权限点、10/10 AI 工具、12+ 前端页面、引擎已挂接请求链）。缺口集中在深度：

| 条目 | 要求 | 状态 | 证据 |
|------|------|------|------|
| §44 业务流程偏离检测 | 任务书 7 项：跳过前置/重复提交/逆序/状态转换/批量执行/取消后继续/未登录后置 | **已完成 2026-09-11（七类全链路+前端+热发布+速率取消字段贯通）** | 网关七类规则全实现（detectors/flow.go，全 OBSERVE）+ 下发面（迁移 000155+000158 补 max_per_window/rate_window_seconds/cancels_flow 五列与 CHECK，管理面校验严于网关恒兼容）+ 前端流程基线页（步骤编辑器含短窗限速/取消语义三字段，零值省略口径）+ 基线变更热发布（SetPublishFunc 接整站发布链）；实库 E2E 通过 |
| ~~§9 协议类型 13 种~~ | REST_JSON/JSON_RPC/XML_RPC/SSE 等 | **已完成 2026-09-11** | `classifier/protocol.go` ClassifyProtocol 13 值词表；事件上报/落库随 §8.2 一并闭环（见下）。protocol_type 列无 CHECK（既有风格对齐） |
| ~~§8.2 四级识别标签~~ | CONFIRMED/PROBABLE/POSSIBLE/NON_API + 置信度 | **已完成 2026-09-11** | classifier 四级 Level + Confidence 落 ctx 扩展 → apievents 新增 `api_level` 上报（omitempty，fail-open/合成结果省略不编造；`api_confidence` 沿用既有 0..1 契约未改）→ 迁移 000149 api_runtime_events.api_level（词表 CHECK）+ 解析/边界校验/读回/OpenAPI schema 全链路；实库集成通过 |
| ~~§33 规范导入~~ | OpenAPI3/Swagger2/JSON Schema/Postman/GraphQL Schema | **已完成 2026-09-10；实库 42P10 缺陷已修复 2026-09-11** | 五种格式全支持 + JSON/YAML 双编码（安全解码/外部 $ref 拒绝/深度大小限制）；18 个解析单测全绿。实库验证发现 ON CONFLICT (endpoint_key) 与迁移 000137 复合唯一索引 uq_api_endpoints_scope 不对齐（42P10），已修 spec_version.go + 测试种子 + 演示脚本共 3 处，4 个 stage8 规范导入集成用例实库通过；yaml.v3 已锁版合规登记 |
| §16/§17 微模型统计 | P50-P99/熵/Unicode 脚本/单调性/离群值等 | 主体完成；format_candidate 已于 2026-11-15 补齐（实库集成待） | 迁移 000145 + 000206：脱敏观测含 null/直方图/前后缀及格式样本，固定格式候选限 UUID/EMAIL/IPV4/IPV6/DATE/DATETIME；至少20个合格字符串样本且唯一最高占比≥0.9，未知计入分母，候选只进 observed 并在详情展示。服务端全量、网关相关包及前端22项测试通过；真实 PostgreSQL/Valkey 迁移与统计集成因测试凭据未配置跳过 |
| §22/§23 字段间关系 | 13 类关系 | 主体完成 2026-09-11（11/13 实现，2 类论证降级） | 11 类实现：9 类（截至 000154）+ COUNT_MATCHES/SUM_MATCHES（迁移 000159 词表 12 值；parser 新增数组长度登记 JSONArrayLen O(1) + 数值聚合 JSONNumAgg 只留 sum/count 聚合量，单数组 64 元素/单请求 2048 步有界截断，截断不判定；SUM 相对容差 1e-9；证据 sha256 指纹不落明文；实库 5 用例通过）。剩余 2 类（父子对象/租户所有者）维持降级归 AUTHZ/BOLA 线 |
| §34 用途多维识别 | 9 维分类 + 40+ 动作词表 | 九维代码已实现（实库与浏览器待验收） | 业务域16映射、操作动作43项、技术协议/交互模式、数据敏感等级、身份要求、业务流程阶段、风险标签和业务对象均已落；BUSINESS_OBJECT 从真实对象模型+段形派生，path取前静态段/变量名、query取参数名，多类型为 MULTI_OBJECT，publishable提高置信度，缺失清理且锁定不改。各维度来源和置信度不同，不以路径猜测冒充全量自动识别；实库与浏览器未验收 |
| §36 API 维度限流 | 16 维限流 | 主体完成（已补凭据/租户/动作/接口组及共享计数，仍有维度/动作缺口） | 小时/日、对象、分页/批量（000152）+ 凭据（000207）+ 可信租户（000208）+ 操作动作（000209）+ 接口组（000210实体/000211限速）贯通保存/发布/版本戳/回滚与 Guard 429；仅消费真实 ACTION 或启用组的真实成员，应用间不拍平。并发和 GraphQL 成本预算另有既有实现。缺口：设备、通用请求成本及 TEMP_BLOCK/BLOCK 可配置动作；credrate/tenrate/objrate/actionrate/grouprate/quota_hour/quota_day 可经 Valkey 共享原子计数，默认内存/故障期为节点本地，恢复不回灌。实库、真实 Valkey 与正式多节点验收未完成 |
| §35 凭据异常 10 项 | Token 跨应用/已吊销凭据/HMAC 签名等 | **已完成 2026-09-11（吊销端到端闭环）** | 跨应用/多设备/位置/HMAC 已挂接生效（第七波）；**吊销凭据全链路**（第十/十一波）：迁移 000156 api_revoked_credentials + CRUD（api_credential.* 权限）+ 发布下发（生效窗口过滤、版本戳、WDSP 门控）+ 变更热发布 + 网关 credrevoked.go 检测器（`credential_type:fingerprint` 全等匹配 O(1)、expires_at 过期跳过、证据不落明文、auth.credential_revoked OBSERVE/HIGH）+ module.go 校验装配；端到端经 serveNext 管线命中验证。遗留：api_revoked_credentials 未入 backups/tables.go 备份清单（小项） |
| ~~§7 RequestContext~~ | device_fingerprint、object_identifiers 等字段 | **已完成 2026-09-11** | device_fingerprint（UA 族 HMAC，与 identitybehavior 对拍锁定口径）+ object_identifiers（只记哈希）；迁移 000150 事件两列 + 000149 findings 冗余列；pipeline.Process 检测段前落 ctx（同口径同盐幂等），检测器可直接消费；全链路透传 + 服务端边界校验 + OpenAPI schema 已补登 |
| §7.2 响应体采样比例 | 大报文限制含响应采样比例 | 引擎与下发面已实现 2026-11-15（真实环境集成待） | 迁移 000205 新增 `gateway_runtime:api_response_sample_ratio`（默认 1）；保存/发布/网关三层校验 0~1，指针保留显式 0；比例进入 handler、`api_policy_version`、WDSP 门控及回滚重放，网关请求/响应相位统一消费。管理面四包、网关 Guard 全包及 context/pipeline 回归通过；两项 PostgreSQL/Valkey 集成因测试凭据未配置跳过，真实迁移/HTTP/跨进程发布未验收 |
| §50 api_request_schemas | 请求 Schema 权威表 | 部分完成（偏差） | 表存在但零写入方，权威来源改为 api_model_versions.schema_json |
| §54 可观测指标 | 19 项指标 | 主体完成 2026-09-11（21 项全挂接） | 指标 15→21 项：server api_collector + 网关 `dynamic_security/metrics` + parser 埋点；第七波补齐：检测耗时/响应解析耗时 Track 已落 pipeline 双相位（非 JSON/截断不计入），事件积压 gauge 已挂接 apievents.Logger（入队/补写/排空三点 SetEventBacklog，未挂接不输出假值） |
| §55 性能矩阵 | 10 万级 API、百万级参数等 15 项 | 主体完成 2026-09-11（阈值待定） | 大规模维度首次实测（test/performance/w23-largescale-scale-result.md，10 万端点/120 万参数/70 万边，隔离库 jiuzhang_perf 测后销毁）：下发构建五查询 P50 合计 8.54s（参数约束查询 6.0s 占大头）、产物 JSON 148MB/gzip 1.56MB、构建堆增量 256MB；图谱查询 P95：edges_timerange 1.66s、edges_mincount 1.59s（均走磁盘排序，work_mem 4MB）。§55 原文无数值目标，达标判定待产品侧定阈值回填；遗留：学习任务并发、版本对比性能两项未测 |
| §61 安全测试 ~35 项 | 学习污染/投毒/BOLA/BFLA/图谱注入等 | 矩阵已建立 2026-09-11，待环境实跑 | `test/security/stage8-security-matrix.sh`（SEC-01~36，45 断言）+ `stage8-security-matrix.md` 逐项对账；bash 语法校验通过；唯一环境受限项 SEC-09 超大响应（缺 fixture）；需真实 stage8 环境首次实跑 |
| §62 E2E 七场景 | Playwright 全覆盖 | 代码完成 2026-09-10，待集成环境验收 | `stage8-api-security.spec.ts` 补齐场景二/四/五/六共 4 个 test（参数学习/冻结偏离不进学习/重新学习分支对比/统一事件单主事件多明细）；需真实栈复跑 |
| §6 建议目录 | telemetry/、coraza_adapter/、caddy_adapter/ | 部分完成（文档为"建议"） | 目录不存在；versioning 并入 learning/ |

阶段8 开工说明（STAGE_8_WDSP_KICKOFF.md）第1节 8 个勾选项经代码抽查全部属实；其 Wave D 收口指向任务书退出条件，实质未完成项同上，另 DEVELOPMENT_STATUS 自述的"诚实遗留"仍有效：

- ~~响应侧 gzip/br/流式直通不脱敏；ENCRYPT/MAP 脱敏动作未实现~~ 已补齐 AES-GCM ENCRYPT、HMAC MAP 与授权恢复（000213）、gzip/br 有界解压重编码、XML/text/SSE 值级观测；多重编码/deflate、压缩SSE、表单/二进制脱敏和真实长连接/实库验收仍有限制
- AuthZ 仅 OWNER 单关系，复杂租户层级未实现
- ~~响应侧值级敏感检测未消费~~ 已完成 JSON/XML/text/SSE `response_body` 规则消费（OBSERVE、证据不落值）；多重编码/压缩SSE、表单/二进制及流式脱敏仍不扫描或撤回
- 正式 P95/吞吐/RSS/长稳与 20 万关系集端到端指标仍缺
- 真实跨进程发布/多节点编排/机器网络故障恢复未验收
- AI 自动运营定时任务（api_ai_schedules 表与前端骨架已有，调度能力介于骨架与完整之间）
- ~~身份手工封禁/解封为阶段3+ 范围~~ 已完成000214状态/发布/网关403/前端闭环；CHALLENGE 身份动作仍未做，实库与跨进程验收待环境
- 请求 Schema 冻结模型的 E2E 覆盖不全（同 §62）

---

## 文档过期清单（文档与代码不一致，引用时需注意）

1. **docs/STAGE8_IMPLEMENTATION_REVIEW.md（2026-07-22）整体过期**：其"3/27 表、0/35 接口、0/10 AI 工具、引擎未接入网关、前端 2/12 页"等结论已全部被代码推翻，该报告结论应作废。
2. **STAGE_8_WDSP_KICKOFF.md 第4节**：称 API_DYNAMIC_PROTECTION_ENABLED 默认 false；代码 `server/internal/product/edition.go:50-56` 实际为"env 显式优先，未设时 wdsp/api 版默认开、waf 默认关"。
3. **STAGE_4_7_REMEDIATION_PLAN.md**：M-22（例外 PUT 更新）、M-23（AI draft 走完整 ValidateInput）、M-24（CC_TEMP_BLOCK_EXPIRED/RELEASED 事件）自述"仍待"，实际代码均已实现；文档验收复选框未打勾。
4. **docs/DEVELOPMENT_STATUS.md**：阶段6 小节标题仍为"进行中"，但同文件已标记阶段6 完成 2026-07-22；阶段5 小节声称 CC 页"分步表单"，代码无分步组件。
5. **docs/REAL_CLIENT_IP_DESIGN.md:43**：声称日志字段含 client_ip_source，代码中不存在。
6. **阶段7 任务书 §30**：接口路径与实现命名不一致（功能等价，文档未更新）。

## 开发进展日志

- **2026-09-10 第一波（9 项并行）**：M-26 S11/S12、阶段5 §8.5、阶段6 §7.1/§10.2（采集部分）/§11.4/§十七、阶段7 §10.5/§37/§26.4 已完成，详见各表状态列。统一验证：gateway/server 全量 go build 通过；middleware、aitools、guardjanitor、runtimehealth、systemalerts、analytics、accesscontrolevents、clientip、jiuzhang_guard 包测试全绿；web typecheck 与改动文件 eslint 无告警。遗留挂接项：FD_USAGE_HIGH 的 evaluator.go DEGRADED→告警分支未接（app.go/evaluator 当时不在改动范围）。
- **2026-09-10 第二波（6 项并行）**：阶段5 §6.5 日志字段（迁移 000144）/§二十一 CC 分步向导、阶段6 §11.5 维护窗口（迁移 000142）+ FD_USAGE_HIGH evaluator 挂接/§十六 漏洞扫描检查项/§二十六 路径口径对齐、阶段7 §11.4 自动续写/§34.1 评估集种子（迁移 000143）已完成，详见各表状态列。收口修复：aiorchestrator 测试 Provider 补 AllowedTargets（适配他人新增的出站 SSRF 策略）、stage6.test.ts 告警类型断言同步 19 类。统一验证：gateway/server 全量 go build 通过；systemalerts、aiorchestrator、aihandlers、delivery、accesslogs、accesscontrolevents、jiuzhang_guard（含 events/clientip）测试全绿；web vitest 872/872。
- **2026-09-10 第三波（6 项并行 + 1 项续接）**：阶段5 §十一 事件→黑名单全链路（含实库集成测试）、阶段6 §7.3 来源维度统计（保护地址命中统计待网关事件）、阶段7 §12.1/§15.2/15.3/§19（3/8 场景）/§36 E2E 补齐、阶段8 §33 规范导入五格式/§16/§17 微模型统计服务端层（迁移 000145）/§62 E2E 补齐已完成，详见各表状态列。收口：OpenAPI merge.py 全量重生成 + 对账 640/640 双向零差；agent-28 曾因 macOS 权限中断后恢复续接完成。统一验证：gateway/server 全量 build 通过；accessrules、aihandlers、apisecurity、apimodels、analytics 等包测试全绿；web vitest 891/891。
- **2026-09-11 第四波（8 项并行）**：M-13 首刷节流事件+fail-closed 拒绝加载、JWT/BOT 事件三字段、阶段5 §七 保护地址自动维护（启动即刷+周期调度）、阶段7 §24.4 对抗测试发布双门（迁移 000146）、§30 五条 AI 详情路由、阶段8 §16/§17 观测上报挂接（apievents 扩展+paramobs 合并写入）、§61 安全测试矩阵（SEC-01~36 共 45 断言+对账 md）、实库验证波（迁移 000141-000145 实库 up/down 往返通过；AI retention 与维护窗口实库冒烟通过；发现规范导入 42P10 缺陷与 3 处测试期望矛盾）、文档同步波（DEVELOPMENT_STATUS/REAL_CLIENT_IP_DESIGN/MONITORING_ALERTING_DESIGN/DELIVERY_ACCEPTANCE_GUIDE/REMEDIATION_PLAN 头部已对齐）。
- **2026-09-11 第五波（5 项并行+1 续接）**：修复 42P10（spec_version.go + 测试种子 + 演示脚本共 3 处，4 个 stage8 规范导入用例实库通过）；TestStage6SystemAlertsExport 按 000100 角色收敛改语义（AUDIT_ADMIN 403 + SYSTEM/SECURITY_ADMIN 200 正向）；stage7 测试与 000139 出站 SSRF 对齐（allowed_targets+canonical_origin，15/15 实库通过）；TestStage7PromptManagement 适配 000146 双门；Prompt 管理页对抗测试前端（三态/明细/发布门错误展示）；§8.1 DRAFT 状态机启用（含实库集成）；顺带修复 TestS5BlacklistFromEvent 的 AUDITOR 角色种子不存在问题。OpenAPI merge 重生成对账 646/646 双向零差。
- **2026-09-11 第六波（9 项并行）**：阶段5 §十七 发布后流量冒烟（publisher_smoke 三探针+FAIL 回滚+SKIPPED 降级如实记录+版本列与前端"流量验证"列，实库通过）；§5.1 自定义 429/阻断页面（迁移 000151、blockresponse.go 白名单净化、默认逐字节不变锁定、系统设置页签，实库通过）；阶段8 §9 协议 13 值词表+§8.2 四级识别标签（classifier，落 ctx 扩展，事件落库列待迁移）；§22/§23 关系扩至 8 类（relationvalue.go+迁移 000147，实库通过）；§34 动作 43 词表+业务域 16 映射（apiassets/classify.go+迁移 000148，实库通过）；§35 凭据异常补跨应用/多设备/位置/HMAC（credanomaly.go，待 pipeline 挂接）；§7 device_fingerprint/object_identifiers 全链路（迁移 000150）；§36 限流扩小时/日/对象/分页批量维度（quota.go 19 单测，待装配下发）；§54 指标 15→21（metrics 包+parser 埋点）。统一验证：gateway/dynamic_security/jiuzhang_guard/server 全量 build+单测绿；web tsc 无告警；OpenAPI 对账 646/646 双向零差；迁移 000147/000148/000150/000151 独立库 up/down/重 up 往返通过。
- **2026-09-11 第七波（pipeline 装配专项，3 代理 + 主代理收口）**：§35 credanomaly 三检测器挂接 pipeline + guard 侧 ApplicationID 填充（跨应用检测生效）；§36 quota 五检测器挂接（配置未到=不启用，区分性负例锁定）；§54 检测耗时/响应解析耗时 Track 落 pipeline 双相位 + 事件积压 gauge 挂接 apievents.Logger 三点；§7 ctx 标识字段 pipeline 检测段前落位（对象限速直接消费）；§8.2/§9 事件闭环：apievents 新增 `api_level` 上报（api_confidence 保持既有 0..1 契约未改）+ 迁移 000149（api_runtime_events.api_level 词表 CHECK + findings 冗余 device_fingerprint/object_identifiers）+ 服务端解析/校验/读回/OpenAPI 全链路实库通过；§7 两列 OpenAPI schema 补登。收口修复：TestStage8CrossBorderSweepOnce 趋势断言 UTC 零点边界 flake 修为日期感知断言。统一验证：gateway/dynamic_security/jiuzhang_guard/server 全量 build+测试绿；OpenAPI 对账 646/646；实库全量 stage5-8 套件两次全绿（修复后）。
- **2026-09-11 第八波（4 项并行 + 主代理收口）**：§44 流程偏离检测首批四类落地（detectors/flow.go 会话追踪器+四规则全 OBSERVE+有界可插拔存储+三类如实降级）；§36 下发面打通（gateway_runtime 组五键+迁移 000152+发布校验/版本戳/回滚重放+网关装配接线测试）；§7.2 响应采样比例引擎层（ResponseSampleRatio，8 单测）；§十五 NAT 检查（temporaryblocks/natguard.go 降档缩短+Valkey 同步+CC_TEMP_BLOCK_DOWNGRADED 审计+迁移 000153，7 单测+3 实库集成）。收口：pipeline.go/quota.go 两处"下发面无字段"过时注释已刷新；OpenAPI merge 对账 646/646；迁移 000152/000153 up/down/重 up 往返通过。统一验证：gateway/dynamic_security/jiuzhang_guard/server 受影响包测试全绿。
- **2026-09-11 第九波（3 项并行）**：§44 七类规则齐（+rapid_batch/post_cancel/anonymous_late_entry，去重与降级口径注释如实）+ 下发面全链路（迁移 000155 两表+api_flow.read/manage 权限点+CRUD 乐观锁审计+发布载荷版本戳+WDSP 门控 strip+网关校验归组填充，实库 E2E 通过）；§22/§23 第 9 类 NOT_EQUALS（迁移 000154 词表 10 值，实库 5 用例通过），其余 4 类逐项论证降级（parser 数组留存超范围/归 AUTHZ-BOLA 线）。统一验证：gateway/server 受影响包全绿；OpenAPI 对账 651/651（新增 5 条 flow-baselines 路由）；迁移 000154/000155 独立库 up/down/重 up 往返通过；web 侧无关系类型枚举需同步（grep 零命中）。
- **2026-09-11 第十波（4 项并行 + 主代理收口；期间 macOS TCC 权限中断一次，恢复后重派成功）**：§44 前端流程基线页（/api-flow-baselines 步骤编辑器+409 冲突提示+权限显隐，32 例 vitest）；§19 What-If 8/8 场景（aihandlers 新增 5 场景真实聚合估算+聊天路径分支+OpenAPI 08 枚举，8 测试函数）；§35 吊销凭据数据源（迁移 000156+CRUD+发布下发+实库集成）；§十七 CC 精确探针（网关 /_wdsp/debug/v1/cc-counter 回显端点内网门禁+ratelimit.Peek 只读访问器+publisher_smoke 第四探针 CC_EXACT）。主代理收口：apiflows/apirevokedcreds SetPublishFunc 热发布钩子+app.go 接线（含 SetRevokedCredentialLister 与路由注册）；debug_cc_counter 开关全链（迁移 000157 缺省 true+settings 白名单+guardconfig 解析+loader 清单）。统一验证：server/gateway 受影响包全绿；OpenAPI 对账 656/656；迁移 000156/000157 up/down 往返通过；实库全量 stage5-8 套件 166 用例两轮全绿（首轮与 vitest 全量并发高负载下 FAIL 一次未留名，疑似负载 flake，连续两轮复跑全绿留观察）；web vitest 全量 121 文件 916 例全绿。
- **2026-09-11 第十一波（6 项并行 + 主代理收口）**：§35 吊销凭据网关消费闭环（credrevoked.go O(1) 比对+过期跳过+证据不落明文+module.go 校验装配+端到端管线命中）；§44 server 契约缺口闭合（迁移 000158 五列+CHECK，管理面校验严于网关恒兼容）+ 前端三字段编辑（零值省略口径，18 例 vitest）；§19 前端 8 场景入口（whatIf.ts 15 例）；§55 大规模首次实测（10 万端点/120 万参数/70 万边：构建 P50 8.54s、产物 148MB/gzip 1.56MB、图谱 P95 最高 1.66s，阈值待产品定义，报告 test/performance/w23-largescale-scale-result.md）；§22/23 第 10/11 类 COUNT_MATCHES/SUM_MATCHES（parser 数组长度+有界聚合留存，迁移 000159 词表 12 值，实库 5 用例）。主代理收口：api_revoked_credentials 入 backups/tables.go 备份配置组。统一验证：gateway/server 受影响包全绿；OpenAPI 对账 656/656；迁移 000158/000159 up/down 往返通过。
- 待下一波：§55 剩余两项（学习任务并发、版本对比性能）+ 阈值定义后回填达标结论；§19 add_exception 的 application_id/uri 收敛参数（可选小项）；§23 完整 RAG（**用户明确暂缓**）与 §19 全矩阵回放引擎（设计级）；§22/23 剩余 2 类（父子对象/租户所有者，归 AUTHZ/BOLA 线，需该线深化后承接）；测试侧：§61/§36/§62 需真实环境首次实跑；DEVELOPMENT_STATUS 等文档待文档波同步。

## 无法从代码静态判定项（需运行环境/人工验收）

- 阶段5 §22 性能目标当前是否仍达标（结果文件为 2026-07-21 历史记录）
- 阶段6 退出条件 21/22"全新环境真实恢复"、§23 故障恢复实测、交付检查 WARNING/FAIL 是否已在交付环境消除
- 阶段7 §35.9 100 并发性能数字归档、真实模型（ollama qwen2.5:3b）连通验收
- 阶段8 §65 #80–84 测试"当前全绿"（103 个 TestStage8* 未实跑）、#86 安全测试无高危、#87 文档与实际一致（需 90 条全量对账）
- AUTHZ-01 系列正式环境验收（跨进程发布、故障矩阵、正式性能）
- 各测试报告均为历史快照，"当前是否通过"一律需重跑对应 make stageN-test-* 目标验证
