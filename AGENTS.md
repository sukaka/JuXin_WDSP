# AGENTS.md — 九章WEB应用智能防护系统V2.0

## 项目定位

九章WEB应用智能防护系统V2.0是一套自主研发的反向代理型Web应用防火墙（WAF）管理系统，基于 Caddy + Coraza WAF + OWASP CRS 构建底层防护能力，管理面与网关控制面完全自主开发。

## 开发原则

1. **独立开发**：不复制任何现有WAF产品的源代码、界面、接口、数据库结构或文案。
2. **宽松许可证**：第三方组件优先选择 Apache-2.0 / MIT / BSD；未经书面批准不得引入 GPL / AGPL 组件。
3. **版本锁定**：所有依赖、Docker 镜像必须明确锁定版本，禁止使用 `latest` 标签；多架构交付时第三方镜像须按架构分别锁定 digest（获取方式见 docs/DEPENDENCIES.md）。
4. **一次一阶段**：一次只完成一个阶段或一个明确模块，不得跳跃式开发。
5. **先读后改**：修改代码前必须先读取本文档、相关设计文档和现有代码。
6. **测试先行**：所有功能必须附带单元测试；接口功能必须附带接口测试；关键流程必须附带 E2E 测试。
7. **安全底线**：不得为了通过测试而删除权限校验、参数校验、CSRF 防护或日志脱敏。

## 技术路线

| 层级 | 技术 |
|------|------|
| 管理前端 | React 18 + TypeScript + Vite + Ant Design 5 + ECharts + TanStack Query + Zustand |
| 管理后端 | Go 1.24+、PostgreSQL 16+、Valkey 8+、RESTful API、OpenAPI 3 |
| 防护网关 | Caddy 2.11.x、Coraza WAF 3.7.x、coraza-caddy 2.5.x、OWASP CRS 4.26.x |
| 自主网关扩展 | jiuzhang_guard Caddy Module |
| 部署 | Docker Compose |
| 测试 | Go Test、Vitest、Playwright、go-ftw |

## 请求处理顺序（网关）

接收请求 → 生成 Request ID → 真实客户端 IP 识别（可信代理判断、伪造检测）→ JWT 信任链验证（WDSP，`jwt_trust` 配置缺省=关闭；真实 IP 改写后纯本地验证、热路径零网络 IO，结果入请求上下文）→ 身份解析与行为观测（Identity + Behavior，可选，`identity_behavior` 配置缺省=关闭，仅观测不拦截；消费 JWT VERIFIED 可信主体信号但不改 identity_key/identity_type 语义）→ 保护地址 → 人工临时封禁 → IP 白名单 → IP 黑名单 → L7 访问控制（首中即停）→ 自动临时封禁 → 身份风险策略处置（Risk Engine，`risk_policy` 配置缺省=关闭，OBSERVE 只记录不实断，PROTECT 达阈 403/429）→ 授权配额全局限速（可选，默认关闭）→ CC 频率限制 → Bot 挑战判定（WDSP P1-02，`bot_policy` 配置缺省=OFF；OBSERVE 只记录不实断，PROTECT 对合格的 HTTPS GET 浏览器文档导航签发 JS 挑战；保护地址/白名单/L7 allow 不跳过 Bot；保留命名空间 `/_wdsp/bot/v1/` 在本步骤最前置本地处理，verify 固定协议端点与 OFF 墓碑 404/405 均不反向代理）→ API 动态防护管线（WDSP，可选，默认关闭；入口处执行 JWT 强制处置：PROTECT 下 INVALID/缺必需 Bearer → 401 带规范 Bearer challenge，UNAVAILABLE → 503 不伪装 Token 错误，白名单/L7 allow 不绕过）→ 请求大小及协议检查 → Coraza/CRS 攻击检测 → 反向代理到源站 → 返回响应 → 记录访问日志和安全事件

以上为 `jiuzhang_guard` 模块真实实现顺序（gateway/modules/jiuzhang_guard/module.go `ServeHTTP`）：JWT 信任链由 `gateway/modules/jiuzhang_guard/jwt_trust.go` 挂接（验证点在真实 IP 改写后、身份观测前；强制处置点在 apiprotect.go `serveNext` 统一放行出口，事件落 access_control_events 与 api_runtime_events）；身份解析与行为观测由 `gateway/modules/jiuzhang_guard/identitybehavior/` 在真实 IP 改写后挂接（包装 ResponseWriter 采集状态码，fail-open，任何异常不影响请求；JWT 验证/执行不经过观测的 fail-open 分支）；Bot 挑战判定由 `gateway/modules/jiuzhang_guard/bot_step.go` 挂接（四个放行出口统一经 `serveNextViaBot`：保护地址/白名单/L7 allow 直达分支与常规 CC 后路径；挑战服务在 `botchallenge/`，信号评估只读消费身份行为窗口计数 `identitybehavior.PeekSnapshot`，不记账）；人工临时封禁优先于白名单；白名单与 L7 allow 命中跳过黑名单、自动封禁与 CC，但不绕过 WAF、API 动态防护、Bot 挑战与 JWT PROTECT（安全底线）。

Caddy 中间件顺序必须经过集成测试验证，不得凭经验随意调整。

## 禁止事项

- 不得复制、Fork、反编译雷池或其他 WAF 产品；
- 不得复刻雷池页面布局、接口路径、数据库表结构或文案；
- 不得使用 `latest` Docker 镜像标签；
- 不得将 Caddy Admin API 暴露到 TCP 端口，主节点必须使用 Unix Socket；受控例外：多节点发布扇出的次要节点允许配置 http(s) 管理地址，仅限内网地址且发布侧强制 SSRF 校验（内网地址校验 + 拨号时 DNS 重解析复检防重绑定），生产环境应使用 https（设计依据：docs/HA_TWO_NODE_DESIGN.md）；
- 不得把私钥、密码、Token 提交到 Git；
- 不得在生产代码中保留默认密码；
- 不得用 Mock 数据或占位接口冒充功能完成；
- 不得跳过数据库迁移、权限校验、参数校验、操作审计和测试；
- 不得静默吞掉错误。

## 阶段划分

- 阶段0：项目初始化（阶段1-6 已全部完成，详见 docs/DEVELOPMENT_STATUS.md）
- 阶段1：网关技术验证
- 阶段2：用户权限和系统基础
- 阶段3：应用接入和配置发布
- 阶段4：WAF策略和事件中心
- 阶段5：访问控制和CC防护
- 阶段6：首页和安全报表
- 阶段7：质量和交付
- 阶段8：统一 Web 与 API 动态防护（WDSP，`develop` 分支；分支策略见 docs/BRANCHING_AND_PRODUCT_LINES.md，状态见 docs/DEVELOPMENT_STATUS.md 阶段8 小节）

## 文档索引

- [产品需求](docs/PRODUCT_REQUIREMENTS.md)
- [架构设计](docs/ARCHITECTURE.md)
- [数据库设计](docs/DATABASE_DESIGN.md)
- [接口设计](docs/API_DESIGN.md)
- [安全设计](docs/SECURITY_DESIGN.md)
- [离线授权设计](docs/LICENSE_DESIGN.md)
- [部署文档](docs/DEPLOYMENT.md)
- [测试计划](docs/TEST_PLAN.md)
- [开源合规](docs/OPEN_SOURCE_COMPLIANCE.md)
- [开发状态](docs/DEVELOPMENT_STATUS.md)
- [产品线与分支策略（WAF/WDSP/API）](docs/BRANCHING_AND_PRODUCT_LINES.md)
- [阶段8/WDSP 开工说明](docs/tasks/STAGE_8_WDSP_KICKOFF.md)
- [阶段8 任务书](docs/tasks/STAGE_8_UNIFIED_WEB_API_DYNAMIC_PROTECTION.md)
- [阶段4–8 任务书未完成项审计清单](docs/tasks/STAGE_4_8_PENDING_ITEMS.md)
- [三微模型统一维度框架](docs/API_MICRO_MODELS.md)
- [API 安全能力现状盘点](docs/API_SECURITY_CURRENT_STATE.md)
- [API 统一 Finding 与统一决策设计](docs/API_UNIFIED_FINDING_DECISION.md)
- [API 准入防护设计（已确认 API 白名单放行）](docs/API_ADMISSION_CONTROL_DESIGN.md)
- [WAF 规则 CNNVD 兼容性设计](docs/CNNVD_COMPATIBILITY_DESIGN.md)
- [API 运行时模型编译器设计](docs/API_RUNTIME_COMPILER.md)
- [API 响应侧安全设计](docs/API_RESPONSE_SECURITY.md)
- [API 身份与授权安全设计](docs/API_IDENTITY_AUTHORIZATION.md)
- [BOLA/BFLA 与多租户授权防护开发设计](docs/API_BOLA_BFLA_MULTI_TENANT_AUTHORIZATION_DESIGN.md)
- [AUTHZ-01 对象授权关系确认与 BOLA/BFLA 网关 OBSERVE 决策任务书](docs/tasks/AUTHZ_BOLA_BFLA_OBSERVE_DECISION.md)
- [API 风险与弱点设计](docs/API_RISK_WEAKNESS.md)
- [API 审计与溯源设计](docs/API_AUDIT_TRACE.md)
- [API 行为检测分布式状态设计](docs/API_BEHAVIOR_DISTRIBUTED_STATE.md)
- [API 主动扫描设计](docs/API_ACTIVE_SCANNING.md)
- [API AI 自动运营设计](docs/API_AI_OPERATIONS.md)
- [多网口管理与多模式部署设计](docs/NETWORK_MODES_DESIGN.md)
- [网络诊断工具与网络设置设计](docs/NETWORK_TOOLS_DESIGN.md)
- [CVE 漏洞库与外部利用情报接入设计](docs/VULN_INTEL_DESIGN.md)
- [站点资产自动发现设计](docs/SITE_DISCOVERY_DESIGN.md)
- [生产裸机网关部署设计](docs/BARE_METAL_GATEWAY_DESIGN.md)
- [主备高可用设计（VIP 漂移 + 网桥端口联动 + 会话保持）](docs/HA_ACTIVE_STANDBY_DESIGN.md)
- [双节点高可用与数据同步方案](docs/HA_TWO_NODE_DESIGN.md)
- [主备高可用部署与运维手册](docs/HA_OPERATIONS_GUIDE.md)
- [裸机网关性能调优指南](docs/BARE_METAL_PERFORMANCE_TUNING.md)
- [HTTP/3 支持现状与启用方式](docs/HTTP3_SUPPORT.md)
- [业务性能监控与代码级 APM 设计](docs/BUSINESS_PERFORMANCE_APM_DESIGN.md)
- [APM 阶段0 ADR 与阶段1实施基线](docs/APM_STAGE0_ADR.md)
- [APM 阶段2 数据面部署手册](docs/APM_DATA_PLANE_DEPLOYMENT.md)
- [APM 运维手册](docs/APM_OPERATIONS_GUIDE.md)
- [APM 排障手册](docs/APM_TROUBLESHOOTING.md)
- [APM 客户接入指南](docs/APM_ONBOARDING_GUIDE.md)
- [独立测试环境自动化回归与报告方案](docs/INDEPENDENT_REGRESSION_TEST_AUTOMATION_DESIGN.md)
- [AI 自动化渗透防护增强实施文档（WDSP）](docs/WDSP_AI_PENTEST_PROTECTION_ENHANCEMENT.md)
- [WDSP Top 20 差异化能力（区别于普通 WAF）](docs/WDSP_TOP20_VS_WAF.md)
- [分布式 Agent 流量采集与转发系统详细设计](docs/agents/WDSP_DISTRIBUTED_AGENT_DESIGN.md)
- [分布式 Agent Phase 1 实施契约（server/agent/web 三方冻结）](docs/agents/WDSP_AGENT_PHASE1_CONTRACT.md)
- [分布式 Agent Phase 2-5 实施契约](docs/agents/WDSP_AGENT_PHASE2_CONTRACT.md)（同目录 PHASE3/PHASE4/PHASE5）
- [分布式 Agent 剩余工作交接文档](docs/agents/WDSP_AGENT_REMAINING_WORK.md)
- [Bot 挑战配置与运维手册（P1-02）](docs/BOT_CHALLENGE_OPERATIONS.md)
- [Bot 挑战强制验收矩阵 BOT-001~024](docs/WDSP_BOT_CHALLENGE_ACCEPTANCE_MATRIX.md)

## Codex 调用 Kimi CLI 的前端协作约束

1. Codex 是唯一编排者，负责拆解任务、确定基线、审查差异、执行验收以及提交和推送。
2. Kimi 必须在独立 Git worktree 中工作，默认只允许修改 `web/`；任务书不得扩大到后端、网关、部署或发布文件。
3. Kimi 不得执行 `git commit`、`git push`、合并、变基、打标签或修改 Git 历史。
4. Kimi 不得读取、输出或写入凭据、Token、私钥、`.env` 等敏感信息，也不得新增遥测或未授权网络调用。
5. 每次调用必须使用 `.agent/tasks/active/` 下的明确任务书，并通过 `tools/kimi-frontend.sh` 建立可审计运行记录。
6. Kimi 返回后必须先通过隔离工作树、其他工作树和共享 Git refs 的范围检查；Codex 再独立运行任务书中的 typecheck、lint、test、build 或 E2E 验收。
7. Kimi 的自述不作为完成证据；最终以 Git 差异、范围检查和 Codex 重跑结果为准。

详细流程与模板见 [`.agent/README.md`](.agent/README.md)。

## 版本号与推送规则

- 版本号格式：`主版本.新功能.bug修复`（如 `1.0.0`），tag 沿用现有 `wdsp-vX.Y.Z` 前缀风格。
- 递增规则：bug 修复 → 第三位 +1；新功能 → 第二位 +1、第三位归零；主版本递增由用户明确指示。
- 用户说「推送」时：先按本次改动类型确定新版本号，更新 CHANGELOG.md（从 Unreleased 归入新版本节），打 tag `wdsp-vX.Y.Z`，再 `git push origin` 分支与 tag。
- 当前基线：`1.0.0`（WDSP 产品线自 1.0.0 起重新编号；仓库内历史 tag `wdsp-v2.5.x` 为旧基线，不再延续）。

## 版权

Copyright © 聚信得仁
All Rights Reserved.
