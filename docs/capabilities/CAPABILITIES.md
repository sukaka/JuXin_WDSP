# WDSP 版本能力清单（自动生成）

> 本文件由 `tools/capability_evidence.py render` 自动生成，禁止手工修改状态。
> 重新生成：`python3 tools/capability_evidence.py render --catalog capabilities.json --manifest <manifest> --output CAPABILITIES.md`

- 构建：dev-final-merged-20260909
- 产品版本：1.1.2
- 源码提交：3f6f6f83d992dfd5f6ed2595b03b179d6fe60ef6（dirty=否）
- 报告日期：2026-09-09
- 发布状态：DEVELOPMENT
- 说明：本报告不构成发布验收通过证明；无证据能力一律显示未验证，不展示通过徽标。

## 能力总览

| 能力 | 产品线 | 实现状态 | 接线状态 | 验证状态 |
|---|---|---|---|---|
| WAF/CRS 攻击检测（`waf-crs-detection`） | WAF/WDSP | IMPLEMENTED | CONNECTED | PASS |
| 真实客户端 IP 识别（`real-client-ip`） | WAF/WDSP/API | IMPLEMENTED | CONNECTED | PASS |
| 访问控制与 CC 频率限制（`access-control-cc`） | WAF/WDSP/API | IMPLEMENTED | CONNECTED | PASS |
| API 资产与模型（`api-assets-models`） | WDSP/API | IMPLEMENTED | CONNECTED | BLOCKED |
| API 请求/响应检测（`api-request-response-detection`） | WDSP/API | IMPLEMENTED | CONNECTED | PASS |
| 身份解析与行为观测（`identity-behavior-observation`） | WAF/WDSP/API | IMPLEMENTED | CONNECTED | PASS |
| 业务 JWT 验证（信任链）（`jwt-verification`） | WDSP/API | IMPLEMENTED | CONNECTED | BLOCKED |
| API 统一最终决策（`api-unified-decision`） | WDSP/API | IMPLEMENTED | CONNECTED | PASS |
| 整条请求处置解释（`request-final-disposition`） | WAF/WDSP/API | IMPLEMENTED | CONNECTED | PASS |
| WAF/API 例外（`waf-exceptions`） | WAF/WDSP/API | IMPLEMENTED | CONNECTED | PASS |
| 事件链路（采集→入库→关联）（`event-chain`） | WAF/WDSP/API | IMPLEMENTED | CONNECTED | BLOCKED |
| 配置发布与双节点 HA（`config-release-ha`） | WAF/WDSP/API | IMPLEMENTED | CONNECTED | BLOCKED |
| APM 入口性能（网关侧）（`apm-entry-performance`） | WDSP | IMPLEMENTED | CONNECTED | PASS |
| APM Trace/SQL/异常（代码级观测）（`apm-trace-sql-exception`） | WDSP | PARTIAL | PARTIAL | BLOCKED |
| Agent 流量采集与转发（`agent-collection-forwarding`） | WDSP/API | PARTIAL | PARTIAL | BLOCKED |

## 分场景明细

### WAF/CRS 攻击检测（`waf-crs-detection`）

- 实现模块：jiuzhang_guard
- 部署模式：REVERSE_PROXY
- 验证状态（强制场景最差结果）：PASS
- 实现引用：
  - `gateway/modules/jiuzhang_guard/module.go`（ServeHTTP）
  - `gateway/rules/coraza.conf`
  - `gateway/rules/crs`
- 场景：
  - `single-reverse-proxy`（单节点反向代理，强制）：PASS
    - BENCH-05：PASS
    - DEC-01：PASS
    - EXC-03：PASS
- 前提：
  - 有效授权
  - CRS 规则集随构建锁定版本
- 限制（如实保留）：
  - CRS 规则文件存在仅证明配置材料可用，不证明拦截率/误报率达标
  - 本轮尚未在隔离环境完成误报/漏报实测（依赖 P0-02 BENCH 系列）
- 证据引用：BENCH-05, DEC-01, EXC-03

### 真实客户端 IP 识别（`real-client-ip`）

- 实现模块：jiuzhang_guard
- 部署模式：REVERSE_PROXY
- 验证状态（强制场景最差结果）：PASS
- 实现引用：
  - `gateway/modules/jiuzhang_guard/clientip`
  - `gateway/modules/jiuzhang_guard/trustedproxy`
- 场景：
  - `single-reverse-proxy`（单节点反向代理，强制）：PASS
    - DEC-03：PASS
    - EXC-08：PASS
- 前提：
  - 可信代理列表按部署真实配置
- 限制（如实保留）：
  - 伪造 XFF 的识别依赖可信代理配置正确，未配置时退化为直连地址
- 证据引用：DEC-03, EXC-08

### 访问控制与 CC 频率限制（`access-control-cc`）

- 实现模块：jiuzhang_guard
- 部署模式：REVERSE_PROXY
- 验证状态（强制场景最差结果）：PASS
- 实现引用：
  - `gateway/modules/jiuzhang_guard/accesscontrol`
  - `gateway/modules/jiuzhang_guard/l7rules`
  - `gateway/modules/jiuzhang_guard/temporaryblock`
  - `gateway/modules/jiuzhang_guard/ratelimit`
- 场景：
  - `single-reverse-proxy`（单节点反向代理，强制）：PASS
    - 说明：请求顺序契约：人工临时封禁先于白名单；白名单与 L7 allow 不绕过 WAF 与 API 动态防护。
    - DEC-03：PASS
    - BENCH-05：PASS
- 前提：
  - 黑白名单、L7 规则、CC 策略已发布有效版本
- 限制（如实保留）：
  - 多节点一致性依赖配置发布回执，未单独实测（见 config-release-ha）
- 证据引用：DEC-03, BENCH-05

### API 资产与模型（`api-assets-models`）

- 实现模块：server/apiassets
- 部署模式：REVERSE_PROXY
- 验证状态（强制场景最差结果）：BLOCKED
- 实现引用：
  - `server/internal/apiassets`
  - `server/internal/apimodels`
  - `server/internal/apiruntime`
- 场景：
  - `single-reverse-proxy`（单节点反向代理，强制）：BLOCKED
    - BENCH-04：BLOCKED（ENVIRONMENT_UNAVAILABLE）
    - BENCH-05：PASS
- 前提：
  - API 动态防护管线（WDSP）按应用开启，默认关闭
- 限制（如实保留）：
  - 模型学习结果与运行时模型的绑定关系未在本轮验收覆盖
- 证据引用：BENCH-04, BENCH-05

### API 请求/响应检测（`api-request-response-detection`）

- 实现模块：dynamic_security
- 部署模式：REVERSE_PROXY
- 验证状态（强制场景最差结果）：PASS
- 实现引用：
  - `gateway/dynamic_security/pipeline`
  - `gateway/dynamic_security/detectors`
  - `gateway/dynamic_security/response`
  - `gateway/modules/jiuzhang_guard/apiprotect.go`
  - `gateway/modules/jiuzhang_guard/apiresponse.go`
- 场景：
  - `single-reverse-proxy`（单节点反向代理，强制）：PASS
    - DEC-01：PASS
    - DEC-04：PASS
    - BENCH-05：PASS
- 前提：
  - API 动态防护管线按应用开启
- 限制（如实保留）：
  - OBSERVE 命中只记录不实断，不得与真实处置混同（DEC-04 覆盖）
- 证据引用：DEC-01, DEC-04, BENCH-05

### 身份解析与行为观测（`identity-behavior-observation`）

- 实现模块：jiuzhang_guard/identitybehavior
- 部署模式：REVERSE_PROXY
- 验证状态（强制场景最差结果）：PASS
- 实现引用：
  - `gateway/modules/jiuzhang_guard/identitybehavior`
  - `gateway/modules/jiuzhang_guard/identitybehavior_module.go`
- 场景：
  - `single-reverse-proxy`（单节点反向代理（fail-open 观测），强制）：PASS
    - 说明：identity_behavior 配置缺省关闭，仅观测不拦截；JWTSubject 取自未验签声明，只作关联不作授权依据。
    - DEC-03：PASS
    - JWT-17：PASS
- 前提：
  - identity_behavior 配置开启后才观测
- 限制（如实保留）：
  - 观测模块 fail-open，任何异常不影响请求；其身份关联不能当作已验证身份
- 证据引用：DEC-03, JWT-17

### 业务 JWT 验证（信任链）（`jwt-verification`）

- 实现模块：dynamic_security/jwtverify + jiuzhang_guard/jwt_trust + server/internal/jwttrust
- 部署模式：REVERSE_PROXY
- 验证状态（强制场景最差结果）：BLOCKED
- 实现引用：
  - `gateway/dynamic_security/jwtverify/`（验签/严格解析/JWKS 缓存/SSRF 受限获取（纯本地热路径））
  - `gateway/modules/jiuzhang_guard/jwt_trust.go`（验证挂点（真实 IP 后、身份观测前）与 PROTECT 处置（401/503））
  - `gateway/modules/jiuzhang_guard/apiprotect.go`（serveNext 统一放行出口 JWT 强制处置（白名单不绕过））
  - `server/internal/jwttrust/`（策略 CRUD/预检/乐观锁/审计/静态 JWKS 校验/ListForGuard 下发契约）
  - `server/internal/guardconfig/jwt_trust.go`（配置供应链：fail-hard 加载、PROTECT 管线门禁、节点门禁）
  - `server/migrations/000125_jwt_trust_policy.up.sql`（策略表+不可变版本表+内网 IdP 允许清单种子）
  - `server/migrations/000126_jwt_trust_perms.up.sql`（jwt_trust.read/manage 权限种子）
  - `server/migrations/000127_api_runtime_events_jwt_verification.up.sql`（事件 JWT 验证摘要列）
  - `web/src/pages/applications/detail/JwtTrustTab.tsx`（JWT 信任策略页签（草稿/预检/状态/私钥拒收））
- 场景：
  - `single-reverse-proxy`（单节点反向代理，强制）：BLOCKED
    - JWT-01：PASS
    - JWT-02：PASS
    - JWT-03：PASS
    - JWT-04：PASS
    - JWT-05：PASS
    - JWT-06：PASS
    - JWT-07：PASS
    - JWT-08：PASS
    - JWT-09：PASS
    - JWT-10：PASS
    - JWT-11：PASS
    - JWT-12：PASS
    - JWT-13：PASS
    - JWT-14：PASS
    - JWT-15：PASS
    - JWT-16：PASS
    - JWT-17：PASS
    - JWT-18：BLOCKED（ENVIRONMENT_UNAVAILABLE）
- 限制（如实保留）：
  - 仅 Authorization 单个 Bearer JWT；不从 URL/Cookie/正文提取
  - 仅 RS256/ES256 显式白名单；不支持 JWE/introspection/登录签发/刷新 Token
  - VERIFIED 仅证明所配置发行方签发，不等于业务对象授权（BOLA 需独立授权真值）
  - 验证通过不绕过 WAF/CC/访问控制等后续防护
  - 管理登录认证不属于本能力范围
- 证据引用：JWT-01, JWT-02, JWT-03, JWT-04, JWT-05, JWT-06, JWT-07, JWT-08, JWT-09, JWT-10, JWT-11, JWT-12, JWT-13, JWT-14, JWT-15, JWT-16, JWT-17, JWT-18

### API 统一最终决策（`api-unified-decision`）

- 实现模块：dynamic_security/decision
- 部署模式：REVERSE_PROXY
- 验证状态（强制场景最差结果）：PASS
- 实现引用：
  - `gateway/dynamic_security/decision`
  - `gateway/dynamic_security/events`
- 场景：
  - `single-reverse-proxy`（单节点反向代理，强制）：PASS
    - 说明：API 决策结果与整条请求最终处置分开保存；API ALLOW 不能覆盖后续 Coraza BLOCK。
    - DEC-01：PASS
    - DEC-04：PASS
    - DEC-05：PASS
    - EXC-10：PASS
- 前提：
  - API 动态防护管线按应用开启
- 限制（如实保留）：
  - 决策引擎 Input.Exceptions 为预留未生效（S0 已核实），例外重算依赖 P0-04
- 证据引用：DEC-01, DEC-04, DEC-05, EXC-10

### 整条请求处置解释（`request-final-disposition`）

- 实现模块：server/securityevents
- 部署模式：REVERSE_PROXY
- 验证状态（强制场景最差结果）：PASS
- 实现引用：
  - `server/internal/securityevents`（final_decision 列存取与 GetByID 详情投影（data.event.final_decision））
  - `server/internal/apiruntime`（API 运行时事件 final_decision 条件补全（已确认拦截优先、幂等合并））
  - `gateway/modules/jiuzhang_guard/disposition.go`（终止分支 RecordTerminal/Finalize、连接劫持与下游错误归因）
  - `gateway/dynamic_security/decision`（观察与实际动作分离（excepted 不定案、OBSERVE 降级））
  - `gateway/internal/eventparser`（网关事件解析上送）
  - `web/src/pages/security-events/EventDetailDrawer.tsx`（事件详情最终处置区块（final_decision 渲染））
- 场景：
  - `single-reverse-proxy`（单节点反向代理，强制）：PASS
    - DEC-01：PASS
    - DEC-02：PASS
    - DEC-03：PASS
    - DEC-04：PASS
    - DEC-05：PASS
    - DEC-06：PASS
- 前提：
  - P0-04 实施完成：final_decision 归因与事件关联
- 限制（如实保留）：
  - 非 API 且无检测明细的请求不产生安全事件，无 final_decision 可收束（设计使然）；非 API 流量事后 Coraza 阻断不回填事件（G1 语义）
  - 无法确认归因时如实标记未知/待关联，不伪报执行者
  - Coraza 合流归因与 coraza-caddy v2.5.0 未导出哨兵耦合，升级必须复核；非 deny 中断按 403 口径记录、phase 3 中断不归因（apicoraza.go 局限声明）
  - 真实 SSE/gRPC 长连接端到端未专项实测，可捕获范围以组件级分支测试为准（DEC-06）
- 证据引用：DEC-01, DEC-02, DEC-03, DEC-04, DEC-05, DEC-06

### WAF/API 例外（`waf-exceptions`）

- 实现模块：server/exceptions
- 部署模式：REVERSE_PROXY
- 验证状态（强制场景最差结果）：PASS
- 实现引用：
  - `server/internal/exceptions`（例外 CRUD/预览/启用门禁/乐观锁/发布快照（ListForPublish 全量 2000 容量））
  - `server/internal/guardconfig`（api_exceptions 配置供应链接线（SetAPIExceptionsLister））
  - `gateway/modules/jiuzhang_guard/apiexceptions.go`（网关例外求值挂点（真实 IP 后、Coraza 前））
  - `gateway/corazasemantics`（SecLang 规则编译/两规则标记法翻折/时间窗运行时求值）
  - `web/src/pages/exceptions`（例外管理页（草稿/预览/启用/派生状态））
- 场景：
  - `single-reverse-proxy`（单节点反向代理，强制）：PASS
    - EXC-01：PASS
    - EXC-02：PASS
    - EXC-03：PASS
    - EXC-04：PASS
    - EXC-05：PASS
    - EXC-06：PASS
    - EXC-07：PASS
    - EXC-08：PASS
    - EXC-09：PASS
    - EXC-10：PASS
    - EXC-11：PASS
    - EXC-12：PASS
    - EXC-13：PASS
    - EXC-14：PASS
    - EXC-15：PASS
- 前提：
  - P0-04 例外条件交集、运行时到期与发布一致性修复完成
- 限制（如实保留）：
  - 仅支持 WAF/API 引擎规则级例外；JWT/协议底线/人工封禁/CC/配额等保护模块不可例外（设计边界，EXC-11 已验证）
  - LOG_ONLY/ADJUST_SCORE 动作已停用：新启用被门禁拒绝，历史数据经迁移 000132 标 NEEDS_REVIEW（EXC-04/EXC-15）
  - 单节点反向代理栈完成验证；多节点发布扇出的部分失败处置未实测（EXC-12 注记）
  - API 侧（is_api=true 流量）例外命中证据链的端到端定时断言待冒烟素材修复后补验（与 DEC-01 同根因）；网关 decision 层单测与栈内 dump 已实证分流行为（EXC-10）
- 证据引用：EXC-01, EXC-02, EXC-03, EXC-04, EXC-05, EXC-06, EXC-07, EXC-08, EXC-09, EXC-10, EXC-11, EXC-12, EXC-13, EXC-14, EXC-15

### 事件链路（采集→入库→关联）（`event-chain`）

- 实现模块：server/securityevents
- 部署模式：REVERSE_PROXY
- 验证状态（强制场景最差结果）：BLOCKED
- 实现引用：
  - `server/internal/securityevents`
  - `server/internal/accesscontrolevents`
  - `gateway/modules/jiuzhang_guard/events`
  - `gateway/dynamic_security/events`
- 场景：
  - `single-reverse-proxy`（单节点反向代理，强制）：BLOCKED
    - BENCH-08：BLOCKED（ENVIRONMENT_UNAVAILABLE）
    - BENCH-09：BLOCKED（ENVIRONMENT_UNAVAILABLE）
    - DEC-05：PASS
- 前提：
  - 事件采集器在线；request_id/application_id/gateway_node 关联链可信
- 限制（如实保留）：
  - 积压、重启与恢复下的数据完整性未实测（依赖 P0-02 BENCH-08/09）
- 证据引用：BENCH-08, BENCH-09, DEC-05

### 配置发布与双节点 HA（`config-release-ha`）

- 实现模块：server/gatewayconfig
- 部署模式：REVERSE_PROXY
- 验证状态（强制场景最差结果）：BLOCKED
- 实现引用：
  - `server/internal/gatewayconfig`
  - `server/internal/guardconfig`
  - `server/internal/hagroups`
  - `server/internal/hastatus`
- 场景：
  - `single-node`（单节点发布与回退，强制）：PASS
    - 说明：草稿保存不等于线上生效；发布失败/部分失败/回退语义以节点回执为准。
    - EXC-12：PASS
    - JWT-14：PASS
  - `ha-two-node`（双节点 HA 扇出，强制）：BLOCKED
    - 说明：次要节点 Caddy Admin 允许 http(s) 属受控例外，限内网且发布侧强制 SSRF 校验。
    - BENCH-04：BLOCKED（ENVIRONMENT_UNAVAILABLE）
    - BENCH-09：BLOCKED（ENVIRONMENT_UNAVAILABLE）
- 前提：
  - 主节点 Caddy Admin 仅 Unix Socket；多节点发布按 docs/HA_TWO_NODE_DESIGN.md
- 限制（如实保留）：
  - 部分节点失败的展示与回退一致性未在本轮实测
- 证据引用：EXC-12, JWT-14, BENCH-04, BENCH-09

### APM 入口性能（网关侧）（`apm-entry-performance`）

- 实现模块：server/apm
- 部署模式：REVERSE_PROXY
- 验证状态（强制场景最差结果）：PASS
- 实现引用：
  - `server/internal/apm/handler.go`
  - `server/internal/app/app.go`（APM 服务接线（PG+ClickHouse 双源，恒注册路由+热生效总开关））
  - `gateway/modules/jiuzhang_guard/trace.go`
- 场景：
  - `gateway-entry`（网关入口性能观测，强制）：PASS
    - 说明：入口性能不等于代码级观测；本场景仅覆盖网关侧入口延迟与状态分布。
    - BENCH-05：PASS
    - BENCH-06：PASS
- 前提：
  - ClickHouse 数据面可用；APM 总开关开启
- 限制（如实保留）：
  - 入口性能≠代码级观测：无探针时不能展示 Trace/SQL/异常（见 apm-trace-sql-exception）
  - 页面存在不代表数据面已接入
- 证据引用：BENCH-05, BENCH-06

### APM Trace/SQL/异常（代码级观测）（`apm-trace-sql-exception`）

- 实现模块：server/apm
- 部署模式：APM_PROBE
- 验证状态（强制场景最差结果）：BLOCKED
- 实现引用：
  - `server/internal/apm/handler.go`
  - `server/internal/apm/agentapi_handler.go`
  - `server/internal/apm/chstore.go`
- 场景：
  - `apm-probe-data-plane`（探针+数据面接入，强制）：BLOCKED
    - 说明：Trace、SQL、异常能力取决于对应采集是否部署；无探针/无数据面时本场景应标注未验证，不得由入口性能推导为通过。
    - BENCH-08：BLOCKED（ENVIRONMENT_UNAVAILABLE）
- 前提：
  - 业务应用接入 APM 探针/Agent
  - ClickHouse 数据面按 docs/APM_DATA_PLANE_DEPLOYMENT.md 部署
- 限制（如实保留）：
  - 代码级观测范围以实际采集协议为准；本轮未完成探针侧端到端实测
- 证据引用：BENCH-08

### Agent 流量采集与转发（`agent-collection-forwarding`）

- 实现模块：wdsp-agent
- 部署模式：AGENT, MIRROR
- 验证状态（强制场景最差结果）：BLOCKED
- 实现引用：
  - `wdsp-agent/cmd/agent`
  - `wdsp-agent/internal/capture`
  - `wdsp-agent/internal/transport`
  - `wdsp-agent/internal/buffer`
- 场景：
  - `agent-capture-forward`（Agent 采集与转发（当前实现范围），强制）：BLOCKED
    - 说明：仅声明当前实际采集/转发范围；未实现阶段见 docs/agents/WDSP_AGENT_REMAINING_WORK.md，单独标明，不得由 Caddy 网关同类协议支持反推 Agent 也支持。
    - BENCH-08：BLOCKED（ENVIRONMENT_UNAVAILABLE）
    - BENCH-09：BLOCKED（ENVIRONMENT_UNAVAILABLE）
    - BENCH-10：BLOCKED（ENVIRONMENT_UNAVAILABLE）
- 前提：
  - Agent 部署目标具备采集权限（镜像流量/网卡/eBPF 按实际模式）
- 限制（如实保留）：
  - 未实现阶段（见 docs/agents/WDSP_AGENT_REMAINING_WORK.md）不构成本能力承诺范围
  - Agent 模式未实测前，不得宣称与反向代理模式等价能力
- 证据引用：BENCH-08, BENCH-09, BENCH-10
