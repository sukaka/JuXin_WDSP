# APM 客户接入指南

> 适用：九章 WAF / WDSP 业务性能监控（APM）能力的客户侧接入——无 Agent 模式开箱即用
> 与各语言 Agent 模式接入。
> 读者：客户侧应用 owner、SRE 与交付工程师。
> 依据：docs/BUSINESS_PERFORMANCE_APM_DESIGN.md（双模式定义与安全边界）、
> docs/APM_STAGE0_ADR.md（W3C 信任策略）、docs/APM_DATA_PLANE_DEPLOYMENT.md（数据面）。
> 遥测协议以 OpenTelemetry 官方零代码插桩为准（https://opentelemetry.io/docs/zero-code/）；
> 运维与排障分别见 docs/APM_OPERATIONS_GUIDE.md、docs/APM_TROUBLESHOOTING.md。

---

## 1. 两种模式怎么选

| | 无 Agent 模式（默认） | Agent 基线模式 | Agent 深度诊断 |
|---|---|---|---|
| 业务改造 | 无 | 加载 Agent/SDK，无代码修改 | 同左，按需临时开启 |
| 能看到 | 请求量、状态码、端到端耗时、端点 P95/P99、WAF 处置影响、上下游可用性 | 加：完整分布式调用链、SQL 指纹与慢查询、异常聚类、依赖拓扑、运行时指标（GC/线程/连接池等） | 加：SQL 细节、定向函数探针、线程/协程阻塞等（限时、限范围、自动回收） |
| 何时用 | 所有应用默认开启 | 需要回答"为什么慢"的服务 | 确认需要代码级证据时，默认 15 分钟、最长 2 小时 |

原则：**先无 Agent 后 Agent，先基线后诊断**。链路中有服务未部署 Agent 时，页面如实
显示"部分链路"，不会伪装成完整 trace。

## 2. 无 Agent 模式开箱即用

无需在业务应用安装任何组件。开通条件（由平台管理员操作）：

1. **APM 总开关**：推荐在「系统设置 → APM 性能监控」界面开启（SYSTEM_ADMIN，保存后立即
   生效、无需重启，并可同页配置 ClickHouse 连接串）；无界面配置时以管理后端环境变量
   `APM_ENABLED=true` 兜底（改 env 需重启）。默认关闭；关闭时 APM 接口整体 503 降级、
   菜单隐藏，不影响 WAF 与既有功能；
2. **应用级指标（常开）**：开通后即可在「业务性能 → 性能总览 / 服务性能」看到请求量、
   5xx/4xx、WAF 阻断量、错误率、P50/P95/P99 与趋势——数据源为网关 Caddy 访问日志聚合；
3. **端点级指标（需开启全量访问日志）**：「系统设置」logging 组
   `logging.access_log_enabled=true`（默认关）。开启后网关全量访问日志（含人工封禁/
   IP 黑白名单/L7/CC 等前置拦截的 403/429）进入 `access_logs` 并产生端点级分钟聚合，
   「端点性能」与慢端点榜才有数据。容量参考：1000 req/s 约 8640 万行/天，沿用
   `logging.retention_days`（默认 7 天）自动清理，开启前按现网流量复核磁盘；
4. **trace 关联**：网关对每个请求生成内部 `trace_id`/`request_id`，访问记录与 WAF
   安全事件可经「调用链检索」双向跳转（按 trace_id 或 request_id 检索）。

无 Agent 模式的如实边界：

- 耗时口径为网关总耗时 + TTFB（首字节），**不做网关/WAF/上游三段虚假拆分**；前置拦截
  的请求无上游阶段，页面如实标注；
- 看不到应用内部的 SQL、函数、线程、GC——这些需要 Agent 模式；
- 端点归一化为 `METHOD /path/{id}` 模板；Top-200 之外的尾端点并入 `__OTHER__`，
  无法归一化的进 `__UNCLASSIFIED__`（治理入口，不污染指标）。

## 3. Agent 模式接入总览

```text
① 申请注册令牌（管理面，一次性）
② 业务侧部署：本地 Collector（127.0.0.1 接收）+ 应用加载 OTel 零代码 Agent/SDK
③ 控制面注册：提交令牌 + CSR → 签发短期客户端证书 + 签名基线策略 → 心跳保活
④ 遥测上报：Agent → 本地 Collector（OTLP）→ 中央 Collector Gateway（OTLP/mTLS）→ ClickHouse
⑤ 验证：服务性能页观测模式变「Agent」，调用链检索可见瀑布
```

**如实说明（部署前必读）**：OTel 官方零代码 Agent 负责遥测产出（span/指标），其本身
不内置九章控制面注册客户端；第③步的注册、心跳、证书轮换与策略拉取由部署侧接入组件
按管理面机器端点协议（§4.2）完成。分语言开箱 Agent 包（内置注册客户端）属交付路线
图项，当前版本的端到端接入**需在部署环境实测验证**后投产。

## 4. 注册令牌申请流程

### 4.1 管理面操作路径

1. 登录管理控制台（SECURITY_ADMIN 或持有 `apm.agents.manage` 权限的自定义角色）；
2. 进入「业务性能 → Agent 管理」，点击「创建注册令牌」；
3. 填写绑定范围：应用（可空）、环境、允许的语言、有效期（默认 60 分钟，合法区间
   5 分钟～7 天）；
4. **令牌原文仅在创建响应中显示一次**，服务端只保留 SHA-256 不可逆摘要——立即复制
   并经安全渠道分发；令牌使用即作废（原子置位防重放），一台 Agent 一个令牌；
5. 泄露处置：令牌未使用前泄露，直接废弃重建；已注册 Agent 失陷，在 Agent 管理页
   「撤销」（终态 REVOKED，证书指纹立即入拒绝列表，撤销不可逆）。

对应接口：`POST /api/v1/apm/agents/enrollment-tokens`（高风险操作审计）。

### 4.2 机器端点协议摘要（Agent/接入组件侧，无浏览器会话）

| 端点 | 认证 | 用途 |
|---|---|---|
| `POST /api/v1/apm/agent/register` | 一次性注册令牌 | 提交令牌 + PKCS#10 CSR（Ed25519/ECDSA P-256·P-384/RSA≥2048），签发短期客户端证书（默认 72h，`APM_AGENT_CERT_TTL_HOURS` 可配 24h～7d），返回 CA 证书/验签公钥、Collector 地址（空串 = 数据面未就绪）、资源属性与已签名基线策略；应用/环境归属取自令牌，不信任自报 |
| `POST /api/v1/apm/agent/heartbeat` | CA 客户端证书 PoP 签名头（`X-JiuZhang-Agent-Cert` / `X-JiuZhang-Agent-Timestamp` / `X-JiuZhang-Agent-Signature`，签名覆盖方法+路径+时间戳+正文 SHA-256，时间戳容差 ±5 分钟） | 心跳保活；响应含当前策略版本与轮换建议；已撤销 403、证书过期/未登记 401 |
| `GET /api/v1/apm/agent/policy` | 同上 | 拉取当前生效签名策略（应用级优先，回退全局基线）；只接受版本递增、签名有效、未过期的策略 |
| `POST /api/v1/apm/agent/rotate-cert` | 当前生效证书 PoP | 提交新 CSR 轮换证书（旧证书立即入撤销列表）；不依赖长期令牌 |
| `POST /api/v1/apm/agents/{id}/revoke` | 管理面会话 | 撤销（管理侧操作） |

纪律：注册令牌不得写入镜像层、配置文件或代码库；经环境变量或密钥管理系统注入。
控制面不可达时 Agent 继续使用最后一份有效基线策略，业务不受影响。

## 5. 分语言接入步骤

通用环境变量（所有语言一致，OTLP 指向本机本地 Collector）：

```bash
export OTEL_SERVICE_NAME='<服务名>'                 # APM 服务主标识，必填
export OTEL_RESOURCE_ATTRIBUTES='deployment.environment.name=prod,service.version=<版本>,service.instance.id=<实例>'
export OTEL_EXPORTER_OTLP_ENDPOINT='http://127.0.0.1:4318'   # 本地 Collector（仅回环）
export OTEL_EXPORTER_OTLP_PROTOCOL='http/protobuf'
export OTEL_PROPAGATORS='tracecontext'              # W3C Trace Context
export OTEL_TRACES_SAMPLER='parentbased_always_on'  # 头采 100%：采样保留决策集中在中央尾采样，
                                                    # Agent 侧不做概率裁剪（丢弃不可恢复）
```

数据安全默认口径（无需额外配置即生效）：不采集请求/响应正文、Authorization/Cookie/
SQL 绑定值/URL 查询值等（本地与中央双层脱敏兜底，清单见设计 §12.1 与 Collector 配置）。

### 5.1 Java（-javaagent，零代码）

依赖：OpenTelemetry Java Instrumentation 官方 javaagent JAR（2.x 系列，支持 Java 8+；
交付锁定版本以离线包/docs/DEPENDENCIES.md 为准）。

```bash
java -javaagent:/opt/otel/opentelemetry-javaagent.jar \
     -jar app.jar    # 环境变量按 §5 通用模板注入
```

兼容性要求：自动插桩覆盖官方支持清单内的框架/库（Spring、JDBC、HTTP 客户端、MQ 等）；
清单外的自研框架不产生 span（如实边界，需手工埋点）。与既有 APM/探针并存、JDK 版本
组合需部署环境实测。

### 5.2 Go（SDK 显式埋点）

Go 无官方零代码字节码插桩；官方零代码方案为 eBPF（OpenTelemetry eBPF
Instrumentation），依赖 Linux 内核版本与特权，作为可选兼容项，**不作为首期推荐**。

生产推荐 SDK 显式埋点：引入 `go.opentelemetry.io/otel` + 对应中间件（HTTP 用
`contrib/.../otelhttp` 包裹 Handler/Transport，DB/RPC 用对应 instrumentation），
初始化 TracerProvider 指向本地 Collector。九章自身组件（管理后端）参考实现：
`APM_SELF_TELEMETRY_ENABLED=true` + `APM_OTLP_ADDR`（默认 `http://127.0.0.1:4318`）。

### 5.3 Node.js（--require 预加载，零代码）

依赖：`@opentelemetry/auto-instrumentations-node`（OTel JS 2.x 要求 Node.js
^18.19.0 或 >=20.6.0；老版本应用需评估升级或使用配套旧版，以官方文档为准）。

```bash
npm install @opentelemetry/auto-instrumentations-node
node --require @opentelemetry/auto-instrumentations-node/register app.js
# 或：NODE_OPTIONS='--require @opentelemetry/auto-instrumentations-node/register' node app.js
```

兼容性要求：覆盖官方支持清单内的 HTTP/Express/Koa/常见 DB 与 MQ 库；自定义函数观测
需代码埋点或诊断会话（CPU profile 属限时能力）。event-loop 指标随基线上报。

### 5.4 .NET（CLR Profiler，零代码）

依赖：OpenTelemetry .NET Automatic Instrumentation
（opentelemetry-dotnet-instrumentation；支持 .NET 6+ 与 .NET Framework 4.6.2+，
self-contained 部署经 NuGet 方式，以官方文档为准）。

```powershell
# Windows 示例（Linux 对应 CORECLR_* 同名变量）；注册令牌等经环境注入
$env:CORECLR_ENABLE_PROFILING='1'
$env:CORECLR_PROFILER='{918728DD-259F-4A6A-AC2B-B85E1B658318}'
$env:CORECLR_PROFILER_PATH='<安装路径>/OpenTelemetry.AutoInstrumentation.Native.dll'
# + §5 通用 OTEL_* 变量
```

兼容性要求：IIS 承载需按官方 IIS 注册方式配置；框架/库覆盖清单与 Runtime 版本组合
需部署环境实测（设计 §8.1 标注 .NET 深度诊断为后续项）。

### 5.5 Python（opentelemetry-instrument，零代码）

依赖：`opentelemetry-distro`（含 `opentelemetry-instrument` 启动器；当前版本要求
Python 3.9+，以官方文档为准）。

```bash
pip install opentelemetry-distro
opentelemetry-bootstrap -a install    # 安装检测到的库对应插桩包
opentelemetry-instrument python app.py
```

兼容性要求：覆盖官方清单内 Web/DB/HTTP 库；GIL、线程阻塞与任意函数观测不能仅靠
通用自动插桩完整覆盖（如实边界）。

### 5.6 版本兼容性统一声明

- 各语言 Agent/SDK 具体版本随交付锁定（离线包清单与 docs/DEPENDENCIES.md），禁止
  客户侧自行更换大版本；
- 框架/库覆盖范围以 OTel 官方支持清单为准，清单外不产生自动 span；
- 基线性能预算目标（吞吐下降 ≤3%、P95 增幅 ≤3% 或 2ms）为验收目标而非承诺，
  接入后应在预发环境以真实流量实测确认。

## 6. traceparent 透传要求

- 链路上下文使用 W3C 标准 `traceparent`（`tracestate` 网关入口一律丢弃、不续传）；
- **公网入口不信任外部 trace**：格式错误/全零 ID/超长一律丢弃并新建内部 trace_id；
  是否续接外部 trace 由 `trace_trust_external` 策略决定（默认否）；
- **网关 → 上游注入**：当前版本网关默认**不向上游注入** traceparent——
  `trace_inject_upstream` 开关网关侧已实现，但发布侧恒按 false 下发、管理面取值
  接线属后续工作包。因此当前版本"网关访问记录 ↔ 首个业务服务 span"的关联依赖
  trace_id 检索拼接（管理面已完成），而非请求头透传；业务服务**之间**的透传由
  OTel 插桩自动完成；
- 业务自研 HTTP 客户端/消息生产者需确认 traceparent 注入与提取（OTel 清单内客户端
  自动完成；清单外按 W3C 规范手工透传 `traceparent` 头/消息属性）；
- 不得把租户、用户名、凭据放入传播头；不盲从外部 sampled 标志（采样由平台策略决定）。

## 7. 接入验证清单

- [ ] 「服务性能」目标应用观测模式显示「Agent（在线 x/y）」；
- [ ] 「调用链检索」能按服务名查到新 trace，瀑布包含 Server/Client/DB span；
- [ ] 制造一笔错误请求，异常分析页出现对应异常指纹，trace 视图可跳关联访问记录；
- [ ] 「SQL 诊断」出现该服务 SQL 指纹（有数据库调用时）；「运行时指标」出现实例指标；
- [ ] 停掉本地 Collector 5 分钟：业务无影响（fail-open），恢复后遥测自动继续；
- [ ] 令牌与私钥未落入镜像/仓库/日志（安全自查）。

## 7.1 标准演示环境（P1-01）

仓库内置可重复部署的安全 + APM 标准演示夹具：`test/security-apm-demo/`（独立 compose
project、合成业务 A→B→独立测试库、演示专用 Collector/ClickHouse，操作手册见其 README.md）。
演示环境的采样与日志配置独立于本文描述的产品默认值；演示对接既有部署管理面/网关的
手动接入步骤、传播边界（含 §6 traceparent 上游注入现状）与已知限制以该 README 为
唯一口径，本文不重复维护第二套说法。

## 8. 常见问题

- **接入后正常请求查不到 trace**：中央尾采样正常流量基线 5%（错误/慢 ≥2s/WAF 高风险
  优先保留），属设计行为；排障时用错误/慢请求样本或开启限时诊断会话提高采样。
- **会不会拖慢业务**：Agent 基线以低开销策略运行，故障一律有界丢弃不阻塞应用；
  性能预算见 §5.6，以预发实测为准。
- **能看到 SQL 原文/请求参数吗**：不能。默认只存 SQL 指纹，不存绑定值、正文、URL
  查询值（双层脱敏）；原始 statement 即使诊断会话首期也保持关闭。
- **4xx 算不算错误率**：端点告警与总览错误率口径为 5xx 占比；SLO availability 同样
  只把 5xx 计为失败（4xx 是否违约由后续端点策略演进）。
- **Agent 离线 = 业务宕机吗**：不是。Agent 心跳与业务健康页面分列，离线仅表示遥测
  通道中断。
- **诊断会话会泄露数据吗**：会话限时（默认 15 分钟、最长 2 小时）、限范围、全程审计，
  到期/失联自动回基线；全局 kill switch 可一键终止全部会话并封锁新建。
- **时钟有要求吗**：有。Agent 宿主机与管理面时钟差超过 ±5 分钟会导致心跳认证失败；
  全链路节点统一 NTP 校时。

---

Copyright © 聚信得仁
All Rights Reserved.
