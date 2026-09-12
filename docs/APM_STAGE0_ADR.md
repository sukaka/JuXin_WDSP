# 九章 APM 阶段0 ADR：观测技术选型与阶段1实施基线

> 文档状态：评审稿（阶段0 退出物）
> 编写日期：2026-08-30
> 依据：`docs/BUSINESS_PERFORMANCE_APM_DESIGN.md`（下称"APM 设计"）§23 阶段0/阶段1
> 读者：架构、后端、网关、前端、测试、运维、安全

本 ADR 记录阶段0（ADR、容量验证与技术 POC）的决策与结论，并给出阶段1（无 Agent 业务性能增强）的实施基线。所有"现状"结论均经 develop 分支代码逐文件核实（核实日期 2026-08-30）。

## 1. 现状核实结论（对 APM 设计 §2.1/§2.2 的修正）

| APM 设计论断 | 代码核实结果 | 对实施的影响 |
|---|---|---|
| access log 未稳定携带 request_id/trace_id/application_id/api_endpoint_id | **部分属实**。`access_logs` 已有 `request_id`（取客户端 `X-Request-Id`，网关注入见下）与 `application_id`（发布侧注入 `Guard.AppID`），但 `trace_id`、`api_endpoint_id`、上游阶段耗时**完全不存在**；`waf_action` 只有 `BLOCK`/空两态 | 阶段1 需补 `trace_id`/`span_id`/`endpoint_key`/TTFB，并把 `waf_action` 扩为 ALLOW/OBSERVE/BLOCK 三态 |
| —（设计未提及） | **request_id 生成已就绪**：发布链 `headers` handler 以 `{http.request.uuid}` 生成（`server/internal/gatewayconfig/headers.go:260-265`），guard 入口读取（`module.go:1042`） | 阶段1 直接复用，不新建 request_id 机制 |
| —（设计未提及） | **存在两条独立访问日志管道**：A. guard 全量日志 `access-full.jsonl` → `access_logs` 表（默认关，`logging.access_log_enabled`）；B. Caddy 原生 access.log → 分钟聚合（应用级 RED 已默认常开） | 端点级 RED 只能建在管道 A 上；应用级 RED 复用管道 B |
| —（设计未提及） | **前置拦截盲区**：人工封禁/IP 黑名单/L7/CC 的 403/429 在 `ServeHTTP` 内直接返回，不经过 `serveNext`，**不产生访问日志**（`module.go:1082-1141`） | "完整 ALLOW/BLOCK 流量"要求把采集点上移到 `ServeHTTP` 入口 |
| `api_call_edges` 缺少可靠写入链路 | **已过期**。阶段8 P1-09/10 已落地 `aggregations/call_edges.go RunCallEdges`（分钟级水位 + 同事务 upsert，崩溃幂等），由 `jobs.go:326` 每分钟驱动 | 阶段1 不再建设，仅复用；`apiassets/value.go:12`、`mem_store.go:656` 两处陈旧注释需顺手修正 |
| RequestContext 含 RequestID/TraceID/ApplicationID/APIEndpointID | 字段已声明（`context.go:177-246`）但 **TraceID/ApplicationID/APIEndpointID/ConnectionID 等从未填充**；`events/event.go:36` 读 `ctx.ApplicationID` 恒为空（实际值走 `g.AppID` 旁路） | 阶段1 桥接填充，统一口径 |
| W3C Trace Context | 全仓**零实现**（无 traceparent/tracestate/span_id 任何代码） | 阶段1 新建，见 D5/D6 |
| 上游阶段耗时 | **无任何数据源**（Caddy 反代不向 guard 暴露分段计时） | 阶段1 采用 D8 口径 |

## 2. 架构决策

### D1 遥测标准：OpenTelemetry（接受）

采用 OTel 作为 Agent 模式的遥测协议与语义约定（traces/metrics 语义、OTLP、W3C Trace Context）。许可证 Apache-2.0，符合项目宽松许可证要求。版本纪律：Collector 选用 contrib 发行版，**固定版本号与镜像 digest**（引入时登记 `docs/DEPENDENCIES.md` 与 `THIRD_PARTY_NOTICES.md`），升级走兼容性回归。阶段1 不引入任何 OTel 依赖——无 Agent 模式只定义与 OTel 对齐的字段语义（trace_id/span_id/route template），避免阶段2 返工。

### D2 数据面存储：ClickHouse（接受，但阶段2 才引入）

接受"PostgreSQL 控制面 + ClickHouse 数据面"的隔离设计（APM 设计 §15）。**关键边界：阶段1（无 Agent 模式）不引入 ClickHouse**——端点级 RED 与慢端点分析完全落在现有 `access_logs` 表 + `metric_*_aggregates` 聚合体系上，零新增基础设施。ClickHouse 随阶段2 OTLP 数据面一并引入，届时单独做容量验证与交付形态（单机/集群）决策。

### D3 采集拓扑：本地 Collector + 中央 Collector Gateway（接受，阶段2 落地）

接受 APM 设计 §5 的分层拓扑。阶段1 不涉及。

### D4 首批语言：Java + Go（接受）

Go 为九章自身组件（管理面/网关控制面）优先，SDK/中间件显式埋点；Java 为客户侧 P0。.NET 紧随，Node.js/Python 按客户栈接入。eBPF 自动插桩仅作可选兼容项（依赖内核/权限），不作为首期方案。阶段1 不涉及 Agent。

### D5 W3C Trace Context 信任策略（采纳并细化）

网关在 `jiuzhang_guard.ServeHTTP` 入口处理 `traceparent`/`tracestate`：

1. **格式严格校验**：`version-traceid-spanid-flags` 四段小写 hex；version 非 `ff`；trace_id 32 hex、span_id 16 hex、均非全零；整头长度上限 128 字符。任一不满足即丢弃外部上下文。
2. **默认不信任外部 trace**：公网入口默认**新建内部 trace_id**（策略可配为"校验通过则续接"，按应用/域名维度，高安全场景保持默认新建）。续接时以外部 trace_id 为父，重新生成 span_id。
3. **tracestate 一律不续传**：入口丢弃外部 `tracestate`，不向客户端回传，不向下游转发（跨信任域清理）。
4. **不盲从外部 sampled 标志**：采样决策由本系统策略决定（阶段1 无 Agent 模式不采样，日志全量；采样语义留待阶段2）。
5. **trace_id 生成**：16 字节加密随机数（crypto/rand），hex 编码；span_id 8 字节同理。
6. **不向客户端返回 trace_id**（默认）。故障工单场景可经配置开启响应头，默认关闭以避免枚举面。

### D6 trace 上下文落点（新建）

- guard `ServeHTTP` 入口完成 D5 处理后，将 `trace_id`/`span_id` 写入请求上下文，并桥接进统一 `RequestContext`（填 `TraceID`，新增 `SpanID` 字段）。
- 访问日志记录新增 `trace_id`/`span_id` 字段；WAF/API 运行时事件记录新增 `trace_id` 关联键，实现"安全事件 ↔ 访问记录"双向检索。
- **不向上游注入 `traceparent`**（阶段1 默认）。注入是 Agent 模式（阶段2）的前提，届时经发布配置开关启用，避免阶段1 改变发往源站的请求字节。

### D7 端点归一化与基数控制（新建 + 复用）

- 端点键复用共享包 `gateway/dynamic_security/normalizer`：`endpoint_key = METHOD + " " + NormalizePath(path)`（数字段→`{id}`、UUID→`{uuid}`、长 hex→`{hex}`）。**纯 WAF 模式同样计算**——归一化是纯函数，不依赖 API 动态防护管线，保证无 Agent 监控对 WAF-only 站点可用。
- 服务端聚合做二级基数护栏：每应用每分钟桶仅保留请求数 Top-N（默认 200）端点，其余并入 `__OTHER__`；`metrics.allowedLabelKeys` 白名单扩 `endpoint`，值长 ≤128 字符。
- 无法归一化的（空路径等）归入"未归类端点"桶，页面如实展示治理入口，不污染高基数指标。

### D8 耗时口径：总耗时 + TTFB（诚实标注）

Caddy 反代不向 guard 暴露连接/TTFB 分段。阶段1 口径：

- `duration_ms`：guard 放行链路总耗时（已有）；
- `ttfb_ms`（新增）：自下游链进入到首个响应字节的耗时（含 WAF 检测 + 上游到首字节），经响应写入包装测得；
- 前置拦截请求无下游耗时，`duration_ms` 为网关处理耗时，页面如实标注"网关拦截，无上游阶段"。

"网关/WAF/上游三段细分"依赖 Caddy tracing 或 Agent，列入阶段2 评估，首期不做虚假拆分（对应验收 §25.1"无法细分时页面如实标识"）。

### D9 访问日志全量覆盖与 waf_action 三态（修改既有行为，默认关）

- 采集点由 `serveNext`（仅放行链路）上移至 `ServeHTTP` 入口：人工封禁/IP 黑名单/L7/CC 拒绝/授权限速的 403/429 同样产生访问日志记录，`response_status` 取实际拦截码。
- `waf_action` 扩为三态：`BLOCK`（任一防护组件拦截）、`OBSERVE`（仅观察命中）、`ALLOW`（放行）。旧数据空串按 `ALLOW` 口径展示（迁移不改历史行，查询层归一）。
- 该能力仍受 `logging.access_log_enabled` 总开关控制，**不翻转存量部署默认值**：新装/既有部署均保持原默认（关），APM 页面在开关关闭时如实显示"端点级数据未开启"并给出开启指引（对应 APM 设计"能力如实降级"原则）。应用级 RED 不受此开关影响（管道 B 常开）。

### D10 api_call_edges：复用既有写入链路（推翻 APM 设计 §23 阶段1 相应任务）

阶段8 已交付分钟级水位派生（`RunCallEdges`，事务内水位推进 + 边 upsert，可重算不重复）。阶段1 仅做两件事：修正 `apiassets/value.go:12` 与 `mem_store.go:656` 的陈旧注释；在阶段1 验收中把"边可重算"纳入回归（重跑水位窗口，call_count 不重复累计）。

### D11 功能开关与产品线归属

- 新增 env 开关 `APM_ENABLED`（默认 `false`），挂在 `config.Config`（仿 `AIConfig` 先例），控制 `/api/v1/apm/*` 路由挂载（关闭时挂 503 降级 stub，仿 `app.go:1105-1118` AI 先例）；前端经 `GET /product/edition` 下发 `apm_enabled`，菜单/路由按能力过滤（仿 `RequireWebWaf`/`RequireAPIDynamicProtection`）。
- 归属：**共享底座能力**（`docs/BRANCHING_AND_PRODUCT_LINES.md` §3"监控"属底座），目标分支 `main`；当前在 `develop` 集成开发，代码组织遵守底座目录边界（`server/internal/apm/`、`web/src/pages/apm-*`），不 import 任何能力域。WDSP 增强关联（API 资产/敏感数据维度）经既有 `api_*` 读模型接线，不在 APM 模块复制。

### D12 权限模型

新增权限码（迁移种子）：`apm.overview.read`、`apm.services.read`、`apm.traces.read`。角色口径沿用三权惯例：SECURITY_ADMIN 全量、AUDIT_ADMIN 只读、SYSTEM_ADMIN 不含（业务观测权限）。纯查询接口不写操作审计（沿用现有惯例）；导出/诊断类动作（阶段2+）才审计。

## 3. 容量模型（阶段1 增量）

阶段1 唯一新增存储压力 = `access_logs` 全量覆盖（前置拦截纳入）+ 端点级分钟聚合：

```text
access_logs 行/天 = 请求速率 × 86400（含被拦截请求，拦截通常占 <5%）
端点聚合行/天 ≈ min(应用数 × Top200 端点, 实际端点数) × 1440 分钟 × 状态码类别数
```

参照：1000 req/s 全开时 `access_logs` ≈ 8640 万行/天（既有 7 天保留与分批清理不变）；端点分钟聚合每应用每天 ≤ 200×1440×3 ≈ 86 万行上限（实际远小于此）。`metric_minute_aggregates` 既有 30 天保留策略不变。结论：阶段1 容量在既有留存纪律内可控，无需新增基础设施；`logging.access_log_enabled` 开启的容量提示沿用既有运维文档。

Agent 模式容量按 APM 设计 §14 公式在阶段2 引入 ClickHouse 前单独验证（本 ADR 不作性能承诺）。

## 4. 兼容矩阵与安全评审结论（阶段1 范围）

**兼容性**：

- 新旧网关 × 新旧管理端：`access_logs` 新列全部 nullable，旧网关上报缺省为 NULL，新管理端可收旧日志；新网关 + 旧管理端时旧采集器忽略未知 JSON 字段（`LogEntry` 解析白名单制，需验证确认）。
- 迁移 000088 为纯加列/加索引/加种子，向后兼容；down 迁移回滚加列。
- 关闭 `APM_ENABLED` 后，现有访问日志聚合、系统健康、WAF 防护与 WDSP 页面行为不变（验收 §25.4）。

**安全结论**：

- traceparent 注入：D5 严格校验 + 默认新建，外部 trace 不可用于跨租户关联污染；trace_id 不进入任何鉴权决策。
- 基数/注入：`endpoint_key` 经归一化 + Top-N 护栏 + 白名单值长限制；访问日志新增字段均为 hex/枚举/整数，无注入面。
- 脱敏：阶段1 新增字段不含任何请求正文/凭据/查询参数值，不触碰既有脱敏面。
- 权限：新接口强制会话 + RBAC + 授权门控，分页与时间窗强制上限。

## 5. 阶段1 实施拆分（工作包）

| WP | 内容 | 主要落点 |
|---|---|---|
| WP2 网关 | D5/D6 trace 上下文；RequestContext 沉睡字段桥接（TraceID/ApplicationID/Domain/ClientIP 等）；访问日志采集点上移 ServeHTTP、新字段（trace_id/span_id/endpoint_key/path_template/ttfb_ms）、waf_action 三态；事件 trace_id 关联键 | `gateway/modules/jiuzhang_guard/`、`gateway/dynamic_security/context/` |
| WP3 服务端数据 | 迁移 000088（access_logs 加列 + apm 权限种子 + APM 设置种子）；`accesslogs` 解析/入库扩展；端点级分钟聚合任务（Top-N + `__OTHER__`）；`metrics` 白名单扩 endpoint | `server/migrations/`、`server/internal/accesslogs/`、`server/internal/aggregations/`、`server/internal/metrics/` |
| WP4 服务端接口 | `server/internal/apm/`：`GET /apm/overview`、`/apm/services`、`/apm/services/{id}`、`/apm/endpoints`、`/apm/traces/{trace_id}`（访问记录+关联 WAF 事件）；路由挂载 + `APM_ENABLED`；OpenAPI 片段 `12-apm.yaml` + `make openapi-reconcile` | `server/internal/apm/`、`server/internal/app/app.go`、`server/internal/config/`、`server/openapi/` |
| WP5 告警 | systemalerts 新增慢端点/端点错误率评估（仿 `security_spike.go`）；runtimehealth 补 accesslog-01 采集链路新鲜度探针（仿 `probeEventCollector`） | `server/internal/systemalerts/`、`server/internal/runtimehealth/` |
| WP6 前端 | `apm_enabled` 能力接线（product store/menu capability/RequireApm）；页面组 `apm-overview`/`apm-services`/`apm-endpoints`，全部图表标注"无 Agent"数据来源；菜单分组"业务性能" | `web/src/` |
| WP7 验证 | 网关/服务端单测与接口测试、前端 vitest、`make openapi-reconcile`、三种构建 | 全仓 |

阶段1 退出条件对照（APM 设计 §23/§25.1）：不装 Agent 可按应用+端点定位慢请求区间；WAF 事件可经 request_id/trace_id 定位访问记录；ALLOW/BLOCK/OBSERVE 口径完整可重算；未归类端点有治理入口且不污染指标；关闭开关行为不变。

## 6. 阶段0 POC 验证状态（诚实记录）

- ✅ 代码级验证：现状逐文件核实（见 §1）；request_id 生成链、双日志管道、聚合水位幂等机制均已确认。
- ✅ 字段语义对齐 OTel/W3C：D5/D6 字段命名与 W3C Trace Context 规范一致。
- ⏳ 环境级 POC（需部署环境，不在本 ADR 内完成）：W3C 上下文经 Caddy→guard→业务服务端到端传播实测、目标吞吐下 span 大小与 ClickHouse 写入压测——列为阶段2 入口门禁，未实测前不承诺性能数字（呼应 APM 设计 §21"不是未经测试的承诺"）。

## 7. 后续阶段入口门禁

1. 阶段2（Agent 数据面）启动前：ClickHouse 交付形态（单机/集群/客户既有）决策完成；OTel Collector 版本与 digest 锁定并登记依赖文档；上游 traceparent 注入开关的端到端传播实测通过。
2. 阶段4（深度诊断）启动前：诊断会话审批流与最长时限管理决策（APM 设计 §26 待确认项）闭环。

---

Copyright © 聚信得仁
All Rights Reserved.
