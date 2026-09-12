# 九章 WAF 代码、安全与 UI/UX 修复复审报告

> 复审日期：2026-09-06  
> 复审对象：`docs/evidence/code-security-ui-ux-audit-2026-09-05.md` 中的 9 项发现，以及 `docs/evidence/code-review-2026-09-05.md` 单列的 6 项设计遗留  
> 代码基线：`develop` / `3c73774` 加当前未提交工作树  
> 复审方式：修复差异与调用链静态检查、针对性单元测试、前端全量测试、Lint、生产构建和依赖审计

## 1. 结论

原审计的 9 项发现中：

| 状态 | 数量 | 项目 |
|---|---:|---|
| 已修复 | 9 | SEC-01、BUG-01、OBS-01、UI-01、UI-02、UI-03、DEP-01、UI-04、UI-05 |
| 部分修复 | 0 | 无 |
| 未修复 | 0 | 无 |

两个高危问题已经形成有效闭环：通知外连具备保存期校验、拨号期复检和重定向限制；APM Agent 注册收敛为单事务，并对并发复用令牌实施行锁。当前没有发现可绕过这两项修复的直接路径。

本轮已继续完成 OBS-01 与 UI-03：审计写入失败具备本地持久化队列、幂等重试、指标和系统告警闭环；图表组件会从配置自动生成核心数据摘要。复审时新增的 UI-06、PERF-01，以及上一轮单列的 MED-5 设计遗留也已修复。按当前代码检查与自动化验证范围，原 9 项发现、本轮 2 项新增发现和上一轮 6 项设计遗留均已关闭。

## 2. 原 9 项修复状态

### SEC-01 [High] 通知渠道 SSRF：已修复

**代码证据**：

- `server/internal/outboundhttp/outboundhttp.go:144-176` 统一限制 `http/https`、拒绝 URL 内嵌凭据，并校验主机与端口。
- `server/internal/outboundhttp/outboundhttp.go:178-197` 对域名的全部 A/AAAA 结果逐一执行地址策略，任一私网或保留地址即拒绝。
- `server/internal/outboundhttp/outboundhttp.go:200-235` 在实际拨号时重新解析并复检地址，再直连已检查的 IP，覆盖 DNS 重绑定窗口。
- `server/internal/outboundhttp/outboundhttp.go:239-263` 对重定向逐跳复检；通知策略设置 `MaxRedirects: 0`，默认拒绝跟随。
- `server/internal/notify/outbound.go:20-53` 对企业微信、飞书使用精确官方域名、HTTPS 和 443 端口约束；内部短信目标只能通过专用 allowlist 放行。
- 测试覆盖私网地址、IPv4 映射 IPv6、保留网段、域名多地址、DNS 重绑定、重定向和敏感头剥离。

**复审判断**：满足“保存时拒绝 + 实际拨号时复检 + 重定向不可绕过”的验收条件。

### BUG-01 [High] APM Agent 注册非原子：已修复

**代码证据**：

- `server/internal/apm/agents_store.go:419-462` 将令牌校验与消费、服务认领、策略解析、旧 Agent 顶替、新 Agent 插入合并为同一 `pgx` 事务。
- `server/internal/apm/agents_store.go:464-490` 使用 `SELECT ... FOR UPDATE` 锁定一次性令牌，并统一处理不存在、已使用和已过期状态。
- 语言白名单校验发生在令牌消费前；任一后续步骤失败均由事务回滚。
- `server/internal/apm/agentapi_handler.go:258` 由注册接口直接调用新的事务入口。
- 测试覆盖语言拒绝、服务认领冲突、CA/插入/策略失败回滚，以及同一令牌并发复用仅一次成功。

**复审判断**：原先两类中间态已被消除。响应在提交后丢失时仍需新令牌重试，这是一次性注册协议的已记录行为，不属于原子性漏洞。

### OBS-01 [Medium] 审计失败被忽略：已修复

**代码证据**：

- `server/internal/audits/fallback.go` 在数据库写入失败时将脱敏后的记录同步追加到本地 JSONL 队列，并对目录和文件分别使用 `0700`、`0600` 权限；追加操作执行 `fsync` 后才返回成功。
- 队列记录包含稳定的 `delivery_id`；`server/migrations/000124_operation_audit_delivery_id.up.sql` 增加唯一索引，重放使用冲突忽略语义，覆盖“数据库提交成功但客户端收到错误”导致的重复投递场景。
- 后台工作器按固定间隔重试，成功后原子收缩队列；失败记录会保留等待下一次重试。
- `GET /api/v1/metrics` 在 `system_health.read` 权限保护下暴露 `audit_write_failures_total`、`audit_retry_queue_pending`、`audit_retry_success_total` 和 `audit_retry_enqueue_failures_total`。
- 首次失败会创建 `AUDIT_WRITE_FAILED` 高危系统告警，队列恢复后自动关闭；结构化日志仍保留请求、模块、动作和对象上下文。
- 故障注入测试覆盖落库失败入队、字段脱敏、文件权限、稳定投递 ID、重试成功清队列、重试失败保留队列和指标输出。

**复审判断**：原先被忽略的写入失败现在会进入持久化补偿链路，且具备指标、告警、恢复和幂等重试。该方案不是与业务数据共用事务的 transactional outbox，但在现有跨模块调用结构下已经满足“业务成功后审计记录最终补写”的验收目标；只有数据库与本地持久化队列同时失败时才会返回并记录不可恢复错误。

### UI-01 [Medium] 隐藏式详情交互与键盘不可达：已修复原报告列出的调用点

**代码证据**：

- 原有 `a` 标签绑定 `onClick` 的伪链接已替换为路由 `Link` 或 Ant Design `Button`。
- 原有 123 个双击详情入口已取消，列表和表格提供可见的详情操作。
- `web/src/pages/security-events/EventDetailDrawer.tsx:451-460` 的可点击关联事件行补充 `role="button"`、`tabIndex={0}`，并支持 Enter/Space。
- 前端全量 698 项测试通过。

**复审判断**：原报告明确列出的伪链接、双击入口和事件列表项已经关闭。其他页面仍有相同类型的残留，见 UI-06。

### UI-02 [Medium] 主布局缺少移动端导航：已修复

**代码证据**：

- `web/src/layouts/AdminLayout.tsx:233-236` 使用 Ant Design 断点识别小于 `md` 的窄屏。
- `web/src/layouts/AdminLayout.tsx:341-356` 在窄屏使用左侧 Drawer 导航，桌面继续使用 Sider。
- `web/src/layouts/AdminLayout.tsx:289-292` 路由切换后自动关闭移动端导航。
- 移动端菜单按钮具有可访问名称，Header 和 Content 边距随断点缩小。

**复审判断**：代码与组件测试满足原验收条件。此次未在真实移动设备上做触控、横竖屏和安全区人工验收。

### UI-03 [Medium] ECharts 缺少无障碍替代：已修复

**代码证据**：

- `web/src/components/EChart.tsx` 为图表容器保留 `role="img"` 和可访问名称，并用 `aria-describedby` 关联始终存在的视觉隐藏摘要。
- `web/src/components/EChartAccessibleSummary.ts` 自动从 ECharts 配置生成文字摘要，不要求各页面逐一传入：折线图和柱状图包含时间范围、点数、首末值、最小值、最大值和趋势；饼图包含总量及主要分类；关系图包含节点数和连线数；空数据提供明确说明。
- 自动摘要同时写入 ECharts ARIA 描述；调用方仍可通过 `summary` 提供更符合业务语义的说明。
- 当前 29 个实际图表渲染调用点均传入了 `ariaLabel`。
- 组件测试覆盖折线图、饼图和空数据摘要。

**复审判断**：常用统计图表的核心信息不再依赖 Canvas，可由屏幕阅读器读取，原发现关闭。复杂关系图当前提供结构规模摘要；逐节点数据表属于进一步增强项，不影响本项关于核心替代信息的关闭结论。

### DEP-01 [Low] React Router 安全公告版本：已修复

- `web/package.json:33` 与锁文件均升级到 `react-router-dom 7.18.3`。
- `npm audit --omit=dev` 报告 0 个已知漏洞。

### UI-04 [Low] 应用详情返回按钮无名称：已修复

- `web/src/pages/applications/ApplicationDetailPage.tsx:89-96` 已增加“返回应用列表”的 Tooltip 和 `aria-label`。

### UI-05 [Low] 面包屑缺少对象上下文：已修复

- `web/src/layouts/AdminLayout.tsx:294-307` 生成“系统 / 当前模块 / 对象”层级，祖先使用可点击 `Link`，当前对象使用纯文本。
- 应用详情、身份详情和攻击会话详情分别注入应用名、身份键和会话键。

## 3. 本轮新增发现

### UI-06 [Medium] 三处动态表单删除图标仍无法通过键盘操作：已修复

**位置**：

- `web/src/pages/api-classifications/ApiClassificationsPage.tsx:201`
- `web/src/pages/risk-policy/RiskPolicyPage.tsx:363`
- `web/src/pages/applications/detail/HeaderProxyTab.tsx:226`

**修复证据**：三处均已改为 Ant Design `Button type="text" danger`，由原生按钮提供焦点和 Enter/Space 行为，并分别设置“删除此分类维度”“删除此信号分值”“删除此头修改规则”的可访问名称和 Tooltip。

**验证**：分类维度、风险策略和 Header Proxy 组件测试均按按钮的可访问名称查询并执行删除操作，覆盖键盘等价的原生按钮语义。

### PERF-01 [Low] 生产主包超过 1 MB gzip：已修复

**修复证据**：

- `web/src/router/index.tsx:1-1335` 将管理布局和各业务页面改为 `React.lazy` 动态导入，并由统一的 `Suspense` 加载态承接首次加载。
- `web/src/pages/big-screen/components/GlobeAttackMap.tsx:4-6` 将 `echarts-gl` 全量副作用导入收敛为实际使用的 globe、lines3D 和 scatter3D 模块。
- `web/vite.config.ts:21-35` 将 React 运行时拆为稳定共享块，避免它随主入口重复增长。
- 相同生产构建条件下，主入口由 3,327.24 kB / gzip 1,005.91 kB 降至 423.05 kB / gzip 139.78 kB，分别下降 87.3% 和 86.1%；最大输出块为 478.79 kB / gzip 163.78 kB，构建不再出现超过 500 kB 的分块告警。

**复审判断**：路由级按需加载和三维图表精确导入已经消除原主入口超限问题，PERF-01 关闭。CI 包体预算与真实设备性能指标属于后续防回归和效果量化工作。

## 4. 上一轮单列设计遗留复核

| 项目 | 状态 | 复核证据 |
|---|---|---|
| HIGH-14 hostctl 标志缺少真实性校验 | 已修复 | `ops/system/hostctl-exec.sh` 使用目录内受控密钥校验 HMAC，相关 `systemops` 测试通过 |
| MED-11 AI 高成本任务每日配额 | 已修复 | `server/internal/aicost` 已实现每日次数判断，编排器在执行前调用，配额测试通过 |
| MED-23 离线包缺少发布签名 | 已修复 | 构建端生成 Ed25519 旁车签名，安装端先验签后解压；未签名默认拒绝，只允许显式 `--allow-unsigned` |
| MED-5 移除 behavior_store 后进程级注入残留 | 已修复 | `gateway/dynamic_security/context/context.go:263-278` 将存储选择绑定到请求上下文，`pipeline/pipeline.go:116` 在每次请求中显式绑定当前配置；Guard 入口在 `apiprotect.go:127,615` 显式传入实例存储。进程级注入 API 已移除，双 Guard 隔离回归测试位于 `apistore_test.go:104-130` |
| LOW-S10 AI Token 限制未贯穿 | 已修复 | 编排器强制输入预算并将输出预算传给模型调用，相关配额测试通过 |
| LOW-G3 XFF 默认透传 | 已修复 | 无显式头配置时默认覆盖 XFF；显式关闭仍被尊重，生成器测试覆盖两种路径 |

## 5. 验证结果

| 检查 | 结果 |
|---|---|
| `go test -count=1 ./internal/outboundhttp ./internal/notify ./internal/apm ./internal/audits ./internal/aicost ./internal/aiorchestrator ./internal/systemops ./internal/appconfigs ./internal/gatewayconfig` | 通过，9 个相关包全部成功；包含需监听本地回环端口的 HTTP 客户端测试 |
| 同范围 `go vet` | 通过 |
| `npm run test -- --run`（Node 24.13.0） | 通过，100 个测试文件、698 项测试 |
| `npm run lint` | 通过 |
| 复审初始 `npm run build` | 通过；主入口 3,327.24 kB / gzip 1,005.91 kB，存在大分块告警 |
| `npm audit --omit=dev` | 通过，0 个已知漏洞 |
| `go test ./internal/audits ./internal/systemalerts ./internal/app` | 通过；覆盖审计持久化补偿、系统告警规则和应用装配 |
| 4 个本次前端定向测试文件 | 通过，17 项测试；覆盖自动图表摘要和三处删除按钮 |
| 本次前端改动的 TypeScript 类型检查与 ESLint | 通过，无错误和警告 |
| 路由拆分后的 4 个前端回归测试文件 | 通过，16 项测试；覆盖路由权限守卫和主布局 |
| 修复后 Vite 生产构建 | 通过；主入口 423.05 kB / gzip 139.78 kB，最大块 478.79 kB / gzip 163.78 kB，无大分块告警 |
| `go test ./...`（`gateway/dynamic_security`） | 通过；覆盖请求级存储绑定、默认内存回退和 WebShell C2 显式存储 |
| `go test .`（`gateway/modules/jiuzhang_guard`） | 通过；包含同进程双 Guard 存储隔离回归测试 |
| 进程级存储注入符号扫描 | `gateway/` 中未发现 `SetStoreOverrides`、`ApplyStoreOverrides` 或无参 `storeOverrides()` 残留 |

前端测试输出仍包含 React `act(...)` 和部分 Ant Design 过时属性警告。它们没有导致测试失败，但应在后续维护中清理，以免真实异步更新问题被大量警告掩盖。

## 6. 后续验证与防回归

### P2

1. 在 CI 建立前端入口块与最大块预算，防止后续依赖或静态导入使包体重新越线。
2. 在固定设备与网络条件下记录 LCP、INP 和脚本执行时间，量化路由拆分对首屏体验的实际改善。
3. 使用真实屏幕阅读器复核图表朗读顺序，并按业务需要为复杂关系图补充可展开数据表。

## 7. 复审限制

- 当前工作树包含大量未提交和未跟踪文件，本报告对应的是 2026-09-06 复审时的本地快照，不是仅凭 `3c73774` 可复现的提交状态。
- 本轮没有连接真实 PostgreSQL、Valkey、ClickHouse 或外部通知平台，也没有运行完整 Docker/多节点/网关流量回归。
- 移动端和图表结论来自代码、组件测试及构建检查；未执行真实设备、真实屏幕阅读器和浏览器性能实验。自动摘要已覆盖核心数据，实际朗读顺序仍需人工验收。
