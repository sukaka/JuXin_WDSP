# 九章 WAF / WDSP 代码、安全与 UI/UX 审计报告

> 审计日期：2026-09-05  
> 审计基线：`develop`，HEAD `3c73774`，包含当前未提交工作区改动  
> 审计方式：代码静态审查、权限与数据流追踪、依赖公告核验、Go 测试与 Vet、前端类型检查与 Lint  
> 说明：本报告只记录审计结果，未修改业务代码；结论不等同于生产环境渗透测试。

## 1. 结论

本轮确认 **9 个新问题**：

| 严重度 | 数量 | 说明 |
|---|---:|---|
| High | 2 | 通知出口 SSRF；APM Agent 注册非事务性导致令牌和在线 Agent 状态损坏 |
| Medium | 4 | 审计记录失败静默丢失；键盘不可达交互；缺少移动端导航；图表无文本替代 |
| Low | 3 | React Router 潜在依赖公告；图标按钮无可访问名称；详情页层级导航不足 |
| **合计** | **9** | 不包含上一轮报告中已明确列出的设计级遗留项 |

静态审计健康度：**74/100**。Go 代码的编译、测试和 Vet 基线较稳，权限中间件、请求大小限制、CSRF 及敏感数据处理也已有较完整的基础设施。主要风险来自跨步骤状态一致性、外连安全能力没有复用、审计写入缺少失败兜底，以及前端交互组件缺少统一的可访问性约束。

最优先处理：

1. 阻断通知 Webhook/SMS 网关访问回环、私网、链路本地和云元数据地址，并对 DNS 与重定向做连接时复检。
2. 把 APM Agent 注册的令牌消费、服务认领、旧 Agent 顶替和新 Agent 写入合并为一个数据库事务。
3. 为审计写入失败增加可靠兜底，至少产生结构化错误日志和指标，关键变更宜使用事务内审计或 outbox。

## 2. Anti-Patterns Verdict

| 检查项 | 结论 | 观察 |
|---|---|---|
| 过量圆角卡片、卡片套卡片 | 基本通过 | 管理控制台以表格、抽屉、表单为主，没有发现全局性卡片堆叠失控 |
| 状态信息滥用胶囊标签 | 通过 | `StatusTag` 主要用于状态、风险和动作，语义匹配 |
| 夸张标题、渐变、装饰性文案 | 通过 | 控制台保持了克制的企业安全产品风格 |
| 隐藏式交互 | **未通过** | 98 个页面文件包含 123 个双击处理器；6 个伪链接和 1 个可点击列表项缺少键盘语义 |
| 响应式布局 | **未通过** | 主导航是永久 `Sider`，没有窄屏 Drawer、断点或零宽收起逻辑 |
| 数据可访问性 | **未通过** | 通用 ECharts 封装只输出 Canvas 容器，没有 ARIA 或数据摘要 |
| 信息层级与导航反馈 | 部分通过 | 顶层菜单清楚，但面包屑只显示系统名和一级菜单，详情页缺少对象上下文 |

## 3. 详细发现

### SEC-01 [High] 通知渠道允许受权限用户发起内网 HTTP 请求

**类别**：SSRF / 出口控制 / 敏感告警数据泄露  
**位置**：

- `server/internal/notify/store.go:464-477`
- `server/internal/notify/sender.go:28-55`
- `server/internal/notify/sender.go:163-218`
- `server/internal/app/app.go:1085-1090`

**证据**：`checkWebhookURL` 只校验 `http/https` 和非空 Host。发送端使用默认 `http.Client`，会按默认规则解析域名并跟随重定向，没有拒绝回环、RFC1918、链路本地、IPv6 本地地址、云元数据网段，也没有连接时 DNS 复检。短信请求还会携带告警正文、手机号、`app_key`、`X-App-Key` 和 `X-Sign`。

拥有 `notification.update` 的用户可以保存指向内网的企业微信、飞书或短信网关地址；拥有 `notification.test` 的用户可以立即触发。即使没有测试权限，后续真实告警也会触发请求。攻击面受权限限制，但落在 WAF 管理面的服务端网络边界内，可能用于内网探测、访问云元数据接口或把告警内容发送到非预期目标。

仓库已有可复用的正确实现：`server/internal/apisecurity/spec_version.go:655-745` 已覆盖公网 IP 校验、全部 A/AAAA 记录校验、拨号时重解析和每次重定向复检。

**修复建议**：

1. 提取统一 `outboundhttp` 安全客户端，校验 URL、端口、全部解析结果、拨号目标和每次重定向。
2. 企业微信与飞书直接限制为官方 HTTPS 域名；短信网关如果必须支持内网，使用管理员配置的目标 CIDR/域名白名单，不接受任意私网地址。
3. 跨 Host 重定向时禁止转发自定义认证头和签名头；建议通知发送默认不跟随重定向。
4. 增加 IPv4/IPv6 回环、RFC1918、`169.254.169.254`、IPv4-mapped IPv6、混合 A/AAAA、重定向和 DNS rebinding 测试。

**验收条件**：不在显式允许列表内的私网或保留地址在保存配置和实际拨号两个阶段都被拒绝；重定向不能绕过限制。

### BUG-01 [High] APM Agent 注册在失败时会烧毁令牌并可能误下线健康 Agent

**类别**：事务一致性 / 可用性 / 注册凭据生命周期  
**位置**：

- `server/internal/apm/agentapi_handler.go:212-309`
- `server/internal/apm/agents_store.go:345-357`
- `server/internal/apm/agents_store.go:378-469`
- `server/internal/apm/agentapi_handler_test.go:132-150`

**证据**：处理器注释声明“成功路径单事务语义链”，实际调用是多次独立数据库操作：

1. `ConsumeEnrollmentToken` 先把一次性令牌标记为已使用；
2. 随后才检查 `LanguageAllowed`；
3. 服务认领使用另一个独立事务；
4. 旧实例 Agent 被 `SupersedeInstanceAgents` 撤销；
5. 之后才签证书、插入新 Agent、解析策略。

任一步失败都不会回滚前序状态。最小可复现路径是提交合法 CSR 但使用不在白名单内的语言：接口返回 400，令牌已经不可再次使用。更严重的路径是旧 Agent 已被撤销后，CA 签发、Agent 插入或策略解析失败，新 Agent 未成功注册，原健康实例却已经被置为 `REVOKED`。

现有测试只断言“坏 CSR 不消费令牌”，没有断言语言不允许、服务认领冲突或后续失败时令牌和旧 Agent 状态回滚。

**修复建议**：

1. 在消费令牌前完成所有不改变状态的校验，包括语言白名单。
2. 在 Store 层增加单一 `EnrollAgent` 事务，锁定并校验令牌，在同一事务中完成令牌消费、服务认领、旧 Agent 顶替和新 Agent 插入。
3. 在撤销旧 Agent 前完成 CSR 与证书签发、策略解析等可能失败的纯计算/读取步骤；数据库最终态一次提交。
4. 增加幂等设计或至少明确“响应写失败后的重试”语义，避免服务端已提交而客户端未收到证书时永久丢失令牌。

**验收条件**：语言拒绝、认领冲突、CA 失败、插入失败、策略读取失败和并发注册时，数据库不会出现令牌已用但 Agent 未注册，或旧 Agent 已撤销但新 Agent 不存在的状态。

### OBS-01 [Medium] 51 个处理器静默忽略审计写入错误

**类别**：审计完整性 / 可观测性 / 合规  
**位置（代表）**：

- `server/internal/apm/settings_handler.go:139-159`
- `server/internal/apm/agents_handler.go:432-459`
- `server/internal/apm/slo_handler.go:272-294`
- `server/internal/apm/diagnostics_handler.go:453-475`
- 全仓匹配：`rg -n '_ = .*audits\.Record|_ = h\.audits\.Record' server/internal --glob '*.go'`，共 51 处

**证据**：高风险设置更新、Agent 策略变更、诊断任务和其他管理操作在业务变更成功后调用 `audits.Record`，返回错误直接丢弃，没有日志、指标、系统告警或补偿队列。数据库部分故障时，管理员看到业务操作成功，但系统永久缺少对应审计证据。

不建议简单改成“审计失败就把已完成的业务操作返回失败”，这会造成假失败和重复操作。应根据业务一致性要求设计可靠写入。

**修复建议**：

1. 最低基线：记录结构化错误日志，带 request ID、action、object ID，并增加 `audit_write_failures_total` 指标和系统告警。
2. 对权限、用户、备份恢复、证书、通知和 APM 设置等高风险变更，优先使用同事务审计或 transactional outbox。
3. 增加故障注入测试，验证审计库不可用时不会无声丢失，且不会向客户端返回误导性的状态。

**验收条件**：任一 `audits.Record` 失败都能在日志/指标/告警中定位；关键变更最终可补写或与业务事务共同回滚。

### UI-01 [Medium] 详情入口缺少键盘语义，双击交互使用过多

**类别**：Accessibility / Interaction / Discoverability  
**WCAG**：2.1.1 Keyboard、2.4.4 Link Purpose、4.1.2 Name, Role, Value  
**位置（代表）**：

- `web/src/pages/protection-policies/ProtectionPoliciesPage.tsx:264`
- `web/src/pages/applications/ApplicationsPage.tsx:228`
- `web/src/pages/waf-rules/WafRulesPage.tsx:197`
- `web/src/pages/exceptions/ExceptionsPage.tsx:264`
- `web/src/pages/certificates/CertificatesPage.tsx:150`
- `web/src/pages/custom-rules/CustomRulesPage.tsx:257`
- `web/src/pages/security-events/EventDetailDrawer.tsx:450`

**证据**：6 处 `<a onClick>` 没有 `href`，默认不能通过 Tab 获得正确链接语义；相关事件列表把点击处理器挂在 `List.Item` 上，也没有 `role`、`tabIndex` 或键盘处理。另有 **98 个页面文件、123 个 `onDoubleClick` 处理器**。双击可以保留为快捷操作，但它不可发现，也不能成为查看详情的唯一入口。

APM 新页面同样包含 7 处双击详情入口：依赖、例外、Agent、端点、SLO、SQL、诊断页面。

**修复建议**：

1. 页面跳转使用 React Router `Link`；打开 Drawer/Modal 使用 Ant Design `Button type="link"`。
2. 每张可查看详情的表格提供可见的“查看”操作；双击只作为附加快捷操作。
3. 若整行可交互，统一封装 `onRow`，补 `tabIndex=0`、合理的 `role`，并处理 Enter/Space；同时避免与行内按钮事件冲突。
4. 加入 axe 或 Playwright 键盘巡检，覆盖登录后主要菜单和 APM 页面。

**建议后续命令**：`$normalize` 统一表格详情入口，`$harden` 补可访问性测试。

### UI-02 [Medium] 管理布局没有移动端导航模式

**类别**：Responsive layout / Navigation  
**WCAG**：1.4.10 Reflow  
**位置**：`web/src/layouts/AdminLayout.tsx:214-315`

**证据**：布局只有桌面侧栏的 `collapsed` 状态。`Sider` 没有 `breakpoint`、`collapsedWidth={0}`、窄屏 Drawer 或移动端菜单按钮；Header 还固定使用 24px 水平内边距。在 320–768px 宽度下，侧栏会持续占用 80px 或 200px，压缩表格、筛选器和详情内容。

**修复建议**：在 `<768px` 使用 Drawer 导航和明确的菜单按钮；Header、内容区和筛选器使用断点间距；表格允许横向滚动但关键操作保持可见。至少验证 320、375、768、1024 和 1440px。

**建议后续命令**：`$adapt` 完成断点方案，`$polish` 做最终对齐和间距复核。

### UI-03 [Medium] 所有通用 ECharts 图表缺少可访问名称和数据替代

**类别**：Accessibility / Data visualization  
**WCAG**：1.1.1 Non-text Content、1.3.1 Info and Relationships  
**位置**：`web/src/components/EChart.tsx:14-64`

**证据**：通用封装只注册 Chart、Grid、Legend、Tooltip 和 CanvasRenderer，最终返回无语义的 `<div>`。未注册 ECharts `AriaComponent`，未启用 `aria` 配置，也没有 `role="img"`、可访问名称或数据表/文字摘要。安全态势、趋势和 APM 指标对屏幕阅读器用户不可读。

**修复建议**：

1. 封装增加必填的 `ariaLabel` 或 `summary`；容器设置合适的 role 和名称。
2. 注册 ECharts ARIA 组件并启用描述，但不要只依赖自动生成文案。
3. 对影响决策的图表提供同源数据摘要或可展开的数据表，包含时间范围、主要趋势、异常值和单位。

**验收条件**：关闭 Canvas 视觉信息后，用户仍能通过文字获得图表表达的核心结论和关键数值。

### DEP-01 [Low] React Router 锁定版本命中 High 公告，但当前代码路径不可达

**类别**：Dependency hygiene / Latent vulnerability  
**位置**：

- `web/package.json:33`
- `web/package-lock.json:5389-5420`
- `web/src/App.tsx:1-65`

**证据**：`npm audit --omit=dev` 报告 `react-router` / `react-router-dom` 7.18.1 命中 [GHSA-qwww-vcr4-c8h2](https://github.com/advisories/GHSA-qwww-vcr4-c8h2)，修复版本为 7.18.2。公告本身评为 High，但明确限定为使用 unstable RSC API 的应用。本项目使用 `BrowserRouter` 的 Vite SPA，代码搜索未发现 RSC API，因此本项目当前实际可利用性低；npm 的 2 个 High 计数是同一公告在直接与传递依赖上的展开，不是两个独立漏洞。

**修复建议**：把 `react-router-dom` 升至 `>=7.18.2` 并更新锁文件，运行 typecheck、单元测试和前端构建。升级成本低，也可恢复依赖门禁为全绿。

### UI-04 [Low] 应用详情返回按钮没有可访问名称

**类别**：Accessibility / Icon control  
**WCAG**：2.4.6 Headings and Labels、4.1.2 Name, Role, Value  
**位置**：`web/src/pages/applications/ApplicationDetailPage.tsx:84`

**证据**：返回按钮只有 `ArrowLeftOutlined` 图标，没有可见文本、`aria-label` 或 Tooltip。屏幕阅读器无法得知用途，新用户也只能猜测返回目标。

**修复建议**：增加 `aria-label="返回应用列表"` 和 Tooltip；空间允许时直接显示“返回应用列表”。

### UI-05 [Low] 详情页与二级页面的面包屑缺少对象上下文

**类别**：Information architecture / Wayfinding  
**WCAG**：2.4.8 Location（AAA，作为产品体验参考）  
**位置**：`web/src/layouts/AdminLayout.tsx:327-331`

**证据**：面包屑固定由“系统名 + 当前一级菜单”组成。应用详情、身份详情、攻击会话等页面不会显示对象名、会话 ID 或当前子页，用户进入深层页面后无法从面包屑判断具体对象，也不能逐级返回。

**修复建议**：由路由元数据生成层级，并允许详情页注入对象名称，例如“九章动态安全 / 应用管理 / 商城生产站点”。祖先节点应可点击，当前节点使用纯文本。

## 4. 系统性模式

### 4.1 安全基础设施存在重复实现

API 规范远程导入已经有完整 SSRF 防护，但通知模块重新使用了默认 HTTP 客户端。应把出口策略做成一个经过测试的公共组件，避免后续 AI 模型网关、Webhook、远程导入、升级源等能力各自实现一套。

### 4.2 业务成功与审计成功缺少明确一致性等级

51 处调用统一选择“忽略审计错误”，但没有区分普通查询配置、敏感权限变更和高风险运维动作。建议定义三级策略：同步同事务、outbox 最终一致、日志/指标兜底，并按对象风险选择。

### 4.3 UI 组件库缺少交互契约

页面大量复制表格 `onRow/onDoubleClick` 和伪链接写法，说明 `SmartTable`、详情入口和图表组件尚未把键盘、ARIA、移动端行为固化为默认能力。逐页修复成本高，也容易回归，应先修公共组件与页面模板。

### 4.4 桌面控制台假设贯穿布局

固定 Sider、密集筛选器和宽表格共同依赖桌面宽度。产品即使主要运行在桌面，也应支持平板巡检和窄窗口处置告警，否则值班场景会直接受影响。

## 5. 已有优点

- 四个 Go 模块的全量测试与 Vet 均通过；关键请求校验和错误处理总体明确。
- API 规范远程导入已有较完整的 SSRF 防护，可作为通知出口修复基线。
- 登出流程会清理 TanStack Query 缓存，降低共享浏览器跨账号数据残留风险。
- 通知配置使用严格 JSON 解码并对密值加密/脱敏，问题集中在目标地址边界而非凭据落库。
- APM CSR 在令牌消费前完成解析，已有“无效输入不烧令牌”的正确设计意识，但尚未覆盖整个注册链。
- UI 颜色、状态标签和安全产品信息密度整体一致，没有明显的装饰性视觉噪声。

## 6. 修复优先级

### P0：立即修复

1. `SEC-01` 通知出口 SSRF。
2. `BUG-01` APM Agent 注册事务化。

### P1：本迭代完成

1. `OBS-01` 审计失败可观测与可靠投递。
2. `UI-01` 键盘可达的详情入口，优先应用、证书、策略、安全事件和全部 APM 页面。
3. `UI-02` 移动端导航与窄屏布局。

### P2：随后完成

1. `UI-03` 图表 ARIA 与数据替代。
2. `DEP-01` React Router 升级至 7.18.2 或更高兼容版本。
3. `UI-04` 图标按钮名称。
4. `UI-05` 路由化面包屑。

## 7. 与上一轮审计的关系

上一轮 `docs/evidence/code-review-2026-09-05.md` 已记录以下设计级遗留，本报告不重复计入 9 个新发现：

- `HIGH-14`：hostctl 标志共享密钥签名验真仍待增强。
- `MED-11`：AI 高成本任务每日配额没有强制点。
- `MED-23`：离线包只有哈希校验，缺少发布签名真实性验证。
- `MED-5`：移除 behavior_store 后，进程级 Valkey 注入可能残留到重启或下次装配。
- `LOW-S10`：AI 输入/输出 Token 限制没有完整贯穿调用链。
- `LOW-G3`：XFF overwrite 的部分默认值仍未统一。

其中 hostctl 请求真实性和离线包签名仍属于发布前应有明确处置计划的安全债务。

## 8. 验证记录

| 命令 | 结果 |
|---|---|
| `cd server && go test ./...` | 通过；沙箱首次因本地监听限制失败，允许本地测试监听后全量通过 |
| `cd server && go vet ./...` | 通过 |
| `cd gateway && go test ./... && go vet ./...` | 通过 |
| `cd gateway/dynamic_security && go test ./... && go vet ./...` | 通过 |
| `cd wdsp-agent && go test ./... && go vet ./...` | 通过 |
| `cd web && npm run typecheck` | 通过 |
| `cd web && npm run lint` | 通过 |
| `cd web && npm run test` | 未执行到用例：现有 `node_modules` 缺少 Rollup 的 Darwin x64 可选包 `@rollup/rollup-darwin-x64` |
| `cd web && npm audit --omit=dev --json` | 发现同一 React Router 公告在直接/传递依赖上的 2 个 High 记录；本项目未使用受影响的 RSC 路径 |
| 私钥/AWS Key 特征扫描 | 只命中测试夹具和证书输入文案，未发现可确认的生产凭据 |
| Dockerfile/Compose `latest` 标签扫描 | 未发现命中 |

## 9. 审计限制

- 当前工作树有大量未提交改动，本报告反映的是审计时工作区状态，不代表 `3c73774` 提交本身。
- 前端 Vitest 因本机可选依赖缺失未实际运行；typecheck 和 lint 已通过。
- 未安装 `govulncheck`，本轮没有对 Go 依赖执行官方漏洞数据库扫描。
- 未连接真实 PostgreSQL、Valkey、ClickHouse、SMTP、Webhook 或多节点环境，未执行生产网络渗透、浏览器视觉回归、性能压测和故障切换演练。

## 10. 建议复验命令

修复后至少执行：

```bash
cd server && go test ./... && go vet ./...
cd ../gateway && go test ./... && go vet ./...
cd dynamic_security && go test ./... && go vet ./...
cd ../../wdsp-agent && go test ./... && go vet ./...
cd ../web && npm run typecheck && npm run lint && npm run test && npm run build
npm audit --omit=dev
```

前端补充 Playwright 场景：

1. 只用键盘完成菜单导航、打开表格详情、关闭 Drawer/Modal 和返回列表。
2. 在 320、375、768、1024、1440px 下检查菜单、筛选器、表格操作列和详情页。
3. 使用 axe 扫描登录、首页、安全事件、应用管理及全部 APM 页面。
4. 为关键图表校验可访问名称、文字摘要和数据表内容与图形数据一致。
