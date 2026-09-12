# 九章WAF 安全管理员手册

适用角色：安全管理员（SECURITY_ADMIN）
版本：九章WEB应用智能防护系统 V2.0（阶段6 交付版）

## 1. 职责范围

安全管理员负责 WAF 业务防护全量工作：应用接入与配置发布、防护策略与规则、例外策略、IP 黑白名单与 CC 防护、临时封禁、安全事件处置、安全态势与统计分析、安全报告，以及可信代理与保护地址的维护。

**不可做**（三权边界）：用户/角色管理、系统设置、备份恢复、系统升级、交付检查执行（属系统管理员）；操作审计、登录日志查看（属审计管理员）。对应菜单不展示，API 返回 403。

登录后可见菜单：工作台、应用防护（Web 应用 `/applications`、HTTPS 证书 `/certificates`、配置发布 `/config-publish`、配置版本 `/config-versions`、网关状态 `/gateway-status`）、WAF 策略（防护策略 `/protection-policies`、WAF 规则 `/waf-rules`、自定义规则 `/custom-rules`、例外策略 `/exceptions`）、访问控制（可信代理 `/trusted-proxies`、IP 黑白名单 `/access-rules`、CC 防护 `/rate-limit`、临时封禁 `/temporary-blocks`、访问控制事件 `/access-control-events`）、事件中心（安全事件 `/security-events`、事件统计 `/event-statistics`）、安全态势（安全总览 `/security-overview`、统计分析 `/analytics`、系统告警 `/system-alerts`）、报表中心（报告任务 `/reports`、报告模板 `/report-templates`、报告归档 `/report-archives`）、个人中心。

## 2. 应用接入与发布

### 2.1 接入 Web 应用（`/applications`）

1. 新建应用：填写应用编码（格式前后端一致校验）、名称、防护模式（Off 转发 / DetectionOnly 仅检测 / On 阻断），`POST /api/v1/applications`。
2. 应用详情"域名"Tab：添加域名（禁协议/路径/端口，泛域名仅 `*.` 前缀），配置 HTTP/HTTPS 端口与跳转，`POST /api/v1/applications/{id}/domains`。
3. "源站"Tab：添加源站（地址/权重/健康检查/TLS 参数），`POST /api/v1/applications/{id}/upstreams`；用"连通性测试"（`POST /api/v1/upstreams/test`）分阶段验证 DNS/TCP/TLS/HTTP，私网地址需显式允许（SSRF 防护）。
4. "证书"Tab：绑定证书（`POST /api/v1/applications/{id}/certificate`），证书先在 `/certificates` 上传。
5. 应用支持复制（`POST /api/v1/applications/{id}/copy`）、启停（`/enable`、`/disable`）、编辑（乐观锁）、删除（二次确认）。

### 2.2 配置发布（`/config-publish`）

1. 预览：`POST /api/v1/gateway-config/preview`，确认变更差异。
2. 校验：`POST /api/v1/gateway-config/validate`。
3. 发布：`POST /api/v1/gateway-config/publish`（二次确认 + 幂等键），任务进度轮询 `GET /api/v1/publish-tasks/{id}`。发布失败自动保持旧配置（失败保护），并产生 CONFIG_PUBLISH_FAILED 告警。
4. 回滚：`/config-versions` 选历史版本回滚（`POST /api/v1/config-versions/{id}/rollback`），版本差异对比 `GET /api/v1/config-versions/{id}/diff`。
5. 发布结果在「网关状态」（`/gateway-status`，`GET /api/v1/gateway/status`）核对版本与哈希。

## 3. 防护策略与规则

### 3.1 防护策略（`/protection-policies`）

- 内置三套模板：宽松（relaxed）/ 标准（standard）/ 严格（strict），内置策略不可改删，可复制后调整（`POST /api/v1/protection-policies/{id}/copy`）。
- 自建策略：`POST /api/v1/protection-policies`；编辑 `PUT /api/v1/protection-policies/{id}`（乐观锁）；查看绑定应用 `GET /api/v1/protection-policies/{id}/applications`。
- 策略要素：CRS 规则启停、异常评分阈值、检测模式；规则覆盖优先级为 应用级 > 策略级 > 默认。

### 3.2 WAF 规则（`/waf-rules`）

- 规则元数据来自 CRS 4.28.0（622 条入库），支持多条件筛选与详情查看（`GET /api/v1/waf-rules`、`GET /api/v1/waf-rules/{rule_id}`）。
- CRS 升级后执行"手动同步"（`POST /api/v1/waf-rules/sync`），系统按内容哈希检测变更。

### 3.3 自定义规则（`/custom-rules`）

- 结构化表单编辑（操作符/变量/动作白名单），自动生成 SecLang，规则 ID 段 7100000+。
- 危险内容（exec/命令替换/文件读取等）在保存校验（`POST /api/v1/custom-rules/{id}/validate`）时拦截。
- 创建 `POST /api/v1/custom-rules`，启停 `POST /api/v1/custom-rules/{id}/enable|disable`。

### 3.4 例外策略（`/exceptions`）

- 类型：精确例外（推荐）、临时例外（到期自动失效）、宽泛例外（强制风险确认）。
- 创建 `POST /api/v1/exceptions`，启停 `POST /api/v1/exceptions/{id}/enable|disable`，删除 `DELETE /api/v1/exceptions/{id}`。
- 启用中的例外随策略发布生成 ctl 规则置于 CRS 之前生效；可从安全事件一键创建例外草稿（见 6.2）。

## 4. 黑白名单、CC 与封禁

### 4.1 IP 黑白名单（`/access-rules`）

- 规则要素：黑/白、全局/应用级、IP/CIDR（IPv4/IPv6）、时间窗（临时规则到期自动失效）。
- 评估顺序（网关强制）：全局白 → 应用白 → 全局黑 → 应用黑；白名单绕过黑名单与 CC，但不绕过 WAF 检测。
- CRUD：`POST /api/v1/access-rules` 新建，`PUT/DELETE /api/v1/access-rules/{id}` 改删；临时规则延期 `POST /api/v1/access-rules/{id}/extend`、解除 `POST /api/v1/access-rules/{id}/release`、复制 `POST /api/v1/access-rules/{id}/copy`。
- 批量导入：`POST /api/v1/access-rules/import`（≤1MB/10000 行，行级错误定位，支持 dry_run 预览与 ALL_OR_NOTHING/SKIP_ERRORS）；导出 `GET /api/v1/access-rules/export`（公式注入已转义）。
- 修改后发布生效：`POST /api/v1/access-rules/publish`；历史版本 `GET /api/v1/access-control/versions`，回滚 `POST /api/v1/access-control/versions/{id}/rollback`。

### 4.2 CC 防护（`/rate-limit`）

- 策略要素：统计维度（IP/URI）、窗口与阈值、触发动作（限速 429 / 自动封禁）、封禁时长；限速响应 429 + Retry-After + X-Jiuzhang-Request-ID，不泄露内部信息。
- CRUD：`POST /api/v1/rate-limit-policies` 新建，`PUT/DELETE /api/v1/rate-limit-policies/{id}` 改删；保存校验 `POST /api/v1/rate-limit-policies/{id}/validate`（零窗口/负阈值/危险正则被拒）。
- 干跑模拟：`POST /api/v1/rate-limit-policies/{id}/test`，上线前评估影响。
- 发布生效：`POST /api/v1/rate-limit-policies/publish`。Valkey 故障时按 GUARD_FAIL_OPEN 配置 Fail-open 或 Fail-closed（随发布下发）。

### 4.3 临时封禁（`/temporary-blocks`）

- 列表展示自动封禁与人工封禁记录（`GET /api/v1/temporary-blocks`）。
- 处置：解封 `POST /api/v1/temporary-blocks/{id}/release`、延期 `POST /api/v1/temporary-blocks/{id}/extend`、转永久黑名单 `POST /api/v1/temporary-blocks/{id}/convert-to-permanent`。
- 到期封禁由调度每分钟自动标记 EXPIRED；保护地址永不封禁（尝试封禁返回 400 并记高风险审计）。

### 4.4 访问控制事件（`/access-control-events`）

查看黑白名单命中、CC 限速、封禁等 8 类事件（`GET /api/v1/access-control-events`），支持详情（`/{id}`）与 CSV 导出（`/export`），Request ID 可与安全事件、网关日志关联。

## 5. 可信代理与保护地址（`/trusted-proxies`）

- 维护可信代理（地址 + 头类型），仅可信代理的代理头才被采信，伪造 XFF 一律忽略并按连接源处理。
- 命中测试：`POST /api/v1/trusted-proxies/test`，验证多级代理链下的真实 IP 识别。
- 保护地址 Tab：`POST /api/v1/protected-addresses/refresh` 刷新系统地址；保护地址不被封禁、不被黑名单命中。

## 6. 事件处置

### 6.1 安全事件（`/security-events`）

- 列表：按时间/攻击类型/风险等级/动作/处置状态/域名/来源 IP 筛选（`GET /api/v1/security-events`）；详情抽屉含脱敏后的请求摘要与匹配规则（`GET /api/v1/security-events/{id}`）；相关事件 `GET /api/v1/security-events/{id}/related`。
- 导出：`GET /api/v1/security-events/export`（CSV，限速 5 次/分钟）。

### 6.2 处置动作（均为 `POST /api/v1/security-events/{id}/...`）

| 动作 | 路径 | 用途 |
|------|------|------|
| 标记分析中 | `/mark-analyzing` | 接手研判 |
| 确认攻击 | `/confirm-attack` | 研判为真实攻击 |
| 确认误报 | `/confirm-false-positive` | 研判为误报，进入误报处理流程 |
| 忽略 | `/ignore` | 噪声事件 |
| 解决 | `/resolve` | 处置闭环 |
| 添加备注 | `/notes` | 研判过程留痕 |
| 一键建例外 | `/create-exception` | 由事件生成精确例外草稿 |

### 6.3 误报处理流程

1. 事件详情核对匹配规则与请求样本，确认为误报后执行"确认误报"。
2. 用"一键建例外"生成精确例外草稿，在 `/exceptions` 核对范围（优先精确例外，避免宽泛例外）。
3. 启用例外并发布配置，回放原请求验证不再命中。
4. 事件标记"解决"；周期性在"事件统计"复查该规则误报率，必要时调整策略规则开关。

## 7. 安全态势与统计分析

- **安全总览**（`/security-overview`）：`GET /api/v1/dashboard/security-overview`，今日请求/攻击/阻断、趋势与分布概览。
- **统计分析**（`/analytics`）：请求趋势（`GET /api/v1/analytics/request-trend`）、安全事件趋势（`/security-event-trend`）、风险等级（`/risk-levels`）、攻击类型（`/attack-types`）、Top 来源 IP（`/top-source-ips`）、Top 应用（`/top-applications`）、Top 规则（`/top-rules`）、Top URI（`/top-uris`）、CC 概览（`/cc-overview`）、访问控制概览（`/access-control-overview`）。
- **事件统计**（`/event-statistics`）：今日/未处置/阻断计数与攻击类型、动作、处置状态分布。
- **系统告警**（`/system-alerts`）：安全管理员可查看安全相关告警并处置（确认/解决/备注）。

## 8. 报告生成（报表中心）

- **报告任务**（`/reports`）：创建日报/周报/月报/自定义报告（`POST /api/v1/reports`，report_type=DAILY/WEEKLY/MONTHLY/CUSTOM），后台 Worker 生成；列表 `GET /api/v1/reports`，失败可重试 `POST /api/v1/reports/{id}/retry`，预览 `GET /api/v1/reports/{id}/preview`，下载 `GET /api/v1/reports/{id}/download`（PDF），删除本人报告 `DELETE /api/v1/reports/{id}`。
- **报告模板**（`/report-templates`）：管理模板（`POST /api/v1/report-templates` 新建，`PUT/DELETE /api/v1/report-templates/{id}` 改删），内置模板不可改删。
- **报告归档**（`/report-archives`）：历史报告检索（`GET /api/v1/report-archives`）。
- 报告失败产生 REPORT_FAILED 告警，重跑即可。

## 9. 典型场景

**场景 A：新应用上线**
1. `/applications` 新建应用（模式先选 DetectionOnly）→ 配域名 → 配源站并连通性测试 → 绑证书。
2. `/protection-policies` 选择或复制一套策略绑定应用。
3. `/config-publish` 预览 → 校验 → 发布；`/gateway-status` 核对哈希。
4. 观察 1-3 天事件误报，处理例外后切换为 On 阻断模式并重新发布。

**场景 B：攻击研判**
1. `/security-overview` 发现攻击突增 → `/analytics` 定位 Top 来源 IP/URI/规则。
2. `/security-events` 筛选相关事件 → 标记分析中 → 查看相关事件与请求样本。
3. 确认攻击后：对来源建临时黑名单或转临时封禁；确认误报则走 6.3 流程。
4. 全部事件标记解决，必要时生成报告归档。

**场景 C：误报消除**
按 6.3 执行；宽泛例外必须填写风险确认理由，临时例外设置到期时间。

**场景 D：封禁处置**
1. `/temporary-blocks` 核对封禁来源（自动封禁关联 CC 策略）。
2. 误封：解封并将来源加入白名单或调优 CC 阈值（先干跑模拟）。
3. 确认恶意：延期或转永久黑名单，发布生效。
4. 在 `/access-control-events` 复查该 IP 后续命中情况。
