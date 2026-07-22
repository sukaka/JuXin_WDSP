# 报告系统设计（阶段6）

实现：`server/internal/reports/`（reports.go 模型 / collect.go 采集 / conclusions.go 结论 / render.go HTML / pdf.go PDF / generator.go 生成器 / files.go 文件安全 / store.go 仓储 / handler.go 接口）。

安全约束：统计内容全部来自聚合表与原始事件表，禁止 Mock；结论与建议由确定性模板规则生成，不使用任何 AI/随机判断；模板字段仅作为数据渲染，不执行代码、不发外部请求；报告不含未脱敏攻击载荷（仅统计与规则元数据）。

## 报告类型与时间范围

| 类型 | 时间范围（UTC，左闭右开，`ComputeTimeRange`） |
|------|----------------------------------------------|
| DAILY | 昨天全天 [今日0点-1天, 今日0点) |
| WEEKLY | 上周一至周日 [本周一0点-7天, 本周一0点) |
| MONTHLY | 上月 [本月1号0点-1月, 本月1号0点) |
| CUSTOM | 显式 RFC3339 起止，end>start，跨度 ≤366 天 |

导出格式：`html`（默认）/ `pdf`。

## 任务状态机

`PENDING → COLLECTING(10%) → AGGREGATING(40%) → RENDERING(70%) → SUCCESS(100%)`
任意阶段失败 → `FAILED`（记录 `failure_code`/`failure_message`）；`FAILED`/`CANCELLED` 可经 retry 重置为 `PENDING` 重排队。

失败码：`COLLECT_FAILED` / `RENDER_FAILED` / `WRITE_FAILED` / `FILE_TOO_LARGE` / `TIMEOUT` / `FONT_UNAVAILABLE` / `TEMPLATE_NOT_FOUND` / `INVALID_STATE`。

## 21 章节结构

章节键（`sections` JSONB 开关同名，未显式关闭即启用）：

cover 封面 / period 报告周期 / scope 报告范围 / summary 管理摘要 / traffic 请求流量 / events_overview 安全事件总览 / risk_level 风险等级 / attack_types 攻击类型分布 / attack_trend 攻击趋势 / source_ips 攻击源IP TOP10 / applications 被攻击应用 TOP10 / rule_hits 命中规则 TOP10 / cc_protection CC防护 / ip_lists 黑白名单 / disposition 事件处置 / false_positives 误报和例外 / upstream_health 源站健康 / certificates 证书状态 / publish_tasks 策略发布 / system_health 系统运行 / conclusions 结论和建议

## 数据采集源（Collector.Collect）

| 章节 | 数据源 |
|------|--------|
| 报告范围 | `applications`（可按 application_ids 过滤） |
| 请求流量 | 聚合表 `http_requests_total`（跨度 >7 天用天表，否则小时表） |
| 事件总览/风险/类型/趋势/源IP/应用 | `security_events`（攻击趋势按 >2 天 date_trunc 'day' 否则 'hour'） |
| 命中规则 | `security_event_matches` JOIN `security_events`（仅 rule_id/名称/次数，名称截断 200） |
| CC/黑白名单 | `access_control_events` 按 event_type 计数 |
| 事件处置/误报 | `security_events.disposition_status`、`exception_policies` 新建数 |
| 源站健康 | `upstreams` + 最新 `upstream_health_records`（LATERAL，限 50） |
| 证书状态 | `certificates`（限 50，剩余天数由 not_after 计算） |
| 策略发布 | `gateway_publish_tasks`（计数 + 最近 10 条，摘要截断 200） |
| 系统运行 | `system_health_snapshots` 每组件最新（窗口放宽至起点前 24h） |

风险等级确定性推导（`computeRiskLevel`）：无事件 → LOW；有高危且零阻断 → CRITICAL；高危 >100 或占比 >30% → HIGH；有高危或事件 >1000 → MEDIUM；否则 LOW。

## 结论与建议（确定性规则）

`BuildConclusions`：事件总量/阻断率/高危占比/主要攻击类型/最活跃源IP/CC 触发/攻击请求占比/综合风险等级，按固定顺序拼接。

`BuildSuggestions` 8 条规则（固定顺序，独立评估，全不命中给默认建议）：

| # | 触发条件 | 建议要点 |
|---|----------|----------|
| 1 | 阻断率 <50% 且有事件 | 观察模式切阻断模式并复核策略 |
| 2 | 主要攻击类型占比 ≥30% | 按类型定向建议（SQL注入/XSS/命令注入/路径穿越/RCE 各有专用文案，其余通用） |
| 3 | 未处置事件占比 >30% | 安全管理员及时分析处置 |
| 4 | 存在确认误报 | 复核例外策略匹配条件 |
| 5 | CC 触发阈值但拦截数为 0 | 检查 CC 策略动作配置 |
| 6 | 证书剩余 ≤30 天 | 尽快更新与绑定（逐张列出） |
| 7 | 源站 DOWN/DEGRADED | 检查源站可用性与健康检查（逐个列出） |
| 8 | 发布失败 >0 | 检查网关状态并重新发布 |

## 异步执行（Worker）

- `Generator.Run` 每 2s 轮询；`ClaimPending` 用 `SELECT ... FOR UPDATE SKIP LOCKED` 原子认领一个 PENDING 任务并置 COLLECTING，多实例/重复执行安全。
- 单任务超时 5 分钟（`GenerateTimeout`）；超时归入 `TIMEOUT` 失败码。
- 生成流程：加载任务（状态校验）→ 采集 → 模板与报告编号（`NextMonthlySeq` 月内序号）→ 渲染 → 写文件 → `CompleteJob` 记录产物。
- 报告编号：模板 `report_no_format`（默认 `JZ-{YYYYMM}-{SEQ}`），`{SEQ}` 至少 4 位补零。

## 文件安全

- 文件名固定 `report-{uuid}.{html|pdf}`（正则严格匹配），存放 `GATEWAY_DATA_DIR/reports/`（目录 0750，文件 0600）；`reportPath` 二次校验防路径穿越。
- 大小上限 20MB（渲染产物与文件双重检查，超限 `FILE_TOO_LARGE`）；生成时长上限 5 分钟。
- 写入时计算 sha256 存 `file_hash`；下载前重新计算比对，不一致拒绝。
- 下载归属校验：仅创建者本人或持 `reports.download_audit` 权限者；删除仅本人（`reports.delete_own`），删记录同时清理文件。
- 预览（HTML）响应头强制 `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'`。
- 创建/重试/下载/删除/模板增删改均写操作审计（模块 `reports`）。

## HTML 渲染

固定内置 Go 模板（`html/template`），模板字段全部自动转义；CSS 全部内联，无任何外部资源/脚本/请求；章节按 `Tpl.Show(key)` 开关渲染，时间统一 UTC 格式。

## PDF 渲染

gofpdf v2 + 内嵌中文字体 `NotoSansCJKsc-VF.ttf`（OFL 1.1；gofpdf 不支持 CFF OTF 故用可变 TTF）。降级链：

1. `REPORT_FONT_PATH` 或候选路径（`assets/fonts/`、`server/assets/fonts/`、`/app/assets/fonts/`）找到字体 → 完整中文 PDF；
2. 字体文件缺失/不可读 → 降级 ASCII 摘要 PDF，页面注明使用 HTML 导出查看完整报告（`tr` 剔除非 ASCII 字符）；
3. 字体存在但解析失败 → 任务失败，`FONT_UNAVAILABLE`。

表格行数受限（趋势最多 31/62 行后省略号），单元格截断防超长。

## 接口与权限

| 接口 | 权限 |
|------|------|
| GET/POST /api/v1/report-templates，GET/PUT/DELETE /{id} | 读：`report_templates.manage`/`reports.read`/`reports.create` 任一；写：`report_templates.manage` |
| GET /api/v1/reports，GET /{id}，GET /api/v1/report-archives | `reports.read` 或 `reports.read_audit` |
| POST /api/v1/reports，POST /{id}/retry | `reports.create` |
| GET /api/v1/reports/{id}/preview | `reports.read` 或 `reports.read_audit` |
| GET /api/v1/reports/{id}/download | `reports.download` 或 `reports.download_audit`（+归属校验） |
| DELETE /api/v1/reports/{id} | `reports.delete_own`（仅本人） |

## 验证

- 单测 `reports_test.go`：时间范围计算、编号格式化、结论/建议规则确定性、模板校验、文件名校验、状态机流转。
- 端到端：创建 DAILY 任务 → Worker 生成 → 进度推进至 SUCCESS → 下载校验 sha256 与审计记录；字体缺失环境验证 PDF 降级页。
