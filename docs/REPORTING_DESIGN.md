# 报告系统设计（阶段6）

实现：`server/internal/reports/`（reports.go 模型 / collect.go 采集 / conclusions.go 结论 / render.go HTML / pdf.go PDF / charts.go 图表 / docx.go Word / generator.go 生成器 / files.go 文件安全 / store.go 仓储 / handler.go 接口）。

安全约束：统计内容全部来自聚合表与原始事件表，禁止 Mock；结论与建议由确定性模板规则生成，不使用任何 AI/随机判断；模板字段仅作为数据渲染，不执行代码、不发外部请求；报告不含未脱敏攻击载荷（仅统计与规则元数据）。

## 报告类型与时间范围

| 类型 | 时间范围（UTC，左闭右开，`ComputeTimeRange`） |
|------|----------------------------------------------|
| DAILY | 昨天全天 [今日0点-1天, 今日0点) |
| WEEKLY | 上周一至周日 [本周一0点-7天, 本周一0点) |
| MONTHLY | 上月 [本月1号0点-1月, 本月1号0点) |
| CUSTOM | 显式 RFC3339 起止，end>start，跨度 ≤366 天 |

导出格式：`html`（默认）/ `pdf` / `docx`（Word）。

纸张方向（`page_orientation`，迁移 000086）：PDF/Word 可选 `P` 竖向 A4（默认）/ `L` 横向 A4。PDF 版宽、列宽、图表嵌入尺寸、页底触发线随方向缩放（横向版宽 277mm）；Word 经 `sectPr` 设置横向页面，图表嵌入尺寸同步放大；HTML 忽略该选项。

内容范围（`content_scope`，迁移 000082）：报告类型固定 DAILY/WEEKLY/MONTHLY/CUSTOM，内容范围独立选择 `WAF`（仅上篇）/ `API`（仅下篇）/ `WAF_API`（全部，缺省；空值为历史任务兼容语义）。`WAF` 采集与渲染均跳过 API 部分；`API` 只采集应用范围 + API 合并数据，渲染时 Web 内容章节经 `tplForScope` 整体关闭（封面/周期/范围/结论等元章节保留），分隔标题改为「API 动态防护」；结论区按范围裁剪。范围含 API 但环境未启用 API 动态防护时创建接口返回 400。API 域专项类型（API_ASSET/RISK/WEAK/SENS）保留接口兼容（不再出现在前端类型选择）。

## 任务状态机

`PENDING → COLLECTING(10%) → AGGREGATING(40%) → RENDERING(70%) → SUCCESS(100%)`
任意阶段失败 → `FAILED`（记录 `failure_code`/`failure_message`）；`FAILED`/`CANCELLED` 可经 retry 重置为 `PENDING` 重排队。

失败码：`COLLECT_FAILED` / `RENDER_FAILED` / `WRITE_FAILED` / `FILE_TOO_LARGE` / `TIMEOUT` / `FONT_UNAVAILABLE` / `TEMPLATE_NOT_FOUND` / `INVALID_STATE`。

## 37 章节结构（上篇 Web 防护 26 节 + 下篇 API 动态防护 11 节）

章节键（`sections` JSONB 开关同名，未显式关闭即启用）。正文标题按实际展示章节自动中文编号（一、二、三……，关闭的章节不占号）。

上篇：cover 封面 / period 报告周期 / scope 报告范围 / summary 管理摘要 / comparison 环比对比 / traffic 请求流量 / events_overview 安全事件总览 / risk_level 风险等级 / attack_types 攻击类型分布 / attack_trend 攻击趋势 / attack_hours 攻击时段分布 / source_ips 攻击源IP TOP10 / source_geo 攻击源地区 TOP10 / applications 被攻击应用 TOP10 / target_paths 被攻击路径 TOP10 / rule_hits 命中规则 TOP10 / event_samples 高危事件明细 TOP20 / cc_protection CC防护 / ip_lists 黑白名单 / disposition 事件处置 / false_positives 误报和例外 / upstream_health 源站健康 / certificates 证书状态 / publish_tasks 策略发布 / system_health 系统运行

下篇（WDSP 且 API 动态防护开启时输出，约占报告内容 40%，篇章分隔页「下篇：API 动态防护」起始）：api_overview API 资产总览 / api_new_endpoints 新增 API TOP20 / api_shadow Shadow API 清单 / api_risk API 风险发现 / api_risk_dist 发现类型与严重度分布 / api_risk_top 风险API TOP10 / api_subjects 风险主体 TOP10 / api_weakness API 弱点整改 / api_weak_overdue 超期未修清单 / api_sensitive API 敏感数据 / api_sensitive_top 涉敏API TOP10

下篇门控：`product.Load().APIDynamicProtectionEnabled()`（WAF edition 恒不输出）；结论区追加「API 安全结论/建议」子块（四类规则各取首条合并）。

站点过滤：主报告与 API 域专项报告（API_ASSET/API_RISK/API_WEAK/API_SENS）共用 `application_ids`——API类按 `api_endpoints.application_id` 直接过滤，发现/弱点/敏感字段经API关联（JOIN 或 `endpoint_id IN (SELECT ...)`）过滤，可单独出具一个或多个站点的报告。

全量资产清单（`include_api_assets`，迁移 000084）：创建报告/定时计划可选开启，报告范围清单每站点附API总数（合计行收尾）；下篇增加「API 资产清单（全量）」章节——方法/路径/用途分类（`api_classification_dimensions` PURPOSE 维关联中文名）/资产状态/影子·僵尸标记（影子=存在未关闭 SHADOW 发现、僵尸=asset_status=ZOMBIE，标红）/命中次数，按命中降序上限 500 条（超出注明总数）。

## 数据采集源（Collector.Collect）

| 章节 | 数据源 |
|------|--------|
| 报告范围 | `applications`（可按 application_ids 过滤） |
| 请求流量 | 聚合表 `http_requests_total`（跨度 >7 天用天表，否则小时表） |
| 环比对比 | 上一等长周期同口径事件与流量（`security_events` + 聚合表） |
| 事件总览/风险/类型/趋势/源IP/应用 | `security_events`（攻击趋势按 >2 天 date_trunc 'day' 否则 'hour'） |
| 攻击时段分布 | `security_events` EXTRACT(HOUR) 0-23 时计数（高峰时段文案） |
| 攻击源地区 | `security_events` 去重源IP（前 200）经 GeoIP（`apigeo` MMDB，`GATEWAY_DATA_DIR/geoip/country.mmdb`）聚合国家码，余量归「其他」；MMDB 缺失时整节降级「未启用」占位 |
| 被攻击路径 | `security_events.request_path`（目标路径，不含查询串与载荷，截断 80） |
| 高危事件明细 | `security_events` 元数据 TOP20（高危优先、时间倒序；时间/源IP/应用/方法/路径/类型/严重度/动作，无查询串与载荷） |
| 命中规则 | `security_event_matches` JOIN `security_events`（仅 rule_id/名称/次数，名称截断 200） |
| CC/黑白名单 | `access_control_events` 按 event_type 计数 |
| 事件处置/误报 | `security_events.disposition_status`、`exception_policies` 新建数 |
| 源站健康 | `upstreams` + 最新 `upstream_health_records`（LATERAL，限 50；记录由 runtimehealth 采集器每 30s 探测启用健康检查的 HTTP 源站写入，保留 7 天、每小时节流清理；无记录时按 `health_check_enabled` 区分「未启用/未知」） |
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

## 展示文案中文化（i18n.go）

采集层保持英文枚举词表（与数据库/网关一致），三种格式渲染时统一经 i18n.go 映射为中文展示：报告类型（日报/周报/月报/自定义/API 域报告名）、严重度（严重/高危/中危/低危）、处置状态、源站与组件状态（正常/故障/降级/未启用/未知）、证书状态、发布任务类型与状态、API 发现类型（影子API/僵尸API/越权等）。词表与前端 utils `*_META` 标签一致。命中规则 TOP10 的 CRS 英文规则名加中文攻击类别前缀（按 CRS 规则 ID 段映射，如【SQL注入】【XSS跨站脚本】），保留英文原名便于对照规则文档；自研中文规则名原样展示。

## 关注项红色高亮（attention.go）

需要用户立即关注的数据点，三种格式统一红色加粗（`#D83931`，与风险徽章同色）。判定为确定性规则，与 BuildSuggestions 建议规则同口径：

| 位置 | 标红条件 |
|------|----------|
| 管理摘要：高危及以上事件 | >0 |
| 管理摘要/风险等级：风险等级 | HIGH/CRITICAL |
| 安全事件总览：阻断率 | 有事件且 <50% |
| 管理摘要/CC防护：CC拦截 | 阈值触发 >0 且拦截 =0 |
| 严重度分布表 | HIGH/CRITICAL 行 |
| 源站健康表 | DOWN/DEGRADED 行 |
| 证书状态表 | 剩余天数 ≤30（含已过期）行 |
| 策略发布：失败 | >0 |
| 系统运行表 | DEGRADED/DOWN 行（UNKNOWN 不标） |
| API 资产：Shadow未关闭 / 僵尸API | >0 |
| API 风险：当前未关闭 | >0 |
| API 弱点：超期未闭环 / 复测失败 | >0 |

实现：HTML 用 `.warn` span（模板函数 `warn`）；PDF 用 `tableMarked`/`warnLine`（CJK 字体同文件注册 B 样式，gofpdf 不合成粗体，红色为主强调）；Word 用 `tableMarked`/`warnLine`（Run 红色+加粗）。

## 定时报告与邮件发送（迁移 000083）

`report_schedules` 计划：每天/每周/每月固定时刻（`time_of_day` UTC；WEEKLY 加 `day_of_week` 1-7，MONTHLY 加 `day_of_month` 1-28 防月末歧义），可选开启邮件发送到 1~10 个邮箱。仅支持 DAILY/WEEKLY/MONTHLY（CUSTOM 不支持定时）；内容范围/应用范围/模板/格式与手工创建同校验；范围含 API 同样受环境门控。

- 调度器（`scheduler.go`，30s 轮询）：`ClaimDueSchedules` 经 `FOR UPDATE SKIP LOCKED` 原子认领一个到期计划并推进 `next_run_at`（`NextRunAt` 纯函数，跨周/跨月正确）；按创建者身份创建报告任务（`report_jobs.schedule_id` 回链），写 `schedule_fire` 审计。进程重启后到期计划自然在下一轮被拾取。
- 邮件（`scheduler_mail.go` + `notify.SendMail`）：`CompleteJob` 成功后，计划任务且开启邮件 → 读首个启用的 SMTP 通知渠道配置（`ListDecrypted` + `ParseSMTPConfig`，密码加密落库不变）→ 以**磁盘上已校验的产物文件**为附件发送（MIME multipart/mixed，QEncoding 主题，base64 折行）。未配置渠道/发送失败仅记录 `last_email_status=FAILED` 与原因（界面可见）并写 `email_send` 审计，**不回滚报告任务**。
- 接口（读 `reports.read`/`read_audit`，写 `reports.create`）：`GET/POST /api/v1/report-schedules`、`GET/PUT/DELETE /{id}`、`POST /{id}/run-now`（标记到期立即触发，联调用）；CRUD/run_now/email_send 均审计。
- 时区：全部 UTC（界面明确标注）。邮箱格式校验、≤10 个；SMTP 配置只读复用（在 系统告警→通知渠道 维护）。

## 异步执行（Worker）

- `Generator.Run` 每 2s 轮询；`ClaimPending` 用 `SELECT ... FOR UPDATE SKIP LOCKED` 原子认领一个 PENDING 任务并置 COLLECTING，多实例/重复执行安全。
- 单任务超时 5 分钟（`GenerateTimeout`）；超时归入 `TIMEOUT` 失败码。
- 生成流程：加载任务（状态校验）→ 采集 → 模板与报告编号（`NextMonthlySeq` 月内序号）→ 渲染 → 写文件 → `CompleteJob` 记录产物。
- 报告编号：模板 `report_no_format`（默认 `JZ-{YYYYMM}-{SEQ}`），`{SEQ}` 至少 4 位补零。

## 文件安全

- 文件名固定 `report-{uuid}.{html|pdf|docx}`（正则严格匹配），存放 `GATEWAY_DATA_DIR/reports/`（目录 0750，文件 0600）；`reportPath` 二次校验防路径穿越。
- 大小上限 20MB（渲染产物与文件双重检查，超限 `FILE_TOO_LARGE`）；生成时长上限 5 分钟。
- 写入时计算 sha256 存 `file_hash`；下载前重新计算比对，不一致拒绝。
- 下载归属校验：仅创建者本人或持 `reports.download_audit` 权限者；删除仅本人（`reports.delete_own`），删记录同时清理文件。
- 预览（HTML）响应头强制 `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'`。
- 创建/重试/下载/删除/模板增删改均写操作审计（模块 `reports`）。

## HTML 渲染

固定内置 Go 模板（`html/template`），模板字段全部自动转义；CSS 全部内联，无任何外部资源/脚本/请求；章节按 `Tpl.Show(key)` 开关渲染，时间统一 UTC 格式。图表以内联 `<svg>` 嵌入（本包本地渲染产物，无脚本、不触发外部请求，CSP 无需调整）。

## 图表渲染（charts.go）

生成阶段统一构建图表（`BuildMainCharts` / `BuildAPICharts`），同一图表定义输出两种产物：SVG（HTML 内联）与 PNG（PDF/Word 嵌入），库为 go-charts/v2（MIT）。图表清单：

- 主报告：请求流量趋势（折线）、攻击趋势（折线）、攻击类型分布（饼图）、严重度分布（饼图）、攻击源IP TOP10（横向条形）、被攻击应用 TOP10（横向条形）；数据为空则不渲染，保留占位文案。
- API 域报告：API_ASSET 资产状态分布；API_RISK 发现类型+严重度分布；API_WEAK 弱点状态+未闭环严重度分布；API_SENS 数据类型分布+按天新增趋势（折线）。

安全与降级纪律：

- 图表中文使用与 PDF 相同的 `NotoSansCJKsc-VF.ttf`；字体文件缺失 → 跳过全部图表（退化为纯文字表格报告，记 warn 日志，不算失败）；字体存在但解析失败 → 任务失败 `FONT_UNAVAILABLE`。
- go-chart 的 SVG 输出不转义文本（上游实现原样写入），所有进入图表的标签（应用名等用户可控数据）经 `sanitizeChartLabel` 将 XML 元字符替换为全角等价字符，防 SVG 注入。

## PDF 渲染

gofpdf v2 + 内嵌中文字体 `NotoSansCJKsc-VF.ttf`（OFL 1.1；gofpdf 不支持 CFF OTF 故用可变 TTF）。降级链：

1. `REPORT_FONT_PATH` 或候选路径（`assets/fonts/`、`server/assets/fonts/`、`/app/assets/fonts/`）找到字体 → 完整中文 PDF；
2. 字体文件缺失/不可读 → 降级 ASCII 摘要 PDF，页面注明使用 HTML 导出查看完整报告（`tr` 剔除非 ASCII 字符）；
3. 字体存在但解析失败 → 任务失败，`FONT_UNAVAILABLE`。

图表 PNG 按 190mm 版宽等比嵌入（900x420px → 190x88.7mm），版面不足整图高度时先换页。表格行数受限（趋势最多 31/62 行后省略号），单元格截断防超长。

## Word（docx）渲染

godocx（MIT）从零生成 OOXML 文档：封面（标题级别，遵循 cover 开关）→ 各节标题（Heading）→ 段落/表格（样式 LightGrid-Accent1，表头加粗，单元格截断）→ 图表 PNG 图片（6.0x2.8 英寸，经临时文件中转插入，渲染后清理）。结构与 PDF 正文一致（21 节、章节开关、相同表格数据）。Word 文档由查看端系统字体渲染中文，无需内嵌字体、无降级路径。docx 不支持在线预览，前端仅提供下载；下载 Content-Type 为 `application/vnd.openxmlformats-officedocument.wordprocessingml.document`。

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
