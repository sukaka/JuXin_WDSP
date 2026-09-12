# 安全态势首页设计（阶段6）

实现：`server/internal/dashboards/`（handler.go / store.go / params.go），路由注册于 `server/internal/app/app.go`。
三个只读接口，分别对应三类管理员的首页视图。

## 接口与权限

| 接口 | 权限点 | 面向角色 |
|------|--------|----------|
| GET /api/v1/dashboard/security-overview | `dashboard.security.read` | 安全管理员（完整安全态势） |
| GET /api/v1/dashboard/runtime-overview | `dashboard.runtime.read` | 系统管理员（运行态势） |
| GET /api/v1/dashboard/audit-overview | `dashboard.audit.read` | 审计管理员（处置与操作审计） |

时间参数：`range` ∈ `1h / 24h / 7d / 30d`，缺省 `24h`，非法值返回 400（`ParseTrendRange`）。
所有时间以 UTC 计算与返回；`generated_at` 为响应生成时刻。

## 数据源分层

| 数据类别 | 数据源 | 说明 |
|----------|--------|------|
| ≤24h 计数与趋势 | `metric_minute_aggregates` | `AggTableFor`：跨度 ≤24h 选分钟表 |
| >24h 计数与趋势 | `metric_hour_aggregates` | 跨度 >24h 选小时表 |
| 趋势桶步长 | 内存分桶 | `TrendStep`：1h→分钟，24h/7d→小时，30d→天；`BucketTimes`/`SeriesInto` 对齐补零 |
| 实时状态 | 业务表直查 | `temporary_blocks` / `security_events` / `applications` / `upstreams` / `certificates` / `gateway_publish_tasks` / `system_health_snapshots` / `operation_audits` |
| 处置状态分布序列 | `security_events` 按 `date_trunc` 分桶 | 粒度由 `StepTrunc` 跟随趋势步长 |

设计约束：趋势与计数只读聚合表，不扫描原始事件全表；只有带时间窗过滤的排行（源 IP/URI）与实时状态直查业务表。

## 安全态势（security-overview）

### 今日计数卡片（TodayCounters，UTC 当日 [零点, now)）

| 字段 | 来源 |
|------|------|
| `requests_total` / `waf_events` / `waf_blocks` / `waf_observes` / `cc_exceeded` / `ip_deny_matches` | 分钟聚合表 `SumRange` 求和 |
| `temp_blocked_ips` | `temporary_blocks` 中 `status='ACTIVE'` 且未到期 |
| `unprocessed_high_events` | `security_events` 中 `disposition_status='UNPROCESSED'` 且 `severity='HIGH'` |
| `protected_apps` / `abnormal_apps` | `applications`：`status='ACTIVE'` / `status='ERROR'` 或 `health_status IN ('UNHEALTHY','DOWN')` |
| `abnormal_upstreams` | 启用中源站最新健康记录非 `HEALTHY/UP` |
| `expiring_certs` | 30 天内到期且未过期证书 |

### 趋势区（SecurityTrendData）

`times` 与下列序列等长对齐：`requests`、`security_events`、`blocks`、`observes`、`cc_exceeded`、`ip_deny`（聚合表单指标求和）；`risk_levels`（`waf_events_total` 按 `severity` 标签分组）；`disposition`（`security_events.disposition_status` 按桶分组）。

### 排行区（TopData）

| 字段 | 条目数 | 来源 |
|------|--------|------|
| `attack_types` | 5 | 聚合表 `waf_events_total` 按 `attack_type` 标签 TopN |
| `source_ips` | 10 | `security_events` 按 `client_ip` 分组（含 `blocks`） |
| `applications` | 5 | 聚合表 `app` 标签 TopN，回查应用名替换 code |
| `rules` | 10 | 聚合表 `waf_rule_hits_total` 按 `policy` 标签（=规则ID）TopN |
| `uris` | 10 | `security_events` 按 `request_path` 分组（含 `blocks`） |

### 风险提示区（RiskData）

| 字段 | 内容 |
|------|------|
| `high_unprocessed_events` | 最近 10 条高危未处置事件摘要 |
| `failed_publish_tasks` | 最近 5 条 `FAILED` 发布任务 |
| `gateway_issues` | 最新健康快照状态非 `UP` 的组件 |
| `collector_lag` | 最新 `event_collector_lag_seconds` 值、24h 内聚合任务失败数、各 `aggregation_jobs` 最新状态 |

## 运行态势（runtime-overview）

| 字段 | 内容 |
|------|------|
| `components` | 各组件最新 `system_health_snapshots`（DISTINCT ON component） |
| `gateway` | 最新 gateway 组件快照状态与 `uptime_seconds` |
| `publish` | 近 30 天发布任务总数/成功/失败/成功率/平均耗时 |
| `reports` | 近 30 天报告任务总数/成功/失败/成功率 |
| `storage` | PG 库容量（`pg_database_size`）、Valkey `used_memory`（INFO 实时采集，失败回退快照并带 `valkey_error`）、磁盘总量/剩余（Statfs，失败带 `disk_error`） |

单点采集失败不导致整体失败：Valkey/磁盘失败仅降级为错误说明字段。

## 审计态势（audit-overview）

| 字段 | 内容 |
|------|------|
| `today_dispositions` | 今日已处置事件数（按 `disposition_at`） |
| `unprocessed_events` | 当前全部未处置事件数 |
| `today_audits` | 今日 `operation_audits` 条数 |
| `recent_audits` | 最近 10 条操作审计（用户/模块/动作/对象/结果/风险等级） |
| `disposition_distribution` | 全量事件处置状态分布 |
| `action_stats` | 今日操作类型 TOP10（`module.action`） |

## 三权视图差异

- 安全管理员：`security-overview` 全量（攻击/阻断/CC/风险），另加 `analytics.security.read` 下的统计分析接口。
- 系统管理员：`runtime-overview` 聚焦组件健康、发布、报告、存储，不含攻击细节。
- 审计管理员：`audit-overview` 聚焦事件处置进度与操作审计，另加 `analytics.disposition.read` 的处置统计。

## 性能约束

- 计数与趋势查询只命中聚合表索引（`(metric, bucket_start DESC)`），数据量与原始请求量解耦。
- 实时状态查询均为带索引的计数/限额查询；排行类固定 `LIMIT ≤ 100`。
- 性能目标（阶段6任务书）：态势首页 P95 < 2s；24h 趋势 P95 < 1s；30d 趋势 P95 < 2s。

## 验证

- 单测 `dashboards_test.go`：range 参数解析、非法 range 返回 400、数据分层选表（`AggTableFor`/`TrendStep`）、分桶对齐（`SeriesInto`）。
- 接口验证：三角色分别访问三个接口，确认权限点与数据域隔离；对比聚合表数据与原始事件计数一致性。
