# 指标数据字典（阶段6）

实现：`server/internal/metrics/metrics.go`（指标模型）、`server/internal/aggregations/`（采集与聚合）。
原则：UTC 存储、指标名固定枚举、标签维度受控、不含敏感数据、聚合可重算。

## 指标清单

`metrics.go` 中声明的固定指标名（禁止用户输入作为指标名）：

| 指标名 | 类型 | 标签 | 写入方 | 状态 |
|--------|------|------|--------|------|
| `http_requests_total` | 计数 | `app`, `status_class`(2xx/4xx/5xx) | 访问日志采集器 | 已启用 |
| `http_request_duration_ms` | 直方图 | `app`（桶计数在 `extra.buckets`） | 访问日志采集器 | 已启用 |
| `waf_events_total` | 计数 | `app`, `attack_type`, `severity`, `action` | 分钟聚合任务（security_events） | 已启用 |
| `waf_blocks_total` | 计数 | `app` | 分钟聚合任务（action='BLOCK'） | 已启用 |
| `waf_observes_total` | 计数 | `app` | 分钟聚合任务（action≠'BLOCK'） | 已启用 |
| `cc_threshold_exceeded_total` | 计数 | `app` | 分钟聚合任务（access_control_events） | 已启用 |
| `cc_request_rejected_total` | 计数 | `app` | 同上 | 已启用 |
| `cc_temp_block_created_total` | 计数 | `app` | 同上 | 已启用 |
| `ip_deny_matches_total` | 计数 | `app` | 同上 | 已启用 |
| `ip_allow_matches_total` | 计数 | `app` | 同上 | 已启用 |
| `security_events_unprocessed` | 仪表盘 | - | 预留（实时值由业务表直查） | 已声明未写入 |
| `event_collector_lag_seconds` | 仪表盘 | - | 采集器提供 `SetLagCallback` 上报口，当前主程序未接线（暂无写入方）；态势页读该指标最新值 | 已声明，读路径已启用 |
| `event_parse_failures_total` | 计数 | - | 预留（解析失败告警直查 `event_parse_failures` 表） | 已声明未写入 |
| `gateway_up` / `upstream_healthy` / `certificate_days_remaining` / `database_size_bytes` / `disk_free_bytes` | 仪表盘 | - | 预留（实时值由 `system_health_snapshots` 承载） | 已声明未写入 |

另有一个未列入常量但由分钟聚合任务写入的指标：`waf_rule_hits_total`（标签 `policy`=规则ID、`attack_type`，来源 `security_event_matches`）。

## 标签维度（受控清单）

允许的标签键（`ValidateLabels` 校验，未知键拒绝，值长度 ≤128 字符，防高基数攻击）：

`app` / `attack_type` / `severity` / `action` / `status_class` / `scope` / `component` / `policy` / `method` / `content_type`

约束：客户端 IP、URI、请求 ID 不进标签；源 IP 与 URI 排行由事件表带时间窗直查。

## 时间粒度与聚合表

三级聚合表，主键均为 `(bucket_start, metric, labels)`，行结构一致：

| 表 | 粒度 | bucket_start 类型 | 用途 |
|----|------|-------------------|------|
| `metric_minute_aggregates` | 1m | TIMESTAMPTZ | ≤24h 查询、今日计数 |
| `metric_hour_aggregates` | 1h | TIMESTAMPTZ | >24h 查询 |
| `metric_daily_aggregates` | 1d | DATE | 报告长周期统计 |

每行字段：`metric VARCHAR(64)`、`labels JSONB`、`value DOUBLE PRECISION`、`extra JSONB`（直方图桶等扩展）、`updated_at`。索引 `(metric, bucket_start DESC)`。

辅助表：`application_security_summaries`（分钟级应用安全汇总，分钟任务写入；`requests_total` 当前固定写 0）、`rule_hit_summaries` / `source_ip_summaries` / `uri_security_summaries`（迁移已建表，当前无写入方——规则命中走 `waf_rule_hits_total`，源 IP/URI 直查事件表）、`aggregation_jobs`（任务执行记录：`job_type` MINUTE/HOUR/DAILY、`window_start/window_end`、`status` SUCCESS/FAILED、`rows_written`、`error`、`started_at/finished_at`）。

## 读取接口（aggregations.Store）

| 方法 | 语义 |
|------|------|
| `QueryRange` | 单指标时间序列（`labels @>` 包含匹配过滤），按桶升序 |
| `SumRange` | 区间求和（`COALESCE(SUM(value),0)`） |
| `TopLabels` | 按 `labels->>key` 分组求和降序取 TopN（limit 缺省 10、上限 100） |

消费方：态势首页（dashboards）、统计分析（analytics）、报告采集（reports）。查询表名由调用方按分层规则选择，不做跨表自动降级。

## 访问日志采集明细

- 日志格式：Caddy 2.11 JSON 行，字段 `ts`（Unix 秒浮点）、`request.remote_ip/method/host/uri`、`status`、`size`、`duration`（秒）。
- 状态分类（`statusClass`）：`status ≥ 500 → 5xx`；`≥ 400 → 4xx`；其余（含 3xx）→ `2xx`。
- 行级容错：JSON 解析失败或 `ts=0` 的行跳过，不中断本轮采集。
- 分钟产出：`http_requests_total{app,status_class}` 计数 + `http_request_duration_ms{app}` 直方图；`host` 先小写化并去端口后经域名映射归应用，未命中为 `unknown`。

## duration 直方图与分位数估算

- 桶边界（毫秒，`DurationBucketsMs`）：`5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000`；桶计数数组长度为 11，最后一桶为 `>5000` 溢出桶（`BucketIndex` 越界归最后一桶）。
- 采集侧：访问日志 `duration`（秒）×1000 定位桶，按应用累计，写入 `extra.buckets`；`value` 为该应用该分钟请求总数。
- 查询侧（`analytics.percentileSeries`）：同桶多应用计数合并（`MergeCounts`），`normalizeCounts` 把溢出桶并入最后一桶防止越界。
- 分位数估算（`PercentileFromBuckets`）：在命中桶内做线性插值 `prevLe + frac×(le−prevLe)`，桶空直接返回上界；总数为 0 返回 0。输出 P50/P95/P99（毫秒）。

## 采集链路

```text
Caddy 访问日志(JSON 行)                security_events(阶段4采集)   access_control_events(阶段5采集)
  │ AccessLogCollector(2s/轮)            │                            │
  │ 断点续传(offset+inode,轮转检测)       │                            │
  │ 坏行跳过不中断                        │                            │
  ▼                                      ▼                            ▼
分钟桶(app|status_class, duration桶) ──► RunMinute(每1min)：重算当前+上一分钟（迟到修正）
  │                                      │ 另写 application_security_summaries
  ▼                                      ▼
metric_minute_aggregates ──► RunHour(每1h)：分钟表→小时表，重算当前+上一小时
                                     └──► RunDaily(随小时任务执行)：小时表→天表，重算今天+昨天
```

- 访问日志采集：checkpoint 文件原子写（tmp+rename，0600）；inode 变化或文件变短判定轮转从头读；只处理完整行；`ts` 解析为 UTC 分钟桶；域名→应用映射 60s 缓存（`RefreshDomainAppMap`，未匹配归 `unknown`）。
- 分钟聚合：WAF 事件按 `app/attack_type/severity/action` 分组（`app` 取 `applications.code`，缺省 `unknown`）；`action='BLOCK'` 拆 `waf_blocks_total`，其余 `waf_observes_total`；规则命中（`security_event_matches`，仅 `rule_id > 0`）写 `waf_rule_hits_total{policy=规则ID, attack_type}`。
- 访问控制事件 `event_type` → 指标映射（未列出的类型不聚合）：

| event_type | 指标 |
|------------|------|
| `CC_THRESHOLD_EXCEEDED` | `cc_threshold_exceeded_total` |
| `CC_REQUEST_REJECTED` | `cc_request_rejected_total` |
| `CC_TEMP_BLOCK_CREATED` | `cc_temp_block_created_total` |
| `IP_DENY_MATCH` | `ip_deny_matches_total` |
| `IP_ALLOW_MATCH` | `ip_allow_matches_total` |

## 幂等与迟到修正

- 分钟/事件聚合：按明确时间窗重算，主键 `ON CONFLICT DO UPDATE` 覆盖式 upsert——同一窗口重算结果直接替换，天然幂等。
- 迟到修正窗口：分钟任务每轮重算当前分钟与上一分钟；小时任务重算当前与上一小时；天任务重算今天与昨天。
- 小时/天 rollup：Go 内按 `(metric, labels)` 合并求和（直方图桶逐桶相加），目标窗口先 `DELETE` 后 `INSERT`，可安全重跑。
- 每轮执行落 `aggregation_jobs`（SUCCESS/FAILED + rows_written + error），供态势页展示与排障。

## 验证

- 单测：`aggregations` 包（采集解析、断点、轮转、upsert 幂等）、`metrics` 桶定位与分位数、`analytics` 直方图合并与透视。
- 数据校验：重复执行 `RunMinute` 后窗口行数与值不变（幂等）；向上一分钟补写事件后下轮聚合值被修正（迟到修正）。
