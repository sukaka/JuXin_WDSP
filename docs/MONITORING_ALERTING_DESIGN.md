# 监控告警设计（阶段6）

实现：`server/internal/runtimehealth/`（采集与快照）、`server/internal/systemalerts/`（评估引擎与处置）。
链路：采集器每 30s 探测组件 → 快照落 `system_health_snapshots` → 评估引擎每 30s 基于最新快照评估 → 触发/合并/恢复 `system_alerts` → 管理员处置（全程审计）。

## 采集组件与指标（10 类，`runtimehealth`）

采集周期 30s（`StartStage6Workers`），单组件探针失败转为 DOWN/UNKNOWN 快照，不中断其他组件。状态枚举：`UP / DOWN / DEGRADED / UNKNOWN`。

| 组件 | 探测方式 | 状态判定 | 主要指标键（`metrics` JSONB） |
|------|----------|----------|------------------------------|
| GATEWAY | Caddy Admin Socket Ping + 读配置哈希 | 不可达 DOWN；可达但读配置失败 DEGRADED | `config_hash`（Ping 耗时入快照 `latency_ms` 字段） |
| CORAZA | 间接判定（嵌入网关进程） | 跟随 GATEWAY | - |
| GUARD | 间接判定 + guard 事件日志 mtime | 网关 DOWN 则 DOWN；日志停滞 >5min 判 DEGRADED；日志未生成视为正常 | `guard_log_stale_seconds` |
| API | 进程自测 | 恒 UP；文件句柄使用率 ≥80%（`FDUsageHighPercent` 可配）判 DEGRADED | `goroutines`、`heap_alloc_bytes`、`memory_sys_bytes`、`uptime_seconds`、`fd_open_files`、`fd_max_open_files`、`fd_usage_percent`（fd_* 为 Linux /proc 采集，非 Linux/采集失败不产出指标、不判级） |
| POSTGRES | Ping + 容量查询 | 不可达 DOWN；指标查询失败 DEGRADED | `database_size_bytes`、`db_connections`、`db_capacity_percent`（库容量/磁盘总量，同卷假设） |
| VALKEY | INFO memory/clients + DBSize | 不可达 DOWN；DBSize 失败 DEGRADED | `used_memory_bytes`、`connected_clients`、`dbsize_keys` |
| EVENT_COLLECTOR | 3 个 checkpoint 滞后：安全事件（DB 表 `event_collector_checkpoints`）、访问控制事件与 access-log（文件 mtime） | 全部缺失 UNKNOWN；最大滞后 >120s DEGRADED | `max_lag_seconds`、`checkpoints`（逐 checkpoint 明细） |
| UPSTREAM | 主动探测启用健康检查的 HTTP 源站（复用 upstreams 连通性测试，防 SSRF；单轮最多 20 个，单探测 3s 超时） | 全部健康 UP；部分健康 DEGRADED；全部失败 DOWN | `upstream_total`、`upstream_healthy`、`upstream_unhealthy`、`upstream_failures`（最多 5 条失败明细） |
| CERTIFICATE | 库表统计在役证书 | 有已过期 DOWN；最近 ≤30 天到期 DEGRADED | `min_days_remaining`、`expiring_count`、`expired_count` |
| DISK | Statfs（默认 /app） | 剩余 ≤10% DEGRADED | `disk_total_bytes`、`disk_free_bytes`、`disk_free_percent` |

快照表 `system_health_snapshots`：`id / taken_at / component / status / latency_ms / metrics JSONB / message(≤500)`，索引 `(component, taken_at DESC)`；`DeleteOlderThan` 支持按保留窗口清理。

采集默认参数（`runtimehealth.Options`）：采集周期 30s；guard 日志停滞阈值 5min；源站探测超时 3s、单轮最多 20 个、失败明细最多 5 条；事件采集滞后降级阈值 120s；磁盘剩余降级阈值 10%；证书临期阈值 30 天；单探针 DB 超时 5s。

查询接口（权限 `system_health.read`）：

| 接口 | 内容 |
|------|------|
| GET /api/v1/system-health | 整体状态（DOWN>DEGRADED>UNKNOWN>UP 取最差）、状态计数、组件快照、未采集组件清单 |
| GET /api/v1/system-health/components | 各组件最新快照 |
| GET /api/v1/system-health/storage | PG 容量与连接数、TOP10 表容量、Valkey 内存、报告/备份目录占用（遍历上限 20 万项）、磁盘空间 |

## 告警类型与等级矩阵（19 类）

等级枚举：`CRITICAL / HIGH / MEDIUM / LOW / INFO`；类型→默认等级为静态映射（`severityRules`），证书临期按剩余天数动态定级。

| 告警类型 | 等级 | 触发源 |
|----------|------|--------|
| GATEWAY_DOWN | CRITICAL | GATEWAY 快照 DOWN |
| MANAGEMENT_API_DOWN | HIGH | API 快照 DOWN |
| FD_USAGE_HIGH | HIGH | API 快照 DEGRADED 且携带 `fd_usage_percent`（指标缺失不判级）；恢复 UP 自动 RESOLVED |
| DATABASE_UNAVAILABLE | CRITICAL | POSTGRES 快照 DOWN |
| VALKEY_UNAVAILABLE | HIGH | VALKEY 快照 DOWN |
| EVENT_COLLECTOR_LAG | MEDIUM | EVENT_COLLECTOR 快照 DEGRADED/DOWN |
| EVENT_PARSE_FAILURE_RATE_HIGH | MEDIUM | 5 分钟窗口内解析失败 ≥5 条且失败率 ≥10% |
| SOURCE_UNHEALTHY | MEDIUM | UPSTREAM 快照 DEGRADED/DOWN |
| CERTIFICATE_EXPIRING | LOW（≤7 天升 MEDIUM） | 证书剩余 ≤30 天 |
| CERTIFICATE_EXPIRED | HIGH | 存在已过期证书 |
| CONFIG_PUBLISH_FAILED | HIGH | 业务失败回调（发布） |
| CONFIG_HASH_MISMATCH | MEDIUM | 业务失败回调（配置哈希不一致） |
| DISK_SPACE_LOW | HIGH | DISK 快照 DEGRADED/DOWN |
| DATABASE_CAPACITY_HIGH | MEDIUM | `db_capacity_percent` ≥80% |
| BACKUP_FAILED | HIGH | 业务失败回调（备份） |
| RESTORE_VALIDATION_FAILED | HIGH | 业务失败回调（恢复验证） |
| REPORT_FAILED | MEDIUM | 业务失败回调（报告） |
| UPGRADE_FAILED | HIGH | 业务失败回调（升级） |
| AUDIT_INTEGRITY_FAILED | CRITICAL | 业务失败回调（审计完整性） |

快照类告警由 `Engine.Evaluate` 每 30s 按最新快照触发；对应组件恢复 UP 时同类型告警自动恢复。业务失败类由 `NotifyFailure` 回调触发（备份/恢复/升级等服务经 `alertFn` 接入）。每轮评估先 `Evaluate` 后 `EvaluateParseFailures`；单组件评估失败不阻断其他组件，错误聚合返回。

## 告警状态机

`OPEN → ACKNOWLEDGED → RESOLVED / IGNORED`；OPEN 也可直接 RESOLVED/IGNORED。
解决方式 `resolve_type`：`MANUAL`（人工解决）、`RECOVERED`（自动恢复）。
表：`system_alerts`（含 `first_seen_at / last_seen_at / occurrence_count` 与处置人字段）、`system_alert_notes`（备注）。

## 合并 / 冷却 / 抖动抑制 / 上限保护 / 自动恢复

| 机制 | 规则（`Engine`，纯决策函数 `decideRaise`/`decideRecover`） |
|------|----------------------------------------------------------|
| 合并去重 | 同 `alert_type+component` 存在未关闭（OPEN/ACKNOWLEDGED）告警时不新建：`occurrence_count+1`、`last_seen_at` 更新 |
| 冷却 | 合并时仅当距上次 message 更新 ≥5 分钟才刷新 message/severity（冷却期内只计数） |
| 抖动抑制 | 同去重键 10 分钟窗口内 OPEN↔RESOLVED 翻转 ≥3 次：新告警 message 追加「（检测到抖动，已抑制频繁翻转）」；抖动中的告警不自动恢复，保持 OPEN |
| 上限保护 | OPEN 总数 ≥500 时，新建 LOW/INFO 告警直接置 IGNORED（message 加「未关闭告警超过上限，已自动忽略：」前缀），防告警风暴撑爆表 |
| 自动恢复 | 组件快照恢复 UP（或阈值回到安全区）→ 未关闭告警置 `RESOLVED(RECOVERED)`；抖动中的除外 |

`flapTracker` 为内存实现，进程重启后重新计数（可接受的近似）。

## 维护窗口（阶段6 §11.5，迁移 000142）

表 `system_alert_maintenance_windows`：`scope=ALL` 抑制全部告警，`scope=CUSTOM` 按 `alert_types`/`components` 非空维度过滤（空数组维度通配）；周期 `ONCE`（起止时刻 `[starts_at, ends_at]`）或 `DAILY`（日期跨度内每日 UTC 日内时段，`end<=start` 表示跨零点）。

`Engine.Raise` 在合并/新建前检查生效窗口：命中则不新建也不合并，但抑制事实可观测——命中窗口 `suppressed_count+1`、刷新 `last_suppressed_at` 并写日志；窗口查询/记账失败如实返回错误，不退化为放行。

接口（读 `system_alerts.read` 系、写 `system_alerts.acknowledge` 系，写操作记审计）：`GET/POST /api/v1/system-alerts/maintenance-windows`、`DELETE /api/v1/system-alerts/maintenance-windows/{id}`；前端在系统告警页提供维护窗口管理。

## 处置操作与审计

| 接口 | 权限（任一） | 审计 |
|------|--------------|------|
| GET /api/v1/system-alerts（筛选 status/severity/alert_type/component/时间窗） | `system_alerts.read` / `read_security` / `read_audit` | - |
| GET /api/v1/system-alerts/{id}（含备注） | 同上 | - |
| POST /{id}/acknowledge、POST /{id}/resolve、POST /{id}/ignore | `system_alerts.acknowledge` / `acknowledge_security` | 中风险 |
| POST /{id}/notes（≤1000 字符） | 同上 | 低风险 |

非法状态流转返回 409（如已 RESOLVED 再 acknowledge）；全部处置写 `operation_audits`（模块 `system_alerts`）。
列表筛选参数统一大写后经 `IsValidStatus/IsValidSeverity/IsValidType` 校验（非法值 400）；`start_time/end_time` 为 RFC3339，按 `last_seen_at` 过滤。

## CSV 导出防注入

`Export` 处理器已实现：导出行上限 10000；`csvCell` 转义——`\r`/`\n` 替换为空格，前导 `= + - @ \t` 加单引号防公式注入，含逗号/引号的单元格加双引号并双写引号；导出动作记审计。
路由已挂载（2026-09-10）：`GET /api/v1/system-alerts/export`（读权限 + 导出限流）。

## 验证

- 单测：`runtimehealth/collector_test.go`（各组件探针状态判定）、`systemalerts/evaluator_test.go` + `rules_test.go`（合并/冷却/抖动/上限/自动恢复决策、解析失败率判定、等级映射）、`handler_test.go`。
- 集成验证：停 Valkey → 30s 内出现 VALKEY_UNAVAILABLE(HIGH)；恢复 → 自动 RESOLVED(RECOVERED)；重复触发只累计 `occurrence_count` 不产生新行。
