// store.go 态势首页查询仓储：聚合表读 + 业务表实时状态。
package dashboards

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/aggregations"
	"github.com/jiuzhang-waf/server/internal/cache"
	"github.com/jiuzhang-waf/server/internal/metrics"
)

// diskPath 磁盘用量采集路径（容器内应用目录）。
const diskPath = "/app"

// Store 态势首页仓储。
type Store struct {
	db    *pgxpool.Pool
	agg   *aggregations.Store
	cache *cache.Client // 可选：用于 valkey used_memory 实时采集
}

// NewStore 创建态势首页仓储。
func NewStore(db *pgxpool.Pool, agg *aggregations.Store) *Store {
	return &Store{db: db, agg: agg}
}

// SetCache 设置 Valkey 客户端（可选）。
func (s *Store) SetCache(c *cache.Client) { s.cache = c }

// ---------- 通用类型 ----------

// KV 通用排行项。
type KV struct {
	Key   string  `json:"key"`
	Value float64 `json:"value"`
}

// SourceIPStat 源 IP 排行项。
type SourceIPStat struct {
	IP     string `json:"ip"`
	Events int64  `json:"events"`
	Blocks int64  `json:"blocks"`
}

// URIStat URI 排行项。
type URIStat struct {
	Path   string `json:"path"`
	Events int64  `json:"events"`
	Blocks int64  `json:"blocks"`
}

// ---------- 今日计数 ----------

// TodayCounters 安全态势今日计数（UTC 当天）。
type TodayCounters struct {
	RequestsTotal         float64 `json:"requests_total"`
	WAFEvents             float64 `json:"waf_events"`
	WAFBlocks             float64 `json:"waf_blocks"`
	WAFObserves           float64 `json:"waf_observes"`
	CCExceeded            float64 `json:"cc_exceeded"`
	IPDenyMatches         float64 `json:"ip_deny_matches"`
	TempBlockedIPs        int64   `json:"temp_blocked_ips"`
	UnprocessedHighEvents int64   `json:"unprocessed_high_events"`
	ProtectedApps         int64   `json:"protected_apps"`
	AbnormalApps          int64   `json:"abnormal_apps"`
	AbnormalUpstreams     int64   `json:"abnormal_upstreams"`
	ExpiringCerts         int64   `json:"expiring_certs"`
}

// TodayCounters 汇总今日计数：计数类来自分钟聚合表，实时状态类来自业务表。
func (s *Store) TodayCounters(ctx context.Context, start, end time.Time) (*TodayCounters, error) {
	out := &TodayCounters{}
	aggSums := []struct {
		metric string
		dst    *float64
	}{
		{metrics.HTTPRequestsTotal, &out.RequestsTotal},
		{metrics.WAFEventsTotal, &out.WAFEvents},
		{metrics.WAFBlocksTotal, &out.WAFBlocks},
		{metrics.WAFObserveTotal, &out.WAFObserves},
		{metrics.CCExceededTotal, &out.CCExceeded},
		{metrics.IPDenyMatchesTotal, &out.IPDenyMatches},
	}
	for _, it := range aggSums {
		v, err := s.agg.SumRange(ctx, "metric_minute_aggregates", it.metric, nil, start, end)
		if err != nil {
			return nil, fmt.Errorf("sum %s: %w", it.metric, err)
		}
		*it.dst = v
	}
	// 实时状态（业务表）
	if err := s.db.QueryRow(ctx, `
SELECT count(*) FROM temporary_blocks WHERE status = 'ACTIVE' AND block_expires_at > now()`).Scan(&out.TempBlockedIPs); err != nil {
		return nil, fmt.Errorf("temp blocks: %w", err)
	}
	if err := s.db.QueryRow(ctx, `
SELECT count(*) FROM security_events WHERE disposition_status = 'UNPROCESSED' AND severity = 'HIGH'`).Scan(&out.UnprocessedHighEvents); err != nil {
		return nil, fmt.Errorf("unprocessed high events: %w", err)
	}
	if err := s.db.QueryRow(ctx, `
SELECT
  count(*) FILTER (WHERE status = 'ACTIVE'),
  count(*) FILTER (WHERE status = 'ERROR' OR health_status IN ('UNHEALTHY', 'DOWN', 'DEGRADED'))
FROM applications WHERE deleted_at IS NULL`).Scan(&out.ProtectedApps, &out.AbnormalApps); err != nil {
		return nil, fmt.Errorf("applications: %w", err)
	}
	if err := s.db.QueryRow(ctx, `
SELECT count(*) FROM upstreams u
JOIN applications a ON a.id = u.application_id
WHERE u.deleted_at IS NULL AND u.status = 'ACTIVE' AND u.health_check_enabled = TRUE
  AND a.deleted_at IS NULL AND a.status = 'ACTIVE' AND a.deployment_mode <> 'MIRROR'
  AND (SELECT h.status FROM upstream_health_records h
       WHERE h.upstream_id = u.id ORDER BY h.checked_at DESC LIMIT 1) NOT IN ('HEALTHY', 'UP')`).Scan(&out.AbnormalUpstreams); err != nil {
		return nil, fmt.Errorf("upstreams: %w", err)
	}
	if err := s.db.QueryRow(ctx, `
SELECT count(*) FROM certificates
WHERE deleted_at IS NULL AND not_after IS NOT NULL
  AND not_after > now() AND not_after <= now() + interval '30 days'`).Scan(&out.ExpiringCerts); err != nil {
		return nil, fmt.Errorf("certificates: %w", err)
	}
	return out, nil
}

// ---------- 趋势 ----------

// metricSeries 单指标原始点序列（聚合表，可能同桶多标签行，由上层合并）。
func (s *Store) metricSeries(ctx context.Context, table, metric string, start, end time.Time) ([]time.Time, []float64, error) {
	rows, times, err := s.agg.QueryRange(ctx, table, metric, nil, start, end)
	if err != nil {
		return nil, nil, err
	}
	values := make([]float64, len(rows))
	for i, r := range rows {
		values[i] = r.Value
	}
	return times, values, nil
}

// severitySeries WAF 事件按严重度的原始点序列。
func (s *Store) severitySeries(ctx context.Context, table string, start, end time.Time) (map[string][]struct {
	T time.Time
	V float64
}, error,
) {
	out := map[string][]struct {
		T time.Time
		V float64
	}{}
	rows, err := s.db.Query(ctx, fmt.Sprintf(`
SELECT bucket_start, labels->>'severity' AS sev, SUM(value) FROM %s
WHERE metric = $1 AND bucket_start >= $2 AND bucket_start < $3 GROUP BY 1, 2`, table),
		metrics.WAFEventsTotal, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var t time.Time
		var sev *string
		var v float64
		if err := rows.Scan(&t, &sev, &v); err != nil {
			return nil, err
		}
		key := "UNKNOWN"
		if sev != nil && *sev != "" {
			key = *sev
		}
		out[key] = append(out[key], struct {
			T time.Time
			V float64
		}{t, v})
	}
	return out, rows.Err()
}

// dispositionSeries 事件处置状态点序列（事件表 date_trunc 分桶）。
func (s *Store) dispositionSeries(ctx context.Context, start, end time.Time, trunc string) (map[string][]struct {
	T time.Time
	V float64
}, error,
) {
	out := map[string][]struct {
		T time.Time
		V float64
	}{}
	rows, err := s.db.Query(ctx, `
SELECT date_trunc($1, occurred_at) AS b, disposition_status, count(*) FROM security_events
WHERE occurred_at >= $2 AND occurred_at < $3 GROUP BY 1, 2`, trunc, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var t time.Time
		var st string
		var v float64
		if err := rows.Scan(&t, &st, &v); err != nil {
			return nil, err
		}
		out[st] = append(out[st], struct {
			T time.Time
			V float64
		}{t, v})
	}
	return out, rows.Err()
}

// ---------- 排行 ----------

func topLabelsToKV(rows []struct {
	Key   string
	Value float64
},
) []KV {
	out := make([]KV, 0, len(rows))
	for _, r := range rows {
		out = append(out, KV{Key: r.Key, Value: r.Value})
	}
	return out
}

// TopAttackTypes 攻击类型排行（聚合表标签）。
func (s *Store) TopAttackTypes(ctx context.Context, table string, start, end time.Time, limit int) ([]KV, error) {
	rows, err := s.agg.TopLabels(ctx, table, metrics.WAFEventsTotal, "attack_type", start, end, limit)
	if err != nil {
		return nil, err
	}
	return topLabelsToKV(rows), nil
}

// TopApplications 应用事件排行（聚合表 app 标签 + 名称补充）。
func (s *Store) TopApplications(ctx context.Context, table string, start, end time.Time, limit int) ([]KV, error) {
	rows, err := s.agg.TopLabels(ctx, table, metrics.WAFEventsTotal, "app", start, end, limit)
	if err != nil {
		return nil, err
	}
	kvs := topLabelsToKV(rows)
	if len(kvs) == 0 {
		return kvs, nil
	}
	codes := make([]string, 0, len(kvs))
	for _, kv := range kvs {
		codes = append(codes, kv.Key)
	}
	nameRows, err := s.db.Query(ctx,
		`SELECT code, name FROM applications WHERE code = ANY($1) AND deleted_at IS NULL`, codes)
	if err != nil {
		return nil, err
	}
	defer nameRows.Close()
	names := map[string]string{}
	for nameRows.Next() {
		var code, name string
		if err := nameRows.Scan(&code, &name); err != nil {
			return nil, err
		}
		names[code] = name
	}
	if err := nameRows.Err(); err != nil {
		return nil, err
	}
	for i := range kvs {
		if n := names[kvs[i].Key]; n != "" {
			kvs[i].Key = n
		}
	}
	return kvs, nil
}

// TopRules 规则命中排行（waf_rule_hits_total，policy 标签 = 规则ID）。
func (s *Store) TopRules(ctx context.Context, table string, start, end time.Time, limit int) ([]KV, error) {
	rows, err := s.agg.TopLabels(ctx, table, "waf_rule_hits_total", "policy", start, end, limit)
	if err != nil {
		return nil, err
	}
	return topLabelsToKV(rows), nil
}

// TopSourceIPs 攻击源 IP 排行（≤24h 走分钟汇总表，更长范围查事件表）。
func (s *Store) TopSourceIPs(ctx context.Context, start, end time.Time, limit int) ([]SourceIPStat, error) {
	if limit <= 0 || limit > 100 {
		limit = 10
	}
	if end.Sub(start) <= 24*time.Hour {
		rows, err := s.db.Query(ctx, `
SELECT host(client_ip) AS ip, SUM(waf_events) AS events, SUM(deny_hits) AS blocks
FROM source_ip_summaries
WHERE bucket_start >= $1 AND bucket_start < $2
GROUP BY client_ip ORDER BY events DESC, ip LIMIT $3`, start, end, limit)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out := []SourceIPStat{}
		for rows.Next() {
			var it SourceIPStat
			if err := rows.Scan(&it.IP, &it.Events, &it.Blocks); err != nil {
				return nil, err
			}
			out = append(out, it)
		}
		return out, rows.Err()
	}
	rows, err := s.db.Query(ctx, `
SELECT host(client_ip) AS ip, count(*) AS events, count(*) FILTER (WHERE action = 'BLOCK') AS blocks
FROM security_events
WHERE occurred_at >= $1 AND occurred_at < $2 AND client_ip IS NOT NULL
GROUP BY ip ORDER BY events DESC, ip LIMIT $3`, start, end, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SourceIPStat{}
	for rows.Next() {
		var it SourceIPStat
		if err := rows.Scan(&it.IP, &it.Events, &it.Blocks); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// TopURIs 受攻击 URI 排行（≤24h 走分钟汇总表，更长范围查事件表）。
func (s *Store) TopURIs(ctx context.Context, start, end time.Time, limit int) ([]URIStat, error) {
	if limit <= 0 || limit > 100 {
		limit = 10
	}
	if end.Sub(start) <= 24*time.Hour {
		rows, err := s.db.Query(ctx, `
SELECT uri_path, SUM(waf_events) AS events, SUM(waf_blocks) AS blocks
FROM uri_security_summaries
WHERE bucket_start >= $1 AND bucket_start < $2 AND uri_path <> ''
GROUP BY uri_path ORDER BY events DESC, uri_path LIMIT $3`, start, end, limit)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out := []URIStat{}
		for rows.Next() {
			var it URIStat
			if err := rows.Scan(&it.Path, &it.Events, &it.Blocks); err != nil {
				return nil, err
			}
			out = append(out, it)
		}
		return out, rows.Err()
	}
	rows, err := s.db.Query(ctx, `
SELECT request_path, count(*) AS events, count(*) FILTER (WHERE action = 'BLOCK') AS blocks
FROM security_events
WHERE occurred_at >= $1 AND occurred_at < $2 AND request_path <> ''
GROUP BY request_path ORDER BY events DESC, request_path LIMIT $3`, start, end, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []URIStat{}
	for rows.Next() {
		var it URIStat
		if err := rows.Scan(&it.Path, &it.Events, &it.Blocks); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// ---------- 风险区 ----------

// EventSummary 高危未处置事件摘要。
type EventSummary struct {
	ID              string    `json:"id"`
	OccurredAt      time.Time `json:"occurred_at"`
	ClientIP        string    `json:"client_ip"`
	ApplicationName string    `json:"application_name"`
	AttackType      string    `json:"attack_type"`
	Severity        string    `json:"severity"`
	RequestPath     string    `json:"request_path"`
	Action          string    `json:"action"`
}

// RecentHighUnprocessed 最近高危未处置事件。
func (s *Store) RecentHighUnprocessed(ctx context.Context, limit int) ([]EventSummary, error) {
	if limit <= 0 || limit > 100 {
		limit = 10
	}
	rows, err := s.db.Query(ctx, `
SELECT id, occurred_at, COALESCE(host(client_ip), ''), application_name_snapshot,
  attack_type, severity, request_path, action
FROM security_events
WHERE disposition_status = 'UNPROCESSED' AND severity = 'HIGH'
ORDER BY occurred_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []EventSummary{}
	for rows.Next() {
		var it EventSummary
		if err := rows.Scan(&it.ID, &it.OccurredAt, &it.ClientIP, &it.ApplicationName,
			&it.AttackType, &it.Severity, &it.RequestPath, &it.Action); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// PublishTaskSummary 发布失败任务摘要。
type PublishTaskSummary struct {
	ID             string    `json:"id"`
	TaskType       string    `json:"task_type"`
	Status         string    `json:"status"`
	RequestedAt    time.Time `json:"requested_at"`
	FailureMessage string    `json:"failure_message"`
}

// RecentFailedPublishes 最近发布失败任务。
func (s *Store) RecentFailedPublishes(ctx context.Context, limit int) ([]PublishTaskSummary, error) {
	if limit <= 0 || limit > 100 {
		limit = 5
	}
	rows, err := s.db.Query(ctx, `
SELECT id, task_type, status, requested_at, failure_message
FROM gateway_publish_tasks WHERE status = 'FAILED'
ORDER BY requested_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PublishTaskSummary{}
	for rows.Next() {
		var it PublishTaskSummary
		if err := rows.Scan(&it.ID, &it.TaskType, &it.Status, &it.RequestedAt, &it.FailureMessage); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// ComponentIssue 异常组件（最新快照非 UP）。
type ComponentIssue struct {
	Component string    `json:"component"`
	Status    string    `json:"status"`
	Message   string    `json:"message"`
	TakenAt   time.Time `json:"taken_at"`
}

// ComponentIssues 最新状态非 UP 的组件。
func (s *Store) ComponentIssues(ctx context.Context) ([]ComponentIssue, error) {
	rows, err := s.db.Query(ctx, `
SELECT component, status, message, taken_at FROM (
  SELECT DISTINCT ON (component) component, status, message, taken_at
  FROM system_health_snapshots ORDER BY component, taken_at DESC
) latest WHERE status <> 'UP'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ComponentIssue{}
	for rows.Next() {
		var it ComponentIssue
		if err := rows.Scan(&it.Component, &it.Status, &it.Message, &it.TakenAt); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// JobStatus 聚合任务最新状态。
type JobStatus struct {
	JobType     string    `json:"job_type"`
	Status      string    `json:"status"`
	StartedAt   time.Time `json:"started_at"`
	RowsWritten int       `json:"rows_written"`
}

// CollectorLag 事件采集延迟与聚合任务状态。
type CollectorLag struct {
	LagSeconds        *float64    `json:"lag_seconds"`
	MeasuredAt        *time.Time  `json:"measured_at"`
	RecentJobFailures int64       `json:"recent_job_failures"`
	Jobs              []JobStatus `json:"jobs"`
}

// CollectorLag 采集延迟：最新 event_collector_lag_seconds + 聚合任务状态。
func (s *Store) CollectorLag(ctx context.Context) (*CollectorLag, error) {
	out := &CollectorLag{Jobs: []JobStatus{}}
	var t time.Time
	var v float64
	err := s.db.QueryRow(ctx, `
SELECT bucket_start, value FROM metric_minute_aggregates
WHERE metric = $1 ORDER BY bucket_start DESC LIMIT 1`, metrics.EventCollectorLagSec).Scan(&t, &v)
	switch {
	case err == nil:
		out.LagSeconds = &v
		out.MeasuredAt = &t
	case errors.Is(err, pgx.ErrNoRows):
		// 尚无延迟上报：保留空值
	default:
		return nil, err
	}
	if err := s.db.QueryRow(ctx, `
SELECT count(*) FROM aggregation_jobs WHERE status = 'FAILED' AND started_at > now() - interval '24 hours'`).Scan(&out.RecentJobFailures); err != nil {
		return nil, err
	}
	rows, err := s.db.Query(ctx, `
SELECT DISTINCT ON (job_type) job_type, status, started_at, rows_written
FROM aggregation_jobs ORDER BY job_type, started_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var it JobStatus
		if err := rows.Scan(&it.JobType, &it.Status, &it.StartedAt, &it.RowsWritten); err != nil {
			return nil, err
		}
		out.Jobs = append(out.Jobs, it)
	}
	return out, rows.Err()
}

// ---------- 运行态势 ----------

// ComponentStatus 组件最新健康快照。
type ComponentStatus struct {
	Component string                 `json:"component"`
	Status    string                 `json:"status"`
	LatencyMs *int                   `json:"latency_ms"`
	Message   string                 `json:"message"`
	TakenAt   time.Time              `json:"taken_at"`
	Metrics   map[string]interface{} `json:"metrics"`
}

// LatestComponentStatuses 各组件最新健康快照。
func (s *Store) LatestComponentStatuses(ctx context.Context) ([]ComponentStatus, error) {
	rows, err := s.db.Query(ctx, `
SELECT DISTINCT ON (component) component, status, latency_ms, message, taken_at, metrics
FROM system_health_snapshots ORDER BY component, taken_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ComponentStatus{}
	for rows.Next() {
		var it ComponentStatus
		var m map[string]interface{}
		if err := rows.Scan(&it.Component, &it.Status, &it.LatencyMs, &it.Message, &it.TakenAt, &m); err != nil {
			return nil, err
		}
		it.Metrics = m
		out = append(out, it)
	}
	return out, rows.Err()
}

// GatewayRuntime 网关运行状态。
type GatewayRuntime struct {
	Status        string     `json:"status"`
	UptimeSeconds *float64   `json:"uptime_seconds"`
	SnapshotAt    *time.Time `json:"snapshot_at"`
}

// GatewayRuntime 网关运行时间：取最新 gateway 组件快照（uptime_seconds 来自快照 metrics）。
func (s *Store) GatewayRuntime(ctx context.Context) (*GatewayRuntime, error) {
	out := &GatewayRuntime{Status: "UNKNOWN"}
	var status string
	var takenAt time.Time
	var m map[string]interface{}
	err := s.db.QueryRow(ctx, `
SELECT status, taken_at, metrics FROM system_health_snapshots
WHERE component ILIKE '%gateway%' ORDER BY taken_at DESC LIMIT 1`).Scan(&status, &takenAt, &m)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	out.Status = status
	out.SnapshotAt = &takenAt
	if m != nil {
		if v, ok := m["uptime_seconds"].(float64); ok {
			out.UptimeSeconds = &v
		}
	}
	return out, nil
}

// PublishStats 发布成功率/耗时（近 windowDays 天）。
type PublishStats struct {
	WindowDays         int     `json:"window_days"`
	Total              int64   `json:"total"`
	Success            int64   `json:"success"`
	Failed             int64   `json:"failed"`
	SuccessRate        float64 `json:"success_rate"`
	AvgDurationSeconds float64 `json:"avg_duration_seconds"`
}

// PublishStats 配置发布统计。
func (s *Store) PublishStats(ctx context.Context, windowDays int) (*PublishStats, error) {
	out := &PublishStats{WindowDays: windowDays}
	since := time.Now().UTC().Add(-time.Duration(windowDays) * 24 * time.Hour)
	var avg *float64
	err := s.db.QueryRow(ctx, `
SELECT count(*),
  count(*) FILTER (WHERE status = 'SUCCESS'),
  count(*) FILTER (WHERE status = 'FAILED'),
  AVG(EXTRACT(EPOCH FROM (finished_at - started_at)))
    FILTER (WHERE status = 'SUCCESS' AND started_at IS NOT NULL AND finished_at IS NOT NULL)
FROM gateway_publish_tasks WHERE requested_at >= $1`, since).
		Scan(&out.Total, &out.Success, &out.Failed, &avg)
	if err != nil {
		return nil, err
	}
	if out.Total > 0 {
		out.SuccessRate = float64(out.Success) / float64(out.Total)
	}
	if avg != nil {
		out.AvgDurationSeconds = *avg
	}
	return out, nil
}

// ReportStats 报告成功率（近 windowDays 天）。
type ReportStats struct {
	WindowDays  int     `json:"window_days"`
	Total       int64   `json:"total"`
	Success     int64   `json:"success"`
	Failed      int64   `json:"failed"`
	SuccessRate float64 `json:"success_rate"`
}

// ReportStats 报告任务统计。
func (s *Store) ReportStats(ctx context.Context, windowDays int) (*ReportStats, error) {
	out := &ReportStats{WindowDays: windowDays}
	since := time.Now().UTC().Add(-time.Duration(windowDays) * 24 * time.Hour)
	err := s.db.QueryRow(ctx, `
SELECT count(*),
  count(*) FILTER (WHERE status = 'SUCCESS'),
  count(*) FILTER (WHERE status = 'FAILED')
FROM report_jobs WHERE requested_at >= $1`, since).
		Scan(&out.Total, &out.Success, &out.Failed)
	if err != nil {
		return nil, err
	}
	if out.Total > 0 {
		out.SuccessRate = float64(out.Success) / float64(out.Total)
	}
	return out, nil
}

// StorageStats 存储用量。
type StorageStats struct {
	PGDatabaseSizeBytes   int64   `json:"pg_database_size_bytes"`
	ValkeyUsedMemoryBytes *int64  `json:"valkey_used_memory_bytes"`
	ValkeyError           string  `json:"valkey_error,omitempty"`
	DiskPath              string  `json:"disk_path"`
	DiskTotalBytes        *uint64 `json:"disk_total_bytes"`
	DiskFreeBytes         *uint64 `json:"disk_free_bytes"`
	DiskError             string  `json:"disk_error,omitempty"`
}

// StorageStats 存储用量：PG 经 db 查询，valkey 经 INFO（或快照回退），磁盘经 Statfs。
// 采集失败不导致整体失败：记录日志并在响应中携带错误说明。
func (s *Store) StorageStats(ctx context.Context) (*StorageStats, error) {
	out := &StorageStats{DiskPath: diskPath}
	if err := s.db.QueryRow(ctx, `SELECT pg_database_size(current_database())`).Scan(&out.PGDatabaseSizeBytes); err != nil {
		return nil, fmt.Errorf("pg database size: %w", err)
	}
	// valkey used_memory：优先 INFO 实时采集，未配置客户端时回退最新组件快照
	if s.cache != nil {
		info, err := s.cache.Redis().Info(ctx, "memory").Result()
		if err != nil {
			slog.Warn("valkey INFO failed", "error", err)
			out.ValkeyError = "valkey INFO 采集失败"
		} else if n, ok := ParseInfoUsedMemory(info); ok {
			out.ValkeyUsedMemoryBytes = &n
		} else {
			slog.Warn("valkey INFO missing used_memory")
			out.ValkeyError = "valkey INFO 缺少 used_memory"
		}
	} else {
		var m map[string]interface{}
		err := s.db.QueryRow(ctx, `
SELECT metrics FROM system_health_snapshots
WHERE component IN ('valkey', 'cache', 'redis') ORDER BY taken_at DESC LIMIT 1`).Scan(&m)
		switch {
		case err == nil:
			if v, ok := m["used_memory_bytes"].(float64); ok {
				n := int64(v)
				out.ValkeyUsedMemoryBytes = &n
			}
		case errors.Is(err, pgx.ErrNoRows):
			// 无快照且无客户端：保留空值
		default:
			return nil, err
		}
	}
	// 磁盘用量
	var st syscall.Statfs_t
	if err := syscall.Statfs(diskPath, &st); err != nil {
		slog.Warn("disk statfs failed", "path", diskPath, "error", err)
		out.DiskError = "磁盘用量采集失败"
	} else {
		total := st.Blocks * uint64(st.Bsize)
		free := st.Bavail * uint64(st.Bsize)
		out.DiskTotalBytes = &total
		out.DiskFreeBytes = &free
	}
	return out, nil
}

// ---------- 审计态势 ----------

// AuditSummary 最近审计摘要。
type AuditSummary struct {
	ID         string    `json:"id"`
	OccurredAt time.Time `json:"occurred_at"`
	Username   string    `json:"username"`
	Module     string    `json:"module"`
	Action     string    `json:"action"`
	ObjectName string    `json:"object_name"`
	Result     string    `json:"result"`
	RiskLevel  string    `json:"risk_level"`
}

// StatusCount 处置状态分布项。
type StatusCount struct {
	Status string `json:"status"`
	Count  int64  `json:"count"`
}

// ActionCount 操作类型统计项。
type ActionCount struct {
	Action string `json:"action"`
	Count  int64  `json:"count"`
}

// AuditCounters 审计态势计数。
type AuditCounters struct {
	TodayDispositions int64 `json:"today_dispositions"`
	UnprocessedEvents int64 `json:"unprocessed_events"`
	TodayAudits       int64 `json:"today_audits"`
}

// AuditCounters 今日处置数 / 未处置数 / 今日审计条数。
func (s *Store) AuditCounters(ctx context.Context, dayStart, now time.Time) (*AuditCounters, error) {
	out := &AuditCounters{}
	if err := s.db.QueryRow(ctx, `
SELECT count(*) FROM security_events
WHERE disposition_at >= $1 AND disposition_at < $2`, dayStart, now).Scan(&out.TodayDispositions); err != nil {
		return nil, fmt.Errorf("today dispositions: %w", err)
	}
	if err := s.db.QueryRow(ctx, `
SELECT count(*) FROM security_events WHERE disposition_status = 'UNPROCESSED'`).Scan(&out.UnprocessedEvents); err != nil {
		return nil, fmt.Errorf("unprocessed events: %w", err)
	}
	if err := s.db.QueryRow(ctx, `
SELECT count(*) FROM operation_audits WHERE occurred_at >= $1 AND occurred_at < $2`, dayStart, now).Scan(&out.TodayAudits); err != nil {
		return nil, fmt.Errorf("today audits: %w", err)
	}
	return out, nil
}

// RecentAudits 最近审计记录。
func (s *Store) RecentAudits(ctx context.Context, limit int) ([]AuditSummary, error) {
	if limit <= 0 || limit > 100 {
		limit = 10
	}
	rows, err := s.db.Query(ctx, `
SELECT id, occurred_at, username, module, action, object_name, result, risk_level
FROM operation_audits ORDER BY occurred_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditSummary{}
	for rows.Next() {
		var it AuditSummary
		if err := rows.Scan(&it.ID, &it.OccurredAt, &it.Username, &it.Module,
			&it.Action, &it.ObjectName, &it.Result, &it.RiskLevel); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// DispositionDistribution 事件处置状态分布（全量）。
func (s *Store) DispositionDistribution(ctx context.Context) ([]StatusCount, error) {
	rows, err := s.db.Query(ctx, `
SELECT disposition_status, count(*) FROM security_events GROUP BY 1 ORDER BY 2 DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []StatusCount{}
	for rows.Next() {
		var it StatusCount
		if err := rows.Scan(&it.Status, &it.Count); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// AuditActionStats 今日操作类型统计（按 module + action）。
func (s *Store) AuditActionStats(ctx context.Context, dayStart, now time.Time, limit int) ([]ActionCount, error) {
	if limit <= 0 || limit > 100 {
		limit = 10
	}
	rows, err := s.db.Query(ctx, `
SELECT module || '.' || action AS op, count(*) FROM operation_audits
WHERE occurred_at >= $1 AND occurred_at < $2
GROUP BY 1 ORDER BY 2 DESC LIMIT $3`, dayStart, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ActionCount{}
	for rows.Next() {
		var it ActionCount
		if err := rows.Scan(&it.Action, &it.Count); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}
