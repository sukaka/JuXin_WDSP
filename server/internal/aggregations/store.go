// Package aggregations 阶段6数据聚合：访问日志采集、分钟/小时/天三级聚合任务。
// 幂等：按明确时间窗口重复计算，主键 upsert；支持迟到事件修正（窗口回看）。
package aggregations

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store 聚合数据仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建聚合仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

// AggRow 聚合行。
type AggRow struct {
	Metric string
	Labels map[string]string
	Value  float64
	Extra  map[string]interface{}
}

func labelsJSON(labels map[string]string) []byte {
	if labels == nil {
		return []byte("{}")
	}
	b, _ := json.Marshal(labels)
	return b
}

func extraJSON(extra map[string]interface{}) []byte {
	if extra == nil {
		return []byte("{}")
	}
	b, _ := json.Marshal(extra)
	return b
}

// upsertMinute 幂等写入分钟聚合（覆盖式：窗口重算结果直接替换）。
func (s *Store) upsertMinute(ctx context.Context, bucket time.Time, rows []AggRow) (int, error) {
	return s.upsert(ctx, "metric_minute_aggregates", bucket, rows)
}

func (s *Store) upsertHour(ctx context.Context, bucket time.Time, rows []AggRow) (int, error) {
	return s.upsert(ctx, "metric_hour_aggregates", bucket, rows)
}

func (s *Store) upsertDaily(ctx context.Context, bucket time.Time, rows []AggRow) (int, error) {
	return s.upsert(ctx, "metric_daily_aggregates", bucket.Truncate(24*time.Hour), rows)
}

func (s *Store) upsert(ctx context.Context, table string, bucket time.Time, rows []AggRow) (int, error) {
	if len(rows) == 0 {
		return 0, nil
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	stmt := fmt.Sprintf(`
INSERT INTO %s (bucket_start, metric, labels, value, extra, updated_at)
VALUES ($1, $2, $3, $4, $5, now())
ON CONFLICT (bucket_start, metric, labels)
DO UPDATE SET value = EXCLUDED.value, extra = EXCLUDED.extra, updated_at = now()`, table)
	b := &pgx.Batch{}
	for _, r := range rows {
		b.Queue(stmt, bucket, r.Metric, labelsJSON(r.Labels), r.Value, extraJSON(r.Extra))
	}
	br := tx.SendBatch(ctx, b)
	n := 0
	for range rows {
		if _, err := br.Exec(); err != nil {
			_ = br.Close()
			return n, fmt.Errorf("upsert %s: %w", table, err)
		}
		n++
	}
	if err := br.Close(); err != nil {
		return n, fmt.Errorf("upsert %s batch close: %w", table, err)
	}
	return n, tx.Commit(ctx)
}

// recordJob 记录聚合任务执行。
func (s *Store) recordJob(ctx context.Context, jobType string, start, end time.Time, status string, rows int, errMsg string) error {
	_, err := s.db.Exec(ctx, `
INSERT INTO aggregation_jobs (job_type, window_start, window_end, status, error, rows_written, finished_at)
VALUES ($1, $2, $3, $4, $5, $6, now())`, jobType, start, end, status, errMsg, rows)
	return err
}

// DomainAppMap 域名→应用映射（访问日志归应用用）。
type DomainAppMap struct {
	ByHost map[string]string // normalized hostname -> app code
}

// RefreshDomainAppMap 从数据库刷新域名映射。
func (s *Store) RefreshDomainAppMap(ctx context.Context) (*DomainAppMap, error) {
	rows, err := s.db.Query(ctx, `
SELECT d.normalized_hostname, a.code FROM application_domains d
JOIN applications a ON a.id = d.application_id
WHERE d.deleted_at IS NULL AND a.deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := &DomainAppMap{ByHost: map[string]string{}}
	for rows.Next() {
		var host, code string
		if err := rows.Scan(&host, &code); err != nil {
			return nil, err
		}
		m.ByHost[host] = code
	}
	return m, rows.Err()
}

// QueryRange 查询指标时间序列（按桶升序）。
func (s *Store) QueryRange(ctx context.Context, table, metric string, labels map[string]string, start, end time.Time) ([]AggRow, []time.Time, error) {
	where := "metric = $1 AND bucket_start >= $2 AND bucket_start < $3"
	args := []interface{}{metric, start, end}
	if len(labels) > 0 {
		where += " AND labels @> $4"
		args = append(args, labelsJSON(labels))
	}
	rows, err := s.db.Query(ctx, fmt.Sprintf(`
SELECT bucket_start, value, extra FROM %s WHERE %s ORDER BY bucket_start`, table, where), args...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var out []AggRow
	var times []time.Time
	for rows.Next() {
		var t time.Time
		var v float64
		var extra []byte
		if err := rows.Scan(&t, &v, &extra); err != nil {
			return nil, nil, err
		}
		var ex map[string]interface{}
		_ = json.Unmarshal(extra, &ex)
		out = append(out, AggRow{Metric: metric, Value: v, Extra: ex})
		times = append(times, t)
	}
	return out, times, rows.Err()
}

// SumRange 汇总区间指标值。
func (s *Store) SumRange(ctx context.Context, table, metric string, labels map[string]string, start, end time.Time) (float64, error) {
	where := "metric = $1 AND bucket_start >= $2 AND bucket_start < $3"
	args := []interface{}{metric, start, end}
	if len(labels) > 0 {
		where += " AND labels @> $4"
		args = append(args, labelsJSON(labels))
	}
	var sum float64
	err := s.db.QueryRow(ctx, fmt.Sprintf(`SELECT COALESCE(SUM(value),0) FROM %s WHERE %s`, table, where), args...).Scan(&sum)
	return sum, err
}

// SumRangeBatch 批量汇总多个无标签过滤的区间指标（单条 SQL 替代多次往返）。
func (s *Store) SumRangeBatch(ctx context.Context, table string, metricNames []string, start, end time.Time) (map[string]float64, error) {
	out := make(map[string]float64, len(metricNames))
	if len(metricNames) == 0 {
		return out, nil
	}
	rows, err := s.db.Query(ctx, fmt.Sprintf(`
SELECT metric, COALESCE(SUM(value), 0)
FROM %s
WHERE metric = ANY($1) AND bucket_start >= $2 AND bucket_start < $3
GROUP BY metric`, table), metricNames, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var m string
		var v float64
		if err := rows.Scan(&m, &v); err != nil {
			return nil, err
		}
		out[m] = v
	}
	return out, rows.Err()
}

// QueryRangeBatch 批量查询多个指标的时间桶序列（按 metric + bucket_start 在库侧合并求和，
// 降低往返次数与网络传输量，口径与逐指标 QueryRange 后再按桶累加完全一致）。
func (s *Store) QueryRangeBatch(ctx context.Context, table string, metricNames []string, start, end time.Time) (map[string][]time.Time, map[string][]float64, error) {
	times := make(map[string][]time.Time, len(metricNames))
	vals := make(map[string][]float64, len(metricNames))
	if len(metricNames) == 0 {
		return times, vals, nil
	}
	rows, err := s.db.Query(ctx, fmt.Sprintf(`
SELECT metric, bucket_start, SUM(value)
FROM %s
WHERE metric = ANY($1) AND bucket_start >= $2 AND bucket_start < $3
GROUP BY metric, bucket_start
ORDER BY metric, bucket_start`, table), metricNames, start, end)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var m string
		var t time.Time
		var v float64
		if err := rows.Scan(&m, &t, &v); err != nil {
			return nil, nil, err
		}
		times[m] = append(times[m], t)
		vals[m] = append(vals[m], v)
	}
	return times, vals, rows.Err()
}

// TopLabels 按值排序取标签排行（如攻击类型/IP/应用）。
func (s *Store) TopLabels(ctx context.Context, table, metric, labelKey string, start, end time.Time, limit int) ([]struct {
	Key   string
	Value float64
}, error,
) {
	if limit <= 0 || limit > 100 {
		limit = 10
	}
	rows, err := s.db.Query(ctx, fmt.Sprintf(`
SELECT labels->>$1 AS k, SUM(value) AS v FROM %s
WHERE metric = $2 AND bucket_start >= $3 AND bucket_start < $4
GROUP BY k ORDER BY v DESC LIMIT $5`, table), labelKey, metric, start, end, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []struct {
		Key   string
		Value float64
	}
	for rows.Next() {
		var k *string
		var v float64
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		if k != nil {
			out = append(out, struct {
				Key   string
				Value float64
			}{*k, v})
		}
	}
	return out, rows.Err()
}
