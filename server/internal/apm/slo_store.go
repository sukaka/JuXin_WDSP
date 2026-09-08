// slo_store.go APM SLO 仓储：apm_slos 定义 CRUD + 窗口评估（当前值/达标率/错误预算/状态）
// + 达标率趋势。评估数据源固定为 metric_hour_aggregates（7d/30d 窗口纪律上不扫分钟表；
// 小时表由分钟表 rollup 产出并保留直方图桶，跨天分位数/占比可估算）。
// 所有 SQL 参数化；service 以 labels->>'app' 精确匹配（SLO.service 即应用编码）。
package apm

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/metrics"
	"github.com/jiuzhang-waf/server/internal/systemalerts"
)

// SLO 仓储错误。
var (
	// ErrSLONotFound SLO 不存在（404 分支）。
	ErrSLONotFound = errors.New("slo not found")
	// ErrSLOConflict 同 service+metric_type+window 的 SLO 定义已存在（唯一约束兜底，409 分支）。
	ErrSLOConflict = errors.New("slo definition conflict")
)

// SLOStore APM SLO 仓储。
type SLOStore struct {
	db *pgxpool.Pool
}

// NewSLOStore 创建 SLO 仓储。
func NewSLOStore(db *pgxpool.Pool) *SLOStore {
	return &SLOStore{db: db}
}

// isUniqueViolation 唯一约束冲突（23505）。
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// scanSLO 扫描 apm_slos 行。
func scanSLO(row pgx.Row) (*SLO, error) {
	var s SLO
	if err := row.Scan(&s.ID, &s.Name, &s.Service, &s.MetricType, &s.Target, &s.Window,
		&s.CreatedBy, &s.CreatedAt, &s.UpdatedAt); err != nil {
		return nil, err
	}
	return &s, nil
}

// sloColumns apm_slos 列清单（window 为 PG 保留字，必须带双引号）。
const sloColumns = `id, name, service, metric_type, target, "window", created_by, created_at, updated_at`

// CreateSLO 创建 SLO 定义（唯一冲突映射 ErrSLOConflict）。
func (s *SLOStore) CreateSLO(ctx context.Context, slo *SLO) error {
	row := s.db.QueryRow(ctx, `
INSERT INTO apm_slos (name, service, metric_type, target, "window", created_by)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING `+sloColumns,
		slo.Name, slo.Service, slo.MetricType, slo.Target, slo.Window, slo.CreatedBy)
	created, err := scanSLO(row)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrSLOConflict
		}
		return fmt.Errorf("create slo: %w", err)
	}
	*slo = *created
	return nil
}

// GetSLO 按 ID 取 SLO 定义（不存在返回 ErrSLONotFound）。
func (s *SLOStore) GetSLO(ctx context.Context, id uuid.UUID) (*SLO, error) {
	slo, err := scanSLO(s.db.QueryRow(ctx, `SELECT `+sloColumns+` FROM apm_slos WHERE id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrSLONotFound
		}
		return nil, fmt.Errorf("get slo: %w", err)
	}
	return slo, nil
}

// UpdateSLO 全量更新 SLO 定义（不存在返回 ErrSLONotFound；唯一冲突映射 ErrSLOConflict）。
func (s *SLOStore) UpdateSLO(ctx context.Context, slo *SLO) error {
	row := s.db.QueryRow(ctx, `
UPDATE apm_slos SET name = $2, service = $3, metric_type = $4, target = $5, "window" = $6, updated_at = now()
WHERE id = $1
RETURNING `+sloColumns,
		slo.ID, slo.Name, slo.Service, slo.MetricType, slo.Target, slo.Window)
	updated, err := scanSLO(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrSLONotFound
		}
		if isUniqueViolation(err) {
			return ErrSLOConflict
		}
		return fmt.Errorf("update slo: %w", err)
	}
	*slo = *updated
	return nil
}

// DeleteSLO 删除 SLO 定义（不存在返回 ErrSLONotFound）。
func (s *SLOStore) DeleteSLO(ctx context.Context, id uuid.UUID) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM apm_slos WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete slo: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrSLONotFound
	}
	return nil
}

// ListSLOs 列出全部 SLO 定义（按创建时间升序，稳定顺序；SLO 数量受唯一约束与自然
// 基数约束，全量列出不分页）。
func (s *SLOStore) ListSLOs(ctx context.Context) ([]SLO, error) {
	rows, err := s.db.Query(ctx, `SELECT `+sloColumns+` FROM apm_slos ORDER BY created_at ASC, id ASC`)
	if err != nil {
		return nil, fmt.Errorf("list slos: %w", err)
	}
	defer rows.Close()
	out := []SLO{}
	for rows.Next() {
		var slo SLO
		if err := rows.Scan(&slo.ID, &slo.Name, &slo.Service, &slo.MetricType, &slo.Target, &slo.Window,
			&slo.CreatedBy, &slo.CreatedAt, &slo.UpdatedAt); err != nil {
			return nil, fmt.Errorf("list slos scan: %w", err)
		}
		out = append(out, slo)
	}
	return out, rows.Err()
}

// ---------- 窗口评估（数据源固定 metric_hour_aggregates） ----------

// sloAggTable SLO 窗口聚合源：恒为小时表（7d/30d 窗口禁止全窗口扫分钟表——
// 性能纪律；小时表直方图桶经 rollup 合并保留，分位数/占比可跨天估算）。
const sloAggTable = "metric_hour_aggregates"

// loadSLOStats 窗口 [start, end) 单服务聚合：请求量（按 status_class）与合并耗时直方图。
func (s *SLOStore) loadSLOStats(ctx context.Context, service string, start, end time.Time) (*sloWindowStats, error) {
	stats := &sloWindowStats{dur: make([]int, len(metrics.DurationBucketsMs)+1)}

	// 请求量与 5xx
	row := s.db.QueryRow(ctx, `
SELECT COALESCE(SUM(value), 0),
       COALESCE(SUM(value) FILTER (WHERE labels->>'status_class' = '5xx'), 0)
FROM `+sloAggTable+`
WHERE metric = $1 AND bucket_start >= $2 AND bucket_start < $3 AND labels->>'app' = $4`,
		metrics.HTTPRequestsTotal, start, end, service)
	if err := row.Scan(&stats.requests, &stats.err5xx); err != nil {
		return nil, fmt.Errorf("slo requests: %w", err)
	}

	// 耗时直方图（extra.buckets 按桶序合并；缺失/NULL 时 lateral 为空集自动跳过）
	rows, err := s.db.Query(ctx, `
SELECT b.idx, SUM(b.cnt::int)
FROM `+sloAggTable+`,
     LATERAL jsonb_array_elements_text(extra->'buckets') WITH ORDINALITY AS b(cnt, idx)
WHERE metric = $1 AND bucket_start >= $2 AND bucket_start < $3 AND labels->>'app' = $4
GROUP BY 1`, metrics.HTTPRequestDurationMs, start, end, service)
	if err != nil {
		return nil, fmt.Errorf("slo duration: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var idx, cnt int
		if err := rows.Scan(&idx, &cnt); err != nil {
			return nil, fmt.Errorf("slo duration scan: %w", err)
		}
		if idx >= 1 && idx <= len(stats.dur) {
			stats.dur[idx-1] += cnt
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("slo duration iterate: %w", err)
	}
	return stats, nil
}

// EvaluateSLO 评估单条 SLO 当前窗口状态（窗口 [now−window, now)，UTC）。
func (s *SLOStore) EvaluateSLO(ctx context.Context, def *SLO, now time.Time) (*SLOListItem, error) {
	end := now.UTC()
	start := end.Add(-sloWindowDuration(def.Window))
	stats, err := s.loadSLOStats(ctx, def.Service, start, end)
	if err != nil {
		return nil, err
	}
	return evalSLO(def, stats), nil
}

// EvaluateAllSLOs 评估全部 SLO（列表接口与告警评估共用；SLO 定义逐条评估——
// 定义数量受 service×metric×window 唯一约束与自然基数约束，逐条两条聚合查询可控）。
func (s *SLOStore) EvaluateAllSLOs(ctx context.Context, now time.Time) ([]SLOListItem, error) {
	defs, err := s.ListSLOs(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]SLOListItem, 0, len(defs))
	for i := range defs {
		item, err := s.EvaluateSLO(ctx, &defs[i], now)
		if err != nil {
			return nil, err
		}
		out = append(out, *item)
	}
	return out, nil
}

// SLOTrend 窗口内达标率趋势（7d 按小时桶、30d 按天桶；零流量桶达标率计 1；
// 时间轴连续，无数据桶补点）。
func (s *SLOStore) SLOTrend(ctx context.Context, def *SLO, now time.Time) ([]SLOTrendPoint, error) {
	end := now.UTC()
	start := end.Add(-sloWindowDuration(def.Window))
	step := sloTrendStep(def.Window)

	// 预置连续时间轴（按桶起点升序）
	buckets := map[time.Time]*sloWindowStats{}
	order := []time.Time{}
	for t := start.Truncate(step); t.Before(end); t = t.Add(step) {
		buckets[t] = &sloWindowStats{dur: make([]int, len(metrics.DurationBucketsMs)+1)}
		order = append(order, t)
	}
	get := func(ts time.Time) *sloWindowStats {
		return buckets[ts.UTC().Truncate(step)]
	}

	// 请求量与 5xx（按小时桶 × status_class，Go 侧合并到天桶）
	rows, err := s.db.Query(ctx, `
SELECT bucket_start, labels->>'status_class', SUM(value)
FROM `+sloAggTable+`
WHERE metric = $1 AND bucket_start >= $2 AND bucket_start < $3 AND labels->>'app' = $4
GROUP BY 1, 2`, metrics.HTTPRequestsTotal, start, end, def.Service)
	if err != nil {
		return nil, fmt.Errorf("slo trend requests: %w", err)
	}
	for rows.Next() {
		var ts time.Time
		var class string
		var v float64
		if err := rows.Scan(&ts, &class, &v); err != nil {
			rows.Close()
			return nil, fmt.Errorf("slo trend requests scan: %w", err)
		}
		if b := get(ts); b != nil {
			b.requests += v
			if class == "5xx" {
				b.err5xx += v
			}
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("slo trend requests iterate: %w", err)
	}

	if def.MetricType == SLOMetricLatencyP95 {
		rows, err = s.db.Query(ctx, `
SELECT bucket_start, b.idx, SUM(b.cnt::int)
FROM `+sloAggTable+`,
     LATERAL jsonb_array_elements_text(extra->'buckets') WITH ORDINALITY AS b(cnt, idx)
WHERE metric = $1 AND bucket_start >= $2 AND bucket_start < $3 AND labels->>'app' = $4
GROUP BY 1, 2`, metrics.HTTPRequestDurationMs, start, end, def.Service)
		if err != nil {
			return nil, fmt.Errorf("slo trend duration: %w", err)
		}
		for rows.Next() {
			var ts time.Time
			var idx, cnt int
			if err := rows.Scan(&ts, &idx, &cnt); err != nil {
				rows.Close()
				return nil, fmt.Errorf("slo trend duration scan: %w", err)
			}
			if b := get(ts); b != nil && idx >= 1 && idx <= len(b.dur) {
				b.dur[idx-1] += cnt
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("slo trend duration iterate: %w", err)
		}
	}

	out := make([]SLOTrendPoint, 0, len(order))
	for _, t := range order {
		b := buckets[t]
		p := SLOTrendPoint{BucketStart: t, ComplianceRatio: 1}
		if def.MetricType == SLOMetricAvailability {
			if b.requests > 0 {
				p.ComplianceRatio = 1 - b.err5xx/b.requests
			}
		} else if n := b.histogramTotal(); n > 0 {
			p.ComplianceRatio = countLEFromBuckets(b.dur, def.Target) / float64(n)
		}
		out = append(out, p)
	}
	return out, nil
}

// ---------- 告警评估供给（systemalerts.SLOBreachStatsStore 实现） ----------

// SLOBreachStates 实现 systemalerts.SLOBreachStatsStore：评估全部 SLO，BREACHED 项
// 携带预格式化告警文案（口径文案归 apm 包；引擎只负责 Raise/合并/恢复机械动作）。
// 读数失败整体返回错误（引擎侧中止本轮，不清动既有告警）。
func (s *SLOStore) SLOBreachStates(ctx context.Context) ([]systemalerts.SLOBreachState, error) {
	items, err := s.EvaluateAllSLOs(ctx, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	out := make([]systemalerts.SLOBreachState, 0, len(items))
	for i := range items {
		it := &items[i]
		st := systemalerts.SLOBreachState{
			Service:  it.Service,
			Name:     it.Name,
			Breached: it.Status == SLOStatusBreached,
		}
		if st.Breached && it.CurrentValue != nil {
			st.Title, st.Message = sloBreachMessage(it)
		}
		out = append(out, st)
	}
	return out, nil
}

// sloBreachMessage 生成违约告警标题与详情（只含服务/SLO 名/指标口径数值，
// 不含任何请求正文、参数或原始路径，符合 §18.2 通知脱敏要求）。
func sloBreachMessage(it *SLOListItem) (title, message string) {
	windowText := "7 天"
	if it.Window == SLOWindow30d {
		windowText = "30 天"
	}
	if it.MetricType == SLOMetricAvailability {
		return "SLO 可用性违约",
			fmt.Sprintf("服务 %s 的 SLO「%s」违约：最近%s可用性 %.4f（目标 %.4f），错误预算已耗尽（剩余 %.0f%%）",
				it.Service, it.Name, windowText, *it.CurrentValue, it.Target, it.ErrorBudgetRemaining*100)
	}
	return "SLO 时延 P95 违约",
		fmt.Sprintf("服务 %s 的 SLO「%s」违约：最近%s p95 约 %.0fms（阈值 %.0fms），错误预算已耗尽（剩余 %.0f%%）",
			it.Service, it.Name, windowText, *it.CurrentValue, it.Target, it.ErrorBudgetRemaining*100)
}

// 确保 SLOStore 满足告警引擎统计源接口（编译期断言）。
var _ systemalerts.SLOBreachStatsStore = (*SLOStore)(nil)
