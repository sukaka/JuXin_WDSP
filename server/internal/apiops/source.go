// source.go 内置任务的只读数据源：Source 接口（SQL 与测试替身共用）+ PostgreSQL 实现。
// 全部为确定性只读查询，数据源表：api_endpoints（资产）、api_runtime_findings（风险发现）、
// api_weaknesses（弱点）、api_sensitive_fields（涉敏字段）。状态词表口径：
// findings 未闭环 = NEW/CONFIRMED/IN_PROGRESS（迁移 000042）；弱点待整改 =
// NEW/CONFIRMED/TO_FIX/REPRODUCED（迁移 000039）。
package apiops

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// findingsOpenStatuses 风险发现「未闭环」状态词表（000042 七态中前三态）。
var findingsOpenStatuses = []string{"NEW", "CONFIRMED", "IN_PROGRESS"}

// weaknessOpenStatuses 弱点「待整改」状态词表（000039 七态；FIXED/IGNORED/ARCHIVED 视为已收口）。
var weaknessOpenStatuses = []string{"NEW", "CONFIRMED", "TO_FIX", "REPRODUCED"}

// EndpointItem 端点清单项。
type EndpointItem struct {
	ID          uuid.UUID `json:"id"`
	EndpointKey string    `json:"endpoint_key"`
	Method      string    `json:"method"`
	Path        string    `json:"path"`
	AssetStatus string    `json:"asset_status"`
	FirstSeenAt time.Time `json:"first_seen_at"`
}

// FindingItem 风险发现清单项（endpoint_key 经 LEFT JOIN 解析，端点已删时为空串）。
type FindingItem struct {
	ID          uuid.UUID `json:"id"`
	EndpointKey string    `json:"endpoint_key"`
	FindingType string    `json:"finding_type"`
	Severity    string    `json:"severity"`
	Status      string    `json:"status"`
	Title       string    `json:"title"`
	Count       int       `json:"count"`
	FirstSeenAt time.Time `json:"first_seen_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`
}

// WeaknessItem 弱点清单项。
type WeaknessItem struct {
	ID           uuid.UUID  `json:"id"`
	EndpointKey  string     `json:"endpoint_key"`
	WeaknessCode string     `json:"weakness_code"`
	WeaknessName string     `json:"weakness_name"`
	Severity     string     `json:"severity"`
	Status       string     `json:"status"`
	Owner        string     `json:"owner"`
	DueDate      *time.Time `json:"due_date"`
}

// SensitiveFieldItem 涉敏字段清单项。
type SensitiveFieldItem struct {
	ID          uuid.UUID `json:"id"`
	EndpointKey string    `json:"endpoint_key"`
	Direction   string    `json:"direction"`
	Path        string    `json:"path"`
	DataType    string    `json:"data_type"`
	FirstSeen   time.Time `json:"first_seen"`
}

// TypeCount 类型分桶计数（finding_type / data_type 共用）。
type TypeCount struct {
	Type  string `json:"type"`
	Count int64  `json:"count"`
}

// AssetDigestData API_ASSET_DIGEST 原料。
type AssetDigestData struct {
	TotalEndpoints    int64          `json:"total_endpoints"`
	StatusCounts      []TypeCount    `json:"status_counts"`       // asset_status 分桶
	NewInWindow       int64          `json:"new_in_window"`       // 窗口内新发现端点数
	ConfirmedInWindow int64          `json:"confirmed_in_window"` // 窗口内人工确认数
	ShadowOpen        int64          `json:"shadow_open"`         // Shadow 未闭环发现数
	ZombieOpen        int64          `json:"zombie_open"`         // Zombie 未闭环发现数
	NewEndpoints      []EndpointItem `json:"new_endpoints"`       // 窗口内新增端点清单（按发现时间倒序，限 limit 条）
}

// ShadowReviewData SHADOW_REVIEW 原料。
type ShadowReviewData struct {
	OpenTotal   int64         `json:"open_total"`    // Shadow 未闭环总数
	NewInWindow int64         `json:"new_in_window"` // 窗口内新增 Shadow 数
	Items       []FindingItem `json:"items"`         // 未闭环 Shadow 清单（按最近命中倒序，限 limit 条）
}

// WeaknessFollowData WEAKNESS_FOLLOW 原料。
type WeaknessFollowData struct {
	OpenTotal     int64          `json:"open_total"`  // 待整改总数
	NoDueDate     int64          `json:"no_due_date"` // 未设整改期限的待整改数
	Overdue       []WeaknessItem `json:"overdue"`     // 已超期清单（按期限升序）
	DueSoon       []WeaknessItem `json:"due_soon"`    // 临近到期清单（now..now+dueWithinDays，按期限升序）
	DueWithinDays int            `json:"due_within_days"`
}

// RiskDigestData RISK_DIGEST 原料。
type RiskDigestData struct {
	OpenHighTotal    int64         `json:"open_high_total"`   // HIGH+CRITICAL 未闭环总数
	OpenCritical     int64         `json:"open_critical"`     // 其中 CRITICAL 数
	NewInWindow      int64         `json:"new_in_window"`     // 窗口内新增高危数
	TypeDistribution []TypeCount   `json:"type_distribution"` // 按 finding_type 分桶（未闭环高危）
	Items            []FindingItem `json:"items"`             // 重点清单（CRITICAL 优先 + 最近命中倒序，限 limit 条）
}

// SensitiveDigestData SENSITIVE_DIGEST 原料。
type SensitiveDigestData struct {
	SensitiveEndpointCount int64                `json:"sensitive_endpoint_count"` // 涉敏端点数（去重）
	SensitiveFieldCount    int64                `json:"sensitive_field_count"`    // 涉敏字段行数
	NewFieldsInWindow      int64                `json:"new_fields_in_window"`     // 窗口内新增涉敏字段数
	TypeDistribution       []TypeCount          `json:"type_distribution"`        // 按数据类型分桶
	NewFields              []SensitiveFieldItem `json:"new_fields"`               // 窗口内新增清单（限 limit 条）
}

// Source 内置任务只读数据源（SQL 与测试替身共用）。
type Source interface {
	AssetDigest(ctx context.Context, since time.Time, limit int) (*AssetDigestData, error)
	ShadowReview(ctx context.Context, since time.Time, limit int) (*ShadowReviewData, error)
	WeaknessFollow(ctx context.Context, now time.Time, dueWithinDays, limit int) (*WeaknessFollowData, error)
	RiskDigest(ctx context.Context, since time.Time, limit int) (*RiskDigestData, error)
	SensitiveDigest(ctx context.Context, since time.Time, limit int) (*SensitiveDigestData, error)
}

// 确保 *SQLSource 实现 Source。
var _ Source = (*SQLSource)(nil)

// SQLSource PostgreSQL 只读数据源。
type SQLSource struct {
	db *pgxpool.Pool
}

// NewSQLSource 创建。
func NewSQLSource(db *pgxpool.Pool) *SQLSource { return &SQLSource{db: db} }

// AssetDigest 资产变化摘要原料。
func (s *SQLSource) AssetDigest(ctx context.Context, since time.Time, limit int) (*AssetDigestData, error) {
	out := &AssetDigestData{StatusCounts: []TypeCount{}, NewEndpoints: []EndpointItem{}}
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM api_endpoints`).Scan(&out.TotalEndpoints); err != nil {
		return nil, fmt.Errorf("asset digest total: %w", err)
	}
	rows, err := s.db.Query(ctx, `SELECT asset_status, count(*) FROM api_endpoints GROUP BY asset_status ORDER BY count(*) DESC, asset_status`)
	if err != nil {
		return nil, fmt.Errorf("asset digest status counts: %w", err)
	}
	for rows.Next() {
		var it TypeCount
		if err := rows.Scan(&it.Type, &it.Count); err != nil {
			rows.Close()
			return nil, err
		}
		out.StatusCounts = append(out.StatusCounts, it)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM api_endpoints WHERE first_seen_at >= $1`, since).Scan(&out.NewInWindow); err != nil {
		return nil, fmt.Errorf("asset digest new count: %w", err)
	}
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM api_endpoints WHERE confirmed_at IS NOT NULL AND confirmed_at >= $1`, since).Scan(&out.ConfirmedInWindow); err != nil {
		return nil, fmt.Errorf("asset digest confirmed count: %w", err)
	}
	// Shadow/Zombie 未闭环计数
	rows2, err := s.db.Query(ctx, `
SELECT finding_type, count(*) FROM api_runtime_findings
WHERE finding_type IN ('SHADOW','ZOMBIE') AND status = ANY($1) GROUP BY finding_type`, findingsOpenStatuses)
	if err != nil {
		return nil, fmt.Errorf("asset digest shadow/zombie: %w", err)
	}
	for rows2.Next() {
		var ft string
		var n int64
		if err := rows2.Scan(&ft, &n); err != nil {
			rows2.Close()
			return nil, err
		}
		if ft == "SHADOW" {
			out.ShadowOpen = n
		} else {
			out.ZombieOpen = n
		}
	}
	rows2.Close()
	if err := rows2.Err(); err != nil {
		return nil, err
	}
	list, err := s.queryEndpoints(ctx, `
SELECT id, endpoint_key, http_method, normalized_path, asset_status, first_seen_at
FROM api_endpoints WHERE first_seen_at >= $1 ORDER BY first_seen_at DESC LIMIT $2`, since, limit)
	if err != nil {
		return nil, fmt.Errorf("asset digest new list: %w", err)
	}
	out.NewEndpoints = list
	return out, nil
}

// ShadowReview Shadow API 运营原料。
func (s *SQLSource) ShadowReview(ctx context.Context, since time.Time, limit int) (*ShadowReviewData, error) {
	out := &ShadowReviewData{Items: []FindingItem{}}
	if err := s.db.QueryRow(ctx, `
SELECT count(*) FROM api_runtime_findings WHERE finding_type = 'SHADOW' AND status = ANY($1)`, findingsOpenStatuses).Scan(&out.OpenTotal); err != nil {
		return nil, fmt.Errorf("shadow review open total: %w", err)
	}
	if err := s.db.QueryRow(ctx, `
SELECT count(*) FROM api_runtime_findings WHERE finding_type = 'SHADOW' AND first_seen_at >= $1`, since).Scan(&out.NewInWindow); err != nil {
		return nil, fmt.Errorf("shadow review new count: %w", err)
	}
	items, err := s.queryFindings(ctx, `
SELECT f.id, COALESCE(e.endpoint_key, ''), f.finding_type, f.severity, f.status, f.title, f.count, f.first_seen_at, f.last_seen_at
FROM api_runtime_findings f LEFT JOIN api_endpoints e ON e.id = f.endpoint_id
WHERE f.finding_type = 'SHADOW' AND f.status = ANY($1)
ORDER BY f.last_seen_at DESC LIMIT $2`, findingsOpenStatuses, limit)
	if err != nil {
		return nil, fmt.Errorf("shadow review list: %w", err)
	}
	out.Items = items
	return out, nil
}

// WeaknessFollow 弱点跟进原料。
func (s *SQLSource) WeaknessFollow(ctx context.Context, now time.Time, dueWithinDays, limit int) (*WeaknessFollowData, error) {
	out := &WeaknessFollowData{Overdue: []WeaknessItem{}, DueSoon: []WeaknessItem{}, DueWithinDays: dueWithinDays}
	if err := s.db.QueryRow(ctx, `
SELECT count(*) FROM api_weaknesses WHERE status = ANY($1)`, weaknessOpenStatuses).Scan(&out.OpenTotal); err != nil {
		return nil, fmt.Errorf("weakness follow open total: %w", err)
	}
	if err := s.db.QueryRow(ctx, `
SELECT count(*) FROM api_weaknesses WHERE status = ANY($1) AND due_date IS NULL`, weaknessOpenStatuses).Scan(&out.NoDueDate); err != nil {
		return nil, fmt.Errorf("weakness follow no-due count: %w", err)
	}
	overdue, err := s.queryWeaknesses(ctx, `
SELECT w.id, COALESCE(e.endpoint_key, ''), w.weakness_code, w.weakness_name, w.severity, w.status, w.owner, w.due_date
FROM api_weaknesses w LEFT JOIN api_endpoints e ON e.id = w.endpoint_id
WHERE w.status = ANY($1) AND w.due_date IS NOT NULL AND w.due_date < $2
ORDER BY w.due_date LIMIT $3`, weaknessOpenStatuses, now, limit)
	if err != nil {
		return nil, fmt.Errorf("weakness follow overdue: %w", err)
	}
	out.Overdue = overdue
	dueSoon, err := s.queryWeaknesses(ctx, `
SELECT w.id, COALESCE(e.endpoint_key, ''), w.weakness_code, w.weakness_name, w.severity, w.status, w.owner, w.due_date
FROM api_weaknesses w LEFT JOIN api_endpoints e ON e.id = w.endpoint_id
WHERE w.status = ANY($1) AND w.due_date IS NOT NULL AND w.due_date >= $2 AND w.due_date <= $3
ORDER BY w.due_date LIMIT $4`, weaknessOpenStatuses, now, now.Add(time.Duration(dueWithinDays)*24*time.Hour), limit)
	if err != nil {
		return nil, fmt.Errorf("weakness follow due soon: %w", err)
	}
	out.DueSoon = dueSoon
	return out, nil
}

// RiskDigest 高风险发现摘要原料。
func (s *SQLSource) RiskDigest(ctx context.Context, since time.Time, limit int) (*RiskDigestData, error) {
	out := &RiskDigestData{TypeDistribution: []TypeCount{}, Items: []FindingItem{}}
	if err := s.db.QueryRow(ctx, `
SELECT count(*), count(*) FILTER (WHERE severity = 'CRITICAL') FROM api_runtime_findings
WHERE severity IN ('HIGH','CRITICAL') AND status = ANY($1)`, findingsOpenStatuses).Scan(&out.OpenHighTotal, &out.OpenCritical); err != nil {
		return nil, fmt.Errorf("risk digest totals: %w", err)
	}
	if err := s.db.QueryRow(ctx, `
SELECT count(*) FROM api_runtime_findings
WHERE severity IN ('HIGH','CRITICAL') AND status = ANY($1) AND first_seen_at >= $2`, findingsOpenStatuses, since).Scan(&out.NewInWindow); err != nil {
		return nil, fmt.Errorf("risk digest new count: %w", err)
	}
	rows, err := s.db.Query(ctx, `
SELECT finding_type, count(*) FROM api_runtime_findings
WHERE severity IN ('HIGH','CRITICAL') AND status = ANY($1)
GROUP BY finding_type ORDER BY count(*) DESC, finding_type`, findingsOpenStatuses)
	if err != nil {
		return nil, fmt.Errorf("risk digest type distribution: %w", err)
	}
	for rows.Next() {
		var it TypeCount
		if err := rows.Scan(&it.Type, &it.Count); err != nil {
			rows.Close()
			return nil, err
		}
		out.TypeDistribution = append(out.TypeDistribution, it)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	items, err := s.queryFindings(ctx, `
SELECT f.id, COALESCE(e.endpoint_key, ''), f.finding_type, f.severity, f.status, f.title, f.count, f.first_seen_at, f.last_seen_at
FROM api_runtime_findings f LEFT JOIN api_endpoints e ON e.id = f.endpoint_id
WHERE f.severity IN ('HIGH','CRITICAL') AND f.status = ANY($1)
ORDER BY CASE f.severity WHEN 'CRITICAL' THEN 0 ELSE 1 END, f.last_seen_at DESC LIMIT $2`, findingsOpenStatuses, limit)
	if err != nil {
		return nil, fmt.Errorf("risk digest list: %w", err)
	}
	out.Items = items
	return out, nil
}

// SensitiveDigest 涉敏概览原料。
func (s *SQLSource) SensitiveDigest(ctx context.Context, since time.Time, limit int) (*SensitiveDigestData, error) {
	out := &SensitiveDigestData{TypeDistribution: []TypeCount{}, NewFields: []SensitiveFieldItem{}}
	if err := s.db.QueryRow(ctx, `
SELECT count(DISTINCT endpoint_id), count(*) FROM api_sensitive_fields`).Scan(&out.SensitiveEndpointCount, &out.SensitiveFieldCount); err != nil {
		return nil, fmt.Errorf("sensitive digest totals: %w", err)
	}
	rows, err := s.db.Query(ctx, `
SELECT data_type, count(*) FROM api_sensitive_fields GROUP BY data_type ORDER BY count(*) DESC, data_type`)
	if err != nil {
		return nil, fmt.Errorf("sensitive digest type distribution: %w", err)
	}
	for rows.Next() {
		var it TypeCount
		if err := rows.Scan(&it.Type, &it.Count); err != nil {
			rows.Close()
			return nil, err
		}
		out.TypeDistribution = append(out.TypeDistribution, it)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// first_seen 自 000040 起回填非空；防御性 COALESCE 兼容历史空值
	if err := s.db.QueryRow(ctx, `
SELECT count(*) FROM api_sensitive_fields WHERE COALESCE(first_seen, created_at) >= $1`, since).Scan(&out.NewFieldsInWindow); err != nil {
		return nil, fmt.Errorf("sensitive digest new count: %w", err)
	}
	rows2, err := s.db.Query(ctx, `
SELECT f.id, COALESCE(e.endpoint_key, ''), f.direction, f.structured_path, f.data_type, COALESCE(f.first_seen, f.created_at)
FROM api_sensitive_fields f LEFT JOIN api_endpoints e ON e.id = f.endpoint_id
WHERE COALESCE(f.first_seen, f.created_at) >= $1
ORDER BY 6 DESC LIMIT $2`, since, limit)
	if err != nil {
		return nil, fmt.Errorf("sensitive digest new list: %w", err)
	}
	defer rows2.Close()
	for rows2.Next() {
		var it SensitiveFieldItem
		if err := rows2.Scan(&it.ID, &it.EndpointKey, &it.Direction, &it.Path, &it.DataType, &it.FirstSeen); err != nil {
			return nil, err
		}
		out.NewFields = append(out.NewFields, it)
	}
	if err := rows2.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// queryEndpoints 端点清单查询公共路径。
func (s *SQLSource) queryEndpoints(ctx context.Context, sql string, args ...any) ([]EndpointItem, error) {
	rows, err := s.db.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []EndpointItem{}
	for rows.Next() {
		var it EndpointItem
		if err := rows.Scan(&it.ID, &it.EndpointKey, &it.Method, &it.Path, &it.AssetStatus, &it.FirstSeenAt); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// queryFindings 发现清单查询公共路径。
func (s *SQLSource) queryFindings(ctx context.Context, sql string, args ...any) ([]FindingItem, error) {
	rows, err := s.db.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []FindingItem{}
	for rows.Next() {
		var it FindingItem
		if err := rows.Scan(&it.ID, &it.EndpointKey, &it.FindingType, &it.Severity, &it.Status, &it.Title, &it.Count, &it.FirstSeenAt, &it.LastSeenAt); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// queryWeaknesses 弱点清单查询公共路径。
func (s *SQLSource) queryWeaknesses(ctx context.Context, sql string, args ...any) ([]WeaknessItem, error) {
	rows, err := s.db.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []WeaknessItem{}
	for rows.Next() {
		var it WeaknessItem
		if err := rows.Scan(&it.ID, &it.EndpointKey, &it.WeaknessCode, &it.WeaknessName, &it.Severity, &it.Status, &it.Owner, &it.DueDate); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}
