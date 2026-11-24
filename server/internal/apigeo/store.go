// store.go 数据出境 PostgreSQL 仓储：看板/明细只读查询（Repository 接口，
// SQL 与内存实现共用，便于诚实单测）+ SweepOnce 生产写入侧（sweepStore 窄接口）。
// 过滤条件一律白名单拼接、值参数化。
package apigeo

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Repository 出境看板/明细只读仓储（SQL 与内存实现共用）。
type Repository interface {
	// ListEvents 明细分页（窗口与看板同口径；occurred_at 倒序）
	ListEvents(ctx context.Context, f EventFilter) ([]CrossBorderEvent, int64, error)
	// Dashboard 看板聚合（窗口 days 天；零值日趋势补齐）
	Dashboard(ctx context.Context, days int) (*DashboardData, error)
}

// runtimeEventRow SweepOnce 扫描的运行时事件行（api_runtime_events 子集）。
type runtimeEventRow struct {
	id             uuid.UUID
	endpointKey    string
	clientIP       string
	identity       string
	details        []byte
	occurredAt     time.Time
	finalAction    string
	responseStatus int
	apiLevel       string
}

// crossBorderRow SweepOnce 产出的待插入行（ID/created_at 由库填）。
type crossBorderRow struct {
	occurredAt    time.Time
	clientIP      string
	country       string
	endpointKey   string
	identity      string
	dataTypes     []string
	direction     string
	riskLevel     string
	sourceEventID uuid.UUID
}

// sweepStore SweepOnce 生产写入侧窄接口（SQL 与内存实现共用）。
type sweepStore interface {
	// Watermark 当前扫描水位（NULL = 从未扫描，首次全量回填）
	Watermark(ctx context.Context) (*time.Time, error)
	// FetchSensitiveEvents 水位之后含敏感明细且带 client_ip 的事件（occurred_at 升序，limit 封顶）
	FetchSensitiveEvents(ctx context.Context, after *time.Time, limit int) ([]runtimeEventRow, error)
	// DataTypeLevels 数据类型→敏感等级映射（api_sensitive_data_types；风险推导输入）
	DataTypeLevels(ctx context.Context) (map[string]string, error)
	// RecordCrossBorder 单事务写入观察行（(source_event_id, direction) 幂等）并推进水位；
	// 返回实际插入行数（冲突跳过不计）
	RecordCrossBorder(ctx context.Context, rows []crossBorderRow, watermark time.Time) (int, error)
}

// 确保 *Store 同时实现只读与生产写入侧接口（*MemStore 见 mem_store.go）。
var (
	_ Repository = (*Store)(nil)
	_ sweepStore = (*Store)(nil)
)

// Store 数据出境 PostgreSQL 仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建。
func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

// ---------- 只读查询 ----------

// eventCols 明细查询列。
const eventCols = `id, occurred_at, client_ip, country, asn, endpoint_key, identity_fingerprint,
	data_types, direction, risk_level, source_event_id, created_at`

// scanEvent 扫描一行观察记录（jsonb 数组列经 json.RawMessage 中转，空归一为 []）。
func scanEvent(row interface{ Scan(...any) error }) (*CrossBorderEvent, error) {
	var ev CrossBorderEvent
	var dataTypes json.RawMessage
	err := row.Scan(&ev.ID, &ev.OccurredAt, &ev.ClientIP, &ev.Country, &ev.Asn,
		&ev.EndpointKey, &ev.IdentityFingerprint, &dataTypes, &ev.Direction,
		&ev.RiskLevel, &ev.SourceEventID, &ev.CreatedAt)
	if err != nil {
		return nil, err
	}
	ev.DataTypes = []string{}
	if len(dataTypes) > 0 && string(dataTypes) != "null" {
		if err := json.Unmarshal(dataTypes, &ev.DataTypes); err != nil {
			return nil, err
		}
	}
	return &ev, nil
}

// ListEvents 明细分页（过滤条件白名单拼接，值一律参数化；occurred_at 倒序）。
func (s *Store) ListEvents(ctx context.Context, f EventFilter) ([]CrossBorderEvent, int64, error) {
	if f.Page <= 0 {
		f.Page = 1
	}
	if f.PageSize <= 0 {
		f.PageSize = 20
	}
	where := []string{`occurred_at >= CURRENT_DATE - ($1::int - 1) * interval '1 day'`}
	args := []any{clampDays(f.Days)}
	if f.Country != "" {
		args = append(args, f.Country)
		where = append(where, fmt.Sprintf("country = $%d", len(args)))
	}
	if f.Direction != "" {
		args = append(args, f.Direction)
		where = append(where, fmt.Sprintf("direction = $%d", len(args)))
	}
	if f.RiskLevel != "" {
		args = append(args, f.RiskLevel)
		where = append(where, fmt.Sprintf("risk_level = $%d", len(args)))
	}
	if f.EndpointKey != "" {
		args = append(args, f.EndpointKey)
		where = append(where, fmt.Sprintf("endpoint_key = $%d", len(args)))
	}
	cond := " WHERE " + strings.Join(where, " AND ")
	var total int64
	if err := s.db.QueryRow(ctx, "SELECT count(*) FROM api_cross_border_events"+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	rows, err := s.db.Query(ctx, `SELECT `+eventCols+` FROM api_cross_border_events`+cond+
		fmt.Sprintf(" ORDER BY occurred_at DESC, id DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []CrossBorderEvent{}
	for rows.Next() {
		ev, err := scanEvent(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *ev)
	}
	return out, total, rows.Err()
}

// Dashboard 看板聚合（SQL 实现）。趋势日期以数据库 CURRENT_DATE 为锚
// （与 occurred_at::date 分组同会话时区），零值日在 Go 侧补齐。
func (s *Store) Dashboard(ctx context.Context, days int) (*DashboardData, error) {
	days = clampDays(days)
	out := &DashboardData{
		Days:          days,
		ByCountry:     []CountryStat{},
		ByCountryType: []CountryTypeStat{},
		ByEndpoint:    []EndpointStat{},
		Trend:         []TrendPoint{},
	}
	const window = `occurred_at >= CURRENT_DATE - ($1::int - 1) * interval '1 day'`

	// 汇总
	if err := s.db.QueryRow(ctx, `
SELECT count(*), count(DISTINCT country), count(DISTINCT endpoint_key),
       count(*) FILTER (WHERE risk_level = 'HIGH')
FROM api_cross_border_events WHERE `+window, days).
		Scan(&out.Summary.TotalEvents, &out.Summary.CountryCount,
			&out.Summary.EndpointCount, &out.Summary.HighRiskCount); err != nil {
		return nil, fmt.Errorf("cross-border dashboard summary: %w", err)
	}

	// 国家/地区聚合（事件数降序）
	rows, err := s.db.Query(ctx, `
SELECT country, count(*), count(DISTINCT endpoint_key)
FROM api_cross_border_events WHERE `+window+` GROUP BY country
ORDER BY count(*) DESC, country`, days)
	if err != nil {
		return nil, fmt.Errorf("cross-border dashboard by country: %w", err)
	}
	for rows.Next() {
		var it CountryStat
		if err := rows.Scan(&it.Country, &it.EventCount, &it.EndpointCount); err != nil {
			rows.Close()
			return nil, err
		}
		it.DataTypes = []string{}
		out.ByCountry = append(out.ByCountry, it)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// 国家/地区×敏感类型聚合（一事件多类型时每类型各计一次；同时归并回 ByCountry.DataTypes）
	typeRows, err := s.db.Query(ctx, `
SELECT country, dt, count(*) FROM api_cross_border_events, jsonb_array_elements_text(data_types) AS dt
WHERE `+window+` GROUP BY country, dt ORDER BY count(*) DESC, country, dt`, days)
	if err != nil {
		return nil, fmt.Errorf("cross-border dashboard by country/type: %w", err)
	}
	typesByCountry := map[string][]string{}
	for typeRows.Next() {
		var it CountryTypeStat
		if err := typeRows.Scan(&it.Country, &it.DataType, &it.EventCount); err != nil {
			typeRows.Close()
			return nil, err
		}
		out.ByCountryType = append(out.ByCountryType, it)
		typesByCountry[it.Country] = append(typesByCountry[it.Country], it.DataType)
	}
	typeRows.Close()
	if err := typeRows.Err(); err != nil {
		return nil, err
	}
	for i := range out.ByCountry {
		if dts := typesByCountry[out.ByCountry[i].Country]; dts != nil {
			out.ByCountry[i].DataTypes = dts
		}
	}

	// 端点聚合（事件数降序，封顶 dashboardEndpointLimit 防无界）
	epRows, err := s.db.Query(ctx, `
SELECT endpoint_key, count(*), count(DISTINCT country)
FROM api_cross_border_events WHERE `+window+` GROUP BY endpoint_key
ORDER BY count(*) DESC, endpoint_key LIMIT $2`, days, dashboardEndpointLimit)
	if err != nil {
		return nil, fmt.Errorf("cross-border dashboard by endpoint: %w", err)
	}
	for epRows.Next() {
		var it EndpointStat
		if err := epRows.Scan(&it.EndpointKey, &it.EventCount, &it.CountryCount); err != nil {
			epRows.Close()
			return nil, err
		}
		out.ByEndpoint = append(out.ByEndpoint, it)
	}
	epRows.Close()
	if err := epRows.Err(); err != nil {
		return nil, err
	}

	// 日期锚（库会话时区，与 occurred_at::date 分组口径一致）
	var anchor time.Time
	if err := s.db.QueryRow(ctx, `SELECT CURRENT_DATE`).Scan(&anchor); err != nil {
		return nil, fmt.Errorf("cross-border dashboard date anchor: %w", err)
	}

	// 趋势（零值日 Go 侧补齐，升序）
	trendRows, err := s.db.Query(ctx, `
SELECT occurred_at::date, count(*) FROM api_cross_border_events
WHERE `+window+` GROUP BY 1`, days)
	if err != nil {
		return nil, fmt.Errorf("cross-border dashboard trend: %w", err)
	}
	byDay := map[string]int64{}
	for trendRows.Next() {
		var d time.Time
		var n int64
		if err := trendRows.Scan(&d, &n); err != nil {
			trendRows.Close()
			return nil, err
		}
		byDay[d.Format("2006-01-02")] = n
	}
	trendRows.Close()
	if err := trendRows.Err(); err != nil {
		return nil, err
	}
	for i := days - 1; i >= 0; i-- {
		day := anchor.AddDate(0, 0, -i).Format("2006-01-02")
		out.Trend = append(out.Trend, TrendPoint{Date: day, EventCount: byDay[day]})
	}
	return out, nil
}

// ---------- SweepOnce 生产写入侧 ----------

// Watermark 当前扫描水位（单行状态表；空行由迁移种子保证，防御性兼容 NULL）。
func (s *Store) Watermark(ctx context.Context) (*time.Time, error) {
	var wm *time.Time
	if err := s.db.QueryRow(ctx,
		`SELECT watermark FROM api_cross_border_state WHERE id = TRUE`).Scan(&wm); err != nil {
		return nil, fmt.Errorf("cross-border sweep watermark: %w", err)
	}
	return wm, nil
}

// FetchSensitiveEvents 水位之后含敏感明细且带 client_ip 的运行时事件（升序限量）。
func (s *Store) FetchSensitiveEvents(ctx context.Context, after *time.Time, limit int) ([]runtimeEventRow, error) {
	rows, err := s.db.Query(ctx, `
SELECT id, endpoint_key, client_ip, identity_fingerprint, details_json, occurred_at,
       COALESCE(final_action, ''), COALESCE(response_status, 0), COALESCE(api_level, '')
FROM api_runtime_events
WHERE client_ip IS NOT NULL AND client_ip <> ''
  AND details_json @> '[{"detector":"sensitive_data"}]'::jsonb
  AND ($1::timestamptz IS NULL OR occurred_at > $1)
ORDER BY occurred_at ASC, id ASC
LIMIT $2`, after, limit)
	if err != nil {
		return nil, fmt.Errorf("cross-border sweep query: %w", err)
	}
	defer rows.Close()
	out := []runtimeEventRow{}
	for rows.Next() {
		var ev runtimeEventRow
		if err := rows.Scan(&ev.id, &ev.endpointKey, &ev.clientIP, &ev.identity, &ev.details, &ev.occurredAt,
			&ev.finalAction, &ev.responseStatus, &ev.apiLevel); err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

// DataTypeLevels 数据类型→敏感等级映射（api_sensitive_data_types 全量，小表）。
func (s *Store) DataTypeLevels(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.Query(ctx, `SELECT data_type, level FROM api_sensitive_data_types`)
	if err != nil {
		return nil, fmt.Errorf("cross-border sweep data type levels: %w", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var dt, level string
		if err := rows.Scan(&dt, &level); err != nil {
			return nil, err
		}
		out[dt] = level
	}
	return out, rows.Err()
}

// RecordCrossBorder 单事务：逐行 INSERT ... ON CONFLICT (source_event_id, direction)
// DO NOTHING（幂等），随后推进水位。返回实际插入行数。
func (s *Store) RecordCrossBorder(ctx context.Context, rows []crossBorderRow, watermark time.Time) (int, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	inserted := 0
	for _, r := range rows {
		dataTypes, err := json.Marshal(r.dataTypes)
		if err != nil {
			return 0, err
		}
		ct, err := tx.Exec(ctx, `
INSERT INTO api_cross_border_events
    (occurred_at, client_ip, country, asn, endpoint_key, identity_fingerprint,
     data_types, direction, risk_level, source_event_id)
VALUES ($1, $2, $3, NULL, $4, $5, $6::jsonb, $7, $8, $9)
ON CONFLICT (source_event_id, direction) DO NOTHING`,
			r.occurredAt, r.clientIP, r.country, r.endpointKey, r.identity,
			string(dataTypes), r.direction, r.riskLevel, r.sourceEventID)
		if err != nil {
			return 0, fmt.Errorf("cross-border sweep insert: %w", err)
		}
		inserted += int(ct.RowsAffected())
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO api_cross_border_state (id, watermark, updated_at) VALUES (TRUE, $1, now())
ON CONFLICT (id) DO UPDATE SET watermark = EXCLUDED.watermark, updated_at = now()`,
		watermark); err != nil {
		return 0, fmt.Errorf("cross-border sweep watermark update: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return inserted, nil
}
