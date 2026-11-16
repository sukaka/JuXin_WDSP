package vulnintel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store 是漏洞情报仓储（全部 SQL 参数化）。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

// advisoryColumns 查询列清单（与 scanAdvisory 顺序一致；raw_json 不出接口，详情亦不返回）。
const advisoryColumns = `id, cve_id, title, summary, severity, cvss_score, published_at, last_modified_at,
tech_tags, references_json, source, created_at, updated_at`

func scanAdvisory(row pgx.Row) (*Advisory, error) {
	var a Advisory
	var techTags, refs []byte
	err := row.Scan(&a.ID, &a.CVEID, &a.Title, &a.Summary, &a.Severity, &a.CVSSScore,
		&a.PublishedAt, &a.LastModifiedAt, &techTags, &refs, &a.Source, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if err := json.Unmarshal(techTags, &a.TechTags); err != nil {
		return nil, fmt.Errorf("decode tech_tags: %w", err)
	}
	if err := json.Unmarshal(refs, &a.References); err != nil {
		return nil, fmt.Errorf("decode references_json: %w", err)
	}
	if a.TechTags == nil {
		a.TechTags = []string{}
	}
	if a.References == nil {
		a.References = []string{}
	}
	return &a, nil
}

// UpsertAdvisory 按 cve_id 幂等写入（冲突更新全文与 updated_at）。
// 返回 isNew=true 表示本次为新建（提醒引擎只对新建触发提醒，更新不重复提醒）。
// raw 为源数据截断副本（追溯证据，可为 nil）。
func (s *Store) UpsertAdvisory(ctx context.Context, a *Advisory, raw json.RawMessage) (bool, error) {
	techJSON, err := json.Marshal(a.TechTags)
	if err != nil {
		return false, err
	}
	refJSON, err := json.Marshal(a.References)
	if err != nil {
		return false, err
	}
	var isNew bool
	err = s.db.QueryRow(ctx, `
INSERT INTO vuln_advisories
(cve_id, title, summary, severity, cvss_score, published_at, last_modified_at,
 tech_tags, references_json, source, raw_json)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9::jsonb,$10,$11::jsonb)
ON CONFLICT (cve_id) DO UPDATE SET
  title = EXCLUDED.title, summary = EXCLUDED.summary, severity = EXCLUDED.severity,
  cvss_score = EXCLUDED.cvss_score, published_at = EXCLUDED.published_at,
  last_modified_at = EXCLUDED.last_modified_at, tech_tags = EXCLUDED.tech_tags,
  references_json = EXCLUDED.references_json, source = EXCLUDED.source,
  raw_json = EXCLUDED.raw_json, updated_at = now()
RETURNING id, created_at, updated_at, (xmax = 0)`,
		a.CVEID, a.Title, a.Summary, a.Severity, a.CVSSScore, a.PublishedAt, a.LastModifiedAt,
		string(techJSON), string(refJSON), a.Source, nullableRaw(raw)).
		Scan(&a.ID, &a.CreatedAt, &a.UpdatedAt, &isNew)
	if err != nil {
		return false, err
	}
	return isNew, nil
}

// nullableRaw 空 raw 落 NULL（不存空 JSON 噪声）。
func nullableRaw(raw json.RawMessage) interface{} {
	if len(raw) == 0 {
		return nil
	}
	return string(raw)
}

// ListFilter 是情报列表查询筛选。
type ListFilter struct {
	Keyword        string // cve_id/title/summary 模糊匹配（ILIKE，通配符转义）
	Severity       string
	Tech           string // tech_tags 包含该技术
	Source         string
	PublishedStart *time.Time
	PublishedEnd   *time.Time
	Page           int
	PageSize       int
}

// ListAdvisories 分页过滤查询（按发布日期倒序，NULLS LAST）。
func (s *Store) ListAdvisories(ctx context.Context, f ListFilter) ([]Advisory, int64, error) {
	if f.Page <= 0 {
		f.Page = 1
	}
	if f.PageSize <= 0 || f.PageSize > 200 {
		f.PageSize = 20
	}
	where := "1=1"
	args := []interface{}{}
	argIdx := 1
	add := func(cond string, v interface{}) {
		where += fmt.Sprintf(" AND "+cond, argIdx)
		args = append(args, v)
		argIdx++
	}
	if f.Keyword != "" {
		add("(cve_id ILIKE $%[1]d ESCAPE '\\' OR title ILIKE $%[1]d ESCAPE '\\' OR summary ILIKE $%[1]d ESCAPE '\\')",
			"%"+ilikeEscape(f.Keyword)+"%")
	}
	if f.Severity != "" {
		add("severity = $%d", f.Severity)
	}
	if f.Tech != "" {
		techJSON, _ := json.Marshal([]string{f.Tech})
		add("tech_tags @> $%d::jsonb", string(techJSON))
	}
	if f.Source != "" {
		add("source = $%d", f.Source)
	}
	if f.PublishedStart != nil {
		add("published_at >= $%d", *f.PublishedStart)
	}
	if f.PublishedEnd != nil {
		add("published_at <= $%d", *f.PublishedEnd)
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM vuln_advisories WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	query := `SELECT ` + advisoryColumns + ` FROM vuln_advisories WHERE ` + where +
		fmt.Sprintf(" ORDER BY published_at DESC NULLS LAST, cve_id LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Advisory{}
	for rows.Next() {
		a, err := scanAdvisory(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *a)
	}
	return out, total, rows.Err()
}

// GetByCVE 按 cve_id 查询详情。
func (s *Store) GetByCVE(ctx context.Context, cveID string) (*Advisory, error) {
	row := s.db.QueryRow(ctx, `SELECT `+advisoryColumns+` FROM vuln_advisories WHERE cve_id = $1`, cveID)
	return scanAdvisory(row)
}

// Overview 是情报概览统计。
type Overview struct {
	Total         int64 `json:"total"`
	NewLast7d     int64 `json:"new_last_7d"`
	CriticalCount int64 `json:"critical_count"`
	HighCount     int64 `json:"high_count"`
}

// GetOverview 统计总数 / 近 7 日新增（按 created_at 入库时间）/ CRITICAL / HIGH。
func (s *Store) GetOverview(ctx context.Context) (*Overview, error) {
	var o Overview
	err := s.db.QueryRow(ctx, `
SELECT count(*),
  count(*) FILTER (WHERE created_at >= now() - interval '7 days'),
  count(*) FILTER (WHERE severity = 'CRITICAL'),
  count(*) FILTER (WHERE severity = 'HIGH')
FROM vuln_advisories`).Scan(&o.Total, &o.NewLast7d, &o.CriticalCount, &o.HighCount)
	if err != nil {
		return nil, err
	}
	return &o, nil
}

// ---------- 应用技术栈映射 ----------

// ListTechAssets 列出全部未删除应用及其技术标签（按应用编码排序，无标签应用返回空数组）。
func (s *Store) ListTechAssets(ctx context.Context) ([]TechAsset, error) {
	rows, err := s.db.Query(ctx, `
SELECT a.id, a.code, a.name,
  COALESCE((SELECT json_agg(t.tech_name ORDER BY t.tech_name)
            FROM application_technologies t WHERE t.application_id = a.id), '[]'::json)
FROM applications a
WHERE a.deleted_at IS NULL
ORDER BY a.code`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TechAsset{}
	for rows.Next() {
		var ta TechAsset
		var tags []byte
		if err := rows.Scan(&ta.ApplicationID, &ta.Code, &ta.Name, &tags); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(tags, &ta.TechTags); err != nil {
			return nil, fmt.Errorf("decode tech tags: %w", err)
		}
		if ta.TechTags == nil {
			ta.TechTags = []string{}
		}
		out = append(out, ta)
	}
	return out, rows.Err()
}

// TechAssetInput 是单应用技术标签目标态（整组替换输入）。
type TechAssetInput struct {
	ApplicationID uuid.UUID
	TechTags      []string
}

// ReplaceAllTechAssets 整组替换应用技术栈映射（单事务：body 为全量目标态，
// 未列出的应用清空标签）。应用不存在（或已删除）返回 ErrInvalidInput 包裹错误，
// HTTP 层映射 400。
func (s *Store) ReplaceAllTechAssets(ctx context.Context, items []TechAssetInput) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, it := range items {
		var exists bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM applications WHERE id = $1 AND deleted_at IS NULL)`,
			it.ApplicationID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("%w: application %s 不存在或已删除", ErrInvalidInput, it.ApplicationID)
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM application_technologies`); err != nil {
		return err
	}
	for _, it := range items {
		for _, tech := range it.TechTags {
			if _, err := tx.Exec(ctx, `
INSERT INTO application_technologies (application_id, tech_name, source)
VALUES ($1, $2, 'MANUAL')
ON CONFLICT (application_id, tech_name) DO NOTHING`, it.ApplicationID, tech); err != nil {
				return err
			}
		}
	}
	return tx.Commit(ctx)
}

// AffectedApps 查询标记了某技术标签的未删除应用（提醒文案「受影响应用」段）。
func (s *Store) AffectedApps(ctx context.Context, tech string) ([]AppRef, error) {
	rows, err := s.db.Query(ctx, `
SELECT a.id, a.code, a.name
FROM application_technologies t
JOIN applications a ON a.id = t.application_id AND a.deleted_at IS NULL
WHERE t.tech_name = $1
ORDER BY a.code`, tech)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AppRef{}
	for rows.Next() {
		var r AppRef
		if err := rows.Scan(&r.ID, &r.Code, &r.Name); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ---------- 同步状态 ----------

// GetSyncState 读取同步状态；无记录返回 IDLE 零值状态（非错误）。
func (s *Store) GetSyncState(ctx context.Context, source string) (*SyncState, error) {
	var st SyncState
	err := s.db.QueryRow(ctx, `
SELECT source, last_sync_at, last_window_start, last_window_end, records_upserted, status, failure_message, updated_at
FROM vuln_intel_sync_state WHERE source = $1`, source).Scan(
		&st.Source, &st.LastSyncAt, &st.LastWindowStart, &st.LastWindowEnd,
		&st.RecordsUpserted, &st.Status, &st.FailureMessage, &st.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return &SyncState{Source: source, Status: SyncStatusIdle}, nil
		}
		return nil, err
	}
	return &st, nil
}

// SaveSyncState 覆盖写入同步状态（upsert）。
func (s *Store) SaveSyncState(ctx context.Context, st *SyncState) error {
	_, err := s.db.Exec(ctx, `
INSERT INTO vuln_intel_sync_state
(source, last_sync_at, last_window_start, last_window_end, records_upserted, status, failure_message, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,now())
ON CONFLICT (source) DO UPDATE SET
  last_sync_at = EXCLUDED.last_sync_at, last_window_start = EXCLUDED.last_window_start,
  last_window_end = EXCLUDED.last_window_end, records_upserted = EXCLUDED.records_upserted,
  status = EXCLUDED.status, failure_message = EXCLUDED.failure_message, updated_at = now()`,
		st.Source, st.LastSyncAt, st.LastWindowStart, st.LastWindowEnd,
		st.RecordsUpserted, st.Status, st.FailureMessage)
	return err
}

// ---------- 提醒去重 ----------

// FilterAlerted 返回候选 advisory 中已对 tech 提醒过的 ID 集合。
func (s *Store) FilterAlerted(ctx context.Context, advisoryIDs []uuid.UUID, tech string) (map[uuid.UUID]bool, error) {
	out := map[uuid.UUID]bool{}
	if len(advisoryIDs) == 0 {
		return out, nil
	}
	rows, err := s.db.Query(ctx, `
SELECT advisory_id FROM vuln_alerted WHERE tech_name = $1 AND advisory_id = ANY($2)`, tech, advisoryIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

// RecordAlerted 记录一批 advisory 已对 tech 提醒（ON CONFLICT 幂等，
// 并发同步/导入下重复提醒由唯一键兜底拦截）。
func (s *Store) RecordAlerted(ctx context.Context, advisoryIDs []uuid.UUID, tech string, alertID *uuid.UUID) error {
	for _, id := range advisoryIDs {
		if _, err := s.db.Exec(ctx, `
INSERT INTO vuln_alerted (advisory_id, tech_name, alert_id)
VALUES ($1, $2, $3)
ON CONFLICT (advisory_id, tech_name) DO NOTHING`, id, tech, alertID); err != nil {
			return err
		}
	}
	return nil
}

// ilikeEscape 转义 ILIKE 模式中的 % _ \。
func ilikeEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}
