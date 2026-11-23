// Package vulnrefs 提供 CNNVD 漏洞条目本地档案（vuln_refs，迁移 000167）管理
// 与「编号 ↔ 规则 ↔ 事件」交叉查询（docs/CNNVD_COMPATIBILITY_DESIGN.md §3.3）。
// 档案为手工维护小表：编号可展开为规范名称与官方链接；交叉口径——
// rule_count=携带该档案编号（cnnvd_id，及 cve_id 对照）的规则数（custom_rules +
// waf_rules 目录行去重），event_count_30d=近 30 天命中这些规则的去重安全事件数。
package vulnrefs

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/wafrules"
)

// 错误
var (
	ErrNotFound = errors.New("vuln ref not found")
	ErrConflict = errors.New("vuln ref cnnvd_id conflict")
)

// Ref 是一条漏洞档案。PublishedAt 为 DATE 列，API 形态为 YYYY-MM-DD 字符串（null=未知）。
type Ref struct {
	ID          uuid.UUID `json:"id"`
	CNNVDID     string    `json:"cnnvd_id"`
	CVEID       string    `json:"cve_id"`
	Title       string    `json:"title"`
	Severity    string    `json:"severity"`
	PublishedAt *string   `json:"published_at"`
	URL         string    `json:"url"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ListItem 是档案列表项（含交叉计数）。
type ListItem struct {
	Ref
	RuleCount     int64 `json:"rule_count"`
	EventCount30d int64 `json:"event_count_30d"`
}

// RuleRef 是携带某编号的规则投影（自定义规则 + CRS 目录）。
type RuleRef struct {
	RuleID      int    `json:"rule_id"`
	RuleSource  string `json:"rule_source"`
	RuleName    string `json:"rule_name"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
}

// SampleEvent 是命中事件样例（近 30 天，最多 5 条最近）。
type SampleEvent struct {
	ID         uuid.UUID `json:"id"`
	OccurredAt time.Time `json:"occurred_at"`
	AttackType string    `json:"attack_type"`
	ClientIP   string    `json:"client_ip"`
	Path       string    `json:"request_path"`
	Action     string    `json:"action"`
}

// Detail 是档案详情交叉查询结果。
type Detail struct {
	Item          ListItem      `json:"ref"`
	Rules         []RuleRef     `json:"rules"`
	EventCount30d int64         `json:"event_count_30d"`
	SampleEvents  []SampleEvent `json:"sample_events"`
}

// Store 是漏洞档案仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

// refColumns 查询列清单（与 scanRef 顺序一致）。
const refColumns = `id, cnnvd_id, cve_id, title, severity, published_at, url, created_at, updated_at`

func scanRef(row pgx.Row) (*Ref, error) {
	var r Ref
	var published *time.Time
	err := row.Scan(&r.ID, &r.CNNVDID, &r.CVEID, &r.Title, &r.Severity, &published, &r.URL, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if published != nil {
		s := published.Format("2006-01-02")
		r.PublishedAt = &s
	}
	return &r, nil
}

// Create 录入档案（cnnvd_id 唯一冲突返回 ErrConflict）。字段已由调用方校验归一。
func (s *Store) Create(ctx context.Context, r *Ref) error {
	var published *time.Time
	if r.PublishedAt != nil && *r.PublishedAt != "" {
		t, err := time.Parse("2006-01-02", *r.PublishedAt)
		if err != nil {
			return fmt.Errorf("published_at 必须是 YYYY-MM-DD 日期")
		}
		published = &t
	}
	err := s.db.QueryRow(ctx, `
INSERT INTO vuln_refs (cnnvd_id, cve_id, title, severity, published_at, url)
VALUES ($1,$2,$3,$4,$5,$6)
RETURNING id, created_at, updated_at`,
		r.CNNVDID, r.CVEID, r.Title, r.Severity, published, r.URL).
		Scan(&r.ID, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrConflict
		}
		return err
	}
	return nil
}

// GetByCNNVD 按编号查询档案（调用方已大写归一）。
func (s *Store) GetByCNNVD(ctx context.Context, cnnvdID string) (*Ref, error) {
	return scanRef(s.db.QueryRow(ctx, `SELECT `+refColumns+` FROM vuln_refs WHERE cnnvd_id = $1`, cnnvdID))
}

// Update 更新档案（cnnvd_id 为主键语义不可改；字段已校验归一）。
func (s *Store) Update(ctx context.Context, r *Ref) error {
	var published *time.Time
	if r.PublishedAt != nil && *r.PublishedAt != "" {
		t, err := time.Parse("2006-01-02", *r.PublishedAt)
		if err != nil {
			return fmt.Errorf("published_at 必须是 YYYY-MM-DD 日期")
		}
		published = &t
	}
	res, err := s.db.Exec(ctx, `
UPDATE vuln_refs SET cve_id=$1, title=$2, severity=$3, published_at=$4, url=$5, updated_at=now()
WHERE cnnvd_id=$6`,
		r.CVEID, r.Title, r.Severity, published, r.URL, r.CNNVDID)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Delete 删除档案。
func (s *Store) Delete(ctx context.Context, cnnvdID string) error {
	res, err := s.db.Exec(ctx, `DELETE FROM vuln_refs WHERE cnnvd_id = $1`, cnnvdID)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// List 分页查询档案（keyword 模糊匹配 cnnvd_id/cve_id/title），并附每页条目的交叉计数。
func (s *Store) List(ctx context.Context, keyword string, page, pageSize int) ([]ListItem, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}
	where := "1=1"
	args := []interface{}{}
	if keyword != "" {
		where += " AND (cnnvd_id ILIKE $1 OR cve_id ILIKE $1 OR title ILIKE $1)"
		args = append(args, "%"+keyword+"%")
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM vuln_refs WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	query := `SELECT ` + refColumns + ` FROM vuln_refs WHERE ` + where +
		fmt.Sprintf(" ORDER BY cnnvd_id LIMIT $%d OFFSET $%d", len(args)+1, len(args)+2)
	rows, err := s.db.Query(ctx, query, append(args, pageSize, (page-1)*pageSize)...)
	if err != nil {
		return nil, 0, err
	}
	var refs []Ref
	for rows.Next() {
		r, err := scanRef(rows)
		if err != nil {
			rows.Close()
			return nil, 0, err
		}
		refs = append(refs, *r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	out := make([]ListItem, 0, len(refs))
	for _, r := range refs {
		out = append(out, ListItem{Ref: r})
	}
	if err := s.attachCrossCounts(ctx, out); err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

// attachCrossCounts 批量计算本页档案的 rule_count / event_count_30d（单次往返）。
// 规则命中口径：custom_rules/waf_rules 的 cnnvd_ids 含档案 cnnvd_id，
// 或档案 cve_id 非空且规则 cve_ids 含之；事件口径：近 30 天 matches 命中这些
// rule_id 的去重 event_id 数（rule_id 段全局不重叠，见 customrules 规则 ID 规划）。
func (s *Store) attachCrossCounts(ctx context.Context, items []ListItem) error {
	if len(items) == 0 {
		return nil
	}
	cnnvdIDs := make([]string, 0, len(items))
	cveIDs := make([]string, 0, len(items))
	for _, it := range items {
		cnnvdIDs = append(cnnvdIDs, it.CNNVDID)
		cveIDs = append(cveIDs, it.CVEID)
	}
	rows, err := s.db.Query(ctx, `
WITH ids AS (
  SELECT * FROM unnest($1::text[], $2::text[]) AS t(cnnvd_id, cve_id)
),
rule_hits AS (
  SELECT ids.cnnvd_id, cr.rule_id
  FROM ids
  JOIN custom_rules cr ON cr.cnnvd_ids @> to_jsonb(ids.cnnvd_id)
     OR (ids.cve_id <> '' AND cr.cve_ids @> to_jsonb(ids.cve_id))
  UNION ALL
  SELECT ids.cnnvd_id, wr.rule_id
  FROM ids
  JOIN waf_rules wr ON wr.cnnvd_ids @> to_jsonb(ids.cnnvd_id)
     OR (ids.cve_id <> '' AND wr.cve_ids @> to_jsonb(ids.cve_id))
)
SELECT rh.cnnvd_id,
       count(DISTINCT rh.rule_id) AS rule_count,
       count(DISTINCT m.event_id) AS event_count_30d
FROM rule_hits rh
LEFT JOIN security_event_matches m
  ON m.rule_id = rh.rule_id AND m.event_occurred_at >= now() - interval '30 days'
GROUP BY rh.cnnvd_id`, cnnvdIDs, cveIDs)
	if err != nil {
		return err
	}
	defer rows.Close()
	counts := map[string][2]int64{}
	for rows.Next() {
		var id string
		var rc, ec int64
		if err := rows.Scan(&id, &rc, &ec); err != nil {
			return err
		}
		counts[id] = [2]int64{rc, ec}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for i := range items {
		if c, ok := counts[items[i].CNNVDID]; ok {
			items[i].RuleCount = c[0]
			items[i].EventCount30d = c[1]
		}
	}
	return nil
}

// Detail 档案详情：条目 + 关联规则列表 + 近 30 天事件计数与样例（≤5 条最近）。
func (s *Store) Detail(ctx context.Context, cnnvdID string) (*Detail, error) {
	ref, err := s.GetByCNNVD(ctx, cnnvdID)
	if err != nil {
		return nil, err
	}
	d := &Detail{
		Item:         ListItem{Ref: *ref},
		Rules:        []RuleRef{},
		SampleEvents: []SampleEvent{},
	}

	// 关联规则：自定义规则 + CRS 目录（目录按 (rule_id, rule_source) 取最新 crs_version 行去重）
	ruleRows, err := s.db.Query(ctx, `
SELECT rule_id, rule_source, rule_name, description, enabled FROM (
  SELECT cr.rule_id, 'USER_CUSTOM'::text AS rule_source, cr.name AS rule_name,
         cr.description AS description, (cr.status = 'ENABLED') AS enabled, 0 AS ord
  FROM custom_rules cr
  WHERE cr.cnnvd_ids @> to_jsonb($1::text) OR ($2 <> '' AND cr.cve_ids @> to_jsonb($2::text))
  UNION ALL
  SELECT rule_id, rule_source, rule_name, description, enabled, 1 FROM (
    SELECT DISTINCT ON (wr.rule_id, wr.rule_source)
           wr.rule_id, wr.rule_source, wr.name AS rule_name, wr.message AS description,
           (wr.default_state = 'ENABLED') AS enabled
    FROM waf_rules wr
    WHERE wr.cnnvd_ids @> to_jsonb($1::text) OR ($2 <> '' AND wr.cve_ids @> to_jsonb($2::text))
    ORDER BY wr.rule_id, wr.rule_source, wr.crs_version DESC
  ) w
) t
ORDER BY ord, rule_source, rule_id`, ref.CNNVDID, ref.CVEID)
	if err != nil {
		return nil, err
	}
	ruleIDs := make([]int, 0)
	for ruleRows.Next() {
		var rr RuleRef
		if err := ruleRows.Scan(&rr.RuleID, &rr.RuleSource, &rr.RuleName, &rr.Description, &rr.Enabled); err != nil {
			ruleRows.Close()
			return nil, err
		}
		if rr.RuleSource != "USER_CUSTOM" {
			rr.RuleName = wafrules.LocalizeRule(rr.RuleID, "", rr.RuleName)
			rr.Description = wafrules.LocalizeMatchMessage(rr.RuleID, rr.Description)
		}
		d.Rules = append(d.Rules, rr)
		ruleIDs = append(ruleIDs, rr.RuleID)
	}
	ruleRows.Close()
	if err := ruleRows.Err(); err != nil {
		return nil, err
	}
	d.Item.RuleCount = int64(len(d.Rules))

	if len(ruleIDs) > 0 {
		if err := s.db.QueryRow(ctx, `
SELECT count(DISTINCT event_id) FROM security_event_matches
WHERE rule_id = ANY($1::int[]) AND event_occurred_at >= now() - interval '30 days'`,
			ruleIDs).Scan(&d.EventCount30d); err != nil {
			return nil, err
		}
		d.Item.EventCount30d = d.EventCount30d

		evRows, err := s.db.Query(ctx, `
SELECT e.id, e.occurred_at, e.attack_type, COALESCE(host(e.client_ip), ''), e.request_path, e.action
FROM security_events e
WHERE e.id IN (
  SELECT DISTINCT event_id FROM security_event_matches
  WHERE rule_id = ANY($1::int[]) AND event_occurred_at >= now() - interval '30 days'
)
ORDER BY e.occurred_at DESC
LIMIT 5`, ruleIDs)
		if err != nil {
			return nil, err
		}
		for evRows.Next() {
			var se SampleEvent
			if err := evRows.Scan(&se.ID, &se.OccurredAt, &se.AttackType, &se.ClientIP, &se.Path, &se.Action); err != nil {
				evRows.Close()
				return nil, err
			}
			d.SampleEvents = append(d.SampleEvents, se)
		}
		evRows.Close()
		if err := evRows.Err(); err != nil {
			return nil, err
		}
	}
	return d, nil
}

// isUniqueViolation 判定唯一约束冲突（pgcode 23505）。
func isUniqueViolation(err error) bool {
	var iface interface{ SQLState() string }
	if errors.As(err, &iface) {
		return iface.SQLState() == "23505"
	}
	return false
}
