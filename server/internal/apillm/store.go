// store.go LLM 观测 PostgreSQL 只读仓储：列表/统计查询（Repository 接口，
// SQL 与内存实现共用，便于诚实单测）。过滤条件一律白名单拼接、值参数化。
package apillm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// Repository 观测列表/统计只读仓储（SQL 与内存实现共用）。
type Repository interface {
	// ListObservations 明细分页（窗口按 occurred_at 口径；occurred_at 倒序）
	ListObservations(ctx context.Context, f ObservationFilter) ([]Observation, int64, error)
	// Stats 统计聚合（模型分布/token 用量趋势/涉敏命中计数，窗口 days 天）
	Stats(ctx context.Context, days int) (*StatsData, error)
}

// Store LLM 观测 PostgreSQL 仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建。
func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

var _ Repository = (*Store)(nil)

// observationCols 明细查询列。
const observationCols = `id, occurred_at, endpoint_key, model, identity_fingerprint,
	prompt_len_bucket, total_tokens, stream, mcp_method, findings, created_at`

// scanObservation 扫描一行观测（findings jsonb 经 json.RawMessage 中转，空归一为 []）。
func scanObservation(row interface{ Scan(...any) error }) (*Observation, error) {
	var o Observation
	var findings json.RawMessage
	err := row.Scan(&o.ID, &o.OccurredAt, &o.EndpointKey, &o.Model, &o.IdentityFingerprint,
		&o.PromptLenBucket, &o.TotalTokens, &o.Stream, &o.MCPMethod, &findings, &o.CreatedAt)
	if err != nil {
		return nil, err
	}
	o.Findings = []dsctx.DetectorMatch{}
	if len(findings) > 0 && string(findings) != "null" {
		if err := json.Unmarshal(findings, &o.Findings); err != nil {
			return nil, err
		}
	}
	return &o, nil
}

// ListObservations 明细分页（过滤条件白名单拼接，值一律参数化；occurred_at 倒序）。
func (s *Store) ListObservations(ctx context.Context, f ObservationFilter) ([]Observation, int64, error) {
	if f.Page <= 0 {
		f.Page = 1
	}
	if f.PageSize <= 0 {
		f.PageSize = 20
	}
	where := []string{`occurred_at >= CURRENT_DATE - ($1::int - 1) * interval '1 day'`}
	args := []any{clampDays(f.Days)}
	if f.Model != "" {
		args = append(args, f.Model)
		where = append(where, fmt.Sprintf("model = $%d", len(args)))
	}
	if f.EndpointKey != "" {
		args = append(args, f.EndpointKey)
		where = append(where, fmt.Sprintf("endpoint_key = $%d", len(args)))
	}
	if f.FindingsOnly {
		where = append(where, `findings <> '[]'::jsonb`)
	}
	cond := " WHERE " + strings.Join(where, " AND ")
	var total int64
	if err := s.db.QueryRow(ctx, "SELECT count(*) FROM api_llm_observations"+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	rows, err := s.db.Query(ctx, `SELECT `+observationCols+` FROM api_llm_observations`+cond+
		fmt.Sprintf(" ORDER BY occurred_at DESC, id DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Observation{}
	for rows.Next() {
		o, err := scanObservation(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *o)
	}
	return out, total, rows.Err()
}

// Stats 统计聚合（SQL 实现；窗口与列表明细同口径）：
// 汇总 + 模型分布 TOP + 按天 token 用量趋势 + 命中规则分布（findings jsonb 展开）。
func (s *Store) Stats(ctx context.Context, days int) (*StatsData, error) {
	days = clampDays(days)
	out := &StatsData{
		Days:           days,
		ByModel:        []ModelStat{},
		TokenTrend:     []TokenTrendPoint{},
		FindingsByRule: []FindingRuleStat{},
	}
	const window = `occurred_at >= CURRENT_DATE - ($1::int - 1) * interval '1 day'`

	// 汇总：观测数/带命中观测数/token 合计/流式数/涉及模型数
	if err := s.db.QueryRow(ctx, `
SELECT count(*),
       count(*) FILTER (WHERE findings <> '[]'::jsonb),
       COALESCE(sum(total_tokens), 0),
       count(*) FILTER (WHERE stream),
       count(DISTINCT model)
FROM api_llm_observations WHERE `+window, days).
		Scan(&out.Summary.Observations, &out.Summary.WithFindings, &out.Summary.TotalTokens,
			&out.Summary.StreamCalls, &out.Summary.DistinctModels); err != nil {
		return nil, fmt.Errorf("llm stats summary: %w", err)
	}

	// 模型分布 TOP（观测数降序；空串 = 未声明模型单列一组如实呈现）
	rows, err := s.db.Query(ctx, `
SELECT model, count(*), COALESCE(sum(total_tokens), 0),
       COALESCE(sum(jsonb_array_length(findings)), 0)
FROM api_llm_observations WHERE `+window+`
GROUP BY model ORDER BY count(*) DESC, model LIMIT $2`, days, topLimit)
	if err != nil {
		return nil, fmt.Errorf("llm stats by model: %w", err)
	}
	for rows.Next() {
		var it ModelStat
		if err := rows.Scan(&it.Model, &it.Observations, &it.TotalTokens, &it.Findings); err != nil {
			rows.Close()
			return nil, err
		}
		out.ByModel = append(out.ByModel, it)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// token 用量趋势（按天；时区与 apifiles CURRENT_DATE 口径一致取库会话时区）
	trendRows, err := s.db.Query(ctx, `
SELECT to_char(occurred_at::date, 'YYYY-MM-DD'), count(*), COALESCE(sum(total_tokens), 0)
FROM api_llm_observations WHERE `+window+`
GROUP BY occurred_at::date ORDER BY occurred_at::date`, days)
	if err != nil {
		return nil, fmt.Errorf("llm stats token trend: %w", err)
	}
	for trendRows.Next() {
		var it TokenTrendPoint
		if err := trendRows.Scan(&it.Day, &it.Observations, &it.TotalTokens); err != nil {
			trendRows.Close()
			return nil, err
		}
		out.TokenTrend = append(out.TokenTrend, it)
	}
	trendRows.Close()
	if err := trendRows.Err(); err != nil {
		return nil, err
	}

	// 命中规则分布（findings jsonb 展开按 rule_id 计数；无命中行不参与）
	findingRows, err := s.db.Query(ctx, `
SELECT f->>'rule_id', count(*)
FROM api_llm_observations, jsonb_array_elements(findings) f
WHERE `+window+`
GROUP BY f->>'rule_id' ORDER BY count(*) DESC, f->>'rule_id' LIMIT $2`, days, topLimit)
	if err != nil {
		return nil, fmt.Errorf("llm stats findings by rule: %w", err)
	}
	defer findingRows.Close()
	for findingRows.Next() {
		var it FindingRuleStat
		if err := findingRows.Scan(&it.RuleID, &it.Count); err != nil {
			return nil, err
		}
		out.FindingsByRule = append(out.FindingsByRule, it)
	}
	return out, findingRows.Err()
}
