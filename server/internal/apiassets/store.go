// Package apiassets API 端点资产管理（发现、列表、确认）。
package apiassets

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrNotFound = errors.New("api endpoint not found")
)

// Endpoint API 端点。
type Endpoint struct {
	ID           uuid.UUID  `json:"id"`
	ApplicationID *uuid.UUID `json:"application_id,omitempty"`
	Method       string     `json:"method"`
	PathTemplate string     `json:"path_template"`
	EndpointKey  string     `json:"endpoint_key"`
	Confidence   float64    `json:"confidence"`
	Status       string     `json:"status"`
	IsAPI        bool       `json:"is_api"`
	HitCount     int64      `json:"hit_count"`
	FirstSeenAt  time.Time  `json:"first_seen_at"`
	LastSeenAt   time.Time  `json:"last_seen_at"`
	ConfirmedAt  *time.Time `json:"confirmed_at,omitempty"`
}

// Store 仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建。
func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

// UpsertDiscovery 发现/命中端点（按 endpoint_key 幂等）。
func (s *Store) UpsertDiscovery(ctx context.Context, method, pathTemplate string, confidence float64, isAPI bool) (*Endpoint, error) {
	method = strings.ToUpper(strings.TrimSpace(method))
	pathTemplate = strings.TrimSpace(pathTemplate)
	if method == "" || pathTemplate == "" {
		return nil, fmt.Errorf("method and path_template required")
	}
	key := method + " " + pathTemplate
	var e Endpoint
	err := s.db.QueryRow(ctx, `
INSERT INTO api_endpoints (method, path_template, endpoint_key, confidence, is_api, hit_count, status)
VALUES ($1,$2,$3,$4,$5,1,'DISCOVERED')
ON CONFLICT (endpoint_key) DO UPDATE SET
  hit_count = api_endpoints.hit_count + 1,
  last_seen_at = now(),
  confidence = GREATEST(api_endpoints.confidence, EXCLUDED.confidence),
  updated_at = now()
RETURNING id, application_id, method, path_template, endpoint_key, confidence, status, is_api,
  hit_count, first_seen_at, last_seen_at, confirmed_at`,
		method, pathTemplate, key, confidence, isAPI,
	).Scan(&e.ID, &e.ApplicationID, &e.Method, &e.PathTemplate, &e.EndpointKey, &e.Confidence,
		&e.Status, &e.IsAPI, &e.HitCount, &e.FirstSeenAt, &e.LastSeenAt, &e.ConfirmedAt)
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// List 分页列表。
func (s *Store) List(ctx context.Context, status string, page, pageSize int) ([]Endpoint, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}
	where := "1=1"
	args := []any{}
	if status != "" {
		where += " AND status = $1"
		args = append(args, status)
	}
	var total int64
	qCount := `SELECT count(*) FROM api_endpoints WHERE ` + where
	if err := s.db.QueryRow(ctx, qCount, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	argN := len(args) + 1
	q := fmt.Sprintf(`
SELECT id, application_id, method, path_template, endpoint_key, confidence, status, is_api,
  hit_count, first_seen_at, last_seen_at, confirmed_at
FROM api_endpoints WHERE %s ORDER BY last_seen_at DESC LIMIT $%d OFFSET $%d`, where, argN, argN+1)
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.db.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Endpoint
	for rows.Next() {
		var e Endpoint
		if err := rows.Scan(&e.ID, &e.ApplicationID, &e.Method, &e.PathTemplate, &e.EndpointKey,
			&e.Confidence, &e.Status, &e.IsAPI, &e.HitCount, &e.FirstSeenAt, &e.LastSeenAt, &e.ConfirmedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	if out == nil {
		out = []Endpoint{}
	}
	return out, total, rows.Err()
}

// Confirm 人工确认端点。
func (s *Store) Confirm(ctx context.Context, id uuid.UUID) (*Endpoint, error) {
	var e Endpoint
	err := s.db.QueryRow(ctx, `
UPDATE api_endpoints SET status='CONFIRMED', confirmed_at=now(), updated_at=now()
WHERE id=$1
RETURNING id, application_id, method, path_template, endpoint_key, confidence, status, is_api,
  hit_count, first_seen_at, last_seen_at, confirmed_at`, id).Scan(
		&e.ID, &e.ApplicationID, &e.Method, &e.PathTemplate, &e.EndpointKey,
		&e.Confidence, &e.Status, &e.IsAPI, &e.HitCount, &e.FirstSeenAt, &e.LastSeenAt, &e.ConfirmedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &e, err
}

// GetByID 查询。
func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (*Endpoint, error) {
	var e Endpoint
	err := s.db.QueryRow(ctx, `
SELECT id, application_id, method, path_template, endpoint_key, confidence, status, is_api,
  hit_count, first_seen_at, last_seen_at, confirmed_at
FROM api_endpoints WHERE id=$1`, id).Scan(
		&e.ID, &e.ApplicationID, &e.Method, &e.PathTemplate, &e.EndpointKey,
		&e.Confidence, &e.Status, &e.IsAPI, &e.HitCount, &e.FirstSeenAt, &e.LastSeenAt, &e.ConfirmedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &e, err
}
