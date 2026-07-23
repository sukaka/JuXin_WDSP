// Package apimodels API Schema 学习版本（候选/正式冻结）。
package apimodels

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrNotFound        = errors.New("model version not found")
	ErrNotCandidate    = errors.New("only candidate can be confirmed")
	ErrFormalImmutable = errors.New("formal model immutable")
)

// Version 模型版本。
type Version struct {
	ID          uuid.UUID         `json:"id"`
	EndpointID  uuid.UUID         `json:"endpoint_id"`
	EndpointKey string            `json:"endpoint_key"`
	Status      string            `json:"status"`
	Schema      map[string]string `json:"schema"`
	ContentHash string            `json:"content_hash"`
	CreatedAt   time.Time         `json:"created_at"`
	FrozenAt    *time.Time        `json:"frozen_at,omitempty"`
}

// Store 仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建。
func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

// CreateCandidate 创建候选版本。
func (s *Store) CreateCandidate(ctx context.Context, endpointID uuid.UUID, endpointKey string, schema map[string]string) (*Version, error) {
	if schema == nil {
		schema = map[string]string{}
	}
	h := hashSchema(endpointKey, schema)
	raw, _ := json.Marshal(schema)
	var v Version
	var schemaRaw []byte
	err := s.db.QueryRow(ctx, `
INSERT INTO api_model_versions (endpoint_id, endpoint_key, status, schema_json, content_hash)
VALUES ($1,$2,'CANDIDATE',$3,$4)
RETURNING id, endpoint_id, endpoint_key, status, schema_json, content_hash, created_at, frozen_at`,
		endpointID, endpointKey, raw, h,
	).Scan(&v.ID, &v.EndpointID, &v.EndpointKey, &v.Status, &schemaRaw, &v.ContentHash, &v.CreatedAt, &v.FrozenAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(schemaRaw, &v.Schema)
	if v.Schema == nil {
		v.Schema = map[string]string{}
	}
	return &v, nil
}

// Confirm 冻结为正式模型。
func (s *Store) Confirm(ctx context.Context, id uuid.UUID) (*Version, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var v Version
	var schemaRaw []byte
	err = tx.QueryRow(ctx, `
SELECT id, endpoint_id, endpoint_key, status, schema_json, content_hash, created_at, frozen_at
FROM api_model_versions WHERE id=$1 FOR UPDATE`, id).Scan(
		&v.ID, &v.EndpointID, &v.EndpointKey, &v.Status, &schemaRaw, &v.ContentHash, &v.CreatedAt, &v.FrozenAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if v.Status != "CANDIDATE" {
		return nil, ErrNotCandidate
	}
	// supersede old formal
	_, _ = tx.Exec(ctx, `
UPDATE api_model_versions SET status='SUPERSEDED' WHERE endpoint_id=$1 AND status='FORMAL'`, v.EndpointID)
	err = tx.QueryRow(ctx, `
UPDATE api_model_versions SET status='FORMAL', frozen_at=now() WHERE id=$1
RETURNING id, endpoint_id, endpoint_key, status, schema_json, content_hash, created_at, frozen_at`, id).Scan(
		&v.ID, &v.EndpointID, &v.EndpointKey, &v.Status, &schemaRaw, &v.ContentHash, &v.CreatedAt, &v.FrozenAt)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	_ = json.Unmarshal(schemaRaw, &v.Schema)
	return &v, nil
}

// FormalSchema 端点正式模型。
func (s *Store) FormalSchema(ctx context.Context, endpointKey string) (map[string]string, error) {
	var raw []byte
	err := s.db.QueryRow(ctx, `
SELECT schema_json FROM api_model_versions
WHERE endpoint_key=$1 AND status='FORMAL' ORDER BY frozen_at DESC NULLS LAST LIMIT 1`, endpointKey).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var m map[string]string
	_ = json.Unmarshal(raw, &m)
	return m, nil
}

// List 按端点列出版本。
func (s *Store) List(ctx context.Context, endpointKey string, page, pageSize int) ([]Version, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM api_model_versions WHERE endpoint_key=$1 OR $1=''`, endpointKey).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(ctx, `
SELECT id, endpoint_id, endpoint_key, status, schema_json, content_hash, created_at, frozen_at
FROM api_model_versions
WHERE endpoint_key=$1 OR $1=''
ORDER BY created_at DESC LIMIT $2 OFFSET $3`, endpointKey, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Version
	for rows.Next() {
		var v Version
		var raw []byte
		if err := rows.Scan(&v.ID, &v.EndpointID, &v.EndpointKey, &v.Status, &raw, &v.ContentHash, &v.CreatedAt, &v.FrozenAt); err != nil {
			return nil, 0, err
		}
		_ = json.Unmarshal(raw, &v.Schema)
		out = append(out, v)
	}
	if out == nil {
		out = []Version{}
	}
	return out, total, rows.Err()
}

func hashSchema(endpoint string, schema map[string]string) string {
	keys := make([]string, 0, len(schema))
	for k := range schema {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	type kv struct{ K, V string }
	arr := make([]kv, 0, len(keys))
	for _, k := range keys {
		arr = append(arr, kv{k, schema[k]})
	}
	b, _ := json.Marshal(struct {
		E string
		S []kv
	}{endpoint, arr})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ListFormalSchemas 返回全部冻结正式模型（endpoint_key → 字段名 → 期望类型），供发布通道下发网关。
// 同一 endpoint_key 存在多个 FORMAL 版本时取最近冻结者（正常 Confirm 流程至多一个 FORMAL）。
func (s *Store) ListFormalSchemas(ctx context.Context) (map[string]map[string]string, error) {
	rows, err := s.db.Query(ctx, `
SELECT DISTINCT ON (endpoint_key) endpoint_key, schema_json
FROM api_model_versions WHERE status='FORMAL'
ORDER BY endpoint_key, frozen_at DESC NULLS LAST`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]map[string]string{}
	for rows.Next() {
		var key string
		var raw []byte
		if err := rows.Scan(&key, &raw); err != nil {
			return nil, err
		}
		var schema map[string]string
		if err := json.Unmarshal(raw, &schema); err != nil {
			return nil, err
		}
		out[key] = schema
	}
	return out, rows.Err()
}
