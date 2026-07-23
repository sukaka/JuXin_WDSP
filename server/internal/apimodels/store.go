// Package apimodels API 模型版本体系（任务书 51.2）：
// 生命周期状态机 CANDIDATE → IN_REVIEW → FORMAL / REJECTED，FORMAL → ARCHIVED；
// 正式模型不可变（除状态迁移外无内容更新接口）。
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

// 模型版本状态机取值。
const (
	StatusCandidate  = "CANDIDATE"
	StatusInReview   = "IN_REVIEW"
	StatusFormal     = "FORMAL"
	StatusRejected   = "REJECTED"
	StatusSuperseded = "SUPERSEDED"
	StatusArchived   = "ARCHIVED"
)

var (
	// ErrNotFound 模型版本不存在。
	ErrNotFound = errors.New("model version not found")
	// ErrNotCandidate 仅候选/评审中版本可确认为正式模型。
	ErrNotCandidate = errors.New("only candidate or in-review version can be confirmed")
	// ErrFormalImmutable 正式模型不可变：除状态迁移外不提供任何内容更新接口。
	ErrFormalImmutable = errors.New("formal model immutable")
	// ErrInvalidTransition 状态机不允许的迁移。
	ErrInvalidTransition = errors.New("invalid model status transition")
	// ErrEndpointNotFound 端点不存在。
	ErrEndpointNotFound = errors.New("api endpoint not found")
)

// Version 模型版本（api_model_versions，000018 迁移对齐任务书 50.2 列）。
type Version struct {
	ID                  uuid.UUID         `json:"id"`
	EndpointID          uuid.UUID         `json:"api_endpoint_id"`
	EndpointKey         string            `json:"endpoint_key"`
	VersionNumber       int               `json:"version_number"`
	ParentVersionID     *uuid.UUID        `json:"parent_version_id,omitempty"`
	RequestSchemaID     *uuid.UUID        `json:"request_schema_id,omitempty"`
	ResponseSchemaSetID *uuid.UUID        `json:"response_schema_set_id,omitempty"`
	Status              string            `json:"status"`
	Schema              map[string]string `json:"schema"`
	ContentHash         string            `json:"content_hash"`
	ChangeSummary       string            `json:"change_summary"`
	SampleCount         int               `json:"sample_count"`
	ValidSampleCount    int               `json:"valid_sample_count"`
	ExcludedSampleCount int               `json:"excluded_sample_count"`
	Confidence          float64           `json:"confidence"`
	CreatedReason       string            `json:"created_reason"`
	CreatedBy           *uuid.UUID        `json:"created_by,omitempty"`
	CreatedAt           time.Time         `json:"created_at"`
	ConfirmedBy         *uuid.UUID        `json:"confirmed_by,omitempty"`
	ConfirmedAt         *time.Time        `json:"confirmed_at,omitempty"`
	ActivatedAt         *time.Time        `json:"activated_at,omitempty"`
}

// versionColumns 版本全列（SELECT/RETURNING 共用，顺序与 scanVersion 一致）。
const versionColumns = `id, api_endpoint_id, endpoint_key, version_number, parent_version_id,
request_schema_id, response_schema_set_id, status, schema_json, content_hash, change_summary,
sample_count, valid_sample_count, excluded_sample_count, confidence,
created_reason, created_by, created_at, confirmed_by, confirmed_at, activated_at`

// scanner 统一 pgx.Row / pgx.Rows 的 Scan 签名。
type scanner interface {
	Scan(dest ...any) error
}

// scanVersion 按 versionColumns 顺序扫描一行版本记录。
func scanVersion(row scanner) (*Version, error) {
	var v Version
	var raw []byte
	err := row.Scan(&v.ID, &v.EndpointID, &v.EndpointKey, &v.VersionNumber, &v.ParentVersionID,
		&v.RequestSchemaID, &v.ResponseSchemaSetID, &v.Status, &raw, &v.ContentHash, &v.ChangeSummary,
		&v.SampleCount, &v.ValidSampleCount, &v.ExcludedSampleCount, &v.Confidence,
		&v.CreatedReason, &v.CreatedBy, &v.CreatedAt, &v.ConfirmedBy, &v.ConfirmedAt, &v.ActivatedAt)
	if err != nil {
		return nil, err
	}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &v.Schema)
	}
	if v.Schema == nil {
		v.Schema = map[string]string{}
	}
	return &v, nil
}

// Store 仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建。
func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

// nullUUID uuid.Nil 转 NULL（可空操作者列）。
func nullUUID(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}

// EndpointKey 读取端点键（创建候选模型时回写模型载体）。
func (s *Store) EndpointKey(ctx context.Context, endpointID uuid.UUID) (string, error) {
	var key string
	err := s.db.QueryRow(ctx, `SELECT endpoint_key FROM api_endpoints WHERE id=$1`, endpointID).Scan(&key)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrEndpointNotFound
	}
	return key, err
}

// CreateCandidate 创建候选版本（初始状态 CANDIDATE）。
// version_number 在创建时按端点序号分配（同端点 max+1），状态迁移不再改变。
func (s *Store) CreateCandidate(ctx context.Context, endpointID uuid.UUID, endpointKey, changeSummary string, schema map[string]string, createdBy uuid.UUID) (*Version, error) {
	if schema == nil {
		schema = map[string]string{}
	}
	h := hashSchema(endpointKey, schema)
	raw, _ := json.Marshal(schema)
	v, err := scanVersion(s.db.QueryRow(ctx, `
INSERT INTO api_model_versions (api_endpoint_id, endpoint_key, status, version_number, schema_json, content_hash, change_summary, created_reason, created_by)
VALUES ($1,$2,$3,(SELECT COALESCE(MAX(version_number),0)+1 FROM api_model_versions WHERE api_endpoint_id=$1),$4,$5,$6,'manual',$7)
RETURNING `+versionColumns,
		endpointID, endpointKey, StatusCandidate, raw, h, changeSummary, nullUUID(createdBy)))
	if err != nil {
		return nil, err
	}
	return v, nil
}

// GetByID 按 ID 读取版本。
func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (*Version, error) {
	v, err := scanVersion(s.db.QueryRow(ctx, `SELECT `+versionColumns+` FROM api_model_versions WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return v, nil
}

// Confirm 确认为正式模型：候选/评审中 → FORMAL；
// 同端点旧 FORMAL 降级 SUPERSEDED，并记录 confirmed_by/confirmed_at/activated_at（事务 + FOR UPDATE）。
// version_number 在创建时已分配，确认不改动（首个 FORMAL 即 v1）。
func (s *Store) Confirm(ctx context.Context, id, operatorID uuid.UUID) (*Version, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	v, err := scanVersion(tx.QueryRow(ctx, `SELECT `+versionColumns+` FROM api_model_versions WHERE id=$1 FOR UPDATE`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if v.Status != StatusCandidate && v.Status != StatusInReview {
		return nil, ErrNotCandidate
	}
	// 旧正式模型降级为 SUPERSEDED
	if _, err := tx.Exec(ctx, `
UPDATE api_model_versions SET status=$1 WHERE api_endpoint_id=$2 AND status=$3 AND id<>$4`,
		StatusSuperseded, v.EndpointID, StatusFormal, id); err != nil {
		return nil, err
	}
	out, err := scanVersion(tx.QueryRow(ctx, `
UPDATE api_model_versions
SET status=$2, confirmed_by=$3, confirmed_at=now(), activated_at=now()
WHERE id=$1
RETURNING `+versionColumns, id, StatusFormal, nullUUID(operatorID)))
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return out, nil
}

// SubmitReview 提交评审：CANDIDATE → IN_REVIEW，并写 api_model_reviews(SUBMIT)。
func (s *Store) SubmitReview(ctx context.Context, id, reviewerID uuid.UUID, comment string) (*Version, error) {
	return s.transitionWithReview(ctx, id, reviewerID, comment, StatusInReview, "SUBMIT", StatusCandidate)
}

// Reject 评审拒绝：CANDIDATE / IN_REVIEW → REJECTED，并写 api_model_reviews(REJECT)。
func (s *Store) Reject(ctx context.Context, id, reviewerID uuid.UUID, comment string) (*Version, error) {
	return s.transitionWithReview(ctx, id, reviewerID, comment, StatusRejected, "REJECT", StatusCandidate, StatusInReview)
}

// transitionWithReview 带评审记录的状态迁移（事务 + FOR UPDATE）。
func (s *Store) transitionWithReview(ctx context.Context, id, reviewerID uuid.UUID, comment, to, action string, from ...string) (*Version, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	v, err := scanVersion(tx.QueryRow(ctx, `SELECT `+versionColumns+` FROM api_model_versions WHERE id=$1 FOR UPDATE`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	allowed := false
	for _, st := range from {
		if v.Status == st {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, ErrInvalidTransition
	}
	out, err := scanVersion(tx.QueryRow(ctx, `
UPDATE api_model_versions SET status=$2 WHERE id=$1 RETURNING `+versionColumns, id, to))
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO api_model_reviews (model_version_id, reviewer_id, action, comment) VALUES ($1,$2,$3,$4)`,
		id, nullUUID(reviewerID), action, comment); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return out, nil
}

// Activate 激活正式模型：仅 FORMAL；
// 置 api_endpoints.current_model_version_id 并刷新版本 activated_at（事务 + FOR UPDATE）。
func (s *Store) Activate(ctx context.Context, id uuid.UUID) (*Version, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	v, err := scanVersion(tx.QueryRow(ctx, `SELECT `+versionColumns+` FROM api_model_versions WHERE id=$1 FOR UPDATE`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if v.Status != StatusFormal {
		return nil, ErrInvalidTransition
	}
	out, err := scanVersion(tx.QueryRow(ctx, `
UPDATE api_model_versions SET activated_at=now() WHERE id=$1 RETURNING `+versionColumns, id))
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `
UPDATE api_endpoints SET current_model_version_id=$1, updated_at=now() WHERE id=$2`, id, v.EndpointID); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return out, nil
}

// Archive 归档：FORMAL / SUPERSEDED / REJECTED → ARCHIVED。
func (s *Store) Archive(ctx context.Context, id uuid.UUID) (*Version, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	v, err := scanVersion(tx.QueryRow(ctx, `SELECT `+versionColumns+` FROM api_model_versions WHERE id=$1 FOR UPDATE`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	switch v.Status {
	case StatusFormal, StatusSuperseded, StatusRejected:
	default:
		return nil, ErrInvalidTransition
	}
	out, err := scanVersion(tx.QueryRow(ctx, `
UPDATE api_model_versions SET status=$2 WHERE id=$1 RETURNING `+versionColumns, id, StatusArchived))
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return out, nil
}

// TypeChange 字段类型变化。
type TypeChange struct {
	Field string `json:"field"`
	From  string `json:"from"`
	To    string `json:"to"`
}

// SchemaDiff 两版本字段级差异。
type SchemaDiff struct {
	Added       []string     `json:"added"`
	Removed     []string     `json:"removed"`
	TypeChanged []TypeChange `json:"type_changed"`
}

// ModelDiff 版本差异记录（api_model_diffs）。
type ModelDiff struct {
	ID             uuid.UUID  `json:"id"`
	ModelVersionID uuid.UUID  `json:"model_version_id"`
	OtherVersionID uuid.UUID  `json:"other_version_id"`
	Diff           SchemaDiff `json:"diff"`
	CreatedAt      time.Time  `json:"created_at"`
}

// Diff 计算 otherID → id 的字段级差异，upsert 进 api_model_diffs 后返回。
func (s *Store) Diff(ctx context.Context, id, otherID uuid.UUID) (*ModelDiff, error) {
	v, err := s.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	other, err := s.GetByID(ctx, otherID)
	if err != nil {
		return nil, err
	}
	d := computeSchemaDiff(other.Schema, v.Schema)
	raw, _ := json.Marshal(d)
	out := &ModelDiff{ModelVersionID: id, OtherVersionID: otherID, Diff: d}
	err = s.db.QueryRow(ctx, `
INSERT INTO api_model_diffs (model_version_id, other_version_id, diff_json)
VALUES ($1,$2,$3)
ON CONFLICT (model_version_id, other_version_id)
DO UPDATE SET diff_json=EXCLUDED.diff_json, created_at=now()
RETURNING id, created_at`, id, otherID, raw).Scan(&out.ID, &out.CreatedAt)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ComputeSchemaDiff 计算 from → to 的字段级差异（导出给只读调用方，如 AI Tool；
// 纯计算不落 api_model_diffs，与 Store.Diff 的持久化路径区分）。
func ComputeSchemaDiff(from, to map[string]string) SchemaDiff { return computeSchemaDiff(from, to) }

// computeSchemaDiff 计算 from → to 的字段级差异（纯函数，输出按字段名排序保证确定性）。
func computeSchemaDiff(from, to map[string]string) SchemaDiff {
	d := SchemaDiff{Added: []string{}, Removed: []string{}, TypeChanged: []TypeChange{}}
	for field, toType := range to {
		fromType, ok := from[field]
		if !ok {
			d.Added = append(d.Added, field)
			continue
		}
		if fromType != toType {
			d.TypeChanged = append(d.TypeChanged, TypeChange{Field: field, From: fromType, To: toType})
		}
	}
	for field := range from {
		if _, ok := to[field]; !ok {
			d.Removed = append(d.Removed, field)
		}
	}
	sort.Strings(d.Added)
	sort.Strings(d.Removed)
	sort.Slice(d.TypeChanged, func(i, j int) bool { return d.TypeChanged[i].Field < d.TypeChanged[j].Field })
	return d
}

// FormalSchema 端点正式模型。
func (s *Store) FormalSchema(ctx context.Context, endpointKey string) (map[string]string, error) {
	var raw []byte
	err := s.db.QueryRow(ctx, `
SELECT schema_json FROM api_model_versions
WHERE endpoint_key=$1 AND status='FORMAL' ORDER BY confirmed_at DESC NULLS LAST LIMIT 1`, endpointKey).Scan(&raw)
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

// List 按端点键列出版本（旧路由兼容；新接口用 ListByEndpoint）。
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
SELECT `+versionColumns+`
FROM api_model_versions
WHERE endpoint_key=$1 OR $1=''
ORDER BY created_at DESC LIMIT $2 OFFSET $3`, endpointKey, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Version
	for rows.Next() {
		v, err := scanVersion(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *v)
	}
	if out == nil {
		out = []Version{}
	}
	return out, total, rows.Err()
}

// ListByEndpoint 按端点 ID 分页列出版本（任务书 51.2）。
func (s *Store) ListByEndpoint(ctx context.Context, endpointID uuid.UUID, page, pageSize int) ([]Version, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM api_model_versions WHERE api_endpoint_id=$1`, endpointID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(ctx, `
SELECT `+versionColumns+`
FROM api_model_versions
WHERE api_endpoint_id=$1
ORDER BY created_at DESC LIMIT $2 OFFSET $3`, endpointID, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Version
	for rows.Next() {
		v, err := scanVersion(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *v)
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
// 同一 endpoint_key 存在多个 FORMAL 版本时取最近确认者（正常 Confirm 流程至多一个 FORMAL）。
func (s *Store) ListFormalSchemas(ctx context.Context) (map[string]map[string]string, error) {
	rows, err := s.db.Query(ctx, `
SELECT DISTINCT ON (endpoint_key) endpoint_key, schema_json
FROM api_model_versions WHERE status='FORMAL'
ORDER BY endpoint_key, confirmed_at DESC NULLS LAST`)
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
