// Package accesscontrolversions 提供访问控制配置版本管理：创建、查询、对比与回滚。
package accesscontrolversions

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 发布结果
const (
	PublishPending = "PENDING"
	PublishSuccess = "SUCCESS"
	PublishFailed  = "FAILED"
)

// 错误
var (
	ErrNotFound         = errors.New("access control version not found")
	ErrInvalidInput     = errors.New("invalid version input")
	ErrInvalidPubResult = errors.New("invalid publish result")
)

// Version 是访问控制配置版本。
type Version struct {
	ID                uuid.UUID       `json:"id"`
	VersionNo         int             `json:"version_no"`
	Config            json.RawMessage `json:"config"`
	ConfigHash        string          `json:"config_hash"`
	ChangeSummary     string          `json:"change_summary"`
	PreviousVersionID *uuid.UUID      `json:"previous_version_id"`
	PublishTaskID     *uuid.UUID      `json:"publish_task_id"`
	PublishResult     string          `json:"publish_result"`
	CreatedBy         *uuid.UUID      `json:"created_by"`
	CreatedAt         time.Time       `json:"created_at"`
}

// CreateInput 是创建版本的输入。
type CreateInput struct {
	Config            json.RawMessage
	ConfigHash        string // 空则自动计算 sha256
	ChangeSummary     string
	PreviousVersionID *uuid.UUID
	PublishTaskID     *uuid.UUID
	CreatedBy         *uuid.UUID
}

// Validate 校验创建输入。
func (in *CreateInput) Validate() error {
	if len(in.Config) == 0 || !json.Valid(in.Config) {
		return fmt.Errorf("%w: config 必须是合法 JSON", ErrInvalidInput)
	}
	if len(in.ChangeSummary) > 1000 {
		return fmt.Errorf("%w: change_summary 不超过1000字符", ErrInvalidInput)
	}
	return nil
}

// Store 是版本仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建版本仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

const versionColumns = `
SELECT id, version_no, config, config_hash, change_summary, previous_version_id,
  publish_task_id, publish_result, created_by, created_at
FROM access_control_versions`

// Create 创建版本（version_no 自增：MAX(version_no)+1，唯一索引兜底并发）。
func (s *Store) Create(ctx context.Context, in CreateInput) (*Version, error) {
	if err := in.Validate(); err != nil {
		return nil, err
	}
	hash := in.ConfigHash
	if hash == "" {
		sum := sha256.Sum256(in.Config)
		hash = hex.EncodeToString(sum[:])
	}
	v := &Version{
		Config:            in.Config,
		ConfigHash:        hash,
		ChangeSummary:     in.ChangeSummary,
		PreviousVersionID: in.PreviousVersionID,
		PublishTaskID:     in.PublishTaskID,
		PublishResult:     PublishPending,
		CreatedBy:         in.CreatedBy,
	}
	err := s.db.QueryRow(ctx, `
INSERT INTO access_control_versions (version_no, config, config_hash, change_summary,
  previous_version_id, publish_task_id, publish_result, created_by)
VALUES ((SELECT COALESCE(MAX(version_no),0)+1 FROM access_control_versions), $1,$2,$3,$4,$5,$6,$7)
RETURNING id, version_no, created_at`,
		string(in.Config), hash, in.ChangeSummary, in.PreviousVersionID,
		in.PublishTaskID, PublishPending, in.CreatedBy,
	).Scan(&v.ID, &v.VersionNo, &v.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("create version: %w", err)
	}
	return v, nil
}

// List 分页查询版本（按 version_no 倒序）。
func (s *Store) List(ctx context.Context, page, pageSize int) ([]Version, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM access_control_versions`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(ctx, versionColumns+` ORDER BY version_no DESC LIMIT $1 OFFSET $2`,
		pageSize, (page-1)*pageSize)
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
	return out, total, rows.Err()
}

// GetByID 查询版本详情。
func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (*Version, error) {
	row := s.db.QueryRow(ctx, versionColumns+` WHERE id = $1`, id)
	return scanVersion(row)
}

// GetLatest 查询最新版本。
func (s *Store) GetLatest(ctx context.Context) (*Version, error) {
	row := s.db.QueryRow(ctx, versionColumns+` ORDER BY version_no DESC LIMIT 1`)
	return scanVersion(row)
}

// SetResult 更新发布结果。
func (s *Store) SetResult(ctx context.Context, id uuid.UUID, publishResult string) error {
	switch publishResult {
	case PublishPending, PublishSuccess, PublishFailed:
	default:
		return fmt.Errorf("%w: %s", ErrInvalidPubResult, publishResult)
	}
	res, err := s.db.Exec(ctx,
		`UPDATE access_control_versions SET publish_result=$1 WHERE id=$2`, publishResult, id)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func scanVersion(row pgx.Row) (*Version, error) {
	var v Version
	err := row.Scan(&v.ID, &v.VersionNo, &v.Config, &v.ConfigHash, &v.ChangeSummary,
		&v.PreviousVersionID, &v.PublishTaskID, &v.PublishResult, &v.CreatedBy, &v.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &v, nil
}
