// store.go delivery_checks / delivery_check_results 仓储。
package delivery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CheckRun 一次交付检查执行。
type CheckRun struct {
	ID           uuid.UUID  `json:"id"`
	Overall      string     `json:"overall_result"`
	Total        int        `json:"total"`
	PassCount    int        `json:"pass_count"`
	WarningCount int        `json:"warning_count"`
	FailCount    int        `json:"fail_count"`
	RequestedBy  *uuid.UUID `json:"requested_by"`
	StartedAt    time.Time  `json:"started_at"`
	FinishedAt   *time.Time `json:"finished_at"`
}

// Store 交付检查仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

const runColumns = `id, overall_result, total, pass_count, warning_count, fail_count,
requested_by, started_at, finished_at`

func scanRun(row pgx.Row) (*CheckRun, error) {
	var c CheckRun
	err := row.Scan(&c.ID, &c.Overall, &c.Total, &c.PassCount, &c.WarningCount, &c.FailCount,
		&c.RequestedBy, &c.StartedAt, &c.FinishedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &c, nil
}

// CreateRun 创建一次检查（PENDING）。
func (s *Store) CreateRun(ctx context.Context, requestedBy *uuid.UUID) (*CheckRun, error) {
	row := s.db.QueryRow(ctx, `
INSERT INTO delivery_checks (overall_result, requested_by)
VALUES ($1, $2)
RETURNING `+runColumns, OverallPending, requestedBy)
	return scanRun(row)
}

// FinishRun 写入整体结果与统计（事务内同时写结果明细）。
func (s *Store) FinishRun(ctx context.Context, id uuid.UUID, overall string, items []ItemResult) error {
	pass, warning, fail := Counts(items)
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `
UPDATE delivery_checks SET overall_result = $2, total = $3, pass_count = $4,
  warning_count = $5, fail_count = $6, finished_at = now()
WHERE id = $1`, id, overall, len(items), pass, warning, fail)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	for _, it := range items {
		var details interface{}
		if len(it.Details) > 0 {
			b, err := json.Marshal(it.Details)
			if err != nil {
				return fmt.Errorf("marshal details of %s: %w", it.Key, err)
			}
			details = b
		}
		if _, err := tx.Exec(ctx, `
INSERT INTO delivery_check_results (check_id, item_key, item_name, category, result, critical, message, details)
VALUES ($1,$2,$3,$4,$5,$6,$7,COALESCE($8,'{}'::jsonb))`,
			id, it.Key, it.Name, it.Category, it.Result, it.Critical, it.Message, details); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// GetRun 查询一次检查。
func (s *Store) GetRun(ctx context.Context, id uuid.UUID) (*CheckRun, error) {
	row := s.db.QueryRow(ctx, `SELECT `+runColumns+` FROM delivery_checks WHERE id = $1`, id)
	return scanRun(row)
}

// ListRuns 分页查询检查执行记录。
func (s *Store) ListRuns(ctx context.Context, page, pageSize int) ([]CheckRun, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM delivery_checks`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(ctx, `
SELECT `+runColumns+` FROM delivery_checks ORDER BY started_at DESC LIMIT $1 OFFSET $2`,
		pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []CheckRun
	for rows.Next() {
		var c CheckRun
		if err := rows.Scan(&c.ID, &c.Overall, &c.Total, &c.PassCount, &c.WarningCount, &c.FailCount,
			&c.RequestedBy, &c.StartedAt, &c.FinishedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, c)
	}
	return out, total, rows.Err()
}

// ListResults 查询一次检查的结果明细（按创建顺序）。
func (s *Store) ListResults(ctx context.Context, checkID uuid.UUID) ([]ItemResult, error) {
	rows, err := s.db.Query(ctx, `
SELECT item_key, item_name, category, result, critical, message, details
FROM delivery_check_results WHERE check_id = $1 ORDER BY created_at, id`, checkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ItemResult
	for rows.Next() {
		var it ItemResult
		var details []byte
		if err := rows.Scan(&it.Key, &it.Name, &it.Category, &it.Result, &it.Critical, &it.Message, &details); err != nil {
			return nil, err
		}
		if len(details) > 0 {
			if err := json.Unmarshal(details, &it.Details); err != nil {
				return nil, fmt.Errorf("parse details of %s: %w", it.Key, err)
			}
		}
		out = append(out, it)
	}
	return out, rows.Err()
}
