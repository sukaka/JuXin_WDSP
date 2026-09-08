// store.go 离线授权 PostgreSQL 仓储：导入落库（同事务旧生效候选行置 SUPERSEDED）、
// 生效候选行查询、状态翻转（EXPIRED/FINGERPRINT_MISMATCH/INVALID/恢复 ACTIVE）、
// 导入历史分页。生效授权 = 唯一 ACTIVE 行（迁移 000078 部分唯一索引保证）。
package license

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Record 授权记录行（licenses）。payload/signature/raw_file 为敏感原文，
// JSON 输出一律排除（历史列表/接口出参不带出）。
type Record struct {
	ID                 uuid.UUID       `json:"id"`
	LicenseID          string          `json:"license_id"`
	LicenseType        string          `json:"license_type"`
	Product            string          `json:"product"`
	Customer           string          `json:"customer"`
	Status             string          `json:"status"`
	ImportedBy         *uuid.UUID      `json:"imported_by"`
	ImportedAt         time.Time       `json:"imported_at"`
	ExpiresAt          *time.Time      `json:"expires_at"` // DATE；NULL = 永久授权
	Perpetual          bool            `json:"perpetual"`
	MachineFingerprint string          `json:"machine_fingerprint"`
	Quotas             json.RawMessage `json:"quotas"`
	Features           json.RawMessage `json:"features"`
	CreatedAt          time.Time       `json:"created_at"`
	// 以下敏感字段仅仓储内部使用，绝不序列化出参
	Payload   json.RawMessage `json:"-"` // 验签通过的 payload 原文（周期复核重解析用）
	Signature string          `json:"-"`
}

// Repository 授权仓储接口（*Store 实现；service/handler 面向接口，便于测试注入）。
type Repository interface {
	// InsertActive 同事务：旧生效候选行（ACTIVE/FINGERPRINT_MISMATCH）置 SUPERSEDED，
	// 插入新 ACTIVE 行并回填 id/imported_at/created_at；
	// license_id 冲突返回 ErrDuplicate。
	InsertActive(ctx context.Context, rec *Record, rawFileCipher []byte) error
	// LatestCandidate 查询最新生效候选行（status ∈ ACTIVE/FINGERPRINT_MISMATCH，
	// 按 imported_at 倒序）；无候选行返回 ErrNoEffective。
	LatestCandidate(ctx context.Context) (*Record, error)
	// SetStatus 条件翻转行状态（WHERE id AND status ∈ from，防并发覆盖）；
	// 返回是否实际触行。
	SetStatus(ctx context.Context, id uuid.UUID, to string, from ...string) (bool, error)
	// ListHistory 导入历史分页（imported_at 倒序；不含 payload/signature/raw_file）。
	ListHistory(ctx context.Context, page, pageSize int) ([]Record, int64, error)
	// EarliestProduct 全表按导入时间最早一条记录的 product（任何状态均计入——
	// 历史不可绕过，产品形态首导绑定判定用）；无记录返回空串。
	EarliestProduct(ctx context.Context) (string, error)
	// RawFileCipher 读取指定行 raw_file 密文（复核篡改检测重验签名用；
	// NULL 返回 nil——enc 未装配时导入的历史行）。
	RawFileCipher(ctx context.Context, id uuid.UUID) ([]byte, error)
}

// Store 授权 PostgreSQL 仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建。
func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

var _ Repository = (*Store)(nil)

// recordCols 生效候选行查询列（含 payload/signature，周期复核重验签用；不含 raw_file）。
const recordCols = `id, license_id, license_type, product, customer, status,
	imported_by, imported_at, expires_at, perpetual, machine_fingerprint,
	quotas, features, payload, signature, created_at`

// listCols 历史列表查询列（不含 payload/signature/raw_file 敏感原文）。
const listCols = `id, license_id, license_type, product, customer, status,
	imported_by, imported_at, expires_at, perpetual, machine_fingerprint,
	quotas, features, created_at`

// InsertActive 导入落库：同事务内先把旧生效候选行（ACTIVE/FINGERPRINT_MISMATCH，
// 含指纹失配行——新授权导入后旧行不再参与生效候选）置 SUPERSEDED，再插入新 ACTIVE 行。
func (s *Store) InsertActive(ctx context.Context, rec *Record, rawFileCipher []byte) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
UPDATE licenses SET status='SUPERSEDED', updated_at=now()
WHERE status IN ('ACTIVE','FINGERPRINT_MISMATCH')`); err != nil {
		return fmt.Errorf("置旧授权 SUPERSEDED 失败: %w", err)
	}
	err = tx.QueryRow(ctx, `
INSERT INTO licenses
(license_id, license_type, product, customer, payload, signature, raw_file,
 status, imported_by, expires_at, perpetual, machine_fingerprint, quotas, features)
VALUES ($1,$2,$3,$4,$5,$6,$7,'ACTIVE',$8,$9,$10,$11,$12,$13)
RETURNING id, imported_at, created_at`,
		rec.LicenseID, rec.LicenseType, rec.Product, rec.Customer, rec.Payload, rec.Signature,
		rawFileCipher, rec.ImportedBy, rec.ExpiresAt, rec.Perpetual, rec.MachineFingerprint,
		rec.Quotas, rec.Features).Scan(&rec.ID, &rec.ImportedAt, &rec.CreatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrDuplicate
		}
		return fmt.Errorf("落库授权失败: %w", err)
	}
	return tx.Commit(ctx)
}

// LatestCandidate 最新生效候选行（ACTIVE/FINGERPRINT_MISMATCH 中取最近导入）。
func (s *Store) LatestCandidate(ctx context.Context) (*Record, error) {
	row := s.db.QueryRow(ctx, `
SELECT `+recordCols+` FROM licenses
WHERE status IN ('ACTIVE','FINGERPRINT_MISMATCH')
ORDER BY imported_at DESC, id DESC LIMIT 1`)
	var rec Record
	if err := row.Scan(&rec.ID, &rec.LicenseID, &rec.LicenseType, &rec.Product, &rec.Customer,
		&rec.Status, &rec.ImportedBy, &rec.ImportedAt, &rec.ExpiresAt, &rec.Perpetual,
		&rec.MachineFingerprint, &rec.Quotas, &rec.Features, &rec.Payload, &rec.Signature, &rec.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNoEffective
		}
		return nil, err
	}
	return &rec, nil
}

// SetStatus 条件翻转行状态（status = ANY(from) 才触行，防与并发导入/复核互相覆盖）。
func (s *Store) SetStatus(ctx context.Context, id uuid.UUID, to string, from ...string) (bool, error) {
	if len(from) == 0 {
		return false, fmt.Errorf("SetStatus 需至少一个源状态")
	}
	res, err := s.db.Exec(ctx, `
UPDATE licenses SET status=$2, updated_at=now() WHERE id=$1 AND status = ANY($3)`,
		id, to, from)
	if err != nil {
		return false, err
	}
	return res.RowsAffected() > 0, nil
}

// EarliestProduct 全表最早导入记录的 product（不限状态：SUPERSEDED/EXPIRED/INVALID
// 历史同样构成绑定，防止通过翻转状态绕过产品形态绑定）。
func (s *Store) EarliestProduct(ctx context.Context) (string, error) {
	var product string
	err := s.db.QueryRow(ctx, `
SELECT product FROM licenses ORDER BY imported_at ASC, id ASC LIMIT 1`).Scan(&product)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		return "", err
	}
	return product, nil
}

// RawFileCipher 读取指定行 raw_file 密文（仅复核篡改检测内部使用，不出接口）。
func (s *Store) RawFileCipher(ctx context.Context, id uuid.UUID) ([]byte, error) {
	var cipher []byte
	err := s.db.QueryRow(ctx, `SELECT raw_file FROM licenses WHERE id=$1`, id).Scan(&cipher)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNoEffective
		}
		return nil, err
	}
	return cipher, nil
}

// ListHistory 导入历史分页（imported_at 倒序；不读出敏感原文列）。
func (s *Store) ListHistory(ctx context.Context, page, pageSize int) ([]Record, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM licenses`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(ctx, `
SELECT `+listCols+` FROM licenses
ORDER BY imported_at DESC, id DESC LIMIT $1 OFFSET $2`, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Record{}
	for rows.Next() {
		var rec Record
		if err := rows.Scan(&rec.ID, &rec.LicenseID, &rec.LicenseType, &rec.Product, &rec.Customer,
			&rec.Status, &rec.ImportedBy, &rec.ImportedAt, &rec.ExpiresAt, &rec.Perpetual,
			&rec.MachineFingerprint, &rec.Quotas, &rec.Features, &rec.CreatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, rec)
	}
	return out, total, rows.Err()
}
