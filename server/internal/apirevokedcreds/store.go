// store.go api_revoked_credentials 表读写（表由迁移 000156 建立）。
// 发布通道只读当前生效窗口内的行（guardconfig.RevokedCredentialStore 按冻结列名读取）。
package apirevokedcreds

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Repository 已吊销凭据仓储接口（pgx 实现见 Store；单测可注入内存 fake）。
type Repository interface {
	Create(ctx context.Context, in CreateInput, operator string) (*Credential, error)
	List(ctx context.Context, filter ListFilter) ([]Credential, error)
	Get(ctx context.Context, id uuid.UUID) (*Credential, error)
	Update(ctx context.Context, id uuid.UUID, in UpdateInput) (*Credential, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

// Store 已吊销凭据 pgx 实现。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建已吊销凭据仓储。
func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

var _ Repository = (*Store)(nil)

const credentialColumns = `
	id, credential_type, fingerprint, reason, COALESCE(revoked_by,''),
	effective_from, effective_until, COALESCE(created_by,''), created_at, updated_at`

func scanCredential(row pgx.Row) (*Credential, error) {
	var c Credential
	if err := row.Scan(&c.ID, &c.CredentialType, &c.Fingerprint, &c.Reason, &c.RevokedBy,
		&c.EffectiveFrom, &c.EffectiveUntil, &c.CreatedBy, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return nil, err
	}
	return &c, nil
}

// Create 登记吊销（同类型同指纹唯一冲突返回 ErrDuplicate）。
func (s *Store) Create(ctx context.Context, in CreateInput, operator string) (*Credential, error) {
	if err := validateCreate(&in); err != nil {
		return nil, err
	}
	row := s.db.QueryRow(ctx, `
INSERT INTO api_revoked_credentials
    (credential_type, fingerprint, reason, revoked_by, effective_from, effective_until, created_by)
VALUES ($1, $2, $3, NULLIF($4,''), COALESCE($5, now()), $6, NULLIF($7,''))
RETURNING`+credentialColumns,
		in.CredentialType, in.Fingerprint, in.Reason, operator, in.EffectiveFrom, in.EffectiveUntil, operator)
	c, err := scanCredential(row)
	if err != nil {
		if mapped := mapWriteError(err); mapped != nil {
			return nil, mapped
		}
		return nil, fmt.Errorf("insert api_revoked_credentials: %w", err)
	}
	return c, nil
}

// List 吊销清单（credential_type/active 过滤可选；按 credential_type, fingerprint 稳定排序——
// 同内容恒得同序列，发布版本戳确定）。
func (s *Store) List(ctx context.Context, filter ListFilter) ([]Credential, error) {
	query := `SELECT` + credentialColumns + ` FROM api_revoked_credentials`
	args := []any{}
	where := ""
	if filter.CredentialType != "" {
		where += ` AND credential_type = $1`
		args = append(args, filter.CredentialType)
	}
	if filter.Active != nil {
		if *filter.Active {
			where += ` AND effective_from <= now() AND (effective_until IS NULL OR effective_until > now())`
		} else {
			where += ` AND (effective_from > now() OR (effective_until IS NOT NULL AND effective_until <= now()))`
		}
	}
	if where != "" {
		query += ` WHERE ` + where[len(" AND "):]
	}
	query += ` ORDER BY credential_type, fingerprint`
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list api_revoked_credentials: %w", err)
	}
	defer rows.Close()
	out := []Credential{}
	for rows.Next() {
		c, err := scanCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// Get 读取单条吊销记录。
func (s *Store) Get(ctx context.Context, id uuid.UUID) (*Credential, error) {
	c, err := scanCredential(s.db.QueryRow(ctx,
		`SELECT`+credentialColumns+` FROM api_revoked_credentials WHERE id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get api_revoked_credentials: %w", err)
	}
	return c, nil
}

// Update 调整吊销（仅 reason/生效窗口可变；吊销对象身份不可变更；不存在返回 ErrNotFound）。
func (s *Store) Update(ctx context.Context, id uuid.UUID, in UpdateInput) (*Credential, error) {
	if err := validateUpdate(&in); err != nil {
		return nil, err
	}
	c, err := scanCredential(s.db.QueryRow(ctx, `
UPDATE api_revoked_credentials
SET reason = $2, effective_from = $3, effective_until = $4, updated_at = now()
WHERE id = $1
RETURNING`+credentialColumns,
		id, in.Reason, in.EffectiveFrom, in.EffectiveUntil))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		if mapped := mapWriteError(err); mapped != nil {
			return nil, mapped
		}
		return nil, fmt.Errorf("update api_revoked_credentials: %w", err)
	}
	return c, nil
}

// Delete 移除吊销记录（移除即退出下次发布载荷；不存在返回 ErrNotFound）。
func (s *Store) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM api_revoked_credentials WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete api_revoked_credentials: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// mapWriteError 唯一冲突/约束违规映射为领域错误（23505 → 409；23514 CHECK 违规 → 400，
// 应用层校验已先行拒绝，此处为兜底不静默吞错）。
func mapWriteError(err error) error {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return nil
	}
	switch pgErr.Code {
	case "23505":
		return ErrDuplicate
	case "23514":
		return &ValidationError{msg: "违反表约束: " + pgErr.ConstraintName}
	}
	return nil
}
