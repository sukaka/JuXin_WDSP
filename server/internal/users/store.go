// Package users 提供用户仓储与用户管理服务。
package users

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 用户错误
var (
	ErrNotFound       = errors.New("user not found")
	ErrUsernameExists = errors.New("username already exists")
	ErrInvalidStatus  = errors.New("invalid user status")
)

// 用户状态
const (
	StatusActive   = "ACTIVE"
	StatusDisabled = "DISABLED"
	StatusLocked   = "LOCKED"
	StatusDeleted  = "DELETED"
)

// User 是用户实体。
type User struct {
	ID                 uuid.UUID  `json:"id"`
	Username           string     `json:"username"`
	DisplayName        string     `json:"display_name"`
	PasswordHash       string     `json:"-"`
	Status             string     `json:"status"`
	MustChangePassword bool       `json:"must_change_password"`
	PasswordChangedAt  *time.Time `json:"password_changed_at"`
	PasswordExpiresAt  *time.Time `json:"password_expires_at"`
	FailedLoginCount   int        `json:"-"`
	LockedUntil        *time.Time `json:"locked_until,omitempty"`
	LastLoginAt        *time.Time `json:"last_login_at"`
	LastLoginIP        string     `json:"last_login_ip,omitempty"`
	CreatedBy          *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
	DeletedAt          *time.Time `json:"-"`
	Version            int        `json:"version"`
	Roles              []RoleInfo `json:"roles,omitempty"`
}

// RoleInfo 是用户关联的角色摘要。
type RoleInfo struct {
	Code string `json:"code"`
	Name string `json:"name"`
}

// Store 是用户仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建用户仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

const userColumns = `id, username, display_name, password_hash, status, must_change_password,
password_changed_at, password_expires_at, failed_login_count, locked_until,
last_login_at, last_login_ip, created_by, created_at, updated_at, deleted_at, version`

func (s *Store) scanUser(row pgx.Row) (*User, error) {
	var u User
	var lastLoginIP *netip.Addr
	err := row.Scan(&u.ID, &u.Username, &u.DisplayName, &u.PasswordHash, &u.Status,
		&u.MustChangePassword, &u.PasswordChangedAt, &u.PasswordExpiresAt,
		&u.FailedLoginCount, &u.LockedUntil, &u.LastLoginAt, &lastLoginIP,
		&u.CreatedBy, &u.CreatedAt, &u.UpdatedAt, &u.DeletedAt, &u.Version)
	if err != nil {
		return nil, err
	}
	if lastLoginIP != nil {
		u.LastLoginIP = lastLoginIP.String()
	}
	return &u, nil
}

// GetByUsername 按用户名查询用户（不区分大小写，不含已删除）。
func (s *Store) GetByUsername(ctx context.Context, username string) (*User, error) {
	row := s.db.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users WHERE lower(username) = lower($1) AND deleted_at IS NULL`,
		username)
	u, err := s.scanUser(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return u, nil
}

// GetByID 按 ID 查询用户。
func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (*User, error) {
	row := s.db.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users WHERE id = $1 AND deleted_at IS NULL`, id)
	u, err := s.scanUser(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return u, nil
}

// GetRoles 查询用户角色。
func (s *Store) GetRoles(ctx context.Context, userID uuid.UUID) ([]RoleInfo, error) {
	rows, err := s.db.Query(ctx, `
SELECT r.code, r.name FROM roles r
JOIN user_roles ur ON ur.role_id = r.id
WHERE ur.user_id = $1`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RoleInfo
	for rows.Next() {
		var ri RoleInfo
		if err := rows.Scan(&ri.Code, &ri.Name); err != nil {
			return nil, err
		}
		out = append(out, ri)
	}
	return out, rows.Err()
}

// GetPermissions 查询用户权限（经角色聚合）。
func (s *Store) GetPermissions(ctx context.Context, userID uuid.UUID) ([]string, error) {
	rows, err := s.db.Query(ctx, `
SELECT DISTINCT p.code FROM permissions p
JOIN role_permissions rp ON rp.permission_id = p.id
JOIN user_roles ur ON ur.role_id = rp.role_id
WHERE ur.user_id = $1`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var code string
		if err := rows.Scan(&code); err != nil {
			return nil, err
		}
		out = append(out, code)
	}
	return out, rows.Err()
}

// ListFilter 是用户列表筛选。
type ListFilter struct {
	Username string
	Status   string
	RoleCode string
	Page     int
	PageSize int
}

// List 分页查询用户。
func (s *Store) List(ctx context.Context, f ListFilter) ([]User, int64, error) {
	if f.Page <= 0 {
		f.Page = 1
	}
	if f.PageSize <= 0 || f.PageSize > 100 {
		f.PageSize = 20
	}
	where := "deleted_at IS NULL"
	args := []interface{}{}
	argIdx := 1
	if f.Username != "" {
		where += fmt.Sprintf(" AND (username ILIKE $%d OR display_name ILIKE $%d)", argIdx, argIdx)
		args = append(args, "%"+f.Username+"%")
		argIdx++
	}
	if f.Status != "" {
		where += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, f.Status)
		argIdx++
	}
	if f.RoleCode != "" {
		where += fmt.Sprintf(" AND id IN (SELECT ur.user_id FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE r.code = $%d)", argIdx)
		args = append(args, f.RoleCode)
		argIdx++
	}

	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM users WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	query := `SELECT ` + userColumns + ` FROM users WHERE ` + where +
		fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)

	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		var lastLoginIP *netip.Addr
		if err := rows.Scan(&u.ID, &u.Username, &u.DisplayName, &u.PasswordHash, &u.Status,
			&u.MustChangePassword, &u.PasswordChangedAt, &u.PasswordExpiresAt,
			&u.FailedLoginCount, &u.LockedUntil, &u.LastLoginAt, &lastLoginIP,
			&u.CreatedBy, &u.CreatedAt, &u.UpdatedAt, &u.DeletedAt, &u.Version); err != nil {
			return nil, 0, err
		}
		u.PasswordHash = "" // 列表不返回哈希
		if lastLoginIP != nil {
			u.LastLoginIP = lastLoginIP.String()
		}
		out = append(out, u)
	}
	return out, total, rows.Err()
}

// Create 创建用户。
func (s *Store) Create(ctx context.Context, u *User) error {
	err := s.db.QueryRow(ctx, `
INSERT INTO users (username, display_name, password_hash, status, must_change_password,
                   password_changed_at, password_expires_at, created_by)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING id, created_at, updated_at, version`,
		u.Username, u.DisplayName, u.PasswordHash, u.Status, u.MustChangePassword,
		u.PasswordChangedAt, u.PasswordExpiresAt, u.CreatedBy).
		Scan(&u.ID, &u.CreatedAt, &u.UpdatedAt, &u.Version)
	if err != nil {
		if strings.Contains(err.Error(), "idx_users_username_lower") {
			return ErrUsernameExists
		}
		return err
	}
	return nil
}

// Update 更新用户基础信息（乐观锁）。
func (s *Store) Update(ctx context.Context, u *User) error {
	res, err := s.db.Exec(ctx, `
UPDATE users SET display_name = $1, status = $2, updated_at = now(), version = version + 1
WHERE id = $3 AND version = $4 AND deleted_at IS NULL`,
		u.DisplayName, u.Status, u.ID, u.Version)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	u.Version++
	return nil
}

// UpdatePassword 更新密码（乐观锁），返回新过期时间由调用方计算。
func (s *Store) UpdatePassword(ctx context.Context, userID uuid.UUID, hash string, expiresAt *time.Time) error {
	res, err := s.db.Exec(ctx, `
UPDATE users SET password_hash = $1, password_changed_at = now(), password_expires_at = $2,
       must_change_password = FALSE, failed_login_count = 0, locked_until = NULL,
       updated_at = now(), version = version + 1
WHERE id = $3 AND deleted_at IS NULL`,
		hash, expiresAt, userID)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdatePasswordForceChange 重置密码并强制首次登录修改。
func (s *Store) UpdatePasswordForceChange(ctx context.Context, userID uuid.UUID, hash string, expiresAt *time.Time) error {
	res, err := s.db.Exec(ctx, `
UPDATE users SET password_hash = $1, password_changed_at = now(), password_expires_at = $2,
       must_change_password = TRUE, failed_login_count = 0, locked_until = NULL,
       updated_at = now(), version = version + 1
WHERE id = $3 AND deleted_at IS NULL`,
		hash, expiresAt, userID)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetStatus 设置用户状态。
func (s *Store) SetStatus(ctx context.Context, id uuid.UUID, status string) error {
	res, err := s.db.Exec(ctx, `
UPDATE users SET status = $1, updated_at = now(), version = version + 1
WHERE id = $2 AND deleted_at IS NULL`, status, id)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SoftDelete 逻辑删除用户。
func (s *Store) SoftDelete(ctx context.Context, id uuid.UUID) error {
	res, err := s.db.Exec(ctx, `
UPDATE users SET deleted_at = now(), status = $2, updated_at = now(), version = version + 1
WHERE id = $1 AND deleted_at IS NULL`, id, StatusDeleted)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// RecordLoginSuccess 记录登录成功（清零失败计数）。
func (s *Store) RecordLoginSuccess(ctx context.Context, id uuid.UUID, sourceIP string) error {
	_, err := s.db.Exec(ctx, `
UPDATE users SET failed_login_count = 0, locked_until = NULL, last_login_at = now(),
       last_login_ip = $2, updated_at = now()
WHERE id = $1`, id, nullableIP(sourceIP))
	return err
}

// RecordLoginFailure 累加失败计数，达到阈值时锁定。
// 返回是否因此次失败而锁定。
func (s *Store) RecordLoginFailure(ctx context.Context, id uuid.UUID, maxAttempts int, lockDuration time.Duration) (bool, error) {
	var count int
	err := s.db.QueryRow(ctx, `
UPDATE users SET failed_login_count = failed_login_count + 1, updated_at = now()
WHERE id = $1 RETURNING failed_login_count`, id).Scan(&count)
	if err != nil {
		return false, err
	}
	if maxAttempts > 0 && count >= maxAttempts {
		_, err = s.db.Exec(ctx, `
UPDATE users SET locked_until = now() + $2 * interval '1 second', status = $3, updated_at = now()
WHERE id = $1`, id, int(lockDuration.Seconds()), StatusLocked)
		if err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

// Unlock 解锁用户。
func (s *Store) Unlock(ctx context.Context, id uuid.UUID) error {
	res, err := s.db.Exec(ctx, `
UPDATE users SET failed_login_count = 0, locked_until = NULL, status = $2, updated_at = now(), version = version + 1
WHERE id = $1 AND deleted_at IS NULL`, id, StatusActive)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ClearExpiredLock 清除过期锁定（登录时检查）。
func (s *Store) ClearExpiredLock(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.Exec(ctx, `
UPDATE users SET failed_login_count = 0, locked_until = NULL, status = $2, updated_at = now()
WHERE id = $1 AND locked_until IS NOT NULL AND locked_until <= now() AND status = $3`,
		id, StatusActive, StatusLocked)
	return err
}

// CountActiveSystemAdmins 统计可用系统管理员数量。
func (s *Store) CountActiveSystemAdmins(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRow(ctx, `
SELECT count(DISTINCT u.id) FROM users u
JOIN user_roles ur ON ur.user_id = u.id
JOIN roles r ON r.id = ur.role_id
WHERE r.code = 'SYSTEM_ADMIN' AND u.status = 'ACTIVE' AND u.deleted_at IS NULL`).Scan(&n)
	return n, err
}

// HasUsers 判断是否已有任何用户（用于初始化）。
func (s *Store) HasUsers(ctx context.Context) (bool, error) {
	var n int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

// AssignRole 分配角色（替换式：一个用户仅一个内置管理角色）。
func (s *Store) AssignRole(ctx context.Context, userID, roleID, operatorID uuid.UUID) error {
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `DELETE FROM user_roles WHERE user_id = $1`, userID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO user_roles (user_id, role_id, created_by) VALUES ($1, $2, $3)`,
		userID, roleID, operatorID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// GetRoleIDByCode 按编码查询角色 ID。
func (s *Store) GetRoleIDByCode(ctx context.Context, code string) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.db.QueryRow(ctx, `SELECT id FROM roles WHERE code = $1`, code).Scan(&id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, errors.New("role not found")
		}
		return uuid.Nil, err
	}
	return id, nil
}

// AddPasswordHistory 记录密码历史。
func (s *Store) AddPasswordHistory(ctx context.Context, userID uuid.UUID, hash string) error {
	_, err := s.db.Exec(ctx,
		`INSERT INTO password_histories (user_id, password_hash) VALUES ($1, $2)`, userID, hash)
	return err
}

// GetPasswordHistories 查询最近 N 条密码历史。
func (s *Store) GetPasswordHistories(ctx context.Context, userID uuid.UUID, limit int) ([]string, error) {
	if limit <= 0 {
		limit = 5
	}
	rows, err := s.db.Query(ctx, `
SELECT password_hash FROM password_histories WHERE user_id = $1
ORDER BY created_at DESC LIMIT $2`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func nullableIP(ip string) interface{} {
	if ip == "" {
		return nil
	}
	return ip
}
