// Package trustedproxies 提供可信代理管理：可信代理 CIDR 的增删改查、启停与命中测试。
// 可信代理列表是真实客户端 IP 识别的信任边界，所有写操作记录审计。
package trustedproxies

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

// 代理头类型
const (
	HeaderXForwardedFor = "X_FORWARDED_FOR"
	HeaderXRealIP       = "X_REAL_IP"
	HeaderForwarded     = "FORWARDED"
	HeaderCustom        = "CUSTOM"
)

// 状态
const (
	StatusEnabled  = "ENABLED"
	StatusDisabled = "DISABLED"
)

// 生效范围
const (
	ScopeGlobal = "GLOBAL"
	ScopeNode   = "NODE"
)

// IP 版本
const (
	IPVersion4 = "IPV4"
	IPVersion6 = "IPV6"
)

// 错误
var (
	ErrNotFound        = errors.New("trusted proxy not found")
	ErrInvalidInput    = errors.New("invalid trusted proxy input")
	ErrCIDRConflict    = errors.New("trusted proxy cidr already exists")
	ErrVersionConflict = errors.New("trusted proxy modified concurrently")
)

// TrustedProxy 是一条可信代理记录。
type TrustedProxy struct {
	ID               uuid.UUID  `json:"id"`
	Name             string     `json:"name"`
	CIDR             string     `json:"cidr"` // 规范形式：单IP或掩码化CIDR
	IPVersion        string     `json:"ip_version"`
	HeaderType       string     `json:"header_type"`
	CustomHeaderName string     `json:"custom_header_name"`
	Priority         int        `json:"priority"`
	Status           string     `json:"status"`
	Scope            string     `json:"scope"`
	NodeName         string     `json:"node_name"`
	Description      string     `json:"description"`
	CreatedBy        *uuid.UUID `json:"created_by"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedBy        *uuid.UUID `json:"updated_by"`
	UpdatedAt        time.Time  `json:"updated_at"`
	Version          int        `json:"version"`
}

// ListFilter 是可信代理列表筛选。
type ListFilter struct {
	Status     string
	HeaderType string
	Keyword    string // 匹配 name / cidr
	Page       int
	PageSize   int
}

// Store 是可信代理仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

const proxyColumns = `id, name, cidr, ip_version, header_type, COALESCE(custom_header_name, ''),
  priority, status, scope, COALESCE(node_name, ''), description,
  created_by, created_at, updated_by, updated_at, version`

// Create 创建可信代理（输入先经 ValidateInput 校验并规范化）。
func (s *Store) Create(ctx context.Context, p *TrustedProxy) error {
	if err := ValidateInput(p); err != nil {
		return err
	}
	err := s.db.QueryRow(ctx, `
INSERT INTO trusted_proxies (name, cidr, ip_version, header_type, custom_header_name,
  priority, status, scope, node_name, description, created_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
RETURNING id, created_at, updated_at, version`,
		p.Name, p.CIDR, p.IPVersion, p.HeaderType, nullableStr(p.CustomHeaderName),
		p.Priority, p.Status, p.Scope, nullableStr(p.NodeName), p.Description, p.CreatedBy,
	).Scan(&p.ID, &p.CreatedAt, &p.UpdatedAt, &p.Version)
	if err != nil {
		if strings.Contains(err.Error(), "ux_trusted_proxies_cidr") {
			return ErrCIDRConflict
		}
		return err
	}
	return nil
}

// GetByID 查询可信代理。
func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (*TrustedProxy, error) {
	row := s.db.QueryRow(ctx, `SELECT `+proxyColumns+`
FROM trusted_proxies WHERE id = $1 AND deleted_at IS NULL`, id)
	return scanProxy(row)
}

// List 分页查询可信代理。
func (s *Store) List(ctx context.Context, f ListFilter) ([]TrustedProxy, int64, error) {
	if f.Page <= 0 {
		f.Page = 1
	}
	if f.PageSize <= 0 || f.PageSize > 100 {
		f.PageSize = 20
	}
	where := "deleted_at IS NULL"
	args := []interface{}{}
	argIdx := 1
	if f.Status != "" {
		where += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, f.Status)
		argIdx++
	}
	if f.HeaderType != "" {
		where += fmt.Sprintf(" AND header_type = $%d", argIdx)
		args = append(args, f.HeaderType)
		argIdx++
	}
	if f.Keyword != "" {
		where += fmt.Sprintf(" AND (name ILIKE $%d OR cidr ILIKE $%d)", argIdx, argIdx)
		args = append(args, "%"+f.Keyword+"%")
		argIdx++
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM trusted_proxies WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	query := `SELECT ` + proxyColumns + `
FROM trusted_proxies WHERE ` + where +
		fmt.Sprintf(" ORDER BY priority ASC, created_at DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []TrustedProxy
	for rows.Next() {
		p, err := scanProxyRows(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *p)
	}
	return out, total, rows.Err()
}

// ListEnabled 返回全部启用中的可信代理（命中测试与网关配置用）。
func (s *Store) ListEnabled(ctx context.Context) ([]TrustedProxy, error) {
	rows, err := s.db.Query(ctx, `SELECT `+proxyColumns+`
FROM trusted_proxies WHERE deleted_at IS NULL AND status = 'ENABLED' ORDER BY priority ASC, created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TrustedProxy
	for rows.Next() {
		p, err := scanProxyRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// Update 更新可信代理（乐观锁：version 不匹配返回 ErrVersionConflict）。
func (s *Store) Update(ctx context.Context, p *TrustedProxy) error {
	if err := ValidateInput(p); err != nil {
		return err
	}
	res, err := s.db.Exec(ctx, `
UPDATE trusted_proxies SET name=$1, cidr=$2, ip_version=$3, header_type=$4, custom_header_name=$5,
  priority=$6, scope=$7, node_name=$8, description=$9,
  updated_by=$10, updated_at=now(), version=version+1
WHERE id=$11 AND version=$12 AND deleted_at IS NULL`,
		p.Name, p.CIDR, p.IPVersion, p.HeaderType, nullableStr(p.CustomHeaderName),
		p.Priority, p.Scope, nullableStr(p.NodeName), p.Description,
		p.UpdatedBy, p.ID, p.Version)
	if err != nil {
		if strings.Contains(err.Error(), "ux_trusted_proxies_cidr") {
			return ErrCIDRConflict
		}
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrVersionConflict
	}
	p.Version++
	return nil
}

// SoftDelete 软删除可信代理。
func (s *Store) SoftDelete(ctx context.Context, id uuid.UUID, deletedBy uuid.UUID) error {
	res, err := s.db.Exec(ctx, `
UPDATE trusted_proxies SET deleted_at=now(), updated_by=$2, updated_at=now(), version=version+1
WHERE id=$1 AND deleted_at IS NULL`, id, deletedBy)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetStatus 启用/停用可信代理。
func (s *Store) SetStatus(ctx context.Context, id uuid.UUID, status string, updatedBy uuid.UUID) error {
	if status != StatusEnabled && status != StatusDisabled {
		return fmt.Errorf("%w: 无效的状态: %s", ErrInvalidInput, status)
	}
	res, err := s.db.Exec(ctx, `
UPDATE trusted_proxies SET status=$1, updated_by=$3, updated_at=now(), version=version+1
WHERE id=$2 AND deleted_at IS NULL`, status, id, updatedBy)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func scanProxy(row pgx.Row) (*TrustedProxy, error) {
	var p TrustedProxy
	err := row.Scan(&p.ID, &p.Name, &p.CIDR, &p.IPVersion, &p.HeaderType, &p.CustomHeaderName,
		&p.Priority, &p.Status, &p.Scope, &p.NodeName, &p.Description,
		&p.CreatedBy, &p.CreatedAt, &p.UpdatedBy, &p.UpdatedAt, &p.Version)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &p, nil
}

func scanProxyRows(rows pgx.Rows) (*TrustedProxy, error) {
	var p TrustedProxy
	err := rows.Scan(&p.ID, &p.Name, &p.CIDR, &p.IPVersion, &p.HeaderType, &p.CustomHeaderName,
		&p.Priority, &p.Status, &p.Scope, &p.NodeName, &p.Description,
		&p.CreatedBy, &p.CreatedAt, &p.UpdatedBy, &p.UpdatedAt, &p.Version)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func nullableStr(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
