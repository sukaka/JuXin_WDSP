// Package protectedaddresses 提供保护地址管理：系统不可封禁地址的自动登记（Refresh）、
// 自定义保护地址维护，以及封禁前保护检查（Checker 接口）。
package protectedaddresses

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 地址类型
const (
	TypeGateway      = "GATEWAY"
	TypeManagement   = "MANAGEMENT"
	TypeUpstream     = "UPSTREAM"
	TypeDatabase     = "DATABASE"
	TypeCache        = "CACHE"
	TypeTrustedProxy = "TRUSTED_PROXY"
	TypeLoopback     = "LOOPBACK"
	TypeLinkLocal    = "LINK_LOCAL"
	TypeCustom       = "CUSTOM"
)

// 来源类型
const (
	SourceSystem = "SYSTEM"
	SourceManual = "MANUAL"
)

// 状态
const (
	StatusEnabled  = "ENABLED"
	StatusDisabled = "DISABLED"
)

// 错误
var (
	ErrNotFound        = errors.New("protected address not found")
	ErrInvalidInput    = errors.New("invalid protected address input")
	ErrConflict        = errors.New("protected address already exists")
	ErrSystemProtected = errors.New("system protected address cannot be deleted")
)

// ProtectedAddress 是一条保护地址记录（address 与 cidr 二选一）。
type ProtectedAddress struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Address     string    `json:"address"` // 单IP，规范形式
	CIDR        string    `json:"cidr"`    // CIDR，掩码化规范形式
	AddressType string    `json:"address_type"`
	SourceType  string    `json:"source_type"`
	Description string    `json:"description"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Checker 保护地址检查接口（accessrules、temporaryblocks 包通过构造注入使用）。
type Checker interface {
	IsProtected(ctx context.Context, ip string) (protected bool, matchedName string, err error)
}

// Store 是保护地址仓储。
type Store struct {
	db *pgxpool.Pool
}

// 编译期检查：Store 实现 Checker 接口。
var _ Checker = (*Store)(nil)

// NewStore 创建仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

const addressColumns = `id, name, COALESCE(address, ''), COALESCE(cidr, ''),
  address_type, source_type, description, status, created_at, updated_at`

// List 返回全部启用中的保护地址，可按地址类型筛选。
func (s *Store) List(ctx context.Context, addressType string) ([]ProtectedAddress, error) {
	where := "status = 'ENABLED'"
	args := []interface{}{}
	if addressType != "" {
		where += " AND address_type = $1"
		args = append(args, addressType)
	}
	rows, err := s.db.Query(ctx, `SELECT `+addressColumns+`
FROM protected_addresses WHERE `+where+` ORDER BY created_at ASC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProtectedAddress
	for rows.Next() {
		a, err := scanAddressRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

// ListPaged 分页查询启用中的保护地址，可按地址类型筛选。
func (s *Store) ListPaged(ctx context.Context, addressType string, page, pageSize int) ([]ProtectedAddress, int64, error) {
	page, pageSize = normalizePage(page, pageSize)
	where := "status = 'ENABLED'"
	args := []interface{}{}
	argIdx := 1
	if addressType != "" {
		where += fmt.Sprintf(" AND address_type = $%d", argIdx)
		args = append(args, addressType)
		argIdx++
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM protected_addresses WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	query := `SELECT ` + addressColumns + `
FROM protected_addresses WHERE ` + where +
		fmt.Sprintf(" ORDER BY created_at ASC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []ProtectedAddress
	for rows.Next() {
		a, err := scanAddressRows(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *a)
	}
	return out, total, rows.Err()
}

// normalizePage 分页参数归一化（page_size 夹取 ≤100，非法回退默认；与兄弟包口径一致）。
func normalizePage(page, pageSize int) (int, int) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}
	return page, pageSize
}

// GetByID 查询保护地址。
func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (*ProtectedAddress, error) {
	row := s.db.QueryRow(ctx, `SELECT `+addressColumns+`
FROM protected_addresses WHERE id = $1`, id)
	var a ProtectedAddress
	err := row.Scan(&a.ID, &a.Name, &a.Address, &a.CIDR, &a.AddressType,
		&a.SourceType, &a.Description, &a.Status, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &a, nil
}

// Create 创建自定义保护地址（固定 source_type=MANUAL、address_type=CUSTOM）。
func (s *Store) Create(ctx context.Context, a *ProtectedAddress) error {
	a.SourceType = SourceManual
	a.AddressType = TypeCustom
	if err := ValidateInput(a); err != nil {
		return err
	}
	err := s.db.QueryRow(ctx, `
INSERT INTO protected_addresses (name, address, cidr, address_type, source_type, description, status)
VALUES ($1,$2,$3,$4,$5,$6,$7)
RETURNING id, created_at, updated_at`,
		a.Name, nullableStr(a.Address), nullableStr(a.CIDR), a.AddressType,
		a.SourceType, a.Description, a.Status,
	).Scan(&a.ID, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "ux_protected_addresses_addr") {
			return ErrConflict
		}
		return err
	}
	return nil
}

// Delete 删除保护地址（仅 MANUAL 可删；SYSTEM 返回 ErrSystemProtected）。
func (s *Store) Delete(ctx context.Context, id uuid.UUID) error {
	res, err := s.db.Exec(ctx,
		`DELETE FROM protected_addresses WHERE id=$1 AND source_type='MANUAL'`, id)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		if _, gerr := s.GetByID(ctx, id); gerr != nil {
			return ErrNotFound
		}
		return ErrSystemProtected
	}
	return nil
}

// IsProtected 封禁前保护检查：ip 是否命中任一启用中的保护地址。
func (s *Store) IsProtected(ctx context.Context, ip string) (bool, string, error) {
	addrs, err := s.List(ctx, "")
	if err != nil {
		return false, "", err
	}
	matched, name := MatchProtected(addrs, ip)
	return matched, name, nil
}

// refreshEntry 是一条待自动登记的系统保护地址。
type refreshEntry struct {
	Name        string
	Address     string
	CIDR        string
	AddressType string
	Description string
}

// Refresh 自动登记系统保护地址（幂等，已存在同地址记录跳过）。
// 返回新增数与跳过数。
func (s *Store) Refresh(ctx context.Context) (added, skipped int, err error) {
	entries := collectStaticEntries(os.Getenv)
	upstreams, err := s.collectUpstreams(ctx)
	if err != nil {
		return 0, 0, err
	}
	entries = append(entries, upstreams...)
	proxies, err := s.collectTrustedProxies(ctx)
	if err != nil {
		return 0, 0, err
	}
	entries = append(entries, proxies...)
	for _, e := range entries {
		res, err := s.db.Exec(ctx, `
INSERT INTO protected_addresses (name, address, cidr, address_type, source_type, description, status)
VALUES ($1,$2,$3,$4,'SYSTEM',$5,'ENABLED')
ON CONFLICT DO NOTHING`,
			e.Name, nullableStr(e.Address), nullableStr(e.CIDR), e.AddressType, e.Description)
		if err != nil {
			return added, skipped, fmt.Errorf("登记保护地址 %s 失败: %w", e.Name, err)
		}
		if res.RowsAffected() == 0 {
			skipped++
		} else {
			added++
		}
	}
	return added, skipped, nil
}

// collectStaticEntries 收集固定保护地址与来自环境变量的组件地址（纯函数，可单测）。
// 环境变量值只有解析为 IP 字面量时才登记（主机名跳过）。
func collectStaticEntries(getenv func(string) string) []refreshEntry {
	entries := []refreshEntry{
		{Name: "回环地址（IPv4）", Address: "127.0.0.1", AddressType: TypeLoopback, Description: "系统回环地址"},
		{Name: "回环地址（IPv6）", Address: "::1", AddressType: TypeLoopback, Description: "系统回环地址"},
		{Name: "链路本地地址（IPv4）", CIDR: "169.254.0.0/16", AddressType: TypeLinkLocal, Description: "链路本地地址段"},
		{Name: "链路本地地址（IPv6）", CIDR: "fe80::/10", AddressType: TypeLinkLocal, Description: "链路本地地址段"},
	}
	envSources := []struct {
		envKey      string
		name        string
		addressType string
	}{
		{"POSTGRES_HOST", "数据库地址", TypeDatabase},
		{"VALKEY_HOST", "缓存地址", TypeCache},
		{"GATEWAY_NODE_NAME", "网关节点地址", TypeGateway},
	}
	for _, src := range envSources {
		v := strings.TrimSpace(getenv(src.envKey))
		if v == "" {
			continue
		}
		normalized, err := normalizeIP(v)
		if err != nil {
			// 主机名（如 postgres/valkey 服务名）非IP字面量，跳过
			continue
		}
		entries = append(entries, refreshEntry{
			Name:        src.name,
			Address:     normalized,
			AddressType: src.addressType,
			Description: "来自环境变量 " + src.envKey,
		})
	}
	return entries
}

// collectUpstreams 从应用源站读取活动源站地址（host 为 IP 才登记，域名跳过）。
func (s *Store) collectUpstreams(ctx context.Context) ([]refreshEntry, error) {
	rows, err := s.db.Query(ctx,
		`SELECT DISTINCT host FROM upstreams WHERE deleted_at IS NULL AND status = 'ACTIVE'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []refreshEntry
	for rows.Next() {
		var host string
		if err := rows.Scan(&host); err != nil {
			return nil, err
		}
		normalized, err := normalizeIP(host)
		if err != nil {
			continue // 域名源站跳过
		}
		out = append(out, refreshEntry{
			Name:        "源站 " + host,
			Address:     normalized,
			AddressType: TypeUpstream,
			Description: "活动源站地址",
		})
	}
	return out, rows.Err()
}

// collectTrustedProxies 读取启用中的可信代理地址（仅单IP登记，CIDR跳过）。
func (s *Store) collectTrustedProxies(ctx context.Context) ([]refreshEntry, error) {
	rows, err := s.db.Query(ctx,
		`SELECT name, cidr FROM trusted_proxies WHERE deleted_at IS NULL AND status = 'ENABLED'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []refreshEntry
	for rows.Next() {
		var name, cidr string
		if err := rows.Scan(&name, &cidr); err != nil {
			return nil, err
		}
		normalized, err := normalizeIP(cidr)
		if err != nil {
			continue // CIDR 代理段跳过
		}
		out = append(out, refreshEntry{
			Name:        "可信代理 " + name,
			Address:     normalized,
			AddressType: TypeTrustedProxy,
			Description: "启用中的可信代理",
		})
	}
	return out, rows.Err()
}

func scanAddressRows(rows pgx.Rows) (*ProtectedAddress, error) {
	var a ProtectedAddress
	err := rows.Scan(&a.ID, &a.Name, &a.Address, &a.CIDR, &a.AddressType,
		&a.SourceType, &a.Description, &a.Status, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func nullableStr(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
