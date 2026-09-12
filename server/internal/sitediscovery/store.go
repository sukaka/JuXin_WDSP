// store.go 站点发现 PostgreSQL 仓储。
package sitediscovery

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// discoveryColumns 全列（扫描顺序固定）。
const discoveryColumns = `id, domain, ip, port, protocol, source_mode, gateway_node,
	seen_count, client_count, first_seen, last_seen, status, confirmed_by, confirmed_at,
	created_at, updated_at`

// rowScanner 抽象 pgx.Row / pgx.Rows 的 Scan。
type rowScanner interface {
	Scan(dest ...any) error
}

func scanDiscovery(rs rowScanner) (*Discovery, error) {
	var d Discovery
	err := rs.Scan(&d.ID, &d.Domain, &d.IP, &d.Port, &d.Protocol, &d.SourceMode, &d.GatewayNode,
		&d.SeenCount, &d.ClientCount, &d.FirstSeen, &d.LastSeen, &d.Status, &d.ConfirmedBy,
		&d.ConfirmedAt, &d.CreatedAt, &d.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &d, nil
}

// Store 是 PostgreSQL 仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建仓储。
func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

// 确保 *Store 实现 Repository。
var _ Repository = (*Store)(nil)

// Upsert 发现/命中 upsert（按 domain+ip+port 幂等）。
// seen_count 累加（EXCLUDED 为本窗口命中数）；client_count/last_seen/gateway_node 覆盖式更新；
// status/confirmed_by/confirmed_at 不覆盖（保留人工处置）；first_seen 保留首插值；
// protocol/source_mode 同样保留首插值（同一三元组协议变更罕见，避免采集覆盖人工可见的初判）。
// 重放安全由唯一键兜底；注意 hits 累加语义在采集器失败重放时会重复计数——
// 接受为近似指标（断点失败不前移换来的是不丢数据，计数上界随重放次数放大，仅作运营参考）。
func (s *Store) Upsert(ctx context.Context, in DiscoveryInput) (*Discovery, error) {
	in, err := normalizeInput(in)
	if err != nil {
		return nil, err
	}
	return scanDiscovery(s.db.QueryRow(ctx, `
INSERT INTO site_asset_discoveries (domain, ip, port, protocol, source_mode, gateway_node,
  seen_count, client_count, first_seen, last_seen)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
ON CONFLICT (domain, ip, port) DO UPDATE SET
  seen_count = site_asset_discoveries.seen_count + EXCLUDED.seen_count,
  client_count = EXCLUDED.client_count,
  last_seen = EXCLUDED.last_seen,
  gateway_node = EXCLUDED.gateway_node,
  updated_at = now()
RETURNING `+discoveryColumns,
		in.Domain, in.IP, in.Port, in.Protocol, in.SourceMode, in.Node,
		in.Hits, in.ClientCount, in.WindowStart, in.WindowEnd))
}

// List 分页列表（status/protocol/source_mode/keyword 过滤；last_seen DESC 排序）。
func (s *Store) List(ctx context.Context, f ListFilter) ([]Discovery, int64, error) {
	if f.Page <= 0 {
		f.Page = 1
	}
	if f.PageSize <= 0 || f.PageSize > 100 {
		f.PageSize = 20
	}
	where := "1=1"
	args := []any{}
	add := func(cond string, v any) {
		args = append(args, v)
		where += fmt.Sprintf(" AND "+cond, len(args))
	}
	if f.Status != "" {
		add("status = $%d", f.Status)
	}
	if f.Protocol != "" {
		add("protocol = $%d", f.Protocol)
	}
	if f.SourceMode != "" {
		add("source_mode = $%d", f.SourceMode)
	}
	if f.Keyword != "" {
		args = append(args, "%"+f.Keyword+"%")
		where += fmt.Sprintf(" AND (domain ILIKE $%d OR ip ILIKE $%d)", len(args), len(args))
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM site_asset_discoveries WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	rows, err := s.db.Query(ctx, fmt.Sprintf(`
SELECT %s FROM site_asset_discoveries
WHERE %s ORDER BY last_seen DESC, id LIMIT $%d OFFSET $%d`,
		discoveryColumns, where, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Discovery{}
	for rows.Next() {
		d, err := scanDiscovery(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *d)
	}
	return out, total, rows.Err()
}

// GetByID 查询；不存在返回 ErrNotFound。
func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (*Discovery, error) {
	d, err := scanDiscovery(s.db.QueryRow(ctx,
		`SELECT `+discoveryColumns+` FROM site_asset_discoveries WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return d, err
}

// transition 状态流转（单语句带状态守卫，行锁保证并发下只有一个流转生效）：
// allowed 为允许的源状态集合；set 为更新片段（含 confirmed_* 处置字段写法）。
// 未命中守卫时区分 ErrNotFound / ErrInvalidTransition（多一次 SELECT，仅错误路径）。
func (s *Store) transition(ctx context.Context, id uuid.UUID, operator, set string, allowed ...string) (*Discovery, error) {
	guard := make([]string, 0, len(allowed))
	for _, st := range allowed {
		guard = append(guard, fmt.Sprintf("'%s'", st))
	}
	// operator 仅在 set 片段引用 $2 时作为参数传入（Restore 清空处置字段，不引用 $2），
	// 否则 pgx 因占位符与参数个数不匹配直接报错。
	args := []any{id}
	if strings.Contains(set, "$2") {
		args = append(args, operator)
	}
	d, err := scanDiscovery(s.db.QueryRow(ctx, fmt.Sprintf(`
UPDATE site_asset_discoveries SET %s, updated_at=now()
WHERE id=$1 AND status IN (%s)
RETURNING `+discoveryColumns, set, strings.Join(guard, ",")), args...))
	if errors.Is(err, pgx.ErrNoRows) {
		var one int
		terr := s.db.QueryRow(ctx, `SELECT 1 FROM site_asset_discoveries WHERE id=$1`, id).Scan(&one)
		if errors.Is(terr, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		if terr != nil {
			return nil, terr
		}
		return nil, ErrInvalidTransition
	}
	if err != nil {
		return nil, err
	}
	return d, nil
}

// Confirm 人工确认（NEW→CONFIRMED；已 CONFIRMED 幂等重写处置人），记录 confirmed_by/confirmed_at。
func (s *Store) Confirm(ctx context.Context, id uuid.UUID, operator string) (*Discovery, error) {
	return s.transition(ctx, id, operator,
		`status='CONFIRMED', confirmed_by=$2, confirmed_at=now()`, StatusNew, StatusConfirmed)
}

// Ignore 人工忽略（NEW/CONFIRMED→IGNORED；已 IGNORED 幂等），记录 confirmed_by/confirmed_at。
func (s *Store) Ignore(ctx context.Context, id uuid.UUID, operator string) (*Discovery, error) {
	return s.transition(ctx, id, operator,
		`status='IGNORED', confirmed_by=$2, confirmed_at=now()`, StatusNew, StatusConfirmed, StatusIgnored)
}

// Restore 恢复为新发现（CONFIRMED/IGNORED→NEW），清空 confirmed_by/confirmed_at。
func (s *Store) Restore(ctx context.Context, id uuid.UUID, operator string) (*Discovery, error) {
	return s.transition(ctx, id, operator,
		`status='NEW', confirmed_by='', confirmed_at=NULL`, StatusConfirmed, StatusIgnored)
}
