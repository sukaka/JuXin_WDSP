// 主备组仓储（PostgreSQL + 内存实现）。
package hagroups

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound 组不存在。
var ErrNotFound = errors.New("ha group not found")

// ErrVersionConflict 乐观锁冲突。
var ErrVersionConflict = errors.New("ha group version conflict")

// ErrNameConflict 组名冲突。
var ErrNameConflict = errors.New("ha group name conflict")

// Repository 仓储接口（*Store 与 *MemStore 实现）。
type Repository interface {
	List(ctx context.Context) ([]Group, error)
	Get(ctx context.Context, id string) (*Group, error)
	// Create 创建组（含成员；AuthCiphertext 为加密后的认证串，空串=未配置）。
	Create(ctx context.Context, g *Group, authCiphertext string) error
	// Update 整体更新（乐观锁；authCiphertext nil 表示不变更认证串）。
	Update(ctx context.Context, g *Group, authCiphertext *string) error
	// Delete 删除组（成员级联）。
	Delete(ctx context.Context, id string) error
}

// ---------- PostgreSQL ----------

// Store PostgreSQL 仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建仓储。
func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

const groupCols = `id, name, state, vrid, iface, vips, preempt, advert_int_ms, unicast, unicast_peers,
COALESCE(auth_ciphertext, ''), version, created_at, updated_at`

func scanGroup(row interface{ Scan(...any) error }) (*Group, error) {
	var g Group
	var vips, peers []byte
	var authCipher string
	var createdAt, updatedAt time.Time
	err := row.Scan(&g.ID, &g.Name, &g.State, &g.VRID, &g.Iface, &vips, &g.Preempt,
		&g.AdvertIntMs, &g.Unicast, &peers, &authCipher, &g.Version, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(vips, &g.VIPs); err != nil {
		return nil, fmt.Errorf("解析 vips: %w", err)
	}
	if err := json.Unmarshal(peers, &g.UnicastPeers); err != nil {
		return nil, fmt.Errorf("解析 unicast_peers: %w", err)
	}
	g.HasAuthPass = authCipher != ""
	g.CreatedAt = createdAt.UTC().Format(time.RFC3339)
	g.UpdatedAt = updatedAt.UTC().Format(time.RFC3339)
	return &g, nil
}

// List 全量组（名称升序，成员随组装配）。
func (s *Store) List(ctx context.Context) ([]Group, error) {
	rows, err := s.db.Query(ctx, `SELECT `+groupCols+` FROM ha_groups ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Group{}
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *g)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if err := s.loadMembers(ctx, &out[i]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Get 单组（含成员）。
func (s *Store) Get(ctx context.Context, id string) (*Group, error) {
	g, err := scanGroup(s.db.QueryRow(ctx, `SELECT `+groupCols+` FROM ha_groups WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := s.loadMembers(ctx, g); err != nil {
		return nil, err
	}
	return g, nil
}

// loadMembers 装配成员（priority 降序，主在前）。
func (s *Store) loadMembers(ctx context.Context, g *Group) error {
	rows, err := s.db.Query(ctx, `
SELECT m.node_id, n.node_name, m.priority FROM ha_group_members m
JOIN api_gateway_nodes n ON n.id = m.node_id
WHERE m.group_id=$1 ORDER BY m.priority DESC`, g.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	g.Members = []Member{}
	for rows.Next() {
		var m Member
		if err := rows.Scan(&m.NodeID, &m.NodeName, &m.Priority); err != nil {
			return err
		}
		g.Members = append(g.Members, m)
	}
	return rows.Err()
}

// Create 创建组（同事务写成员）。
func (s *Store) Create(ctx context.Context, g *Group, authCiphertext string) error {
	vips, _ := json.Marshal(g.VIPs)
	peers, _ := json.Marshal(g.UnicastPeers)
	var auth any
	if authCiphertext != "" {
		auth = authCiphertext
	}
	id := uuid.New()
	_, err := s.db.Exec(ctx, `
INSERT INTO ha_groups (id, name, state, vrid, iface, vips, preempt, advert_int_ms, unicast, unicast_peers, auth_ciphertext)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		id, g.Name, g.State, g.VRID, g.Iface, vips, g.Preempt, g.AdvertIntMs, g.Unicast, peers, auth)
	if isUniqueViolation(err) {
		return ErrNameConflict
	}
	if err != nil {
		return err
	}
	g.ID = id.String()
	return s.replaceMembers(ctx, id, g.Members)
}

// Update 整体更新（乐观锁 version；authCiphertext nil 不变更）。
func (s *Store) Update(ctx context.Context, g *Group, authCiphertext *string) error {
	vips, _ := json.Marshal(g.VIPs)
	peers, _ := json.Marshal(g.UnicastPeers)
	authExpr := `auth_ciphertext`
	args := []any{g.Name, g.State, g.VRID, g.Iface, vips, g.Preempt, g.AdvertIntMs, g.Unicast, peers, g.ID, g.Version}
	if authCiphertext != nil {
		authExpr = `$12`
		args = append(args, *authCiphertext)
	}
	tag, err := s.db.Exec(ctx, fmt.Sprintf(`
UPDATE ha_groups SET name=$1, state=$2, vrid=$3, iface=$4, vips=$5, preempt=$6,
    advert_int_ms=$7, unicast=$8, unicast_peers=$9, auth_ciphertext=%s, updated_at=now(), version=version+1
WHERE id=$10 AND version=$11`, authExpr), args...)
	if isUniqueViolation(err) {
		return ErrNameConflict
	}
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		// 版本冲突或不存在：区分报错语义
		if _, gerr := s.Get(ctx, g.ID); errors.Is(gerr, ErrNotFound) {
			return ErrNotFound
		}
		return ErrVersionConflict
	}
	uid, _ := uuid.Parse(g.ID)
	return s.replaceMembers(ctx, uid, g.Members)
}

// AuthCiphertext 取认证串密文（下发构造用）。
func (s *Store) AuthCiphertext(ctx context.Context, id string) (string, error) {
	var cipher string
	err := s.db.QueryRow(ctx, `SELECT COALESCE(auth_ciphertext,'') FROM ha_groups WHERE id=$1`, id).Scan(&cipher)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return cipher, err
}

// Delete 删除组（成员级联）。
func (s *Store) Delete(ctx context.Context, id string) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM ha_groups WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// replaceMembers 整体替换成员（先删后插；组内恰 2 行由 Validate 保证）。
func (s *Store) replaceMembers(ctx context.Context, groupID uuid.UUID, members []Member) error {
	if _, err := s.db.Exec(ctx, `DELETE FROM ha_group_members WHERE group_id=$1`, groupID); err != nil {
		return err
	}
	for _, m := range members {
		if _, err := s.db.Exec(ctx,
			`INSERT INTO ha_group_members (group_id, node_id, priority) VALUES ($1,$2,$3)`,
			groupID, m.NodeID, m.Priority); err != nil {
			return fmt.Errorf("写入成员: %w", err)
		}
	}
	return nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// ---------- 内存实现（测试） ----------

// MemStore 内存仓储。
type MemStore struct {
	mu     sync.Mutex
	groups map[string]*Group
	auths  map[string]string
}

// NewMemStore 创建内存仓储。
func NewMemStore() *MemStore {
	return &MemStore{groups: map[string]*Group{}, auths: map[string]string{}}
}

// List 实现 Repository。
func (m *MemStore) List(_ context.Context) ([]Group, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []Group{}
	for _, g := range m.groups {
		out = append(out, *cloneGroup(g))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Get 实现 Repository。
func (m *MemStore) Get(_ context.Context, id string) (*Group, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.groups[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneGroup(g), nil
}

// Create 实现 Repository。
func (m *MemStore) Create(_ context.Context, g *Group, authCiphertext string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, x := range m.groups {
		if x.Name == g.Name {
			return ErrNameConflict
		}
	}
	ng := cloneGroup(g)
	ng.ID = uuid.New().String()
	ng.Version = 1
	ng.HasAuthPass = authCiphertext != ""
	m.groups[ng.ID] = ng
	m.auths[ng.ID] = authCiphertext
	g.ID = ng.ID
	return nil
}

// Update 实现 Repository。
func (m *MemStore) Update(_ context.Context, g *Group, authCiphertext *string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	old, ok := m.groups[g.ID]
	if !ok {
		return ErrNotFound
	}
	if old.Version != g.Version {
		return ErrVersionConflict
	}
	for id, x := range m.groups {
		if id != g.ID && x.Name == g.Name {
			return ErrNameConflict
		}
	}
	ng := cloneGroup(g)
	ng.Version = old.Version + 1
	if authCiphertext != nil {
		m.auths[g.ID] = *authCiphertext
	}
	ng.HasAuthPass = m.auths[g.ID] != ""
	m.groups[g.ID] = ng
	return nil
}

// Delete 实现 Repository。
func (m *MemStore) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.groups[id]; !ok {
		return ErrNotFound
	}
	delete(m.groups, id)
	delete(m.auths, id)
	return nil
}

// AuthCiphertext 取认证串密文（下发构造用）。
func (m *MemStore) AuthCiphertext(_ context.Context, id string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.auths[id], nil
}

func cloneGroup(g *Group) *Group {
	ng := *g
	ng.VIPs = append([]string(nil), g.VIPs...)
	ng.UnicastPeers = append([]string(nil), g.UnicastPeers...)
	ng.Members = append([]Member(nil), g.Members...)
	return &ng
}
