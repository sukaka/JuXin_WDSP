// 主备组仓储（PostgreSQL + 内存实现）。
package hagroups

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
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

// ErrNodeAlreadyInGroup 成员节点已归属其他主备组。
var ErrNodeAlreadyInGroup = errors.New("ha group member node already in another group")

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
	EventRepository
}

// ---------- PostgreSQL ----------

// Store PostgreSQL 仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建仓储。
func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

const groupCols = `id, name, state, vrid, iface, vips, preempt, advert_int_ms, unicast, unicast_peers,
track_interfaces, COALESCE(auth_ciphertext, ''), version, created_at, updated_at`

func marshalStringSlice(s []string) ([]byte, error) {
	if s == nil {
		s = []string{}
	}
	return json.Marshal(s)
}

func scanGroup(row interface{ Scan(...any) error }) (*Group, error) {
	var g Group
	var vips, peers, tracks []byte
	var authCipher string
	var createdAt, updatedAt time.Time
	err := row.Scan(&g.ID, &g.Name, &g.State, &g.VRID, &g.Iface, &vips, &g.Preempt,
		&g.AdvertIntMs, &g.Unicast, &peers, &tracks, &authCipher, &g.Version, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(vips, &g.VIPs); err != nil {
		return nil, fmt.Errorf("解析 vips: %w", err)
	}
	if g.VIPs == nil {
		g.VIPs = []string{}
	}
	if err := json.Unmarshal(peers, &g.UnicastPeers); err != nil {
		return nil, fmt.Errorf("解析 unicast_peers: %w", err)
	}
	if g.UnicastPeers == nil {
		g.UnicastPeers = []string{}
	}
	if len(tracks) > 0 {
		if err := json.Unmarshal(tracks, &g.TrackInterfaces); err != nil {
			return nil, fmt.Errorf("解析 track_interfaces: %w", err)
		}
	}
	if g.TrackInterfaces == nil {
		g.TrackInterfaces = []string{}
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

// Create 创建组（显式事务原子写主表与成员表，任一失败整体回滚）。
func (s *Store) Create(ctx context.Context, g *Group, authCiphertext string) error {
	vips, err := marshalStringSlice(g.VIPs)
	if err != nil {
		return fmt.Errorf("序列化 vips: %w", err)
	}
	peers, err := marshalStringSlice(g.UnicastPeers)
	if err != nil {
		return fmt.Errorf("序列化 unicast_peers: %w", err)
	}
	tracks, err := marshalStringSlice(g.TrackInterfaces)
	if err != nil {
		return fmt.Errorf("序列化 track_interfaces: %w", err)
	}
	var auth any
	if authCiphertext != "" {
		auth = authCiphertext
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("开启事务: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	id := uuid.New()
	_, err = tx.Exec(ctx, `
INSERT INTO ha_groups (id, name, state, vrid, iface, vips, preempt, advert_int_ms, unicast, unicast_peers, track_interfaces, auth_ciphertext)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		id, g.Name, g.State, g.VRID, g.Iface, vips, g.Preempt, g.AdvertIntMs, g.Unicast, peers, tracks, auth)
	if isUniqueViolation(err) {
		return ErrNameConflict
	}
	if err != nil {
		return err
	}
	if err := s.replaceMembersTx(ctx, tx, id, g.Members); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("提交事务: %w", err)
	}
	g.ID = id.String()
	return nil
}

// Update 整体更新（显式事务 + 乐观锁 version；authCiphertext nil 不变更）。
func (s *Store) Update(ctx context.Context, g *Group, authCiphertext *string) error {
	uid, err := uuid.Parse(g.ID)
	if err != nil {
		return ErrNotFound
	}
	vips, err := marshalStringSlice(g.VIPs)
	if err != nil {
		return fmt.Errorf("序列化 vips: %w", err)
	}
	peers, err := marshalStringSlice(g.UnicastPeers)
	if err != nil {
		return fmt.Errorf("序列化 unicast_peers: %w", err)
	}
	tracks, err := marshalStringSlice(g.TrackInterfaces)
	if err != nil {
		return fmt.Errorf("序列化 track_interfaces: %w", err)
	}
	authExpr := `auth_ciphertext`
	args := []any{g.Name, g.State, g.VRID, g.Iface, vips, g.Preempt, g.AdvertIntMs, g.Unicast, peers, tracks, g.ID, g.Version}
	if authCiphertext != nil {
		authExpr = `$13`
		var authVal any
		if *authCiphertext != "" {
			authVal = *authCiphertext
		}
		args = append(args, authVal)
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("开启事务: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(ctx, fmt.Sprintf(`
UPDATE ha_groups SET name=$1, state=$2, vrid=$3, iface=$4, vips=$5, preempt=$6,
    advert_int_ms=$7, unicast=$8, unicast_peers=$9, track_interfaces=$10, auth_ciphertext=%s, updated_at=now(), version=version+1
WHERE id=$11 AND version=$12`, authExpr), args...)
	if isUniqueViolation(err) {
		return ErrNameConflict
	}
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		// 版本冲突或不存在：在同事务内区分报错语义
		var exists int
		if gerr := tx.QueryRow(ctx, `SELECT 1 FROM ha_groups WHERE id=$1`, g.ID).Scan(&exists); errors.Is(gerr, pgx.ErrNoRows) {
			return ErrNotFound
		} else if gerr != nil {
			return gerr
		}
		return ErrVersionConflict
	}
	if err := s.replaceMembersTx(ctx, tx, uid, g.Members); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("提交事务: %w", err)
	}
	return nil
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

// replaceMembersTx 在给定事务内整体替换成员（先删后插；组内恰 2 行由 Validate 保证）。
func (s *Store) replaceMembersTx(ctx context.Context, tx pgx.Tx, groupID uuid.UUID, members []Member) error {
	if _, err := tx.Exec(ctx, `DELETE FROM ha_group_members WHERE group_id=$1`, groupID); err != nil {
		return err
	}
	for _, m := range members {
		if _, err := tx.Exec(ctx,
			`INSERT INTO ha_group_members (group_id, node_id, priority) VALUES ($1,$2,$3)`,
			groupID, m.NodeID, m.Priority); err != nil {
			if isNodeUniqueViolation(err) {
				return ErrNodeAlreadyInGroup
			}
			return fmt.Errorf("写入成员: %w", err)
		}
	}
	return nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func isNodeUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		return false
	}
	return pgErr.ConstraintName == "uq_ha_group_members_node_id" ||
		strings.Contains(pgErr.Detail, "(node_id)")
}

// ---------- 内存实现（测试） ----------

// MemStore 内存仓储。
type MemStore struct {
	mu          sync.Mutex
	groups      map[string]*Group
	auths       map[string]string
	events      []HaEvent
	nextEventID int64
}

// NewMemStore 创建内存仓储。
func NewMemStore() *MemStore {
	return &MemStore{
		groups: map[string]*Group{},
		auths:  map[string]string{},
		events: []HaEvent{},
	}
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
	if m.hasMemberConflictLocked("", g.Members) {
		return ErrNodeAlreadyInGroup
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
	if m.hasMemberConflictLocked(g.ID, g.Members) {
		return ErrNodeAlreadyInGroup
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

func (m *MemStore) hasMemberConflictLocked(excludeGroupID string, members []Member) bool {
	wanted := make(map[string]bool, len(members))
	for _, mem := range members {
		wanted[mem.NodeID] = true
	}
	for id, x := range m.groups {
		if id == excludeGroupID {
			continue
		}
		for _, xm := range x.Members {
			if wanted[xm.NodeID] {
				return true
			}
		}
	}
	return false
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
	if g.VIPs == nil {
		ng.VIPs = []string{}
	} else {
		ng.VIPs = append([]string{}, g.VIPs...)
	}
	if g.UnicastPeers == nil {
		ng.UnicastPeers = []string{}
	} else {
		ng.UnicastPeers = append([]string{}, g.UnicastPeers...)
	}
	if g.TrackInterfaces == nil {
		ng.TrackInterfaces = []string{}
	} else {
		ng.TrackInterfaces = append([]string{}, g.TrackInterfaces...)
	}
	if g.Members == nil {
		ng.Members = []Member{}
	} else {
		ng.Members = append([]Member{}, g.Members...)
	}
	return &ng
}
