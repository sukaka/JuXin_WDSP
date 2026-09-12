// mem_store.go 内存站点发现仓储（单元测试用），与 *Store 共用 normalizeInput 与流转语义。
package sitediscovery

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// MemStore 是内存仓储（单元测试用）。
type MemStore struct {
	mu   sync.Mutex
	rows map[string]*Discovery // key: domain + "\x00" + ip + "\x00" + port
	byID map[uuid.UUID]*Discovery
}

// NewMemStore 创建内存仓储。
func NewMemStore() *MemStore {
	return &MemStore{rows: map[string]*Discovery{}, byID: map[uuid.UUID]*Discovery{}}
}

// 确保 *MemStore 实现 Repository。
var _ Repository = (*MemStore)(nil)

func memKey(domain, ip string, port int) string {
	return domain + "\x00" + ip + "\x00" + strconv.Itoa(port)
}

// Upsert 发现/命中 upsert（语义同 SQL 仓储：seen_count 累加，采集字段覆盖，人工字段不覆盖）。
func (m *MemStore) Upsert(_ context.Context, in DiscoveryInput) (*Discovery, error) {
	in, err := normalizeInput(in)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := memKey(in.Domain, in.IP, in.Port)
	if row, ok := m.rows[key]; ok {
		row.SeenCount += in.Hits
		row.ClientCount = in.ClientCount
		row.LastSeen = in.WindowEnd
		row.GatewayNode = in.Node
		row.UpdatedAt = time.Now().UTC()
		cp := *row
		return &cp, nil
	}
	now := time.Now().UTC()
	d := &Discovery{
		ID:          uuid.New(),
		Domain:      in.Domain,
		IP:          in.IP,
		Port:        in.Port,
		Protocol:    in.Protocol,
		SourceMode:  in.SourceMode,
		GatewayNode: in.Node,
		SeenCount:   in.Hits,
		ClientCount: in.ClientCount,
		FirstSeen:   in.WindowStart,
		LastSeen:    in.WindowEnd,
		Status:      StatusNew,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	m.rows[key] = d
	m.byID[d.ID] = d
	cp := *d
	return &cp, nil
}

// List 分页列表（过滤/排序语义同 SQL 仓储）。
func (m *MemStore) List(_ context.Context, f ListFilter) ([]Discovery, int64, error) {
	if f.Page <= 0 {
		f.Page = 1
	}
	if f.PageSize <= 0 || f.PageSize > 100 {
		f.PageSize = 20
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	kw := strings.ToLower(f.Keyword)
	var matched []*Discovery
	for _, row := range m.rows {
		if f.Status != "" && row.Status != f.Status {
			continue
		}
		if f.Protocol != "" && row.Protocol != f.Protocol {
			continue
		}
		if f.SourceMode != "" && row.SourceMode != f.SourceMode {
			continue
		}
		if kw != "" && !strings.Contains(strings.ToLower(row.Domain), kw) &&
			!strings.Contains(row.IP, f.Keyword) {
			continue
		}
		matched = append(matched, row)
	}
	sort.SliceStable(matched, func(i, j int) bool {
		if !matched[i].LastSeen.Equal(matched[j].LastSeen) {
			return matched[i].LastSeen.After(matched[j].LastSeen)
		}
		return matched[i].ID.String() < matched[j].ID.String()
	})
	total := int64(len(matched))
	start := (f.Page - 1) * f.PageSize
	if start >= len(matched) {
		return []Discovery{}, total, nil
	}
	end := start + f.PageSize
	if end > len(matched) {
		end = len(matched)
	}
	out := make([]Discovery, 0, end-start)
	for _, row := range matched[start:end] {
		out = append(out, *row)
	}
	return out, total, nil
}

// GetByID 查询；不存在返回 ErrNotFound。
func (m *MemStore) GetByID(_ context.Context, id uuid.UUID) (*Discovery, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	row, ok := m.byID[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *row
	return &cp, nil
}

// transition 状态流转（语义同 SQL 仓储的守卫式转移）。
func (m *MemStore) transition(_ context.Context, id uuid.UUID, operator, target string, allowed map[string]bool) (*Discovery, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	row, ok := m.byID[id]
	if !ok {
		return nil, ErrNotFound
	}
	if !allowed[row.Status] {
		return nil, ErrInvalidTransition
	}
	row.Status = target
	if target == StatusNew {
		row.ConfirmedBy = ""
		row.ConfirmedAt = nil
	} else {
		now := time.Now().UTC()
		row.ConfirmedBy = operator
		row.ConfirmedAt = &now
	}
	row.UpdatedAt = time.Now().UTC()
	cp := *row
	return &cp, nil
}

// Confirm 人工确认（NEW→CONFIRMED；已 CONFIRMED 幂等）。
func (m *MemStore) Confirm(ctx context.Context, id uuid.UUID, operator string) (*Discovery, error) {
	return m.transition(ctx, id, operator, StatusConfirmed, map[string]bool{StatusNew: true, StatusConfirmed: true})
}

// Ignore 人工忽略（NEW/CONFIRMED→IGNORED；已 IGNORED 幂等）。
func (m *MemStore) Ignore(ctx context.Context, id uuid.UUID, operator string) (*Discovery, error) {
	return m.transition(ctx, id, operator, StatusIgnored,
		map[string]bool{StatusNew: true, StatusConfirmed: true, StatusIgnored: true})
}

// Restore 恢复为新发现（CONFIRMED/IGNORED→NEW），清空处置字段。
func (m *MemStore) Restore(ctx context.Context, id uuid.UUID, operator string) (*Discovery, error) {
	return m.transition(ctx, id, operator, StatusNew, map[string]bool{StatusConfirmed: true, StatusIgnored: true})
}
