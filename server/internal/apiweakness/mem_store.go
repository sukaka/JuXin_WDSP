// mem_store.go 进程内弱点仓储：与 SQL Store 相同业务语义，供单测与无库环境驱动真实 Handler/Sweeper。
package apiweakness

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

// MemStore 进程内弱点仓储。
type MemStore struct {
	mu           sync.Mutex
	byID         map[uuid.UUID]*Weakness
	actions      map[uuid.UUID][]WeaknessAction // weakness_id → 历史（追加序）
	endpointKeys map[uuid.UUID]string           // 测试预置：endpoint_id → endpoint_key
}

// NewMemStore 创建空内存仓储。
func NewMemStore() *MemStore {
	return &MemStore{
		byID:         map[uuid.UUID]*Weakness{},
		actions:      map[uuid.UUID][]WeaknessAction{},
		endpointKeys: map[uuid.UUID]string{},
	}
}

// SetEndpointKey 预置端点键（等价 SQL 的 LEFT JOIN api_endpoints 带出）。
func (m *MemStore) SetEndpointKey(endpointID uuid.UUID, key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.endpointKeys[endpointID] = key
}

// cloneWeakness 拷贝弱点（避免调用方持有内部指针）。
func cloneWeakness(w *Weakness) *Weakness {
	cp := *w
	if w.EndpointID != nil {
		id := *w.EndpointID
		cp.EndpointID = &id
	}
	if w.DueDate != nil {
		t := *w.DueDate
		cp.DueDate = &t
	}
	if w.FixedAt != nil {
		t := *w.FixedAt
		cp.FixedAt = &t
	}
	if w.RetestedAt != nil {
		t := *w.RetestedAt
		cp.RetestedAt = &t
	}
	if w.Evidence != nil {
		cp.Evidence = append(json.RawMessage(nil), w.Evidence...)
	}
	return &cp
}

// List 分页列表（过滤语义与 SQL List 一致；按 last_seen 倒序）。
func (m *MemStore) List(ctx context.Context, f ListFilter) ([]Weakness, int64, error) {
	_ = ctx
	if f.Page <= 0 {
		f.Page = 1
	}
	if f.PageSize <= 0 {
		f.PageSize = 20
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	matched := []Weakness{}
	for _, w := range m.byID {
		if f.Status != "" && w.Status != f.Status {
			continue
		}
		if f.Severity != "" && w.Severity != f.Severity {
			continue
		}
		if f.Category != "" && w.Category != f.Category {
			continue
		}
		if f.EndpointID != nil && (w.EndpointID == nil || *w.EndpointID != *f.EndpointID) {
			continue
		}
		matched = append(matched, *cloneWeakness(w))
	}
	sort.Slice(matched, func(i, j int) bool {
		if matched[i].LastSeen.Equal(matched[j].LastSeen) {
			return matched[i].ID.String() < matched[j].ID.String()
		}
		return matched[i].LastSeen.After(matched[j].LastSeen)
	})
	total := int64(len(matched))
	start := (f.Page - 1) * f.PageSize
	if start >= len(matched) {
		return []Weakness{}, total, nil
	}
	end := start + f.PageSize
	if end > len(matched) {
		end = len(matched)
	}
	return matched[start:end], total, nil
}

// GetByID 弱点详情（不存在返回 ErrNotFound）。
func (m *MemStore) GetByID(ctx context.Context, id uuid.UUID) (*Weakness, error) {
	_ = ctx
	m.mu.Lock()
	defer m.mu.Unlock()
	w, ok := m.byID[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneWeakness(w), nil
}

// ListActions 整改/复测历史分页（created_at 倒序）。
func (m *MemStore) ListActions(ctx context.Context, weaknessID uuid.UUID, page, pageSize int) ([]WeaknessAction, int64, error) {
	_ = ctx
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	history := append([]WeaknessAction(nil), m.actions[weaknessID]...)
	sort.Slice(history, func(i, j int) bool {
		if history[i].CreatedAt.Equal(history[j].CreatedAt) {
			return history[i].ID.String() > history[j].ID.String()
		}
		return history[i].CreatedAt.After(history[j].CreatedAt)
	})
	total := int64(len(history))
	start := (page - 1) * pageSize
	if start >= len(history) {
		return []WeaknessAction{}, total, nil
	}
	end := start + pageSize
	if end > len(history) {
		end = len(history)
	}
	return history[start:end], total, nil
}

// appendAction 追加动作历史（调用方须持锁）。
func (m *MemStore) appendAction(weaknessID uuid.UUID, action, actor, note string, now time.Time) {
	m.actions[weaknessID] = append(m.actions[weaknessID], WeaknessAction{
		ID: uuid.New(), WeaknessID: weaknessID, Action: action, Actor: actor, Note: note, CreatedAt: now,
	})
}

// Transition 生命周期流转（状态机校验 + 更新 + 动作历史；非法迁移返回 ErrInvalidTransition）。
func (m *MemStore) Transition(ctx context.Context, id uuid.UUID, action string, in TransitionInput) (*Weakness, error) {
	_ = ctx
	if in.Now.IsZero() {
		in.Now = time.Now().UTC()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	w, ok := m.byID[id]
	if !ok {
		return nil, ErrNotFound
	}
	to, ok := ResolveTransition(action, w.Status)
	if !ok {
		return nil, fmt.Errorf("%w: %s 状态不允许 %s", ErrInvalidTransition, w.Status, action)
	}
	w.Status = to
	w.UpdatedAt = in.Now
	switch action {
	case ActionAssign:
		w.Owner = in.Owner
		if in.DueDate != nil {
			t := *in.DueDate
			w.DueDate = &t
		} else {
			w.DueDate = nil
		}
	case ActionMarkFixed:
		w.FixedAt = &in.Now
	case ActionRetestPass, ActionRetestFail:
		w.RetestedAt = &in.Now
	}
	m.appendAction(id, action, in.Actor, in.Note, in.Now)
	return cloneWeakness(w), nil
}

// UpsertDerived 派生 upsert（语义与 SQL Store 一致：计数 +1、刷新证据、FIXED 回 REPRODUCED）。
func (m *MemStore) UpsertDerived(ctx context.Context, in DerivedInput) (UpsertResult, error) {
	_ = ctx
	if in.Now.IsZero() {
		in.Now = time.Now().UTC()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, w := range m.byID {
		if w.EndpointID == nil || *w.EndpointID != in.EndpointID || w.WeaknessCode != in.WeaknessCode {
			continue
		}
		w.TriggerCount++
		w.LastSeen = in.Now
		w.Evidence = append(json.RawMessage(nil), in.Evidence...)
		w.UpdatedAt = in.Now
		reproduced := w.Status == StatusFixed
		if reproduced {
			w.Status = StatusReproduced
			m.appendAction(w.ID, ActionReproduced, "system", "整改后再次被扫描命中", in.Now)
		}
		return UpsertResult{ID: w.ID, Reproduced: reproduced}, nil
	}
	id := uuid.New()
	endpointID := in.EndpointID
	m.byID[id] = &Weakness{
		ID: id, EndpointID: &endpointID, EndpointKey: m.endpointKeys[in.EndpointID],
		WeaknessCode: in.WeaknessCode, WeaknessName: in.WeaknessName, Category: in.Category,
		Severity: in.Severity, Status: StatusNew, Evidence: append(json.RawMessage(nil), in.Evidence...),
		FirstSeen: in.Now, LastSeen: in.Now, TriggerCount: 1, CreatedAt: in.Now, UpdatedAt: in.Now,
	}
	m.appendAction(id, ActionDerived, "system", "派生扫描发现", in.Now)
	return UpsertResult{ID: id, Inserted: true}, nil
}
