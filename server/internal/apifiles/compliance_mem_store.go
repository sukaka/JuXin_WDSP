// compliance_mem_store.go 文件合规规则内存仓储：与 SQL ComplianceStore 相同业务语义，
// 供包内单测与无库环境驱动真实 Handler。
package apifiles

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

// MemComplianceStore 进程内合规规则仓储（实现 ComplianceRepository）。
type MemComplianceStore struct {
	mu    sync.Mutex
	rules []ComplianceRule
}

// NewMemComplianceStore 创建空内存仓储。
func NewMemComplianceStore() *MemComplianceStore { return &MemComplianceStore{} }

// 确保 *MemComplianceStore 实现接口。
var _ ComplianceRepository = (*MemComplianceStore)(nil)

// matchCompliance 过滤判定（与 SQL WHERE 口径一致）。
func matchCompliance(r ComplianceRule, f ComplianceFilter) bool {
	if f.Direction != "" && r.Direction != f.Direction {
		return false
	}
	if f.MatchType != "" && r.MatchType != f.MatchType {
		return false
	}
	if f.Action != "" && r.Action != f.Action {
		return false
	}
	if f.Enabled != nil && r.Enabled != *f.Enabled {
		return false
	}
	return true
}

// dedupConflict 去重键冲突判定（direction+match_type+match_value，excludeID 用于更新自省）。
func (m *MemComplianceStore) dedupConflict(r *ComplianceRule, excludeID uuid.UUID) bool {
	for _, it := range m.rules {
		if it.ID == excludeID {
			continue
		}
		if it.Direction == r.Direction && it.MatchType == r.MatchType && it.MatchValue == r.MatchValue {
			return true
		}
	}
	return false
}

// ListComplianceRules 明细分页（内存镜像；created_at 倒序，与 SQL ORDER BY 口径一致）。
func (m *MemComplianceStore) ListComplianceRules(_ context.Context, f ComplianceFilter) ([]ComplianceRule, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if f.Page <= 0 {
		f.Page = 1
	}
	if f.PageSize <= 0 {
		f.PageSize = 20
	}
	matched := []ComplianceRule{}
	for _, r := range m.rules {
		if matchCompliance(r, f) {
			matched = append(matched, r)
		}
	}
	sort.Slice(matched, func(i, j int) bool {
		if matched[i].CreatedAt.Equal(matched[j].CreatedAt) {
			return matched[i].ID.String() > matched[j].ID.String()
		}
		return matched[i].CreatedAt.After(matched[j].CreatedAt)
	})
	total := int64(len(matched))
	start := (f.Page - 1) * f.PageSize
	if start >= len(matched) {
		return []ComplianceRule{}, total, nil
	}
	end := start + f.PageSize
	if end > len(matched) {
		end = len(matched)
	}
	return matched[start:end], total, nil
}

// GetComplianceRule 按 ID 取单条。
func (m *MemComplianceStore) GetComplianceRule(_ context.Context, id uuid.UUID) (*ComplianceRule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.rules {
		if r.ID == id {
			cp := r
			return &cp, nil
		}
	}
	return nil, ErrComplianceNotFound
}

// CreateComplianceRule 新建（内存生成 ID/时间戳；去重键冲突 ErrComplianceConflict）。
func (m *MemComplianceStore) CreateComplianceRule(_ context.Context, r *ComplianceRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dedupConflict(r, uuid.Nil) {
		return ErrComplianceConflict
	}
	now := time.Now().UTC()
	r.ID = uuid.New()
	r.CreatedAt = now
	r.UpdatedAt = now
	m.rules = append(m.rules, *r)
	return nil
}

// UpdateComplianceRule 整体更新（刷新 updated_at；冲突/未找到同 SQL 语义）。
func (m *MemComplianceStore) UpdateComplianceRule(_ context.Context, r *ComplianceRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, it := range m.rules {
		if it.ID == r.ID {
			if m.dedupConflict(r, r.ID) {
				return ErrComplianceConflict
			}
			r.CreatedAt = it.CreatedAt
			r.CreatedBy = it.CreatedBy
			r.UpdatedAt = time.Now().UTC()
			m.rules[i] = *r
			return nil
		}
	}
	return ErrComplianceNotFound
}

// DeleteComplianceRule 硬删除。
func (m *MemComplianceStore) DeleteComplianceRule(_ context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, r := range m.rules {
		if r.ID == id {
			m.rules = append(m.rules[:i], m.rules[i+1:]...)
			return nil
		}
	}
	return ErrComplianceNotFound
}
