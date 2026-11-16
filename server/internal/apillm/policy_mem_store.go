package apillm

import (
	"context"
	"encoding/json"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

type MemSecurityPolicyStore struct {
	mu       sync.Mutex
	policies map[uuid.UUID]SecurityPolicy
	versions map[uuid.UUID][]SecurityPolicyVersion
}

func NewMemSecurityPolicyStore() *MemSecurityPolicyStore {
	return &MemSecurityPolicyStore{policies: map[uuid.UUID]SecurityPolicy{}, versions: map[uuid.UUID][]SecurityPolicyVersion{}}
}

var _ SecurityPolicyRepository = (*MemSecurityPolicyStore)(nil)

func (m *MemSecurityPolicyStore) ListSecurityPolicies(context.Context) ([]SecurityPolicy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []SecurityPolicy{}
	for _, p := range m.policies {
		out = append(out, cloneSecurityPolicy(p))
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name || out[i].Name == out[j].Name && out[i].ID.String() < out[j].ID.String()
	})
	return out, nil
}

func (m *MemSecurityPolicyStore) GetSecurityPolicy(_ context.Context, id uuid.UUID) (*SecurityPolicy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.policies[id]
	if !ok {
		return nil, ErrSecurityPolicyNotFound
	}
	cp := cloneSecurityPolicy(p)
	return &cp, nil
}

func (m *MemSecurityPolicyStore) conflict(p *SecurityPolicy) bool {
	for _, existing := range m.policies {
		if existing.ApplicationID == p.ApplicationID && existing.ID != p.ID {
			return true
		}
	}
	return false
}

func (m *MemSecurityPolicyStore) recordVersion(p *SecurityPolicy) {
	raw, _ := json.Marshal(p)
	m.versions[p.ID] = append(m.versions[p.ID], SecurityPolicyVersion{
		ID: uuid.New(), PolicyID: p.ID, Version: p.Version, PolicySnapshot: raw,
		CreatedBy: p.UpdatedBy, CreatedAt: p.UpdatedAt,
	})
}

func (m *MemSecurityPolicyStore) CreateSecurityPolicy(_ context.Context, p *SecurityPolicy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.conflict(p) {
		return ErrSecurityPolicyConflict
	}
	now := time.Now().UTC()
	p.ID = uuid.New()
	p.Version = 1
	p.CreatedAt = now
	p.UpdatedAt = now
	m.policies[p.ID] = cloneSecurityPolicy(*p)
	m.recordVersion(p)
	return nil
}

func (m *MemSecurityPolicyStore) UpdateSecurityPolicy(_ context.Context, p *SecurityPolicy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	current, ok := m.policies[p.ID]
	if !ok {
		return ErrSecurityPolicyNotFound
	}
	if m.conflict(p) {
		return ErrSecurityPolicyConflict
	}
	p.CreatedAt = current.CreatedAt
	p.CreatedBy = current.CreatedBy
	p.Version = current.Version + 1
	p.UpdatedAt = time.Now().UTC()
	m.policies[p.ID] = cloneSecurityPolicy(*p)
	m.recordVersion(p)
	return nil
}

func (m *MemSecurityPolicyStore) DeleteSecurityPolicy(_ context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.policies[id]; !ok {
		return ErrSecurityPolicyNotFound
	}
	delete(m.policies, id)
	delete(m.versions, id)
	return nil
}

func (m *MemSecurityPolicyStore) ListSecurityPolicyVersions(_ context.Context, id uuid.UUID) ([]SecurityPolicyVersion, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	versions := append([]SecurityPolicyVersion(nil), m.versions[id]...)
	sort.Slice(versions, func(i, j int) bool { return versions[i].Version > versions[j].Version })
	return versions, nil
}

func (m *MemSecurityPolicyStore) ListEnabledSecurityPolicies(context.Context) ([]gatewayconfig.GuardLLMSecurityPolicy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []gatewayconfig.GuardLLMSecurityPolicy{}
	for _, p := range m.policies {
		if p.Enabled {
			out = append(out, p.GuardConfig())
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ApplicationID < out[j].ApplicationID })
	return out, nil
}
