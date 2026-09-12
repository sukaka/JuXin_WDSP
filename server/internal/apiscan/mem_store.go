// mem_store.go 进程内主动扫描仓储：与 SQL Store 相同业务语义，供单测驱动真实 Handler/Worker。
package apiscan

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

// MemStore 进程内主动扫描仓储。
type MemStore struct {
	mu       sync.Mutex
	targets  map[uuid.UUID]*Target
	authzs   map[uuid.UUID]*Authorization
	jobs     map[uuid.UUID]*Job
	findings map[uuid.UUID]*Finding
}

// NewMemStore 创建空内存仓储。
func NewMemStore() *MemStore {
	return &MemStore{
		targets:  map[uuid.UUID]*Target{},
		authzs:   map[uuid.UUID]*Authorization{},
		jobs:     map[uuid.UUID]*Job{},
		findings: map[uuid.UUID]*Finding{},
	}
}

// cloneTarget / cloneAuthorization / cloneJob / cloneFinding 拷贝记录（避免调用方持有内部指针）。
func cloneTarget(t *Target) *Target {
	cp := *t
	cp.AllowedPaths = append([]string(nil), t.AllowedPaths...)
	if t.CreatedBy != nil {
		id := *t.CreatedBy
		cp.CreatedBy = &id
	}
	return &cp
}

func cloneAuthorization(a *Authorization) *Authorization {
	cp := *a
	cp.Allowlist = append([]string(nil), a.Allowlist...)
	if a.TimeWindow.Start != nil {
		t := *a.TimeWindow.Start
		cp.TimeWindow.Start = &t
	}
	if a.TimeWindow.End != nil {
		t := *a.TimeWindow.End
		cp.TimeWindow.End = &t
	}
	if a.RevokedAt != nil {
		t := *a.RevokedAt
		cp.RevokedAt = &t
	}
	return &cp
}

func cloneJob(j *Job) *Job {
	cp := *j
	if j.StartedAt != nil {
		t := *j.StartedAt
		cp.StartedAt = &t
	}
	if j.FinishedAt != nil {
		t := *j.FinishedAt
		cp.FinishedAt = &t
	}
	if j.CreatedBy != nil {
		id := *j.CreatedBy
		cp.CreatedBy = &id
	}
	return &cp
}

func cloneFinding(f *Finding) *Finding {
	cp := *f
	if f.WeaknessID != nil {
		id := *f.WeaknessID
		cp.WeaknessID = &id
	}
	return &cp
}

// ---------- 目标 ----------

func (m *MemStore) CreateTarget(_ context.Context, t *Target) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	if t.Status == "" {
		t.Status = TargetStatusEnabled
	}
	now := time.Now().UTC()
	t.CreatedAt, t.UpdatedAt = now, now
	m.targets[t.ID] = cloneTarget(t)
	return nil
}

func (m *MemStore) UpdateTarget(_ context.Context, t *Target) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.targets[t.ID]
	if !ok {
		return ErrNotFound
	}
	cp := cloneTarget(t)
	cp.CreatedAt = cur.CreatedAt
	cp.UpdatedAt = time.Now().UTC()
	m.targets[t.ID] = cp
	return nil
}

func (m *MemStore) GetTarget(_ context.Context, id uuid.UUID) (*Target, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.targets[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneTarget(t), nil
}

func (m *MemStore) ListTargets(_ context.Context, applicationID *uuid.UUID, status string, page, pageSize int) ([]Target, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	all := []*Target{}
	for _, t := range m.targets {
		if applicationID != nil && t.ApplicationID != *applicationID {
			continue
		}
		if status != "" && t.Status != status {
			continue
		}
		all = append(all, t)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].CreatedAt.After(all[j].CreatedAt) })
	total := int64(len(all))
	out := []Target{}
	for _, t := range pageSlice(page, pageSize, len(all)) {
		out = append(out, *cloneTarget(all[t]))
	}
	return out, total, nil
}

// ---------- 授权 ----------

func (m *MemStore) CreateAuthorization(_ context.Context, a *Authorization) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	a.CreatedAt = time.Now().UTC()
	m.authzs[a.ID] = cloneAuthorization(a)
	return nil
}

func (m *MemStore) GetAuthorization(_ context.Context, id uuid.UUID) (*Authorization, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.authzs[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneAuthorization(a), nil
}

func (m *MemStore) ListAuthorizations(_ context.Context, targetID uuid.UUID, page, pageSize int) ([]Authorization, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	all := []*Authorization{}
	for _, a := range m.authzs {
		if a.TargetID == targetID {
			all = append(all, a)
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].CreatedAt.After(all[j].CreatedAt) })
	total := int64(len(all))
	out := []Authorization{}
	for _, i := range pageSlice(page, pageSize, len(all)) {
		out = append(out, *cloneAuthorization(all[i]))
	}
	return out, total, nil
}

func (m *MemStore) RevokeAuthorization(_ context.Context, id uuid.UUID, now time.Time) (*Authorization, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.authzs[id]
	if !ok {
		return nil, ErrNotFound
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if a.RevokedAt == nil {
		a.RevokedAt = &now
	}
	return cloneAuthorization(a), nil
}

// ---------- 任务 ----------

func (m *MemStore) CreateJob(_ context.Context, j *Job) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if j.ID == uuid.Nil {
		j.ID = uuid.New()
	}
	if j.Status == "" {
		j.Status = JobStatusPending
	}
	j.CreatedAt = time.Now().UTC()
	m.jobs[j.ID] = cloneJob(j)
	return nil
}

func (m *MemStore) GetJob(_ context.Context, id uuid.UUID) (*Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneJob(j), nil
}

func (m *MemStore) ListJobs(_ context.Context, f JobFilter) ([]Job, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	all := []*Job{}
	for _, j := range m.jobs {
		if f.TargetID != nil && j.TargetID != *f.TargetID {
			continue
		}
		if f.Status != "" && j.Status != f.Status {
			continue
		}
		all = append(all, j)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].CreatedAt.After(all[j].CreatedAt) })
	total := int64(len(all))
	out := []Job{}
	for _, i := range pageSlice(f.Page, f.PageSize, len(all)) {
		out = append(out, *cloneJob(all[i]))
	}
	return out, total, nil
}

func (m *MemStore) ClaimPendingJob(_ context.Context, now time.Time) (*Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	// 与 SQL 同语义：PENDING 按创建序，同目标无 RUNNING 任务才可取
	runningTargets := map[uuid.UUID]bool{}
	for _, j := range m.jobs {
		if j.Status == JobStatusRunning {
			runningTargets[j.TargetID] = true
		}
	}
	pending := []*Job{}
	for _, j := range m.jobs {
		if j.Status == JobStatusPending && !runningTargets[j.TargetID] {
			pending = append(pending, j)
		}
	}
	if len(pending) == 0 {
		return nil, nil
	}
	sort.Slice(pending, func(i, j int) bool { return pending[i].CreatedAt.Before(pending[j].CreatedAt) })
	j := pending[0]
	j.Status = JobStatusRunning
	j.StartedAt = &now
	return cloneJob(j), nil
}

func (m *MemStore) StartJob(_ context.Context, id uuid.UUID, now time.Time) (*Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[id]
	if !ok {
		return nil, ErrNotFound
	}
	if j.Status != JobStatusPending && j.Status != JobStatusPaused {
		return nil, ErrInvalidTransition
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	j.Status = JobStatusRunning
	j.StartedAt = &now
	return cloneJob(j), nil
}

func (m *MemStore) SaveJobProgress(_ context.Context, id uuid.UUID, p Progress) (*Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[id]
	if !ok {
		return nil, ErrNotFound
	}
	if j.Status == JobStatusRunning {
		j.Progress = p
	}
	return cloneJob(j), nil
}

func (m *MemStore) FinishJob(_ context.Context, id uuid.UUID, status string, p Progress, now time.Time) (*Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[id]
	if !ok {
		return nil, ErrNotFound
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if j.Status == JobStatusRunning {
		j.Status = status
		j.Progress = p
		j.FinishedAt = &now
	}
	return cloneJob(j), nil
}

func (m *MemStore) StopJob(_ context.Context, id uuid.UUID, now time.Time) (*Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[id]
	if !ok {
		return nil, ErrNotFound
	}
	if j.Terminal() {
		return nil, ErrInvalidTransition
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	j.Status = JobStatusStopped
	j.FinishedAt = &now
	return cloneJob(j), nil
}

func (m *MemStore) StopJobsByAuthorization(_ context.Context, authorizationID uuid.UUID, now time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var n int64
	for _, j := range m.jobs {
		if j.AuthorizationID == authorizationID && !j.Terminal() {
			j.Status = JobStatusStopped
			j.FinishedAt = &now
			n++
		}
	}
	return n, nil
}

// ---------- 发现 ----------

func (m *MemStore) CreateFinding(_ context.Context, f *Finding) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if f.ID == uuid.Nil {
		f.ID = uuid.New()
	}
	if f.Engine == "" {
		f.Engine = "builtin"
	}
	if f.Status == "" {
		f.Status = FindingStatusNew
	}
	f.CreatedAt = time.Now().UTC()
	m.findings[f.ID] = cloneFinding(f)
	return nil
}

func (m *MemStore) GetFinding(_ context.Context, id uuid.UUID) (*Finding, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.findings[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneFinding(f), nil
}

func (m *MemStore) ListFindings(_ context.Context, fl FindingFilter) ([]Finding, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	all := []*Finding{}
	for _, f := range m.findings {
		if fl.JobID != nil && f.JobID != *fl.JobID {
			continue
		}
		if fl.Status != "" && f.Status != fl.Status {
			continue
		}
		if fl.Severity != "" && f.Severity != fl.Severity {
			continue
		}
		if fl.Template != "" && f.Template != fl.Template {
			continue
		}
		all = append(all, f)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].CreatedAt.After(all[j].CreatedAt) })
	total := int64(len(all))
	out := []Finding{}
	for _, i := range pageSlice(fl.Page, fl.PageSize, len(all)) {
		out = append(out, *cloneFinding(all[i]))
	}
	return out, total, nil
}

func (m *MemStore) SetFindingStatus(_ context.Context, id uuid.UUID, status string, weaknessID *uuid.UUID) (*Finding, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.findings[id]
	if !ok {
		return nil, ErrNotFound
	}
	if f.Status != FindingStatusNew {
		return nil, ErrInvalidTransition
	}
	f.Status = status
	f.WeaknessID = weaknessID
	return cloneFinding(f), nil
}

// pageSlice 分页下标区间（1 基页码）。
func pageSlice(page, pageSize, total int) []int {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	start := (page - 1) * pageSize
	if start > total {
		start = total
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	idx := make([]int, 0, end-start)
	for i := start; i < end; i++ {
		idx = append(idx, i)
	}
	return idx
}
