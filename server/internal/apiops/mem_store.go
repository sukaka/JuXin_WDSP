// mem_store.go Repository 内存实现（单测驱动真实 Handler/Sweeper，与 SQL 实现同语义）。
package apiops

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

// MemStore 内存仓储。
type MemStore struct {
	mu        sync.Mutex
	schedules map[uuid.UUID]*Schedule
	runs      map[uuid.UUID]*Run
}

// NewMemStore 创建。
func NewMemStore() *MemStore {
	return &MemStore{schedules: map[uuid.UUID]*Schedule{}, runs: map[uuid.UUID]*Run{}}
}

// cloneSchedule 复制计划（避免调用方持有内部指针）。
func cloneSchedule(s *Schedule) *Schedule {
	cp := *s
	if s.Config != nil {
		cp.Config = append(json.RawMessage(nil), s.Config...)
	}
	return &cp
}

// cloneRun 复制执行记录。
func cloneRun(r *Run) *Run {
	cp := *r
	if r.Report != nil {
		cp.Report = append(json.RawMessage(nil), r.Report...)
	}
	return &cp
}

func (m *MemStore) CreateSchedule(_ context.Context, s *Schedule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	now := time.Now().UTC()
	s.CreatedAt, s.UpdatedAt = now, now
	if len(s.Config) == 0 {
		s.Config = json.RawMessage(`{}`)
	}
	m.schedules[s.ID] = cloneSchedule(s)
	return nil
}

func (m *MemStore) GetSchedule(_ context.Context, id uuid.UUID) (*Schedule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.schedules[id]
	if !ok {
		return nil, ErrScheduleNotFound
	}
	return cloneSchedule(s), nil
}

func (m *MemStore) ListSchedules(_ context.Context, f ScheduleFilter) ([]Schedule, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var matched []Schedule
	for _, s := range m.schedules {
		if f.TaskType != "" && s.TaskType != f.TaskType {
			continue
		}
		if f.Enabled != nil && s.Enabled != *f.Enabled {
			continue
		}
		matched = append(matched, *cloneSchedule(s))
	}
	sort.Slice(matched, func(i, j int) bool { return matched[i].CreatedAt.After(matched[j].CreatedAt) })
	total := int64(len(matched))
	if f.Page < 1 {
		f.Page = 1
	}
	if f.PageSize <= 0 {
		f.PageSize = 20
	}
	start := (f.Page - 1) * f.PageSize
	if start >= len(matched) {
		return []Schedule{}, total, nil
	}
	end := start + f.PageSize
	if end > len(matched) {
		end = len(matched)
	}
	return matched[start:end], total, nil
}

func (m *MemStore) UpdateSchedule(_ context.Context, s *Schedule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.schedules[s.ID]
	if !ok {
		return ErrScheduleNotFound
	}
	cur.Name = s.Name
	cur.CronExpr = s.CronExpr
	cur.Config = normalizeConfig(s.Config)
	cur.NextRunAt = s.NextRunAt
	cur.UpdatedAt = time.Now().UTC()
	s.UpdatedAt = cur.UpdatedAt
	return nil
}

func (m *MemStore) DeleteSchedule(_ context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.schedules[id]; !ok {
		return ErrScheduleNotFound
	}
	delete(m.schedules, id)
	// 与 SQL 侧 ON DELETE CASCADE 同语义：级联删除执行记录
	for rid, r := range m.runs {
		if r.ScheduleID == id {
			delete(m.runs, rid)
		}
	}
	return nil
}

func (m *MemStore) SetScheduleEnabled(_ context.Context, id uuid.UUID, enabled bool, nextRunAt *time.Time) (*Schedule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.schedules[id]
	if !ok {
		return nil, ErrScheduleNotFound
	}
	cur.Enabled = enabled
	cur.NextRunAt = nextRunAt
	// 与 SQL 侧同语义：手动启用复位熔断状态（计数清零、清空熔断时间与原因）
	if enabled {
		cur.ConsecutiveFailures = 0
		cur.CircuitOpenedAt = nil
		cur.CircuitReason = ""
	}
	cur.UpdatedAt = time.Now().UTC()
	return cloneSchedule(cur), nil
}

func (m *MemStore) ListDueSchedules(_ context.Context, now time.Time, limit int) ([]Schedule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Schedule
	for _, s := range m.schedules {
		if !s.Enabled || s.NextRunAt == nil || s.NextRunAt.After(now) {
			continue
		}
		out = append(out, *cloneSchedule(s))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NextRunAt.Before(*out[j].NextRunAt) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *MemStore) UpdateNextRunAt(_ context.Context, id uuid.UUID, next *time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.schedules[id]
	if !ok {
		return ErrScheduleNotFound
	}
	cur.NextRunAt = next
	cur.UpdatedAt = time.Now().UTC()
	return nil
}

func (m *MemStore) UpdateScheduleRunState(_ context.Context, id uuid.UUID, lastRunAt time.Time, status, errMsg string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.schedules[id]
	if !ok {
		return ErrScheduleNotFound
	}
	cur.LastRunAt = &lastRunAt
	cur.LastStatus = status
	cur.LastError = errMsg
	cur.UpdatedAt = time.Now().UTC()
	return nil
}

// RecordRunOutcome 与 SQL 实现同语义（互斥锁内完成，等价单事务）：
// 轨迹回填 + 计数（成功清零/失败 +1）+ 达阈且启用中熔断（停用、清游标、记原因）。
func (m *MemStore) RecordRunOutcome(_ context.Context, id uuid.UUID, lastRunAt time.Time, status, errMsg string, threshold int) (*Schedule, bool, error) {
	if threshold < 1 {
		threshold = 1
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.schedules[id]
	if !ok {
		return nil, false, ErrScheduleNotFound
	}
	cur.LastRunAt = &lastRunAt
	cur.LastStatus = status
	cur.LastError = errMsg
	if status == RunStatusSuccess {
		cur.ConsecutiveFailures = 0
	} else {
		cur.ConsecutiveFailures++
	}
	cur.UpdatedAt = time.Now().UTC()
	circuitOpened := false
	if status != RunStatusSuccess && cur.ConsecutiveFailures >= threshold && cur.Enabled {
		now := time.Now().UTC()
		cur.Enabled = false
		cur.NextRunAt = nil
		cur.CircuitOpenedAt = &now
		cur.CircuitReason = truncRunes(fmt.Sprintf("连续失败 %d 次（阈值 %d），最近一次：%s", cur.ConsecutiveFailures, threshold, errMsg), 500)
		cur.UpdatedAt = now
		circuitOpened = true
	}
	return cloneSchedule(cur), circuitOpened, nil
}

func (m *MemStore) CreateRun(_ context.Context, r *Run) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r.ID == uuid.Nil {
		r.ID = uuid.New()
	}
	r.Status = RunStatusRunning
	r.CreatedAt = time.Now().UTC()
	m.runs[r.ID] = cloneRun(r)
	return nil
}

func (m *MemStore) FinishRun(_ context.Context, id uuid.UUID, status, summary string, report json.RawMessage, finishedAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.runs[id]
	if !ok || cur.Status != RunStatusRunning {
		return ErrRunNotFound
	}
	cur.Status = status
	cur.Summary = summary
	if len(report) == 0 {
		report = json.RawMessage(`{}`)
	}
	cur.Report = append(json.RawMessage(nil), report...)
	cur.FinishedAt = &finishedAt
	return nil
}

func (m *MemStore) HasRunningRun(_ context.Context, scheduleID uuid.UUID) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.runs {
		if r.ScheduleID == scheduleID && r.Status == RunStatusRunning {
			return true, nil
		}
	}
	return false, nil
}

func (m *MemStore) ListRuns(_ context.Context, scheduleID uuid.UUID, page, pageSize int) ([]Run, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var matched []Run
	for _, r := range m.runs {
		if r.ScheduleID == scheduleID {
			matched = append(matched, *cloneRun(r))
		}
	}
	sort.Slice(matched, func(i, j int) bool { return matched[i].StartedAt.After(matched[j].StartedAt) })
	total := int64(len(matched))
	if page < 1 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	start := (page - 1) * pageSize
	if start >= len(matched) {
		return []Run{}, total, nil
	}
	end := start + pageSize
	if end > len(matched) {
		end = len(matched)
	}
	return matched[start:end], total, nil
}

func (m *MemStore) GetRun(_ context.Context, id uuid.UUID) (*Run, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.runs[id]
	if !ok {
		return nil, ErrRunNotFound
	}
	return cloneRun(r), nil
}
