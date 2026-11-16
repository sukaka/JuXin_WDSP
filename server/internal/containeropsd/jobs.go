// jobs.go 运维动作任务：异步执行、内存索引 + 共享目录（socket 同级 results/）持久化，
// 支持进程重启后按 job_id 查询历史结果。
package containeropsd

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

// 任务状态
const (
	JobAccepted = "ACCEPTED"
	JobRunning  = "RUNNING"
	JobSuccess  = "SUCCESS"
	JobFailed   = "FAILED"
)

// 支持的动作
const (
	ActionStart   = "start"
	ActionStop    = "stop"
	ActionRestart = "restart"
	ActionUpdate  = "update"
)

const (
	defaultMaxActiveJobs = 64
	defaultMaxStoredJobs = 1024
	jobWorkerCount       = 4
)

var (
	errJobQueueFull = errors.New("活动任务数已达上限")
	errJobStoreFull = errors.New("任务存储已满且没有可回收的历史任务")
)

// jobIDRe 校验任务 ID 格式（16 字节随机数 hex；杜绝路径穿越）。
var jobIDRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

// ActionJob 是一条运维动作任务记录（同时是 API 响应与 results/ 持久化文件格式）。
type ActionJob struct {
	JobID      string     `json:"job_id"`
	Service    string     `json:"service"`
	Action     string     `json:"action"`
	Status     string     `json:"status"`
	Message    string     `json:"message"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

// ValidJobID 校验任务 ID 格式。
func ValidJobID(id string) bool { return jobIDRe.MatchString(id) }

func cloneActionJob(job *ActionJob) *ActionJob {
	if job == nil {
		return nil
	}
	cloned := *job
	if job.StartedAt != nil {
		startedAt := *job.StartedAt
		cloned.StartedAt = &startedAt
	}
	if job.FinishedAt != nil {
		finishedAt := *job.FinishedAt
		cloned.FinishedAt = &finishedAt
	}
	return &cloned
}

// jobStore 任务存储：内存索引与最后一次成功落盘的状态一致，每次状态迁移原子落盘（tmp+rename）。
type jobStore struct {
	mu         sync.Mutex
	dir        string
	jobs       map[string]*ActionJob
	activeJobs map[string]struct{}
	maxActive  int
	maxJobs    int
	// svcLocks 按服务串行化动作（同一服务的 start/stop/update 不并发）
	svcLocks map[string]*sync.Mutex
}

// newJobStore 创建任务存储并加载 results/ 目录中的历史任务（损坏文件跳过）。
func newJobStore(dir string) (*jobStore, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("创建任务结果目录失败: %w", err)
	}
	s := &jobStore{
		dir:        dir,
		jobs:       map[string]*ActionJob{},
		activeJobs: map[string]struct{}{},
		maxActive:  defaultMaxActiveJobs,
		maxJobs:    defaultMaxStoredJobs,
		svcLocks:   map[string]*sync.Mutex{},
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("读取任务结果目录失败: %w", err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !jobIDRe.MatchString(name[:len(name)-len(filepath.Ext(name))]) || filepath.Ext(name) != ".json" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		var job ActionJob
		if json.Unmarshal(raw, &job) != nil || !ValidJobID(job.JobID) {
			continue
		}
		// 进程重启后遗留的 ACCEPTED/RUNNING 任务不会再被推进，标记为失败避免悬挂。
		if job.Status == JobAccepted || job.Status == JobRunning {
			next := cloneActionJob(&job)
			now := time.Now().UTC()
			next.Status = JobFailed
			next.Message = "sidecar 重启，任务中断"
			next.FinishedAt = &now
			if err := s.persist(next); err != nil {
				return nil, fmt.Errorf("持久化中断任务 %s 的失败状态失败: %w", job.JobID, err)
			}
			job = *next
		}
		s.jobs[job.JobID] = cloneActionJob(&job)
	}
	if err := s.pruneToLocked(s.maxJobs); err != nil {
		return nil, fmt.Errorf("回收历史任务失败: %w", err)
	}
	return s, nil
}

// create 新建 ACCEPTED 任务并落盘，同时为本任务预留一个活动任务名额。
func (s *jobStore) create(service, action string) (*ActionJob, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, fmt.Errorf("生成任务 ID 失败: %w", err)
	}
	job := &ActionJob{
		JobID:   hex.EncodeToString(raw[:]),
		Service: service,
		Action:  action,
		Status:  JobAccepted,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.activeJobs) >= s.maxActive {
		return nil, errJobQueueFull
	}
	if len(s.jobs) >= s.maxJobs {
		if err := s.pruneToLocked(s.maxJobs - 1); err != nil {
			return nil, err
		}
	}
	if err := s.persist(job); err != nil {
		return nil, fmt.Errorf("持久化新任务失败: %w", err)
	}
	s.jobs[job.JobID] = job
	s.activeJobs[job.JobID] = struct{}{}
	return cloneActionJob(job), nil
}

// transition 先持久化候选状态，再原子替换内存记录；失败时保留最后一份已持久化状态。
func (s *jobStore) transition(jobID, status, message string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.jobs[jobID]
	if !ok {
		return fmt.Errorf("任务 %s 不存在", jobID)
	}
	next := cloneActionJob(current)
	now := time.Now().UTC()
	next.Status = status
	if message != "" {
		next.Message = message
	}
	switch status {
	case JobRunning:
		next.StartedAt = &now
	case JobSuccess, JobFailed:
		next.FinishedAt = &now
		if next.StartedAt == nil {
			next.StartedAt = &now
		}
	}
	if err := s.persist(next); err != nil {
		return fmt.Errorf("持久化任务 %s 的 %s 状态失败: %w", jobID, status, err)
	}
	s.jobs[jobID] = next
	return nil
}

// done 释放活动任务名额；任务终态仍保留在 jobs 中供查询。
func (s *jobStore) done(jobID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.activeJobs, jobID)
}

// get 返回独立快照，调用方不得持有或改写存储内对象。
func (s *jobStore) get(id string) (*ActionJob, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.jobs[id]
	return cloneActionJob(job), ok
}

// lockFor 返回指定服务的互斥锁。
func (s *jobStore) lockFor(service string) *sync.Mutex {
	s.mu.Lock()
	defer s.mu.Unlock()
	mu, ok := s.svcLocks[service]
	if !ok {
		mu = &sync.Mutex{}
		s.svcLocks[service] = mu
	}
	return mu
}

// pruneToLocked 优先淘汰最早完成的终态任务；活动任务绝不淘汰。
func (s *jobStore) pruneToLocked(limit int) error {
	for len(s.jobs) > limit {
		oldestID := ""
		var oldestTime time.Time
		for id, job := range s.jobs {
			if job.Status != JobSuccess && job.Status != JobFailed {
				continue
			}
			completedAt := time.Time{}
			if job.FinishedAt != nil {
				completedAt = *job.FinishedAt
			} else if job.StartedAt != nil {
				completedAt = *job.StartedAt
			}
			if oldestID == "" || completedAt.Before(oldestTime) || completedAt.Equal(oldestTime) && id < oldestID {
				oldestID = id
				oldestTime = completedAt
			}
		}
		if oldestID == "" {
			return errJobStoreFull
		}
		if err := os.Remove(filepath.Join(s.dir, oldestID+".json")); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("删除历史任务 %s 失败: %w", oldestID, err)
		}
		delete(s.jobs, oldestID)
	}
	return nil
}

// persist 原子写入任务文件（调用方须持锁）。
func (s *jobStore) persist(job *ActionJob) error {
	payload, err := json.Marshal(job)
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	tmp, err := os.CreateTemp(s.dir, ".job-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	final := filepath.Join(s.dir, job.JobID+".json")
	if err := os.Chmod(tmpName, 0o640); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return os.Rename(tmpName, final)
}
