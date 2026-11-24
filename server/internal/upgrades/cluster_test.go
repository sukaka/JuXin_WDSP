package upgrades

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
)

// ---------- 内存版 clusterRepo + jobNodeExecStore（全流程状态机与路由单测共用） ----------

type memClusterStore struct {
	mu    sync.Mutex
	pkgs  map[uuid.UUID]*Package
	jobs  map[uuid.UUID]*Job
	execs map[uuid.UUID][]*NodeExecution // keyed by jobID
}

func newMemClusterStore() *memClusterStore {
	return &memClusterStore{
		pkgs:  map[uuid.UUID]*Package{},
		jobs:  map[uuid.UUID]*Job{},
		execs: map[uuid.UUID][]*NodeExecution{},
	}
}

func (m *memClusterStore) addPkg(p *Package) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *p
	m.pkgs[p.ID] = &cp
}

func (m *memClusterStore) GetPackage(_ context.Context, id uuid.UUID) (*Package, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.pkgs[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *p
	return &cp, nil
}

func (m *memClusterStore) GetJob(_ context.Context, id uuid.UUID) (*Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *j
	return &cp, nil
}

func (m *memClusterStore) ListJobs(_ context.Context, status string, page, pageSize int) ([]Job, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Job
	for _, j := range m.jobs {
		if status != "" && j.Status != status {
			continue
		}
		out = append(out, *j)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RequestedAt.After(out[j].RequestedAt) })
	return out, int64(len(out)), nil
}

func (m *memClusterStore) HasActiveJob(_ context.Context) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, j := range m.jobs {
		if !TerminalStatus(j.Status) {
			return true, nil
		}
	}
	return false, nil
}

func (m *memClusterStore) CreateJobWithModeIfNoActive(_ context.Context, packageID uuid.UUID, requestedBy *uuid.UUID, requestID, clusterMode string) (*Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, j := range m.jobs {
		if !TerminalStatus(j.Status) {
			return nil, ErrActiveUpgrade
		}
	}
	now := time.Now().UTC()
	job := &Job{
		ID:          uuid.New(),
		PackageID:   &packageID,
		Status:      StatusPending,
		ClusterMode: clusterMode,
		RequestedBy: requestedBy,
		RequestedAt: now,
		RequestID:   requestID,
	}
	m.jobs[job.ID] = job
	cp := *job
	return &cp, nil
}

func (m *memClusterStore) CreateScheduledJobWithModeIfNoActive(_ context.Context, packageID uuid.UUID, requestedBy *uuid.UUID, requestID string, scheduledAt time.Time, clusterMode string) (*Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, j := range m.jobs {
		if !TerminalStatus(j.Status) {
			return nil, ErrActiveUpgrade
		}
	}
	at := scheduledAt.UTC()
	job := &Job{
		ID:          uuid.New(),
		PackageID:   &packageID,
		Status:      StatusScheduled,
		ClusterMode: clusterMode,
		RequestedBy: requestedBy,
		RequestedAt: time.Now().UTC(),
		ScheduledAt: &at,
		RequestID:   requestID,
	}
	m.jobs[job.ID] = job
	cp := *job
	return &cp, nil
}

func (m *memClusterStore) Transition(_ context.Context, id uuid.UUID, from, to string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[id]
	if !ok || j.Status != from || !CanTransition(from, to) {
		return ErrInvalidStatus
	}
	j.Status = to
	if j.StartedAt == nil && to != StatusPending {
		now := time.Now().UTC()
		j.StartedAt = &now
	}
	return nil
}

func (m *memClusterStore) SetPrecheck(_ context.Context, id uuid.UUID, items []CheckItem) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[id]
	if !ok {
		return ErrNotFound
	}
	b, _ := json.Marshal(items)
	j.Precheck = b
	return nil
}

func (m *memClusterStore) SetBackupJob(_ context.Context, id, backupJobID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if j, ok := m.jobs[id]; ok {
		j.BackupJobID = &backupJobID
	}
	return nil
}

func (m *memClusterStore) SetExecutorDeadline(_ context.Context, _ uuid.UUID, _ time.Time) error {
	return nil
}

func (m *memClusterStore) MarkFailed(_ context.Context, id uuid.UUID, code string, err error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[id]
	if !ok {
		return ErrNotFound
	}
	now := time.Now().UTC()
	j.Status = StatusFailed
	j.FailureCode = code
	j.FailureMessage = failMsg(err)
	j.FinishedAt = &now
	return nil
}

func (m *memClusterStore) MarkFinished(_ context.Context, id uuid.UUID, status string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[id]
	if !ok {
		return ErrNotFound
	}
	now := time.Now().UTC()
	j.Status = status
	j.FailureCode = ""
	j.FailureMessage = ""
	j.FinishedAt = &now
	return nil
}

func (m *memClusterStore) CreateNodeExecutions(_ context.Context, execs []NodeExecution) ([]NodeExecution, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	out := make([]NodeExecution, 0, len(execs))
	for _, e := range execs {
		cp := e
		if cp.ID == uuid.Nil {
			cp.ID = uuid.New()
		}
		if cp.Status == "" {
			cp.Status = NodeStatusPending
		}
		cp.CreatedAt = now
		cp.UpdatedAt = now
		stored := cp
		m.execs[cp.JobID] = append(m.execs[cp.JobID], &stored)
		out = append(out, cp)
	}
	return out, nil
}

func (m *memClusterStore) ListNodeExecutions(_ context.Context, jobID uuid.UUID) ([]NodeExecution, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rows := m.execs[jobID]
	out := make([]NodeExecution, 0, len(rows))
	for _, r := range rows {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	return out, nil
}

func (m *memClusterStore) ListNodeExecutionsByJobIDs(ctx context.Context, jobIDs []uuid.UUID) (map[uuid.UUID][]NodeExecution, error) {
	out := make(map[uuid.UUID][]NodeExecution)
	for _, id := range jobIDs {
		rows, _ := m.ListNodeExecutions(ctx, id)
		if len(rows) > 0 {
			out[id] = rows
		}
	}
	return out, nil
}

func (m *memClusterStore) GetNodeExecution(_ context.Context, jobID, nodeID uuid.UUID) (*NodeExecution, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.execs[jobID] {
		if r.NodeID != nil && *r.NodeID == nodeID {
			cp := *r
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

func (m *memClusterStore) UpdateNodeExecutionStatus(_ context.Context, id uuid.UUID, status, errorCode, errorMessage string, setStarted, setFinished bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	for _, rows := range m.execs {
		for _, r := range rows {
			if r.ID == id {
				r.Status = status
				r.ErrorCode = errorCode
				r.ErrorMessage = truncate(errorMessage, 500)
				if setStarted && r.StartedAt == nil {
					t := now
					r.StartedAt = &t
				}
				if setFinished {
					t := now
					r.FinishedAt = &t
				}
				r.UpdatedAt = now
				return nil
			}
		}
	}
	return ErrNotFound
}

func (m *memClusterStore) ResetNodeExecutionForRetry(_ context.Context, id uuid.UUID, initialStatus string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	for _, rows := range m.execs {
		for _, r := range rows {
			if r.ID == id {
				if r.Role != NodeRoleStandby || (r.Status != NodeStatusFailed && r.Status != NodeStatusSkipped) {
					return ErrInvalidStatus
				}
				r.Status = initialStatus
				r.ErrorCode = ""
				r.ErrorMessage = ""
				t := now
				r.StartedAt = &t
				r.FinishedAt = nil
				r.UpdatedAt = now
				return nil
			}
		}
	}
	return ErrNotFound
}

func (m *memClusterStore) MarkPrimaryNodeExecution(_ context.Context, jobID uuid.UUID, status, errorCode, errorMessage string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	for _, r := range m.execs[jobID] {
		if r.Role == NodeRolePrimary {
			r.Status = status
			r.ErrorCode = errorCode
			r.ErrorMessage = truncate(errorMessage, 500)
			if r.StartedAt == nil {
				t := now
				r.StartedAt = &t
			}
			if status == NodeStatusSuccess || status == NodeStatusFailed || status == NodeStatusSkipped {
				t := now
				r.FinishedAt = &t
			}
			r.UpdatedAt = now
		}
	}
	return nil
}

// ---------- 可编程 ClusterSyncClient 测试桩 ----------

type fakeClusterSyncClient struct {
	mu           sync.Mutex
	nodes        []ClusterNode
	splitBrain   bool
	splitErr     error
	healthFn     func(nodeID uuid.UUID) (*ClusterNodeHealth, error)
	uploadFn     func(nodeID uuid.UUID, filePath, fileName, sha256Hex string) error
	startFn      func(nodeID uuid.UUID, req ExecutorRequest) error
	pollFn       func(nodeID uuid.UUID, jobID string) (*ExecutorResult, bool, error)
	events       []string
	uploadedTo   []uuid.UUID
	startedReqs  map[uuid.UUID][]ExecutorRequest
}

func (f *fakeClusterSyncClient) record(ev string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, ev)
}

func (f *fakeClusterSyncClient) ListClusterNodes(_ context.Context) ([]ClusterNode, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]ClusterNode(nil), f.nodes...), nil
}

func (f *fakeClusterSyncClient) HasOpenSplitBrain(_ context.Context) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.splitBrain, f.splitErr
}

func (f *fakeClusterSyncClient) CheckNodeHealth(_ context.Context, nodeID uuid.UUID) (*ClusterNodeHealth, error) {
	f.mu.Lock()
	fn := f.healthFn
	f.mu.Unlock()
	if fn != nil {
		return fn(nodeID)
	}
	return &ClusterNodeHealth{Version: "1.12.0", CaddyReachable: true, HostctlReady: true, UpgradeReady: true}, nil
}

func (f *fakeClusterSyncClient) UploadPackage(_ context.Context, nodeID uuid.UUID, filePath, fileName, sha256Hex string) error {
	f.mu.Lock()
	f.uploadedTo = append(f.uploadedTo, nodeID)
	fn := f.uploadFn
	f.mu.Unlock()
	f.record("upload:" + nodeID.String())
	if fn != nil {
		return fn(nodeID, filePath, fileName, sha256Hex)
	}
	return nil
}

func (f *fakeClusterSyncClient) StartRemoteUpgrade(_ context.Context, nodeID uuid.UUID, req ExecutorRequest) error {
	f.mu.Lock()
	if f.startedReqs == nil {
		f.startedReqs = map[uuid.UUID][]ExecutorRequest{}
	}
	f.startedReqs[nodeID] = append(f.startedReqs[nodeID], req)
	fn := f.startFn
	f.mu.Unlock()
	f.record("start:" + nodeID.String())
	if fn != nil {
		return fn(nodeID, req)
	}
	return nil
}

func (f *fakeClusterSyncClient) PollRemoteResult(_ context.Context, nodeID uuid.UUID, jobID string) (*ExecutorResult, bool, error) {
	f.mu.Lock()
	fn := f.pollFn
	f.mu.Unlock()
	if fn != nil {
		return fn(nodeID, jobID)
	}
	return &ExecutorResult{JobID: jobID, Status: "SUCCESS", Stage: StatusVerifying, FinishedAt: time.Now().UTC()}, true, nil
}

func setupClusterTestPackage(t *testing.T, versionFrom, versionTo string) (string, *Package) {
	t.Helper()
	dir := t.TempDir()
	data := []byte("signed-cluster-upgrade-package-bytes")
	sum := sha256.Sum256(data)
	name := "jiuzhang-wdsp-update-full-" + versionTo + "-amd64.tar.gz"
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o640); err != nil {
		t.Fatal(err)
	}
	pkg := &Package{
		ID:          uuid.New(),
		FileName:    name,
		VersionFrom: versionFrom,
		VersionTo:   versionTo,
		FileHash:    hex.EncodeToString(sum[:]),
		FileSize:    int64(len(data)),
		Status:      PackageVerified,
		UploadedAt:  time.Now().UTC(),
	}
	return dir, pkg
}

func newClusterTestService(t *testing.T, pkgsDir string, repo *memClusterStore, client ClusterSyncClient) *Service {
	t.Helper()
	pre := &Prechecker{
		packagesDir:    pkgsDir,
		currentVersion: "1.12.0",
		artifactVerifier: func(string, *Package) error {
			return nil
		},
	}
	svc := &Service{
		prechecker:        pre,
		packagesDir:       pkgsDir,
		executorDir:       t.TempDir(),
		clusterStore:      repo,
		resStore:          repo,
		clusterClient:     client,
		localNodeName:     "gw-a",
		backupWait:        5 * time.Second,
		restoreWait:       5 * time.Second,
		executorWait:      5 * time.Second,
		standbyVerifyWait: 2 * time.Second,
		poll:              10 * time.Millisecond,
		nowFn:             time.Now,
		precheckLocalFn: func(_ context.Context, _ *Package) []CheckItem {
			return []CheckItem{{Name: "version_match", Result: CheckPass, Message: "ok"}}
		},
	}
	svc.startRun = func(id uuid.UUID) { svc.run(id) }
	return svc
}

// ---------- 测试用例 ----------

func TestNormalizeClusterMode(t *testing.T) {
	if got, err := NormalizeClusterMode(""); err != nil || got != ClusterModeLocal {
		t.Fatalf("empty => %q, %v", got, err)
	}
	if got, err := NormalizeClusterMode("ha_rolling"); err != nil || got != ClusterModeHARolling {
		t.Fatalf("ha_rolling => %q, %v", got, err)
	}
	if _, err := NormalizeClusterMode("UNKNOWN"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestPrecheckHARollingSplitBrainAndStandbyValidation(t *testing.T) {
	pkgsDir, pkg := setupClusterTestPackage(t, "1.12.0", "1.13.0")
	repo := newMemClusterStore()
	repo.addPkg(pkg)

	primaryID := uuid.New()
	standbyID := uuid.New()
	client := &fakeClusterSyncClient{
		nodes: []ClusterNode{
			{NodeID: primaryID, NodeName: "gw-a", SyncEnabled: true, SyncAgentAddr: "https://10.0.0.1:18443", ReportedVersion: "1.12.0"},
			{NodeID: standbyID, NodeName: "gw-b", SyncEnabled: true, SyncAgentAddr: "https://10.0.0.2:18443", ReportedVersion: "1.12.0"},
		},
	}
	svc := newClusterTestService(t, pkgsDir, repo, client)

	// 1. 脑裂状态必须阻断预检
	client.splitBrain = true
	items, err := svc.RunPrecheckWithMode(context.Background(), pkg.ID, ClusterModeHARolling)
	if err != nil {
		t.Fatalf("RunPrecheckWithMode: %v", err)
	}
	if !HasFail(items) || !hasSplitBrainFailure(items) {
		t.Fatalf("expected split-brain FAIL in precheck, got %+v", items)
	}

	// 2. 解除脑裂但备节点版本不匹配 -> FAIL
	client.splitBrain = false
	client.healthFn = func(uuid.UUID) (*ClusterNodeHealth, error) {
		return &ClusterNodeHealth{Node: "gw-b", Version: "1.11.0", CaddyReachable: true, UpgradeReady: true}, nil
	}
	items, err = svc.RunPrecheckWithMode(context.Background(), pkg.ID, ClusterModeHARolling)
	if err != nil || !HasFail(items) {
		t.Fatalf("expected version mismatch FAIL, got items=%+v err=%v", items, err)
	}

	// 3. 备节点 upgrade_ready=false -> FAIL
	client.healthFn = func(uuid.UUID) (*ClusterNodeHealth, error) {
		return &ClusterNodeHealth{Node: "gw-b", Version: "1.12.0", CaddyReachable: true, UpgradeReady: false}, nil
	}
	items, err = svc.RunPrecheckWithMode(context.Background(), pkg.ID, ClusterModeHARolling)
	if err != nil || !HasFail(items) {
		t.Fatalf("expected upgrade_ready=false FAIL, got items=%+v err=%v", items, err)
	}

	// 4. 全部正常 -> PASS
	client.healthFn = func(uuid.UUID) (*ClusterNodeHealth, error) {
		return &ClusterNodeHealth{Node: "gw-b", Version: "1.12.0", CaddyReachable: true, HostctlReady: true, UpgradeReady: true}, nil
	}
	items, err = svc.RunPrecheckWithMode(context.Background(), pkg.ID, ClusterModeHARolling)
	if err != nil || HasFail(items) {
		t.Fatalf("expected all PASS, got items=%+v err=%v", items, err)
	}
}

func TestHARollingUpgradeStandbyFirstThenPrimarySuccess(t *testing.T) {
	pkgsDir, pkg := setupClusterTestPackage(t, "1.12.0", "1.13.0")
	repo := newMemClusterStore()
	repo.addPkg(pkg)

	primaryID := uuid.New()
	standby1 := uuid.New()
	standby2 := uuid.New()

	var mu sync.Mutex
	upgraded := map[uuid.UUID]bool{}
	healthPollCount := map[uuid.UUID]int{}
	order := []string{}

	client := &fakeClusterSyncClient{
		nodes: []ClusterNode{
			{NodeID: primaryID, NodeName: "gw-a", SyncEnabled: true, SyncAgentAddr: "https://10.0.0.1:18443", ReportedVersion: "1.12.0"},
			{NodeID: standby2, NodeName: "gw-c", SyncEnabled: true, SyncAgentAddr: "https://10.0.0.3:18443", ReportedVersion: "1.12.0"},
			{NodeID: standby1, NodeName: "gw-b", SyncEnabled: true, SyncAgentAddr: "https://10.0.0.2:18443", ReportedVersion: "1.12.0"},
		},
	}
	client.healthFn = func(id uuid.UUID) (*ClusterNodeHealth, error) {
		mu.Lock()
		defer mu.Unlock()
		if !upgraded[id] {
			return &ClusterNodeHealth{Version: "1.12.0", CaddyReachable: true, HostctlReady: true, UpgradeReady: true}, nil
		}
		healthPollCount[id]++
		if healthPollCount[id] == 1 {
			// 首次健康轮询仍在旧版本，验证 VERIFYING 会等待切到目标版本
			return &ClusterNodeHealth{Version: "1.12.0", CaddyReachable: true, HostctlReady: true, UpgradeReady: true}, nil
		}
		return &ClusterNodeHealth{Version: "1.13.0", CaddyReachable: true, HostctlReady: true, UpgradeReady: true}, nil
	}
	client.pollFn = func(id uuid.UUID, jobID string) (*ExecutorResult, bool, error) {
		mu.Lock()
		upgraded[id] = true
		if id == standby1 {
			order = append(order, "standby:gw-b")
		} else if id == standby2 {
			order = append(order, "standby:gw-c")
		}
		mu.Unlock()
		return &ExecutorResult{JobID: jobID, Status: "SUCCESS", Stage: StatusVerifying, FinishedAt: time.Now().UTC()}, true, nil
	}

	svc := newClusterTestService(t, pkgsDir, repo, client)
	backupCount := 0
	svc.runBackupFn = func(_ context.Context, _ *Job) error {
		backupCount++
		mu.Lock()
		order = append(order, "backup")
		mu.Unlock()
		return nil
	}
	svc.runPrimaryFn = func(_ context.Context, _ *Job) error {
		mu.Lock()
		order = append(order, "primary:gw-a")
		mu.Unlock()
		return nil
	}

	job, err := svc.ExecuteWithMode(context.Background(), pkg.ID, uuid.New(), "req-ha-ok", ClusterModeHARolling)
	if err != nil {
		t.Fatalf("ExecuteWithMode: %v", err)
	}

	finalJob, err := repo.GetJob(context.Background(), job.ID)
	if err != nil || finalJob.Status != StatusSuccess || finalJob.ClusterMode != ClusterModeHARolling {
		t.Fatalf("unexpected final job: %+v err=%v", finalJob, err)
	}
	if backupCount != 1 {
		t.Fatalf("expected exactly 1 backup on primary, got %d", backupCount)
	}
	wantOrder := []string{"backup", "standby:gw-b", "standby:gw-c", "primary:gw-a"}
	if strings.Join(order, ",") != strings.Join(wantOrder, ",") {
		t.Fatalf("execution order = %v, want %v", order, wantOrder)
	}

	execs, err := repo.ListNodeExecutions(context.Background(), job.ID)
	if err != nil || len(execs) != 3 {
		t.Fatalf("expected 3 node executions, got %d (%v)", len(execs), err)
	}
	for i, want := range []struct {
		name string
		role string
		seq  int
	}{
		{"gw-b", NodeRoleStandby, 1},
		{"gw-c", NodeRoleStandby, 2},
		{"gw-a", NodeRolePrimary, 3},
	} {
		if execs[i].NodeName != want.name || execs[i].Role != want.role || execs[i].Seq != want.seq || execs[i].Status != NodeStatusSuccess {
			t.Fatalf("exec[%d] = %+v, want %+v SUCCESS", i, execs[i], want)
		}
		if execs[i].StartedAt == nil || execs[i].FinishedAt == nil {
			t.Fatalf("exec[%d] missing timestamps: %+v", i, execs[i])
		}
	}
}

func TestHARollingUpgradeStandbyFailureStopsBeforePrimary(t *testing.T) {
	pkgsDir, pkg := setupClusterTestPackage(t, "1.12.0", "1.13.0")
	repo := newMemClusterStore()
	repo.addPkg(pkg)

	standby1 := uuid.New()
	standby2 := uuid.New()
	client := &fakeClusterSyncClient{
		nodes: []ClusterNode{
			{NodeID: standby1, NodeName: "gw-b", SyncEnabled: true, SyncAgentAddr: "https://10.0.0.2:18443", ReportedVersion: "1.12.0"},
			{NodeID: standby2, NodeName: "gw-c", SyncEnabled: true, SyncAgentAddr: "https://10.0.0.3:18443", ReportedVersion: "1.12.0"},
		},
		pollFn: func(nodeID uuid.UUID, jobID string) (*ExecutorResult, bool, error) {
			return &ExecutorResult{
				JobID:      jobID,
				Status:     "FAILED",
				Stage:      StatusApplying,
				ErrorCode:  "IMAGE_VERIFY_FAILED",
				Message:    "备机镜像校验失败",
				FinishedAt: time.Now().UTC(),
			}, true, nil
		},
	}

	var alerts []string
	primaryTouched := false
	svc := newClusterTestService(t, pkgsDir, repo, client)
	svc.alertFn = func(alertType, _, _, _ string) {
		alerts = append(alerts, alertType)
	}
	svc.runBackupFn = func(_ context.Context, _ *Job) error { return nil }
	svc.runPrimaryFn = func(_ context.Context, _ *Job) error {
		primaryTouched = true
		return nil
	}

	job, err := svc.ExecuteWithMode(context.Background(), pkg.ID, uuid.New(), "req-ha-fail", ClusterModeHARolling)
	if err != nil {
		t.Fatalf("ExecuteWithMode: %v", err)
	}
	if primaryTouched {
		t.Fatal("SAFETY VIOLATION: primary upgrade MUST NOT run after standby failure")
	}

	finalJob, _ := repo.GetJob(context.Background(), job.ID)
	if finalJob.Status != StatusFailed || finalJob.FailureCode != FailStandbyUpgrade {
		t.Fatalf("expected FAILED/%s, got %s/%s", FailStandbyUpgrade, finalJob.Status, finalJob.FailureCode)
	}
	if len(alerts) == 0 || alerts[0] != "UPGRADE_FAILED" {
		t.Fatalf("expected UPGRADE_FAILED alert, got %v", alerts)
	}

	execs, _ := repo.ListNodeExecutions(context.Background(), job.ID)
	if len(execs) != 3 {
		t.Fatalf("expected 3 node executions, got %d", len(execs))
	}
	if execs[0].Status != NodeStatusFailed || execs[0].ErrorCode != "IMAGE_VERIFY_FAILED" {
		t.Fatalf("gw-b expected FAILED/IMAGE_VERIFY_FAILED, got %+v", execs[0])
	}
	if execs[1].Status != NodeStatusSkipped || execs[2].Status != NodeStatusSkipped {
		t.Fatalf("gw-c and primary expected SKIPPED, got gw-c=%s primary=%s", execs[1].Status, execs[2].Status)
	}
	if len(client.uploadedTo) != 1 || client.uploadedTo[0] != standby1 {
		t.Fatalf("gw-c should never have received upload after gw-b failed, uploadedTo=%v", client.uploadedTo)
	}
}

func TestHARollingSplitBrainAbortsBeforeBackupAndPrimary(t *testing.T) {
	pkgsDir, pkg := setupClusterTestPackage(t, "1.12.0", "1.13.0")
	repo := newMemClusterStore()
	repo.addPkg(pkg)

	client := &fakeClusterSyncClient{
		splitBrain: true,
		nodes: []ClusterNode{
			{NodeID: uuid.New(), NodeName: "gw-b", SyncEnabled: true, SyncAgentAddr: "https://10.0.0.2:18443", ReportedVersion: "1.12.0"},
		},
	}
	backupRan := false
	primaryRan := false
	svc := newClusterTestService(t, pkgsDir, repo, client)
	svc.runBackupFn = func(context.Context, *Job) error { backupRan = true; return nil }
	svc.runPrimaryFn = func(context.Context, *Job) error { primaryRan = true; return nil }

	job, err := svc.ExecuteWithMode(context.Background(), pkg.ID, uuid.New(), "req-sb", ClusterModeHARolling)
	if err != nil {
		t.Fatalf("ExecuteWithMode: %v", err)
	}
	finalJob, _ := repo.GetJob(context.Background(), job.ID)
	if finalJob.Status != StatusFailed || finalJob.FailureCode != FailClusterSplitBrain {
		t.Fatalf("expected FAILED/%s, got %s/%s", FailClusterSplitBrain, finalJob.Status, finalJob.FailureCode)
	}
	if backupRan || primaryRan {
		t.Fatalf("expected split-brain to block before backup/primary (backup=%v primary=%v)", backupRan, primaryRan)
	}
}

func TestRetryNodeUpgradeAndGuards(t *testing.T) {
	pkgsDir, pkg := setupClusterTestPackage(t, "1.12.0", "1.13.0")
	repo := newMemClusterStore()
	repo.addPkg(pkg)

	primaryID := uuid.New()
	standbyID := uuid.New()
	jobID := uuid.New()
	reqBy := uuid.New()

	repo.jobs[jobID] = &Job{
		ID:          jobID,
		PackageID:   &pkg.ID,
		Status:      StatusFailed,
		ClusterMode: ClusterModeHARolling,
		FailureCode: FailStandbyUpgrade,
		RequestedBy: &reqBy,
		RequestedAt: time.Now().UTC(),
	}
	_, _ = repo.CreateNodeExecutions(context.Background(), []NodeExecution{
		{JobID: jobID, NodeID: &standbyID, NodeName: "gw-b", Role: NodeRoleStandby, Seq: 1, Status: NodeStatusFailed, FromVersion: "1.12.0", ToVersion: "1.13.0", ErrorCode: "APPLY_FAILED"},
		{JobID: jobID, NodeID: &primaryID, NodeName: "gw-a", Role: NodeRolePrimary, Seq: 2, Status: NodeStatusSkipped, FromVersion: "1.12.0", ToVersion: "1.13.0"},
	})

	client := &fakeClusterSyncClient{
		healthFn: func(uuid.UUID) (*ClusterNodeHealth, error) {
			return &ClusterNodeHealth{Node: "gw-b", Version: "1.13.0", CaddyReachable: true, HostctlReady: true, UpgradeReady: true}, nil
		},
	}
	svc := newClusterTestService(t, pkgsDir, repo, client)
	svc.startRetryNode = func(fn func()) { fn() } // 同步执行便于断言终态

	var auditActions []string
	svc.auditFn = func(_ context.Context, in audits.RecordInput) error {
		auditActions = append(auditActions, in.Action+":"+in.Result)
		return nil
	}

	// 1. 不允许重试 PRIMARY 节点
	if _, err := svc.RetryNodeUpgrade(context.Background(), jobID, primaryID, reqBy, "req-1"); !errors.Is(err, ErrInvalidStatus) {
		t.Fatalf("retry PRIMARY expected ErrInvalidStatus, got %v", err)
	}

	// 2. 脑裂期间拒绝重试
	client.splitBrain = true
	if _, err := svc.RetryNodeUpgrade(context.Background(), jobID, standbyID, reqBy, "req-2"); !errors.Is(err, ErrClusterSplitBrain) {
		t.Fatalf("retry during split-brain expected ErrClusterSplitBrain, got %v", err)
	}
	client.splitBrain = false

	// 3. 合法重试 FAILED 备节点 -> 使用全新远端执行 ID 并转为 SUCCESS
	row, err := svc.RetryNodeUpgrade(context.Background(), jobID, standbyID, reqBy, "req-3")
	if err != nil {
		t.Fatalf("RetryNodeUpgrade failed: %v", err)
	}
	if row.Status != NodeStatusTransferring {
		t.Fatalf("immediate returned status = %s, want TRANSFERRING", row.Status)
	}
	after, err := repo.GetNodeExecution(context.Background(), jobID, standbyID)
	if err != nil || after.Status != NodeStatusSuccess {
		t.Fatalf("after retry expected SUCCESS, got %+v err=%v", after, err)
	}
	if reqs := client.startedReqs[standbyID]; len(reqs) != 1 || reqs[0].JobID == jobID.String() {
		t.Fatalf("retry must use fresh remote executor job_id (not %s), got %+v", jobID, reqs)
	}
	if len(auditActions) != 1 || auditActions[0] != "retry_node_result:SUCCESS" {
		t.Fatalf("unexpected retry audit actions: %v", auditActions)
	}

	// 4. 已 SUCCESS 的节点不允许重复重试
	if _, err := svc.RetryNodeUpgrade(context.Background(), jobID, standbyID, reqBy, "req-4"); !errors.Is(err, ErrInvalidStatus) {
		t.Fatalf("retry SUCCESS node expected ErrInvalidStatus, got %v", err)
	}
}

func TestListClusterNodeStatuses(t *testing.T) {
	pkgsDir, _ := setupClusterTestPackage(t, "1.12.0", "1.13.0")
	repo := newMemClusterStore()
	primaryID := uuid.New()
	standbyID := uuid.New()
	client := &fakeClusterSyncClient{
		nodes: []ClusterNode{
			{NodeID: standbyID, NodeName: "gw-b", SyncEnabled: true, SyncAgentAddr: "https://10.0.0.2:18443", ReportedVersion: "1.12.0"},
			{NodeID: primaryID, NodeName: "gw-a", SyncEnabled: true, SyncAgentAddr: "https://10.0.0.1:18443", ReportedVersion: "1.12.0"},
		},
		healthFn: func(uuid.UUID) (*ClusterNodeHealth, error) {
			return &ClusterNodeHealth{Node: "gw-b", Version: "1.12.0", CaddyReachable: true, HostctlReady: true, UpgradeReady: true}, nil
		},
	}
	svc := newClusterTestService(t, pkgsDir, repo, client)

	res, err := svc.ListClusterNodeStatuses(context.Background())
	if err != nil {
		t.Fatalf("ListClusterNodeStatuses: %v", err)
	}
	if !res.ClusterReady || res.SplitBrain || res.CurrentVersion != "1.12.0" || len(res.Items) != 2 {
		t.Fatalf("unexpected cluster nodes response: %+v", res)
	}
	if res.Items[0].Role != NodeRolePrimary || res.Items[1].Role != NodeRoleStandby || !res.Items[1].VersionAligned {
		t.Fatalf("expected PRIMARY first and STANDBY aligned, got %+v", res.Items)
	}

	// 备机不可达时 cluster_ready=false
	client.healthFn = func(uuid.UUID) (*ClusterNodeHealth, error) { return nil, errors.New("connection refused") }
	res2, err := svc.ListClusterNodeStatuses(context.Background())
	if err != nil || res2.ClusterReady || res2.Items[1].Reachable || res2.Items[1].Error == "" {
		t.Fatalf("expected unreachable standby => cluster_ready=false, got %+v err=%v", res2, err)
	}
}

func TestClusterUpgradeHTTPHandlersAndRoutes(t *testing.T) {
	pkgsDir, pkg := setupClusterTestPackage(t, "1.12.0", "1.13.0")
	repo := newMemClusterStore()
	repo.addPkg(pkg)

	primaryID := uuid.New()
	standbyID := uuid.New()
	client := &fakeClusterSyncClient{
		nodes: []ClusterNode{
			{NodeID: primaryID, NodeName: "gw-a", SyncEnabled: true, SyncAgentAddr: "https://10.0.0.1:18443", ReportedVersion: "1.12.0"},
			{NodeID: standbyID, NodeName: "gw-b", SyncEnabled: true, SyncAgentAddr: "https://10.0.0.2:18443", ReportedVersion: "1.12.0"},
		},
		healthFn: func(uuid.UUID) (*ClusterNodeHealth, error) {
			return &ClusterNodeHealth{Node: "gw-b", Version: "1.12.0", CaddyReachable: true, HostctlReady: true, UpgradeReady: true}, nil
		},
	}
	svc := newClusterTestService(t, pkgsDir, repo, client)
	svc.startRun = func(uuid.UUID) {} // Execute 接口测试不跑后台 goroutine
	svc.startRetryNode = func(fn func()) { fn() }

	h := NewHandler(nil, svc, audits.NewService(nil))
	h.jobReader = repo
	h.SetAuditRecorder(func(*http.Request, *authz.Principal, string, string, string, string, string, string) {})

	mux := http.NewServeMux()
	authMW := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			perms := map[string]bool{"upgrades.read": true, "upgrades.precheck": true, "upgrades.execute": true}
			if r.Header.Get("X-Test-No-Perms") == "1" {
				perms = map[string]bool{}
			}
			p := &authz.Principal{
				UserID:   uuid.New(),
				Username: "admin",
				PermsSet: perms,
			}
			next.ServeHTTP(w, r.WithContext(authz.WithPrincipal(r.Context(), p)))
		})
	}
	h.RegisterRoutes(mux, authMW)

	// 0. 无权限请求被 403 拦截
	noPermReq := httptest.NewRequest(http.MethodGet, "/api/v1/upgrades/nodes", nil)
	noPermReq.Header.Set("X-Test-No-Perms", "1")
	rec403 := httptest.NewRecorder()
	mux.ServeHTTP(rec403, noPermReq)
	if rec403.Code != http.StatusForbidden {
		t.Fatalf("GET /api/v1/upgrades/nodes without perm expected 403, got %d", rec403.Code)
	}

	// 1. GET /api/v1/upgrades/nodes（验证固定路由优先于 /upgrades/{id}）
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/upgrades/nodes", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/upgrades/nodes status=%d body=%s", rec.Code, rec.Body.String())
	}
	var nodesEnv struct {
		Data ClusterNodesResponse `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &nodesEnv); err != nil {
		t.Fatal(err)
	}
	if !nodesEnv.Data.ClusterReady || len(nodesEnv.Data.Items) != 2 {
		t.Fatalf("unexpected nodes data: %+v", nodesEnv.Data)
	}

	// 2. POST /api/v1/upgrades/precheck with HA_ROLLING
	preBody := `{"package_id":"` + pkg.ID.String() + `","cluster_mode":"HA_ROLLING"}`
	recPre := httptest.NewRecorder()
	mux.ServeHTTP(recPre, httptest.NewRequest(http.MethodPost, "/api/v1/upgrades/precheck", strings.NewReader(preBody)))
	if recPre.Code != http.StatusOK || !strings.Contains(recPre.Body.String(), `"cluster_mode":"HA_ROLLING"`) {
		t.Fatalf("POST precheck HA_ROLLING status=%d body=%s", recPre.Code, recPre.Body.String())
	}

	// 3. POST /api/v1/upgrades with HA_ROLLING & invalid cluster_mode
	recBadMode := httptest.NewRecorder()
	mux.ServeHTTP(recBadMode, httptest.NewRequest(http.MethodPost, "/api/v1/upgrades",
		strings.NewReader(`{"package_id":"`+pkg.ID.String()+`","cluster_mode":"BOGUS"}`)))
	if recBadMode.Code != http.StatusBadRequest {
		t.Fatalf("invalid cluster_mode expected 400, got %d", recBadMode.Code)
	}

	recExec := httptest.NewRecorder()
	mux.ServeHTTP(recExec, httptest.NewRequest(http.MethodPost, "/api/v1/upgrades",
		strings.NewReader(`{"package_id":"`+pkg.ID.String()+`","cluster_mode":"HA_ROLLING"}`)))
	if recExec.Code != http.StatusOK {
		t.Fatalf("POST execute HA_ROLLING status=%d body=%s", recExec.Code, recExec.Body.String())
	}
	var execEnv struct {
		Data struct {
			Job Job `json:"job"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recExec.Body.Bytes(), &execEnv); err != nil {
		t.Fatal(err)
	}
	jobID := execEnv.Data.Job.ID
	if execEnv.Data.Job.ClusterMode != ClusterModeHARolling {
		t.Fatalf("expected cluster_mode HA_ROLLING, got %q", execEnv.Data.Job.ClusterMode)
	}

	// 模拟任务终态失败且备节点失败，测试 GET 附带 node_executions 与 POST retry-node
	_ = repo.MarkFailed(context.Background(), jobID, FailStandbyUpgrade, errors.New("boom"))
	_, _ = repo.CreateNodeExecutions(context.Background(), []NodeExecution{
		{JobID: jobID, NodeID: &standbyID, NodeName: "gw-b", Role: NodeRoleStandby, Seq: 1, Status: NodeStatusFailed, FromVersion: "1.12.0", ToVersion: "1.13.0"},
	})

	recGet := httptest.NewRecorder()
	mux.ServeHTTP(recGet, httptest.NewRequest(http.MethodGet, "/api/v1/upgrades/"+jobID.String(), nil))
	if recGet.Code != http.StatusOK || !strings.Contains(recGet.Body.String(), `"node_executions"`) {
		t.Fatalf("GET job expected node_executions, status=%d body=%s", recGet.Code, recGet.Body.String())
	}

	recList := httptest.NewRecorder()
	mux.ServeHTTP(recList, httptest.NewRequest(http.MethodGet, "/api/v1/upgrades", nil))
	if recList.Code != http.StatusOK || !strings.Contains(recList.Body.String(), `"node_executions"`) {
		t.Fatalf("LIST jobs expected node_executions, status=%d body=%s", recList.Code, recList.Body.String())
	}

	// 4. POST /api/v1/upgrades/{id}/retry-node
	client.healthFn = func(uuid.UUID) (*ClusterNodeHealth, error) {
		return &ClusterNodeHealth{Node: "gw-b", Version: "1.13.0", CaddyReachable: true, HostctlReady: true, UpgradeReady: true}, nil
	}
	retryReq := httptest.NewRequest(http.MethodPost, "/api/v1/upgrades/"+jobID.String()+"/retry-node",
		bytes.NewBufferString(`{"node_id":"`+standbyID.String()+`"}`))
	recRetry := httptest.NewRecorder()
	mux.ServeHTTP(recRetry, retryReq)
	if recRetry.Code != http.StatusOK || !strings.Contains(recRetry.Body.String(), `"node_execution"`) {
		t.Fatalf("POST retry-node status=%d body=%s", recRetry.Code, recRetry.Body.String())
	}

	// 5. 上传表单携带非法 cluster_mode 应返回 400
	content, pub, _ := embeddedPackageBytes(t, "2.0.0", "2.1.0", 0)
	hUp, _, _, _ := newUploadTestHandler(t, pub)
	code, _, _ := serveUpload(t, hUp, buildUploadRequest(t, "pkg.tar.gz", content, map[string]string{"cluster_mode": "BAD"}))
	if code != http.StatusBadRequest {
		t.Fatalf("upload invalid cluster_mode expected 400, got %d", code)
	}
}
