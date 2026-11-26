package upgrades

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
)

func TestExecutorResultRoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	id := uuid.New().String()
	want := ExecutorResult{
		JobID: id, Status: "SUCCESS", Stage: StatusVerifying,
		Message: "ok", FinishedAt: time.Now().UTC().Truncate(time.Second),
	}
	path := filepath.Join(dir, "results", id+".json")
	if err := writeJSONAtomic(path, want, 0o640); err != nil {
		t.Fatalf("writeJSONAtomic: %v", err)
	}
	got, err := readExecutorResult(path)
	if err != nil {
		t.Fatalf("readExecutorResult: %v", err)
	}
	if got.JobID != want.JobID || got.Status != want.Status || got.Stage != want.Stage {
		t.Fatalf("unexpected result: %+v", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %o, want 640", info.Mode().Perm())
	}
}

func TestReadExecutorResultRejectsInvalidData(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte(`{"job_id":"not-a-uuid","status":"SUCCESS"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readExecutorResult(path); err == nil {
		t.Fatal("expected invalid job id error")
	}

	if err := os.WriteFile(path, []byte(`{"job_id":"`+uuid.New().String()+`","status":"RUNNING"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readExecutorResult(path); err == nil {
		t.Fatal("expected invalid status error")
	}
}

type fakeResultStore struct {
	jobs        map[uuid.UUID]*Job
	transitions []string
}

func (f *fakeResultStore) GetJob(_ context.Context, id uuid.UUID) (*Job, error) {
	j, ok := f.jobs[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *j
	return &cp, nil
}

func (f *fakeResultStore) Transition(_ context.Context, id uuid.UUID, from, to string) error {
	j, ok := f.jobs[id]
	if !ok || j.Status != from || !CanTransition(from, to) {
		return ErrInvalidStatus
	}
	j.Status = to
	f.transitions = append(f.transitions, from+"->"+to)
	return nil
}

func (f *fakeResultStore) MarkFailed(_ context.Context, id uuid.UUID, code string, err error) error {
	j := f.jobs[id]
	j.Status = StatusFailed
	j.FailureCode = code
	j.FailureMessage = failMsg(err)
	return nil
}

func (f *fakeResultStore) MarkFinished(_ context.Context, id uuid.UUID, status string) error {
	j := f.jobs[id]
	j.Status = status
	return nil
}

func TestReconcileResultsVerifyFailureRollsBackInsteadOfWedging(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	id := uuid.New()
	reqBy := uuid.New()
	if err := writeJSONAtomic(filepath.Join(dir, "results", id.String()+".json"), ExecutorResult{
		JobID: id.String(), Status: "SUCCESS", Stage: StatusVerifying, FinishedAt: time.Now().UTC(),
	}, 0o640); err != nil {
		t.Fatal(err)
	}

	fs := &fakeResultStore{jobs: map[uuid.UUID]*Job{
		id: {ID: id, Status: StatusApplying, RequestedBy: &reqBy},
	}}
	rollbacks := 0
	var alerts []string
	svc := &Service{
		executorDir: dir,
		resStore:    fs,
		verifyFn:    func(context.Context) error { return errors.New("schema mismatch") },
		rollbackFn: func(_ context.Context, _ uuid.UUID, _ *uuid.UUID) error {
			rollbacks++
			return nil
		},
		alertFn: func(alertType, _, _, _ string) { alerts = append(alerts, alertType) },
	}

	svc.reconcileResults(context.Background())

	if rollbacks != 1 {
		t.Fatalf("rollback calls = %d, want 1", rollbacks)
	}
	if fs.jobs[id].Status != StatusRolledBack {
		t.Fatalf("job status = %s, want ROLLED_BACK (must not wedge in VERIFYING)", fs.jobs[id].Status)
	}
	if len(alerts) != 1 || alerts[0] != "UPGRADE_ROLLED_BACK" {
		t.Fatalf("alerts = %v, want [UPGRADE_ROLLED_BACK]", alerts)
	}

	// Second reconcile tick must be a no-op
	svc.reconcileResults(context.Background())
	if rollbacks != 1 {
		t.Fatalf("reconcile re-ran rollback on terminal job: %d", rollbacks)
	}
}

func TestProcessExecutorResultVerifyAndRollbackFailureMarksFailedOnce(t *testing.T) {
	t.Parallel()
	id := uuid.New()
	reqBy := uuid.New()
	fs := &fakeResultStore{jobs: map[uuid.UUID]*Job{
		id: {ID: id, Status: StatusApplying, RequestedBy: &reqBy},
	}}
	rollbacks := 0
	var alerts []string
	svc := &Service{
		resStore: fs,
		verifyFn: func(context.Context) error { return errors.New("valkey down") },
		rollbackFn: func(_ context.Context, _ uuid.UUID, _ *uuid.UUID) error {
			rollbacks++
			return errors.New("restore failed")
		},
		alertFn: func(alertType, _, _, _ string) { alerts = append(alerts, alertType) },
	}

	err := svc.processExecutorResult(context.Background(), &ExecutorResult{
		JobID: id.String(), Status: "SUCCESS", Stage: StatusVerifying,
	})
	if err == nil {
		t.Fatal("expected error when verify and rollback both fail")
	}
	if rollbacks != 1 {
		t.Fatalf("rollback calls = %d, want 1", rollbacks)
	}
	if fs.jobs[id].Status != StatusFailed || fs.jobs[id].FailureCode != FailRollback {
		t.Fatalf("job = %+v, want FAILED/%s", fs.jobs[id], FailRollback)
	}
	if len(alerts) != 1 || alerts[0] != "UPGRADE_ROLLBACK_FAILED" {
		t.Fatalf("alerts = %v", alerts)
	}
}

func TestProcessExecutorResultFailedStatusNoDoubleRollback(t *testing.T) {
	t.Parallel()
	id := uuid.New()
	reqBy := uuid.New()
	fs := &fakeResultStore{jobs: map[uuid.UUID]*Job{
		id: {ID: id, Status: StatusApplying, RequestedBy: &reqBy},
	}}
	rollbacks := 0
	svc := &Service{
		resStore: fs,
		rollbackFn: func(_ context.Context, _ uuid.UUID, _ *uuid.UUID) error {
			rollbacks++
			return errors.New("db rollback error")
		},
	}

	result := &ExecutorResult{JobID: id.String(), Status: "FAILED", Stage: StatusApplying, ErrorCode: FailApply, Message: "apply failed"}
	err := svc.processExecutorResult(context.Background(), result)
	if err == nil {
		t.Fatal("expected rollback error")
	}
	// Simulate service.go:366-371 guard: terminal status prevents second rollback
	cur, getErr := svc.resultRepo().GetJob(context.Background(), id)
	if getErr != nil {
		t.Fatal(getErr)
	}
	if !TerminalStatus(cur.Status) {
		t.Fatalf("job should be terminal after processExecutorResult failure rollback, got %s", cur.Status)
	}
	// Re-invoking processExecutorResult must also be a no-op
	if err := svc.processExecutorResult(context.Background(), result); err != nil {
		t.Fatalf("second processExecutorResult should be no-op, got %v", err)
	}
	if rollbacks != 1 {
		t.Fatalf("double rollback detected: %d", rollbacks)
	}
}

type fakeVersionResultStore struct {
	fakeResultStore
	packages       map[uuid.UUID]*Package
	currentVersion string
	setVersionErr  error
}

func (f *fakeVersionResultStore) GetPackage(_ context.Context, id uuid.UUID) (*Package, error) {
	p, ok := f.packages[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *p
	return &cp, nil
}

func (f *fakeVersionResultStore) SetCurrentVersion(_ context.Context, version string) error {
	if f.setVersionErr != nil {
		return f.setVersionErr
	}
	f.currentVersion = version
	return nil
}

func TestProcessExecutorResultPersistsCurrentVersionOnSuccess(t *testing.T) {
	t.Parallel()
	jobID := uuid.New()
	pkgID := uuid.New()
	fs := &fakeVersionResultStore{
		fakeResultStore: fakeResultStore{
			jobs: map[uuid.UUID]*Job{
				jobID: {ID: jobID, PackageID: &pkgID, Status: StatusApplying},
			},
		},
		packages: map[uuid.UUID]*Package{
			pkgID: {ID: pkgID, VersionFrom: "1.11.1", VersionTo: "1.11.2"},
		},
	}
	svc := &Service{
		resStore: fs,
		verifyFn: func(context.Context) error { return nil },
	}
	if err := svc.processExecutorResult(context.Background(), &ExecutorResult{
		JobID: jobID.String(), Status: "SUCCESS", Stage: StatusVerifying,
	}); err != nil {
		t.Fatalf("processExecutorResult failed: %v", err)
	}
	if fs.jobs[jobID].Status != StatusSuccess {
		t.Fatalf("job status = %s, want SUCCESS", fs.jobs[jobID].Status)
	}
	if fs.currentVersion != "1.11.2" {
		t.Fatalf("persisted currentVersion = %q, want 1.11.2", fs.currentVersion)
	}
}

func TestProcessExecutorResultPropagatesVersionPersistError(t *testing.T) {
	t.Parallel()
	jobID := uuid.New()
	pkgID := uuid.New()
	fs := &fakeVersionResultStore{
		fakeResultStore: fakeResultStore{
			jobs: map[uuid.UUID]*Job{
				jobID: {ID: jobID, PackageID: &pkgID, Status: StatusApplying},
			},
		},
		packages: map[uuid.UUID]*Package{
			pkgID: {ID: pkgID, VersionFrom: "1.11.1", VersionTo: "1.11.2"},
		},
		setVersionErr: errors.New("db write failed"),
	}
	svc := &Service{
		resStore: fs,
		verifyFn: func(context.Context) error { return nil },
	}
	if err := svc.processExecutorResult(context.Background(), &ExecutorResult{
		JobID: jobID.String(), Status: "SUCCESS", Stage: StatusVerifying,
	}); err == nil {
		t.Fatal("expected error when persisting current_version fails")
	}
	if fs.jobs[jobID].Status == StatusSuccess {
		t.Fatal("job must not be marked SUCCESS when current_version persistence failed")
	}
}

func TestResolveEffectiveSystemVersion(t *testing.T) {
	t.Parallel()
	// 纯前端/网关差量升级后库内版本高于未替换的 API 二进制：应返回库内新版本
	if got := resolveEffectiveSystemVersion("1.11.2", "1.11.1"); got != "1.11.2" {
		t.Fatalf("got %q, want 1.11.2", got)
	}
	// 宿主机完整包升级替换了 API 二进制而库内仍为旧版本：应返回更高的二进制版本
	if got := resolveEffectiveSystemVersion("1.11.1", "1.12.0"); got != "1.12.0" {
		t.Fatalf("got %q, want 1.12.0", got)
	}
	// 相同版本
	if got := resolveEffectiveSystemVersion("1.12.0", "1.12.0"); got != "1.12.0" {
		t.Fatalf("got %q, want 1.12.0", got)
	}
	// 异常库值原样返回给预检 fail-closed
	if got := resolveEffectiveSystemVersion("corrupted", "1.12.0"); got != "corrupted" {
		t.Fatalf("got %q, want corrupted", got)
	}
}

type fakeJobGetStore struct {
	fakeVersionResultStore
}

func (f *fakeJobGetStore) ListJobs(_ context.Context, _ string, _, _ int) ([]Job, int64, error) {
	out := make([]Job, 0, len(f.jobs))
	for _, j := range f.jobs {
		out = append(out, *j)
	}
	return out, int64(len(out)), nil
}

func (f *fakeJobGetStore) ListNodeExecutions(_ context.Context, _ uuid.UUID) ([]NodeExecution, error) {
	return nil, nil
}

func (f *fakeJobGetStore) ListNodeExecutionsByJobIDs(_ context.Context, _ []uuid.UUID) (map[uuid.UUID][]NodeExecution, error) {
	return map[uuid.UUID][]NodeExecution{}, nil
}

func TestReconcileJobResultAndEvaluateReadiness(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	jobID := uuid.New()
	pkgID := uuid.New()
	fs := &fakeJobGetStore{
		fakeVersionResultStore: fakeVersionResultStore{
			fakeResultStore: fakeResultStore{
				jobs: map[uuid.UUID]*Job{
					jobID: {ID: jobID, PackageID: &pkgID, Status: StatusApplying},
				},
			},
			packages: map[uuid.UUID]*Package{
				pkgID: {ID: pkgID, VersionFrom: "1.15.0", VersionTo: "1.15.1"},
			},
		},
	}
	var verifyErr error
	svc := &Service{
		executorDir: dir,
		resStore:    fs,
		verifyFn:    func(context.Context) error { return verifyErr },
	}

	// 1. 执行器尚未写入结果文件：按需收敛不报错，状态保持 APPLYING，server_status.ready=false
	if err := svc.ReconcileJobResult(context.Background(), jobID); err != nil {
		t.Fatalf("ReconcileJobResult (pending): %v", err)
	}
	st := svc.EvaluateJobReadiness(context.Background(), fs.jobs[jobID])
	if st.Ready || !st.HealthOK {
		t.Fatalf("pending job readiness = %+v, want ready=false health_ok=true", st)
	}

	// 2. 执行器写入 SUCCESS 结果文件：ReconcileJobResult 立即核验并落库 SUCCESS 与目标版本
	resPath := filepath.Join(dir, "results", jobID.String()+".json")
	if err := writeJSONAtomic(resPath, ExecutorResult{
		JobID: jobID.String(), Status: "SUCCESS", Stage: StatusVerifying, FinishedAt: time.Now().UTC(),
	}, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := svc.ReconcileJobResult(context.Background(), jobID); err != nil {
		t.Fatalf("ReconcileJobResult (success): %v", err)
	}
	if fs.jobs[jobID].Status != StatusSuccess {
		t.Fatalf("job status = %s, want SUCCESS", fs.jobs[jobID].Status)
	}
	if fs.currentVersion != "1.15.1" {
		t.Fatalf("currentVersion = %q, want 1.15.1", fs.currentVersion)
	}
	st = svc.EvaluateJobReadiness(context.Background(), fs.jobs[jobID])
	if !st.Ready || !st.HealthOK {
		t.Fatalf("success job readiness = %+v, want ready=true health_ok=true", st)
	}

	// 3. 若后端实时健康检查失败，即使 job 为 SUCCESS 也必须返回 ready=false
	verifyErr = errors.New("valkey ping failed")
	st = svc.EvaluateJobReadiness(context.Background(), fs.jobs[jobID])
	if st.Ready || st.HealthOK || st.HealthDetail == "" {
		t.Fatalf("unhealthy readiness = %+v, want ready=false health_ok=false with detail", st)
	}
}

func TestHandlerGetReconcilesAndReturnsServerStatus(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	jobID := uuid.New()
	pkgID := uuid.New()
	fs := &fakeJobGetStore{
		fakeVersionResultStore: fakeVersionResultStore{
			fakeResultStore: fakeResultStore{
				jobs: map[uuid.UUID]*Job{
					jobID: {ID: jobID, PackageID: &pkgID, Status: StatusApplying},
				},
			},
			packages: map[uuid.UUID]*Package{
				pkgID: {ID: pkgID, VersionFrom: "1.15.0", VersionTo: "1.15.1"},
			},
		},
	}
	svc := &Service{
		executorDir: dir,
		resStore:    fs,
		verifyFn:    func(context.Context) error { return nil },
	}
	h := NewHandler(nil, svc, audits.NewService(nil))
	h.jobReader = fs

	callGet := func() (Job, ServerUpgradeStatus) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/upgrades/"+jobID.String(), nil)
		req.SetPathValue("id", jobID.String())
		rec := httptest.NewRecorder()
		h.Get(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var env struct {
			Data struct {
				Job          Job                 `json:"job"`
				ServerStatus ServerUpgradeStatus `json:"server_status"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		return env.Data.Job, env.Data.ServerStatus
	}

	// 执行器尚未写结果文件：返回 APPLYING 且 server_status.ready=false
	job, st := callGet()
	if job.Status != StatusApplying || st.Ready {
		t.Fatalf("before result: status=%s ready=%v, want APPLYING/false", job.Status, st.Ready)
	}

	// 执行器写入 SUCCESS 结果文件后：GET 立即收敛返回 SUCCESS 且 server_status.ready=true
	resPath := filepath.Join(dir, "results", jobID.String()+".json")
	if err := writeJSONAtomic(resPath, ExecutorResult{
		JobID: jobID.String(), Status: "SUCCESS", Stage: StatusVerifying, FinishedAt: time.Now().UTC(),
	}, 0o640); err != nil {
		t.Fatal(err)
	}
	job, st = callGet()
	if job.Status != StatusSuccess || !st.Ready || !st.HealthOK {
		t.Fatalf("after result: status=%s server_status=%+v, want SUCCESS/ready=true", job.Status, st)
	}
}
