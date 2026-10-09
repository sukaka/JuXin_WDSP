package upgrades

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
)

// fakeStrandedStore 内存版滞留任务存储（同 scheduleStore 测试替换模式）。
type fakeStrandedStore struct {
	jobs        []Job
	listErr     error
	markErr     error
	markedID    uuid.UUID
	markedFrom  string
	markedCode  string
	markedMsg   string
	markCalled  bool
	lastCutoff  time.Time
	lastWaitSec time.Duration
}

func (f *fakeStrandedStore) ListExpiredApplyingJobs(_ context.Context, cutoff time.Time, wait time.Duration) ([]Job, error) {
	f.lastCutoff = cutoff
	f.lastWaitSec = wait
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.jobs, nil
}

func (f *fakeStrandedStore) MarkFailedIfStatus(_ context.Context, id uuid.UUID, from, code string, err error) error {
	f.markCalled = true
	f.markedID = id
	f.markedFrom = from
	f.markedCode = code
	f.markedMsg = fmt.Sprintf("%v", err)
	return f.markErr
}

// newStrandedTestService 装配仅含兜底清扫协作点的 Service（不触碰数据库与备份）。
func newStrandedTestService(t *testing.T, fs *fakeStrandedStore) (*Service, *[]audits.RecordInput, *[]string) {
	t.Helper()
	executorDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(executorDir, "results"), 0o750); err != nil {
		t.Fatal(err)
	}
	s := &Service{executorDir: executorDir, executorWait: 30 * time.Minute, stranded: fs}
	auditInputs := &[]audits.RecordInput{}
	s.SetAuditFunc(func(_ context.Context, in audits.RecordInput) error {
		*auditInputs = append(*auditInputs, in)
		return nil
	})
	alerts := &[]string{}
	s.alertFn = func(alertType, component, title, message string) {
		*alerts = append(*alerts, alertType+"|"+title)
	}
	return s, auditInputs, alerts
}

// TestReconcileExpiredApplyingClosesStrandedJob F7 核心回归：超期且无结果文件的
// APPLYING 任务（执行器中断 + API 重启场景）必须被兜底终结为 FAILED/EXECUTOR_TIMEOUT，
// 审计在册、告警触发，不自动重跑。
func TestReconcileExpiredApplyingClosesStrandedJob(t *testing.T) {
	t.Parallel()
	requestedBy := uuid.New()
	job := Job{ID: uuid.New(), Status: StatusApplying, RequestedBy: &requestedBy, RequestID: "req-stranded"}
	fs := &fakeStrandedStore{jobs: []Job{job}}
	s, auditInputs, alerts := newStrandedTestService(t, fs)

	s.reconcileExpiredApplying(context.Background())

	if !fs.markCalled {
		t.Fatal("expected MarkFailedIfStatus to be called")
	}
	if fs.markedID != job.ID || fs.markedFrom != StatusApplying || fs.markedCode != FailExecutorTimeout {
		t.Fatalf("unexpected mark: id=%s from=%s code=%s", fs.markedID, fs.markedFrom, fs.markedCode)
	}
	if fs.markedMsg == "" {
		t.Fatal("expected failure message to explain interruption semantics")
	}
	if len(*auditInputs) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(*auditInputs))
	}
	audit := (*auditInputs)[0]
	if audit.Module != "upgrades" || audit.Action != "executor_timeout_close" ||
		audit.ObjectID != job.ID.String() || audit.Result != audits.ResultSuccess ||
		audit.RiskLevel != audits.RiskHigh || audit.RequestID != "req-stranded" {
		t.Fatalf("unexpected audit record: %+v", audit)
	}
	if audit.UserID == nil || *audit.UserID != requestedBy {
		t.Fatalf("audit operator should be job requester: %+v", audit.UserID)
	}
	if len(*alerts) != 1 || (*alerts)[0] != "UPGRADE_FAILED|升级执行器超时，滞留任务已终结" {
		t.Fatalf("unexpected alerts: %v", *alerts)
	}
	if fs.lastWaitSec != 30*time.Minute {
		t.Fatalf("expected executor wait 30m passed to query, got %s", fs.lastWaitSec)
	}
}

// TestReconcileExpiredApplyingSkipsJobWithResult 结果文件已落盘的超期任务交给
// reconcileResults 正常处理，兜底清扫不得按超时终结（否则 SUCCESS 会被误判为中断）。
func TestReconcileExpiredApplyingSkipsJobWithResult(t *testing.T) {
	t.Parallel()
	job := Job{ID: uuid.New(), Status: StatusApplying}
	fs := &fakeStrandedStore{jobs: []Job{job}}
	s, auditInputs, alerts := newStrandedTestService(t, fs)
	path := filepath.Join(s.executorDir, "results", job.ID.String()+".json")
	if err := os.WriteFile(path, []byte(`{"job_id":"`+job.ID.String()+`","status":"SUCCESS","stage":"VERIFYING"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	s.reconcileExpiredApplying(context.Background())

	if fs.markCalled {
		t.Fatal("job with result file must not be timeout-closed")
	}
	if len(*auditInputs) != 0 || len(*alerts) != 0 {
		t.Fatalf("no audit/alert expected, got %d/%d", len(*auditInputs), len(*alerts))
	}
}

// TestReconcileExpiredApplyingEmpty 无超期任务时零动作。
func TestReconcileExpiredApplyingEmpty(t *testing.T) {
	t.Parallel()
	fs := &fakeStrandedStore{}
	s, auditInputs, alerts := newStrandedTestService(t, fs)

	s.reconcileExpiredApplying(context.Background())

	if fs.markCalled || len(*auditInputs) != 0 || len(*alerts) != 0 {
		t.Fatal("expected no action for empty expired list")
	}
}

// TestReconcileExpiredApplyingRaceLost 与执行器结果处理竞争失败（任务已离开
// APPLYING）时不审计不告警——恰好一方生效。
func TestReconcileExpiredApplyingRaceLost(t *testing.T) {
	t.Parallel()
	job := Job{ID: uuid.New(), Status: StatusApplying}
	fs := &fakeStrandedStore{jobs: []Job{job}, markErr: fmt.Errorf("%w: job not in status %s", ErrInvalidStatus, StatusApplying)}
	s, auditInputs, alerts := newStrandedTestService(t, fs)

	s.reconcileExpiredApplying(context.Background())

	if !fs.markCalled {
		t.Fatal("expected close attempt")
	}
	if len(*auditInputs) != 0 || len(*alerts) != 0 {
		t.Fatalf("race-lost close must not audit/alert, got %d/%d", len(*auditInputs), len(*alerts))
	}
}

// TestReconcileExpiredApplyingListError 查询失败只记日志，不静默吞错也不误标任务。
func TestReconcileExpiredApplyingListError(t *testing.T) {
	t.Parallel()
	fs := &fakeStrandedStore{listErr: errors.New("db down")}
	s, _, _ := newStrandedTestService(t, fs)

	s.reconcileExpiredApplying(context.Background())

	if fs.markCalled {
		t.Fatal("list error must not mark any job")
	}
}
