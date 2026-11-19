package upgrades

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
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
