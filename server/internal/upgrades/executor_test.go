package upgrades

import (
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
