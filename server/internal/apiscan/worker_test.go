// worker_test.go 调度执行器单测（MemStore + httptest 靶标 + 真实内置引擎）：
// RunOnce 端到端、整体开关、授权状态机执行侧语义（过期 FAILED / 撤销 STOPPED）、
// 吊销即停、人工停止、紧急停止（STOP+撤销授权）、同目标互斥。
package apiscan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
)

// fakeSettings 设置替身（开关/并发上限/测试回环放行开关）。
type fakeSettings struct {
	enabled       bool
	maxJobs       int
	allowLoopback bool
}

func (f fakeSettings) GetBool(_ context.Context, _, key string, def bool) bool {
	if key == settingsKeyEnabled {
		return f.enabled
	}
	if key == settingsKeyAllowLoopback {
		return f.allowLoopback
	}
	return def
}

func (f fakeSettings) GetInt(_ context.Context, _, key string, def int) int {
	if key == settingsKeyMaxJobs && f.maxJobs > 0 {
		return f.maxJobs
	}
	return def
}

// spyAudits 审计间谍。
type spyAudits struct{ entries []audits.RecordInput }

func (s *spyAudits) Record(_ context.Context, in audits.RecordInput) error {
	s.entries = append(s.entries, in)
	return nil
}

// seedJob 预置目标+授权+任务（返回三元组）。
func seedJob(t *testing.T, store *MemStore, baseURL string, paths []string, mutateAuthz func(*Authorization)) (uuid.UUID, uuid.UUID, uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	target := &Target{
		ApplicationID: uuid.New(), Name: "测试目标", BaseURL: baseURL,
		AllowedPaths: paths, Status: TargetStatusEnabled,
	}
	if err := store.CreateTarget(ctx, target); err != nil {
		t.Fatal(err)
	}
	authz := &Authorization{
		TargetID: target.ID, AuthorizedBy: uuid.New(),
		MaxQPS: 1000, MaxConcurrency: 1, ExpiresAt: time.Now().Add(time.Hour),
	}
	if mutateAuthz != nil {
		mutateAuthz(authz)
	}
	if err := store.CreateAuthorization(ctx, authz); err != nil {
		t.Fatal(err)
	}
	job := &Job{TargetID: target.ID, AuthorizationID: authz.ID, ProbeSet: ProbeAuthRequired}
	if err := store.CreateJob(ctx, job); err != nil {
		t.Fatal(err)
	}
	return target.ID, authz.ID, job.ID
}

// newTestWorker 装配测试执行器（真实引擎+签名器，假设置，审计间谍）。
func newTestWorker(store *MemStore, settings fakeSettings) (*Worker, *spyAudits) {
	signer, _ := NewSigner(make([]byte, 32))
	spy := &spyAudits{}
	return NewWorker(store, NewBuiltinEngine(nil), signer, settings, spy), spy
}

// TestWorkerRunOnceEndToEnd RunOnce 端到端：任务完成、发现落库、进度计数、审计留痕。
func TestWorkerRunOnceEndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/open" {
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	store := NewMemStore()
	_, _, jobID := seedJob(t, store, srv.URL, []string{"/open", "/closed"}, nil)
	worker, spy := newTestWorker(store, fakeSettings{enabled: true, allowLoopback: true})

	stats, err := worker.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Claimed != 1 || stats.Completed != 1 {
		t.Fatalf("stats=%+v", stats)
	}
	job, _ := store.GetJob(context.Background(), jobID)
	if job.Status != JobStatusCompleted {
		t.Fatalf("job status=%s", job.Status)
	}
	if job.Progress.Total != 2 || job.Progress.Done != 2 || job.Progress.Requests != 2 || job.Progress.Findings != 1 {
		t.Fatalf("progress=%+v", job.Progress)
	}
	// 发现落库（/open 未认证可访问）
	fs, total, err := store.ListFindings(context.Background(), FindingFilter{JobID: &jobID})
	if err != nil || total != 1 {
		t.Fatalf("findings total=%d err=%v", total, err)
	}
	if fs[0].Template != ProbeAuthRequired || fs[0].Status != FindingStatusNew {
		t.Fatalf("finding=%+v", fs[0])
	}
	// 审计留痕（system 完成记录）
	if len(spy.entries) != 1 || spy.entries[0].Action != "scan_job_completed" {
		t.Fatalf("audits=%+v", spy.entries)
	}
}

// TestWorkerDisabledIdles 整体开关关闭：调度空转，任务保持 PENDING。
func TestWorkerDisabledIdles(t *testing.T) {
	store := NewMemStore()
	_, _, jobID := seedJob(t, store, "http://127.0.0.1:1", []string{"/a"}, nil)
	worker, _ := newTestWorker(store, fakeSettings{enabled: false})

	stats, err := worker.RunOnce(context.Background())
	if err != nil || stats.Claimed != 0 {
		t.Fatalf("stats=%+v err=%v", stats, err)
	}
	job, _ := store.GetJob(context.Background(), jobID)
	if job.Status != JobStatusPending {
		t.Fatalf("disabled worker must not run jobs, status=%s", job.Status)
	}
	// nil settings 同样视为关闭（安全默认）
	w2 := NewWorker(store, NewBuiltinEngine(nil), nil, nil, nil)
	stats, _ = w2.RunOnce(context.Background())
	if stats.Claimed != 0 {
		t.Fatal("nil settings should mean disabled")
	}
}

// TestWorkerExpiredAuthorizationFails 授权过期：任务 FAILED 且原因落 last_error。
func TestWorkerExpiredAuthorizationFails(t *testing.T) {
	store := NewMemStore()
	_, _, jobID := seedJob(t, store, "http://127.0.0.1:1", []string{"/a"}, func(a *Authorization) {
		a.ExpiresAt = time.Now().Add(-time.Minute)
	})
	worker, _ := newTestWorker(store, fakeSettings{enabled: true})

	stats, err := worker.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Failed != 1 {
		t.Fatalf("stats=%+v", stats)
	}
	job, _ := store.GetJob(context.Background(), jobID)
	if job.Status != JobStatusFailed || job.Progress.LastError == "" {
		t.Fatalf("job=%+v", job)
	}
}

// TestWorkerRevokedAuthorizationStops 授权已撤销：任务 STOPPED（撤销即停的启动前形态）。
func TestWorkerRevokedAuthorizationStops(t *testing.T) {
	store := NewMemStore()
	_, authzID, jobID := seedJob(t, store, "http://127.0.0.1:1", []string{"/a"}, nil)
	if _, err := store.RevokeAuthorization(context.Background(), authzID, time.Now()); err != nil {
		t.Fatal(err)
	}
	worker, _ := newTestWorker(store, fakeSettings{enabled: true})

	stats, err := worker.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Stopped != 1 {
		t.Fatalf("stats=%+v", stats)
	}
	job, _ := store.GetJob(context.Background(), jobID)
	if job.Status != JobStatusStopped {
		t.Fatalf("job status=%s", job.Status)
	}
}

// TestWorkerRevokeMidRunStops 吊销即停（执行中撤销：Guard 批次复查命中，任务早退 STOPPED）。
func TestWorkerRevokeMidRunStops(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		time.Sleep(60 * time.Millisecond) // 慢靶标，留出撤销窗口
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	store := NewMemStore()
	paths := []string{"/p1", "/p2", "/p3", "/p4", "/p5", "/p6", "/p7", "/p8"}
	_, authzID, jobID := seedJob(t, store, srv.URL, paths, nil)
	worker, _ := newTestWorker(store, fakeSettings{enabled: true, allowLoopback: true})

	done := make(chan Stats, 1)
	go func() {
		stats, _ := worker.RunOnce(context.Background())
		done <- stats
	}()
	// 等首端点执行中撤销授权
	time.Sleep(120 * time.Millisecond)
	if _, _, err := worker.RevokeAuthorization(context.Background(), authzID); err != nil {
		t.Fatal(err)
	}
	stats := <-done
	if stats.Stopped != 1 {
		t.Fatalf("stats=%+v, want stopped=1", stats)
	}
	job, _ := store.GetJob(context.Background(), jobID)
	if job.Status != JobStatusStopped {
		t.Fatalf("job status=%s", job.Status)
	}
	// 早退：未探完全部端点
	if got := atomic.LoadInt64(&hits); int(got) >= len(paths) {
		t.Fatalf("job should abort early, hits=%d", got)
	}
}

// TestWorkerStopJobCancels 人工停止：PENDING 直接 STOPPED；执行中停止即取消。
func TestWorkerStopJobCancels(t *testing.T) {
	store := NewMemStore()
	_, _, jobID := seedJob(t, store, "http://127.0.0.1:1", []string{"/a"}, nil)
	worker, _ := newTestWorker(store, fakeSettings{enabled: true})

	// PENDING 停止
	job, err := worker.StopJob(context.Background(), jobID)
	if err != nil || job.Status != JobStatusStopped {
		t.Fatalf("stop pending: job=%+v err=%v", job, err)
	}
	// 终态再停止 → ErrInvalidTransition
	if _, err := worker.StopJob(context.Background(), jobID); err != ErrInvalidTransition {
		t.Fatalf("stop terminal should fail: %v", err)
	}
	// RunOnce 不应再取到该任务
	stats, _ := worker.RunOnce(context.Background())
	if stats.Claimed != 0 {
		t.Fatalf("stopped job claimed: %+v", stats)
	}
}

// TestWorkerEmergencyStop 紧急停止：任务 STOPPED + 授权撤销 + 该授权下全部任务停止。
func TestWorkerEmergencyStop(t *testing.T) {
	store := NewMemStore()
	_, authzID, jobID := seedJob(t, store, "http://127.0.0.1:1", []string{"/a"}, nil)
	// 同授权下第二个排队任务
	job2 := &Job{TargetID: mustGetJobTarget(t, store, jobID), AuthorizationID: authzID}
	if err := store.CreateJob(context.Background(), job2); err != nil {
		t.Fatal(err)
	}
	worker, _ := newTestWorker(store, fakeSettings{enabled: true})

	authz, stopped, err := worker.EmergencyStop(context.Background(), jobID)
	if err != nil {
		t.Fatal(err)
	}
	if authz.RevokedAt == nil {
		t.Fatal("authorization not revoked")
	}
	if stopped != 2 {
		t.Fatalf("stopped=%d, want 2", stopped)
	}
	for _, id := range []uuid.UUID{jobID, job2.ID} {
		j, _ := store.GetJob(context.Background(), id)
		if j.Status != JobStatusStopped {
			t.Fatalf("job %s status=%s", id, j.Status)
		}
	}
}

func mustGetJobTarget(t *testing.T, store *MemStore, jobID uuid.UUID) uuid.UUID {
	t.Helper()
	j, err := store.GetJob(context.Background(), jobID)
	if err != nil {
		t.Fatal(err)
	}
	return j.TargetID
}

// TestWorkerSameTargetMutualExclusion 同目标互斥：目标有 RUNNING 任务时不再取新任务。
func TestWorkerSameTargetMutualExclusion(t *testing.T) {
	store := NewMemStore()
	targetID, _, jobID := seedJob(t, store, "http://127.0.0.1:1", []string{"/a"}, nil)
	job2 := &Job{TargetID: targetID, AuthorizationID: mustGetJobAuthz(t, store, jobID)}
	if err := store.CreateJob(context.Background(), job2); err != nil {
		t.Fatal(err)
	}
	// 第一次取到 job（RUNNING）
	claimed, err := store.ClaimPendingJob(context.Background(), time.Now())
	if err != nil || claimed == nil {
		t.Fatalf("first claim: %v %v", claimed, err)
	}
	// 同目标第二个任务不可取
	again, err := store.ClaimPendingJob(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if again != nil {
		t.Fatalf("same-target job should be excluded, got %s", again.ID)
	}
}

func mustGetJobAuthz(t *testing.T, store *MemStore, jobID uuid.UUID) uuid.UUID {
	t.Helper()
	j, err := store.GetJob(context.Background(), jobID)
	if err != nil {
		t.Fatal(err)
	}
	return j.AuthorizationID
}

// TestWorkerAllowlistEnforced allowlist 强制执行：目标主机不在名单内任务 FAILED。
func TestWorkerAllowlistEnforced(t *testing.T) {
	store := NewMemStore()
	_, _, jobID := seedJob(t, store, "http://127.0.0.1:9", []string{"/a"}, func(a *Authorization) {
		a.Allowlist = []string{"api.example.com"}
	})
	worker, _ := newTestWorker(store, fakeSettings{enabled: true})

	stats, err := worker.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Failed != 1 {
		t.Fatalf("stats=%+v", stats)
	}
	job, _ := store.GetJob(context.Background(), jobID)
	if job.Status != JobStatusFailed || job.Progress.LastError == "" {
		t.Fatalf("job=%+v", job)
	}
}
