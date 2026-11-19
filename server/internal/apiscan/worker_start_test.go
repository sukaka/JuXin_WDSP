// worker_start_test.go StartJob 手动启动并发语义单测：
// 全局并发上限在并发 StartJob 下不被穿透（计数检查与占槽同锁），
// 失败回滚不残留占位（后续任务可再启动）。
package apiscan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestStartJobConcurrentCapNotExceeded 并发 StartJob：maxJobs=1 时 8 路并发只有一个成功，
// 其余全部因上限拒绝（修复前 check-then-act 竞态下可多个同时穿透）。
func TestStartJobConcurrentCapNotExceeded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(80 * time.Millisecond) // 慢靶标，保证首个任务驻留在跑
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	store := NewMemStore()
	worker, _ := newTestWorker(store, fakeSettings{enabled: true, maxJobs: 1, allowLoopback: true})

	const n = 8
	jobIDs := make([]uuid.UUID, n)
	for i := 0; i < n; i++ {
		target := &Target{
			ApplicationID: uuid.New(), Name: "并发目标", BaseURL: srv.URL,
			AllowedPaths: []string{"/a", "/b", "/c"}, Status: TargetStatusEnabled,
		}
		if err := store.CreateTarget(context.Background(), target); err != nil {
			t.Fatal(err)
		}
		authz := &Authorization{
			TargetID: target.ID, AuthorizedBy: uuid.New(),
			MaxQPS: 1000, MaxConcurrency: 1, ExpiresAt: time.Now().Add(time.Hour),
		}
		if err := store.CreateAuthorization(context.Background(), authz); err != nil {
			t.Fatal(err)
		}
		job := &Job{TargetID: target.ID, AuthorizationID: authz.ID, ProbeSet: ProbeAuthRequired}
		if err := store.CreateJob(context.Background(), job); err != nil {
			t.Fatal(err)
		}
		jobIDs[i] = job.ID
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var succeeded, rejected int
	for _, id := range jobIDs {
		wg.Add(1)
		go func(id uuid.UUID) {
			defer wg.Done()
			err := worker.StartJob(context.Background(), id)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				succeeded++
			} else if strings.Contains(err.Error(), "并发任务上限") {
				rejected++
			} else {
				t.Errorf("StartJob 非预期错误: %v", err)
			}
		}(id)
	}
	wg.Wait()
	if succeeded != 1 || rejected != n-1 {
		t.Fatalf("succeeded=%d rejected=%d, want 1/%d（上限不得被并发穿透）", succeeded, rejected, n-1)
	}
}

// TestStartJobFailureRollsBackSlot 库操作失败（任务不存在）回滚占位：
// 不占用并发额度，后续合法任务可正常启动。
func TestStartJobFailureRollsBackSlot(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	store := NewMemStore()
	worker, _ := newTestWorker(store, fakeSettings{enabled: true, maxJobs: 1, allowLoopback: true})

	// 不存在的任务：占槽后库操作失败，应回滚
	if err := worker.StartJob(context.Background(), uuid.New()); err == nil {
		t.Fatal("不存在任务应启动失败")
	}
	if got := worker.starting; got != 0 {
		t.Fatalf("失败后 starting=%d，占位未回滚", got)
	}
	// 合法任务随后可正常启动（额度未被泄漏的占位吃掉）
	_, _, jobID := seedJob(t, store, srv.URL, []string{"/a"}, nil)
	if err := worker.StartJob(context.Background(), jobID); err != nil {
		t.Fatalf("回滚后合法任务应可启动: %v", err)
	}
	// 等后台执行完，避免测试退出时 goroutine 仍在写库
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		job, _ := store.GetJob(context.Background(), jobID)
		if job.Status == JobStatusCompleted || job.Status == JobStatusFailed || job.Status == JobStatusStopped {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("后台任务未在时限内终结")
}
