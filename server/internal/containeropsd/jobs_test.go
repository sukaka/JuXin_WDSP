package containeropsd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func newJobStoreForTest(t *testing.T) *jobStore {
	t.Helper()
	store, err := newJobStore(filepath.Join(shortTempDir(t), "results"))
	if err != nil {
		t.Fatalf("创建任务存储: %v", err)
	}
	return store
}

func jobStoreCounts(store *jobStore) (jobs, active int) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.jobs), len(store.activeJobs)
}

func waitActiveJobs(t *testing.T, svc *Service, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_, active := jobStoreCounts(svc.jobs)
		if active == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	_, active := jobStoreCounts(svc.jobs)
	t.Fatalf("活动任务数 = %d，期望 %d", active, want)
}

func replaceJobDirWithFile(t *testing.T, store *jobStore) func() {
	t.Helper()
	saved := store.dir + ".saved"
	if err := os.Rename(store.dir, saved); err != nil {
		t.Fatalf("移走任务目录: %v", err)
	}
	if err := os.WriteFile(store.dir, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("替换任务目录: %v", err)
	}
	var once sync.Once
	restore := func() {
		once.Do(func() {
			if err := os.Remove(store.dir); err != nil && !os.IsNotExist(err) {
				t.Errorf("移除占位文件: %v", err)
			}
			if err := os.Rename(saved, store.dir); err != nil {
				t.Errorf("恢复任务目录: %v", err)
			}
		})
	}
	t.Cleanup(restore)
	return restore
}

type synchronizedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *synchronizedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *synchronizedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

func TestJobStoreReturnsDeepSnapshots(t *testing.T) {
	store := newJobStoreForTest(t)
	created, err := store.create("web", ActionStart)
	if err != nil {
		t.Fatal(err)
	}
	jobID := created.JobID
	created.Status = JobFailed
	created.Message = "caller mutation"
	got, ok := store.get(jobID)
	if !ok || got.Status != JobAccepted || got.Message != "" {
		t.Fatalf("create 返回值不是独立快照: %+v", got)
	}
	if err := store.transition(jobID, JobRunning, ""); err != nil {
		t.Fatal(err)
	}
	first, _ := store.get(jobID)
	if first.StartedAt == nil {
		t.Fatal("RUNNING 任务缺少 started_at")
	}
	startedAt := *first.StartedAt
	first.Status = JobSuccess
	*first.StartedAt = time.Time{}
	second, _ := store.get(jobID)
	if second.Status != JobRunning || second.StartedAt == nil || !second.StartedAt.Equal(startedAt) {
		t.Fatalf("get 快照或时间指针与存储共享: %+v", second)
	}
	store.done(jobID)
}

func TestJobStoreConcurrentQueriesAndTransitions(t *testing.T) {
	store := newJobStoreForTest(t)
	job, err := store.create("web", ActionRestart)
	if err != nil {
		t.Fatal(err)
	}
	jobID := job.JobID
	done := make(chan struct{})
	errs := make(chan error, 6)
	var readers sync.WaitGroup
	for i := 0; i < cap(errs); i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				snapshot, ok := store.get(jobID)
				if !ok {
					errs <- fmt.Errorf("任务查询丢失")
					return
				}
				if snapshot.JobID != jobID {
					errs <- fmt.Errorf("任务 ID = %q，期望 %q", snapshot.JobID, jobID)
					return
				}
				if _, err := json.Marshal(snapshot); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	for i := 0; i < 40; i++ {
		if err := store.transition(jobID, JobRunning, fmt.Sprintf("iteration-%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	close(done)
	readers.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if err := store.transition(jobID, JobSuccess, "执行成功"); err != nil {
		t.Fatal(err)
	}
	store.done(jobID)
}

func TestJobStoreBoundsMemoryAndFiles(t *testing.T) {
	store := newJobStoreForTest(t)
	store.maxJobs = 3
	var firstID, lastID string
	for i := 0; i < 9; i++ {
		job, err := store.create("web", ActionRestart)
		if err != nil {
			t.Fatalf("第 %d 个任务创建失败: %v", i, err)
		}
		if i == 0 {
			firstID = job.JobID
		}
		lastID = job.JobID
		if err := store.transition(job.JobID, JobRunning, ""); err != nil {
			t.Fatal(err)
		}
		if err := store.transition(job.JobID, JobSuccess, "执行成功"); err != nil {
			t.Fatal(err)
		}
		store.done(job.JobID)
		jobs, active := jobStoreCounts(store)
		if jobs > 3 || active != 0 {
			t.Fatalf("任务数量越界: jobs=%d active=%d", jobs, active)
		}
		entries, err := os.ReadDir(store.dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) > 3 {
			t.Fatalf("结果文件数量越界: %d", len(entries))
		}
	}
	if _, ok := store.get(firstID); ok {
		t.Fatal("最旧终态任务应被回收")
	}
	if job, ok := store.get(lastID); !ok || job.Status != JobSuccess {
		t.Fatalf("最新任务应保留: %+v ok=%v", job, ok)
	}
}

func TestJobTransitionPersistenceFailureKeepsLastDurableState(t *testing.T) {
	store := newJobStoreForTest(t)
	job, err := store.create("web", ActionRestart)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.transition(job.JobID, JobRunning, ""); err != nil {
		t.Fatal(err)
	}
	before, _ := store.get(job.JobID)
	restore := replaceJobDirWithFile(t, store)
	if err := store.transition(job.JobID, JobSuccess, "执行成功"); err == nil {
		t.Fatal("落盘失败必须返回错误")
	}
	after, _ := store.get(job.JobID)
	if after.Status != JobRunning || after.FinishedAt != nil || !after.StartedAt.Equal(*before.StartedAt) {
		t.Fatalf("失败迁移不应改写内存状态: before=%+v after=%+v", before, after)
	}
	restore()
	raw, err := os.ReadFile(filepath.Join(store.dir, job.JobID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var persisted ActionJob
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.Status != JobRunning || persisted.FinishedAt != nil {
		t.Fatalf("磁盘与内存最后持久化状态不一致: %+v", persisted)
	}
	store.done(job.JobID)
}

func TestActionCreatePersistenceFailureIsReported(t *testing.T) {
	engine, dc := newFakeEngine(t)
	engine.addContainer(&fakeContainer{name: "proj-web-1", service: "web", running: true})
	svc := newTestService(t, dc, shortTempDir(t), "proj", "web")
	var logs synchronizedBuffer
	svc.logger = slog.New(slog.NewTextHandler(&logs, nil))
	replaceJobDirWithFile(t, svc.jobs)

	code, body := submitAction(t, svc, "web", `{"action":"restart"}`)
	if code != http.StatusInternalServerError || body["error"].(map[string]interface{})["code"] != "INTERNAL_ERROR" {
		t.Fatalf("创建落盘失败应明确返回 500: code=%d body=%v", code, body)
	}
	jobs, active := jobStoreCounts(svc.jobs)
	if jobs != 0 || active != 0 {
		t.Fatalf("失败创建不应留下任务或名额: jobs=%d active=%d", jobs, active)
	}
	if !strings.Contains(logs.String(), "创建运维任务失败") {
		t.Fatalf("创建落盘失败未记录日志: %s", logs.String())
	}
}

func TestAsyncPersistenceFailureIsLoggedAndDoesNotExecute(t *testing.T) {
	engine, dc := newFakeEngine(t)
	engine.addContainer(&fakeContainer{name: "proj-web-1", service: "web", running: true})
	svc := newTestService(t, dc, shortTempDir(t), "proj", "web")
	var logs synchronizedBuffer
	svc.logger = slog.New(slog.NewTextHandler(&logs, nil))
	code, body := submitAction(t, svc, "web", `{"action":"restart","delay_seconds":1}`)
	if code != http.StatusAccepted {
		t.Fatalf("受理应 202: code=%d body=%v", code, body)
	}
	jobID := body["job_id"].(string)
	restore := replaceJobDirWithFile(t, svc.jobs)
	waitActiveJobs(t, svc, 0)
	job, ok := svc.jobs.get(jobID)
	if !ok || job.Status != JobAccepted || job.StartedAt != nil {
		t.Fatalf("状态落盘失败时应保持最后持久化状态: %+v", job)
	}
	if calls := len(engine.callsWith("/restart")); calls != 0 {
		t.Fatalf("RUNNING 状态无法持久化时不应执行动作，调用数=%d", calls)
	}
	if logsText := logs.String(); !strings.Contains(logsText, "持久化运维任务运行状态失败") || !strings.Contains(logsText, jobID) {
		t.Fatalf("异步落盘失败未记录完整日志: %s", logsText)
	}
	restore()
	raw, err := os.ReadFile(filepath.Join(svc.jobs.dir, jobID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var persisted ActionJob
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.Status != JobAccepted {
		t.Fatalf("磁盘状态应为 ACCEPTED: %+v", persisted)
	}
}

func TestActionAdmissionCapacityAndRelease(t *testing.T) {
	engine, dc := newFakeEngine(t)
	engine.addContainer(&fakeContainer{name: "proj-web-1", service: "web", running: true})
	svc := newTestService(t, dc, shortTempDir(t), "proj", "web")
	svc.jobs.maxActive = 2
	ids := make([]string, 0, 2)
	for i := 0; i < 2; i++ {
		code, body := submitAction(t, svc, "web", `{"action":"restart","delay_seconds":1}`)
		if code != http.StatusAccepted {
			t.Fatalf("第 %d 个任务应受理: code=%d body=%v", i, code, body)
		}
		ids = append(ids, body["job_id"].(string))
	}
	code, body := submitAction(t, svc, "web", `{"action":"restart"}`)
	if code != http.StatusTooManyRequests || body["error"].(map[string]interface{})["code"] != "JOB_QUEUE_FULL" {
		t.Fatalf("容量满应返回 429 JOB_QUEUE_FULL: code=%d body=%v", code, body)
	}
	jobs, active := jobStoreCounts(svc.jobs)
	if jobs != 2 || active != 2 {
		t.Fatalf("活动任务必须受容量约束: jobs=%d active=%d", jobs, active)
	}
	for _, id := range ids {
		if job := waitJob(t, svc, id); job.Status != JobSuccess {
			t.Fatalf("排队任务应正常完成: %+v", job)
		}
	}
	waitActiveJobs(t, svc, 0)
	code, body = submitAction(t, svc, "web", `{"action":"restart"}`)
	if code != http.StatusAccepted {
		t.Fatalf("完成后应释放受理容量: code=%d body=%v", code, body)
	}
	if job := waitJob(t, svc, body["job_id"].(string)); job.Status != JobSuccess {
		t.Fatalf("释放容量后的任务应成功: %+v", job)
	}
	waitActiveJobs(t, svc, 0)
}

func TestWorkerPoolKeepsSameServiceActionsSerial(t *testing.T) {
	engine, dc := newFakeEngine(t)
	engine.addContainer(&fakeContainer{name: "proj-web-1", service: "web", running: true})
	engine.restartStarted = make(chan struct{}, 2)
	engine.restartRelease = make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(engine.restartRelease) }) }
	t.Cleanup(release)
	svc := newTestService(t, dc, shortTempDir(t), "proj", "web")

	code, body := submitAction(t, svc, "web", `{"action":"restart"}`)
	if code != http.StatusAccepted {
		t.Fatalf("第一个任务应受理: code=%d body=%v", code, body)
	}
	firstID := body["job_id"].(string)
	select {
	case <-engine.restartStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("第一个 restart 未到达 Engine")
	}
	code, body = submitAction(t, svc, "web", `{"action":"restart"}`)
	if code != http.StatusAccepted {
		t.Fatalf("第二个任务应受理: code=%d body=%v", code, body)
	}
	secondID := body["job_id"].(string)
	select {
	case <-engine.restartStarted:
		t.Fatal("同一服务的第二个 restart 在第一个完成前进入 Engine")
	case <-time.After(150 * time.Millisecond):
	}
	release()
	for _, id := range []string{firstID, secondID} {
		if job := waitJob(t, svc, id); job.Status != JobSuccess {
			t.Fatalf("串行任务应成功: %+v", job)
		}
	}
	waitActiveJobs(t, svc, 0)
}

func TestAsyncResultPersistenceFailureKeepsLastDurableState(t *testing.T) {
	engine, dc := newFakeEngine(t)
	engine.addContainer(&fakeContainer{name: "proj-web-1", service: "web", running: true})
	engine.restartStarted = make(chan struct{}, 1)
	engine.restartRelease = make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(engine.restartRelease) }) }
	t.Cleanup(release)
	svc := newTestService(t, dc, shortTempDir(t), "proj", "web")
	var logs synchronizedBuffer
	svc.logger = slog.New(slog.NewTextHandler(&logs, nil))

	code, body := submitAction(t, svc, "web", `{"action":"restart"}`)
	if code != http.StatusAccepted {
		t.Fatalf("受理应 202: code=%d body=%v", code, body)
	}
	jobID := body["job_id"].(string)
	select {
	case <-engine.restartStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("restart 未到达 Engine")
	}
	restore := replaceJobDirWithFile(t, svc.jobs)
	release()
	waitActiveJobs(t, svc, 0)
	job, ok := svc.jobs.get(jobID)
	if !ok || job.Status != JobRunning || job.StartedAt == nil || job.FinishedAt != nil {
		t.Fatalf("结果落盘失败时应保留 RUNNING: %+v", job)
	}
	if logsText := logs.String(); !strings.Contains(logsText, "持久化运维任务结果失败") || !strings.Contains(logsText, jobID) {
		t.Fatalf("最终状态落盘失败未记录完整日志: %s", logsText)
	}
	restore()
	raw, err := os.ReadFile(filepath.Join(svc.jobs.dir, jobID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var persisted ActionJob
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.Status != JobRunning || persisted.StartedAt == nil || persisted.FinishedAt != nil {
		t.Fatalf("磁盘应保留与内存一致的 RUNNING 状态: %+v", persisted)
	}
}
