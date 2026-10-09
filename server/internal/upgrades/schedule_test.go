package upgrades

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
)

// ---------- scheduled_at 解析与边界 ----------

// TestParseScheduledAt 定时时间校验矩阵：过去/太近拒绝，恰好 now+2 分钟与
// 恰好 now+90 天为合法边界，超出 90 天拒绝，缺时区/非 RFC3339 拒绝。
func TestParseScheduledAt(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	cst := time.FixedZone("CST", 8*3600)
	cases := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{"过去时间", now.Add(-time.Hour).Format(time.RFC3339), true},
		{"1 分钟内（太近）", now.Add(time.Minute).Format(time.RFC3339), true},
		{"差 1 秒到 2 分钟", now.Add(2*time.Minute - time.Second).Format(time.RFC3339), true},
		{"恰好 2 分钟边界", now.Add(2 * time.Minute).Format(time.RFC3339), false},
		{"正常 +1 小时", now.Add(time.Hour).Format(time.RFC3339), false},
		{"恰好 90 天边界", now.Add(90 * 24 * time.Hour).Format(time.RFC3339), false},
		{"90 天外多 1 秒", now.Add(90*24*time.Hour + time.Second).Format(time.RFC3339), true},
		{"缺时区", "2026-09-20T12:00:00", true},
		{"空格分隔非 RFC3339", "2026-09-20 12:00:00+08:00", true},
		{"垃圾字符串", "not-a-time", true},
		{"空串", "", true},
		{"带 +08:00 时区", now.Add(3 * time.Hour).In(cst).Format(time.RFC3339), false},
	}
	for _, c := range cases {
		got, err := ParseScheduledAt(c.in, now)
		if c.wantErr {
			if err == nil {
				t.Errorf("%s: 应报错", c.name)
			} else if !errors.Is(err, ErrInvalidInput) {
				t.Errorf("%s: 错误应包装 ErrInvalidInput, got %v", c.name, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: 意外报错: %v", c.name, err)
			continue
		}
		if got.Location() != time.UTC {
			t.Errorf("%s: 结果应统一为 UTC, got %v", c.name, got.Location())
		}
	}
	// 带时区解析后时刻一致（+08:00 与 UTC 表示同一时刻）
	want := now.Add(3 * time.Hour)
	got, err := ParseScheduledAt(now.Add(3*time.Hour).In(cst).Format(time.RFC3339), now)
	if err != nil || !got.Equal(want) {
		t.Errorf("+08:00 解析 = %v, %v; want %v", got, err, want)
	}
}

// ---------- 状态机扩展 ----------

func TestScheduledTransitions(t *testing.T) {
	legal := [][2]string{
		{StatusScheduled, StatusPending},   // 到点 promote 进入正常执行流程
		{StatusScheduled, StatusCancelled}, // 定时任务取消
	}
	for _, tr := range legal {
		if !CanTransition(tr[0], tr[1]) {
			t.Errorf("CanTransition(%s,%s) 应为合法", tr[0], tr[1])
		}
	}
	illegal := [][2]string{
		{StatusScheduled, StatusPrecheck},
		{StatusScheduled, StatusSuccess},
		{StatusPending, StatusCancelled}, // 已开始任务不可取消
		{StatusPrecheck, StatusCancelled},
		{StatusCancelled, StatusPending},
		{StatusCancelled, StatusRollingBack},
	}
	for _, tr := range illegal {
		if CanTransition(tr[0], tr[1]) {
			t.Errorf("CanTransition(%s,%s) 应为非法", tr[0], tr[1])
		}
	}
	for _, s := range []string{StatusScheduled, StatusCancelled} {
		if !ValidStatus(s) {
			t.Errorf("ValidStatus(%s) 应为 true", s)
		}
	}
	if !TerminalStatus(StatusCancelled) {
		t.Error("CANCELLED 应为终态")
	}
	if TerminalStatus(StatusScheduled) {
		t.Error("SCHEDULED 不应为终态")
	}
}

// ---------- 内存版定时任务存储（同 handler 测试替换模式） ----------

type fakeScheduleStore struct {
	pkg        *Package
	jobs       map[uuid.UUID]*Job
	createErr  error
	promoteErr error
	promoted   []uuid.UUID
	cancelled  []uuid.UUID
}

func (f *fakeScheduleStore) GetPackage(_ context.Context, id uuid.UUID) (*Package, error) {
	if f.pkg == nil || f.pkg.ID != id {
		return nil, ErrNotFound
	}
	return f.pkg, nil
}

func (f *fakeScheduleStore) GetJob(_ context.Context, id uuid.UUID) (*Job, error) {
	if j, ok := f.jobs[id]; ok {
		return j, nil
	}
	return nil, ErrNotFound
}

func (f *fakeScheduleStore) CreateScheduledJobIfNoActive(_ context.Context, packageID uuid.UUID, requestedBy *uuid.UUID, requestID string, scheduledAt time.Time) (*Job, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	at := scheduledAt
	job := &Job{
		ID: uuid.New(), PackageID: &packageID, Status: StatusScheduled, ScheduledAt: &at,
		RequestedBy: requestedBy, RequestedAt: time.Now().UTC(), RequestID: requestID,
	}
	if f.jobs == nil {
		f.jobs = map[uuid.UUID]*Job{}
	}
	f.jobs[job.ID] = job
	return job, nil
}

func (f *fakeScheduleStore) ListDueScheduledJobs(_ context.Context, now time.Time) ([]Job, error) {
	var out []Job
	for _, j := range f.jobs {
		if j.Status == StatusScheduled && j.ScheduledAt != nil && !j.ScheduledAt.After(now) {
			out = append(out, *j)
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].ScheduledAt.Before(*out[b].ScheduledAt) })
	return out, nil
}

func (f *fakeScheduleStore) PromoteScheduledToPending(_ context.Context, id uuid.UUID, now time.Time) error {
	j, ok := f.jobs[id]
	if !ok || j.Status != StatusScheduled || j.ScheduledAt == nil || j.ScheduledAt.After(now) {
		return fmt.Errorf("%w: 定时任务不存在、已取消或未到执行时间", ErrInvalidStatus)
	}
	if f.promoteErr != nil {
		return f.promoteErr
	}
	j.Status = StatusPending
	f.promoted = append(f.promoted, id)
	return nil
}

func (f *fakeScheduleStore) CancelScheduled(_ context.Context, id uuid.UUID) error {
	j, ok := f.jobs[id]
	if !ok || j.Status != StatusScheduled {
		return fmt.Errorf("%w: 任务已开始，无法取消", ErrInvalidStatus)
	}
	j.Status = StatusCancelled
	f.cancelled = append(f.cancelled, id)
	return nil
}

func newScheduleTestService(store *fakeScheduleStore, now time.Time) (*Service, *[]uuid.UUID, *[]audits.RecordInput) {
	started := &[]uuid.UUID{}
	auditInputs := &[]audits.RecordInput{}
	svc := NewService(nil, nil, nil, nil, nil, "", nil).
		SetScheduleStore(store).
		SetNowFunc(func() time.Time { return now }).
		SetStartRunFunc(func(id uuid.UUID) { *started = append(*started, id) }).
		SetAuditFunc(func(_ context.Context, in audits.RecordInput) error {
			*auditInputs = append(*auditInputs, in)
			return nil
		})
	return svc, started, auditInputs
}

// ---------- Service.Schedule ----------

func TestServiceSchedule(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	pkgID := uuid.New()
	scheduledAt := now.Add(time.Hour)

	// VERIFIED 包 → SCHEDULED 任务落库，不启动执行
	store := &fakeScheduleStore{pkg: &Package{ID: pkgID, Status: PackageVerified}}
	svc, started, _ := newScheduleTestService(store, now)
	job, err := svc.Schedule(context.Background(), pkgID, uuid.New(), "req-1", scheduledAt)
	if err != nil {
		t.Fatalf("Schedule 意外失败: %v", err)
	}
	if job.Status != StatusScheduled {
		t.Errorf("状态 = %s, want SCHEDULED", job.Status)
	}
	if job.ScheduledAt == nil || !job.ScheduledAt.Equal(scheduledAt) {
		t.Errorf("scheduled_at = %v, want %v", job.ScheduledAt, scheduledAt)
	}
	if len(*started) != 0 {
		t.Error("定时任务创建后不得立即启动执行")
	}

	// REJECTED 包 → ErrPackageNotVerified
	store.pkg.Status = PackageRejected
	if _, err := svc.Schedule(context.Background(), pkgID, uuid.New(), "req-2", scheduledAt); !errors.Is(err, ErrPackageNotVerified) {
		t.Errorf("REJECTED 包应返回 ErrPackageNotVerified, got %v", err)
	}

	// 包不存在 → ErrNotFound
	if _, err := svc.Schedule(context.Background(), uuid.New(), uuid.New(), "req-3", scheduledAt); !errors.Is(err, ErrNotFound) {
		t.Errorf("不存在包应返回 ErrNotFound, got %v", err)
	}

	// 活动任务冲突 → 如实传递 ErrActiveUpgrade
	store.pkg.Status = PackageVerified
	store.createErr = ErrActiveUpgrade
	if _, err := svc.Schedule(context.Background(), pkgID, uuid.New(), "req-4", scheduledAt); !errors.Is(err, ErrActiveUpgrade) {
		t.Errorf("冲突应返回 ErrActiveUpgrade, got %v", err)
	}
}

// ---------- 到点 promote ----------

// TestPromoteDueScheduled 到点任务 promote 为 PENDING 并启动执行、记高危审计；
// 未到点任务不动；promote 失败记失败审计且不启动。
func TestPromoteDueScheduled(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	requester := uuid.New()
	dueAt := now.Add(-time.Minute)
	futureAt := now.Add(time.Hour)
	dueJob := &Job{ID: uuid.New(), Status: StatusScheduled, ScheduledAt: &dueAt, RequestedBy: &requester, RequestID: "req-due"}
	futureJob := &Job{ID: uuid.New(), Status: StatusScheduled, ScheduledAt: &futureAt, RequestedBy: &requester, RequestID: "req-future"}
	store := &fakeScheduleStore{jobs: map[uuid.UUID]*Job{dueJob.ID: dueJob, futureJob.ID: futureJob}}
	svc, started, auditInputs := newScheduleTestService(store, now)

	svc.promoteDueScheduled(context.Background())

	if dueJob.Status != StatusPending {
		t.Errorf("到点任务状态 = %s, want PENDING", dueJob.Status)
	}
	if futureJob.Status != StatusScheduled {
		t.Errorf("未到点任务状态 = %s, want SCHEDULED", futureJob.Status)
	}
	if len(*started) != 1 || (*started)[0] != dueJob.ID {
		t.Fatalf("应仅启动到点任务, started = %v", *started)
	}
	if len(*auditInputs) != 1 {
		t.Fatalf("promote 应记 1 条审计, got %d", len(*auditInputs))
	}
	in := (*auditInputs)[0]
	if in.Action != "scheduled_execute" || in.RiskLevel != audits.RiskHigh || in.Result != audits.ResultSuccess {
		t.Errorf("审计 = action:%s risk:%s result:%s, want scheduled_execute/HIGH/SUCCESS", in.Action, in.RiskLevel, in.Result)
	}
	if in.UserID == nil || *in.UserID != requester {
		t.Error("审计操作人应取任务创建人")
	}
	if in.Module != "upgrades" || in.ObjectID != dueJob.ID.String() || in.RequestID != "req-due" {
		t.Errorf("审计上下文不符: %+v", in)
	}

	// promote 失败（如与取消竞争失败/存储异常）→ 失败审计，不启动执行
	*started, *auditInputs = nil, nil
	dueJob.Status = StatusScheduled // 复位为待 promote 状态
	store.promoteErr = errors.New("db down")
	svc.promoteDueScheduled(context.Background())
	if len(*started) != 0 {
		t.Error("promote 失败不得启动执行")
	}
	if len(*auditInputs) != 1 || (*auditInputs)[0].Result != audits.ResultFailure || (*auditInputs)[0].FailureReason == "" {
		t.Fatalf("promote 失败应记失败审计并带原因: %+v", *auditInputs)
	}
}

// TestRunSchedulerTick 调度器按周期检查（注入时钟与启动入口，首 tick 即生效）。
func TestRunSchedulerTick(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	dueAt := now.Add(-time.Second)
	dueJob := &Job{ID: uuid.New(), Status: StatusScheduled, ScheduledAt: &dueAt}
	store := &fakeScheduleStore{jobs: map[uuid.UUID]*Job{dueJob.ID: dueJob}}
	svc, _, _ := newScheduleTestService(store, now)
	svc.SetScheduleTick(time.Hour) // 只需首个即时 tick，避免测试依赖真实等待

	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan uuid.UUID, 1)
	svc.SetStartRunFunc(func(id uuid.UUID) {
		select {
		case started <- id:
		case <-ctx.Done():
		}
	})
	done := make(chan struct{})
	go func() { svc.RunScheduler(ctx); close(done) }()
	defer func() {
		cancel()
		<-done
	}()
	select {
	case id := <-started:
		if id != dueJob.ID {
			t.Fatalf("启动任务 = %v, want %v", id, dueJob.ID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("调度器首 tick 未 promote 到点任务")
	}
	cancel()
	<-done
	if dueJob.Status != StatusPending {
		t.Errorf("到点任务状态 = %s, want PENDING", dueJob.Status)
	}
}

// ---------- Service.Cancel 状态守卫 ----------

func TestServiceCancelGuard(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	at := now.Add(time.Hour)

	// SCHEDULED → 取消成功，转为 CANCELLED
	schedJob := &Job{ID: uuid.New(), Status: StatusScheduled, ScheduledAt: &at}
	store := &fakeScheduleStore{jobs: map[uuid.UUID]*Job{schedJob.ID: schedJob}}
	svc, started, _ := newScheduleTestService(store, now)
	job, err := svc.Cancel(context.Background(), schedJob.ID, uuid.New())
	if err != nil {
		t.Fatalf("Cancel 意外失败: %v", err)
	}
	if job.Status != StatusCancelled {
		t.Errorf("状态 = %s, want CANCELLED", job.Status)
	}
	if len(store.cancelled) != 1 || store.cancelled[0] != schedJob.ID {
		t.Errorf("取消应落库一次: %v", store.cancelled)
	}
	if len(*started) != 0 {
		t.Error("取消不得启动执行")
	}

	// PENDING 及以后 → ErrInvalidStatus「任务已开始，无法取消」
	for _, status := range []string{StatusPending, StatusPrecheck, StatusApplying, StatusSuccess, StatusCancelled} {
		j := &Job{ID: uuid.New(), Status: status, ScheduledAt: &at}
		store.jobs[j.ID] = j
		_, err := svc.Cancel(context.Background(), j.ID, uuid.New())
		if !errors.Is(err, ErrInvalidStatus) {
			t.Errorf("%s: 应返回 ErrInvalidStatus, got %v", status, err)
			continue
		}
		if !strings.Contains(err.Error(), "任务已开始，无法取消") {
			t.Errorf("%s: 错误信息应为「任务已开始，无法取消」, got %q", status, err.Error())
		}
	}

	// 不存在 → ErrNotFound
	if _, err := svc.Cancel(context.Background(), uuid.New(), uuid.New()); !errors.Is(err, ErrNotFound) {
		t.Errorf("不存在任务应返回 ErrNotFound, got %v", err)
	}
}

// ---------- 上传定时路径 ----------

// TestUploadPackageScheduled 上传指定 scheduled_at：VERIFIED 后创建 SCHEDULED 定时任务，
// 不立即执行；execution 带 scheduled_at；审计 action=schedule 高危。
func TestUploadPackageScheduled(t *testing.T) {
	content, pub, _ := embeddedPackageBytes(t, "2.0.0", "2.1.0", 0)
	h, _, exec, _ := newUploadTestHandler(t, pub)
	var auditInputs []audits.RecordInput
	h.SetAuditRecorder(func(_ *http.Request, _ *authz.Principal, action, objID, _, result, risk, failReason string) {
		auditInputs = append(auditInputs, audits.RecordInput{
			Action: action, ObjectID: objID, Result: result, RiskLevel: risk, FailureReason: failReason,
		})
	})

	scheduledAt := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	code, msg, result := serveUpload(t, h, buildUploadRequest(t, "jiuzhang-offline-2.1.0.tar.gz", content,
		map[string]string{"scheduled_at": scheduledAt.Format(time.RFC3339)}))
	if code != http.StatusOK {
		t.Fatalf("状态码 = %d, want 200 (%s)", code, msg)
	}
	if result.Package == nil || result.Package.Status != PackageVerified {
		t.Fatalf("包应为 VERIFIED: %+v", result.Package)
	}
	if result.Execution == nil {
		t.Fatal("定时上传验证通过后应创建执行")
	}
	if result.Execution.Status != StatusScheduled {
		t.Errorf("执行状态 = %s, want SCHEDULED", result.Execution.Status)
	}
	if result.Execution.ScheduledAt == nil || !result.Execution.ScheduledAt.Equal(scheduledAt) {
		t.Errorf("execution.scheduled_at = %v, want %v", result.Execution.ScheduledAt, scheduledAt)
	}
	if exec.scheduleCalls != 1 || exec.calls != 0 {
		t.Errorf("应走定时分支（schedule=%d）且不立即执行（execute=%d）", exec.scheduleCalls, exec.calls)
	}
	if !exec.lastScheduleAt.Equal(scheduledAt) {
		t.Errorf("传给服务的 scheduled_at = %v, want %v", exec.lastScheduleAt, scheduledAt)
	}
	if result.Warning != "" {
		t.Errorf("定时创建成功不应有 warning: %s", result.Warning)
	}
	// 审计：upload_package（中危）+ schedule（高危）
	var sawSchedule bool
	for _, in := range auditInputs {
		if in.Action == "schedule" {
			sawSchedule = true
			if in.RiskLevel != audits.RiskHigh || in.Result != audits.ResultSuccess {
				t.Errorf("schedule 审计 = risk:%s result:%s, want HIGH/SUCCESS", in.RiskLevel, in.Result)
			}
		}
	}
	if !sawSchedule {
		t.Errorf("缺少 schedule 审计: %+v", auditInputs)
	}
}

// TestUploadPackageScheduledAtRejected scheduled_at 非法一律 400（中文提示），
// 不登记包、不创建执行。
func TestUploadPackageScheduledAtRejected(t *testing.T) {
	content, pub, _ := embeddedPackageBytes(t, "2.0.0", "2.1.0", 0)
	now := time.Now().UTC()
	bad := map[string]string{
		"过去时间":      now.Add(-time.Hour).Format(time.RFC3339),
		"1 分钟内":     now.Add(time.Minute).Format(time.RFC3339),
		"90 天外":     now.Add(91 * 24 * time.Hour).Format(time.RFC3339),
		"缺时区":       "2026-09-20T12:00:00",
		"非 RFC3339": "2026-09-20 12:00:00",
	}
	for name, value := range bad {
		h, reg, exec, _ := newUploadTestHandler(t, pub)
		code, msg, result := serveUpload(t, h, buildUploadRequest(t, "pkg-"+name+".tar.gz", content,
			map[string]string{"scheduled_at": value}))
		if code != http.StatusBadRequest {
			t.Errorf("%s: 状态码 = %d, want 400 (%s)", name, code, msg)
		}
		if result.Package != nil {
			t.Errorf("%s: 非法 scheduled_at 不得登记包", name)
		}
		if len(reg.byHash) != 0 {
			t.Errorf("%s: 非法 scheduled_at 不得落库", name)
		}
		if exec.calls != 0 || exec.scheduleCalls != 0 {
			t.Errorf("%s: 非法 scheduled_at 不得创建执行", name)
		}
	}
}

// TestUploadPackageScheduledConflictWarning 定时任务创建失败（已有执行中任务）：
// 包保持 VERIFIED，execution 为 null 且 warning 说明，schedule 审计记失败。
func TestUploadPackageScheduledConflictWarning(t *testing.T) {
	content, pub, _ := embeddedPackageBytes(t, "2.0.0", "2.1.0", 0)
	h, _, exec, _ := newUploadTestHandler(t, pub)
	exec.err = ErrActiveUpgrade

	scheduledAt := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	code, _, result := serveUpload(t, h, buildUploadRequest(t, "jiuzhang-offline-2.1.0.tar.gz", content,
		map[string]string{"scheduled_at": scheduledAt}))
	if code != http.StatusOK {
		t.Fatalf("状态码 = %d, want 200", code)
	}
	if result.Package == nil || result.Package.Status != PackageVerified {
		t.Fatalf("包应保持 VERIFIED: %+v", result.Package)
	}
	if result.Execution != nil {
		t.Error("定时创建失败时 execution 应为 null")
	}
	if !strings.Contains(result.Warning, "手动执行") {
		t.Errorf("warning 应说明可手动执行: %q", result.Warning)
	}
	if exec.scheduleCalls != 1 || exec.calls != 0 {
		t.Errorf("应仅尝试定时分支: schedule=%d execute=%d", exec.scheduleCalls, exec.calls)
	}
}

// ---------- Cancel 接口 ----------

type fakeUpgradeCanceller struct {
	job   *Job
	err   error
	calls int
}

func (f *fakeUpgradeCanceller) Cancel(_ context.Context, _, _ uuid.UUID) (*Job, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.job, nil
}

func serveCancel(t *testing.T, h *Handler, id string) (int, string, *Job) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/upgrades/"+id+"/cancel", nil)
	r.SetPathValue("id", id)
	principal := &authz.Principal{UserID: uuid.New(), Username: "tester"}
	r = r.WithContext(authz.WithPrincipal(r.Context(), principal))
	rec := httptest.NewRecorder()
	h.Cancel(rec, r)
	var body struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Job *Job `json:"job"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("响应不是合法 JSON: %v, body=%s", err, rec.Body.String())
	}
	return rec.Code, body.Code + " " + body.Message, body.Data.Job
}

// TestCancelHandler 取消接口：SCHEDULED 成功（200 + CANCELLED + 中危审计），
// PENDING 409「任务已开始，无法取消」，不存在 404，非法 ID 400。
func TestCancelHandler(t *testing.T) {
	at := time.Now().Add(time.Hour).UTC()
	cancelled := &Job{ID: uuid.New(), Status: StatusCancelled, ScheduledAt: &at}

	t.Run("SCHEDULED 取消成功", func(t *testing.T) {
		fake := &fakeUpgradeCanceller{job: cancelled}
		h := NewHandler(nil, nil, audits.NewService(nil)).SetCanceller(fake)
		var auditInputs []audits.RecordInput
		h.SetAuditRecorder(func(_ *http.Request, _ *authz.Principal, action, objID, _, result, risk, _ string) {
			auditInputs = append(auditInputs, audits.RecordInput{Action: action, ObjectID: objID, Result: result, RiskLevel: risk})
		})
		code, msg, job := serveCancel(t, h, cancelled.ID.String())
		if code != http.StatusOK {
			t.Fatalf("状态码 = %d, want 200 (%s)", code, msg)
		}
		if job == nil || job.Status != StatusCancelled {
			t.Errorf("返回任务应为 CANCELLED: %+v", job)
		}
		if fake.calls != 1 {
			t.Errorf("取消服务应调用一次, got %d", fake.calls)
		}
		if len(auditInputs) != 1 || auditInputs[0].Action != "cancel" || auditInputs[0].RiskLevel != audits.RiskMedium {
			t.Errorf("取消应记中危 cancel 审计: %+v", auditInputs)
		}
	})

	t.Run("PENDING 409 任务已开始", func(t *testing.T) {
		fake := &fakeUpgradeCanceller{err: fmt.Errorf("%w: 任务已开始，无法取消（当前状态 %s）", ErrInvalidStatus, StatusPending)}
		h := NewHandler(nil, nil, audits.NewService(nil)).SetCanceller(fake)
		code, msg, job := serveCancel(t, h, uuid.New().String())
		if code != http.StatusConflict {
			t.Fatalf("状态码 = %d, want 409 (%s)", code, msg)
		}
		if !strings.Contains(msg, "任务已开始，无法取消") {
			t.Errorf("409 文案应为「任务已开始，无法取消」: %q", msg)
		}
		if job != nil {
			t.Error("409 不应返回任务")
		}
	})

	t.Run("不存在 404", func(t *testing.T) {
		fake := &fakeUpgradeCanceller{err: ErrNotFound}
		h := NewHandler(nil, nil, audits.NewService(nil)).SetCanceller(fake)
		code, msg, _ := serveCancel(t, h, uuid.New().String())
		if code != http.StatusNotFound {
			t.Fatalf("状态码 = %d, want 404 (%s)", code, msg)
		}
	})

	t.Run("非法 ID 400", func(t *testing.T) {
		fake := &fakeUpgradeCanceller{}
		h := NewHandler(nil, nil, audits.NewService(nil)).SetCanceller(fake)
		code, _, _ := serveCancel(t, h, "not-a-uuid")
		if code != http.StatusBadRequest {
			t.Fatalf("状态码 = %d, want 400", code)
		}
		if fake.calls != 0 {
			t.Error("非法 ID 不得调用取消服务")
		}
	})
}
