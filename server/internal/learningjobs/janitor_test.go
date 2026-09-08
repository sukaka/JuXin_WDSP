package learningjobs

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apiassets"
	"github.com/jiuzhang-waf/server/internal/apimodels"
	"github.com/jiuzhang-waf/server/internal/audits"
)

type fakeJobs struct {
	jobs        []apiassets.LearningJobProgress
	completed   []uuid.UUID
	errors      map[uuid.UUID]string
	failed      map[uuid.UUID]string
	attached    map[uuid.UUID]uuid.UUID
	completeErr error
	failErr     error
	attachErr   error
}

func (f *fakeJobs) ListRunningLearningJobs(_ context.Context) ([]apiassets.LearningJobProgress, error) {
	return f.jobs, nil
}

func (f *fakeJobs) CompleteLearning(_ context.Context, jobID, endpointID uuid.UUID, actor, reason string) (*apiassets.LearningJob, error) {
	if f.completeErr != nil {
		return nil, f.completeErr
	}
	f.completed = append(f.completed, jobID)
	for i := range f.jobs {
		if f.jobs[i].ID == jobID {
			f.jobs[i].Status = "COMPLETED"
			cp := f.jobs[i].LearningJob
			return &cp, nil
		}
	}
	return nil, apiassets.ErrLearningNotRunning
}

func (f *fakeJobs) FailLearning(_ context.Context, jobID uuid.UUID, cause string) error {
	if f.failErr != nil {
		return f.failErr
	}
	if f.failed == nil {
		f.failed = map[uuid.UUID]string{}
	}
	for i := range f.jobs {
		if f.jobs[i].ID == jobID && f.jobs[i].Status == "RUNNING" {
			f.jobs[i].Status = "FAILED"
			f.failed[jobID] = cause
			return nil
		}
	}
	return apiassets.ErrLearningNotRunning
}

func (f *fakeJobs) RecordLearningError(_ context.Context, jobID uuid.UUID, cause string) error {
	if f.errors == nil {
		f.errors = map[uuid.UUID]string{}
	}
	f.errors[jobID] = cause
	return nil
}

func (f *fakeJobs) AttachLearningCandidate(_ context.Context, jobID, versionID uuid.UUID) error {
	if f.attachErr != nil {
		return f.attachErr
	}
	if f.attached == nil {
		f.attached = map[uuid.UUID]uuid.UUID{}
	}
	f.attached[jobID] = versionID
	return nil
}

type fakeCandidates struct {
	created      []*apimodels.Version
	validSamples []int
	createErr    error
	keyErr       error
}

func (f *fakeCandidates) EndpointKey(_ context.Context, endpointID uuid.UUID) (string, error) {
	if f.keyErr != nil {
		return "", f.keyErr
	}
	return "GET /v1/a", nil
}

func (f *fakeCandidates) CreateLearnedCandidate(_ context.Context, endpointID uuid.UUID, endpointKey string, validSamples int) (*apimodels.Version, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	// 模拟真实实现：候选创建后自动提交评审（IN_REVIEW）
	v := &apimodels.Version{ID: uuid.New(), EndpointID: endpointID, EndpointKey: endpointKey,
		VersionNumber: 1, Status: apimodels.StatusInReview, CreatedReason: apimodels.CreatedReasonLearningThreshold}
	f.created = append(f.created, v)
	f.validSamples = append(f.validSamples, validSamples)
	return v, nil
}

type fakeAudit struct{ inputs []audits.RecordInput }

func (f *fakeAudit) Record(_ context.Context, in audits.RecordInput) error {
	f.inputs = append(f.inputs, in)
	return nil
}

// reachedJob 满足全部默认条件（样本达标、来源≥1、未超期、成功率不判定）的 RUNNING 任务。
func reachedJob() apiassets.LearningJobProgress {
	return apiassets.LearningJobProgress{
		LearningJob: apiassets.LearningJob{
			ID: uuid.New(), EndpointID: uuid.New(), Status: "RUNNING",
			SampleTarget: 100, CollectedCount: 120, ValidCount: 100, ExcludedCount: 20,
			StartedAt: time.Now().Add(-time.Hour),
		},
		UniqueIPs:         3,
		StatusSampleCount: 100,
		SuccessCount:      100,
	}
}

// TestSweepOnceThresholdReached 达标：COMPLETED + 自动候选（IN_REVIEW）+ 回填候选版本 + 审计。
func TestSweepOnceThresholdReached(t *testing.T) {
	job := reachedJob()
	jobs := &fakeJobs{jobs: []apiassets.LearningJobProgress{job}}
	cands := &fakeCandidates{}
	aud := &fakeAudit{}
	w := NewWorker(jobs, cands, aud, nil)

	stats, err := w.SweepOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Scanned != 1 || stats.Completed != 1 || stats.Failed != 0 || stats.Expired != 0 {
		t.Fatalf("stats=%+v", stats)
	}
	if len(jobs.completed) != 1 || jobs.completed[0] != job.ID {
		t.Fatalf("completed=%v", jobs.completed)
	}
	if len(cands.created) != 1 {
		t.Fatalf("candidates=%d", len(cands.created))
	}
	v := cands.created[0]
	if v.Status != apimodels.StatusInReview {
		t.Fatalf("auto candidate status=%q, want IN_REVIEW（自动提交评审）", v.Status)
	}
	if v.CreatedReason != apimodels.CreatedReasonLearningThreshold {
		t.Fatalf("created_reason=%q", v.CreatedReason)
	}
	if cands.validSamples[0] != job.ValidCount {
		t.Fatalf("validSamples=%d, want %d", cands.validSamples[0], job.ValidCount)
	}
	if jobs.attached[job.ID] != v.ID {
		t.Fatalf("candidate_version_id attach=%v, want %v", jobs.attached[job.ID], v.ID)
	}
	if len(aud.inputs) != 1 || aud.inputs[0].Module != "api_learning" || aud.inputs[0].Username != "system" {
		t.Fatalf("audit=%+v", aud.inputs)
	}
	if !strings.Contains(aud.inputs[0].AfterSummary, "自动提交评审") {
		t.Fatalf("audit summary should mention auto submit: %q", aud.inputs[0].AfterSummary)
	}
	if len(jobs.errors) != 0 {
		t.Fatalf("unexpected last_error: %v", jobs.errors)
	}
}

// TestSweepOnceNotReached 未达标与 sample_target=0：不动（未超期不判 FAILED）。
func TestSweepOnceNotReached(t *testing.T) {
	base := reachedJob()
	notReached := base
	notReached.ID = uuid.New()
	notReached.ValidCount = 99
	zeroTarget := base
	zeroTarget.ID = uuid.New()
	zeroTarget.SampleTarget = 0
	zeroTarget.ValidCount = 0
	jobs := &fakeJobs{jobs: []apiassets.LearningJobProgress{notReached, zeroTarget}}
	cands := &fakeCandidates{}
	w := NewWorker(jobs, cands, &fakeAudit{}, nil)

	stats, err := w.SweepOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Scanned != 2 || stats.Completed != 0 || stats.Failed != 0 || stats.Expired != 0 {
		t.Fatalf("stats=%+v", stats)
	}
	if len(jobs.completed) != 0 || len(cands.created) != 0 || len(jobs.failed) != 0 {
		t.Fatalf("should not touch jobs: completed=%v created=%v failed=%v",
			jobs.completed, cands.created, jobs.failed)
	}
}

// TestSweepOnceExpiredJobFailed 超期未达标：任务置 FAILED + last_error 说明，不产生候选。
func TestSweepOnceExpiredJobFailed(t *testing.T) {
	job := reachedJob()
	job.ValidCount = 5 // 样本不足
	job.StartedAt = time.Now().Add(-8 * 24 * time.Hour)
	job.FirstSampleAt = nil // 回退 started_at，超默认最长时限 7 天
	jobs := &fakeJobs{jobs: []apiassets.LearningJobProgress{job}}
	cands := &fakeCandidates{}
	w := NewWorker(jobs, cands, &fakeAudit{}, nil)

	stats, err := w.SweepOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Expired != 1 || stats.Completed != 0 || stats.Failed != 0 {
		t.Fatalf("stats=%+v", stats)
	}
	cause, ok := jobs.failed[job.ID]
	if !ok {
		t.Fatalf("job should be FAILED: %+v", jobs.failed)
	}
	if !strings.Contains(cause, "超过最长时限") || !strings.Contains(cause, "有效样本数不足") {
		t.Fatalf("last_error should explain expiry and unmet conditions: %q", cause)
	}
	if len(jobs.completed) != 0 || len(cands.created) != 0 {
		t.Fatal("expired job must not be completed or produce candidate")
	}
}

// TestSweepOnceUnmetNotExpired 未达标但未超期：跳过等待下轮（不 FAILED、不完成）。
func TestSweepOnceUnmetNotExpired(t *testing.T) {
	job := reachedJob()
	job.UniqueIPs = 0 // 来源多样性不足（默认下限 1）
	jobs := &fakeJobs{jobs: []apiassets.LearningJobProgress{job}}
	w := NewWorker(jobs, &fakeCandidates{}, &fakeAudit{}, nil)

	stats, err := w.SweepOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Completed != 0 || stats.Expired != 0 || stats.Failed != 0 {
		t.Fatalf("stats=%+v", stats)
	}
	if len(jobs.failed) != 0 {
		t.Fatalf("unexpired unmet job must not fail: %v", jobs.failed)
	}
}

// TestSweepOnceFailureDoesNotBlockOthers 单任务失败继续：失败记 last_error，其他任务照常完成。
func TestSweepOnceFailureDoesNotBlockOthers(t *testing.T) {
	bad := reachedJob()
	good := reachedJob()
	jobs := &fakeJobs{jobs: []apiassets.LearningJobProgress{bad, good}}
	cands := &fakeCandidates{}
	// 第一个任务候选创建失败（完成已提交），第二个照常
	call := 0
	candsWithFail := &flakyCandidates{fakeCandidates: cands, failOnCall: 1, call: &call}
	w := NewWorker(jobs, candsWithFail, &fakeAudit{}, nil)

	stats, err := w.SweepOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Completed != 1 || stats.Failed != 1 {
		t.Fatalf("stats=%+v", stats)
	}
	if len(jobs.completed) != 2 {
		t.Fatalf("both jobs should be completed (complete precedes candidate): %v", jobs.completed)
	}
	if len(jobs.errors) != 1 {
		t.Fatalf("last_error should be recorded once: %v", jobs.errors)
	}
	if _, ok := jobs.errors[bad.ID]; !ok {
		t.Fatalf("last_error should be on the failed job: %v", jobs.errors)
	}
	// 失败任务未回填候选版本；成功任务已回填
	if _, ok := jobs.attached[bad.ID]; ok {
		t.Fatal("failed job must not attach candidate")
	}
	if _, ok := jobs.attached[good.ID]; !ok {
		t.Fatal("succeeded job should attach candidate")
	}
}

// flakyCandidates 第 failOnCall 次创建失败（1 起计）。
type flakyCandidates struct {
	*fakeCandidates
	failOnCall int
	call       *int
}

func (f *flakyCandidates) CreateLearnedCandidate(ctx context.Context, endpointID uuid.UUID, endpointKey string, validSamples int) (*apimodels.Version, error) {
	*f.call++
	if *f.call == f.failOnCall {
		return nil, errors.New("insert conflict")
	}
	return f.fakeCandidates.CreateLearnedCandidate(ctx, endpointID, endpointKey, validSamples)
}

// TestSweepOnceCompleteFailure 完成动作本身失败：任务留 RUNNING 可下轮重试，记 last_error。
func TestSweepOnceCompleteFailure(t *testing.T) {
	job := reachedJob()
	jobs := &fakeJobs{jobs: []apiassets.LearningJobProgress{job}, completeErr: errors.New("tx aborted")}
	cands := &fakeCandidates{}
	w := NewWorker(jobs, cands, &fakeAudit{}, nil)

	stats, err := w.SweepOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Completed != 0 || stats.Failed != 1 {
		t.Fatalf("stats=%+v", stats)
	}
	if len(cands.created) != 0 {
		t.Fatal("candidate must not be created when completion fails")
	}
	if _, ok := jobs.errors[job.ID]; !ok {
		t.Fatal("last_error not recorded")
	}
}

// TestSweepOnceIntervalClamp 调度间隔夹取（防误配）。
func TestSweepOnceIntervalClamp(t *testing.T) {
	w := NewWorker(&fakeJobs{}, &fakeCandidates{}, nil, nil)
	if got := w.interval(context.Background()); got != DefaultInterval {
		t.Fatalf("default interval=%v", got)
	}
	w = NewWorker(&fakeJobs{}, &fakeCandidates{}, nil, fakeSettings{v: 1})
	if got := w.interval(context.Background()); got != minInterval {
		t.Fatalf("clamped min=%v", got)
	}
	w = NewWorker(&fakeJobs{}, &fakeCandidates{}, nil, fakeSettings{v: 7200})
	if got := w.interval(context.Background()); got != maxInterval {
		t.Fatalf("clamped max=%v", got)
	}
	w = NewWorker(&fakeJobs{}, &fakeCandidates{}, nil, fakeSettings{v: 60})
	if got := w.interval(context.Background()); got != time.Minute {
		t.Fatalf("custom interval=%v", got)
	}
}

type fakeSettings struct {
	v       int               // sweep_interval_seconds
	strings map[string]string // api_learning 条件键（字符串数值）
}

func (f fakeSettings) GetInt(_ context.Context, group, key string, def int) int {
	if group == "api_learning" && key == "sweep_interval_seconds" {
		return f.v
	}
	return def
}

func (f fakeSettings) GetString(_ context.Context, group, key, def string) string {
	if group == "api_learning" {
		if v, ok := f.strings[key]; ok {
			return v
		}
	}
	return def
}

// TestLoadLearningConditions 条件配置加载：合法自定义生效；非法/越界回落默认。
func TestLoadLearningConditions(t *testing.T) {
	// nil settings → 全默认
	def := LoadLearningConditions(context.Background(), nil)
	if def.MinValidSamples != 10 || def.MinUniqueIPs != 1 || def.MinUniqueIdentities != 0 ||
		def.MinDuration != 0 || def.MaxDuration != 7*24*time.Hour || def.MinSuccessRatio != 0 {
		t.Fatalf("defaults=%+v", def)
	}
	// 合法自定义
	c := LoadLearningConditions(context.Background(), fakeSettings{strings: map[string]string{
		"min_valid_samples":             "200",
		"min_unique_ips":                "5",
		"min_unique_identities":         "2",
		"min_learning_duration_seconds": "3600",
		"max_learning_duration_seconds": "86400",
		"minimum_success_ratio":         "0.8",
	}})
	if c.MinValidSamples != 200 || c.MinUniqueIPs != 5 || c.MinUniqueIdentities != 2 ||
		c.MinDuration != time.Hour || c.MaxDuration != 24*time.Hour || c.MinSuccessRatio != 0.8 {
		t.Fatalf("custom=%+v", c)
	}
	// 非法/越界 → 回落默认（不阻断调度）
	bad := LoadLearningConditions(context.Background(), fakeSettings{strings: map[string]string{
		"min_valid_samples":             "abc", // 解析失败
		"min_unique_ips":                "-1",  // 越界
		"max_learning_duration_seconds": "10",  // 低于下限 60
		"minimum_success_ratio":         "1.5", // 超出 [0,1]
	}})
	if bad.MinValidSamples != def.MinValidSamples || bad.MinUniqueIPs != def.MinUniqueIPs ||
		bad.MaxDuration != def.MaxDuration || bad.MinSuccessRatio != def.MinSuccessRatio {
		t.Fatalf("invalid should fallback to defaults: %+v", bad)
	}
}

// TestEvaluateLearningConditions 多条件判定矩阵：任一条件不满足即不达标（原因非空）。
func TestEvaluateLearningConditions(t *testing.T) {
	now := time.Now()
	pass := reachedJob()
	pass.StartedAt = now.Add(-time.Hour)

	cases := []struct {
		name   string
		mutate func(*apiassets.LearningJobProgress)
		cond   LearningConditions
		want   int // 未满足原因数（0=达标）
	}{
		{"默认条件全达标", nil, DefaultLearningConditions(), 0},
		{"样本数不足", func(j *apiassets.LearningJobProgress) { j.ValidCount = 99 }, DefaultLearningConditions(), 1},
		{"全局样本下限抬升", func(j *apiassets.LearningJobProgress) { j.ValidCount = 150 },
			LearningConditions{MinValidSamples: 200, MinUniqueIPs: 1, MaxDuration: 7 * 24 * time.Hour}, 1},
		{"sample_target=0 不空转", func(j *apiassets.LearningJobProgress) { j.SampleTarget = 0; j.ValidCount = 1000 },
			DefaultLearningConditions(), 1},
		{"来源 IP 不足", func(j *apiassets.LearningJobProgress) { j.UniqueIPs = 0 }, DefaultLearningConditions(), 1},
		{"身份多样性要求", func(j *apiassets.LearningJobProgress) {},
			LearningConditions{MinValidSamples: 10, MinUniqueIPs: 1, MinUniqueIdentities: 1, MaxDuration: 7 * 24 * time.Hour}, 1},
		{"最短时长不足", func(j *apiassets.LearningJobProgress) {},
			LearningConditions{MinValidSamples: 10, MinUniqueIPs: 1, MinDuration: 2 * time.Hour, MaxDuration: 7 * 24 * time.Hour}, 1},
		{"时长起点取首次落样", func(j *apiassets.LearningJobProgress) {
			first := now.Add(-3 * time.Hour)
			j.StartedAt = now.Add(-10 * 24 * time.Hour) // started_at 很早，但首次落样仅 3h 前
			j.FirstSampleAt = &first
		}, LearningConditions{MinValidSamples: 10, MinUniqueIPs: 1, MinDuration: 2 * time.Hour, MaxDuration: 7 * 24 * time.Hour}, 0},
		{"成功率达标", nil,
			LearningConditions{MinValidSamples: 10, MinUniqueIPs: 1, MaxDuration: 7 * 24 * time.Hour, MinSuccessRatio: 0.9}, 0},
		{"成功率不足", func(j *apiassets.LearningJobProgress) { j.SuccessCount = 10 },
			LearningConditions{MinValidSamples: 10, MinUniqueIPs: 1, MaxDuration: 7 * 24 * time.Hour, MinSuccessRatio: 0.9}, 1},
		{"成功率无分母", func(j *apiassets.LearningJobProgress) { j.StatusSampleCount = 0; j.SuccessCount = 0 },
			LearningConditions{MinValidSamples: 10, MinUniqueIPs: 1, MaxDuration: 7 * 24 * time.Hour, MinSuccessRatio: 0.5}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			j := pass
			if tc.mutate != nil {
				tc.mutate(&j)
			}
			if got := EvaluateLearningConditions(&j, tc.cond, now); len(got) != tc.want {
				t.Fatalf("unmet=%v, want %d", got, tc.want)
			}
		})
	}
}

// TestLearningExpired 超期判定：默认 7 天；起点取首次落样。
func TestLearningExpired(t *testing.T) {
	now := time.Now()
	cond := DefaultLearningConditions()
	j := reachedJob()
	j.StartedAt = now.Add(-8 * 24 * time.Hour)
	if !LearningExpired(&j, cond, now) {
		t.Fatal("8 days old should be expired")
	}
	j.StartedAt = now.Add(-6 * 24 * time.Hour)
	if LearningExpired(&j, cond, now) {
		t.Fatal("6 days old should not be expired")
	}
	// 首次落样覆盖起点：started_at 8 天前但首次落样 1 天前 → 未超期
	j.StartedAt = now.Add(-8 * 24 * time.Hour)
	first := now.Add(-24 * time.Hour)
	j.FirstSampleAt = &first
	if LearningExpired(&j, cond, now) {
		t.Fatal("first_sample_at should override started_at as duration origin")
	}
}

// fakeProfiles 参数统计画像刷新伪实现。
type fakeProfiles struct {
	calls        int
	n            int
	err          error
	propagateErr error
}

func (f *fakeProfiles) RefreshParameterStatistics(_ context.Context) (int, error) {
	f.calls++
	return f.n, f.err
}

func (f *fakeProfiles) PropagateSensitivityLevels(_ context.Context) (int64, error) {
	return 0, f.propagateErr
}

// TestSweepOnceRefreshesProfiles 注入 Profiles 后每轮清扫末尾刷新一次画像；
// 未注入时零开销跳过（既有用例默认覆盖 nil 分支，ProfilesRefreshed 恒 0）。
func TestSweepOnceRefreshesProfiles(t *testing.T) {
	profiles := &fakeProfiles{n: 7}
	w := NewWorker(&fakeJobs{}, &fakeCandidates{}, nil, nil)
	w.SetProfileRefresher(profiles)

	stats, err := w.SweepOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if profiles.calls != 1 {
		t.Fatalf("refresh calls=%d, want 1", profiles.calls)
	}
	if stats.ProfilesRefreshed != 7 {
		t.Fatalf("ProfilesRefreshed=%d, want 7", stats.ProfilesRefreshed)
	}
}

// TestSweepOnceProfilesFailure 画像刷新失败向上返回错误（不静默吞错），
// 任务完成统计不受影响（已完成任务不回滚）。
func TestSweepOnceProfilesFailure(t *testing.T) {
	job := reachedJob()
	jobs := &fakeJobs{jobs: []apiassets.LearningJobProgress{job}}
	cands := &fakeCandidates{}
	profiles := &fakeProfiles{err: errors.New("db down")}
	w := NewWorker(jobs, cands, nil, nil)
	w.SetProfileRefresher(profiles)

	stats, err := w.SweepOnce(context.Background())
	if err == nil {
		t.Fatal("expected error from profile refresh")
	}
	if stats.Completed != 1 {
		t.Fatalf("Completed=%d, want 1（任务完成不受画像失败影响）", stats.Completed)
	}
	if len(jobs.completed) != 1 {
		t.Fatalf("job should still be completed: %v", jobs.completed)
	}
}
