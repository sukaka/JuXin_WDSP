package apiassets

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"
)

// TestMemStoreStartLearningSampleTarget 样本目标入参：0 取缺省、合法值落库、越界拒绝。
func TestMemStoreStartLearningSampleTarget(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	e, err := store.UpsertDiscovery(ctx, DiscoveryInput{Method: "POST", PathTemplate: "/pay/{id}", Confidence: 0.8, IsAPI: true})
	if err != nil {
		t.Fatal(err)
	}
	// 缺省（0 → DefaultSampleTarget）
	job, err := store.StartLearning(ctx, e.ID, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if job.SampleTarget != DefaultSampleTarget {
		t.Fatalf("sample_target=%d, want default %d", job.SampleTarget, DefaultSampleTarget)
	}
	if _, err := store.StopLearning(ctx, e.ID, "tester"); err != nil {
		t.Fatal(err)
	}
	// 合法值
	job, err = store.StartLearning(ctx, e.ID, MinSampleTarget, nil)
	if err != nil {
		t.Fatal(err)
	}
	if job.SampleTarget != MinSampleTarget {
		t.Fatalf("sample_target=%d, want %d", job.SampleTarget, MinSampleTarget)
	}
	if _, err := store.StopLearning(ctx, e.ID, "tester"); err != nil {
		t.Fatal(err)
	}
	// 越界（含 0 语义：0 是缺省而非非法，但负数与超上限拒绝）
	for _, target := range []int{-1, MinSampleTarget - 1, MaxSampleTarget + 1} {
		if _, err := store.StartLearning(ctx, e.ID, target, nil); !errors.Is(err, ErrInvalidSampleTarget) {
			t.Fatalf("target=%d err=%v, want ErrInvalidSampleTarget", target, err)
		}
	}
}

// TestLearningJobThresholdReached 阈值判定：达标/未达标/sample_target=0 不空转。
func TestLearningJobThresholdReached(t *testing.T) {
	cases := []struct {
		target, valid int
		want          bool
	}{
		{100, 100, true},
		{100, 150, true},
		{100, 99, false},
		{10, 10, true},
		{0, 0, false},   // target=0：历史任务不空转
		{0, 100, false}, // target=0：即使 valid_count 有值也不判定
	}
	for _, c := range cases {
		j := &LearningJob{SampleTarget: c.target, ValidCount: c.valid}
		if got := j.ThresholdReached(); got != c.want {
			t.Fatalf("target=%d valid=%d reached=%v, want %v", c.target, c.valid, got, c.want)
		}
	}
}

// TestSourceAcceptedCap 来源占比上限：max(10, sample_target/2)。
func TestSourceAcceptedCap(t *testing.T) {
	cases := []struct{ target, want int }{
		{10, 10},  // 5 → 下限 10
		{20, 10},  // 10
		{100, 50}, // 50
		{100000, 50000},
	}
	for _, c := range cases {
		if got := SourceAcceptedCap(c.target); got != c.want {
			t.Fatalf("target=%d cap=%d, want %d", c.target, got, c.want)
		}
	}
}

// TestLearningSampleHash 样本哈希：确定性 + 输入敏感。
func TestLearningSampleHash(t *testing.T) {
	h1 := LearningSampleHash("GET /v1/users/{id}", "req-1")
	if h1 != LearningSampleHash("GET /v1/users/{id}", "req-1") {
		t.Fatal("hash not deterministic")
	}
	if h1 == LearningSampleHash("GET /v1/users/{id}", "req-2") ||
		h1 == LearningSampleHash("POST /v1/users/{id}", "req-1") {
		t.Fatal("hash should vary with endpoint_key and request_id")
	}
	if len(h1) != 64 {
		t.Fatalf("sha256 hex length=%d", len(h1))
	}
}

// TestLearningStartSampleTargetValidation 接口级阈值校验：缺省/合法/越界 400。
func TestLearningStartSampleTargetValidation(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	ep, err := store.UpsertDiscovery(ctx, DiscoveryInput{Method: "GET", PathTemplate: "/v1/target-check", Confidence: 0.7, IsAPI: true})
	if err != nil {
		t.Fatal(err)
	}
	mux := newTestMux(NewHandler(store, nil))
	url := "/api/v1/api-security/endpoints/" + ep.ID.String() + "/learning/start"
	stop := func() {
		rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/endpoints/"+ep.ID.String()+"/learning/stop", nil)
		if rr.Code != http.StatusOK {
			t.Fatalf("stop status=%d body=%s", rr.Code, rr.Body.String())
		}
	}

	// 无请求体 → 缺省 100
	rr := doJSON(t, mux, http.MethodPost, url, nil)
	data := decodeData(t, rr)
	jobRaw, _ := json.Marshal(data["job"])
	var job LearningJob
	if err := json.Unmarshal(jobRaw, &job); err != nil {
		t.Fatal(err)
	}
	if job.SampleTarget != DefaultSampleTarget {
		t.Fatalf("default sample_target=%d", job.SampleTarget)
	}
	stop()

	// 合法值（边界 10 与 100000）
	for _, target := range []int{10, 500, 100000} {
		rr = doJSON(t, mux, http.MethodPost, url, map[string]any{"sample_target": target})
		data = decodeData(t, rr)
		jobRaw, _ = json.Marshal(data["job"])
		job = LearningJob{}
		if err := json.Unmarshal(jobRaw, &job); err != nil {
			t.Fatal(err)
		}
		if job.SampleTarget != target {
			t.Fatalf("sample_target=%d, want %d", job.SampleTarget, target)
		}
		stop()
	}

	// 越界（0 / 9 / 100001）→ 400，且不创建任务
	for _, target := range []int{0, 9, 100001} {
		rr = doJSON(t, mux, http.MethodPost, url, map[string]any{"sample_target": target})
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("target=%d status=%d body=%s", target, rr.Code, rr.Body.String())
		}
	}
	latest, _, err := store.LearningStatus(ctx, ep.ID)
	if err != nil {
		t.Fatal(err)
	}
	if latest != nil && latest.Status == "RUNNING" {
		t.Fatal("invalid sample_target must not create a running job")
	}

	// 非法 JSON 体 → 400
	rr = doJSON(t, mux, http.MethodPost, url, map[string]any{"sample_target": "abc"})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad json status=%d", rr.Code)
	}
}

// TestLearningJobProgressStartAt 学习时长起点：首次落样优先，无落样回退任务启动时间。
func TestLearningJobProgressStartAt(t *testing.T) {
	started := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	p := &LearningJobProgress{LearningJob: LearningJob{StartedAt: started}}
	if got := p.LearningStartAt(); !got.Equal(started) {
		t.Fatalf("no sample: start=%v, want started_at %v", got, started)
	}
	first := started.Add(2 * time.Hour)
	p.FirstSampleAt = &first
	if got := p.LearningStartAt(); !got.Equal(first) {
		t.Fatalf("with sample: start=%v, want first_sample_at %v", got, first)
	}
}
