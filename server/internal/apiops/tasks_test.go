// tasks_test.go 五种内置任务产出正确性测试（fake Source 造数断言报告与摘要）、
// 任务入参校验、LLM 润色挂点降级纪律。
package apiops

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// fakeSource 测试数据源：返回预造数据并记录调用参数。
type fakeSource struct {
	asset     *AssetDigestData
	shadow    *ShadowReviewData
	weakness  *WeaknessFollowData
	risk      *RiskDigestData
	sensitive *SensitiveDigestData
	err       error

	gotSince   time.Time
	gotLimit   int
	gotDueDays int
	callCount  int
}

func (f *fakeSource) AssetDigest(_ context.Context, since time.Time, limit int) (*AssetDigestData, error) {
	f.gotSince, f.gotLimit, f.callCount = since, limit, f.callCount+1
	if f.err != nil {
		return nil, f.err
	}
	return f.asset, nil
}

func (f *fakeSource) ShadowReview(_ context.Context, since time.Time, limit int) (*ShadowReviewData, error) {
	f.gotSince, f.gotLimit, f.callCount = since, limit, f.callCount+1
	if f.err != nil {
		return nil, f.err
	}
	return f.shadow, nil
}

func (f *fakeSource) WeaknessFollow(_ context.Context, now time.Time, dueWithinDays, limit int) (*WeaknessFollowData, error) {
	f.gotDueDays, f.gotLimit, f.callCount = dueWithinDays, limit, f.callCount+1
	if f.err != nil {
		return nil, f.err
	}
	return f.weakness, nil
}

func (f *fakeSource) RiskDigest(_ context.Context, since time.Time, limit int) (*RiskDigestData, error) {
	f.gotSince, f.gotLimit, f.callCount = since, limit, f.callCount+1
	if f.err != nil {
		return nil, f.err
	}
	return f.risk, nil
}

func (f *fakeSource) SensitiveDigest(_ context.Context, since time.Time, limit int) (*SensitiveDigestData, error) {
	f.gotSince, f.gotLimit, f.callCount = since, limit, f.callCount+1
	if f.err != nil {
		return nil, f.err
	}
	return f.sensitive, nil
}

var testNow = time.Date(2026, 8, 18, 9, 0, 0, 0, time.UTC)

func TestParseTaskConfig(t *testing.T) {
	// 空配置 → 全缺省
	cfg, err := ParseTaskConfig(nil)
	if err != nil {
		t.Fatalf("nil config: %v", err)
	}
	if cfg.WindowHours != 24 || cfg.Limit != 20 || cfg.DueWithinDays != 3 {
		t.Fatalf("defaults: %+v", cfg)
	}
	// 显式零值 → 缺省
	cfg, err = ParseTaskConfig(json.RawMessage(`{"window_hours":0}`))
	if err != nil || cfg.WindowHours != 24 {
		t.Fatalf("zero window_hours should fall back to default: %+v err=%v", cfg, err)
	}
	// 合法覆盖
	cfg, err = ParseTaskConfig(json.RawMessage(`{"window_hours":72,"limit":50,"due_within_days":7}`))
	if err != nil || cfg.WindowHours != 72 || cfg.Limit != 50 || cfg.DueWithinDays != 7 {
		t.Fatalf("override: %+v err=%v", cfg, err)
	}
	// 非法：未知键 / 越界 / 类型错误
	for _, raw := range []string{
		`{"unknown":1}`, `{"window_hours":721}`, `{"window_hours":-1}`, `{"limit":101}`,
		`{"due_within_days":31}`, `{"window_hours":"abc"}`, `not-json`,
	} {
		if _, err := ParseTaskConfig(json.RawMessage(raw)); err == nil {
			t.Fatalf("config %s should be rejected", raw)
		} else if !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("config %s error should wrap ErrInvalidConfig: %v", raw, err)
		}
	}
}

func TestTaskAssetDigest(t *testing.T) {
	src := &fakeSource{asset: &AssetDigestData{
		TotalEndpoints:    42,
		StatusCounts:      []TypeCount{{Type: "DISCOVERED", Count: 7}, {Type: "CONFIRMED", Count: 35}},
		NewInWindow:       3,
		ConfirmedInWindow: 2,
		ShadowOpen:        4,
		ZombieOpen:        1,
		NewEndpoints: []EndpointItem{
			{ID: uuid.New(), Method: "GET", Path: "/v1/users", AssetStatus: "DISCOVERED", FirstSeenAt: testNow},
		},
	}}
	res, err := runAssetDigest(context.Background(), src, TaskConfig{WindowHours: 24, Limit: 20}, testNow)
	if err != nil {
		t.Fatalf("runAssetDigest: %v", err)
	}
	// 报告原样为数据源结构（report_json 可回放）
	report, ok := res.Report.(*AssetDigestData)
	if !ok || report.TotalEndpoints != 42 || report.ShadowOpen != 4 {
		t.Fatalf("report: %+v", res.Report)
	}
	for _, want := range []string{"42", "待确认 7", "新发现端点 3 个", "人工确认 2 个", "Shadow 未闭环 4 项", "Zombie 未闭环 1 项", "GET /v1/users", "建议"} {
		if !strings.Contains(res.Draft, want) {
			t.Fatalf("draft missing %q: %s", want, res.Draft)
		}
	}
	// 窗口换算：since = now - window_hours
	if !src.gotSince.Equal(testNow.Add(-24 * time.Hour)) {
		t.Fatalf("since=%v, want now-24h", src.gotSince)
	}
}

func TestTaskShadowReview(t *testing.T) {
	src := &fakeSource{shadow: &ShadowReviewData{
		OpenTotal: 5, NewInWindow: 2,
		Items: []FindingItem{
			{ID: uuid.New(), EndpointKey: "GET /v1/hidden", Severity: "MEDIUM", Count: 12, LastSeenAt: testNow},
		},
	}}
	res, err := runShadowReview(context.Background(), src, TaskConfig{WindowHours: 24, Limit: 20}, testNow)
	if err != nil {
		t.Fatalf("runShadowReview: %v", err)
	}
	for _, want := range []string{"未闭环 Shadow 发现共 5 项", "新增 2 项", "GET /v1/hidden", "命中 12 次", "建议"} {
		if !strings.Contains(res.Draft, want) {
			t.Fatalf("draft missing %q: %s", want, res.Draft)
		}
	}
	// 空数据口径：无未闭环时给出保持观测结论
	empty := &fakeSource{shadow: &ShadowReviewData{Items: []FindingItem{}}}
	res, err = runShadowReview(context.Background(), empty, TaskConfig{WindowHours: 24, Limit: 20}, testNow)
	if err != nil || !strings.Contains(res.Draft, "无未闭环 Shadow 发现") {
		t.Fatalf("empty draft: %q err=%v", res.Draft, err)
	}
}

func TestTaskWeaknessFollow(t *testing.T) {
	due := testNow.Add(-24 * time.Hour)
	src := &fakeSource{weakness: &WeaknessFollowData{
		OpenTotal: 9, NoDueDate: 3, DueWithinDays: 3,
		Overdue: []WeaknessItem{
			{ID: uuid.New(), WeaknessName: "未认证敏感API", Severity: "HIGH", Owner: "zhangsan", DueDate: &due},
		},
		DueSoon: []WeaknessItem{
			{ID: uuid.New(), WeaknessName: "查询串敏感参数", Severity: "MEDIUM", Owner: ""},
		},
	}}
	res, err := runWeaknessFollow(context.Background(), src, TaskConfig{DueWithinDays: 3, Limit: 20}, testNow)
	if err != nil {
		t.Fatalf("runWeaknessFollow: %v", err)
	}
	for _, want := range []string{"待整改弱点共 9 项", "已超期 1 项", "3 天内到期 1 项", "未设期限 3 项",
		"未认证敏感API", "zhangsan", "查询串敏感参数", "未指派", "催办"} {
		if !strings.Contains(res.Draft, want) {
			t.Fatalf("draft missing %q: %s", want, res.Draft)
		}
	}
	if src.gotDueDays != 3 {
		t.Fatalf("dueWithinDays=%d, want 3", src.gotDueDays)
	}
}

func TestTaskRiskDigest(t *testing.T) {
	src := &fakeSource{risk: &RiskDigestData{
		OpenHighTotal: 8, OpenCritical: 2, NewInWindow: 3,
		TypeDistribution: []TypeCount{{Type: "BOLA", Count: 5}, {Type: "SENSITIVE_LEAK", Count: 3}},
		Items: []FindingItem{
			{ID: uuid.New(), EndpointKey: "GET /v1/orders/{id}", FindingType: "BOLA", Severity: "CRITICAL", LastSeenAt: testNow},
		},
	}}
	res, err := runRiskDigest(context.Background(), src, TaskConfig{WindowHours: 24, Limit: 20}, testNow)
	if err != nil {
		t.Fatalf("runRiskDigest: %v", err)
	}
	for _, want := range []string{"共 8 项", "CRITICAL 2 项", "新增 3 项", "BOLA 5 项", "GET /v1/orders/{id}", "人工动作"} {
		if !strings.Contains(res.Draft, want) {
			t.Fatalf("draft missing %q: %s", want, res.Draft)
		}
	}
}

func TestTaskSensitiveDigest(t *testing.T) {
	src := &fakeSource{sensitive: &SensitiveDigestData{
		SensitiveEndpointCount: 6, SensitiveFieldCount: 18, NewFieldsInWindow: 2,
		TypeDistribution: []TypeCount{{Type: "phone", Count: 10}, {Type: "id_card", Count: 8}},
		NewFields: []SensitiveFieldItem{
			{ID: uuid.New(), EndpointKey: "POST /v1/kyc", Direction: "REQUEST", Path: "id_card", DataType: "id_card", FirstSeen: testNow},
		},
	}}
	res, err := runSensitiveDigest(context.Background(), src, TaskConfig{WindowHours: 24, Limit: 20}, testNow)
	if err != nil {
		t.Fatalf("runSensitiveDigest: %v", err)
	}
	for _, want := range []string{"涉敏端点 6 个", "涉敏字段 18 行", "新增涉敏字段 2 行", "phone 10 行", "POST /v1/kyc", "建议"} {
		if !strings.Contains(res.Draft, want) {
			t.Fatalf("draft missing %q: %s", want, res.Draft)
		}
	}
}

func TestTaskSourceErrorPropagates(t *testing.T) {
	// 数据源失败：错误向上传递（不静默吞错，由调度器落 FAILED run）
	src := &fakeSource{err: errors.New("db down")}
	for name, fn := range taskRegistry {
		if _, err := fn(context.Background(), src, TaskConfig{WindowHours: 24, Limit: 20, DueWithinDays: 3}, testNow); err == nil {
			t.Fatalf("task %s should propagate source error", name)
		}
	}
}

// fakeSummarizer 测试润色器。
type fakeSummarizer struct {
	out    string
	err    error
	called int
	gotRaw json.RawMessage
}

func (f *fakeSummarizer) Polish(_ context.Context, _ string, report json.RawMessage, _ string) (string, error) {
	f.called++
	f.gotRaw = report
	return f.out, f.err
}

func TestPolishSummaryDegrade(t *testing.T) {
	report := map[string]any{"total": 1}
	// nil 润色器 → 模板草稿
	if got := polishSummary(context.Background(), nil, TaskRiskDigest, report, "草稿"); got != "草稿" {
		t.Fatalf("nil summarizer should use draft, got %q", got)
	}
	// 润色成功 → 采用润色结果，且入参含结构化报告
	s := &fakeSummarizer{out: "润色后摘要"}
	if got := polishSummary(context.Background(), s, TaskRiskDigest, report, "草稿"); got != "润色后摘要" {
		t.Fatalf("polished: %q", got)
	}
	if s.called != 1 || !strings.Contains(string(s.gotRaw), `"total":1`) {
		t.Fatalf("summarizer input: called=%d raw=%s", s.called, s.gotRaw)
	}
	// 润色失败 / 返回空白 → 回退草稿（降级而非失败）
	for _, bad := range []*fakeSummarizer{{err: errors.New("llm timeout")}, {out: "  "}} {
		if got := polishSummary(context.Background(), bad, TaskRiskDigest, report, "草稿"); got != "草稿" {
			t.Fatalf("degrade should use draft, got %q", got)
		}
	}
}
