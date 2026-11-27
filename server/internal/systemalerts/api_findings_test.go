package systemalerts

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// fakeAPIFindings 是 APIFindingsStatsStore 的可编程内存实现。
type fakeAPIFindings struct {
	criticalTotal   int64
	criticalSamples []FindingSample
	typeCounts      []FindingTypeCount
	maskFailures    int64
	err             error

	calls int // 统计方法被调用次数（开关关闭时不得调用）
}

func (f *fakeAPIFindings) CountNewCritical(_ context.Context, _ time.Duration, limit int) (int64, []FindingSample, error) {
	f.calls++
	if f.err != nil {
		return 0, nil, f.err
	}
	samples := f.criticalSamples
	if limit > 0 && len(samples) > limit {
		samples = samples[:limit]
	}
	return f.criticalTotal, samples, nil
}

func (f *fakeAPIFindings) CountNewByType(_ context.Context, _ time.Duration) ([]FindingTypeCount, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.typeCounts, nil
}

func (f *fakeAPIFindings) CountNewMaskFailures(_ context.Context, _ time.Duration) (int64, error) {
	f.calls++
	if f.err != nil {
		return 0, f.err
	}
	return f.maskFailures, nil
}

// fakeSettings 是 SettingsReader 的 map 实现。
type fakeSettings struct {
	bools  map[string]bool
	ints   map[string]int
	floats map[string]float64
}

func (s *fakeSettings) GetBool(_ context.Context, group, key string, def bool) bool {
	if v, ok := s.bools[group+"/"+key]; ok {
		return v
	}
	return def
}

func (s *fakeSettings) GetInt(_ context.Context, group, key string, def int) int {
	if v, ok := s.ints[group+"/"+key]; ok {
		return v
	}
	return def
}

func (s *fakeSettings) GetFloat(_ context.Context, group, key string, def float64) float64 {
	if v, ok := s.floats[group+"/"+key]; ok {
		return v
	}
	return def
}

// newAPIFindingsEngine 创建注入 findings 统计源的引擎（可控时钟）。
func newAPIFindingsEngine(store *fakeStore, findings *fakeAPIFindings, settings SettingsReader, now *time.Time) *Engine {
	return NewEngine(store, EngineOptions{
		Now:           func() time.Time { return *now },
		Cooldown:      time.Minute,
		FlapWindow:    10 * time.Minute,
		FlapThreshold: 3,
		MaxOpen:       500,
		APIFindings:   findings,
		Settings:      settings,
	})
}

// TestEvaluateAPICriticalFinding CRITICAL finding 触发→合并→消退自动恢复。
func TestEvaluateAPICriticalFinding(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	findings := &fakeAPIFindings{
		criticalTotal: 2,
		criticalSamples: []FindingSample{
			{FindingType: "BOLA_UNAUTHENTICATED_OBJECT_ACCESS", Title: "未认证对象访问", SubjectType: "IP"},
			{FindingType: "SENSITIVE_LEAK", Title: "敏感数据泄露"},
		},
	}
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	e := newAPIFindingsEngine(store, findings, nil, &now)

	if err := e.EvaluateAPIFindings(ctx); err != nil {
		t.Fatalf("EvaluateAPIFindings: %v", err)
	}
	if n := store.countByStatus(StatusOpen); n != 1 {
		t.Fatalf("应创建 1 条 OPEN 告警, got %d", n)
	}
	var raised Alert
	for _, a := range store.alerts {
		raised = *a
	}
	if raised.AlertType != TypeAPICriticalFinding || raised.Component != ComponentAPISecurity {
		t.Errorf("告警指纹错误: type=%s component=%s", raised.AlertType, raised.Component)
	}
	if raised.Severity != SeverityCritical {
		t.Errorf("等级 = %s, want CRITICAL", raised.Severity)
	}
	if !strings.Contains(raised.Message, "2 条严重级风险发现") || !strings.Contains(raised.Message, "未认证对象越权访问（未认证对象访问）") || !strings.Contains(raised.Message, "敏感数据泄露") {
		t.Errorf("message 应含中文总数与样本摘要: %q", raised.Message)
	}
	if strings.Contains(raised.Message, "BOLA_UNAUTHENTICATED_OBJECT_ACCESS") || strings.Contains(raised.Message, "SENSITIVE_LEAK") || strings.Contains(raised.Message, "CRITICAL") {
		t.Errorf("message 不应包含原始英文枚举码: %q", raised.Message)
	}
	if strings.Contains(raised.Message, "敏感数据泄露（敏感数据泄露）") {
		t.Errorf("message 不应重复括注相同中文标题: %q", raised.Message)
	}

	// 同窗口持续存在 → 合并（occurrence_count+1），不新建
	if err := e.EvaluateAPIFindings(ctx); err != nil {
		t.Fatalf("再次评估: %v", err)
	}
	if n := store.countByStatus(StatusOpen); n != 1 {
		t.Fatalf("持续触发应合并为同一条, got %d 条 OPEN", n)
	}
	if got := store.get(raised.ID).OccurrenceCount; got != 2 {
		t.Errorf("合并后 occurrence_count = %d, want 2", got)
	}

	// 窗口内不再有 NEW CRITICAL findings → 自动恢复
	findings.criticalTotal = 0
	findings.criticalSamples = nil
	if err := e.EvaluateAPIFindings(ctx); err != nil {
		t.Fatalf("消退评估: %v", err)
	}
	if got := store.get(raised.ID); got.Status != StatusResolved || got.ResolveType == nil || *got.ResolveType != ResolveRecovered {
		t.Errorf("消退后应 RESOLVED(RECOVERED), got status=%s", got.Status)
	}
}

// TestEvaluateAPIFindingSpike 同类型激增超阈触发、未超阈不触发、冷却期 message 不更新。
func TestEvaluateAPIFindingSpike(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	findings := &fakeAPIFindings{
		typeCounts: []FindingTypeCount{
			{FindingType: "SCHEMA_DEVIATION", Count: 30},
			{FindingType: "ZOMBIE", Count: 5}, // 未超阈（默认阈值 20）
		},
	}
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	e := newAPIFindingsEngine(store, findings, nil, &now)

	if err := e.EvaluateAPIFindings(ctx); err != nil {
		t.Fatalf("EvaluateAPIFindings: %v", err)
	}
	var raised Alert
	found := false
	for _, a := range store.alerts {
		if a.AlertType == TypeAPIFindingSpike {
			raised, found = *a, true
		}
	}
	if !found {
		t.Fatal("超阈应触发 API_FINDING_SPIKE")
	}
	if raised.Severity != SeverityHigh {
		t.Errorf("等级 = %s, want HIGH", raised.Severity)
	}
	if !strings.Contains(raised.Message, "模型偏离 30 条") {
		t.Errorf("message 应含中文超阈类型与计数: %q", raised.Message)
	}
	if strings.Contains(raised.Message, "SCHEMA_DEVIATION") || strings.Contains(raised.Message, "ZOMBIE") || strings.Contains(raised.Message, "僵尸 API") {
		t.Errorf("message 不应包含英文类型码或未超阈类型: %q", raised.Message)
	}
	firstMsg := raised.Message

	// 冷却期内再次评估（计数变化）→ 合并但 message 不更新
	findings.typeCounts[0].Count = 45
	if err := e.EvaluateAPIFindings(ctx); err != nil {
		t.Fatalf("冷却期评估: %v", err)
	}
	if got := store.get(raised.ID); got.Message != firstMsg {
		t.Errorf("冷却期内 message 不应更新: %q → %q", firstMsg, got.Message)
	}
	// 冷却期过后 → message 更新为最新计数
	now = now.Add(2 * time.Minute)
	if err := e.EvaluateAPIFindings(ctx); err != nil {
		t.Fatalf("冷却期后评估: %v", err)
	}
	if got := store.get(raised.ID); !strings.Contains(got.Message, "模型偏离 45 条") {
		t.Errorf("冷却期后 message 应更新: %q", got.Message)
	}

	// 回落至阈值以下 → 自动恢复
	findings.typeCounts[0].Count = 10
	now = now.Add(2 * time.Minute)
	if err := e.EvaluateAPIFindings(ctx); err != nil {
		t.Fatalf("回落评估: %v", err)
	}
	if got := store.get(raised.ID); got.Status != StatusResolved {
		t.Errorf("回落后应自动恢复, got status=%s", got.Status)
	}
}

// TestEvaluateAPIMaskFailure MASK_RESPONSE 失败触发与消退恢复。
func TestEvaluateAPIMaskFailure(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	findings := &fakeAPIFindings{maskFailures: 3}
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	e := newAPIFindingsEngine(store, findings, nil, &now)

	if err := e.EvaluateAPIFindings(ctx); err != nil {
		t.Fatalf("EvaluateAPIFindings: %v", err)
	}
	found := false
	for _, a := range store.alerts {
		if a.AlertType == TypeAPIMaskFailure {
			found = true
			if !strings.Contains(a.Message, "3 条") || strings.Contains(a.Message, "MASK_RESPONSE") {
				t.Errorf("message 应含中文失败条数且不含英文枚举码: %q", a.Message)
			}
		}
	}
	if !found {
		t.Fatal("存在 MASK 失败 finding 时应触发 API_MASK_FAILURE")
	}

	findings.maskFailures = 0
	if err := e.EvaluateAPIFindings(ctx); err != nil {
		t.Fatalf("消退评估: %v", err)
	}
	for _, a := range store.alerts {
		if a.AlertType == TypeAPIMaskFailure && a.Status != StatusResolved {
			t.Errorf("消退后应自动恢复, got status=%s", a.Status)
		}
	}
}

// TestEvaluateAPIFindingsSwitchOff 开关关闭的类型跳过评估（不触发也不清动既有告警）。
func TestEvaluateAPIFindingsSwitchOff(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	findings := &fakeAPIFindings{
		criticalTotal: 1,
		typeCounts:    []FindingTypeCount{{FindingType: "BOLA", Count: 99}},
		maskFailures:  5,
	}
	settings := &fakeSettings{bools: map[string]bool{
		apiAlertSettingsGroup + "/" + apiAlertKeyCriticalEnabled: false,
		apiAlertSettingsGroup + "/" + apiAlertKeySpikeEnabled:    false,
		apiAlertSettingsGroup + "/" + apiAlertKeyMaskEnabled:     false,
	}}
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	e := newAPIFindingsEngine(store, findings, settings, &now)

	if err := e.EvaluateAPIFindings(ctx); err != nil {
		t.Fatalf("EvaluateAPIFindings: %v", err)
	}
	if findings.calls != 0 {
		t.Errorf("全部开关关闭时不应访问统计源, got %d 次调用", findings.calls)
	}
	if n := store.countByStatus(StatusOpen); n != 0 {
		t.Errorf("全部开关关闭时不应产生告警, got %d", n)
	}
}

// TestEvaluateAPIFindingsNilStore 未注入统计源时不执行（装配缺省形态）。
func TestEvaluateAPIFindingsNilStore(t *testing.T) {
	e := NewEngine(newFakeStore(), EngineOptions{})
	if err := e.EvaluateAPIFindings(context.Background()); err != nil {
		t.Fatalf("未注入统计源应为无操作, got %v", err)
	}
}

// TestLoadAPIAlertConfig 配置读取：默认值、覆盖、非法值回退。
func TestLoadAPIAlertConfig(t *testing.T) {
	ctx := context.Background()

	// nil 配置源 → 全默认
	cfg := loadAPIAlertConfig(ctx, nil)
	if !cfg.CriticalEnabled || !cfg.SpikeEnabled || !cfg.MaskEnabled {
		t.Errorf("默认开关应全部开启: %+v", cfg)
	}
	if cfg.SpikeThreshold != defaultSpikeThreshold ||
		cfg.SpikeWindow != defaultSpikeWindowMin*time.Minute ||
		cfg.ScanWindow != defaultScanWindowMin*time.Minute {
		t.Errorf("默认阈值/窗口错误: %+v", cfg)
	}

	// 合法覆盖
	custom := &fakeSettings{
		bools: map[string]bool{apiAlertSettingsGroup + "/" + apiAlertKeyCriticalEnabled: false},
		ints: map[string]int{
			apiAlertSettingsGroup + "/" + apiAlertKeySpikeThreshold: 50,
			apiAlertSettingsGroup + "/" + apiAlertKeySpikeWindowMin: 30,
			apiAlertSettingsGroup + "/" + apiAlertKeyScanWindowMin:  5,
		},
	}
	cfg = loadAPIAlertConfig(ctx, custom)
	if cfg.CriticalEnabled {
		t.Errorf("覆盖后 critical 开关应为 false")
	}
	if cfg.SpikeThreshold != 50 || cfg.SpikeWindow != 30*time.Minute || cfg.ScanWindow != 5*time.Minute {
		t.Errorf("覆盖值未生效: %+v", cfg)
	}

	// 非法值（0/负/超上限）→ 回退默认
	bad := &fakeSettings{ints: map[string]int{
		apiAlertSettingsGroup + "/" + apiAlertKeySpikeThreshold: -1,
		apiAlertSettingsGroup + "/" + apiAlertKeySpikeWindowMin: 0,
		apiAlertSettingsGroup + "/" + apiAlertKeyScanWindowMin:  99999,
	}}
	cfg = loadAPIAlertConfig(ctx, bad)
	if cfg.SpikeThreshold != defaultSpikeThreshold ||
		cfg.SpikeWindow != defaultSpikeWindowMin*time.Minute ||
		cfg.ScanWindow != defaultScanWindowMin*time.Minute {
		t.Errorf("非法配置应回退默认: %+v", cfg)
	}
}

// TestRaiseSilencedSkipsSyslog 同指纹静默期内新建告警：仍落库但不外发通知。
func TestRaiseSilencedSkipsSyslog(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	store.silencedNow = &now
	e := newAPIFindingsEngine(store, &fakeAPIFindings{}, nil, &now)

	var calls int
	e.SetSyslogForwarder(func(string, interface{}) { calls++ })

	// 预置一条同指纹、已解决但仍在静默期内的历史告警（人工解决后静默意愿延续至到期）
	future := now.Add(30 * time.Minute)
	resolved := now.Add(-time.Hour)
	oldID := uuid.New()
	store.alerts[oldID] = &Alert{
		ID:            oldID,
		AlertType:     TypeAPIFindingSpike,
		Component:     ComponentAPISecurity,
		Severity:      SeverityHigh,
		Status:        StatusResolved,
		ResolvedAt:    &resolved,
		SilencedUntil: &future,
		FirstSeenAt:   resolved,
		LastSeenAt:    resolved,
	}

	a, err := e.Raise(ctx, RaiseRequest{
		AlertType: TypeAPIFindingSpike,
		Component: ComponentAPISecurity,
		Title:     "API风险发现激增",
		Message:   "最近 60 分钟同类型风险发现超过阈值 20：BOLA 30 条",
	})
	if err != nil {
		t.Fatalf("Raise: %v", err)
	}
	if a.Status != StatusOpen {
		t.Errorf("静默期内新建告警仍应正常落库为 OPEN, got %s", a.Status)
	}
	if calls != 0 {
		t.Errorf("同指纹静默期内不应外发通知, got %d 次", calls)
	}

	// 静默到期后同指纹新建 → 恢复外发
	past := now.Add(-time.Minute)
	for _, old := range store.alerts {
		if old.ID != a.ID {
			old.SilencedUntil = &past
		}
	}
	// 已有 OPEN（上一步新建）会先合并；先将其解决再走新建路径
	open := store.alerts[a.ID]
	open.Status = StatusResolved
	if _, err := e.Raise(ctx, RaiseRequest{
		AlertType: TypeAPIFindingSpike,
		Component: ComponentAPISecurity,
		Title:     "API风险发现激增",
		Message:   "再次激增",
	}); err != nil {
		t.Fatalf("静默到期后 Raise: %v", err)
	}
	if calls != 1 {
		t.Errorf("静默到期后新建应恢复外发, got %d 次", calls)
	}
}

// TestAPIAlertTypes 新告警类型注册与默认等级。
func TestAPIAlertTypes(t *testing.T) {
	for _, typ := range []string{TypeAPICriticalFinding, TypeAPIFindingSpike, TypeAPIMaskFailure} {
		if !IsValidType(typ) {
			t.Errorf("%s 未注册为合法告警类型", typ)
		}
	}
	if SeverityFor(TypeAPICriticalFinding) != SeverityCritical {
		t.Errorf("API_CRITICAL_FINDING 默认等级 = %s, want CRITICAL", SeverityFor(TypeAPICriticalFinding))
	}
	if SeverityFor(TypeAPIFindingSpike) != SeverityHigh || SeverityFor(TypeAPIMaskFailure) != SeverityHigh {
		t.Errorf("SPIKE/MASK_FAILURE 默认等级应为 HIGH")
	}
}

// TestSpikeExceeded 超阈筛选纯函数。
func TestSpikeExceeded(t *testing.T) {
	counts := []FindingTypeCount{
		{FindingType: "A", Count: 21},
		{FindingType: "B", Count: 20}, // 等于阈值不算超（「超阈值」严格大于）
		{FindingType: "C", Count: 100},
	}
	got := spikeExceeded(counts, 20)
	if len(got) != 2 || got[0].FindingType != "A" || got[1].FindingType != "C" {
		t.Errorf("spikeExceeded = %+v, want [A C]", got)
	}
	if len(spikeExceeded(nil, 20)) != 0 {
		t.Errorf("空输入应得空结果")
	}
}

// TestSilenceViewHelpers 三态视图口径校验。
func TestSilenceViewHelpers(t *testing.T) {
	for _, v := range []string{ViewActive, ViewSilenced, ViewHistory} {
		if !IsValidView(v) {
			t.Errorf("%s 应为合法视图", v)
		}
	}
	if IsValidView("ALL") || IsValidView("") {
		t.Errorf("非法视图不应通过校验")
	}
}
