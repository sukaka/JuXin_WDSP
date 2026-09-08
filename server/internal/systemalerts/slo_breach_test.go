// slo_breach_test.go APM SLO 违约告警评估单测（fakeStore + fake SLOBreachStatsStore，
// 可控时钟；触发/合并/自动恢复/空转/中止语义）。
package systemalerts

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// fakeSLOBreach 是 SLOBreachStatsStore 的可编程内存实现。
type fakeSLOBreach struct {
	states []SLOBreachState
	err    error
	calls  int
}

func (f *fakeSLOBreach) SLOBreachStates(_ context.Context) ([]SLOBreachState, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.states, nil
}

func newSLOBreachEngine(store *fakeStore, src *fakeSLOBreach, now *time.Time) *Engine {
	return NewEngine(store, EngineOptions{
		Now:           func() time.Time { return *now },
		Cooldown:      time.Minute,
		FlapWindow:    10 * time.Minute,
		FlapThreshold: 3,
		MaxOpen:       500,
		SLOBreach:     src,
	})
}

var sloNow = time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)

// TestAPMSLOBreachTypeRegistered APM_SLO_BREACH 已注册规则矩阵（MEDIUM）。
func TestAPMSLOBreachTypeRegistered(t *testing.T) {
	if !IsValidType(TypeAPMSLOBreach) {
		t.Fatal("APM_SLO_BREACH 应为合法类型")
	}
	if got := SeverityFor(TypeAPMSLOBreach); got != SeverityMedium {
		t.Errorf("APM_SLO_BREACH 等级 = %s, want MEDIUM", got)
	}
}

// TestEvaluateSLOBreachNilSource 评估源未注入（APM_ENABLED 关闭形态）时空转。
func TestEvaluateSLOBreachNilSource(t *testing.T) {
	e := NewEngine(newFakeStore(), EngineOptions{Now: func() time.Time { return sloNow }})
	if err := e.EvaluateSLOBreach(context.Background()); err != nil {
		t.Fatalf("nil source evaluate: %v", err)
	}
}

// TestEvaluateSLOBreachRaiseMergeRecover 违约触发 → 重复评估合并 → 恢复自动收口。
func TestEvaluateSLOBreachRaiseMergeRecover(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	src := &fakeSLOBreach{states: []SLOBreachState{
		{Service: "shop", Name: "可用性", Breached: true, Title: "SLO 可用性违约", Message: "服务 shop 违约"},
		{Service: "pay", Name: "时延", Breached: false}, // 未违约不触发
	}}
	now := sloNow
	e := newSLOBreachEngine(store, src, &now)

	// 第一轮：触发 1 条
	if err := e.EvaluateSLOBreach(ctx); err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	a := findAlert(store, TypeAPMSLOBreach)
	if a == nil {
		t.Fatal("want APM_SLO_BREACH alert")
	}
	if a.Severity != SeverityMedium || a.Status != StatusOpen {
		t.Errorf("alert = %+v", a)
	}
	if a.Component != "shop/可用性" {
		t.Errorf("component = %q, want shop/可用性", a.Component)
	}
	if a.Title != "SLO 可用性违约" || !strings.Contains(a.Message, "服务 shop") {
		t.Errorf("title/message = %q/%q", a.Title, a.Message)
	}

	// 第二轮仍违约：合并而非新建
	if err := e.EvaluateSLOBreach(ctx); err != nil {
		t.Fatalf("evaluate 2: %v", err)
	}
	if n := store.countByStatus(StatusOpen); n != 1 {
		t.Errorf("open count = %d, want 1（合并去重）", n)
	}

	// 第三轮恢复：自动收口为 RESOLVED(RECOVERED)
	src.states = []SLOBreachState{
		{Service: "shop", Name: "可用性", Breached: false},
	}
	now = now.Add(time.Minute)
	if err := e.EvaluateSLOBreach(ctx); err != nil {
		t.Fatalf("evaluate 3: %v", err)
	}
	got := store.get(a.ID)
	if got.Status != StatusResolved || got.ResolveType == nil || *got.ResolveType != ResolveRecovered {
		t.Errorf("recovered alert = %+v", got)
	}

	// 第四轮再次违约：重新触发（新 OPEN，而非复活旧告警）
	src.states = []SLOBreachState{
		{Service: "shop", Name: "可用性", Breached: true, Title: "SLO 可用性违约", Message: "服务 shop 再次违约"},
	}
	now = now.Add(time.Minute)
	if err := e.EvaluateSLOBreach(ctx); err != nil {
		t.Fatalf("evaluate 4: %v", err)
	}
	if n := store.countByStatus(StatusOpen); n != 1 {
		t.Fatalf("re-raise open count = %d, want 1", n)
	}
	for _, al := range store.alerts {
		if al.AlertType == TypeAPMSLOBreach && al.Status == StatusOpen && al.ID == a.ID {
			t.Error("re-raise 应为新告警而非复活已恢复告警")
		}
	}
}

// TestEvaluateSLOBreachDeletedSLORecovers SLO 定义删除后（不再出现在评估结果中）
// 既有未关闭告警自动恢复。
func TestEvaluateSLOBreachDeletedSLORecovers(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	src := &fakeSLOBreach{states: []SLOBreachState{
		{Service: "shop", Name: "可用性", Breached: true, Title: "t", Message: "m"},
	}}
	now := sloNow
	e := newSLOBreachEngine(store, src, &now)
	if err := e.EvaluateSLOBreach(ctx); err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if a := findAlert(store, TypeAPMSLOBreach); a == nil || a.Status != StatusOpen {
		t.Fatal("want open alert")
	}

	// SLO 被删除：评估结果为空 → 既有告警恢复
	src.states = nil
	now = now.Add(time.Minute)
	if err := e.EvaluateSLOBreach(ctx); err != nil {
		t.Fatalf("evaluate after delete: %v", err)
	}
	if a := findAlert(store, TypeAPMSLOBreach); a.Status != StatusResolved {
		t.Errorf("status = %s, want RESOLVED", a.Status)
	}
}

// TestEvaluateSLOBreachAbortOnReadError 读数失败整体中止：不清动既有告警。
func TestEvaluateSLOBreachAbortOnReadError(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	src := &fakeSLOBreach{states: []SLOBreachState{
		{Service: "shop", Name: "可用性", Breached: true, Title: "t", Message: "m"},
	}}
	now := sloNow
	e := newSLOBreachEngine(store, src, &now)
	if err := e.EvaluateSLOBreach(ctx); err != nil {
		t.Fatalf("evaluate: %v", err)
	}

	src.err = errors.New("pg down")
	if err := e.EvaluateSLOBreach(ctx); err == nil {
		t.Fatal("want error on stats failure")
	}
	if a := findAlert(store, TypeAPMSLOBreach); a.Status != StatusOpen {
		t.Errorf("status = %s, want OPEN（读数失败不误恢复）", a.Status)
	}
}

// TestSLOBreachComponentTruncation 超长 service/name 去重键截断 + 摘要后缀
// （不同长键不碰撞；与端点告警同口径）。
func TestSLOBreachComponentTruncation(t *testing.T) {
	longA := strings.Repeat("服", 100) + "/" + strings.Repeat("甲", 100)
	longB := strings.Repeat("服", 100) + "/" + strings.Repeat("乙", 100)
	ca := truncatedAlertComponent(longA)
	cb := truncatedAlertComponent(longB)
	if ca == cb {
		t.Error("截断后不同长键碰撞")
	}
	if len([]rune(ca)) > endpointComponentMaxLen {
		t.Errorf("component 超 %d 字符", endpointComponentMaxLen)
	}
	if got := truncatedAlertComponent("shop/可用性"); got != "shop/可用性" {
		t.Errorf("短键原样保留，got %q", got)
	}
}
