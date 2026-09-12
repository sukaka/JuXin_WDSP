package attacksessions

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// 纯函数：阶段集 + 指示信号 → 判定与 basis。
func TestAutomationEval(t *testing.T) {
	cases := []struct {
		name      string
		stages    []string
		signal    string
		want      bool
		wantBasis string
	}{
		{"3 stages + indicator", []string{"RECON", "AUTH_PROBE", "EXPLOIT"}, "SENSITIVE_PATH_PROBE", true,
			"stages=AUTH_PROBE,EXPLOIT,RECON;indicator=SENSITIVE_PATH_PROBE"},
		{"3 stages no indicator", []string{"RECON", "AUTH_PROBE", "EXPLOIT"}, "", false,
			"stages=AUTH_PROBE,EXPLOIT,RECON"},
		{"2 stages + indicator", []string{"RECON", "EXPLOIT"}, "HEADLESS", false,
			"stages=EXPLOIT,RECON;indicator=HEADLESS"},
		{"unknown stage not counted", []string{"RECON", "UNKNOWN", "EXPLOIT"}, "HEADLESS", false,
			"stages=EXPLOIT,RECON;indicator=HEADLESS"},
		{"non-indicator signal not counted", []string{"RECON", "AUTH_PROBE", "EXPLOIT"}, "AUTH_FAIL_PROBE", false,
			"stages=AUTH_PROBE,EXPLOIT,RECON"},
	}
	for _, c := range cases {
		st := automationState{stages: map[string]bool{}}
		for _, s := range c.stages {
			st.observe(s, "")
		}
		st.observe(StageUnknown, c.signal)
		got, basis := st.eval()
		if got != c.want || basis != c.wantBasis {
			t.Errorf("%s: eval = (%v, %q), want (%v, %q)", c.name, got, basis, c.want, c.wantBasis)
		}
	}
}

// basis 持久化往返：恢复状态后继续累积（跨 Sweep 增量语义）。
func TestAutomationBasisRoundTrip(t *testing.T) {
	st := parseAutomationBasis("stages=AUTH_PROBE,RECON;indicator=HEADLESS")
	st.observe("EXPLOIT", "")
	got, basis := st.eval()
	if !got {
		t.Fatalf("expected suspected after 3rd stage, basis=%q", basis)
	}
	if !strings.Contains(basis, "EXPLOIT") || !strings.HasSuffix(basis, ";indicator=HEADLESS") {
		t.Errorf("basis = %q", basis)
	}
	// 坏数据容忍：零状态重来
	st2 := parseAutomationBasis("garbage")
	if ok, b := st2.eval(); ok || b != "stages=" {
		t.Errorf("garbage basis should reset, got (%v, %q)", ok, b)
	}
}

// 聚合器端到端：三阶段 + 指示信号 → 会话自动标注；同链无指示信号 → 不标注。
func TestSweepOnceAutomationSuspected(t *testing.T) {
	newChain := func(signal string) (*fakeRepo, *Aggregator) {
		repo := newFakeRepo()
		now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
		identityID := uuid.New()
		t0 := now.Add(-time.Hour)
		ev1 := evAt(SourceBehaviorEvents, "b1", "req-1", identityID, t0, 15, StageRecon)
		ev1.Signal = signal
		repo.events[SourceBehaviorEvents] = []Event{ev1}
		repo.events[SourceAPIRuntimeEvents] = []Event{
			evAt(SourceAPIRuntimeEvents, "r1", "req-2", identityID, t0.Add(time.Minute), 10, StageAuthProbe),
			evAt(SourceAPIRuntimeEvents, "r2", "req-3", identityID, t0.Add(2*time.Minute), 50, StageExploit),
		}
		return repo, newTestAggregator(repo, now)
	}

	repo, agg := newChain("SENSITIVE_PATH_PROBE")
	if _, err := agg.SweepOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	sess := repo.onlySession(t)
	if !sess.AutomationSuspected {
		t.Errorf("chain with 3 stages + indicator must be flagged, basis=%q", sess.AutomationBasis)
	}
	if !strings.Contains(sess.AutomationBasis, "indicator=SENSITIVE_PATH_PROBE") {
		t.Errorf("basis missing indicator: %q", sess.AutomationBasis)
	}

	repo2, agg2 := newChain("")
	if _, err := agg2.SweepOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	sess2 := repo2.onlySession(t)
	if sess2.AutomationSuspected {
		t.Errorf("chain without indicator must not be flagged, basis=%q", sess2.AutomationBasis)
	}
}

// 单调性：命中后标注不回退，basis 冻结在判定时刻（后续事件不再改写）。
func TestSweepOnceAutomationMonotonic(t *testing.T) {
	repo := newFakeRepo()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	identityID := uuid.New()
	t0 := now.Add(-10 * time.Minute) // 近窗事件：两轮 Sweep 都不会被 30min 不活跃收口
	ev1 := evAt(SourceBehaviorEvents, "b1", "req-1", identityID, t0, 15, StageRecon)
	ev1.Signal = "HEADLESS"
	repo.events[SourceBehaviorEvents] = []Event{ev1}
	repo.events[SourceAPIRuntimeEvents] = []Event{
		evAt(SourceAPIRuntimeEvents, "r1", "req-2", identityID, t0.Add(time.Minute), 10, StageAuthProbe),
		evAt(SourceAPIRuntimeEvents, "r2", "req-3", identityID, t0.Add(2*time.Minute), 50, StageExploit),
	}
	agg := newTestAggregator(repo, now)
	if _, err := agg.SweepOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	sess := repo.onlySession(t)
	if !sess.AutomationSuspected {
		t.Fatalf("must be flagged, basis=%q", sess.AutomationBasis)
	}
	frozenBasis := sess.AutomationBasis

	// 第二轮：第四阶段事件并入——标注保持 true，basis 不追加 DATA_ACCESS
	repo.events[SourceAPIRuntimeEvents] = append(repo.events[SourceAPIRuntimeEvents],
		evAt(SourceAPIRuntimeEvents, "r3", "req-4", identityID, t0.Add(3*time.Minute), 15, StageDataAccess))
	if _, err := agg.SweepOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	sess = repo.onlySession(t)
	if !sess.AutomationSuspected || sess.AutomationBasis != frozenBasis {
		t.Errorf("monotonic violated: suspected=%v basis=%q, want frozen %q",
			sess.AutomationSuspected, sess.AutomationBasis, frozenBasis)
	}
}
