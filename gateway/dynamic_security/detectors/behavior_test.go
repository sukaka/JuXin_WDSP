package detectors

import (
	"testing"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// fakeClock 可推进的测试时钟。
type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time          { return c.now }
func (c *fakeClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

func resetBehaviorTrackerForTest(clk *fakeClock) {
	defaultBehaviorTracker = newWindowTracker(behaviorMaxKeys, clk.Now)
}

func TestBehavior_RateSpike(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	resetBehaviorTrackerForTest(clk)
	const key, ek = "ip:10.0.0.1", "GET /v1/orders"
	// 5 个历史窗口，每窗 2 次 → 均值 2，阈值 max(20, 3×2)=20
	for w := 0; w < 5; w++ {
		for i := 0; i < 2; i++ {
			ctx := dsctx.New("t", dsctx.DefaultParseLimits())
			CheckBehavior(ctx, key, ek)
			if ctx.MatchCount() != 0 {
				t.Fatalf("baseline building must not match (window %d)", w)
			}
		}
		clk.Advance(time.Minute)
	}
	// 当前窗口前 20 次不报，第 21 次（>20）报 RATE_SPIKE
	for i := 1; i <= 21; i++ {
		ctx := dsctx.New("t", dsctx.DefaultParseLimits())
		CheckBehavior(ctx, key, ek)
		if i <= 20 && ctx.MatchCount() != 0 {
			t.Fatalf("hit %d below threshold must not match", i)
		}
		if i == 21 {
			m := findMatch(ctx, "behavior.rate_spike")
			if m == nil {
				t.Fatalf("hit %d above threshold must match", i)
			}
			if m.Category != "OBSERVE" || m.Severity != "MEDIUM" || m.ScoreDelta != 15 {
				t.Fatalf("bad attrs: %+v", m)
			}
			if m.Evidence["window_count"] != "21" || m.Evidence["threshold"] != "20" {
				t.Fatalf("bad evidence: %+v", m.Evidence)
			}
		}
	}
}

func TestBehavior_InsufficientHistoryNoMatch(t *testing.T) {
	// 负例：历史窗口样本 <5 时，即使计数远超 20 也不报（基线未建立）
	clk := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	resetBehaviorTrackerForTest(clk)
	const key, ek = "ip:10.0.0.2", "GET /v1/x"
	for i := 0; i < 100; i++ {
		ctx := dsctx.New("t", dsctx.DefaultParseLimits())
		CheckBehavior(ctx, key, ek)
		if ctx.MatchCount() != 0 {
			t.Fatalf("no baseline must not match, got %+v", ctx.CopyMatches())
		}
	}
	// 仅 3 个历史窗口仍不够
	for w := 0; w < 3; w++ {
		clk.Advance(time.Minute)
		for i := 0; i < 30; i++ {
			ctx := dsctx.New("t", dsctx.DefaultParseLimits())
			CheckBehavior(ctx, key, ek)
			if ctx.MatchCount() != 0 {
				t.Fatalf("3 history windows < 5 must not match, got %+v", ctx.CopyMatches())
			}
		}
	}
}

func TestBehavior_BelowThresholdNoMatch(t *testing.T) {
	// 负例：基线建立后未超阈值不报
	clk := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	resetBehaviorTrackerForTest(clk)
	const key, ek = "ip:10.0.0.3", "GET /v1/y"
	for w := 0; w < 5; w++ {
		for i := 0; i < 30; i++ {
			CheckBehavior(dsctx.New("t", dsctx.DefaultParseLimits()), key, ek)
		}
		clk.Advance(time.Minute)
	}
	// 历史均值 30 → 阈值 max(20, 90)=90；当前窗口 50 次不超
	for i := 0; i < 50; i++ {
		ctx := dsctx.New("t", dsctx.DefaultParseLimits())
		CheckBehavior(ctx, key, ek)
		if ctx.MatchCount() != 0 {
			t.Fatalf("below 3x baseline must not match, got %+v", ctx.CopyMatches())
		}
	}
}

func TestBehavior_IdentityIsolation(t *testing.T) {
	// 不同 identity/endpoint 维度互不污染
	clk := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	resetBehaviorTrackerForTest(clk)
	for w := 0; w < 5; w++ {
		for i := 0; i < 2; i++ {
			CheckBehavior(dsctx.New("t", dsctx.DefaultParseLimits()), "ip:10.0.0.4", "GET /v1/a")
		}
		clk.Advance(time.Minute)
	}
	// 另一个 identity 无基线，高频也不报
	for i := 0; i < 100; i++ {
		ctx := dsctx.New("t", dsctx.DefaultParseLimits())
		CheckBehavior(ctx, "ip:10.0.0.5", "GET /v1/a")
		if ctx.MatchCount() != 0 {
			t.Fatalf("other identity must not be affected, got %+v", ctx.CopyMatches())
		}
	}
}
