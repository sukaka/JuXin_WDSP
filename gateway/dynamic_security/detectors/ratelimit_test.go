package detectors

import (
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

func resetAPIWriteTrackerForTest() {
	defaultAPIWriteTracker = newWindowTracker(apiWriteMaxKeys, nil)
}

func TestAPIWriteRate_Exceeded(t *testing.T) {
	resetAPIWriteTrackerForTest()
	const key, ek = "auth:abc", "POST /v1/orders"
	for i := 1; i <= 3; i++ {
		ctx := dsctx.New("t", dsctx.DefaultParseLimits())
		CheckAPIWriteRate(ctx, key, ek, 3)
		if ctx.MatchCount() != 0 {
			t.Fatalf("hit %d at/below limit must not match", i)
		}
	}
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	CheckAPIWriteRate(ctx, key, ek, 3)
	m := findMatch(ctx, "ratelimit.api_write_rate")
	if m == nil {
		t.Fatalf("over limit must match, got %+v", ctx.CopyMatches())
	}
	if m.Category != "RATE_LIMIT" || m.Severity != "HIGH" || m.ScoreDelta != 30 {
		t.Fatalf("bad attrs: %+v", m)
	}
	if m.Evidence["limit"] != "3" || m.Evidence["window_count"] != "4" {
		t.Fatalf("bad evidence: %+v", m.Evidence)
	}
}

func TestAPIWriteRate_AtLimitNoMatch(t *testing.T) {
	// 负例：恰好等于阈值不报
	resetAPIWriteTrackerForTest()
	const key, ek = "auth:def", "PUT /v1/profile"
	for i := 0; i < 5; i++ {
		ctx := dsctx.New("t", dsctx.DefaultParseLimits())
		CheckAPIWriteRate(ctx, key, ek, 5)
		if ctx.MatchCount() != 0 {
			t.Fatalf("at limit must not match, got %+v", ctx.CopyMatches())
		}
	}
}

func TestAPIWriteRate_DefaultLimit60(t *testing.T) {
	// limit ≤ 0 走默认 60：第 61 次才报
	resetAPIWriteTrackerForTest()
	const key, ek = "auth:ghi", "DELETE /v1/items/{id}"
	for i := 1; i <= 61; i++ {
		ctx := dsctx.New("t", dsctx.DefaultParseLimits())
		CheckAPIWriteRate(ctx, key, ek, 0)
		if i <= 60 && ctx.MatchCount() != 0 {
			t.Fatalf("hit %d under default limit must not match", i)
		}
		if i == 61 {
			m := findMatch(ctx, "ratelimit.api_write_rate")
			if m == nil || m.Evidence["limit"] != "60" {
				t.Fatalf("hit 61 must match with default limit, got %+v", ctx.CopyMatches())
			}
		}
	}
}

func TestAPIWriteRate_EndpointIsolation(t *testing.T) {
	// 负例：不同端点计数隔离
	resetAPIWriteTrackerForTest()
	for i := 0; i < 3; i++ {
		CheckAPIWriteRate(dsctx.New("t", dsctx.DefaultParseLimits()), "auth:jkl", "POST /v1/a", 3)
	}
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	CheckAPIWriteRate(ctx, "auth:jkl", "POST /v1/b", 3)
	if ctx.MatchCount() != 0 {
		t.Fatalf("different endpoint must not share counter, got %+v", ctx.CopyMatches())
	}
}

func TestIsWriteMethod(t *testing.T) {
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		if !IsWriteMethod(m) {
			t.Fatalf("%s must be write method", m)
		}
	}
	for _, m := range []string{"GET", "HEAD", "OPTIONS", ""} {
		if IsWriteMethod(m) {
			t.Fatalf("%s must not be write method", m)
		}
	}
}
