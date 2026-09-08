package riskengine

import (
	"net/http/httptest"
	"testing"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/identitybehavior"
	"go.uber.org/zap"
)

func newTestEngine(t *testing.T, p *Params) *Engine {
	t.Helper()
	cfg, err := Compile(p, zap.NewNop())
	if err != nil || cfg == nil {
		t.Fatalf("compile: %v %v", cfg, err)
	}
	return NewEngine(cfg, NewMemoryStore(cfg.Window(), 0, zap.NewNop()), zap.NewNop())
}

// 阈值边界：39 → PASS；40..79 → RATE_LIMIT；80 → BLOCK。
func TestEvaluateThresholdBoundaries(t *testing.T) {
	eng := newTestEngine(t, &Params{Enabled: true, Mode: ModeProtect, Version: 1})
	now := time.Now().UTC()
	add := func(score int) {
		if err := eng.store.Add("id1", entryAt("WAF", score, now)); err != nil {
			t.Fatal(err)
		}
	}
	add(39)
	dec, err := eng.Evaluate("id1")
	if err != nil || dec.Action != ActionPass || dec.Score != 39 || dec.Threshold != 0 || dec.Level != "MEDIUM" {
		t.Fatalf("39: %+v %v", dec, err)
	}
	add(40) // 79：RATE_LIMIT 档上界
	dec, _ = eng.Evaluate("id1")
	if dec.Action != ActionRateLimit || dec.Score != 79 || dec.Threshold != 40 || dec.Level != "CRITICAL" {
		t.Fatalf("79: %+v", dec)
	}
	add(1) // 80 达 block_threshold
	dec, _ = eng.Evaluate("id1")
	if dec.Action != ActionBlock || dec.Score != 80 || dec.Threshold != 80 {
		t.Fatalf("80: %+v", dec)
	}
	// RATE_LIMIT 档：40..79
	eng2 := newTestEngine(t, &Params{Enabled: true})
	_ = eng2.store.Add("id1", entryAt("AUTH_FAIL_PROBE", 40, now))
	dec, _ = eng2.Evaluate("id1")
	if dec.Action != ActionRateLimit || dec.Threshold != 40 || dec.Level != "HIGH" {
		t.Fatalf("40: %+v", dec)
	}
}

// scores 覆盖表：命中键覆盖信号自带分；显式 0 = 该信号不计分；未命中键用自带分。
func TestScoreOverrides(t *testing.T) {
	eng := newTestEngine(t, &Params{Enabled: true, Scores: map[string]int{"WAF": 30, "HEADLESS": 0}})
	eng.AddSignal("id1", "WAF", 50, "sqli")       // 覆盖 50 → 30
	eng.AddSignal("id1", "HEADLESS", 10, "ua")    // 覆盖为 0 → 不计
	eng.AddSignal("id1", "API_SCHEMA", 15, "dev") // 未覆盖 → 自带 15
	dec, _ := eng.Evaluate("id1")
	if dec.Score != 45 || len(dec.Signals) != 2 {
		t.Fatalf("overrides: %+v", dec)
	}
	if dec.Signals[0].Type != "WAF" || dec.Signals[0].Score != 30 {
		t.Fatalf("override entry: %+v", dec.Signals[0])
	}
}

// AddIdentitySignals：identitybehavior 信号名原样入账（signal_type 契约）。
func TestAddIdentitySignals(t *testing.T) {
	eng := newTestEngine(t, &Params{Enabled: true})
	eng.AddIdentitySignals("id1", []identitybehavior.Signal{
		{Signal: identitybehavior.SignalSensitivePathProbe, ScoreDelta: 15, Reason: "probe"},
		{Signal: identitybehavior.SignalHeadless, ScoreDelta: 10, Reason: "ua"},
	})
	dec, _ := eng.Evaluate("id1")
	if dec.Score != 25 || dec.Signals[0].Type != "SENSITIVE_PATH_PROBE" || dec.Signals[1].Type != "HEADLESS" {
		t.Fatalf("identity signals: %+v", dec)
	}
}

// AddDetectorMatches：仅 ScoreDelta>0 入账；signal_type=detector 名大写蛇形；reason 含 rule_id。
func TestAddDetectorMatches(t *testing.T) {
	eng := newTestEngine(t, &Params{Enabled: true})
	eng.AddDetectorMatches("id1", []dsctx.DetectorMatch{
		{Detector: "waf", RuleID: "waf.downstream_intercept", ScoreDelta: 50, Message: "blocked by downstream WAF"},
		{Detector: "api_schema", RuleID: "schema.type_mismatch", ScoreDelta: 15},
		{Detector: "api_parser", ScoreDelta: 0, Message: "zero must be skipped"},
		{Detector: "authentication", ScoreDelta: -5, Message: "negative must be skipped"},
	})
	dec, _ := eng.Evaluate("id1")
	if dec.Score != 65 || len(dec.Signals) != 2 {
		t.Fatalf("detector matches: %+v", dec)
	}
	if dec.Signals[0].Type != "WAF" || dec.Signals[0].Reason == "" {
		t.Fatalf("waf signal: %+v", dec.Signals[0])
	}
	if dec.Signals[1].Type != "API_SCHEMA" {
		t.Fatalf("schema signal: %+v", dec.Signals[1])
	}
}

// ShouldEmit 事件节流：60s / identity+action。
func TestShouldEmitThrottle(t *testing.T) {
	eng := newTestEngine(t, &Params{Enabled: true})
	base := time.Now().UTC()
	eng.now = func() time.Time { return base }
	if !eng.ShouldEmit("id1", "blocked") {
		t.Fatal("first emit must pass")
	}
	if eng.ShouldEmit("id1", "blocked") {
		t.Fatal("second within 60s must be throttled")
	}
	if !eng.ShouldEmit("id1", "rate_limited") {
		t.Fatal("different action must not share throttle")
	}
	if !eng.ShouldEmit("id2", "blocked") {
		t.Fatal("different identity must not share throttle")
	}
	eng.now = func() time.Time { return base.Add(time.Minute + time.Second) }
	if !eng.ShouldEmit("id1", "blocked") {
		t.Fatal("after 60s must emit again")
	}
}

// IdentityKeyFor：identity_behavior 未启用时按同一算法现场解析（确定性同键）。
func TestIdentityKeyForDeterministic(t *testing.T) {
	r1 := httptest.NewRequest("GET", "http://waf-test.local/", nil)
	r1.Header.Set("User-Agent", "sqlmap/1.7")
	r2 := httptest.NewRequest("GET", "http://waf-test.local/", nil)
	r2.Header.Set("User-Agent", "sqlmap/1.7")
	k1 := IdentityKeyFor(r1, "salt", "203.0.113.10")
	k2 := IdentityKeyFor(r2, "salt", "203.0.113.11")
	if k1 == "" || k1 != k2 {
		t.Fatalf("same UA anon identity must share key across IPs: %q %q", k1, k2)
	}
	r3 := httptest.NewRequest("GET", "http://waf-test.local/", nil)
	r3.Header.Set("X-API-Key", "key-abc")
	if k3 := IdentityKeyFor(r3, "salt", "203.0.113.10"); k3 == k1 {
		t.Fatal("credential identity must differ from anon")
	}
}
