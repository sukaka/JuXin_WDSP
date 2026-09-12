package identitybehavior

import (
	"net/netip"
	"testing"
)

// compileTestConfig 编译测试配置（enabled；其余走默认/覆盖）。
func compileTestConfig(t *testing.T, mutate func(p *Params)) *Config {
	t.Helper()
	p := &Params{Enabled: true}
	if mutate != nil {
		mutate(p)
	}
	cfg, err := Compile(p, nil)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if cfg == nil {
		t.Fatal("enabled config must compile non-nil")
	}
	return cfg
}

func i64(v int64) *int64     { return &v }
func f64(v float64) *float64 { return &v }
func snapWith(mut func(s *Snapshot)) *Snapshot {
	s := &Snapshot{}
	if mut != nil {
		mut(s)
	}
	return s
}

func signalsOf(cfg *Config, snap *Snapshot, sensitivePrefix string) map[string]Signal {
	out := map[string]Signal{}
	for _, sig := range EvaluateRecon(cfg, snap, sensitivePrefix) {
		out[sig.Signal] = sig
	}
	return out
}

func TestReconURIEnumerationBoundary(t *testing.T) {
	cfg := compileTestConfig(t, nil)
	// 恰好等于阈值 → 命中
	snap := snapWith(func(s *Snapshot) {
		s.Windows[Window5m].UniqueURICount = 50
		s.Windows[Window5m].RequestCount = 60
		s.Windows[Window5m].NewURICount = 48 // 48/60 = 0.8
	})
	sigs := signalsOf(cfg, snap, "")
	sig, ok := sigs[SignalURIEnumeration]
	if !ok {
		t.Fatalf("threshold boundary must fire: %+v", sigs)
	}
	if sig.RuleCode != RuleURIEnumeration || sig.RuleVersion != RuleVersion || sig.ScoreDelta != 15 || sig.Mode != ModeObserve || sig.Window != "5m" {
		t.Fatalf("signal fields: %+v", sig)
	}
	// 恰低一档 → 不命中
	snap.Windows[Window5m].UniqueURICount = 49
	if _, ok := signalsOf(cfg, snap, "")[SignalURIEnumeration]; ok {
		t.Fatal("below unique threshold must not fire")
	}
	snap.Windows[Window5m].UniqueURICount = 50
	snap.Windows[Window5m].NewURICount = 47.9 // 47.9/60 < 0.8
	if _, ok := signalsOf(cfg, snap, "")[SignalURIEnumeration]; ok {
		t.Fatal("below ratio threshold must not fire")
	}
}

func TestReconNotFoundEnumerationBoundary(t *testing.T) {
	cfg := compileTestConfig(t, nil)
	snap := snapWith(func(s *Snapshot) {
		s.Windows[Window5m].RequestCount = 30
		s.Windows[Window5m].Status404Count = 21 // 21/30 = 0.7
	})
	if _, ok := signalsOf(cfg, snap, "")[SignalNotFoundEnumeration]; !ok {
		t.Fatal("threshold boundary must fire")
	}
	snap.Windows[Window5m].RequestCount = 29
	if _, ok := signalsOf(cfg, snap, "")[SignalNotFoundEnumeration]; ok {
		t.Fatal("below min requests must not fire")
	}
	snap.Windows[Window5m].RequestCount = 30
	snap.Windows[Window5m].Status404Count = 20.9
	if _, ok := signalsOf(cfg, snap, "")[SignalNotFoundEnumeration]; ok {
		t.Fatal("below ratio must not fire")
	}
}

func TestReconSensitivePathProbe(t *testing.T) {
	cfg := compileTestConfig(t, nil)
	sigs := signalsOf(cfg, snapWith(nil), "/.git")
	sig, ok := sigs[SignalSensitivePathProbe]
	if !ok {
		t.Fatal("sensitive hit must fire")
	}
	if sig.Window != "request" || sig.Metadata["matched_prefix"] != "/.git" {
		t.Fatalf("sensitive signal: %+v", sig)
	}
	if _, ok := signalsOf(cfg, snapWith(nil), "")[SignalSensitivePathProbe]; ok {
		t.Fatal("no sensitive hit must not fire")
	}
}

func TestReconMethodEnumerationBoundary(t *testing.T) {
	cfg := compileTestConfig(t, nil)
	snap := snapWith(func(s *Snapshot) { s.DistinctMethods = 4 })
	sig, ok := signalsOf(cfg, snap, "")[SignalMethodEnumeration]
	if !ok {
		t.Fatal("boundary must fire")
	}
	if sig.Window != "30m" {
		t.Fatalf("method enum window: %+v", sig)
	}
	snap.DistinctMethods = 3
	if _, ok := signalsOf(cfg, snap, "")[SignalMethodEnumeration]; ok {
		t.Fatal("below threshold must not fire")
	}
}

func TestReconParamMutationAndAuthFailBoundary(t *testing.T) {
	cfg := compileTestConfig(t, nil)
	snap := snapWith(func(s *Snapshot) {
		s.Windows[Window5m].ParameterMutationCount = 30
		s.Windows[Window5m].AuthFailCount = 10
	})
	sigs := signalsOf(cfg, snap, "")
	if sig, ok := sigs[SignalParameterMutation]; !ok || sig.ScoreDelta != 20 {
		t.Fatalf("param mutation boundary: %+v", sigs)
	}
	if _, ok := sigs[SignalAuthFailProbe]; !ok {
		t.Fatalf("auth fail boundary: %+v", sigs)
	}
	snap.Windows[Window5m].ParameterMutationCount = 29
	snap.Windows[Window5m].AuthFailCount = 9
	sigs = signalsOf(cfg, snap, "")
	if _, ok := sigs[SignalParameterMutation]; ok {
		t.Fatal("below param threshold must not fire")
	}
	if _, ok := sigs[SignalAuthFailProbe]; ok {
		t.Fatal("below auth threshold must not fire")
	}
}

func TestReconLowSlowWindows(t *testing.T) {
	cfg := compileTestConfig(t, nil)
	// 30m 命中优先
	snap := snapWith(func(s *Snapshot) {
		s.Windows[Window30m].SensitivePathHits = 10
		s.Windows[Window24h].SensitivePathHits = 12
	})
	sig, ok := signalsOf(cfg, snap, "")[SignalLowSlowRecon]
	if !ok || sig.Window != "30m" {
		t.Fatalf("30m low slow: %+v", sig)
	}
	// 仅 24h 命中
	snap = snapWith(func(s *Snapshot) {
		s.Windows[Window24h].SensitivePathHits = 10
	})
	sig, ok = signalsOf(cfg, snap, "")[SignalLowSlowRecon]
	if !ok || sig.Window != "24h" {
		t.Fatalf("24h low slow: %+v", sig)
	}
	snap = snapWith(func(s *Snapshot) {
		s.Windows[Window30m].SensitivePathHits = 9
		s.Windows[Window24h].SensitivePathHits = 9
	})
	if _, ok := signalsOf(cfg, snap, "")[SignalLowSlowRecon]; ok {
		t.Fatal("below threshold must not fire")
	}
}

// 阈值 0 = 规则关闭；分值 0 = 规则关闭。
func TestReconDisabledByZeroThresholdAndScore(t *testing.T) {
	cfg := compileTestConfig(t, func(p *Params) {
		p.URIEnumUniqueThreshold = i64(0) // 显式 0 关闭
	})
	snap := snapWith(func(s *Snapshot) {
		s.Windows[Window5m].UniqueURICount = 9999
		s.Windows[Window5m].RequestCount = 100
		s.Windows[Window5m].NewURICount = 99
	})
	if _, ok := signalsOf(cfg, snap, "")[SignalURIEnumeration]; ok {
		t.Fatal("zero threshold must disable rule")
	}
	cfg = compileTestConfig(t, func(p *Params) {
		p.Scores = map[string]int{SignalURIEnumeration: 0}
	})
	if _, ok := signalsOf(cfg, snap, "")[SignalURIEnumeration]; ok {
		t.Fatal("zero score must disable rule")
	}
	// 分值可配覆盖
	cfg = compileTestConfig(t, func(p *Params) {
		p.Scores = map[string]int{SignalURIEnumeration: 42}
	})
	if sig, ok := signalsOf(cfg, snap, "")[SignalURIEnumeration]; !ok || sig.ScoreDelta != 42 {
		t.Fatalf("score override: %+v", sig)
	}
	// 未覆盖信号保持默认分值
	if sig, ok := signalsOf(cfg, snapWith(func(s *Snapshot) { s.DistinctMethods = 9 }), "")[SignalMethodEnumeration]; !ok || sig.ScoreDelta != 10 {
		t.Fatalf("default score preserved: %+v", sig)
	}
}

// 阈值可配覆盖（非默认值生效）。
func TestReconThresholdOverride(t *testing.T) {
	cfg := compileTestConfig(t, func(p *Params) {
		p.AuthFailThreshold = i64(3)
	})
	snap := snapWith(func(s *Snapshot) { s.Windows[Window5m].AuthFailCount = 3 })
	if _, ok := signalsOf(cfg, snap, "")[SignalAuthFailProbe]; !ok {
		t.Fatal("overridden threshold must apply")
	}
}

func TestSensitivePathPrefixMatching(t *testing.T) {
	cfg := compileTestConfig(t, nil)
	cases := map[string]string{
		"/.git/config":        "/.git",
		"/.Git/HEAD":          "/.git", // 大小写不敏感
		"/.env":               "/.env",
		"/admin/users":        "/admin",
		"/swagger/index.html": "/swagger",
		"/v3/api-docs":        "/v3/api-docs",
		"/graphql":            "/graphql",
		"/api/users":          "",
		"/":                   "",
	}
	for path, want := range cases {
		if got := cfg.SensitivePathPrefix(path); got != want {
			t.Fatalf("SensitivePathPrefix(%q) = %q, want %q", path, got, want)
		}
	}
	// 可配覆盖
	cfg = compileTestConfig(t, func(p *Params) { p.SensitivePaths = []string{"/internal"} })
	if got := cfg.SensitivePathPrefix("/internal/debug"); got != "/internal" {
		t.Fatalf("custom sensitive paths: %q", got)
	}
	if got := cfg.SensitivePathPrefix("/.git/config"); got != "" {
		t.Fatalf("override replaces defaults: %q", got)
	}
	// 显式空列表 = 无敏感路径
	cfg = compileTestConfig(t, func(p *Params) { p.SensitivePaths = []string{} })
	if got := cfg.SensitivePathPrefix("/.git/config"); got != "" {
		t.Fatalf("explicit empty list must disable: %q", got)
	}
}

func TestWhitelistMatching(t *testing.T) {
	cfg := compileTestConfig(t, func(p *Params) {
		p.WhitelistIPs = []string{"10.0.0.0/8", "192.0.2.7"}
		p.WhitelistUAs = []string{"Internal-Monitor"}
	})
	if !cfg.Whitelisted(netip.MustParseAddr("10.1.2.3"), "") {
		t.Fatal("cidr whitelist")
	}
	if !cfg.Whitelisted(netip.MustParseAddr("192.0.2.7"), "") {
		t.Fatal("bare ip whitelist")
	}
	if cfg.Whitelisted(netip.MustParseAddr("192.0.2.8"), "") {
		t.Fatal("non-whitelisted ip")
	}
	if !cfg.Whitelisted(netip.MustParseAddr("192.0.2.8"), "internal-monitor/1.0") {
		t.Fatal("ua substring whitelist (case-insensitive)")
	}
	if cfg.Whitelisted(netip.MustParseAddr("192.0.2.8"), "curl/8") {
		t.Fatal("non-whitelisted ua")
	}
}

// 编译与校验：nil/disabled 零变化；非法值报错。
func TestCompileAndValidate(t *testing.T) {
	cfg, err := Compile(nil, nil)
	if err != nil || cfg != nil {
		t.Fatalf("nil params: %v %v", cfg, err)
	}
	cfg, err = Compile(&Params{Enabled: false}, nil)
	if err != nil || cfg != nil {
		t.Fatalf("disabled: %v %v", cfg, err)
	}
	if err := ValidateParams(&Params{URIEnumNewRatioThreshold: f64(1.5)}); err == nil {
		t.Fatal("ratio > 1 must fail")
	}
	if err := ValidateParams(&Params{NotFoundRatioThreshold: f64(-0.1)}); err == nil {
		t.Fatal("negative ratio must fail")
	}
	if err := ValidateParams(&Params{AuthFailThreshold: i64(-1)}); err == nil {
		t.Fatal("negative threshold must fail")
	}
	if err := ValidateParams(&Params{Scores: map[string]int{"X": -1}}); err == nil {
		t.Fatal("negative score must fail")
	}
	if err := ValidateParams(&Params{WhitelistIPs: []string{"not-an-ip"}}); err == nil {
		t.Fatal("bad whitelist ip must fail")
	}
	if err := ValidateParams(&Params{SensitivePaths: []string{""}}); err == nil {
		t.Fatal("empty sensitive path must fail")
	}
	if err := ValidateParams(&Params{Enabled: true}); err != nil {
		t.Fatalf("valid params: %v", err)
	}
}
