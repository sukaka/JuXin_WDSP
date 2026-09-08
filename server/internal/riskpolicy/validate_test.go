package riskpolicy

import (
	"testing"
)

func validPolicy() *Policy {
	return &Policy{
		Enabled:             true,
		Mode:                ModeObserve,
		Version:             1,
		BlockThreshold:      80,
		RateLimitThreshold:  40,
		RateLimitRPS:        10,
		SignalWindowSeconds: 86400,
		Scores:              map[string]int{"URI_ENUMERATION": 15, "SQLI": 50},
		RiskLevels:          map[string]int{"medium": 20, "high": 40, "critical": 70},
	}
}

// TestValidateDefaultsOK 合法默认策略通过校验。
func TestValidateDefaultsOK(t *testing.T) {
	if errs := Validate(validPolicy()); len(errs) != 0 {
		t.Fatalf("valid policy rejected: %+v", errs)
	}
}

// TestValidateMode 仅支持 OBSERVE / PROTECT。
func TestValidateMode(t *testing.T) {
	p := validPolicy()
	p.Mode = "ENFORCE"
	assertFieldErr(t, Validate(p), "mode")

	p = validPolicy()
	p.Mode = ModeProtect
	if errs := Validate(p); len(errs) != 0 {
		t.Fatalf("PROTECT mode rejected: %+v", errs)
	}
}

// TestValidateThresholds 阈值必须 1-100 且限速阈值小于阻断阈值。
func TestValidateThresholds(t *testing.T) {
	p := validPolicy()
	p.BlockThreshold = 0
	assertFieldErr(t, Validate(p), "block_threshold")

	p = validPolicy()
	p.RateLimitThreshold = 101
	assertFieldErr(t, Validate(p), "rate_limit_threshold")

	p = validPolicy()
	p.RateLimitThreshold = 80 // 等于阻断阈值 → 倒置
	assertFieldErr(t, Validate(p), "rate_limit_threshold")

	// 阻断阈值本身非法时不重复报交叉错误（只报 block_threshold）
	p = validPolicy()
	p.BlockThreshold = 0
	p.RateLimitThreshold = 40
	errs := Validate(p)
	assertFieldErr(t, errs, "block_threshold")
	if len(errs) != 1 {
		t.Fatalf("want exactly 1 error, got %+v", errs)
	}
}

// TestValidateRPS 限速 RPS 必须 > 0。
func TestValidateRPS(t *testing.T) {
	p := validPolicy()
	p.RateLimitRPS = 0
	assertFieldErr(t, Validate(p), "rate_limit_rps")
}

// TestValidateWindow 信号窗口必须 1-604800 秒。
func TestValidateWindow(t *testing.T) {
	p := validPolicy()
	p.SignalWindowSeconds = 0
	assertFieldErr(t, Validate(p), "signal_window_seconds")

	p = validPolicy()
	p.SignalWindowSeconds = 604801
	assertFieldErr(t, Validate(p), "signal_window_seconds")
}

// TestValidateScores scores 键为合法信号类型格式、值 0-100。
func TestValidateScores(t *testing.T) {
	p := validPolicy()
	p.Scores = map[string]int{"lower_case": 10}
	assertFieldErr(t, Validate(p), "scores")

	p = validPolicy()
	p.Scores = map[string]int{"URI_ENUMERATION": 101}
	assertFieldErr(t, Validate(p), "scores.URI_ENUMERATION")
}

// TestValidateRiskLevels risk_levels 恰为三键、值 0-100 且严格递增。
func TestValidateRiskLevels(t *testing.T) {
	p := validPolicy()
	p.RiskLevels = map[string]int{"medium": 20, "high": 40}
	assertFieldErr(t, Validate(p), "risk_levels")

	p = validPolicy()
	p.RiskLevels = map[string]int{"medium": 20, "high": 40, "critical": 70, "fatal": 90}
	assertFieldErr(t, Validate(p), "risk_levels")

	p = validPolicy()
	p.RiskLevels = map[string]int{"medium": 40, "high": 40, "critical": 70}
	assertFieldErr(t, Validate(p), "risk_levels.high")

	p = validPolicy()
	p.RiskLevels = map[string]int{"medium": 20, "high": 101, "critical": 102}
	assertFieldErr(t, Validate(p), "risk_levels.high")
}

func assertFieldErr(t *testing.T, errs []FieldError, field string) {
	t.Helper()
	for _, e := range errs {
		if e.Field == field {
			return
		}
	}
	t.Fatalf("want field error %q, got %+v", field, errs)
}
