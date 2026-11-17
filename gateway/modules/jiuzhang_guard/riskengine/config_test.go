package riskengine

import (
	"fmt"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// 缺省/未启用 = 零配置（nil）。
func TestCompileDefaults(t *testing.T) {
	if c, err := Compile(nil, nil); c != nil || err != nil {
		t.Fatalf("nil params: %v %v", c, err)
	}
	if c, err := Compile(&Params{Enabled: false}, nil); c != nil || err != nil {
		t.Fatalf("disabled: %v %v", c, err)
	}
	c, err := Compile(&Params{Enabled: true}, nil)
	if err != nil || c == nil {
		t.Fatalf("enabled: %v %v", c, err)
	}
	if c.Mode != ModeObserve || c.BlockThreshold != 80 || c.RateLimitThreshold != 40 ||
		c.RateLimitRPS != 10 || c.SignalWindowSeconds != 86400 {
		t.Fatalf("defaults: %+v", c)
	}
	if c.LevelMedium != 20 || c.LevelHigh != 40 || c.LevelCritical != 70 {
		t.Fatalf("level defaults: %+v", c)
	}
}

// 冻结契约示例全量下发原样生效。
func TestCompileFrozenContractExample(t *testing.T) {
	c, err := Compile(&Params{
		Enabled: true, Mode: "OBSERVE", Version: 1,
		BlockThreshold: 80, RateLimitThreshold: 40, RateLimitRPS: 10,
		SignalWindowSeconds: 86400,
		Scores:              map[string]int{"SIGNAL_TYPE": 15},
		RiskLevels:          &RiskLevels{Medium: 20, High: 40, Critical: 70},
	}, nil)
	if err != nil || c == nil {
		t.Fatalf("compile: %v", err)
	}
	if c.Mode != ModeObserve || c.Version != 1 || c.Scores["SIGNAL_TYPE"] != 15 {
		t.Fatalf("contract fields: %+v", c)
	}
}

// 非法配置 fail-open 按 OBSERVE/默认值：逐项消毒 + Warn，绝不返回错误。
func TestCompileInvalidFailOpen(t *testing.T) {
	core, logs := observer.New(zap.WarnLevel)
	c, err := Compile(&Params{
		Enabled: true, Mode: "BLOCK_EVERYTHING", Version: -1,
		BlockThreshold: -5, RateLimitThreshold: 0, RateLimitRPS: -2,
		SignalWindowSeconds: -1,
		Scores:              map[string]int{"BAD": -1, "OK": 25},
		RiskLevels:          &RiskLevels{Medium: 70, High: 40, Critical: 20},
	}, zap.New(core))
	if err != nil || c == nil {
		t.Fatalf("invalid config must not fail compile: %v %v", c, err)
	}
	if c.Mode != ModeObserve {
		t.Fatalf("invalid mode must fall back to OBSERVE: %s", c.Mode)
	}
	if c.Version != 0 || c.BlockThreshold != 80 || c.RateLimitThreshold != 40 ||
		c.RateLimitRPS != 10 || c.SignalWindowSeconds != 86400 {
		t.Fatalf("invalid values must fall back to defaults: %+v", c)
	}
	if _, ok := c.Scores["BAD"]; ok || c.Scores["OK"] != 25 {
		t.Fatalf("negative score entry must be dropped: %v", c.Scores)
	}
	if c.LevelMedium != 20 || c.LevelHigh != 40 || c.LevelCritical != 70 {
		t.Fatalf("non-ascending levels must fall back: %+v", c)
	}
	if logs.Len() == 0 {
		t.Fatal("sanitizing must warn (不静默吞错)")
	}
}

// mode=PROTECT 原样生效；rate_limit_threshold >= block_threshold 告警但保留（BLOCK 优先）。
func TestCompileProtectAndInvertedThresholds(t *testing.T) {
	core, logs := observer.New(zap.WarnLevel)
	c, err := Compile(&Params{Enabled: true, Mode: ModeProtect, BlockThreshold: 40, RateLimitThreshold: 60},
		zap.New(core))
	if err != nil || c.Mode != ModeProtect {
		t.Fatalf("protect: %v %+v", err, c)
	}
	if c.BlockThreshold != 40 || c.RateLimitThreshold != 60 {
		t.Fatalf("thresholds kept as published: %+v", c)
	}
	if logs.Len() == 0 {
		t.Fatal("inverted thresholds must warn")
	}
}

// 风险等级边界映射（含截断上界 100）。
func TestLevelMapping(t *testing.T) {
	c, _ := Compile(&Params{Enabled: true}, nil)
	cases := map[int]string{0: "LOW", 19: "LOW", 20: "MEDIUM", 39: "MEDIUM", 40: "HIGH", 69: "HIGH", 70: "CRITICAL", 100: "CRITICAL"}
	for score, want := range cases {
		if got := c.Level(score); got != want {
			t.Fatalf("level(%d) = %s, want %s", score, got, want)
		}
	}
}

func TestCompileChallengeDefaultAndInvalidOnlyDisableNewTier(t *testing.T) {
	c, err := Compile(&Params{Enabled: true, Mode: ModeProtect}, nil)
	if err != nil || c.ChallengeThreshold != 0 {
		t.Fatalf("challenge must default off: %+v, err=%v", c, err)
	}
	for _, threshold := range []int{-1, 101, 20, 40, 80, 90} {
		t.Run(fmt.Sprintf("threshold_%d", threshold), func(t *testing.T) {
			core, logs := observer.New(zap.WarnLevel)
			c, err := Compile(&Params{
				Enabled: true, Mode: ModeProtect, BlockThreshold: 80,
				ChallengeThreshold: threshold, RateLimitThreshold: 40, RateLimitRPS: 7,
			}, zap.New(core))
			if err != nil || c == nil {
				t.Fatalf("compile: %+v, err=%v", c, err)
			}
			if c.ChallengeThreshold != 0 {
				t.Fatalf("invalid/inverted challenge tier must be disabled: %+v", c)
			}
			if c.BlockThreshold != 80 || c.RateLimitThreshold != 40 || c.RateLimitRPS != 7 || c.Mode != ModeProtect {
				t.Fatalf("legacy behavior must remain intact: %+v", c)
			}
			if logs.Len() == 0 {
				t.Fatal("disabled invalid/inverted challenge tier must warn")
			}
		})
	}
}
