package decision

import (
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

func TestDecideRateLimitActionMapping(t *testing.T) {
	for _, tc := range []struct {
		name   string
		action string
		mode   Mode
		want   dsctx.FinalAction
	}{
		{name: "default", want: dsctx.ActionRateLimit},
		{name: "explicit rate limit", action: "RATE_LIMIT", want: dsctx.ActionRateLimit},
		{name: "block", action: "BLOCK", want: dsctx.ActionBlock},
		{name: "temp block", action: "TEMP_BLOCK", want: dsctx.ActionTempBlock},
		{name: "case and whitespace normalized", action: " temp_block ", want: dsctx.ActionTempBlock},
		{name: "unknown remains safe default", action: "NOT_VALID", want: dsctx.ActionRateLimit},
		{name: "observe block", action: "BLOCK", mode: ModeObserve, want: dsctx.ActionObserve},
		{name: "observe temp block", action: "TEMP_BLOCK", mode: ModeObserve, want: dsctx.ActionObserve},
		{name: "observe rate limit", action: "RATE_LIMIT", mode: ModeObserve, want: dsctx.ActionObserve},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mode := tc.mode
			if mode == "" {
				mode = ModeProtect
			}
			ctx := dsctx.New("rid-rate-action", dsctx.DefaultParseLimits())
			ctx.AddMatch(dsctx.DetectorMatch{Detector: "api_ratelimit", RuleID: "ratelimit.action_rate", Category: "RATE_LIMIT", Severity: "HIGH", ScoreDelta: 30})
			if got := Decide(ctx, Input{Mode: mode, RateLimitAction: tc.action}); got != tc.want {
				t.Fatalf("action=%s want=%s", got, tc.want)
			}
			if ctx.GetFinalAction() != tc.want {
				t.Fatalf("final=%s want=%s", ctx.GetFinalAction(), tc.want)
			}
		})
	}
}
