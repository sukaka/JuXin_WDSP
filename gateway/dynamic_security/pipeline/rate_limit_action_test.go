package pipeline

import (
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
)

func TestProcessRateLimitActionMapping(t *testing.T) {
	for _, tc := range []struct {
		name       string
		action     string
		mode       decision.Mode
		wantAction string
	}{
		{name: "default", wantAction: "RATE_LIMIT"},
		{name: "rate limit", action: "RATE_LIMIT", wantAction: "RATE_LIMIT"},
		{name: "block", action: "BLOCK", wantAction: "BLOCK"},
		{name: "temp block", action: "TEMP_BLOCK", wantAction: "TEMP_BLOCK"},
		{name: "observe block", action: "BLOCK", mode: decision.ModeObserve, wantAction: "OBSERVE"},
		{name: "observe temp block", action: "TEMP_BLOCK", mode: decision.ModeObserve, wantAction: "OBSERVE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mode := tc.mode
			if mode == "" {
				mode = decision.ModeProtect
			}
			cfg := actionRatePipelineConfig(string(mode), "pipeline-rate-action-"+tc.name)
			cfg.RateLimitAction = tc.action
			first := asmProcess(t, actionRatePipelineRequest(t), cfg)
			if hasRule(first, "ratelimit.action_rate") {
				t.Fatalf("first request must not match: %+v", first.Context.CopyMatches())
			}
			second := asmProcess(t, actionRatePipelineRequest(t), cfg)
			if !hasRule(second, "ratelimit.action_rate") {
				t.Fatalf("second request must match: %+v", second.Context.CopyMatches())
			}
			if string(second.FinalAction) != tc.wantAction {
				t.Fatalf("final action=%s want=%s", second.FinalAction, tc.wantAction)
			}
		})
	}
}
