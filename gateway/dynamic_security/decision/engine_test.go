package decision

import (
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

func TestDecideMultiMatchFinalAction(t *testing.T) {
	ctx := dsctx.New("rid-1", dsctx.DefaultParseLimits())
	// detectors only add matches — they do not set FinalAction
	ctx.AddMatch(dsctx.DetectorMatch{Detector: "waf", Category: "BLOCK", Severity: "HIGH", ScoreDelta: 50, RuleID: "942100"})
	ctx.AddMatch(dsctx.DetectorMatch{Detector: "api_schema", Category: "OBSERVE", Severity: "MEDIUM", ScoreDelta: 10, RuleID: "schema.extra_field"})
	if ctx.GetFinalAction() != dsctx.ActionUnset {
		t.Fatal("detectors must not set final action")
	}
	act := Decide(ctx, Input{Mode: ModeProtect})
	if act != dsctx.ActionBlock {
		t.Fatalf("action=%s", act)
	}
	if ctx.GetFinalAction() != dsctx.ActionBlock {
		t.Fatal(ctx.GetFinalAction())
	}
	if ctx.MatchCount() != 2 {
		t.Fatal(ctx.MatchCount())
	}
}

func TestDecideObserveMode(t *testing.T) {
	ctx := dsctx.New("rid-2", dsctx.DefaultParseLimits())
	ctx.AddMatch(dsctx.DetectorMatch{Detector: "waf", Severity: "HIGH", ScoreDelta: 50})
	act := Decide(ctx, Input{Mode: ModeObserve})
	if act != dsctx.ActionObserve {
		t.Fatalf("got %s", act)
	}
}

func TestDecideAllowWhenClean(t *testing.T) {
	ctx := dsctx.New("rid-3", dsctx.DefaultParseLimits())
	act := Decide(ctx, Input{Mode: ModeProtect})
	if act != dsctx.ActionAllow {
		t.Fatal(act)
	}
}

func TestDecideIgnoresInfoIdentity(t *testing.T) {
	ctx := dsctx.New("rid-info", dsctx.DefaultParseLimits())
	ctx.AddMatch(dsctx.DetectorMatch{
		Detector: "identity", RuleID: "identity.token_present",
		Category: "INFO", Severity: "INFO",
	})
	act := Decide(ctx, Input{Mode: ModeProtect})
	if act != dsctx.ActionAllow {
		t.Fatalf("INFO must not force observe/block, got %s", act)
	}
}
