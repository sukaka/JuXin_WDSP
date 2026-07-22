package events

import (
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

func TestBuildPrimaryMultiDetail(t *testing.T) {
	ctx := dsctx.New("req-evt-1", dsctx.DefaultParseLimits())
	ctx.AddMatch(dsctx.DetectorMatch{Detector: "waf", RuleID: "1"})
	ctx.AddMatch(dsctx.DetectorMatch{Detector: "api_schema", RuleID: "2"})
	ctx.SetFinalAction(dsctx.ActionObserve)
	ev := BuildPrimary("evt-1", ctx, "GET /x")
	if ev.RequestID != "req-evt-1" || len(ev.Details) != 2 {
		t.Fatalf("%+v", ev)
	}
	if ev.FinalAction != string(dsctx.ActionObserve) {
		t.Fatal(ev.FinalAction)
	}
}
