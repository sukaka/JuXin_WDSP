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

func TestBuildPrimaryCarriesContextIdentifierFields(t *testing.T) {
	ctx := dsctx.New("req-evt-2", dsctx.DefaultParseLimits())
	ctx.DeviceFingerprint = "fp-32-hex"
	ctx.SetObjectIdentifiers([]dsctx.ObjectIdentifier{
		{Source: "path", Param: "id", ValueHash: "h1"},
	})
	ev := BuildPrimary("evt-2", ctx, "GET /users/{id}")
	if ev.DeviceFingerprint != "fp-32-hex" {
		t.Fatalf("device fingerprint not carried: %q", ev.DeviceFingerprint)
	}
	if len(ev.ObjectIdentifiers) != 1 || ev.ObjectIdentifiers[0].ValueHash != "h1" {
		t.Fatalf("object identifiers not carried: %+v", ev.ObjectIdentifiers)
	}
	// 快照拷贝：改上下文不影响已构建事件
	ctx.ObjectIdentifiers[0].ValueHash = "mutated"
	if ev.ObjectIdentifiers[0].ValueHash != "h1" {
		t.Fatal("event must snapshot a copy of object identifiers")
	}
	// 空字段保持零值（omitempty 由序列化方保证键省略）
	empty := BuildPrimary("evt-3", dsctx.New("req-evt-3", dsctx.DefaultParseLimits()), "GET /x")
	if empty.DeviceFingerprint != "" || empty.ObjectIdentifiers != nil {
		t.Fatalf("empty context must yield zero fields: %+v", empty)
	}
}
