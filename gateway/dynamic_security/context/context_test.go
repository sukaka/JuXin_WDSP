package context

import (
	"testing"
)

func TestNewDefaults(t *testing.T) {
	c := New("req-1", ParseLimits{})
	if c.RequestID != "req-1" {
		t.Fatal(c.RequestID)
	}
	if c.Limits.MaxBodyParseBytes != 1<<20 {
		t.Fatalf("limits not defaulted: %+v", c.Limits)
	}
	if c.RiskLevel != RiskNone || c.FinalAction != ActionUnset {
		t.Fatal("unexpected initial risk/action")
	}
}

func TestAddMatchUpdatesScore(t *testing.T) {
	c := New("r", DefaultParseLimits())
	c.AddMatch(DetectorMatch{Detector: "waf", RuleID: "942100", ScoreDelta: 30, Message: "sqli"})
	if c.MatchCount() != 1 {
		t.Fatal(c.MatchCount())
	}
	if c.RiskScore != 30 || c.RiskLevel != RiskMedium {
		t.Fatalf("score=%d level=%s", c.RiskScore, c.RiskLevel)
	}
	c.AddMatch(DetectorMatch{Detector: "api_schema", ScoreDelta: 30})
	if c.RiskLevel != RiskHigh {
		t.Fatalf("level=%s", c.RiskLevel)
	}
}

func TestFinalActionAndExtension(t *testing.T) {
	c := New("r", DefaultParseLimits())
	c.SetFinalAction(ActionBlock)
	if c.GetFinalAction() != ActionBlock {
		t.Fatal(c.GetFinalAction())
	}
	c.SetExtension("api.endpoint_template", "/users/{id}")
	if c.Extensions["api.endpoint_template"] != "/users/{id}" {
		t.Fatal(c.Extensions)
	}
}
