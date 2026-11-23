package urlwhitelist

import (
	"testing"
	"time"
)

func TestNewRuleSetValidation(t *testing.T) {
	cases := []struct {
		name string
		rule Rule
	}{
		{"missing id", Rule{MatchType: MatchExact, URIPattern: "/health"}},
		{"empty pattern", Rule{ID: "r1", MatchType: MatchExact, URIPattern: ""}},
		{"no leading slash", Rule{ID: "r1", MatchType: MatchExact, URIPattern: "health"}},
		{"query in pattern", Rule{ID: "r1", MatchType: MatchExact, URIPattern: "/api?a=1"}},
		{"invalid regex", Rule{ID: "r1", MatchType: MatchRegex, URIPattern: "[unclosed"}},
		{"unknown match type", Rule{ID: "r1", MatchType: "CONTAINS", URIPattern: "/api"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewRuleSet([]Rule{tc.rule}); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}

func TestMatchModesAndPathBoundary(t *testing.T) {
	now := time.Now()
	rs, err := NewRuleSet([]Rule{
		{ID: "exact-health", MatchType: MatchExact, URIPattern: "/healthz", Priority: 10},
		{ID: "prefix-api", MatchType: MatchPrefix, URIPattern: "/api/public", Priority: 20},
		{ID: "prefix-slash", MatchType: MatchPrefix, URIPattern: "/static/", Priority: 30},
		{ID: "regex-cb", MatchType: MatchRegex, URIPattern: `^/webhooks/[0-9]+/notify$`, Methods: []string{"POST"}, Priority: 40},
	})
	if err != nil {
		t.Fatalf("NewRuleSet: %v", err)
	}

	// Exact match + canonical path traversal / double-slash handling
	if d := rs.Match("/healthz", "GET", now); !d.Matched || d.RuleID != "exact-health" {
		t.Fatalf("expected exact-health, got %+v", d)
	}
	if d := rs.Match("//healthz", "GET", now); !d.Matched || d.RuleID != "exact-health" {
		t.Fatalf("expected canonical exact-health, got %+v", d)
	}
	if d := rs.Match("/healthz/extra", "GET", now); d.Matched {
		t.Fatalf("exact rule should not match subpath: %+v", d)
	}

	// Prefix boundary: /api/public matches /api/public and /api/public/v1, NOT /api/public-admin
	if d := rs.Match("/api/public", "GET", now); !d.Matched || d.RuleID != "prefix-api" {
		t.Fatalf("expected prefix-api for exact prefix, got %+v", d)
	}
	if d := rs.Match("/api/public/v1/status", "GET", now); !d.Matched || d.RuleID != "prefix-api" {
		t.Fatalf("expected prefix-api for child path, got %+v", d)
	}
	if d := rs.Match("/api/public-admin/delete", "GET", now); d.Matched {
		t.Fatalf("prefix-api must NOT match sibling prefix /api/public-admin: %+v", d)
	}
	// Traversal out of prefix must NOT match
	if d := rs.Match("/api/public/../admin/secret", "GET", now); d.Matched {
		t.Fatalf("traversal out of prefix must NOT match: %+v", d)
	}

	// Trailing slash prefix: /static/ matches /static/a.js, NOT /static
	if d := rs.Match("/static/a.js", "GET", now); !d.Matched || d.RuleID != "prefix-slash" {
		t.Fatalf("expected prefix-slash, got %+v", d)
	}
	if d := rs.Match("/static", "GET", now); d.Matched {
		t.Fatalf("/static/ must not match bare /static: %+v", d)
	}

	// Regex + method filtering
	if d := rs.Match("/webhooks/42/notify", "POST", now); !d.Matched || d.RuleID != "regex-cb" {
		t.Fatalf("expected regex-cb for POST, got %+v", d)
	}
	if d := rs.Match("/webhooks/42/notify", "GET", now); d.Matched {
		t.Fatalf("regex-cb should not match GET: %+v", d)
	}
}

func TestPriorityExpiryAndLayeredEvaluate(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Minute)
	future := now.Add(time.Hour)

	globalSet, err := NewRuleSet([]Rule{
		{ID: "expired", MatchType: MatchExact, URIPattern: "/cb", Priority: 1, EffectiveUntil: &past},
		{ID: "not-yet", MatchType: MatchExact, URIPattern: "/cb", Priority: 2, EffectiveFrom: &future},
		{ID: "g-low", MatchType: MatchPrefix, URIPattern: "/cb", Priority: 50},
		{ID: "g-high", MatchType: MatchExact, URIPattern: "/cb", Priority: 10, EffectiveUntil: &future},
	})
	if err != nil {
		t.Fatalf("global NewRuleSet: %v", err)
	}
	appSet, err := NewRuleSet([]Rule{
		{ID: "app-only", MatchType: MatchExact, URIPattern: "/app-health", Priority: 5},
		{ID: "app-cb", MatchType: MatchExact, URIPattern: "/cb", Priority: 1},
	})
	if err != nil {
		t.Fatalf("app NewRuleSet: %v", err)
	}

	// Global takes priority over app; within global, priority 10 beats 50 and skips expired/future
	d := Evaluate("/cb", "GET", now, globalSet, appSet)
	if !d.Matched || d.RuleID != "g-high" || len(d.MatchedRuleIDs) != 2 {
		t.Fatalf("unexpected global decision: %+v", d)
	}
	// Falls through to app layer when global does not match
	d2 := Evaluate("/app-health", "GET", now, globalSet, appSet)
	if !d2.Matched || d2.RuleID != "app-only" {
		t.Fatalf("unexpected app decision: %+v", d2)
	}
}
