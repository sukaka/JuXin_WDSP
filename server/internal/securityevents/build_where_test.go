package securityevents

import (
	"strings"
	"testing"
	"time"
)

func TestBuildListWhereRuleIDUsesCorrelatedExistsAndTimeBounds(t *testing.T) {
	ruleID := 942100
	start := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)

	where, args := buildListWhere(ListFilter{
		StartTime: &start,
		EndTime:   &end,
		RuleID:    &ruleID,
	})
	if strings.Contains(where, "id IN (SELECT event_id") {
		t.Fatalf("RuleID filter must not use unbounded IN subquery: %s", where)
	}
	for _, want := range []string{
		"EXISTS (SELECT 1 FROM security_event_matches m",
		"m.event_id = security_events.id",
		"m.event_occurred_at = security_events.occurred_at",
		"m.rule_id = $3",
		"m.event_occurred_at >= $4",
		"m.event_occurred_at <= $5",
	} {
		if !strings.Contains(where, want) {
			t.Fatalf("where missing %q: %s", want, where)
		}
	}
	if len(args) != 5 {
		t.Fatalf("args len = %d, want 5 (%v)", len(args), args)
	}
}
