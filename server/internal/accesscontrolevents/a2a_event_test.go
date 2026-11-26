package accesscontrolevents

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

func a2aDetailFixture() map[string]interface{} {
	return map[string]interface{}{
		"policy_version":   3,
		"mode":             "PROTECT",
		"method":           "tasks/send",
		"agent_name":       "billing-agent",
		"agent_url":        "https://agents.example.com/billing",
		"agent_version":    "1.2.0",
		"skills":           []string{"invoice.read", "invoice.refund"},
		"auth_schemes":     []string{"oauth2", "bearer"},
		"delegation_depth": 2,
		"rule_id":          "a2a.delegation_depth_exceeded",
		"action_taken":     "BLOCKED",
		"reason":           "delegation depth exceeded",
	}
}

func TestParseA2AEventsAllTypes(t *testing.T) {
	for _, evType := range A2AEventTypes {
		t.Run(evType, func(t *testing.T) {
			d := a2aDetailFixture()
			d["unknown_secret_token"] = "must-be-dropped"
			evt, err := ParseEventLine(validLine(t, map[string]interface{}{
				"event_type": evType,
				"action":     "REJECT",
				"a2a":        d,
				"final_decision": map[string]interface{}{
					"schema_version": 1,
					"action":         "BLOCK",
				},
			}), "default-node")
			if err != nil {
				t.Fatalf("valid %s line rejected: %v", evType, err)
			}
			a2a, ok := evt.Details["a2a"].(map[string]interface{})
			if !ok {
				t.Fatalf("details.a2a missing: %+v", evt.Details)
			}
			if a2a["policy_version"] != 3 || a2a["agent_name"] != "billing-agent" ||
				a2a["delegation_depth"] != 2 || a2a["rule_id"] != "a2a.delegation_depth_exceeded" {
				t.Errorf("details.a2a mismatch: %+v", a2a)
			}
			if _, leaked := a2a["unknown_secret_token"]; leaked {
				t.Errorf("undeclared field must be dropped: %+v", a2a)
			}
			if _, ok := evt.Details["final_decision"]; !ok {
				t.Error("final_decision must be preserved alongside details.a2a")
			}
			if label := formatACEventType(evType); label == evType {
				t.Errorf("missing Chinese export label for %s", evType)
			}
		})
	}
}

func TestParseA2AEventMissingDetailRejectedAndCaps(t *testing.T) {
	if _, err := ParseEventLine(validLine(t, map[string]interface{}{
		"event_type": EventTypeA2ABlocked,
		"action":     "REJECT",
	}), "default-node"); err == nil {
		t.Fatal("A2A_* event missing a2a object must fail parse")
	}

	manySkills := make([]string, 40)
	for i := range manySkills {
		manySkills[i] = "skill-" + strings.Repeat("x", 5)
	}
	manySchemes := make([]string, 20)
	for i := range manySchemes {
		manySchemes[i] = "scheme"
	}
	evt, err := ParseEventLine(validLine(t, map[string]interface{}{
		"event_type": EventTypeA2AAgentCardDiscovered,
		"action":     "OBSERVE",
		"a2a": map[string]interface{}{
			"agent_name":   "capped-agent",
			"skills":       manySkills,
			"auth_schemes": manySchemes,
		},
	}), "default-node")
	if err != nil {
		t.Fatalf("valid capped line rejected: %v", err)
	}
	a2a := evt.Details["a2a"].(map[string]interface{})
	if skills := a2a["skills"].([]string); len(skills) != 32 {
		t.Fatalf("skills cap = %d, want 32", len(skills))
	}
	if schemes := a2a["auth_schemes"].([]string); len(schemes) != 16 {
		t.Fatalf("auth_schemes cap = %d, want 16", len(schemes))
	}
}

type fakeA2AIngester struct {
	mu     sync.Mutex
	events []*Event
	err    error
}

func (f *fakeA2AIngester) IngestEvent(_ context.Context, evt *Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := *evt
	f.events = append(f.events, &cp)
	return f.err
}

func TestCollectorA2AIngesterAndFailOpen(t *testing.T) {
	dir := t.TempDir()
	lineCard := validLine(t, map[string]interface{}{
		"request_id": "a2a-1",
		"event_type": EventTypeA2AAgentCardDiscovered,
		"action":     "OBSERVE",
		"a2a":        a2aDetailFixture(),
	})
	lineLoop := validLine(t, map[string]interface{}{
		"request_id": "a2a-2",
		"event_type": EventTypeA2ALoopKilled,
		"action":     "REJECT",
		"a2a":        a2aDetailFixture(),
	})
	lineCC := validLine(t, map[string]interface{}{
		"request_id": "cc-1",
		"event_type": EventTypeCCRequestRejected,
		"action":     ActionReject,
	})
	logPath := writeEventsFile(t, dir, lineCard, lineLoop, lineCC)

	// 1. 正常回调：仅 A2A_* 触发 ingester
	store := &fakeEventStore{}
	ing := &fakeA2AIngester{}
	c := NewCollector(store, "a2a-test", logPath, "", "gw-1")
	c.SetA2AIngester(ing)

	n, err := c.CollectOnce(context.Background())
	if err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}
	if n != 3 || len(store.events) != 3 {
		t.Fatalf("processed=%d inserted=%d, want 3/3", n, len(store.events))
	}
	if len(ing.events) != 2 {
		t.Fatalf("a2a ingester received %d events, want 2", len(ing.events))
	}
	if ing.events[0].RequestID != "a2a-1" || ing.events[1].RequestID != "a2a-2" {
		t.Fatalf("unexpected ingested events: %+v", ing.events)
	}

	// 2. Fail-open：ingester 返回错误不得阻塞主事件入库或中断 CollectOnce
	dir2 := t.TempDir()
	logPath2 := writeEventsFile(t, dir2, lineCard, lineCC)
	store2 := &fakeEventStore{}
	ingFail := &fakeA2AIngester{err: errors.New("a2a db temporarily unavailable")}
	c2 := NewCollector(store2, "a2a-failopen", logPath2, "", "gw-1")
	c2.SetA2AIngester(ingFail)

	n2, err := c2.CollectOnce(context.Background())
	if err != nil {
		t.Fatalf("CollectOnce must fail-open when a2a ingester errors: %v", err)
	}
	if n2 != 2 || len(store2.events) != 2 {
		t.Fatalf("main event log must still persist all events on fail-open: n=%d inserted=%d", n2, len(store2.events))
	}
}
