package accesscontrolevents

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

func clientSideDetailFixture() map[string]interface{} {
	return map[string]interface{}{
		"policy_version":     2,
		"mode":               "PROTECT",
		"violation_type":     "UNAUTHORIZED_SCRIPT",
		"script_url":         "https://evil.example/skim.js",
		"script_origin":      "https://evil.example",
		"script_type":        "EXTERNAL",
		"expected_sri":       "sha384-expected",
		"observed_sri":       "sha384-observed",
		"page_path":          "/checkout",
		"violated_directive": "script-src",
		"blocked_uri":        "https://evil.example/skim.js",
		"action_taken":       "STRIPPED",
		"reason":             "unauthorized_external_script",
	}
}

func TestParseClientSideEventsAllTypes(t *testing.T) {
	for _, evType := range ClientSideEventTypes {
		t.Run(evType, func(t *testing.T) {
			d := clientSideDetailFixture()
			d["unknown_future_secret"] = "should-be-dropped"
			evt, err := ParseEventLine(validLine(t, map[string]interface{}{
				"event_type":  evType,
				"action":      "OBSERVE",
				"client_side": d,
				"final_decision": map[string]interface{}{
					"schema_version": 1,
					"action":         "OBSERVE",
				},
			}), "default-node")
			if err != nil {
				t.Fatalf("valid %s line rejected: %v", evType, err)
			}
			cs, ok := evt.Details["client_side"].(map[string]interface{})
			if !ok {
				t.Fatalf("details.client_side missing: %+v", evt.Details)
			}
			if cs["policy_version"] != 2 || cs["script_url"] != "https://evil.example/skim.js" || cs["action_taken"] != "STRIPPED" {
				t.Errorf("details.client_side mismatch: %+v", cs)
			}
			if _, leaked := cs["unknown_future_secret"]; leaked {
				t.Errorf("undeclared field must be dropped: %+v", cs)
			}
			if _, ok := evt.Details["final_decision"]; !ok {
				t.Error("final_decision must be preserved alongside details.client_side")
			}
			// 验证 CSV 导出中文标签已覆盖
			if label := formatACEventType(evType); label == evType {
				t.Errorf("missing Chinese export label for %s", evType)
			}
		})
	}
}

func TestParseClientSideEventMissingDetailRejected(t *testing.T) {
	if _, err := ParseEventLine(validLine(t, map[string]interface{}{
		"event_type": EventTypeClientSideUnauthorizedScript,
		"action":     "OBSERVE",
	}), "default-node"); err == nil {
		t.Fatal("CLIENT_SIDE_* event missing client_side object must fail parse")
	}
}

type fakeClientSideIngester struct {
	mu     sync.Mutex
	events []*Event
	err    error
}

func (f *fakeClientSideIngester) IngestEvent(_ context.Context, evt *Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := *evt
	f.events = append(f.events, &cp)
	return f.err
}

func TestCollectorClientSideIngesterAndFailOpen(t *testing.T) {
	dir := t.TempDir()
	lineObserved := validLine(t, map[string]interface{}{
		"request_id":  "cs-1",
		"event_type":  EventTypeClientSideScriptObserved,
		"action":      "OBSERVE",
		"client_side": clientSideDetailFixture(),
	})
	lineViolation := validLine(t, map[string]interface{}{
		"request_id":  "cs-2",
		"event_type":  EventTypeClientSideCSPViolation,
		"action":      "LOG",
		"client_side": clientSideDetailFixture(),
	})
	lineCC := validLine(t, map[string]interface{}{
		"request_id": "cc-1",
		"event_type": EventTypeCCRequestRejected,
		"action":     ActionReject,
	})
	logPath := writeEventsFile(t, dir, lineObserved, lineViolation, lineCC)

	// 1. 正常回调：仅 CLIENT_SIDE_* 触发 ingester
	store := &fakeEventStore{}
	ing := &fakeClientSideIngester{}
	c := NewCollector(store, "cs-test", logPath, "", "gw-1")
	c.SetClientSideIngester(ing)

	n, err := c.CollectOnce(context.Background())
	if err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}
	if n != 3 || len(store.events) != 3 {
		t.Fatalf("processed=%d inserted=%d, want 3/3", n, len(store.events))
	}
	if len(ing.events) != 2 {
		t.Fatalf("clientSide ingester received %d events, want 2", len(ing.events))
	}
	if ing.events[0].RequestID != "cs-1" || ing.events[1].RequestID != "cs-2" {
		t.Fatalf("unexpected ingested events: %+v", ing.events)
	}

	// 2. Fail-open：ingester 返回错误不得阻塞主事件入库或中断 CollectOnce
	dir2 := t.TempDir()
	logPath2 := writeEventsFile(t, dir2, lineObserved, lineCC)
	store2 := &fakeEventStore{}
	ingFail := &fakeClientSideIngester{err: errors.New("inventory db temporarily unavailable")}
	c2 := NewCollector(store2, "cs-failopen", logPath2, "", "gw-1")
	c2.SetClientSideIngester(ingFail)

	n2, err := c2.CollectOnce(context.Background())
	if err != nil {
		t.Fatalf("CollectOnce must fail-open when clientSide ingester errors: %v", err)
	}
	if n2 != 2 || len(store2.events) != 2 {
		t.Fatalf("main event log must still persist all events on fail-open: n=%d inserted=%d", n2, len(store2.events))
	}
	if !strings.Contains(store2.events[0].EventType, "CLIENT_SIDE_") {
		t.Fatalf("unexpected first event: %+v", store2.events[0])
	}
}
