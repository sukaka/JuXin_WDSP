package events

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEmitClientSideDetailSanitizeAndOmit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.log")
	l, err := NewLogger(path, "node-cs-1")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	origDetail := &ClientSideDetail{
		PolicyVersion:     5,
		Mode:              "PROTECT\nBAD",
		ViolationType:     "UNAUTHORIZED_SCRIPT\r\n",
		ScriptURL:         "https://evil.example/skim.js\nINJECT",
		ScriptOrigin:      "https://evil.example\r",
		ScriptType:        "EXTERNAL",
		ExpectedSRI:       "sha384-AAA",
		ObservedSRI:       "sha384-BBB\x00",
		PagePath:          "/checkout\n/evil",
		ViolatedDirective: "script-src\r\n",
		BlockedURI:        "https://evil.example/skim.js\tbad",
		ActionTaken:       "STRIPPED",
		Reason:            strings.Repeat("r", 600),
	}

	if err := l.Emit(Event{
		RequestID:  "req-cs-1",
		ClientIP:   "203.0.113.10",
		EventType:  ClientSideUnauthorizedScript,
		Action:     "STRIPPED",
		ClientSide: origDetail,
	}); err != nil {
		t.Fatal(err)
	}
	if err := l.Emit(Event{
		RequestID: "req-non-cs",
		ClientIP:  "203.0.113.11",
		EventType: IPAllowMatch,
	}); err != nil {
		t.Fatal(err)
	}
	_ = l.Close()

	// Caller's struct must NOT be mutated by Emit.
	if !strings.Contains(origDetail.ScriptURL, "\n") {
		t.Fatal("Emit must not mutate caller's ClientSideDetail pointer")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 JSONL lines, got %d", len(lines))
	}

	var parsed Event
	if err := json.Unmarshal([]byte(lines[0]), &parsed); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	if parsed.ClientSide == nil {
		t.Fatal("client_side detail missing")
	}
	cs := parsed.ClientSide
	if cs.PolicyVersion != 5 || cs.Mode != "PROTECTBAD" || cs.ViolationType != "UNAUTHORIZED_SCRIPT" ||
		strings.ContainsAny(cs.ScriptURL, "\r\n") || strings.ContainsAny(cs.PagePath, "\r\n") ||
		strings.ContainsAny(cs.BlockedURI, "\t\r\n") || len(cs.Reason) > maxMsgLen {
		t.Fatalf("client_side detail not properly sanitized: %+v", cs)
	}
	if strings.Contains(lines[1], `"client_side"`) {
		t.Fatalf("non-client-side event must omit client_side key: %s", lines[1])
	}
}
