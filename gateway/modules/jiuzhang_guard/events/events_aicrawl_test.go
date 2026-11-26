package events

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	dsevents "github.com/jiuzhang-waf/gateway/dynamic_security/events"
)

func TestEmitAICrawlDetailAndJWTTokenBindingSanitize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.log")
	l, err := NewLogger(path, "node-9a")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// 1. TokenBindingVerified control char stripping & length cap in e.JWT.
	if err := l.Emit(Event{
		RequestID: "req-jwt-bind-1",
		ClientIP:  "203.0.113.10",
		EventType: JWTObserved,
		Action:    "OBSERVE",
		JWT: &dsevents.JWTVerification{
			Status:               "VERIFIED",
			ReasonCode:           "OK",
			TokenBindingVerified: "DPOP\nINJECT" + strings.Repeat("x", 64),
		},
	}); err != nil {
		t.Fatal(err)
	}

	// 2. AICrawlDetail sanitization & serialization.
	origDetail := &AICrawlDetail{
		PolicyVersion:      4,
		Mode:               "PROTECT\n",
		Category:           "AI_TRAINING\r",
		AgentID:            "agent-1",
		AgentSlug:          "gptbot\n",
		AgentName:          "GPTBot",
		SignatureAgent:     "https://bot.example\n/inject",
		SignatureVerified:  true,
		SignatureKeyID:     "kid-1",
		SignatureReason:    "OK",
		RuleID:             "rule-1",
		RuleName:           "Block Training",
		Action:             "HTTP_402",
		ExemptBotChallenge: true,
		LabyrinthDepth:     2,
		TrapValid:          true,
	}
	if err := l.Emit(Event{
		RequestID: "req-aicrawl-1",
		ClientIP:  "203.0.113.11",
		EventType: AICrawlTrapHit,
		Action:    "TARPIT",
		AICrawl:   origDetail,
	}); err != nil {
		t.Fatal(err)
	}

	// 3. Non-AICrawl event omits ai_crawl key.
	if err := l.Emit(Event{
		RequestID: "req-plain-1",
		ClientIP:  "203.0.113.12",
		EventType: IPAllowMatch,
	}); err != nil {
		t.Fatal(err)
	}
	_ = l.Close()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 single-line events, got %d", len(lines))
	}

	var evJWT Event
	if err := json.Unmarshal([]byte(lines[0]), &evJWT); err != nil {
		t.Fatal(err)
	}
	if evJWT.JWT == nil || len(evJWT.JWT.TokenBindingVerified) != 32 || strings.Contains(evJWT.JWT.TokenBindingVerified, "\n") {
		t.Fatalf("TokenBindingVerified not sanitized/truncated: %+v", evJWT.JWT)
	}

	var evAC Event
	if err := json.Unmarshal([]byte(lines[1]), &evAC); err != nil {
		t.Fatal(err)
	}
	if evAC.EventType != AICrawlTrapHit || evAC.AICrawl == nil {
		t.Fatalf("AICrawl event missing detail: %+v", evAC)
	}
	if evAC.AICrawl.Mode != "PROTECT" || evAC.AICrawl.Category != "AI_TRAINING" ||
		strings.Contains(evAC.AICrawl.SignatureAgent, "\n") || evAC.AICrawl.LabyrinthDepth != 2 || !evAC.AICrawl.TrapValid {
		t.Fatalf("AICrawl detail unexpected: %+v", evAC.AICrawl)
	}
	// Ensure caller's pointer was not mutated by Emit.
	if origDetail.Mode != "PROTECT\n" {
		t.Fatalf("Emit mutated caller's AICrawlDetail pointer")
	}

	if strings.Contains(lines[2], `"ai_crawl"`) {
		t.Fatalf("non-aicrawl event must omit ai_crawl key: %s", lines[2])
	}
}
