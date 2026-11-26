package events

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSemanticDetailSanitizeAndOmit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.log")
	l, err := NewLogger(path, "gw-sem-1")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	if err := l.Emit(Event{
		RequestID: "req-sem-1",
		ClientIP:  "198.51.100.20",
		EventType: SemanticBlocked,
		Action:    "BLOCK",
		Semantic: &SemanticDetail{
			PolicyVersion: 4,
			Mode:          "PROTECT\n",
			Channel:       "llm_prompt\r",
			RuleID:        "semantic.prompt_injection",
			Label:         "prompt_injection\x00",
			Score:         0.94,
			ModelID:       "onnx-int8-v1\nINJECT",
			LatencyMS:     5,
			InputRunes:    128,
			FailPolicy:    "FAIL_CLOSED",
			ActionTaken:   "BLOCKED",
			Reason:        "score_exceeds_block_threshold\nline2",
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := l.Emit(Event{
		RequestID: "req-sem-2",
		ClientIP:  "198.51.100.21",
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
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %d", len(lines))
	}
	var got Event
	if err := json.Unmarshal([]byte(lines[0]), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Semantic == nil {
		t.Fatal("expected semantic detail")
	}
	if got.Semantic.Mode != "PROTECT" || got.Semantic.Channel != "llm_prompt" ||
		got.Semantic.Label != "prompt_injection" || got.Semantic.ModelID != "onnx-int8-v1INJECT" ||
		got.Semantic.Reason != "score_exceeds_block_thresholdline2" {
		t.Fatalf("control chars not sanitized: %+v", got.Semantic)
	}
	if got.Semantic.Score != 0.94 || got.Semantic.LatencyMS != 5 || got.Semantic.InputRunes != 128 {
		t.Fatalf("numeric fields mismatch: %+v", got.Semantic)
	}
	if strings.Contains(lines[1], `"semantic"`) {
		t.Fatalf("non-semantic event must omit semantic key: %s", lines[1])
	}
}
