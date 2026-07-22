package events

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEmitAndSanitize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.log")
	l, err := NewLogger(path, "node-1")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	long := strings.Repeat("a", 600)
	ev := Event{
		RequestID: "req-1",
		ClientIP:  "203.0.113.1",
		Path:      long + "\nINJECT",
		EventType: IPDenyMatch,
	}
	if err := l.Emit(ev); err != nil {
		t.Fatal(err)
	}
	l.Close()

	f, _ := os.Open(path)
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		t.Fatal("no event written")
	}
	line := sc.Text()
	var got Event
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatalf("event not json: %v", err)
	}
	if got.GatewayNode != "node-1" || got.EventType != IPDenyMatch {
		t.Errorf("fields: %+v", got)
	}
	if len(got.Path) > 512 || strings.Contains(got.Path, "INJECT") {
		t.Errorf("path not sanitized: len=%d", len(got.Path))
	}
	if got.OccurredAt.IsZero() {
		t.Error("occurred_at should be set")
	}
	// 单行（无换行注入）
	if sc.Scan() {
		t.Error("event must be single line")
	}
}
