package events

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWasmPluginDetailSanitizeAndOmit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.log")
	l, err := NewLogger(path, "gw-wasm-1")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	if err := l.Emit(Event{
		RequestID: "req-wasm-1",
		ClientIP:  "198.51.100.30",
		EventType: WasmPluginBlock,
		Action:    "BLOCK",
		WasmPlugin: &WasmPluginDetail{
			PluginID:      "plg-1\n",
			PluginName:    "sql_guard\r",
			PluginVersion: 3,
			ABIVersion:    "wdsp_v1\x00",
			Mode:          "PROTECT\n",
			SHA256:        strings.Repeat("a", 64) + "extra",
			RuleID:        "custom.rule\r\n1",
			Reason:        "blocked_pattern\x7f" + strings.Repeat("x", 200),
			ScoreDelta:    80,
			LatencyMS:     1,
			FailPolicy:    "FAIL_CLOSED\n",
			ActionTaken:   "blocked\r",
			Error:         "boom\nline2",
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := l.Emit(Event{
		RequestID: "req-wasm-2",
		ClientIP:  "198.51.100.31",
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
	if got.WasmPlugin == nil {
		t.Fatal("expected wasm_plugin detail")
	}
	if got.WasmPlugin.PluginID != "plg-1" || got.WasmPlugin.PluginName != "sql_guard" ||
		got.WasmPlugin.ABIVersion != "wdsp_v1" || got.WasmPlugin.Mode != "PROTECT" ||
		got.WasmPlugin.RuleID != "custom.rule1" || got.WasmPlugin.FailPolicy != "FAIL_CLOSED" ||
		got.WasmPlugin.ActionTaken != "blocked" || got.WasmPlugin.Error != "boomline2" {
		t.Fatalf("control chars not sanitized: %+v", got.WasmPlugin)
	}
	if len(got.WasmPlugin.SHA256) != 64 {
		t.Fatalf("sha256 not bounded to 64: len=%d", len(got.WasmPlugin.SHA256))
	}
	if len(got.WasmPlugin.Reason) != 128 {
		t.Fatalf("reason not bounded to 128: len=%d", len(got.WasmPlugin.Reason))
	}
	if got.WasmPlugin.PluginVersion != 3 || got.WasmPlugin.ScoreDelta != 80 || got.WasmPlugin.LatencyMS != 1 {
		t.Fatalf("numeric fields mismatch: %+v", got.WasmPlugin)
	}
	if strings.Contains(lines[1], `"wasm_plugin"`) {
		t.Fatalf("non-wasm event must omit wasm_plugin key: %s", lines[1])
	}
}
