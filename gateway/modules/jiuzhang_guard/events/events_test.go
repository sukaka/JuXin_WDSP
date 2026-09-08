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
		Proto:     "HTTP/2.0",
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
	if got.Proto != "HTTP/2.0" {
		t.Errorf("proto = %q, want HTTP/2.0", got.Proto)
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

// Proto 为空时省略字段（旧版采集端 JSON 兼容，缺失容忍）。
func TestEmitProtoOmittedWhenEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.log")
	l, err := NewLogger(path, "node-1")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	if err := l.Emit(Event{RequestID: "req-2", ClientIP: "203.0.113.2", EventType: IPAllowMatch}); err != nil {
		t.Fatal(err)
	}
	l.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"proto"`) {
		t.Errorf("empty proto must be omitted: %s", data)
	}
}

// BotDetail 序列化与脱敏：仅 BOT_* 事件携带 bot 对象；字段截断/控制字符剥离；
// 其余事件 bot 键缺省（omitempty 零变化——旧采集端 JSON 兼容）。
func TestEmitBotDetail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.log")
	l, err := NewLogger(path, "node-1")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// 带 Bot 明细的事件：控制字符剥离 + 长度截断
	if err := l.Emit(Event{
		RequestID: "req-bot-1",
		ClientIP:  "203.0.113.3",
		EventType: BotVerifyRejected,
		Action:    "REJECT",
		Bot: &BotDetail{
			PolicyVersion: 7,
			PolicyEpoch:   7,
			Mode:          "PROTECT",
			Reason:        "BAD_SOLUTION\nINJECT",
			FlowID:        "0123456789abcdef",
			KeyID:         "bot-key-a",
			Attempts:      2,
		},
	}); err != nil {
		t.Fatal(err)
	}
	// 无 Bot 明细的事件：bot 键缺省
	if err := l.Emit(Event{RequestID: "req-bot-2", ClientIP: "203.0.113.4", EventType: IPDenyMatch}); err != nil {
		t.Fatal(err)
	}
	l.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines: %d", len(lines))
	}
	// 控制字符已剥离（\n 删除后两段拼接，单行 JSON 无换行注入）
	if strings.Contains(lines[0], `\n`) || len(strings.Split(lines[0], "\n")) != 1 {
		t.Errorf("bot.reason must be single-line: %s", lines[0])
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(lines[0]), &parsed); err != nil {
		t.Fatal(err)
	}
	bot, ok := parsed["bot"].(map[string]interface{})
	if !ok {
		t.Fatalf("bot detail missing: %s", lines[0])
	}
	if bot["reason"] != "BAD_SOLUTIONINJECT" || bot["flow_id"] != "0123456789abcdef" || bot["key_id"] != "bot-key-a" {
		t.Errorf("bot detail fields: %v", bot)
	}
	if strings.Contains(lines[1], `"bot"`) {
		t.Errorf("non-bot event must omit bot key: %s", lines[1])
	}
}
