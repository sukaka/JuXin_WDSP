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

// 阶段5 §6.5：client_ip_source/trusted_proxy_used/forwarded_chain_summary
// 三字段随事件输出（截断 + 控制字符剥离）；空值键缺省（omitempty，旧采集端兼容）。
func TestEmitRealClientIPFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.log")
	l, err := NewLogger(path, "node-1")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	if err := l.Emit(Event{
		RequestID:             "req-ip-1",
		ClientIP:              "198.51.100.9",
		ConnectionIP:          "10.0.0.1",
		EventType:             IPDenyMatch,
		ClientIPSource:        "X_FORWARDED_FOR",
		TrustedProxyUsed:      "lb-1",
		ForwardedChainSummary: strings.Repeat("9.9.9.9, ", 40) + "\nINJECT",
	}); err != nil {
		t.Fatal(err)
	}
	// 直连事件：source 恒有（CONNECTION），其余两键缺省
	if err := l.Emit(Event{
		RequestID:      "req-ip-2",
		ClientIP:       "203.0.113.5",
		ConnectionIP:   "203.0.113.5",
		EventType:      IPAllowMatch,
		ClientIPSource: "CONNECTION",
	}); err != nil {
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
	var got Event
	if err := json.Unmarshal([]byte(lines[0]), &got); err != nil {
		t.Fatalf("event not json: %v", err)
	}
	if got.ClientIPSource != "X_FORWARDED_FOR" || got.TrustedProxyUsed != "lb-1" {
		t.Errorf("real client ip fields: %+v", got)
	}
	if len(got.ForwardedChainSummary) > 256 || strings.Contains(got.ForwardedChainSummary, "INJECT") {
		t.Errorf("chain summary not sanitized/truncated: len=%d", len(got.ForwardedChainSummary))
	}
	if !strings.Contains(lines[0], `"client_ip_source"`) {
		t.Errorf("client_ip_source key missing: %s", lines[0])
	}
	// 空值键缺省（旧采集端 JSON 兼容）
	if strings.Contains(lines[1], `"trusted_proxy_used"`) || strings.Contains(lines[1], `"forwarded_chain_summary"`) {
		t.Errorf("empty real-client-ip keys must be omitted: %s", lines[1])
	}
	var direct Event
	if err := json.Unmarshal([]byte(lines[1]), &direct); err != nil {
		t.Fatalf("event not json: %v", err)
	}
	if direct.ClientIPSource != "CONNECTION" {
		t.Errorf("direct connection source = %q, want CONNECTION", direct.ClientIPSource)
	}
}

func TestEmitA2ADetailSanitizeAndCap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.log")
	l, err := NewLogger(path, "node-1")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	skills := make([]string, 40)
	for i := range skills {
		skills[i] = "skill-\n" + strings.Repeat("s", 10)
	}
	schemes := make([]string, 20)
	for i := range schemes {
		schemes[i] = "Bearer\r\n"
	}

	if err := l.Emit(Event{
		RequestID: "req-a2a-1",
		ClientIP:  "198.51.100.10",
		EventType: A2AAgentCardDiscovered,
		Action:    "DISCOVERED",
		A2A: &A2ADetail{
			PolicyVersion:   2,
			Mode:            "PROTECT",
			Method:          "GET",
			AgentName:       "Agent\nInject",
			AgentURL:        "https://agent.example.com/a2a",
			AgentVersion:    "1.0.0",
			Skills:          skills,
			AuthSchemes:     schemes,
			DelegationDepth: 2,
			RuleID:          "a2a.delegation_depth_exceeded",
			ActionTaken:     "BLOCKED",
			Reason:          "depth\nexceeded",
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := l.Emit(Event{RequestID: "req-a2a-2", ClientIP: "198.51.100.11", EventType: IPAllowMatch}); err != nil {
		t.Fatal(err)
	}
	l.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines=%d", len(lines))
	}
	var got Event
	if err := json.Unmarshal([]byte(lines[0]), &got); err != nil {
		t.Fatal(err)
	}
	if got.A2A == nil {
		t.Fatal("missing a2a detail")
	}
	if got.A2A.AgentName != "AgentInject" || got.A2A.Reason != "depthexceeded" {
		t.Fatalf("control chars not stripped: %+v", got.A2A)
	}
	if len(got.A2A.Skills) != 32 || len(got.A2A.AuthSchemes) != 16 {
		t.Fatalf("caps not enforced: skills=%d auth=%d", len(got.A2A.Skills), len(got.A2A.AuthSchemes))
	}
	if strings.Contains(lines[1], `"a2a"`) {
		t.Fatalf("non-A2A event must omit a2a key: %s", lines[1])
	}
}
