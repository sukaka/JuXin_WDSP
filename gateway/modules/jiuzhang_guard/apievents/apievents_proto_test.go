// apievents_proto_test.go 事件协议可见性字段测试（W14-GW）：
// proto（HTTP 协议版本）与 protocol（应用层协议族）序列化存在与省略、超长清洗。
package apievents

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// proto/protocol 字段随事件落盘；缺省时省略（事件零变化，采集端容忍缺失）。
func TestEmitProtoAndProtocolFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "api-events.log")
	l, err := NewLogger(path, "node-1")
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}
	defer func() { _ = l.Close() }()

	// 携带两个协议字段
	if err := l.Emit(Record{RequestID: "req-proto-1", EndpointKey: "POST /pkg.Svc/Call",
		Proto: "HTTP/2.0", Protocol: "GRPC"}); err != nil {
		t.Fatalf("emit: %v", err)
	}
	// 缺省省略
	if err := l.Emit(Record{RequestID: "req-proto-2", EndpointKey: "POST /v1/orders"}); err != nil {
		t.Fatalf("emit: %v", err)
	}
	// 超长清洗（防日志注入/膨胀）
	if err := l.Emit(Record{RequestID: "req-proto-3", EndpointKey: "POST /v1/x",
		Proto: strings.Repeat("H", 64) + "\nINJECT", Protocol: strings.Repeat("G", 64)}); err != nil {
		t.Fatalf("emit: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 {
		t.Fatalf("want 3 lines, got %d", len(lines))
	}
	var withProto, without map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &withProto); err != nil {
		t.Fatalf("line1: %v", err)
	}
	if withProto["proto"] != "HTTP/2.0" || withProto["protocol"] != "GRPC" {
		t.Fatalf("proto/protocol = %v/%v", withProto["proto"], withProto["protocol"])
	}
	if err := json.Unmarshal([]byte(lines[1]), &without); err != nil {
		t.Fatalf("line2: %v", err)
	}
	if _, ok := without["proto"]; ok {
		t.Fatal("proto must be omitted when empty")
	}
	if _, ok := without["protocol"]; ok {
		t.Fatal("protocol must be omitted when empty")
	}
	var cleaned Record
	if err := json.Unmarshal([]byte(lines[2]), &cleaned); err != nil {
		t.Fatalf("line3: %v", err)
	}
	if len(cleaned.Proto) > maxProtoLen || strings.Contains(cleaned.Proto, "\n") || len(cleaned.Protocol) > maxProtoLen {
		t.Fatalf("sanitize broken: %q/%q", cleaned.Proto, cleaned.Protocol)
	}
}
