package apiobserve

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/apievent"
)

func captureWithBody(body string) apievent.CaptureRecord {
	return apievent.CaptureRecord{
		EventID: "request-1", OccurredAt: time.Now().UTC(),
		Source:  apievent.Source{Type: "IN_PROCESS", Language: "java", Framework: "spring-webmvc", AgentVersion: "1.0.0"},
		Service: apievent.Service{Name: "orders", InstanceID: "orders-1"},
		HTTP: apievent.CaptureHTTP{
			Direction: "SERVER", Method: "POST", Host: "orders", PathTemplate: "/orders", Status: 201,
			Request:  apievent.CaptureMessage{ContentType: "application/json", BodyBase64: base64.StdEncoding.EncodeToString([]byte(body)), BodyState: "ANALYZED"},
			Response: apievent.CaptureMessage{ContentType: "application/json", BodyState: "NOT_COLLECTED"},
		},
	}
}

func TestProcessorSensitiveFieldsWithoutRawValues(t *testing.T) {
	processor := NewProcessor("agent-1", []byte("test-hmac-key"), "key-1")
	body := `{"customer":{"mobile":"13800138000","id":"11010519491231002X","name":"alice"},"password":"secret-value"}`
	record, err := processor.Process(captureWithBody(body))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"13800138000", "11010519491231002X", "secret-value", "alice", "body_base64"} {
		if strings.Contains(string(wire), forbidden) {
			t.Fatalf("remote observation contains raw value %q: %s", forbidden, wire)
		}
	}
	types := map[string]string{}
	for _, field := range record.Fields {
		types[field.DataType] = field.DataType
		if field.DataType == "PHONE" || field.DataType == "CN_ID" {
			if !strings.HasPrefix(field.ValueHMAC, "hmac-sha256:") || field.HMACKeyID != "key-1" {
				t.Fatalf("missing sensitive fingerprint: %+v", field)
			}
		}
	}
	if types["PHONE"] == "" || types["CN_ID"] == "" || types["STRING"] == "" {
		t.Fatalf("unexpected types: %+v", types)
	}
}

func TestProcessorSameSensitiveValueHasSameHMAC(t *testing.T) {
	processor := NewProcessor("agent-1", []byte("test-hmac-key"), "key-1")
	first, err := processor.Process(captureWithBody(`{"mobile":"13800138000"}`))
	if err != nil {
		t.Fatal(err)
	}
	second, err := processor.Process(captureWithBody(`{"mobile":"13800138000"}`))
	if err != nil {
		t.Fatal(err)
	}
	if first.Fields[0].ValueHMAC != second.Fields[0].ValueHMAC {
		t.Fatal("identical normalized value should have identical HMAC")
	}
}

func TestProcessorUnsupportedAndInvalidJSON(t *testing.T) {
	processor := NewProcessor("agent-1", nil, "")
	capture := captureWithBody(`{"mobile":"13800138000"}`)
	capture.HTTP.Request.ContentType = "text/plain"
	record, err := processor.Process(capture)
	if err != nil {
		t.Fatal(err)
	}
	if record.Quality.RequestBodyState != "UNSUPPORTED_CONTENT_TYPE" || len(record.Fields) != 0 {
		t.Fatalf("unexpected unsupported result: %+v", record)
	}
	capture = captureWithBody(`{"broken":`)
	record, err = processor.Process(capture)
	if err != nil {
		t.Fatal(err)
	}
	if record.Quality.RequestBodyState != "DECODE_FAILED" || len(record.Fields) != 0 {
		t.Fatalf("unexpected decode result: %+v", record)
	}
}

func TestProcessorRejectsOversizeBatch(t *testing.T) {
	processor := NewProcessor("agent-1", nil, "")
	if _, err := processor.ProcessBatch(apievent.CaptureBatch{SchemaVersion: 1, Records: make([]apievent.CaptureRecord, 101)}); err == nil {
		t.Fatal("expected batch limit error")
	}
}

func TestProcessorPreservesObservedAddresses(t *testing.T) {
	capture := captureWithBody(`{"ok":true}`)
	capture.HTTP.PeerAddress = "192.0.2.10"
	capture.HTTP.ClientAddress = "192.0.2.10"
	capture.HTTP.ClientAddressSource = "DIRECT_PEER"
	capture.HTTP.ServerAddress = "10.20.30.40"
	record, err := NewProcessor("agent-1", nil, "").Process(capture)
	if err != nil {
		t.Fatal(err)
	}
	if record.HTTP.PeerAddress != "192.0.2.10" ||
		record.HTTP.ClientAddress != "192.0.2.10" ||
		record.HTTP.ClientAddressSource != "DIRECT_PEER" ||
		record.HTTP.ServerAddress != "10.20.30.40" {
		t.Fatalf("observed addresses were not preserved: %+v", record.HTTP)
	}
}

func TestProcessorLegacyPeerAddressRemainsCompatible(t *testing.T) {
	capture := captureWithBody(`{"ok":true}`)
	capture.HTTP.PeerAddress = "192.0.2.10"
	record, err := NewProcessor("agent-1", nil, "").Process(capture)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(record.HTTP)
	if err != nil {
		t.Fatal(err)
	}
	if record.HTTP.PeerAddress != "192.0.2.10" || record.HTTP.ClientAddress != "" ||
		record.HTTP.ClientAddressSource != "" || record.HTTP.ServerAddress != "" {
		t.Fatalf("legacy peer address semantics changed: %+v", record.HTTP)
	}
	for _, field := range []string{"client_address", "client_address_source", "server_address"} {
		if strings.Contains(string(wire), field) {
			t.Fatalf("empty optional field %q must be omitted: %s", field, wire)
		}
	}
}

func TestProcessorMaxBodyBytesAndPathTruncation(t *testing.T) {
	processor := NewProcessor("agent-1", nil, "").WithMaxBodyBytes(32)
	if processor.MaxBodyBytes() != 32 {
		t.Fatalf("MaxBodyBytes() = %d, want 32", processor.MaxBodyBytes())
	}
	bigBody := `{"key":"` + strings.Repeat("a", 64) + `"}`
	rec, err := processor.Process(captureWithBody(bigBody))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Quality.RequestBodyState != "TRUNCATED" || len(rec.Fields) != 0 {
		t.Fatalf("body exceeding custom maxBodyBytes must be TRUNCATED: %+v", rec)
	}

	// Overlong JSON key path (>512 bytes) and overlong HTTP route/path_template are truncated to <=512 bytes
	longKey := strings.Repeat("k", 600)
	longCapture := captureWithBody(`{"` + longKey + `":"v"}`)
	longCapture.HTTP.Route = "/" + strings.Repeat("r", 600)
	longCapture.HTTP.PathTemplate = "/" + strings.Repeat("p", 600)
	rec2, err := NewProcessor("agent-1", nil, "").Process(longCapture)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec2.HTTP.Route) > 512 || len(rec2.HTTP.PathTemplate) > 512 || !rec2.Quality.Truncated {
		t.Fatalf("HTTP route/path_template not truncated to <=512: route=%d path=%d trunc=%v",
			len(rec2.HTTP.Route), len(rec2.HTTP.PathTemplate), rec2.Quality.Truncated)
	}
	if len(rec2.Fields) != 1 || len(rec2.Fields[0].Path) > 512 || !rec2.Fields[0].Truncated {
		t.Fatalf("field path not truncated to <=512: %+v", rec2.Fields)
	}
}
