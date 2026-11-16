package inprocess

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/apievent"
	"github.com/jiuzhang-waf/wdsp-agent/internal/apiobserve"
)

func TestUnixSocketCapture(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "api.sock")
	server, err := Listen(socket, 0o600, apiobserve.NewProcessor("agent-1", []byte("key"), "key-1"), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() { _ = server.Run(ctx) }()
	defer server.Close()

	body := `{"customer":{"mobile":"13800138000"}}`
	capture := apievent.CaptureBatch{SchemaVersion: 1, Records: []apievent.CaptureRecord{{
		EventID: "req-1", OccurredAt: time.Now().UTC(),
		Source:  apievent.Source{Type: "IN_PROCESS", Language: "java", Framework: "spring", AgentVersion: "1"},
		Service: apievent.Service{Name: "orders", InstanceID: "orders-1"},
		HTTP: apievent.CaptureHTTP{Direction: "SERVER", Method: "POST", Host: "orders", PathTemplate: "/orders", Status: 201,
			Request: apievent.CaptureMessage{ContentType: "application/json", BodyBase64: base64.StdEncoding.EncodeToString([]byte(body)), BodyState: "ANALYZED"}},
	}}}
	payload, _ := json.Marshal(capture)
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}}
	response, err := client.Post("http://unix/v1/api-captures", "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("status=%d", response.StatusCode)
	}
	var result map[string]int
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result["accepted_count"] != 1 {
		t.Fatalf("unexpected response: %+v", result)
	}
	if strings.Contains(string(payload), "body_base64") == false {
		t.Fatal("local capture should contain bounded body")
	}
}

func TestCaptureRejectsUnknownFields(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "api.sock")
	server, err := Listen(socket, 0o600, apiobserve.NewProcessor("agent-1", nil, ""), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() { _ = server.Run(ctx) }()
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}}
	response, err := client.Post("http://unix/v1/api-captures", "application/json", strings.NewReader(`{"schema_version":1,"records":[],"raw_body":"secret"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d", response.StatusCode)
	}
}
