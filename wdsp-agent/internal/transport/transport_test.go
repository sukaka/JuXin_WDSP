package transport

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/events"
)

func newClient(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	c, err := New(srv.URL, false, "test")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNewRejectsBadServer(t *testing.T) {
	if _, err := New("ftp://x", false, "t"); err == nil {
		t.Fatal("非法 scheme 应拒绝")
	}
	if _, err := New("not-a-url", false, "t"); err == nil {
		t.Fatal("非法地址应拒绝")
	}
}

func TestEnroll(t *testing.T) {
	var gotBody EnrollRequest
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agents/enroll" || r.Method != http.MethodPost {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"agent_id":"a3c98f51-x","credential":"wda_deadbeef","heartbeat_interval_seconds":15,"config_version":0}`))
	}))
	defer srv.Close()

	c := newClient(t, srv)
	resp, err := c.Enroll(context.Background(), EnrollRequest{
		EnrollmentToken: "wdt_123", Hostname: "web-01", IP: "10.0.1.10",
		OS: "Rocky Linux 9", Kernel: "5.14.0", Arch: "amd64", Version: "1.0.0",
		Interfaces: []InterfaceInfo{{Name: "eth0", MAC: "aa:bb:cc:dd:ee:ff", IPv4: "10.0.1.10", MTU: 1500, SpeedMbps: 1000}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.AgentID != "a3c98f51-x" || resp.Credential != "wda_deadbeef" {
		t.Fatalf("resp=%+v", resp)
	}
	if gotAuth != "" {
		t.Fatal("enroll 不应携带 Authorization")
	}
	if gotBody.EnrollmentToken != "wdt_123" || gotBody.Interfaces[0].SpeedMbps != 1000 {
		t.Fatalf("body=%+v", gotBody)
	}
}

func TestHeartbeatSerialization(t *testing.T) {
	var got HeartbeatRequest
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agents/agent-1/heartbeat" {
			t.Errorf("path=%s", r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&got)
		_ = json.NewEncoder(w).Encode(HeartbeatResponse{
			ServerTime: 1788256801, ConfigVersion: 12, DesiredState: "ENABLED", HeartbeatIntervalSeconds: 15,
		})
	}))
	defer srv.Close()

	c := newClient(t, srv)
	c.SetCredential("wda_x")
	resp, err := c.Heartbeat(context.Background(), "agent-1", HeartbeatRequest{
		Timestamp: 1788256800, Status: "ONLINE",
		Metrics: Metrics{CPUPercent: 3.2, MemoryMB: 128.5, PacketsReceived: 900000, KernelDrops: 3},
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer wda_x" {
		t.Fatalf("auth=%q", gotAuth)
	}
	if got.Status != "ONLINE" || got.Metrics.PacketsReceived != 900000 {
		t.Fatalf("body=%+v", got)
	}
	if resp.ConfigVersion != 12 || resp.DesiredState != "ENABLED" {
		t.Fatalf("resp=%+v", resp)
	}
}

func TestGetConfigAndAck(t *testing.T) {
	var ackBody AckRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/config"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"version": 12,
				"policy": map[string]any{
					"name": "production-web",
					"capture": map[string]any{
						"interfaces": []string{"eth0"}, "direction": "both",
						"protocols": []string{"tcp"}, "ports": []int{80, 443, 8080, 8443},
					},
					"capture_level": "L1",
					"output":        map[string]any{"mode": "FLOW"},
					"limits":        map[string]any{"max_body_size": 262144, "outbound_mbps": 100, "cpu_percent": 20, "memory_mb": 512},
					"sampling":      map[string]any{"enabled": false, "rate": 1.0},
					"buffer":        map[string]any{"enabled": true, "max_size_mb": 512, "max_age_minutes": 30},
				},
			})
		case strings.HasSuffix(r.URL.Path, "/config/ack"):
			_ = json.NewDecoder(r.Body).Decode(&ackBody)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("path=%s", r.URL.Path)
		}
	}))
	defer srv.Close()

	c := newClient(t, srv)
	c.SetCredential("x")
	resp, err := c.GetConfig(context.Background(), "agent-1")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Version != 12 || resp.Policy == nil {
		t.Fatalf("resp=%+v", resp)
	}
	if !strings.Contains(string(*resp.Policy), "production-web") {
		t.Fatalf("policy=%s", *resp.Policy)
	}
	if err := c.AckConfig(context.Background(), "agent-1", AckRequest{Version: 12, Status: "APPLIED"}); err != nil {
		t.Fatal(err)
	}
	if ackBody.Version != 12 || ackBody.Status != "APPLIED" {
		t.Fatalf("ack=%+v", ackBody)
	}
}

func TestGetConfigNullPolicy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"version":7,"policy":null}`))
	}))
	defer srv.Close()
	c := newClient(t, srv)
	resp, err := c.GetConfig(context.Background(), "a")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Policy != nil && string(*resp.Policy) != "null" {
		t.Fatalf("policy=%v", resp.Policy)
	}
}

func TestPostFlows(t *testing.T) {
	var got events.FlowsRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agents/agent-1/flows" {
			t.Errorf("path=%s", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"accepted":2}`))
	}))
	defer srv.Close()

	c := newClient(t, srv)
	c.SetCredential("x")
	accepted, err := c.PostFlows(context.Background(), "agent-1", []events.FlowEvent{
		{EventType: "request", FlowID: "f1", Timestamp: 1788256800, SrcIP: "10.1.1.10", SrcPort: 51234,
			DstIP: "10.1.2.20", DstPort: 8080, Protocol: "tcp", Direction: "ingress",
			TLSVisibility: "PLAINTEXT", HTTPMethod: "POST", HTTPHost: "api.example.com", HTTPURI: "/api/login"},
		{EventType: "flow_end", FlowID: "f1", Timestamp: 1788256890, BytesIn: 100, BytesOut: 200},
	})
	if err != nil || accepted != 2 {
		t.Fatalf("accepted=%d err=%v", accepted, err)
	}
	if len(got.Events) != 2 || got.Events[0].HTTPMethod != "POST" || got.Events[0].HTTPStatus != 0 {
		t.Fatalf("events=%+v", got.Events)
	}
}

func TestPostPacketsBinary(t *testing.T) {
	var gotCT string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"accepted_frames":1}`))
	}))
	defer srv.Close()

	b := events.NewPacketBatcher(0, nil)
	b.Add(events.PacketFrame{Ts: time.Unix(1788256800, 123000000), OrigLen: 60, Data: []byte("fake-ethernet-frame")})
	body := b.Flush(time.Unix(1788256805, 0))

	c := newClient(t, srv)
	c.SetCredential("x")
	n, err := c.PostPackets(context.Background(), "agent-1", body)
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if gotCT != "application/x-wdsp-packet-batch" {
		t.Fatalf("content-type=%s", gotCT)
	}
	if string(gotBody[:4]) != "WDP1" {
		t.Fatalf("magic=%q", gotBody[:4])
	}
}

func TestUnauthorizedHandling(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"code":"CREDENTIAL_REVOKED","message":"credential revoked"}}`))
	}))
	defer srv.Close()
	c := newClient(t, srv)
	c.SetCredential("bad")
	_, err := c.Heartbeat(context.Background(), "a", HeartbeatRequest{})
	if !IsUnauthorized(err) {
		t.Fatalf("err=%v", err)
	}
	var ae *APIError
	if !errors.As(err, &ae) || ae.Code != "CREDENTIAL_REVOKED" {
		t.Fatalf("apiErr=%v", err)
	}
}

func TestServerError(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":{"code":"INTERNAL","message":"db down"}}`))
	}))
	defer srv.Close()
	c := newClient(t, srv)
	c.SetCredential("x")
	_, err := c.PostFlows(context.Background(), "a", []events.FlowEvent{{EventType: "request"}})
	if err == nil || IsUnauthorized(err) {
		t.Fatalf("err=%v", err)
	}
	var ae *APIError
	if !errors.As(err, &ae) || ae.StatusCode != 500 || ae.Code != "INTERNAL" {
		t.Fatalf("err=%v", err)
	}
}

func TestBackoff(t *testing.T) {
	b := NewBackoff(0, 0)
	if d := b.Next(); d != time.Second {
		t.Fatalf("首次=%s, 应 1s", d)
	}
	if d := b.Next(); d != 2*time.Second {
		t.Fatalf("第二次=%s", d)
	}
	for i := 0; i < 10; i++ {
		b.Next()
	}
	if d := b.Next(); d != 60*time.Second {
		t.Fatalf("应封顶 60s, got %s", d)
	}
	b.Reset()
	if d := b.Next(); d != time.Second {
		t.Fatalf("Reset 后=%s", d)
	}
}
