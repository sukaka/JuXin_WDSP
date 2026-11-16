package jiuzhang_guard

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	_ "github.com/corazawaf/coraza-caddy/v2"
)

type mutableResourceSampler struct{ memory atomic.Int64 }

func (s *mutableResourceSampler) Sample() resourceSample {
	return resourceSample{
		takenAt: time.Now().UTC(), cpuAvailable: true, cpuPercent: 10,
		memoryAvailable: true, memoryPercent: float64(s.memory.Load()),
	}
}

func TestSoftwareBypassCaddyIntegration(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Origin-Response", "true")
		_, _ = io.WriteString(w, "origin")
	}))
	defer upstream.Close()
	gatewayAddr := freeTCPAddress(t)
	socketDir, err := os.MkdirTemp(".", ".sb-e2e-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socket := socketDir + "/admin.sock"
	previousAutosavePath := caddy.ConfigAutosavePath
	caddy.ConfigAutosavePath = socketDir + "/autosave.json"
	t.Cleanup(func() { caddy.ConfigAutosavePath = previousAutosavePath })

	previousRuntime := globalSoftwareRuntime
	sampler := &mutableResourceSampler{}
	runtime := newSoftwareRuntime(sampler, globalConnectionMetrics)
	globalSoftwareRuntime = runtime
	t.Cleanup(func() {
		_ = caddy.Stop()
		runtime.stop()
		globalSoftwareRuntime = previousRuntime
	})

	config := caddyIntegrationConfig(gatewayAddr, socket, strings.TrimPrefix(upstream.URL, "http://"))
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	var caddyConfig caddy.Config
	if err := json.Unmarshal(raw, &caddyConfig); err != nil {
		t.Fatal(err)
	}
	if err := caddy.Run(&caddyConfig); err != nil {
		t.Fatalf("start Caddy: %v", err)
	}
	runtime.sampleOnce()

	baseURL := "http://" + gatewayAddr
	if status := caddyRequest(t, baseURL+"/attack", ""); status != 403 {
		t.Fatalf("normal attack status = %d, want 403", status)
	}
	if status := caddyRequest(t, baseURL+"/", "JSESSIONID=integration-session"); status != 200 {
		t.Fatalf("normal origin status = %d, want 200", status)
	}

	sampler.memory.Store(90)
	runtime.sampleOnce()
	if status := caddyRequest(t, baseURL+"/attack", ""); status != 200 {
		t.Fatalf("bypass attack status = %d, want 200", status)
	}
	snapshot := caddyRuntimeSnapshot(t, socket)
	if !snapshot.SoftwareBypass.Active || snapshot.SoftwareBypass.Reason != "MEMORY_THRESHOLD" {
		t.Fatalf("bypass snapshot = %+v", snapshot.SoftwareBypass)
	}
	if snapshot.HTTP.SessionsActive != 1 || snapshot.HTTP.SessionsNewTotal != 1 {
		t.Fatalf("session snapshot = %+v", snapshot.HTTP)
	}
	if snapshot.Connections.AcceptedTotal == 0 || snapshot.SoftwareBypass.BypassedRequestsTotal == 0 {
		t.Fatalf("connection/bypass snapshot = %+v", snapshot)
	}

	sampler.memory.Store(20)
	time.Sleep(1100 * time.Millisecond)
	runtime.sampleOnce()
	if status := caddyRequest(t, baseURL+"/attack", ""); status != 403 {
		t.Fatalf("recovered attack status = %d, want 403", status)
	}
	if snapshot := caddyRuntimeSnapshot(t, socket); snapshot.SoftwareBypass.Active {
		t.Fatalf("bypass still active after recovery: %+v", snapshot.SoftwareBypass)
	}
}

func freeTCPAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

func caddyRequest(t *testing.T, url, cookie string) int {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cookie != "" {
		request.Header.Set("Cookie", cookie)
	}
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	return response.StatusCode
}

func caddyRuntimeSnapshot(t *testing.T, socket string) RuntimeSnapshot {
	t.Helper()
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	response, err := client.Get("http://localhost/jiuzhang/runtime")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("runtime admin status = %d", response.StatusCode)
	}
	var snapshot RuntimeSnapshot
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&snapshot); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func caddyIntegrationConfig(gatewayAddr, socket, upstreamAddr string) map[string]interface{} {
	waf := map[string]interface{}{
		"handler": "waf",
		"directives": `SecRuleEngine On
SecRule REQUEST_URI "@contains /attack" "id:1001,phase:1,deny,status:403,log"`,
	}
	selector := map[string]interface{}{
		"handler": "jiuzhang_software_bypass", "app_id": "integration-app",
		"enabled": true, "cpu_threshold_percent": 80, "memory_threshold_percent": 80,
		"min_hold_seconds": 1, "session_cookie_names": []string{"JSESSIONID"},
		"normal": map[string]interface{}{"routes": []interface{}{map[string]interface{}{"handle": []interface{}{waf}}}},
		"bypass": map[string]interface{}{"routes": []interface{}{}},
	}
	return map[string]interface{}{
		"admin":   map[string]interface{}{"listen": "unix/" + socket},
		"storage": map[string]interface{}{"module": "file_system", "root": strings.TrimSuffix(socket, "/admin.sock") + "/data"},
		"apps": map[string]interface{}{
			"http": map[string]interface{}{
				"servers": map[string]interface{}{
					"integration": map[string]interface{}{
						"listen": []string{gatewayAddr}, "automatic_https": map[string]interface{}{"disable": true},
						"listener_wrappers": []interface{}{map[string]interface{}{"wrapper": "jiuzhang_connection_metrics"}},
						"routes": []interface{}{map[string]interface{}{"handle": []interface{}{
							selector,
							map[string]interface{}{"handler": "reverse_proxy", "upstreams": []interface{}{map[string]interface{}{"dial": upstreamAddr}}},
						}}},
					},
				},
			},
		},
	}
}
