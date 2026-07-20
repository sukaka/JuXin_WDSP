package gatewayconfig

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/applications"
)

func intPtr(v int) *int { return &v }

func sampleApps() []AppData {
	return []AppData{
		{
			Code:           "portal-system",
			ProtectionMode: applications.ModeProtect,
			Domains: []applications.Domain{
				{
					ID: uuid.New(), Hostname: "www.example.com", NormalizedHostname: "www.example.com",
					DomainType: "EXACT", IsPrimary: true, HTTPEnabled: true, HTTPSEnabled: false,
					HTTPPort: intPtr(8080), Status: "ACTIVE",
				},
			},
			Upstreams: []applications.Upstream{
				{ID: uuid.New(), Name: "b1", Scheme: "http", Host: "192.0.2.1", NormalizedHost: "192.0.2.1", Port: 9001, Weight: 10, Status: "ACTIVE", HealthCheckEnabled: true, HealthCheckPath: "/health", HealthCheckIntervalSeconds: 30, HealthCheckTimeoutSeconds: 5, ConnectTimeoutMs: 3000, ResponseHeaderTimeoutMs: 10000, MaxRetries: 1},
			},
		},
	}
}

func TestGenerateDeterministic(t *testing.T) {
	in := GenerateInput{
		Apps:        sampleApps(),
		AdminSocket: "unix//var/run/caddy/admin.sock",
	}
	g1, err := Generate(in)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	g2, err := Generate(in)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if g1.Hash != g2.Hash {
		t.Errorf("same input produced different hashes: %s vs %s", g1.Hash, g2.Hash)
	}
	if g1.JSON != g2.JSON {
		t.Error("same input produced different JSON")
	}
}

func TestGenerateStructure(t *testing.T) {
	in := GenerateInput{
		Apps:        sampleApps(),
		AdminSocket: "unix//var/run/caddy/admin.sock",
	}
	g, err := Generate(in)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal([]byte(g.JSON), &cfg); err != nil {
		t.Fatalf("generated JSON invalid: %v", err)
	}
	// admin socket 必须存在
	admin := cfg["admin"].(map[string]interface{})
	if admin["listen"] != "unix//var/run/caddy/admin.sock" {
		t.Errorf("admin.listen = %v", admin["listen"])
	}
	// server 存在
	servers := cfg["apps"].(map[string]interface{})["http"].(map[string]interface{})["servers"].(map[string]interface{})
	if len(servers) == 0 {
		t.Fatal("no servers generated")
	}
	if g.RouteCount == 0 {
		t.Error("no routes generated")
	}
	// 校验路由含 host matcher 与 reverse_proxy
	srv := servers["srv0"].(map[string]interface{})
	routes := srv["routes"].([]interface{})
	route := routes[0].(map[string]interface{})
	matches := route["match"].([]interface{})[0].(map[string]interface{})
	hosts := matches["host"].([]interface{})
	if hosts[0] != "www.example.com" {
		t.Errorf("route host = %v", hosts[0])
	}
}

func TestGenerateProtectionModes(t *testing.T) {
	modes := []struct {
		mode     string
		expected string
	}{
		{applications.ModeOff, "SecRuleEngine Off"},
		{applications.ModeObserve, "SecRuleEngine DetectionOnly"},
		{applications.ModeProtect, "SecRuleEngine On"},
	}
	for _, m := range modes {
		apps := sampleApps()
		apps[0].ProtectionMode = m.mode
		g, err := Generate(GenerateInput{Apps: apps, AdminSocket: "unix//var/run/caddy/admin.sock"})
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if !contains(g.JSON, m.expected) {
			t.Errorf("mode %s: expected %q in config", m.mode, m.expected)
		}
	}
}

func TestGenerateMultiUpstream(t *testing.T) {
	apps := sampleApps()
	apps[0].Upstreams = append(apps[0].Upstreams, applications.Upstream{
		ID: uuid.New(), Name: "b2", Scheme: "http", Host: "192.0.2.2", NormalizedHost: "192.0.2.2",
		Port: 9002, Weight: 20, Status: "ACTIVE", ConnectTimeoutMs: 3000, ResponseHeaderTimeoutMs: 10000,
	})
	g, err := Generate(GenerateInput{Apps: apps, AdminSocket: "unix//var/run/caddy/admin.sock"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !contains(g.JSON, "weighted_round_robin") {
		t.Error("multi upstream should use weighted_round_robin")
	}
	if !contains(g.JSON, "192.0.2.2:9002") {
		t.Error("second upstream missing")
	}
}

func TestGenerateDisabledUpstreamExcluded(t *testing.T) {
	apps := sampleApps()
	apps[0].Upstreams = append(apps[0].Upstreams, applications.Upstream{
		ID: uuid.New(), Name: "disabled", Scheme: "http", Host: "192.0.2.99", NormalizedHost: "192.0.2.99",
		Port: 9999, Weight: 10, Status: "DISABLED", ConnectTimeoutMs: 3000, ResponseHeaderTimeoutMs: 10000,
	})
	g, err := Generate(GenerateInput{Apps: apps, AdminSocket: "unix//var/run/caddy/admin.sock"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if contains(g.JSON, "192.0.2.99") {
		t.Error("disabled upstream should be excluded")
	}
}

func TestGenerateHTTPSRedirect(t *testing.T) {
	apps := sampleApps()
	apps[0].Domains[0].RedirectHTTPToHTTPS = true
	apps[0].Domains[0].HTTPSEnabled = true
	apps[0].Domains[0].HTTPSPort = intPtr(443)
	apps[0].HasCert = true
	apps[0].CertFileName = "cert1.pem"
	g, err := Generate(GenerateInput{Apps: apps, AdminSocket: "unix//var/run/caddy/admin.sock"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !contains(g.JSON, "308") {
		t.Error("http->https redirect should return 308")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
