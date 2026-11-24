package gatewayconfig

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/applications"
)

func TestGenerateACMEHTTP01_PrependOnExistingPort80AndPendingAutoSSL(t *testing.T) {
	app := AppData{
		AppID:          uuid.NewString(),
		Code:           "shop",
		ProtectionMode: applications.ModeProtect,
		DeploymentMode: applications.DeployModeReverseProxy,
		PendingAutoSSL: true,
		Domains: []applications.Domain{{
			Hostname:            "shop.example.com",
			NormalizedHostname:  "shop.example.com",
			HTTPEnabled:         true,
			HTTPSEnabled:        true,
			HTTPPort:            intPtr(80),
			HTTPSPort:           intPtr(443),
			RedirectHTTPToHTTPS: true,
		}},
		Upstreams: []applications.Upstream{{
			Scheme: "http", NormalizedHost: "127.0.0.1", Port: 8080, Weight: 10, Status: "ACTIVE",
		}},
	}

	gen, err := Generate(GenerateInput{
		Apps:        []AppData{app},
		AdminSocket: "/var/run/caddy/admin.sock",
		ACMEHTTP01: &ACMEHTTP01Config{
			Enabled: true,
			Valkey:  &GuardValkey{Address: "valkey:6379", Password: "secret-valkey-pass", DB: 0},
		},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var cfg map[string]any
	if err := json.Unmarshal([]byte(gen.JSON), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	servers := cfg["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
	// PendingAutoSSL 暂缓生成 :443 server，仅存在 :80 server
	if len(servers) != 1 {
		t.Fatalf("servers count=%d, want 1 (only :80 while PendingAutoSSL): %v", len(servers), servers)
	}
	srv0 := servers["srv0"].(map[string]any)
	routes := srv0["routes"].([]any)
	if len(routes) < 2 {
		t.Fatalf("routes=%d, want >=2 (acme + app)", len(routes))
	}
	firstHandle := routes[0].(map[string]any)["handle"].([]any)[0].(map[string]any)
	if firstHandle["handler"] != "jiuzhang_acme_http01" {
		t.Fatalf("first route handler=%v, want jiuzhang_acme_http01", firstHandle["handler"])
	}
	if firstHandle["challenge_dir"] != "/etc/caddy/certs/.acme-challenges" {
		t.Fatalf("challenge_dir=%v", firstHandle["challenge_dir"])
	}
	// PendingAutoSSL 期间不应下发 308 跳转到尚未就绪的 HTTPS
	if strings.Contains(gen.JSON, `"status_code":308`) {
		t.Fatalf("PendingAutoSSL must suppress 308 redirect until cert issued")
	}

	// 脱敏必须隐藏 ACME handler 中的 valkey.password
	redacted, err := RedactConfigSecrets(gen.JSON)
	if err != nil {
		t.Fatalf("RedactConfigSecrets: %v", err)
	}
	if strings.Contains(redacted, "secret-valkey-pass") {
		t.Fatalf("redacted config leaked ACME valkey password: %s", redacted)
	}
	if !strings.Contains(redacted, `"password":"***"`) {
		t.Fatalf("redacted config missing *** placeholder: %s", redacted)
	}

	// 回滚重注入必须恢复当前 Valkey 凭据
	pub := &Publisher{
		guard: stubGuardProvider{cfg: &GuardConfig{
			Valkey: &GuardValkey{Address: "valkey:6379", Password: "new-rotated-password", DB: 0},
		}},
	}
	reinjected, err := pub.reinjectConfigSecrets(context.Background(), redacted)
	if err != nil {
		t.Fatalf("reinjectConfigSecrets: %v", err)
	}
	if !strings.Contains(reinjected, "new-rotated-password") {
		t.Fatalf("reinjected config missing rotated valkey password: %s", reinjected)
	}
}

func TestGenerateACMEHTTP01_SynthesizesPort80WhenHTTPSOnly(t *testing.T) {
	app := AppData{
		AppID:          uuid.NewString(),
		Code:           "httpsonly",
		ProtectionMode: applications.ModeProtect,
		DeploymentMode: applications.DeployModeReverseProxy,
		PendingAutoSSL: true,
		Domains: []applications.Domain{{
			Hostname:           "secure.example.com",
			NormalizedHostname: "secure.example.com",
			HTTPEnabled:        false,
			HTTPSEnabled:       true,
			HTTPSPort:          intPtr(443),
		}},
		Upstreams: []applications.Upstream{{
			Scheme: "http", NormalizedHost: "127.0.0.1", Port: 8080, Weight: 10, Status: "ACTIVE",
		}},
	}
	gen, err := Generate(GenerateInput{
		Apps:        []AppData{app},
		AdminSocket: "/var/run/caddy/admin.sock",
		ACMEHTTP01:  &ACMEHTTP01Config{Enabled: true},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	ports, ok := extractPublicTCPPortsFromConfig(gen.JSON)
	if !ok || len(ports) != 1 || ports[0] != 80 {
		t.Fatalf("ports=%v ok=%v, want [80] from srv_acme_http01", ports, ok)
	}
	if !strings.Contains(gen.JSON, `"srv_acme_http01"`) {
		t.Fatalf("expected srv_acme_http01 in config: %s", gen.JSON)
	}
}

type stubGuardProvider struct {
	cfg *GuardConfig
}

func (s stubGuardProvider) BuildGuardConfig(context.Context) (*GuardConfig, error) {
	return s.cfg, nil
}
func (s stubGuardProvider) SaveVersionSnapshot(context.Context, *GuardConfig, uuid.UUID, uuid.UUID) (uuid.UUID, error) {
	return uuid.New(), nil
}
func (s stubGuardProvider) MarkVersionResult(context.Context, uuid.UUID, string) error { return nil }
func (s stubGuardProvider) GetVersionConfig(context.Context, uuid.UUID) (*GuardConfig, error) {
	return s.cfg, nil
}
