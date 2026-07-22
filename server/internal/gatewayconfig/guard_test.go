package gatewayconfig

import (
	"strings"
	"testing"

	"github.com/jiuzhang-waf/server/internal/applications"
)

func testGuardConfig() *GuardConfig {
	return &GuardConfig{
		TrustedProxies: []GuardProxy{
			{Name: "lb", CIDR: "10.0.0.0/8", HeaderType: "X_FORWARDED_FOR", Priority: 10},
		},
		MaxProxyChain:      16,
		ProtectedAddresses: []string{"127.0.0.1", "10.0.0.1"},
		GlobalAllow:        []GuardRule{{ID: "ga1", Address: "192.0.2.1", Priority: 10}},
		GlobalDeny:         []GuardRule{{ID: "gd1", Address: "203.0.113.0/24", Priority: 10}},
		GlobalPolicies: []GuardPolicy{{
			ID: "gcp1", Name: "全局限速", Dimension: "CLIENT_IP", Algorithm: "TOKEN_BUCKET",
			URIMatchType: "ALL", RequestsLimit: 100, WindowSeconds: 60, Action: "REJECT", Priority: 10,
		}},
		AppRules: map[string]*GuardAppRules{
			"shop": {
				Allow: []GuardRule{{ID: "aa1", Address: "198.51.100.1", Priority: 20}},
				Deny:  []GuardRule{{ID: "ad1", Address: "198.51.100.2", Priority: 20}},
				Policies: []GuardPolicy{{
					ID: "acp1", Name: "登录限速", Dimension: "CLIENT_IP_AND_URI", Algorithm: "SLIDING_WINDOW",
					URIMatchType: "PREFIX", URIPattern: "/api/", RequestsLimit: 5, WindowSeconds: 60,
					Action: "TEMP_BLOCK", BlockDurationSeconds: 900, Priority: 20,
				}},
			},
		},
		Valkey:         &GuardValkey{Address: "valkey:6379", Password: "secret", DB: 0},
		CounterBackend: "valkey",
		MaxCounterKeys: 100000,
		FailOpen:       true,
		EventsLog:      "/var/log/caddy/guard-events.log",
		GatewayNode:    "gateway-test-01",
	}
}

func TestGenerateWithGuard(t *testing.T) {
	in := GenerateInput{
		Apps: []AppData{{
			AppID: "app-uuid-1", Code: "shop", ProtectionMode: applications.ModeProtect,
			Domains:   []applications.Domain{{NormalizedHostname: "shop.example.com", HTTPEnabled: true, HTTPPort: intPtr(8080), Status: "ACTIVE"}},
			Upstreams: []applications.Upstream{{NormalizedHost: "127.0.0.1", Port: 9001, Status: "ACTIVE", Weight: 1}},
		}},
		AdminSocket: "/var/run/caddy/admin.sock",
		Guard:       testGuardConfig(),
	}
	gen, err := Generate(in)
	if err != nil {
		t.Fatal(err)
	}
	j := gen.JSON
	// guard 处理器存在且位于 Request ID headers 之后、waf 之前
	gi := strings.Index(j, "jiuzhang_guard")
	wi := strings.Index(j, `"handler":"waf"`)
	hi := strings.Index(j, "X-Request-Id")
	if gi < 0 || wi < 0 || hi < 0 {
		t.Fatalf("guard/waf/headers handler missing: guard=%d waf=%d headers=%d", gi, wi, hi)
	}
	if !(hi < gi && gi < wi) {
		t.Fatalf("order must be headers -> guard -> waf: %d %d %d", hi, gi, wi)
	}
	// 应用级规则与策略注入
	for _, want := range []string{`"app_id":"app-uuid-1"`, `"app_code":"shop"`, "aa1", "ad1", "acp1", "gcp1", "gateway-test-01", "guard-events.log", "valkey:6379"} {
		if !strings.Contains(j, want) {
			t.Errorf("config missing %q", want)
		}
	}
}

func TestGenerateGuardAppIsolation(t *testing.T) {
	in := GenerateInput{
		Apps: []AppData{{
			AppID: "app-uuid-2", Code: "other", ProtectionMode: applications.ModeProtect,
			Domains:   []applications.Domain{{NormalizedHostname: "other.example.com", HTTPEnabled: true, HTTPPort: intPtr(8080), Status: "ACTIVE"}},
			Upstreams: []applications.Upstream{{NormalizedHost: "127.0.0.1", Port: 9002, Status: "ACTIVE", Weight: 1}},
		}},
		AdminSocket: "/var/run/caddy/admin.sock",
		Guard:       testGuardConfig(),
	}
	gen, err := Generate(in)
	if err != nil {
		t.Fatal(err)
	}
	// other 应用不应包含 shop 的应用级规则，但应包含全局策略
	if strings.Contains(gen.JSON, "aa1") || strings.Contains(gen.JSON, "acp1") {
		t.Error("app-level rules leaked to other app")
	}
	if !strings.Contains(gen.JSON, "gcp1") || !strings.Contains(gen.JSON, "gd1") {
		t.Error("global rules/policies should apply to all apps")
	}
}

func TestGenerateWithoutGuardBackwardCompatible(t *testing.T) {
	in := GenerateInput{
		Apps: []AppData{{
			Code: "shop", ProtectionMode: applications.ModeProtect,
			Domains:   []applications.Domain{{NormalizedHostname: "shop.example.com", HTTPEnabled: true, HTTPPort: intPtr(8080), Status: "ACTIVE"}},
			Upstreams: []applications.Upstream{{NormalizedHost: "127.0.0.1", Port: 9001, Status: "ACTIVE", Weight: 1}},
		}},
		AdminSocket: "/var/run/caddy/admin.sock",
	}
	gen, err := Generate(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(gen.JSON, "jiuzhang_guard") {
		t.Error("nil guard must not inject handler (stage3/4 compatibility)")
	}
}
