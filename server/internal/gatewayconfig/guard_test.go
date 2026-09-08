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

// 授权配额全局限速下发：LicenseMaxQPS>0 时 guard JSON 携带 license_max_qps；0=不限制不下发。
func TestGenerateGuardLicenseMaxQPS(t *testing.T) {
	newApp := func() AppData {
		return AppData{
			AppID: "app-uuid-1", Code: "shop", ProtectionMode: applications.ModeProtect,
			Domains:   []applications.Domain{{NormalizedHostname: "shop.example.com", HTTPEnabled: true, HTTPPort: intPtr(8080), Status: "ACTIVE"}},
			Upstreams: []applications.Upstream{{NormalizedHost: "127.0.0.1", Port: 9001, Status: "ACTIVE", Weight: 1}},
		}
	}

	// >0：注入 guard JSON
	cfg := testGuardConfig()
	cfg.LicenseMaxQPS = 1000
	gen, err := Generate(GenerateInput{
		Apps:        []AppData{newApp()},
		AdminSocket: "/var/run/caddy/admin.sock",
		Guard:       cfg,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gen.JSON, `"license_max_qps":1000`) {
		t.Error("license_max_qps must be injected into guard JSON when > 0")
	}

	// 0（缺省）：不下发，JSON 与历史版本一致
	gen, err = Generate(GenerateInput{
		Apps:        []AppData{newApp()},
		AdminSocket: "/var/run/caddy/admin.sock",
		Guard:       testGuardConfig(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(gen.JSON, "license_max_qps") {
		t.Error("license_max_qps must be omitted when 0")
	}
}

// ROUTED（路由牵引，docs/NETWORK_MODES_DESIGN.md §4.1）：guard JSON 的 trusted_proxies
// 输出为空数组且附加 "deployment_mode":"ROUTED"；REVERSE_PROXY（含缺省）逐字节不变。
func TestGenerateGuardRoutedDeploymentMode(t *testing.T) {
	newApp := func(mode string) AppData {
		return AppData{
			AppID: "app-uuid-1", Code: "shop", ProtectionMode: applications.ModeProtect, DeploymentMode: mode,
			Domains:   []applications.Domain{{NormalizedHostname: "shop.example.com", HTTPEnabled: true, HTTPPort: intPtr(8080), Status: "ACTIVE"}},
			Upstreams: []applications.Upstream{{NormalizedHost: "127.0.0.1", Port: 9001, Status: "ACTIVE", Weight: 1}},
		}
	}

	// ROUTED：不下发可信代理链（空数组而非 null），附加 deployment_mode 便于事件/排障识别
	gen, err := Generate(GenerateInput{
		Apps:        []AppData{newApp(applications.DeployModeRouted)},
		AdminSocket: "/var/run/caddy/admin.sock",
		Guard:       testGuardConfig(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gen.JSON, `"trusted_proxies":[]`) {
		t.Error("ROUTED guard must output empty trusted_proxies array")
	}
	if !strings.Contains(gen.JSON, `"deployment_mode":"ROUTED"`) {
		t.Error("ROUTED guard must carry deployment_mode field")
	}
	if strings.Contains(gen.JSON, "10.0.0.0/8") {
		t.Error("ROUTED guard must not leak trusted proxy CIDRs")
	}

	// REVERSE_PROXY 与缺省（空串）：可信代理链照常下发，不出现 deployment_mode 键
	for _, mode := range []string{applications.DeployModeReverseProxy, ""} {
		gen, err := Generate(GenerateInput{
			Apps:        []AppData{newApp(mode)},
			AdminSocket: "/var/run/caddy/admin.sock",
			Guard:       testGuardConfig(),
		})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(gen.JSON, "10.0.0.0/8") {
			t.Errorf("mode %q: trusted proxies must be passed through", mode)
		}
		if strings.Contains(gen.JSON, `"deployment_mode"`) {
			t.Errorf("mode %q: guard JSON must not contain deployment_mode (byte-identical to legacy)", mode)
		}
	}
}
