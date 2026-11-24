package gatewayconfig

import (
	"encoding/json"
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

// TRANSPARENT（透明串接，P1-2）：PROXY protocol 已还原真实客户端对端 IP，
// guard 必须下发 "deployment_mode":"TRANSPARENT" 且 trusted_proxies 为空数组（绝不信任
// 127.0.0.1/32 或上游代理网段导致 X-Forwarded-For 伪造）。
func TestGenerateGuardTransparentDeploymentMode(t *testing.T) {
	cfg := testGuardConfig()
	cfg.TrustedProxies = append(cfg.TrustedProxies, GuardProxy{
		Name: "local", CIDR: "127.0.0.1/32", HeaderType: "X_FORWARDED_FOR", Priority: 1,
	})
	app := AppData{
		AppID: "app-tpx-1", Code: "shop-tpx", ProtectionMode: applications.ModeProtect,
		DeploymentMode: applications.DeployModeTransparent,
		Domains:        []applications.Domain{{NormalizedHostname: "tpx.example.com", HTTPEnabled: true, HTTPPort: intPtr(80), Status: "ACTIVE"}},
		Upstreams:      []applications.Upstream{{NormalizedHost: "192.0.2.1", Port: 8080, Status: "ACTIVE", Weight: 1}},
	}
	gen, err := Generate(GenerateInput{
		Apps:        []AppData{app},
		AdminSocket: "/var/run/caddy/admin.sock",
		Guard:       cfg,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gen.JSON, `"deployment_mode":"TRANSPARENT"`) {
		t.Errorf("TRANSPARENT guard must emit deployment_mode=TRANSPARENT: %s", gen.JSON)
	}
	if !strings.Contains(gen.JSON, `"trusted_proxies":[]`) {
		t.Errorf("TRANSPARENT guard must output empty trusted_proxies array: %s", gen.JSON)
	}
	if strings.Contains(gen.JSON, `"cidr":"127.0.0.1/32"`) || strings.Contains(gen.JSON, "10.0.0.0/8") {
		t.Errorf("TRANSPARENT guard must not inject loopback or upstream trusted_proxies: %s", gen.JSON)
	}
}

// debug_cc_counter 下发：true 显式注入，false/缺省与历史版本逐字节一致。
func TestBuildGuardHandlerDebugCCCounter(t *testing.T) {
	app := AppData{AppID: "app-x", Code: "shop", ProtectionMode: applications.ModeProtect}
	off := buildGuardHandler(testGuardConfig(), app, 8080)
	if _, ok := off["debug_cc_counter"]; ok {
		t.Fatal("debug_cc_counter must be absent when disabled")
	}
	on := testGuardConfig()
	on.DebugCCCounter = true
	h := buildGuardHandler(on, app, 8080)
	if h["debug_cc_counter"] != true {
		t.Fatalf("debug_cc_counter = %v, want true", h["debug_cc_counter"])
	}
}

// api_mcp_tool_catalogs/api_mcp_bindings 段下发（NG-MCP G1 批次 B1；S5 教训
// 「发布段 handler 映射缺失」锚定）：空段缺省与历史版本逐字节一致（omitempty
// 语义），非空注入 handler 哈希映射（网关 module.go 同 tag 接收）。
func TestBuildGuardHandlerMCPSegments(t *testing.T) {
	app := AppData{AppID: "app-x", Code: "shop", ProtectionMode: applications.ModeProtect}
	off := buildGuardHandler(testGuardConfig(), app, 8080)
	if _, ok := off["api_mcp_tool_catalogs"]; ok {
		t.Fatal("api_mcp_tool_catalogs must be absent when empty")
	}
	if _, ok := off["api_mcp_bindings"]; ok {
		t.Fatal("api_mcp_bindings must be absent when empty")
	}
	on := testGuardConfig()
	on.APIDynamicProtection = true // API 特性段仅 WDSP 开启时注入
	on.APIMCPToolCatalogs = []GuardMCPToolCatalog{{
		Name: "pay-mcp", ServiceIdentity: "mcp://pay.example.com", ProtocolVersion: "2025-11-25",
		CatalogHash: "mcp-catalog-sha256:v1:abc",
		Tools: []GuardMCPTool{{
			ToolName: "refund", ToolVersion: "1.0.0", ToolHash: "mcp-tool-sha256:v1:def",
			RiskLevel: "HIGH", DataClassification: "UNKNOWN",
		}},
	}}
	on.APIMCPBindings = []GuardMCPBinding{
		{ApplicationID: "app-x", EndpointPath: "/mcp/pay", CatalogName: "pay-mcp", Mode: "PROTECT"},
	}
	h := buildGuardHandler(on, app, 8080)
	cats, ok := h["api_mcp_tool_catalogs"].([]GuardMCPToolCatalog)
	if !ok || len(cats) != 1 || cats[0].Name != "pay-mcp" || len(cats[0].Tools) != 1 {
		t.Fatalf("api_mcp_tool_catalogs 注入: %+v", h["api_mcp_tool_catalogs"])
	}
	bindings, ok := h["api_mcp_bindings"].([]GuardMCPBinding)
	if !ok || len(bindings) != 1 || bindings[0].Mode != "PROTECT" {
		t.Fatalf("api_mcp_bindings 注入: %+v", h["api_mcp_bindings"])
	}
	// 序列化形态逐字冻结对照（§5 批次 B1 发布段 JSON 形状）
	raw, err := json.Marshal(h["api_mcp_tool_catalogs"])
	if err != nil {
		t.Fatal(err)
	}
	js := string(raw)
	for _, key := range []string{`"name":"pay-mcp"`, `"service_identity":"mcp://pay.example.com"`,
		`"protocol_version":"2025-11-25"`, `"catalog_hash":"mcp-catalog-sha256:v1:abc"`,
		`"tool_name":"refund"`, `"tool_hash":"mcp-tool-sha256:v1:def"`,
		`"risk_level":"HIGH"`, `"data_classification":"UNKNOWN"`, `"input_schema":null`, `"output_schema":null`} {
		if !strings.Contains(js, key) {
			t.Fatalf("目录段 JSON 应含 %s: %s", key, js)
		}
	}
	raw, err = json.Marshal(h["api_mcp_bindings"])
	if err != nil {
		t.Fatal(err)
	}
	js = string(raw)
	for _, key := range []string{`"application_id":"app-x"`, `"endpoint_path":"/mcp/pay"`,
		`"catalog_name":"pay-mcp"`, `"mode":"PROTECT"`} {
		if !strings.Contains(js, key) {
			t.Fatalf("绑定段 JSON 应含 %s: %s", key, js)
		}
	}
}

// api_machine_identities/api_machine_identity_bindings/api_machine_identity_meta 段下发
// （NG-ID g1 批次 B1；S5 教训「发布段 handler 映射缺失」锚定）：空段缺省与历史版本
// 逐字节一致（omitempty 语义），非空注入 handler 哈希映射（紧随 api_mcp_bindings 之后，
// 网关 module.go 同 tag 接收）；序列化形态对照设计 §1.12 发布段逐字冻结形状。
func TestBuildGuardHandlerMachineIDSegments(t *testing.T) {
	app := AppData{AppID: "app-x", Code: "shop", ProtectionMode: applications.ModeProtect}
	off := buildGuardHandler(testGuardConfig(), app, 8080)
	for _, key := range []string{"api_machine_identities", "api_machine_identity_bindings", "api_machine_identity_meta"} {
		if _, ok := off[key]; ok {
			t.Fatalf("%s must be absent when empty", key)
		}
	}
	on := testGuardConfig()
	on.APIDynamicProtection = true // API 特性段仅 WDSP 开启时注入
	tenant := "tenant-a"
	notBefore := "2026-01-01T00:00:00Z"
	revokedSeq := int64(3)
	on.APIMachineIdentities = []GuardMachineIdentity{{
		IdentityName: "pay-gateway", TenantID: &tenant, Status: "ENABLED", BotChallengeExempt: true,
		Keys: []GuardMachineIdentityKey{{
			Kid: "k1", Alg: "ed25519", PublicKeyPEM: "-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----",
			Status: "REVOKED", NotBefore: &notBefore, RevokedSeq: &revokedSeq,
		}},
	}}
	on.APIMachineIdentityBindings = []GuardMachineIdentityBinding{
		{ApplicationID: "app-x", PathPrefix: "/api", Mode: "PROTECT", ProofRequired: true},
	}
	on.APIMachineIdentityMeta = &GuardMachineIdentityMeta{RevocationWatermark: 3, RegistryVersion: 1760000000000}
	h := buildGuardHandler(on, app, 8080)
	ids, ok := h["api_machine_identities"].([]GuardMachineIdentity)
	if !ok || len(ids) != 1 || ids[0].IdentityName != "pay-gateway" || len(ids[0].Keys) != 1 {
		t.Fatalf("api_machine_identities 注入: %+v", h["api_machine_identities"])
	}
	bindings, ok := h["api_machine_identity_bindings"].([]GuardMachineIdentityBinding)
	if !ok || len(bindings) != 1 || bindings[0].Mode != "PROTECT" || !bindings[0].ProofRequired {
		t.Fatalf("api_machine_identity_bindings 注入: %+v", h["api_machine_identity_bindings"])
	}
	meta, ok := h["api_machine_identity_meta"].(*GuardMachineIdentityMeta)
	if !ok || meta.RevocationWatermark != 3 || meta.RegistryVersion != 1760000000000 {
		t.Fatalf("api_machine_identity_meta 注入: %+v", h["api_machine_identity_meta"])
	}
	// 序列化形态逐字冻结对照（§1.12 发布段 JSON 形状：键名与可空键恒在——无 omitempty）
	raw, err := json.Marshal(h["api_machine_identities"])
	if err != nil {
		t.Fatal(err)
	}
	js := string(raw)
	for _, key := range []string{`"identity_name":"pay-gateway"`, `"tenant_id":"tenant-a"`,
		`"principal_binding":null`, `"status":"ENABLED"`, `"bot_challenge_exempt":true`,
		`"keys":[{`, `"kid":"k1"`, `"alg":"ed25519"`, `"public_key_pem":"-----BEGIN PUBLIC KEY-----`,
		`"status":"REVOKED"`, `"not_before":"2026-01-01T00:00:00Z"`, `"not_after":null`,
		`"retire_overlap_until":null`, `"revoked_seq":3`} {
		if !strings.Contains(js, key) {
			t.Fatalf("身份段 JSON 应含 %s: %s", key, js)
		}
	}
	raw, err = json.Marshal(h["api_machine_identity_bindings"])
	if err != nil {
		t.Fatal(err)
	}
	js = string(raw)
	for _, key := range []string{`"application_id":"app-x"`, `"path_exact":""`, `"path_prefix":"/api"`,
		`"mode":"PROTECT"`, `"proof_required":true`} {
		if !strings.Contains(js, key) {
			t.Fatalf("绑定段 JSON 应含 %s: %s", key, js)
		}
	}
	raw, err = json.Marshal(h["api_machine_identity_meta"])
	if err != nil {
		t.Fatal(err)
	}
	if js = string(raw); js != `{"revocation_watermark":3,"registry_version":1760000000000}` {
		t.Fatalf("meta 段 JSON 逐字形状: %s", js)
	}
}
